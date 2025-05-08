"""deCONZ serial protocol API."""

from __future__ import annotations

import asyncio
import collections
import itertools
import logging
import sys
from typing import Any, Callable

if sys.version_info[:2] < (3, 11):
    from async_timeout import timeout as asyncio_timeout  # pragma: no cover
else:
    from asyncio import timeout as asyncio_timeout  # pragma: no cover

from zigpy.datastructures import PriorityLock
from zigpy.types import (
    APSStatus,
    Bool,
    Channels,
    KeyData,
    SerializableBytes,
    Struct,
    ZigbeePacket,
)
from zigpy.zdo.types import SimpleDescriptor

from zigpy_deconz.exception import CommandError, MismatchedResponseError, ParsingError
import zigpy_deconz.types as t
import zigpy_deconz.uart
from zigpy_deconz.utils import restart_forever

LOGGER = logging.getLogger(__name__)

MISMATCHED_RESPONSE_TIMEOUT = 0.5
COMMAND_TIMEOUT = 1.8
PROBE_TIMEOUT = 2

FRAME_LENGTH = object()
PAYLOAD_LENGTH = object()


class Status(t.enum8):
    SUCCESS = 0
    FAILURE = 1
    BUSY = 2
    TIMEOUT = 3
    UNSUPPORTED = 4
    ERROR = 5
    NO_NETWORK = 6
    INVALID_VALUE = 7


class NetworkState2(t.enum2):
    OFFLINE = 0
    JOINING = 1
    CONNECTED = 2
    LEAVING = 3


class DeviceStateFlags(t.bitmap6):
    APSDE_DATA_CONFIRM = 0b00001
    APSDE_DATA_INDICATION = 0b000010
    CONF_CHANGED = 0b000100
    APSDE_DATA_REQUEST_FREE_SLOTS_AVAILABLE = 0b0001000


class DeviceState(t.Struct):
    network_state: NetworkState2
    device_state: DeviceStateFlags


class FirmwarePlatform(t.enum8):
    Conbee = 0x05
    Conbee_II = 0x07
    Conbee_III = 0x09


class FirmwareVersion(t.IntStruct, t.uint32_t):
    reserved: t.uint8_t
    platform: FirmwarePlatform
    minor: t.uint8_t
    major: t.uint8_t


class NetworkState(t.enum8):
    OFFLINE = 0
    JOINING = 1
    CONNECTED = 2
    LEAVING = 3


class SecurityMode(t.enum8):
    NO_SECURITY = 0x00
    PRECONFIGURED_NETWORK_KEY = 0x01
    NETWORK_KEY_FROM_TC = 0x02
    ONLY_TCLK = 0x03


class ZDPResponseHandling(t.bitmap16):
    NONE = 0x0000
    NodeDescRsp = 0x0001


class CommandId(t.enum8):
    aps_data_confirm = 0x04
    device_state = 0x07
    change_network_state = 0x08
    read_parameter = 0x0A
    write_parameter = 0x0B
    version = 0x0D
    device_state_changed = 0x0E
    aps_data_request = 0x12
    aps_data_indication = 0x17
    zigbee_green_power = 0x19
    mac_poll = 0x1C
    update_neighbor = 0x1D
    mac_beacon_indication = 0x1F


class TXStatus(t.enum8):
    SUCCESS = 0x00

    @classmethod
    def _missing_(cls, value):
        chained = APSStatus(value)
        status = t.uint8_t.__new__(cls, chained.value)
        status._name_ = chained.name
        status._value_ = value
        return status


class NetworkParameter(t.enum8):
    mac_address = 0x01
    nwk_panid = 0x05
    nwk_address = 0x07
    nwk_extended_panid = 0x08
    aps_designed_coordinator = 0x09
    channel_mask = 0x0A
    aps_extended_panid = 0x0B
    trust_center_address = 0x0E
    security_mode = 0x10
    configure_endpoint = 0x13
    use_predefined_nwk_panid = 0x15
    network_key = 0x18
    link_key = 0x19
    current_channel = 0x1C
    permit_join = 0x21
    protocol_version = 0x22
    nwk_update_id = 0x24
    watchdog_ttl = 0x26
    nwk_frame_counter = 0x27
    app_zdp_response_handling = 0x28


class IndexedKey(Struct):
    index: t.uint8_t
    key: KeyData


class LinkKey(Struct):
    ieee: t.EUI64
    key: KeyData


class IndexedEndpoint(Struct):
    index: t.uint8_t
    descriptor: SimpleDescriptor


class UpdateNeighborAction(t.enum8):
    ADD = 0x01


NETWORK_PARAMETER_TYPES = {
    NetworkParameter.mac_address: (None, t.EUI64),
    NetworkParameter.nwk_panid: (None, t.PanId),
    NetworkParameter.nwk_address: (None, t.NWK),
    NetworkParameter.nwk_extended_panid: (None, t.ExtendedPanId),
    NetworkParameter.aps_designed_coordinator: (None, t.uint8_t),
    NetworkParameter.channel_mask: (None, Channels),
    NetworkParameter.aps_extended_panid: (None, t.ExtendedPanId),
    NetworkParameter.trust_center_address: (None, t.EUI64),
    NetworkParameter.security_mode: (None, t.uint8_t),
    NetworkParameter.configure_endpoint: (t.uint8_t, IndexedEndpoint),
    NetworkParameter.use_predefined_nwk_panid: (None, Bool),
    NetworkParameter.network_key: (t.uint8_t, IndexedKey),
    NetworkParameter.link_key: (t.EUI64, LinkKey),
    NetworkParameter.current_channel: (None, t.uint8_t),
    NetworkParameter.permit_join: (None, t.uint8_t),
    NetworkParameter.protocol_version: (None, t.uint16_t),
    NetworkParameter.nwk_update_id: (None, t.uint8_t),
    NetworkParameter.watchdog_ttl: (None, t.uint32_t),
    NetworkParameter.nwk_frame_counter: (None, t.uint32_t),
    NetworkParameter.app_zdp_response_handling: (None, ZDPResponseHandling),
}


class Command(Struct):
    command_id: CommandId
    seq: t.uint8_t
    payload: t.Bytes


COMMAND_SCHEMAS = {
    CommandId.update_neighbor: (
        {
            "status": Status.SUCCESS,
            "frame_length": FRAME_LENGTH,
            "payload_length": PAYLOAD_LENGTH,
            "action": UpdateNeighborAction,
            "nwk": t.NWK,
            "ieee": t.EUI64,
            "mac_capability_flags": t.uint8_t,
        },
        {
            "status": Status,
            "frame_length": t.uint16_t,
            "payload_length": t.uint16_t,
            "action": UpdateNeighborAction,
            "nwk": t.NWK,
            "ieee": t.EUI64,
            "mac_capability_flags": t.uint8_t,
        },
    ),
    CommandId.aps_data_confirm: (
        {
            "status": Status.SUCCESS,
            "frame_length": FRAME_LENGTH,
            "payload_length": PAYLOAD_LENGTH,
        },
        {
            "status": Status,
            "frame_length": t.uint16_t,
            "payload_length": t.uint16_t,
            "device_state": DeviceState,
            "request_id": t.uint8_t,
            "dst_addr": t.DeconzAddressEndpoint,
            "src_ep": t.uint8_t,
            "confirm_status": TXStatus,
            "reserved1": t.uint8_t,
            "reserved2": t.uint8_t,
            "reserved3": t.uint8_t,
            "reserved4": t.uint8_t,
        },
    ),
    CommandId.aps_data_indication: (
        {
            "status": Status.SUCCESS,
            "frame_length": FRAME_LENGTH,
            "payload_length": PAYLOAD_LENGTH,
            "flags": t.DataIndicationFlags,
        },
        {
            "status": Status,
            "frame_length": t.uint16_t,
            "payload_length": t.uint16_t,
            "device_state": DeviceState,
            "dst_addr": t.DeconzAddress,
            "dst_ep": t.uint8_t,
            "src_addr": t.DeconzAddress,
            "src_ep": t.uint8_t,
            "profile_id": t.uint16_t,
            "cluster_id": t.uint16_t,
            "asdu": t.LongOctetString,
            "reserved1": t.uint8_t,
            "reserved2": t.uint8_t,
            "lqi": t.uint8_t,
            "reserved3": t.uint8_t,
            "reserved4": t.uint8_t,
            "reserved5": t.uint8_t,
            "reserved6": t.uint8_t,
            "rssi": t.int8s,
        },
    ),
    CommandId.aps_data_request: (
        {
            "status": Status.SUCCESS,
            "frame_length": FRAME_LENGTH,
            "payload_length": PAYLOAD_LENGTH,
            "request_id": t.uint8_t,
            "flags": t.DeconzSendDataFlags,
            "dst": t.DeconzAddressEndpoint,
            "profile_id": t.uint16_t,
            "cluster_id": t.uint16_t,
            "src_ep": t.uint8_t,
            "asdu": t.LongOctetString,
            "tx_options": t.DeconzTransmitOptions,
            "radius": t.uint8_t,
            "relays": t.NWKList,  # optional
        },
        {
            "status": Status,
            "frame_length": t.uint16_t,
            "payload_length": t.uint16_t,
            "device_state": DeviceState,
            "request_id": t.uint8_t,
        },
    ),
    CommandId.change_network_state: (
        {
            "status": Status.SUCCESS,
            "frame_length": FRAME_LENGTH,
            # "payload_length": PAYLOAD_LENGTH,
            "network_state": NetworkState,
        },
        {
            "status": Status,
            "frame_length": t.uint16_t,
            # "payload_length": t.uint16_t,
            "network_state": NetworkState,
        },
    ),
    CommandId.device_state: (
        {
            "status": Status.SUCCESS,
            "frame_length": FRAME_LENGTH,
            # "payload_length": PAYLOAD_LENGTH,
            "reserved1": t.uint8_t(0),
            "reserved2": t.uint8_t(0),
            "reserved3": t.uint8_t(0),
        },
        {
            "status": Status,
            "frame_length": t.uint16_t,
            # "payload_length": t.uint16_t,
            "device_state": DeviceState,
            "reserved1": t.uint8_t,
            "reserved2": t.uint8_t,
        },
    ),
    CommandId.device_state_changed: (
        None,
        {
            "status": Status,
            "frame_length": t.uint16_t,
            # "payload_length": t.uint16_t,
            "device_state": DeviceState,
            "reserved": t.uint8_t,
        },
    ),
    CommandId.mac_poll: (
        None,
        {
            "status": Status,
            "frame_length": t.uint16_t,
            "payload_length": t.uint16_t,
            "src_addr": t.DeconzAddress,
            "lqi": t.uint8_t,
            "rssi": t.int8s,
            "life_time": t.uint32_t,  # Optional
            "device_timeout": t.uint32_t,  # Optional
        },
    ),
    CommandId.read_parameter: (
        {
            "status": Status.SUCCESS,
            "frame_length": FRAME_LENGTH,
            "payload_length": PAYLOAD_LENGTH,
            "parameter_id": NetworkParameter,
            "parameter": t.Bytes,
        },
        {
            "status": Status,
            "frame_length": t.uint16_t,
            "payload_length": t.uint16_t,
            "parameter_id": NetworkParameter,
            "parameter": t.Bytes,
        },
    ),
    CommandId.version: (
        {
            "status": Status.SUCCESS,
            "frame_length": FRAME_LENGTH,
            # "payload_length": PAYLOAD_LENGTH,
            "reserved": t.uint32_t(0),
        },
        {
            "status": Status,
            "frame_length": t.uint16_t,
            # "payload_length": t.uint16_t,
            "version": FirmwareVersion,
        },
    ),
    CommandId.write_parameter: (
        {
            "status": Status.SUCCESS,
            "frame_length": FRAME_LENGTH,
            "payload_length": PAYLOAD_LENGTH,
            "parameter_id": NetworkParameter,
            "parameter": t.Bytes,
        },
        {
            "status": Status,
            "frame_length": t.uint16_t,
            "payload_length": t.uint16_t,
            "parameter_id": NetworkParameter,
        },
    ),
    CommandId.zigbee_green_power: (
        None,
        {
            "status": Status,
            "frame_length": t.uint16_t,
            "payload_length": t.uint16_t,
            "reserved": t.LongOctetString,
        },
    ),
}


class Deconz:
    """deCONZ API class."""

    def __init__(self, app: Callable, device_config: dict[str, Any]):
        """Init instance."""
        self._app = app

        # [seq][cmd_id] = [fut1, fut2, ...]
        self._awaiting = collections.defaultdict(lambda: collections.defaultdict(list))
        self._mismatched_response_timers: dict[int, asyncio.TimerHandle] = {}
        self._command_lock = PriorityLock()
        self._config = device_config
        self._device_state = DeviceState(
            network_state=NetworkState2.OFFLINE,
            device_state=(
                DeviceStateFlags.APSDE_DATA_CONFIRM
                | DeviceStateFlags.APSDE_DATA_INDICATION
            ),
        )

        self._free_slots_available_event = asyncio.Event()
        self._free_slots_available_event.set()

        self._data_poller_event = asyncio.Event()
        self._data_poller_event.set()
        self._data_poller_task: asyncio.Task | None = None

        self._seq = 1
        self._protocol_version = 0
        self._firmware_version = FirmwareVersion(0)
        self._uart: zigpy_deconz.uart.Gateway | None = None

    @property
    def firmware_version(self) -> FirmwareVersion:
        """Return ConBee firmware version."""
        return self._firmware_version

    @property
    def network_state(self) -> NetworkState:
        """Return current network state."""
        return self._device_state.network_state

    @property
    def protocol_version(self) -> int:
        """Protocol Version."""
        return self._protocol_version

    async def connect(self) -> None:
        assert self._uart is None

        self._uart = await zigpy_deconz.uart.connect(self._config, self)

        try:
            await self.version()
            device_state_rsp = await self.send_command(CommandId.device_state)
        except Exception:
            await self.disconnect()
            self._uart = None
            raise

        self._device_state = device_state_rsp["device_state"]

        self._data_poller_task = asyncio.create_task(self._data_poller())

    def connection_lost(self, exc: Exception | None) -> None:
        """Lost serial connection."""
        if self._app is not None:
            self._app.connection_lost(exc)

    async def disconnect(self):
        if self._data_poller_task is not None:
            self._data_poller_task.cancel()
            self._data_poller_task = None

        if self._uart is not None:
            await self._uart.disconnect()
            self._uart = None

        self._app = None

    def _get_command_priority(self, command: Command) -> int:
        return {
            # The watchdog is fed using `write_parameter` and `get_device_state` so they
            # must take priority
            CommandId.write_parameter: 999,
            CommandId.device_state: 999,
            # APS data requests are retried and can be deprioritized
            CommandId.aps_data_request: -1,
        }.get(command.command_id, 0)

    async def send_command(self, cmd, **kwargs) -> Any:
        while True:
            try:
                return await self._command(cmd, **kwargs)
            except MismatchedResponseError as exc:
                LOGGER.debug("Firmware responded incorrectly (%s), retrying", exc)

    async def _command(self, cmd, **kwargs):
        payload = []
        tx_schema, _ = COMMAND_SCHEMAS[cmd]
        trailing_optional = False

        for name, param_type in tx_schema.items():
            if isinstance(param_type, int):
                if name not in kwargs:
                    # Default value
                    value = param_type.serialize()
                else:
                    value = type(param_type)(kwargs[name]).serialize()
            elif name in ("frame_length", "payload_length"):
                value = param_type
            elif kwargs.get(name) is None:
                trailing_optional = True
                value = None
            elif not isinstance(kwargs[name], param_type):
                value = param_type(kwargs[name]).serialize()
            else:
                value = kwargs[name].serialize()

            if value is None:
                continue

            if trailing_optional:
                raise ValueError(
                    f"Command {cmd} with kwargs {kwargs}"
                    f" has non-trailing optional argument"
                )

            payload.append(value)

        if PAYLOAD_LENGTH in payload:
            payload = t.list_replace(
                lst=payload,
                old=PAYLOAD_LENGTH,
                new=t.uint16_t(
                    sum(len(p) for p in payload[payload.index(PAYLOAD_LENGTH) + 1 :])
                ).serialize(),
            )

        if FRAME_LENGTH in payload:
            payload = t.list_replace(
                lst=payload,
                old=FRAME_LENGTH,
                new=t.uint16_t(
                    2 + sum(len(p) if p is not FRAME_LENGTH else 2 for p in payload)
                ).serialize(),
            )

        command = Command(
            command_id=cmd,
            seq=None,
            payload=b"".join(payload),
        )

        if self._uart is None:
            # connection was lost
            raise CommandError(
                "API is not running",
                status=Status.ERROR,
                command=command,
            )

        async with self._command_lock(priority=self._get_command_priority(command)):
            seq = self._seq
            self._seq = (self._seq % 255) + 1

            fut = asyncio.Future()
            self._awaiting[seq][cmd].append(fut)

            try:
                LOGGER.debug("Sending %s%s (seq=%s)", cmd, kwargs, seq)
                self._uart.send(command.replace(seq=seq).serialize())

                async with asyncio_timeout(COMMAND_TIMEOUT):
                    return await fut
            except asyncio.TimeoutError:
                LOGGER.debug("No response to '%s' command with seq %d", cmd, seq)
                raise
            finally:
                self._awaiting[seq][cmd].remove(fut)

    def data_received(self, data: bytes) -> None:
        command, _ = Command.deserialize(data)

        if command.command_id not in COMMAND_SCHEMAS:
            LOGGER.warning("Unknown command received: %s", command)
            return

        _, rx_schema = COMMAND_SCHEMAS[command.command_id]

        fut = None
        wrong_fut_cmd_id = None

        try:
            fut = self._awaiting[command.seq][command.command_id][0]
        except IndexError:
            # XXX: The firmware can sometimes respond with the wrong response. Find the
            # future associated with it so we can throw an appropriate error.
            for cmd_id, futs in self._awaiting[command.seq].items():
                if futs:
                    fut = futs[0]
                    wrong_fut_cmd_id = cmd_id
                    break

        try:
            params, rest = t.deserialize_dict(command.payload, rx_schema)
        except Exception:
            LOGGER.debug("Failed to parse command %s", command, exc_info=True)

            if fut is not None and not fut.done():
                fut.set_exception(
                    ParsingError(
                        f"Failed to parse command: {command}",
                        status=Status.ERROR,
                        command=command,
                    )
                )

            return

        if rest:
            LOGGER.debug("Unparsed data remains after frame: %s, %s", command, rest)

        assert params["frame_length"] == len(data)

        if "payload_length" in params:
            running_length = itertools.accumulate(
                len(v.serialize()) if v is not None else 0 for v in params.values()
            )
            length_at_param = dict(zip(params.keys(), running_length))

            assert (
                len(data) - length_at_param["payload_length"] - 2
                == params["payload_length"]
            )

        LOGGER.debug(
            "Received command %s%s (seq %d)", command.command_id, params, command.seq
        )
        status = params["status"]

        exc = None

        # Make sure to clear any pending mismatched response timers
        if command.seq in self._mismatched_response_timers:
            LOGGER.debug("Clearing existing mismatched response timer")
            self._mismatched_response_timers.pop(command.seq).cancel()

        if wrong_fut_cmd_id is not None:
            LOGGER.debug(
                "Mismatched response, triggering error in %0.2fs",
                MISMATCHED_RESPONSE_TIMEOUT,
            )
            # The firmware *sometimes* responds with the correct response later
            self._mismatched_response_timers[
                command.seq
            ] = asyncio.get_event_loop().call_later(
                MISMATCHED_RESPONSE_TIMEOUT,
                fut.set_exception,
                MismatchedResponseError(
                    command.command_id,
                    params,
                    (
                        f"Response is mismatched! Sent {wrong_fut_cmd_id},"
                        f" received {command.command_id}"
                    ),
                ),
            )

            # Make sure we do not resolve the future
            fut = None
        elif status != Status.SUCCESS:
            exc = CommandError(
                f"{command.command_id}, status: {status}",
                status=status,
                command=command,
            )

        if fut is not None:
            try:
                if exc is None:
                    fut.set_result(params)
                else:
                    fut.set_exception(exc)
            except asyncio.InvalidStateError:
                LOGGER.debug(
                    "Duplicate or delayed response for seq %s (awaiting %s)",
                    command.seq,
                    self._awaiting[command.seq],
                )

            if exc is not None:
                return

        if handler := getattr(self, f"_handle_{command.command_id.name}", None):
            handler_params = {
                k: v
                for k, v in params.items()
                if k not in ("frame_length", "payload_length")
            }

            # Queue up the callback within the event loop
            asyncio.get_running_loop().call_soon(lambda: handler(**handler_params))

    @restart_forever
    async def _data_poller(self):
        while True:
            await self._data_poller_event.wait()
            self._data_poller_event.clear()

            if self._device_state.network_state == NetworkState2.OFFLINE:
                continue

            # Poll data indication
            if (
                DeviceStateFlags.APSDE_DATA_INDICATION
                in self._device_state.device_state
            ):
                # Old Conbee I firmware has an addressing bug for incoming multicasts
                if (
                    self.protocol_version >= 0x010B
                    and self.firmware_version.platform == FirmwarePlatform.Conbee
                ):
                    flags = t.DataIndicationFlags.Include_Both_NWK_And_IEEE
                else:
                    flags = t.DataIndicationFlags.Always_Use_NWK_Source_Addr

                rsp = await self.send_command(
                    CommandId.aps_data_indication, flags=flags
                )
                self._handle_device_state_changed(
                    status=rsp["status"], device_state=rsp["device_state"]
                )

                self._app.packet_received(
                    ZigbeePacket(
                        src=rsp["src_addr"].as_zigpy_type(),
                        src_ep=rsp["src_ep"],
                        dst=rsp["dst_addr"].as_zigpy_type(),
                        dst_ep=rsp["dst_ep"],
                        tsn=None,
                        profile_id=rsp["profile_id"],
                        cluster_id=rsp["cluster_id"],
                        data=SerializableBytes(rsp["asdu"]),
                        lqi=rsp["lqi"],
                        rssi=rsp["rssi"],
                    )
                )

            # Poll data confirm
            if DeviceStateFlags.APSDE_DATA_CONFIRM in self._device_state.device_state:
                rsp = await self.send_command(CommandId.aps_data_confirm)

                self._app.handle_tx_confirm(rsp["request_id"], rsp["confirm_status"])
                self._handle_device_state_changed(
                    status=rsp["status"], device_state=rsp["device_state"]
                )

    def _handle_device_state_changed(
        self,
        status: t.Status,
        device_state: DeviceState,
        reserved: t.uint8_t = 0,
    ) -> None:
        if device_state.network_state != self.network_state:
            LOGGER.debug(
                "Network device_state transition: %s -> %s",
                self.network_state.name,
                device_state.network_state.name,
            )

        if (
            DeviceStateFlags.APSDE_DATA_REQUEST_FREE_SLOTS_AVAILABLE
            in device_state.device_state
        ):
            self._free_slots_available_event.set()
        else:
            self._free_slots_available_event.clear()

        self._device_state = device_state
        self._data_poller_event.set()

    def _handle_device_state(
        self,
        status: t.Status,
        device_state: DeviceState,
        reserved1: t.uint8_t,
        reserved2: t.uint8_t,
    ) -> None:
        if (
            self.firmware_version.platform == FirmwarePlatform.Conbee_III
            and self.firmware_version == 0x26450900
        ):
            # Initial Conbee III firmware used the wrong command to notify of network
            # state changes
            self._handle_device_state_changed(status=status, device_state=device_state)

    async def version(self):
        self._protocol_version = await self.read_parameter(
            NetworkParameter.protocol_version
        )

        version_rsp = await self.send_command(CommandId.version, reserved=0)
        self._firmware_version = version_rsp["version"]

        return self.firmware_version

    async def read_parameter(
        self, parameter_id: NetworkParameter, parameter: Any = None
    ) -> Any:
        read_param_type, write_param_type = NETWORK_PARAMETER_TYPES[parameter_id]

        if parameter is None:
            value = t.Bytes(b"")
        else:
            value = read_param_type(parameter).serialize()

        rsp = await self.send_command(
            CommandId.read_parameter,
            parameter_id=parameter_id,
            parameter=value,
        )

        assert rsp["parameter_id"] == parameter_id

        result, _ = write_param_type.deserialize(rsp["parameter"])
        LOGGER.debug("Read parameter %s(%s)=%r", parameter_id.name, parameter, result)

        return result

    async def write_parameter(
        self, parameter_id: NetworkParameter, parameter: Any
    ) -> None:
        read_param_type, write_param_type = NETWORK_PARAMETER_TYPES[parameter_id]
        await self.send_command(
            CommandId.write_parameter,
            parameter_id=parameter_id,
            parameter=write_param_type(parameter).serialize(),
        )

    async def aps_data_request(
        self,
        req_id,
        dst_addr_ep,
        profile,
        cluster,
        src_ep,
        aps_payload,
        *,
        relays=None,
        tx_options=t.DeconzTransmitOptions.USE_NWK_KEY_SECURITY,
        radius=0,
    ) -> None:
        flags = t.DeconzSendDataFlags.NONE

        # https://github.com/zigpy/zigpy-deconz/issues/180#issuecomment-1017932865
        if relays is not None:
            # There is a max of 9 relays
            assert len(relays) <= 9
            flags |= t.DeconzSendDataFlags.RELAYS

        if not self._free_slots_available_event.is_set():
            LOGGER.debug("Waiting for free slots to become available")
            await self._free_slots_available_event.wait()

        rsp = await self.send_command(
            CommandId.aps_data_request,
            request_id=req_id,
            flags=flags,
            dst=dst_addr_ep,
            profile_id=profile,
            cluster_id=cluster,
            src_ep=src_ep,
            asdu=aps_payload,
            tx_options=tx_options,
            radius=radius,
            relays=relays,
        )

        self._handle_device_state_changed(
            status=rsp["status"], device_state=rsp["device_state"]
        )

    async def get_device_state(self) -> DeviceState:
        rsp = await self.send_command(CommandId.device_state)

        return rsp["device_state"]

    async def change_network_state(self, new_state: NetworkState) -> None:
        await self.send_command(CommandId.change_network_state, network_state=new_state)

    async def add_neighbour(
        self, nwk: t.NWK, ieee: t.EUI64, mac_capability_flags: t.uint8_t
    ) -> None:
        try:
            await self.send_command(
                CommandId.update_neighbor,
                action=UpdateNeighborAction.ADD,
                nwk=nwk,
                ieee=ieee,
                mac_capability_flags=mac_capability_flags,
            )
        except ParsingError as exc:
            # Older Conbee III firmwares send back an invalid response
            status = Status(exc.command.payload[0])

            if status != Status.SUCCESS:
                raise CommandError(
                    f"{exc.command.command_id}, status: {status}",
                    status=status,
                    command=exc.command,
                ) from exc
