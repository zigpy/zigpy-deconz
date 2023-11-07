"""deCONZ serial protocol API."""

from __future__ import annotations

import asyncio
import itertools
import logging
import sys
from typing import Any, Callable

if sys.version_info[:2] < (3, 11):
    from async_timeout import timeout as asyncio_timeout  # pragma: no cover
else:
    from asyncio import timeout as asyncio_timeout  # pragma: no cover

from zigpy.config import CONF_DEVICE_PATH
from zigpy.types import APSStatus, Bool, Channels, KeyData, Struct
from zigpy.zdo.types import SimpleDescriptor

from zigpy_deconz.exception import APIException, CommandError
import zigpy_deconz.types as t
import zigpy_deconz.uart
from zigpy_deconz.utils import restart_forever

LOGGER = logging.getLogger(__name__)

COMMAND_TIMEOUT = 1.8
PROBE_TIMEOUT = 2
MIN_PROTO_VERSION = 0x010B
REQUEST_RETRY_DELAYS = (0.5, 1.0, 1.5, None)

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
    add_neighbour = 0x1D
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
    ep_id: t.uint8_t
    descriptor: SimpleDescriptor


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


TX_COMMANDS = {
    CommandId.add_neighbour: {
        "status": Status.SUCCESS,
        "frame_length": FRAME_LENGTH,
        "payload_length": PAYLOAD_LENGTH,
        "unknown": t.uint8_t,
        "nwk": t.NWK,
        "ieee": t.EUI64,
        "mac_capability_flags": t.uint8_t,
    },
    CommandId.aps_data_confirm: {
        "status": Status.SUCCESS,
        "frame_length": FRAME_LENGTH,
        "payload_length": PAYLOAD_LENGTH,
    },
    CommandId.aps_data_indication: {
        "status": Status.SUCCESS,
        "frame_length": FRAME_LENGTH,
        "payload_length": PAYLOAD_LENGTH,
        "flags": t.DataIndicationFlags,
    },
    CommandId.aps_data_request: {
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
    CommandId.change_network_state: {
        "status": Status.SUCCESS,
        "frame_length": FRAME_LENGTH,
        # "payload_length": PAYLOAD_LENGTH,
        "network_state": NetworkState,
    },
    CommandId.device_state: {
        "status": Status.SUCCESS,
        "frame_length": FRAME_LENGTH,
        # "payload_length": PAYLOAD_LENGTH,
        "reserved1": t.uint8_t(0),
        "reserved2": t.uint8_t(0),
        "reserved3": t.uint8_t(0),
    },
    CommandId.read_parameter: {
        "status": Status.SUCCESS,
        "frame_length": FRAME_LENGTH,
        "payload_length": PAYLOAD_LENGTH,
        "parameter_id": NetworkParameter,
        "parameter": t.Bytes,
    },
    CommandId.version: {
        "status": Status.SUCCESS,
        "frame_length": FRAME_LENGTH,
        # "payload_length": PAYLOAD_LENGTH,
        "reserved": t.uint32_t(0),
    },
    CommandId.write_parameter: {
        "status": Status.SUCCESS,
        "frame_length": FRAME_LENGTH,
        "payload_length": PAYLOAD_LENGTH,
        "parameter_id": NetworkParameter,
        "parameter": t.Bytes,
    },
}

RX_COMMANDS = {
    CommandId.add_neighbour: (
        {
            "status": Status,
            "frame_length": t.uint16_t,
            "payload_length": t.uint16_t,
            "unknown": t.uint8_t,
            "nwk": t.NWK,
            "ieee": t.EUI64,
            "mac_capability_flags": t.uint8_t,
        },
        True,
    ),
    CommandId.aps_data_confirm: (
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
        True,
    ),
    CommandId.aps_data_indication: (
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
        True,
    ),
    CommandId.aps_data_request: (
        {
            "status": Status,
            "frame_length": t.uint16_t,
            "payload_length": t.uint16_t,
            "device_state": DeviceState,
            "request_id": t.uint8_t,
        },
        True,
    ),
    CommandId.change_network_state: (
        {
            "status": Status,
            "frame_length": t.uint16_t,
            # "payload_length": t.uint16_t,
            "network_state": NetworkState,
        },
        True,
    ),
    CommandId.device_state: (
        {
            "status": Status,
            "frame_length": t.uint16_t,
            # "payload_length": t.uint16_t,
            "device_state": DeviceState,
            "reserved1": t.uint8_t,
            "reserved2": t.uint8_t,
        },
        True,
    ),
    CommandId.device_state_changed: (
        {
            "status": Status,
            "frame_length": t.uint16_t,
            # "payload_length": t.uint16_t,
            "device_state": DeviceState,
            "reserved": t.uint8_t,
        },
        False,
    ),
    CommandId.mac_poll: (
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
        False,
    ),
    CommandId.read_parameter: (
        {
            "status": Status,
            "frame_length": t.uint16_t,
            "payload_length": t.uint16_t,
            "parameter_id": NetworkParameter,
            "parameter": t.Bytes,
        },
        True,
    ),
    CommandId.mac_beacon_indication: (
        {
            "status": Status,
            "frame_length": t.uint16_t,
            "payload_length": t.uint16_t,
            "src_addr": t.uint16_t,
            "pan_id": t.uint16_t,
            "channel": t.uint8_t,
            "flags": t.uint8_t,
            "update_id": t.uint8_t,
            "data": t.Bytes,
        },
        False,
    ),
    CommandId.version: (
        {
            "status": Status,
            "frame_length": t.uint16_t,
            # "payload_length": t.uint16_t,
            "version": t.uint32_t,
        },
        True,
    ),
    CommandId.write_parameter: (
        {
            "status": Status,
            "frame_length": t.uint16_t,
            "payload_length": t.uint16_t,
            "parameter_id": NetworkParameter,
        },
        True,
    ),
    CommandId.zigbee_green_power: (
        {
            "status": Status,
            "frame_length": t.uint16_t,
            "payload_length": t.uint16_t,
            "reserved": t.LongOctetString,
        },
        False,
    ),
}


class Deconz:
    """deCONZ API class."""

    def __init__(self, app: Callable, device_config: dict[str, Any]):
        """Init instance."""
        self._app = app
        self._awaiting = {}
        self._command_lock = asyncio.Lock()
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
        self._proto_ver: int | None = None
        self._firmware_version: int | None = None
        self._uart: zigpy_deconz.uart.Gateway | None = None

    @property
    def firmware_version(self) -> int | None:
        """Return ConBee firmware version."""
        return self._firmware_version

    @property
    def network_state(self) -> NetworkState:
        """Return current network state."""
        return self._device_state.network_state

    @property
    def protocol_version(self) -> int | None:
        """Protocol Version."""
        return self._proto_ver

    async def connect(self) -> None:
        assert self._uart is None
        self._uart = await zigpy_deconz.uart.connect(self._config, self)
        await self._command(CommandId.device_state)

        self._data_poller_task = asyncio.create_task(self._data_poller())

    def connection_lost(self, exc: Exception) -> None:
        """Lost serial connection."""
        LOGGER.debug(
            "Serial %r connection lost unexpectedly: %r",
            self._config[CONF_DEVICE_PATH],
            exc,
        )

        if self._app is not None:
            self._app.connection_lost(exc)

    def close(self):
        self._app = None

        if self._data_poller_task is not None:
            self._data_poller_task.cancel()
            self._data_poller_task = None

        if self._uart is not None:
            self._uart.close()
            self._uart = None

    async def _command(self, cmd, **kwargs):
        payload = []
        schema = TX_COMMANDS[cmd]
        trailing_optional = False

        for name, param_type in schema.items():
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
            raise CommandError(Status.ERROR, "API is not running")

        async with self._command_lock:
            seq = self._seq = (self._seq % 255) + 1

            LOGGER.debug("Sending %s%s (seq=%s)", cmd, kwargs, seq)
            self._uart.send(command.replace(seq=seq).serialize())

            fut = asyncio.Future()
            self._awaiting[seq] = (fut, cmd)

            try:
                async with asyncio_timeout(COMMAND_TIMEOUT):
                    return await fut
            except asyncio.TimeoutError:
                LOGGER.warning(
                    "No response to '%s' command with seq id '0x%02x'", cmd, seq
                )
                self._awaiting.pop(seq, None)
                raise

    def data_received(self, data: bytes) -> None:
        command, _ = Command.deserialize(data)

        if command.command_id not in RX_COMMANDS:
            LOGGER.warning("Unknown command received: %s", command)
            return

        schema, solicited = RX_COMMANDS[command.command_id]

        if solicited and command.seq in self._awaiting:
            fut, cmd = self._awaiting.pop(command.seq)
        else:
            fut, cmd = None, None

        try:
            params, rest = t.deserialize_dict(command.payload, schema)

            if rest:
                LOGGER.debug("Unparsed data remains after frame: %s, %s", command, rest)
        except Exception:
            LOGGER.warning("Failed to parse command %s", command, exc_info=True)

            if fut is not None and not fut.done():
                fut.set_exception(
                    APIException(f"Failed to deserialize command: {command}")
                )

            return

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

        if status != Status.SUCCESS:
            try:
                fut.set_exception(
                    CommandError(status, f"{command.command_id}, status: {status}")
                )
            except asyncio.InvalidStateError:
                LOGGER.warning(
                    "Duplicate or delayed response for 0x:%02x sequence",
                    command.seq,
                )
            return

        if fut is not None:
            if cmd != command.command_id:
                LOGGER.warning(
                    "UNEXPECTED RESPONSE TYPE???? %s != %s", cmd, command.command_id
                )

            try:
                fut.set_result(params)
            except asyncio.InvalidStateError:
                LOGGER.warning(
                    "Duplicate or delayed response for 0x:%02x sequence", command.seq
                )

        if handler := getattr(self, f"_handle_{command.command_id.name}", None):
            handler_params = {
                k: v
                for k, v in params.items()
                if k not in ("frame_length", "payload_length")
            }

            # Queue up the callback within the event loop
            asyncio.get_running_loop().call_soon(lambda: handler(**handler_params))

    async def read_parameter(
        self, parameter_id: NetworkParameter, parameter: Any = None
    ) -> Any:
        read_param_type, write_param_type = NETWORK_PARAMETER_TYPES[parameter_id]

        if parameter is None:
            value = t.Bytes(b"")
        else:
            value = read_param_type(parameter).serialize()

        rsp = await self._command(
            CommandId.read_parameter,
            parameter_id=parameter_id,
            parameter=value,
        )

        assert rsp["parameter_id"] == parameter_id

        result, _ = write_param_type.deserialize(rsp["parameter"])
        LOGGER.debug("Read parameter %s(%s)=%r", parameter_id.name, parameter, result)

        return result

    def reconnect(self):
        """Reconnect using saved parameters."""
        LOGGER.debug("Reconnecting '%s' serial port", self._config[CONF_DEVICE_PATH])
        return self.connect()

    async def write_parameter(
        self, parameter_id: NetworkParameter, parameter: Any
    ) -> None:
        read_param_type, write_param_type = NETWORK_PARAMETER_TYPES[parameter_id]
        rsp = await self._command(
            CommandId.write_parameter,
            parameter_id=parameter_id,
            parameter=write_param_type(parameter).serialize(),
        )

        assert rsp["status"] == Status.SUCCESS

    async def version(self):
        self._proto_ver = await self.read_parameter(NetworkParameter.protocol_version)

        version_rsp = await self._command(CommandId.version, reserved=0)
        self._firmware_version = version_rsp["version"]

        return self.firmware_version

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
        if relays:
            # There is a max of 9 relays
            assert len(relays) <= 9
            flags |= t.DeconzSendDataFlags.RELAYS

        if not self._free_slots_available_event.is_set():
            LOGGER.debug("Waiting for free slots to become available")
            await self._free_slots_available_event.wait()

        for delay in REQUEST_RETRY_DELAYS:
            try:
                rsp = await self._command(
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
            except CommandError as ex:
                LOGGER.debug("'aps_data_request' failure: %s", ex)
                if delay is None or ex.status != Status.BUSY:
                    raise

                LOGGER.debug("retrying 'aps_data_request' in %ss", delay)
                await asyncio.sleep(delay)
            else:
                self._handle_device_state_changed(
                    status=rsp["status"], device_state=rsp["device_state"]
                )
                return

    @restart_forever
    async def _data_poller(self):
        while True:
            await self._data_poller_event.wait()
            self._data_poller_event.clear()

            # Poll data indication
            if (
                self._device_state.network_state != NetworkState2.OFFLINE
                and DeviceStateFlags.APSDE_DATA_INDICATION
                in self._device_state.device_state
            ):
                if (
                    self.protocol_version is not None
                    and self.firmware_version is not None
                    and self.protocol_version >= MIN_PROTO_VERSION
                    and (self.firmware_version & 0x0000FF00) == 0x00000500
                ):
                    flags = t.DataIndicationFlags.Include_Both_NWK_And_IEEE
                else:
                    flags = t.DataIndicationFlags.Always_Use_NWK_Source_Addr

                rsp = await self._command(CommandId.aps_data_indication, flags=flags)
                self._handle_device_state_changed(
                    status=rsp["status"], device_state=rsp["device_state"]
                )

                self._app.handle_rx(
                    src=rsp["src_addr"],
                    src_ep=rsp["src_ep"],
                    dst=rsp["dst_addr"],
                    dst_ep=rsp["dst_ep"],
                    profile_id=rsp["profile_id"],
                    cluster_id=rsp["cluster_id"],
                    data=rsp["asdu"],
                    lqi=rsp["lqi"],
                    rssi=rsp["rssi"],
                )

            # Poll data confirm
            if (
                self._device_state.network_state != NetworkState2.OFFLINE
                and DeviceStateFlags.APSDE_DATA_CONFIRM
                in self._device_state.device_state
            ):
                rsp = await self._command(CommandId.aps_data_confirm)

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

        self._device_state = device_state
        self._data_poller_event.set()

        if (
            DeviceStateFlags.APSDE_DATA_REQUEST_FREE_SLOTS_AVAILABLE
            in device_state.device_state
        ):
            self._free_slots_available_event.set()
        else:
            LOGGER.debug("Data request queue full.")
            self._free_slots_available_event.clear()
