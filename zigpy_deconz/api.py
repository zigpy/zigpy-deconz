"""deCONZ serial protocol API."""

import asyncio
import binascii
import enum
import functools
import logging
from typing import Any, Callable, Dict, Optional, Tuple

import serial
from zigpy.config import CONF_DEVICE_PATH
import zigpy.exceptions
from zigpy.types import APSStatus, Bool, Channels

from zigpy_deconz.exception import APIException, CommandError
import zigpy_deconz.types as t
import zigpy_deconz.uart

LOGGER = logging.getLogger(__name__)

COMMAND_TIMEOUT = 1.8
PROBE_TIMEOUT = 2
MIN_PROTO_VERSION = 0x010B


class Status(t.uint8_t, enum.Enum):
    SUCCESS = 0
    FAILURE = 1
    BUSY = 2
    TIMEOUT = 3
    UNSUPPORTED = 4
    ERROR = 5
    NO_NETWORK = 6
    INVALID_VALUE = 7


class DeviceState(enum.IntFlag):
    APSDE_DATA_CONFIRM = 0x04
    APSDE_DATA_INDICATION = 0x08
    CONF_CHANGED = 0x10
    APSDE_DATA_REQUEST_SLOTS_AVAILABLE = 0x20

    @classmethod
    def deserialize(cls, data) -> Tuple["DeviceState", bytes]:
        """Deserialize DevceState."""
        state, data = t.uint8_t.deserialize(data)
        return cls(state), data

    def serialize(self) -> bytes:
        """Serialize data."""
        return t.uint8_t(self).serialize()

    @property
    def network_state(self) -> "NetworkState":
        """Return network state."""
        return NetworkState(self & 0x03)


class NetworkState(t.uint8_t, enum.Enum):
    OFFLINE = 0
    JOINING = 1
    CONNECTED = 2
    LEAVING = 3


class Command(t.uint8_t, enum.Enum):
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
    simplified_beacon = 0x1F


class TXStatus(t.uint8_t, enum.Enum):
    SUCCESS = 0x00

    @classmethod
    def _missing_(cls, value):
        chained = APSStatus(value)
        status = t.uint8_t.__new__(cls, chained.value)
        status._name_ = chained.name
        status._value_ = value
        return status


TX_COMMANDS = {
    Command.add_neighbour: (t.uint16_t, t.uint8_t, t.NWK, t.EUI64, t.uint8_t),
    Command.aps_data_confirm: (t.uint16_t,),
    Command.aps_data_indication: (t.uint16_t, t.uint8_t),
    Command.aps_data_request: (
        t.uint16_t,
        t.uint8_t,
        t.uint8_t,
        t.DeconzAddressEndpoint,
        t.uint16_t,
        t.uint16_t,
        t.uint8_t,
        t.LVBytes,
        t.uint8_t,
        t.uint8_t,
    ),
    Command.change_network_state: (t.uint8_t,),
    Command.device_state: (t.uint8_t, t.uint8_t, t.uint8_t),
    Command.read_parameter: (t.uint16_t, t.uint8_t, t.Bytes),
    Command.version: (t.uint32_t,),
    Command.write_parameter: (t.uint16_t, t.uint8_t, t.Bytes),
}

RX_COMMANDS = {
    Command.add_neighbour: ((t.uint16_t, t.uint8_t, t.NWK, t.EUI64, t.uint8_t), True),
    Command.aps_data_confirm: (
        (
            t.uint16_t,
            DeviceState,
            t.uint8_t,
            t.DeconzAddressEndpoint,
            t.uint8_t,
            TXStatus,
            t.uint8_t,
            t.uint8_t,
            t.uint8_t,
            t.uint8_t,
        ),
        True,
    ),
    Command.aps_data_indication: (
        (
            t.uint16_t,
            DeviceState,
            t.DeconzAddress,
            t.uint8_t,
            t.DeconzAddress,
            t.uint8_t,
            t.uint16_t,
            t.uint16_t,
            t.LVBytes,
            t.uint8_t,
            t.uint8_t,
            t.uint8_t,
            t.uint8_t,
            t.uint8_t,
            t.uint8_t,
            t.uint8_t,
            t.int8s,
        ),
        True,
    ),
    Command.aps_data_request: ((t.uint16_t, DeviceState, t.uint8_t), True),
    Command.change_network_state: ((t.uint8_t,), True),
    Command.device_state: ((DeviceState, t.uint8_t, t.uint8_t), True),
    Command.device_state_changed: ((DeviceState, t.uint8_t), False),
    Command.mac_poll: ((t.uint16_t, t.DeconzAddress, t.uint8_t, t.int8s), False),
    Command.read_parameter: ((t.uint16_t, t.uint8_t, t.Bytes), True),
    Command.simplified_beacon: (
        (t.uint16_t, t.uint16_t, t.uint16_t, t.uint8_t, t.uint8_t, t.uint8_t),
        False,
    ),
    Command.version: ((t.uint32_t,), True),
    Command.write_parameter: ((t.uint16_t, t.uint8_t), True),
    Command.zigbee_green_power: ((t.LVBytes,), False),
}


class NetworkParameter(t.uint8_t, enum.Enum):
    mac_address = 0x01
    nwk_panid = 0x05
    nwk_address = 0x07
    nwk_extended_panid = 0x08
    aps_designed_coordinator = 0x09
    channel_mask = 0x0A
    aps_extended_panid = 0x0B
    trust_center_address = 0x0E
    security_mode = 0x10
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


NETWORK_PARAMETER_SCHEMA = {
    NetworkParameter.mac_address: (t.EUI64,),
    NetworkParameter.nwk_panid: (t.PanId,),
    NetworkParameter.nwk_address: (t.NWK,),
    NetworkParameter.nwk_extended_panid: (t.ExtendedPanId,),
    NetworkParameter.aps_designed_coordinator: (t.uint8_t,),
    NetworkParameter.channel_mask: (Channels,),
    NetworkParameter.aps_extended_panid: (t.ExtendedPanId,),
    NetworkParameter.trust_center_address: (t.EUI64,),
    NetworkParameter.security_mode: (t.uint8_t,),
    NetworkParameter.use_predefined_nwk_panid: (Bool,),
    NetworkParameter.network_key: (t.uint8_t, t.Key),
    NetworkParameter.link_key: (t.EUI64, t.Key),
    NetworkParameter.current_channel: (t.uint8_t,),
    NetworkParameter.permit_join: (t.uint8_t,),
    NetworkParameter.protocol_version: (t.uint16_t,),
    NetworkParameter.nwk_update_id: (t.uint8_t,),
    NetworkParameter.watchdog_ttl: (t.uint32_t,),
    NetworkParameter.nwk_frame_counter: (t.uint32_t,),
    NetworkParameter.app_zdp_response_handling: (t.uint16_t,),
}


class Deconz:
    """deCONZ API class."""

    def __init__(self, app: Callable, device_config: Dict[str, Any]):
        """Init instance."""
        self._app = app
        self._aps_data_ind_flags: int = 0x01
        self._awaiting = {}
        self._command_lock = asyncio.Lock()
        self._config = device_config
        self._conn_lost_task: Optional[asyncio.Task] = None
        self._data_indication: bool = False
        self._data_confirm: bool = False
        self._device_state = DeviceState(NetworkState.OFFLINE)
        self._seq = 1
        self._proto_ver: Optional[int] = None
        self._firmware_version: Optional[int] = None
        self._uart: Optional[zigpy_deconz.uart.Gateway] = None

    @property
    def firmware_version(self) -> Optional[int]:
        """Return ConBee firmware version."""
        return self._firmware_version

    @property
    def network_state(self) -> NetworkState:
        """Return current network state."""
        return self._device_state.network_state

    @property
    def protocol_version(self) -> Optional[int]:
        """Protocol Version."""
        return self._proto_ver

    async def connect(self) -> None:
        assert self._uart is None
        self._uart = await zigpy_deconz.uart.connect(self._config, self)

    def connection_lost(self, exc: Exception) -> None:
        """Lost serial connection."""
        LOGGER.warning(
            "Serial '%s' connection lost unexpectedly: %s",
            self._config[CONF_DEVICE_PATH],
            exc,
        )
        self._uart = None
        if self._conn_lost_task and not self._conn_lost_task.done():
            self._conn_lost_task.cancel()
        self._conn_lost_task = asyncio.ensure_future(self._connection_lost())

    async def _connection_lost(self) -> None:
        """Reconnect serial port."""
        try:
            await self._reconnect_till_done()
        except asyncio.CancelledError:
            LOGGER.debug("Cancelling reconnection attempt")

    async def _reconnect_till_done(self) -> None:
        attempt = 1
        while True:
            try:
                await asyncio.wait_for(self.reconnect(), timeout=10)
                break
            except (asyncio.TimeoutError, OSError) as exc:
                wait = 2 ** min(attempt, 5)
                attempt += 1
                LOGGER.debug(
                    "Couldn't re-open '%s' serial port, retrying in %ss: %s",
                    self._config[CONF_DEVICE_PATH],
                    wait,
                    str(exc),
                )
                await asyncio.sleep(wait)

        LOGGER.debug(
            "Reconnected '%s' serial port after %s attempts",
            self._config[CONF_DEVICE_PATH],
            attempt,
        )

    def close(self):
        if self._uart:
            self._uart.close()
            self._uart = None

    async def _command(self, cmd, *args):
        if self._uart is None:
            # connection was lost
            raise CommandError(Status.ERROR, "API is not running")
        async with self._command_lock:
            LOGGER.debug("Command %s %s", cmd, args)
            data, seq = self._api_frame(cmd, *args)
            self._uart.send(data)
            fut = asyncio.Future()
            self._awaiting[seq] = fut
            try:
                return await asyncio.wait_for(fut, timeout=COMMAND_TIMEOUT)
            except asyncio.TimeoutError:
                LOGGER.warning(
                    "No response to '%s' command with seq id '0x%02x'", cmd, seq
                )
                self._awaiting.pop(seq, None)
                raise

    def _api_frame(self, cmd, *args):
        schema = TX_COMMANDS[cmd]
        d = t.serialize(args, schema)
        data = t.uint8_t(cmd).serialize()
        self._seq = (self._seq % 255) + 1
        data += t.uint8_t(self._seq).serialize()
        data += t.uint8_t(0).serialize()
        data += t.uint16_t(len(d) + 5).serialize()
        data += d
        return data, self._seq

    def data_received(self, data):
        try:
            command = Command(data[0])
            schema, solicited = RX_COMMANDS[command]
        except ValueError:
            LOGGER.debug("Unknown command received: 0x%02x", data[0])
            return
        seq = data[1]
        try:
            status = Status(data[2])
        except ValueError:
            status = data[2]

        fut = None
        if solicited and seq in self._awaiting:
            fut = self._awaiting.pop(seq)
            if status != Status.SUCCESS:
                try:
                    fut.set_exception(
                        CommandError(status, "%s, status: %s" % (command, status))
                    )
                except asyncio.InvalidStateError:
                    LOGGER.warning(
                        "Duplicate or delayed response for 0x:%02x sequence", seq
                    )
                return

        try:
            data, _ = t.deserialize(data[5:], schema)
        except Exception:
            LOGGER.warning("Failed to deserialize frame: %s", binascii.hexlify(data))
            if fut is not None and not fut.done():
                fut.set_exception(
                    APIException(
                        f"Failed to deserialize frame: {binascii.hexlify(data)}"
                    )
                )
            return

        if fut is not None:
            try:
                fut.set_result(data)
            except asyncio.InvalidStateError:
                LOGGER.warning(
                    "Duplicate or delayed response for 0x:%02x sequence", seq
                )

        getattr(self, "_handle_%s" % (command.name,))(data)

    add_neighbour = functools.partialmethod(_command, Command.add_neighbour, 12)
    device_state = functools.partialmethod(_command, Command.device_state, 0, 0, 0)
    change_network_state = functools.partialmethod(
        _command, Command.change_network_state
    )

    def _handle_device_state(self, data):
        LOGGER.debug("Device state response: %s", data)
        self._handle_device_state_value(data[0])

    def _handle_change_network_state(self, data):
        LOGGER.debug("Change network state response: %s", NetworkState(data[0]).name)

    @classmethod
    async def probe(cls, device_config: Dict[str, Any]) -> bool:
        """Probe port for the device presence."""
        api = cls(None, device_config)
        try:
            await asyncio.wait_for(api._probe(), timeout=PROBE_TIMEOUT)
            return True
        except (asyncio.TimeoutError, serial.SerialException, APIException) as exc:
            LOGGER.debug(
                "Unsuccessful radio probe of '%s' port",
                device_config[CONF_DEVICE_PATH],
                exc_info=exc,
            )
        finally:
            api.close()

        return False

    async def _probe(self) -> None:
        """Open port and try sending a command."""
        await self.connect()
        await self.device_state()
        self.close()

    async def read_parameter(self, id_, *args):
        try:
            if isinstance(id_, str):
                param = NetworkParameter[id_]
            else:
                param = NetworkParameter(id_)
        except (KeyError, ValueError):
            raise KeyError("Unknown parameter id: %s" % (id_,))

        data = t.serialize(args, NETWORK_PARAMETER_SCHEMA[param])
        r = await self._command(Command.read_parameter, 1 + len(data), param, data)
        data = t.deserialize(r[2], NETWORK_PARAMETER_SCHEMA[param])[0]
        LOGGER.debug("Read parameter %s response: %s", param.name, data)
        return data

    def reconnect(self):
        """Reconnect using saved parameters."""
        LOGGER.debug("Reconnecting '%s' serial port", self._config[CONF_DEVICE_PATH])
        return self.connect()

    def _handle_read_parameter(self, data):
        pass

    def write_parameter(self, id_, *args):
        try:
            if isinstance(id_, str):
                param = NetworkParameter[id_]
            else:
                param = NetworkParameter(id_)
        except (KeyError, ValueError):
            raise KeyError("Unknown parameter id: %s write request" % (id_,))

        v = t.serialize(args, NETWORK_PARAMETER_SCHEMA[param])
        length = len(v) + 1
        return self._command(Command.write_parameter, length, param, v)

    def _handle_write_parameter(self, data):
        try:
            param = NetworkParameter(data[1])
        except ValueError:
            LOGGER.error("Received unknown network param id '%s' response", data[1])
            return
        LOGGER.debug("Write parameter %s: SUCCESS", param.name)

    async def version(self):
        (self._proto_ver,) = await self[NetworkParameter.protocol_version]
        (self._firmware_version,) = await self._command(Command.version, 0)
        if (
            self.protocol_version >= MIN_PROTO_VERSION
            and (self.firmware_version & 0x0000FF00) == 0x00000500
        ):
            self._aps_data_ind_flags = 0x04
        return self.firmware_version

    def _handle_version(self, data):
        LOGGER.debug("Version response: %x", data[0])

    def _handle_device_state_changed(self, data):
        LOGGER.debug("Device state changed response: %s", data)
        self._handle_device_state_value(data[0])

    async def _aps_data_indication(self):
        try:
            r = await self._command(
                Command.aps_data_indication, 1, self._aps_data_ind_flags
            )
            LOGGER.debug(
                (
                    "'aps_data_indication' response from %s, ep: %s, "
                    "profile: 0x%04x, cluster_id: 0x%04x, data: %s"
                ),
                r[4],
                r[5],
                r[6],
                r[7],
                binascii.hexlify(r[8]),
            )
            return r
        except (asyncio.TimeoutError, zigpy.exceptions.ZigbeeException):
            pass
        finally:
            self._data_indication = False

    def _handle_aps_data_indication(self, data):
        LOGGER.debug("APS data indication response: %s", data)
        self._data_indication = False
        self._handle_device_state_value(data[1])
        if self._app:
            self._app.handle_rx(
                data[4],  # src_addr
                data[5],  # src_ep
                data[3],  # dst_ep
                data[6],  # profile_id
                data[7],  # cluster_id
                data[8],  # APS payload
                data[11],  # lqi
                data[16],
            )  # rssi

    async def aps_data_request(
        self, req_id, dst_addr_ep, profile, cluster, src_ep, aps_payload
    ):
        dst = dst_addr_ep.serialize()
        length = len(dst) + len(aps_payload) + 11
        delays = (0.5, 1.0, 1.5, None)
        for delay in delays:
            try:
                return await self._command(
                    Command.aps_data_request,
                    length,
                    req_id,
                    0,
                    dst_addr_ep,
                    profile,
                    cluster,
                    src_ep,
                    aps_payload,
                    2,
                    0,
                )
            except CommandError as ex:
                LOGGER.debug("'aps_data_request' failure: %s", ex)
                if delay is not None and ex.status == Status.BUSY:
                    LOGGER.debug("retrying 'aps_data_request' in %ss", delay)
                    await asyncio.sleep(delay)
                    continue
                raise

    def _handle_aps_data_request(self, data):
        LOGGER.debug("APS data request response: %s", data)
        self._handle_device_state_value(data[1])

    async def _aps_data_confirm(self):
        try:
            r = await self._command(Command.aps_data_confirm, 0)
            LOGGER.debug(
                ("Request id: 0x%02x 'aps_data_confirm' for %s, " "status: 0x%02x"),
                r[2],
                r[3],
                r[5],
            )
            return r
        except (asyncio.TimeoutError, zigpy.exceptions.ZigbeeException):
            pass
        finally:
            self._data_confirm = False

    def _handle_add_neighbour(self, data) -> None:
        """Handle add_neighbour response."""
        LOGGER.debug("add neighbour response: %s", data)

    def _handle_aps_data_confirm(self, data):
        LOGGER.debug(
            "APS data confirm response for request with id %s: %02x", data[2], data[5]
        )
        self._data_confirm = False
        self._handle_device_state_value(data[1])
        self._app.handle_tx_confirm(data[2], data[5])

    def _handle_mac_poll(self, data):
        pass

    def _handle_zigbee_green_power(self, data):
        pass

    def _handle_simplified_beacon(self, data):
        LOGGER.debug(
            (
                "Received simplified beacon frame: source=0x%04x, "
                "pan_id=0x%04x, channel=%s, flags=0x%02x, "
                "update_id=0x%02x"
            ),
            data[1],
            data[2],
            data[3],
            data[4],
            data[5],
        )

    def _handle_device_state_value(self, state: DeviceState) -> None:
        if state.network_state != self.network_state:
            LOGGER.debug(
                "Network state transition: %s -> %s",
                self.network_state.name,
                state.network_state.name,
            )
        self._device_state = state
        if DeviceState.APSDE_DATA_REQUEST_SLOTS_AVAILABLE not in state:
            LOGGER.debug("Data request queue full.")
        if DeviceState.APSDE_DATA_INDICATION in state and not self._data_indication:
            self._data_indication = True
            asyncio.ensure_future(self._aps_data_indication())
        if DeviceState.APSDE_DATA_CONFIRM in state and not self._data_confirm:
            self._data_confirm = True
            asyncio.ensure_future(self._aps_data_confirm())

    def __getitem__(self, key):
        """Access parameters via getitem."""
        return self.read_parameter(key)

    def __setitem__(self, key, value):
        """Set parameters via setitem."""
        return asyncio.ensure_future(self.write_parameter(key, value))
