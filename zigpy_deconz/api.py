import asyncio
import logging
import enum
import binascii

from . import uart
from . import types as t
from zigpy_deconz.exception import CommandError

LOGGER = logging.getLogger(__name__)

COMMAND_TIMEOUT = 2
DECONZ_BAUDRATE = 38400
MIN_PROTO_VERSION = 0x010B


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
    simplified_beacon = 0x1F


TX_COMMANDS = {
    Command.aps_data_confirm: (t.uint16_t, ),
    Command.aps_data_indication: (t.uint16_t, t.uint8_t),
    Command.aps_data_request: (
        t.uint16_t, t.uint8_t, t.uint8_t, t.DeconzAddressEndpoint,
        t.uint16_t, t.uint16_t, t.uint8_t, t.LVBytes, t.uint8_t, t.uint8_t,
    ),
    Command.change_network_state: (t.uint8_t, ),
    Command.device_state: (t.uint8_t, t.uint8_t, t.uint8_t),
    Command.read_parameter: (t.uint16_t, t.uint8_t, t.Bytes),
    Command.version: (),
    Command.write_parameter: (t.uint16_t, t.uint8_t, t.Bytes),
}

RX_COMMANDS = {
    Command.aps_data_confirm: (
        (t.uint16_t, t.uint8_t, t.uint8_t, t.DeconzAddressEndpoint,
         t.uint8_t, t.uint8_t, t.uint8_t, t.uint8_t, t.uint8_t, t.uint8_t),
        True),
    Command.aps_data_indication: (
        (t.uint16_t, t.uint8_t, t.DeconzAddress, t.uint8_t, t.DeconzAddress,
         t.uint8_t, t.uint16_t, t.uint16_t, t.LVBytes, t.uint8_t,
         t.uint8_t, t.uint8_t, t.uint8_t, t.uint8_t, t.uint8_t, t.uint8_t,
         t.int8s),
        True),
    Command.aps_data_request: ((t.uint16_t, t.uint8_t, t.uint8_t), True),
    Command.change_network_state: ((t.uint8_t, ), True),
    Command.device_state: ((t.uint8_t, t.uint8_t, t.uint8_t), True),
    Command.device_state_changed: ((t.uint8_t, t.uint8_t), False),
    Command.mac_poll: ((t.uint16_t, t.DeconzAddress, t.uint8_t, t.int8s), False),
    Command.read_parameter: ((t.uint16_t, t.uint8_t, t.Bytes), True),
    Command.simplified_beacon: (
        (t.uint16_t, t.uint16_t, t.uint16_t, t.uint8_t, t.uint8_t, t.uint8_t),
        False),
    Command.version: ((t.uint32_t, ), True),
    Command.write_parameter: ((t.uint16_t, t.uint8_t), True),
    Command.zigbee_green_power: ((t.LVBytes, ), False),
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
    network_key = 0x18
    current_channel = 0x1C
    permit_join = 0x21
    protocol_version = 0x22
    nwk_update_id = 0x24
    watchdog_ttl = 0x26


NETWORK_PARAMETER_SCHEMA = {
    NetworkParameter.mac_address: (t.EUI64, ),
    NetworkParameter.nwk_panid: (t.PanId, ),
    NetworkParameter.nwk_address: (t.NWK, ),
    NetworkParameter.nwk_extended_panid: (t.ExtendedPanId, ),
    NetworkParameter.aps_designed_coordinator: (t.uint8_t, ),
    NetworkParameter.channel_mask: (t.uint32_t, ),
    NetworkParameter.aps_extended_panid: (t.ExtendedPanId, ),
    NetworkParameter.trust_center_address: (t.EUI64, ),
    NetworkParameter.security_mode: (t.uint8_t, ),
    NetworkParameter.network_key: (t.uint8_t, t.Key, ),
    NetworkParameter.current_channel: (t.uint8_t, ),
    NetworkParameter.permit_join: (t.uint8_t, ),
    NetworkParameter.protocol_version: (t.uint16_t, ),
    NetworkParameter.nwk_update_id: (t.uint8_t, ),
    NetworkParameter.watchdog_ttl: (t.uint32_t, ),
}


class Status(t.uint8_t, enum.Enum):
    SUCCESS = 0
    FAILURE = 1
    BUSY = 2
    TIMEOUT = 3
    UNSUPPORTED = 4
    ERROR = 5
    NO_NETWORK = 6
    INVALID_VALUE = 7


class DeviceState(t.uint8_t, enum.Enum):
    APSDE_DATA_CONFIRM = 0x04
    APSDE_DATA_INDICATION = 0x08
    CONF_CHANGED = 0x10
    APSDE_DATA_REQUEST = 0x20

    @classmethod
    def flags(cls, value: int):
        """Make it into list of flags, until we deprecate py35 and py36."""
        return [flag for flag in cls if (value & flag) == flag]


class NetworkState(t.uint8_t, enum.Enum):
    OFFLINE = 0
    JOINING = 1
    CONNECTED = 2
    LEAVING = 3


class Deconz:
    def __init__(self):
        self._uart = None
        self._seq = 1
        self._awaiting = {}
        self._app = None
        self._cmd_mode_future = None
        self.network_state = NetworkState.OFFLINE
        self._data_indication = False
        self._data_confirm = False
        self._proto_ver = None
        self._aps_data_ind_flags = 0x01

    @property
    def protocol_version(self):
        """Protocol Version."""
        return self._proto_ver

    def set_application(self, app):
        self._app = app

    async def connect(self, device, baudrate=DECONZ_BAUDRATE):
        assert self._uart is None
        self._uart = await uart.connect(device, DECONZ_BAUDRATE, self)

    def close(self):
        return self._uart.close()

    async def _command(self, cmd, *args):
        LOGGER.debug("Command %s %s", cmd, args)
        data, seq = self._api_frame(cmd, *args)
        self._uart.send(data)
        fut = asyncio.Future()
        self._awaiting[seq] = fut
        try:
            return await asyncio.wait_for(fut, timeout=COMMAND_TIMEOUT)
        except asyncio.TimeoutError:
            LOGGER.warning("No response to '%s' command", cmd)
            self._awaiting.pop(seq)
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
        try:
            data, _ = t.deserialize(data[5:], schema)
        except Exception as exc:
            LOGGER.warning("Failed to deserialize frame: %s", binascii.hexlify(data))
            if solicited and seq in self._awaiting:
                fut = self._awaiting.pop(seq)
                fut.set_exception(exc)
            return
        if solicited and seq in self._awaiting:
            fut = self._awaiting.pop(seq)
            if status != Status.SUCCESS:
                fut.set_exception(
                    CommandError(status, '%s, status: %s' % (command,
                                                             status, )))
                return
            fut.set_result(data)
        getattr(self, '_handle_%s' % (command.name, ))(data)

    def device_state(self):
        return self._command(Command.device_state, 0, 0, 0)

    def _handle_device_state(self, data):
        LOGGER.debug("Device state response: %s", data)
        self._handle_device_state_value(data[0])

    def change_network_state(self, state):
        return self._command(Command.change_network_state, state)

    def _handle_change_network_state(self, data):
        LOGGER.debug("Change network state response: %s", NetworkState(data[0]).name)

    async def read_parameter(self, id_, *args):
        try:
            if isinstance(id_, str):
                param = NetworkParameter[id_]
            else:
                param = NetworkParameter(id_)
        except (KeyError, ValueError):
            raise KeyError("Unknown parameter id: %s" % (id_, ))

        data = t.serialize(args, NETWORK_PARAMETER_SCHEMA[param])
        r = await self._command(Command.read_parameter, 1 + len(data), param, data)
        data = t.deserialize(r[2], NETWORK_PARAMETER_SCHEMA[param])[0]
        LOGGER.debug("Read parameter %s response: %s", param.name, data)
        return data

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
            LOGGER.error("Received unknown network param id '%s' response",
                         data[1])
            return
        LOGGER.debug("Write parameter %s: SUCCESS", param.name)

    async def version(self):
        self._proto_ver, = await self[NetworkParameter.protocol_version]
        version = await self._command(Command.version)
        if self.protocol_version >= MIN_PROTO_VERSION and \
                (version[0] & 0x0000FF00) == 0x00000500:
            self._aps_data_ind_flags = 0x04
        return version[0]

    def _handle_version(self, data):
        LOGGER.debug("Version response: %x", data[0])

    def _handle_device_state_changed(self, data):
        LOGGER.debug("Device state changed response: %s", data)
        self._handle_device_state_value(data[0])

    async def _aps_data_indication(self):
        try:
            r = await self._command(Command.aps_data_indication, 1, self._aps_data_ind_flags)
            LOGGER.debug(("'aps_data_indication' response from %s, ep: %s, "
                          "profile: 0x%04x, cluster_id: 0x%04x, data: %s"),
                         r[4], r[5], r[6], r[7], binascii.hexlify(r[8]))
            return r
        except asyncio.TimeoutError:
            self._data_indication = False

    def _handle_aps_data_indication(self, data):
        LOGGER.debug("APS data indication response: %s", data)
        self._data_indication = False
        self._handle_device_state_value(data[1])
        if self._app:
            self._app.handle_rx(data[4],    # src_addr
                                data[5],    # src_ep
                                data[3],    # dst_ep
                                data[6],    # profile_id
                                data[7],    # cluster_id
                                data[8],    # APS payload
                                data[11],   # lqi
                                data[16])   # rssi

    async def aps_data_request(self, req_id, dst_addr_ep, profile, cluster, src_ep, aps_payload):
        dst = dst_addr_ep.serialize()
        length = len(dst) + len(aps_payload) + 11
        delays = (0.5, 1.0, 1.5, None)
        for delay in delays:
            try:
                return await self._command(Command.aps_data_request, length,
                                           req_id, 0, dst_addr_ep, profile,
                                           cluster, src_ep, aps_payload, 2, 0)
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
            LOGGER.debug(("Request id: 0x%02x 'aps_data_confirm' for %s, "
                          "status: 0x%02x"), r[2], r[3], r[5])
            return r
        except asyncio.TimeoutError:
            self._data_confirm = False

    def _handle_aps_data_confirm(self, data):
        LOGGER.debug("APS data confirm response for request with id %s: %02x", data[2], data[5])
        self._data_confirm = False
        self._handle_device_state_value(data[1])
        self._app.handle_tx_confirm(data[2], data[5])

    def _handle_mac_poll(self, data):
        pass

    def _handle_zigbee_green_power(self, data):
        pass

    def _handle_simplified_beacon(self, data):
        LOGGER.debug(("Received simplified beacon frame: source=0x%04x, "
                      "pan_id=0x%04x, channel=%s, flags=0x%02x, "
                      "update_id=0x%02x"),
                     data[1], data[2], data[3], data[4], data[5])

    def _handle_device_state_value(self, value):
        flags = DeviceState.flags(value)
        ns = NetworkState(value & 0x03)
        if ns != self.network_state:
            LOGGER.debug("Network state transition: %s -> %s",
                         self.network_state.name, ns.name)
        self.network_state = ns
        if DeviceState.APSDE_DATA_REQUEST not in flags:
            LOGGER.debug("Data request queue full.")
        if DeviceState.APSDE_DATA_INDICATION in flags and not self._data_indication:
            self._data_indication = True
            asyncio.ensure_future(self._aps_data_indication())
        if DeviceState.APSDE_DATA_CONFIRM in flags and not self._data_confirm:
            self._data_confirm = True
            asyncio.ensure_future(self._aps_data_confirm())

    def __getitem__(self, key):
        return self.read_parameter(key)

    def __setitem__(self, key, value):
        return asyncio.ensure_future(self.write_parameter(key, value))
