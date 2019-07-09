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

TX_COMMANDS = {
    'device_state': (0x07, (t.uint8_t, t.uint8_t, t.uint8_t), True),
    'change_network_state': (0x08, (t.uint8_t, ), True),
    'read_parameter': (0x0A, (t.uint16_t, t.uint8_t), True),
    'write_parameter': (0x0B, (t.uint16_t, t.uint8_t, t.Bytes), True),
    'version': (0x0D, (), True),
    'aps_data_indication': (0x17, (t.uint16_t, t.uint8_t), True),
    'aps_data_request': (
        0x12,
        (t.uint16_t, t.uint8_t, t.uint8_t, t.DeconzAddressEndpoint,
            t.uint16_t, t.uint16_t, t.uint8_t, t.LVBytes, t.uint8_t,
            t.uint8_t),
        True),
    'aps_data_confirm': (0x04, (t.uint16_t, ), True),
}

RX_COMMANDS = {
    'device_state': (0x07, (t.uint8_t, t.uint8_t, t.uint8_t), True),
    'change_network_state': (0x08, (t.uint8_t, ), True),
    'read_parameter': (0x0A, (t.uint16_t, t.uint8_t, t.Bytes), True),
    'write_parameter': (0x0B, (t.uint16_t, t.uint8_t), True),
    'version': (0x0D, (t.uint32_t, ), True),
    'device_state_changed': (0x0E, (t.uint8_t, t.uint8_t), False),
    'aps_data_indication': (
        0x17,
        (t.uint16_t, t.uint8_t, t.DeconzAddress, t.uint8_t, t.DeconzAddress,
            t.uint8_t, t.uint16_t, t.uint16_t, t.LVBytes, t.uint8_t,
            t.uint8_t, t.uint8_t, t.uint8_t, t.uint8_t, t.uint8_t, t.uint8_t,
            t.int8s),
        True
    ),
    'aps_data_request': (0x12, (t.uint16_t, t.uint8_t, t.uint8_t), True),
    'aps_data_confirm': (
        0x04,
        (t.uint16_t, t.uint8_t, t.uint8_t, t.DeconzAddressEndpoint,
            t.uint8_t, t.uint8_t, t.uint8_t, t.uint8_t, t.uint8_t, t.uint8_t),
        True
    ),
    'mac_poll': (0x1C, (t.uint16_t, t.DeconzAddress, t.uint8_t, t.int8s), False),
    'zigbee_green_power': (0x19, (t.LVBytes, ), False),
    'simplified_beacon': (0x1f, (t.uint16_t, t.uint16_t, t.uint16_t, t.uint8_t,
                          t.uint8_t, t.uint8_t), False)
}

NETWORK_PARAMETER = {
    'mac_address': (0x01, t.uint64_t),
    'nwk_panid': (0x05, t.uint16_t),
    'nwk_address': (0x07, t.uint16_t),
    'nwk_extended_panid': (0x08, t.uint64_t),
    'aps_designed_coordinator': (0x09, t.uint8_t),
    'channel_mask': (0x0A, t.uint32_t),
    'aps_extended_panid': (0x0B, t.uint64_t),
    'trust_center_address': (0x0E, t.uint64_t),
    'security_mode': (0x10, t.uint8_t),
    'network_key': (0x18, t.uint8_t),
    'current_channel': (0x1C, t.uint8_t),
    'permit_join': (0x21, t.uint8_t),
    'protocol_version': (0x22, t.uint16_t),
    'nwk_update_id': (0x24, t.uint8_t),
    'watchdog_ttl': (0x26, t.uint32_t),
}

NETWORK_PARAMETER_BY_ID = {v[0]: (k, v[1]) for k, v in NETWORK_PARAMETER.items()}


class STATUS(t.uint8_t, enum.Enum):
    SUCCESS = 0
    FAILURE = 1
    BUSY = 2
    TIMEOUT = 3
    UNSUPPORTED = 4
    ERROR = 5
    NO_NETWORK = 6
    INVALID_VALUE = 7


class DEVICE_STATE(enum.Enum):
    APSDE_DATA_CONFIRM = 0x04
    APSDE_DATA_INDICATION = 0x08
    CONF_CHANGED = 0x10
    APSDE_DATA_REQUEST = 0x20


class NETWORK_STATE(enum.Enum):
    OFFLINE = 0
    JOINING = 1
    CONNECTED = 2
    LEAVING = 3


class Deconz:
    def __init__(self):
        self._uart = None
        self._seq = 1
        self._commands_by_id = {v[0]: k for k, v in RX_COMMANDS.items()}
        self._awaiting = {}
        self._app = None
        self._cmd_mode_future = None
        self.network_state = NETWORK_STATE.OFFLINE.value
        self._data_indication = False
        self._data_confirm = False

    def set_application(self, app):
        self._app = app

    async def connect(self, device, baudrate=DECONZ_BAUDRATE):
        assert self._uart is None
        self._uart = await uart.connect(device, DECONZ_BAUDRATE, self)

    def close(self):
        return self._uart.close()

    async def _command(self, name, *args):
        LOGGER.debug("Command %s %s", name, args)
        data, needs_response = self._api_frame(name, *args)
        self._uart.send(data)
        fut = None
        if needs_response:
            fut = asyncio.Future()
            self._awaiting[self._seq] = (fut, )
        self._seq = (self._seq % 255) + 1
        try:
            return await asyncio.wait_for(fut, timeout=COMMAND_TIMEOUT)
        except asyncio.TimeoutError:
            LOGGER.warning("No response to '%s' command", name)
            raise

    def _api_frame(self, name, *args):
        c = TX_COMMANDS[name]
        d = t.serialize(args, c[1])
        data = t.uint8_t(c[0]).serialize()
        data += t.uint8_t(self._seq).serialize()
        data += t.uint8_t(0).serialize()
        data += t.uint16_t(len(d) + 5).serialize()
        data += d
        return data, c[2]

    def data_received(self, data):
        if data[0] not in self._commands_by_id:
            LOGGER.debug("Unknown command received: %s", data[0])
            return
        command = self._commands_by_id[data[0]]
        seq = data[1]
        try:
            status = STATUS(data[2])
        except ValueError:
            status = data[2]
        try:
            data, _ = t.deserialize(data[5:], RX_COMMANDS[command][1])
        except Exception:
            LOGGER.warning("Failed to deserialize frame: %s", binascii.hexlify(data))
        if RX_COMMANDS[command][2]:
            fut, = self._awaiting.pop(seq)
            if status != STATUS.SUCCESS:
                fut.set_exception(
                    CommandError(status, '%s, status: %s' % (command,
                                                             status, )))
                return
            fut.set_result(data)
        getattr(self, '_handle_%s' % (command, ))(data)

    def device_state(self):
        return self._command('device_state', 0, 0, 0)

    def _handle_device_state(self, data):
        LOGGER.debug("Device state response: %s", data)
        self._handle_device_state_value(data[0])

    def change_network_state(self, state):
        return self._command('change_network_state', state)

    def _handle_change_network_state(self, data):
        LOGGER.debug("Change network state response: %s", NETWORK_STATE(data[0]).name)

    def read_parameter(self, id_):
        return self._command('read_parameter', 1, id_)

    def _handle_read_parameter(self, data):
        LOGGER.debug("Read parameter %s response: %s", NETWORK_PARAMETER_BY_ID[data[1]][0], data[2])

    def write_parameter(self, id_, value):
        v = NETWORK_PARAMETER_BY_ID[id_][1](value).serialize()
        length = len(v) + 1
        return self._command('write_parameter', length, id_, v)

    def _handle_write_parameter(self, data):
        LOGGER.debug("Write parameter %s: SUCCESS", NETWORK_PARAMETER_BY_ID[data[1]][0])

    def version(self):
        return self._command('version')

    def _handle_version(self, data):
        LOGGER.debug("Version response: %x", data[0])

    def _handle_device_state_changed(self, data):
        LOGGER.debug("Device state changed response: %s", data)
        self._handle_device_state_value(data[0])

    async def _aps_data_indication(self):
        try:
            r = await self._command('aps_data_indication', 1, 1)
            LOGGER.debug(("'aps_data_indication' responnse from %s, ep: %s, "
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
                return await self._command('aps_data_request', length, req_id,
                                           0, dst_addr_ep, profile, cluster,
                                           src_ep, aps_payload, 2, 0)
            except CommandError as ex:
                LOGGER.debug("'aps_data_request' failure: %s", ex)
                if delay is not None and ex.status == STATUS.BUSY:
                    LOGGER.debug("retrying 'aps_data_request' in %ss", delay)
                    await asyncio.sleep(delay)
                    continue
                raise

    def _handle_aps_data_request(self, data):
        LOGGER.debug("APS data request response: %s", data)
        self._handle_device_state_value(data[1])

    async def _aps_data_confirm(self):
        try:
            r = await self._command('aps_data_confirm', 0)
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
        flags = [i for i in DEVICE_STATE if (value & i.value) == i.value]
        ns = value & 0x03
        if ns != self.network_state:
            LOGGER.debug("Network state: %s", NETWORK_STATE(ns).name)
        self.network_state = ns
        if DEVICE_STATE.APSDE_DATA_REQUEST not in flags:
            LOGGER.debug("Data request queue full.")
        if DEVICE_STATE.APSDE_DATA_INDICATION in flags and not self._data_indication:
            self._data_indication = True
            asyncio.ensure_future(self._aps_data_indication())
        if DEVICE_STATE.APSDE_DATA_CONFIRM in flags and not self._data_confirm:
            self._data_confirm = True
            asyncio.ensure_future(self._aps_data_confirm())
