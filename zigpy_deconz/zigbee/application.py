import asyncio
import binascii
import logging

from zigpy_deconz.api import NETWORK_PARAMETER, NETWORK_STATE
from zigpy_deconz import types as t

import zigpy.application
import zigpy.exceptions
import zigpy.endpoint
import zigpy.types
import zigpy.util
import zigpy.device


LOGGER = logging.getLogger(__name__)

CHANGE_NETWORK_WAIT = 1
SEND_CONFIRM_TIMEOUT = 30
TIMEOUT_REPLY_ROUTER = 6
TIMEOUT_REPLY_ENDDEV = 29


class ControllerApplication(zigpy.application.ControllerApplication):
    def __init__(self, api, database_file=None):
        super().__init__(database_file=database_file)
        self._api = api
        api.set_application(self)

        self._pending = Requests()

        self._nwk = 0
        self.discovering = False
        self.version = 0

    async def _reset_watchdog(self):
        while True:
            await self._api.write_parameter(NETWORK_PARAMETER['watchdog_ttl'][0], 3600)
            await asyncio.sleep(1200)

    async def shutdown(self):
        """Shutdown application."""
        self._api.close()

    async def startup(self, auto_form=False):
        """Perform a complete application startup"""
        r = await self._api.version()
        self.version = r[0]
        await self._api.device_state()
        r = await self._api.read_parameter(NETWORK_PARAMETER['mac_address'][0])
        self._ieee = zigpy.types.EUI64([zigpy.types.uint8_t(r[2][i]) for i in range(7, -1, -1)])
        await self._api.read_parameter(NETWORK_PARAMETER['nwk_panid'][0])
        await self._api.read_parameter(NETWORK_PARAMETER['nwk_address'][0])
        await self._api.read_parameter(NETWORK_PARAMETER['nwk_extended_panid'][0])
        await self._api.read_parameter(NETWORK_PARAMETER['channel_mask'][0])
        await self._api.read_parameter(NETWORK_PARAMETER['aps_extended_panid'][0])
        await self._api.read_parameter(NETWORK_PARAMETER['trust_center_address'][0])
        await self._api.read_parameter(NETWORK_PARAMETER['security_mode'][0])
        await self._api.read_parameter(NETWORK_PARAMETER['current_channel'][0])
        await self._api.read_parameter(NETWORK_PARAMETER['protocol_version'][0])
        await self._api.read_parameter(NETWORK_PARAMETER['nwk_update_id'][0])
        await self._api.write_parameter(NETWORK_PARAMETER['aps_designed_coordinator'][0], 1)

        if self.version > 0x261f0500:
            asyncio.ensure_future(self._reset_watchdog())

        if auto_form:
            await self.form_network()
        self.devices[self.ieee] = await ConBeeDevice.new(self,
                                                         self.ieee, self.nwk)

    async def force_remove(self, dev):
        """Forcibly remove device from NCP."""
        pass

    async def form_network(self, channel=15, pan_id=None, extended_pan_id=None):
        LOGGER.info("Forming network")
        if self._api.network_state == NETWORK_STATE.CONNECTED.value:
            return

        await self._api.change_network_state(NETWORK_STATE.CONNECTED.value)
        for _ in range(10):
            await self._api.device_state()
            if self._api.network_state == NETWORK_STATE.CONNECTED.value:
                return
            await asyncio.sleep(CHANGE_NETWORK_WAIT)
        raise Exception("Could not form network.")

    @zigpy.util.retryable_request
    async def request(self, nwk, profile, cluster, src_ep, dst_ep, sequence, data, expect_reply=True,
                      timeout=TIMEOUT_REPLY_ROUTER):
        LOGGER.debug("Zigbee request with id %s, data: %s", sequence, binascii.hexlify(data))
        assert sequence not in self._pending
        dst_addr_ep = t.DeconzAddressEndpoint()
        dst_addr_ep.address_mode = t.uint8_t(t.ADDRESS_MODE.NWK.value)
        dst_addr_ep.address = t.uint16_t(nwk)
        dst_addr_ep.endpoint = t.uint8_t(dst_ep)

        with self._pending.new(sequence, expect_reply) as req:
            await self._api.aps_data_request(
                sequence,
                dst_addr_ep,
                profile,
                cluster,
                min(1, src_ep),
                data
            )

            r = await asyncio.wait_for(req.send, SEND_CONFIRM_TIMEOUT)

            if r:
                LOGGER.warning("Error while sending frame: 0x%02x", r)
                raise zigpy.exceptions.DeliveryError(
                    "[0x%04x:%s:0x%04x] failed transmission request: %s" % (nwk, dst_ep, cluster, r)
                )

            if not expect_reply:
                return

            dev = self.get_device(nwk=nwk)
            if dev.node_desc.is_end_device in (True, None):
                LOGGER.debug("Extending timeout for %s/0x%04x", dev.ieee, nwk)
                timeout = TIMEOUT_REPLY_ENDDEV
            return await asyncio.wait_for(req.reply, timeout)

    async def broadcast(self, profile, cluster, src_ep, dst_ep, grpid, radius,
                        sequence, data,
                        broadcast_address=zigpy.types.BroadcastAddress.RX_ON_WHEN_IDLE):
        LOGGER.debug("Zigbee broadcast with id %s, data: %s", sequence, binascii.hexlify(data))
        assert sequence not in self._pending
        dst_addr_ep = t.DeconzAddressEndpoint()
        dst_addr_ep.address_mode = t.uint8_t(t.ADDRESS_MODE.GROUP.value)
        dst_addr_ep.address = t.uint16_t(broadcast_address)

        with self._pending.new(sequence) as req:
            await self._api.aps_data_request(
                sequence,
                dst_addr_ep,
                profile,
                cluster,
                min(1, src_ep),
                data
            )

            r = await asyncio.wait_for(req.send, SEND_CONFIRM_TIMEOUT)

            if r:
                LOGGER.warning("Error while sending broadcast: 0x%02x", r)
                raise zigpy.exceptions.DeliveryError(
                    "[0x%04x:%s:0x%04x] failed transmission request: %s" % (broadcast_address,
                                                                            dst_ep, cluster, r)
                )

    async def permit_ncp(self, time_s=60):
        assert 0 <= time_s <= 254
        await self._api.write_parameter(
            NETWORK_PARAMETER['permit_join'][0],
            time_s
        )

    def handle_rx(self, src_addr, src_ep, dst_ep, profile_id, cluster_id, data, lqi, rssi):
        # intercept ZDO device announce frames
        if dst_ep == 0 and cluster_id == 0x13:
            nwk, rest = t.uint16_t.deserialize(data[1:])
            ieee, _ = zigpy.types.EUI64.deserialize(rest)
            LOGGER.info("New device joined: 0x%04x, %s", nwk, ieee)
            self.handle_join(nwk, ieee, 0)

        try:
            if src_addr.address_mode == t.ADDRESS_MODE.NWK.value:
                device = self.get_device(nwk=src_addr.address)
            elif src_addr.address_mode == t.ADDRESS_MODE.IEEE.value:
                device = self.get_device(ieee=src_addr.address)
            else:
                raise Exception("Unsupported address mode in handle_rx: %s" % (src_addr.address_mode))
        except KeyError:
            LOGGER.debug("Received frame from unknown device: 0x%04x", src_addr.address)
            return

        device.lqi = lqi
        device.rssi = rssi

        if device.status == zigpy.device.Status.NEW and dst_ep != 0:
            # only allow ZDO responses while initializing device
            LOGGER.debug("Received frame on uninitialized device %s (%s) for endpoint: %s", device.ieee, device.status, dst_ep)
            return
        elif device.status == zigpy.device.Status.ZDO_INIT and dst_ep != 0 and cluster_id != 0:
            # only allow access to basic cluster while initializing endpoints
            LOGGER.debug("Received frame on uninitialized device %s endpoint %s for cluster: %s", device.ieee, dst_ep, cluster_id)
            return

        try:
            tsn, command_id, is_reply, args = self.deserialize(device, src_ep, cluster_id, data)
        except ValueError as e:
            LOGGER.error("Failed to parse message (%s) on cluster %d, because %s", binascii.hexlify(data), cluster_id, e)
            return

        if is_reply:
            self._handle_reply(device, profile_id, cluster_id, src_ep, dst_ep,
                               tsn, command_id, args)
        else:
            self.handle_message(device, False, profile_id, cluster_id, src_ep,
                                dst_ep, tsn, command_id, args)

    def _handle_reply(self, device, profile, cluster, src_ep, dst_ep, tsn, command_id, args):
        try:
            req = self._pending[tsn]
            if req.reply:
                req.reply.set_result(args)
            return
        except KeyError as exc:
            LOGGER.warning("Unexpected response TSN=%s command=%s args=%s, %s", tsn, command_id, args, exc)
        except asyncio.futures.InvalidStateError as exc:
            LOGGER.debug("Invalid state on future - probably duplicate response: %s", exc)
            # We've already handled, don't drop through to device handler
            return

        self.handle_message(device, True, profile, cluster, src_ep, dst_ep, tsn, command_id, args)

    def handle_tx_confirm(self, sequence, status):
        try:
            self._pending[sequence].send.set_result(status)
            return
        except KeyError as exc:
            LOGGER.warning("Unexpected transmit confirm for request id %s, Status: 0x%02x, %s", sequence, status, exc)
        except asyncio.futures.InvalidStateError as exc:
            LOGGER.debug("Invalid state on future - probably duplicate response: %s", exc)


class Requests(dict):
    def new(self, sequence, expect_reply=False):
        """Wrap new request into a context manager."""
        return Request(self, sequence, expect_reply)


class Request:
    """Context manager."""

    def __init__(self, pending, sequence, expect_reply=False):
        """Init context manager for sendUnicast/sendBroadcast."""
        assert sequence not in pending
        self._exception = None
        self._pending = pending
        self._reply_fut = None
        if expect_reply:
            self._reply_fut = asyncio.Future()
        self._send_fut = asyncio.Future()
        self._sequence = sequence

    @property
    def exception(self):
        """Exit status."""
        return self._exception

    @property
    def reply(self):
        """Reply Future."""
        return self._reply_fut

    @property
    def sequence(self):
        """Send Future."""
        return self._sequence

    @property
    def send(self):
        return self._send_fut

    def __enter__(self):
        """Return context manager."""
        self._pending[self.sequence] = self
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        """Clean up pending on exit."""
        if not self.send.done():
            self.send.cancel()
        if self.reply and not self.reply.done():
            self.reply.cancel()
        self._pending.pop(self.sequence)

        if exc_type in (asyncio.TimeoutError,
                        zigpy.exceptions.ZigbeeException):
            self._exception = (exc_type, exc_value, exc_traceback)
            LOGGER.debug("Request id 0x%02x failure: %s",
                         self.sequence, exc_type.__name__)

        return False


class ConBeeDevice(zigpy.device.Device):
    """Zigpy Device representing Coordinator."""

    async def add_to_group(self, grp_id: int,
                           name: str = None) -> None:
        group = self.application.groups.add_group(grp_id, name)

        for epid in self.endpoints:
            if not epid:
                continue  # skip ZDO
            group.add_member(self.endpoints[epid])
        return [0]

    async def remove_from_group(self, grp_id: int) -> None:
        for epid in self.endpoints:
            if not epid:
                continue  # skip ZDO
            self.application.groups[grp_id].remove_member(self.endpoints[epid])
        return [0]

    @property
    def manufacturer(self):
        return "dresden elektronik"

    @property
    def model(self):
        return 'ConBee'

    @classmethod
    async def new(cls, application, ieee, nwk):
        """Create or replace zigpy device."""
        dev = cls(application, ieee, nwk)

        if ieee in application.devices:
            from_dev = application.get_device(ieee=ieee)
            dev.status = from_dev.status
            dev.node_desc = from_dev.node_desc
            for ep_id, from_ep in from_dev.endpoints.items():
                if not ep_id:
                    continue  # Skip ZDO
                ep = dev.add_endpoint(ep_id)
                ep.profile_id = from_ep.profile_id
                ep.device_type = from_ep.device_type
                ep.status = from_ep.status
                ep.in_clusters = from_ep.in_clusters
                ep.out_clusters = from_ep.out_clusters
        else:
            application.devices[ieee] = dev
            await dev._initialize()

        return dev
