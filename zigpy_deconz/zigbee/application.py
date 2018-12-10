import asyncio
import binascii
import logging

from zigpy_deconz.api import NETWORK_PARAMETER, NETWORK_STATE
from zigpy_deconz import types as t

import zigpy.application
import zigpy.types
import zigpy.util
import zigpy.device


DISCOVERY_DEVICE = zigpy.types.EUI64([t.uint8_t(0xEE) for a in range(8)])

LOGGER = logging.getLogger(__name__)


class ControllerApplication(zigpy.application.ControllerApplication):
    def __init__(self, api, database_file=None):
        super().__init__(database_file=database_file)
        self._api = api
        api.set_application(self)

        self._pending = {}

        self._nwk = 0
        self.discovering = False

    async def startup(self, auto_form=False):
        """Perform a complete application startup"""
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
        if auto_form:
            await self.form_network()

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
            await asyncio.sleep(1)
        raise Exception("Could not form network.")

    @zigpy.util.retryable_request
    async def request(self, nwk, profile, cluster, src_ep, dst_ep, sequence, data, expect_reply=True, timeout=10):
        LOGGER.debug("Zigbee request seq %s, data: %s", sequence, binascii.hexlify(data))
        assert sequence not in self._pending
        if expect_reply:
            reply_fut = asyncio.Future()
            self._pending[sequence] = reply_fut
        dst_addr = t.DeconzAddress()
        dst_addr.address_mode = t.uint8_t(t.ADDRESS_MODE.NWK.value)
        dst_addr.address = t.uint16_t(nwk)
        await self._api.aps_data_request(
            dst_addr,
            dst_ep,
            profile,
            cluster,
            src_ep,
            data
        )

        if not expect_reply:
            return

        try:
            return await asyncio.wait_for(reply_fut, timeout)
        except asyncio.TimeoutError:
            self._pending.pop(sequence, None)
            raise

    async def permit(self, time_s=60):
        assert 0 <= time_s <= 254
        await self._api.write_parameter(
            NETWORK_PARAMETER['permit_join'][0],
            time_s
        )

    def handle_rx(self, src_addr, src_ep, dst_ep, profile_id, cluster_id, data, lqi, rssi):
        if not src_addr.address_mode == t.ADDRESS_MODE.NWK.value:
            raise Exception("Unsupported address mode in handle_rx: %s" % (src_addr.address_mode))

        nwk = src_addr.address
        try:
            device = self.get_device(nwk=nwk)
        except KeyError:
            # we do not know the ieee addr yet, so use a dummy for now
            device = self.add_device(DISCOVERY_DEVICE, nwk)
            if not self.discovering:
                LOGGER.debug("Start device discovery: %s", nwk)
                asyncio.ensure_future(self._discovery(device, 0))

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
            reply_fut = self._pending[tsn]
            if reply_fut:
                self._pending.pop(tsn)
                reply_fut.set_result(args)
            return
        except KeyError as exc:
            LOGGER.warning("Unexpected response TSN=%s command=%s args=%s, %s", tsn, command_id, args, exc)
        except asyncio.futures.InvalidStateError as exc:
            LOGGER.debug("Invalid state on future - probably duplicate response: %s", exc)
            # We've already handled, don't drop through to device handler
            return

        self.handle_message(device, True, profile, cluster, src_ep, dst_ep, tsn, command_id, args)

    async def _discovery(self, dev, parent_nwk):
        try:
            r = await dev.zdo.request(0x0001, dev.nwk, 0, 0, tries=3, delay=2)
            if r[0] != 0:
                raise Exception("ZDO ieee address request failed: %s", r)
        except Exception as exc:
            self.discovering = False
            LOGGER.exception("Failed ZDO ieee address request during device discovery: %s", exc)
            return
        LOGGER.debug("ZDO ieee addr response: %s", r[1])
        dev._ieee = r[1]
        self.discovering = False
        self.handle_join(dev.nwk, dev.ieee, parent_nwk)
