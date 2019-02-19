import asyncio
import binascii
import logging

from zigpy_deconz.api import NETWORK_PARAMETER, NETWORK_STATE
from zigpy_deconz import types as t

import zigpy.application
import zigpy.types
import zigpy.util
import zigpy.device


LOGGER = logging.getLogger(__name__)

SEND_CONFIRM_TIMEOUT = 15


class ControllerApplication(zigpy.application.ControllerApplication):
    def __init__(self, api, database_file=None):
        super().__init__(database_file=database_file)
        self._api = api
        api.set_application(self)

        self._pending = {}

        self._nwk = 0
        self.discovering = False
        self.version = 0

        asyncio.ensure_future(self._reset_watchdog())

    async def _reset_watchdog(self):
        while True:
            await self._api.write_parameter(NETWORK_PARAMETER['watchdog_ttl'][0], 3600)
            await asyncio.sleep(1200)

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
        LOGGER.debug("Zigbee request with id %s, data: %s", sequence, binascii.hexlify(data))
        assert sequence not in self._pending
        send_fut = asyncio.Future()
        reply_fut = None
        if expect_reply:
            reply_fut = asyncio.Future()
        self._pending[sequence] = (send_fut, reply_fut)
        dst_addr = t.DeconzAddress()
        dst_addr.address_mode = t.uint8_t(t.ADDRESS_MODE.NWK.value)
        dst_addr.address = t.uint16_t(nwk)

        await self._api.aps_data_request(
            sequence,
            dst_addr,
            dst_ep,
            profile,
            cluster,
            min(1, src_ep),
            data
        )

        try:
            r = await asyncio.wait_for(send_fut, SEND_CONFIRM_TIMEOUT)
        except asyncio.TimeoutError:
            self._pending.pop(sequence, None)
            LOGGER.warning("Failed to receive transmit confirm for request id: %s", sequence)
            raise

        if r:
            LOGGER.warning("Error while sending frame: 0x%02x", r)

        if not expect_reply:
            return

        try:
            return await asyncio.wait_for(reply_fut, timeout)
        except asyncio.TimeoutError:
            self._pending.pop(sequence, None)
            raise

    async def permit_ncp(self, time_s=60):
        assert 0 <= time_s <= 254
        await self._api.write_parameter(
            NETWORK_PARAMETER['permit_join'][0],
            time_s
        )

    def handle_rx(self, src_addr, src_ep, dst_ep, profile_id, cluster_id, data, lqi, rssi):
        # intercept ZDO device announce frames
        if dst_ep == 0 and cluster_id == 0x13:
            nwk, data = t.uint16_t.deserialize(data[1:])
            ieee = zigpy.types.EUI64(map(t.uint8_t, data[7::-1]))
            LOGGER.info("New device joined: 0x%04x, %s", nwk, ieee)
            self.handle_join(nwk, ieee, 0)
        if not src_addr.address_mode == t.ADDRESS_MODE.NWK.value:
            raise Exception("Unsupported address mode in handle_rx: %s" % (src_addr.address_mode))

        try:
            device = self.get_device(nwk=src_addr.address)
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
            _, reply_fut = self._pending[tsn]
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

    def handle_tx_confirm(self, sequence, status):
        try:
            send_fut, _ = self._pending[sequence]
            if send_fut:
                send_fut.set_result(status)
            return
        except KeyError as exc:
            LOGGER.warning("Unexpected transmit confirm for request id %s, Status: 0x%02x, %s", sequence, status, exc)
        except asyncio.futures.InvalidStateError as exc:
            LOGGER.debug("Invalid state on future - probably duplicate response: %s", exc)

    async def broadcast(self, profile, cluster, src_ep, dst_ep, grpid, radius,
                        sequence, data, broadcast_address):
        LOGGER.debug("Broadcast not implemented.")
