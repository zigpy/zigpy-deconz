import asyncio
import binascii
import logging

import zigpy.application
import zigpy.device
import zigpy.endpoint
import zigpy.exceptions
import zigpy.types
import zigpy.util
import zigpy_deconz.exception
from zigpy_deconz import types as t
from zigpy_deconz.api import NETWORK_PARAMETER, NetworkState

LOGGER = logging.getLogger(__name__)

CHANGE_NETWORK_WAIT = 1
SEND_CONFIRM_TIMEOUT = 60


class ControllerApplication(zigpy.application.ControllerApplication):
    def __init__(self, api, database_file=None):
        super().__init__(database_file=database_file)
        self._api = api
        api.set_application(self)

        self._pending = zigpy.util.Requests()

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
        if self._api.network_state == NetworkState.CONNECTED.value:
            return

        await self._api.change_network_state(NetworkState.CONNECTED.value)
        for _ in range(10):
            await self._api.device_state()
            if self._api.network_state == NetworkState.CONNECTED.value:
                return
            await asyncio.sleep(CHANGE_NETWORK_WAIT)
        raise Exception("Could not form network.")

    @zigpy.util.retryable_request
    async def request(self, device, profile, cluster, src_ep, dst_ep, sequence, data,
                      expect_reply=True, use_ieee=False):
        req_id = self.get_sequence()
        LOGGER.debug("Sending Zigbee request with tsn %s under %s request id, data: %s",
                     sequence, req_id, binascii.hexlify(data))
        dst_addr_ep = t.DeconzAddressEndpoint()
        dst_addr_ep.endpoint = t.uint8_t(dst_ep)
        if use_ieee:
            dst_addr_ep.address_mode = t.uint8_t(t.ADDRESS_MODE.IEEE)
            dst_addr_ep.address = device.ieee
        else:
            dst_addr_ep.address_mode = t.uint8_t(t.ADDRESS_MODE.NWK)
            dst_addr_ep.address = device.nwk

        with self._pending.new(req_id) as req:
            try:
                await self._api.aps_data_request(
                    req_id,
                    dst_addr_ep,
                    profile,
                    cluster,
                    min(1, src_ep),
                    data
                )
            except zigpy_deconz.exception.CommandError as ex:
                return ex.status, "Couldn't enqueue send data request: {}".format(ex)

            r = await asyncio.wait_for(req.result, SEND_CONFIRM_TIMEOUT)

            if r:
                LOGGER.warning("Error while sending %s req id frame: 0x%02x", req_id, r)
                return r, "message send failure"

            return r, "message send success"

    async def broadcast(self, profile, cluster, src_ep, dst_ep, grpid, radius,
                        sequence, data,
                        broadcast_address=zigpy.types.BroadcastAddress.RX_ON_WHEN_IDLE):
        req_id = self.get_sequence()
        LOGGER.debug("Sending Zigbee broadcast with tsn %s under %s request id, data: %s",
                     sequence, req_id, binascii.hexlify(data))
        dst_addr_ep = t.DeconzAddressEndpoint()
        dst_addr_ep.address_mode = t.uint8_t(t.ADDRESS_MODE.GROUP.value)
        dst_addr_ep.address = t.uint16_t(broadcast_address)

        with self._pending.new(req_id) as req:
            try:
                await self._api.aps_data_request(
                    req_id,
                    dst_addr_ep,
                    profile,
                    cluster,
                    min(1, src_ep),
                    data
                )
            except zigpy_deconz.exception.CommandError as ex:
                return ex.status, "Couldn't enqueue send data request for broadcast: {}".format(ex)

            r = await asyncio.wait_for(req.result, SEND_CONFIRM_TIMEOUT)

            if r:
                LOGGER.warning("Error while sending %s req id broadcast: 0x%02x",
                               req_id, r)
                return r, "broadcast send failure"
            return r, "broadcast send success"

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

        device.radio_details(lqi, rssi)
        self.handle_message(device, profile_id, cluster_id, src_ep, dst_ep, data)

    def handle_tx_confirm(self, req_id, status):
        try:
            self._pending[req_id].result.set_result(status)
            return
        except KeyError as exc:
            LOGGER.warning("Unexpected transmit confirm for request id %s, Status: 0x%02x, %s", req_id, status, exc)
        except asyncio.futures.InvalidStateError as exc:
            LOGGER.debug("Invalid state on future - probably duplicate response: %s", exc)


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
