import asyncio
import binascii
import logging
from typing import Any, Dict

import zigpy.application
import zigpy.config
import zigpy.device
import zigpy.endpoint
import zigpy.exceptions
import zigpy.types
import zigpy.util

from zigpy_deconz import types as t
from zigpy_deconz.api import Deconz, NetworkParameter, NetworkState, Status
from zigpy_deconz.config import CONF_WATCHDOG_TTL, CONFIG_SCHEMA
import zigpy_deconz.exception

LOGGER = logging.getLogger(__name__)

CHANGE_NETWORK_WAIT = 1
SEND_CONFIRM_TIMEOUT = 60
PROTO_VER_WATCHDOG = 0x0108
WATCHDOG_TTL = 600


class ControllerApplication(zigpy.application.ControllerApplication):
    SCHEMA = CONFIG_SCHEMA

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config=zigpy.config.ZIGPY_SCHEMA(config))
        self._api = None
        self._pending = zigpy.util.Requests()
        self._nwk = 0
        self.version = 0

    async def _reset_watchdog(self):
        while True:
            try:
                await self._api.write_parameter(
                    NetworkParameter.watchdog_ttl, self._config[CONF_WATCHDOG_TTL]
                )
            except (asyncio.TimeoutError, zigpy.exceptions.ZigbeeException):
                LOGGER.warning("No watchdog response")
            await asyncio.sleep(self._config[CONF_WATCHDOG_TTL] * 0.75)

    async def shutdown(self):
        """Shutdown application."""
        self._api.close()

    async def startup(self, auto_form=False):
        """Perform a complete application startup"""
        self._api = Deconz(self, self._config[zigpy.config.CONF_DEVICE])
        await self._api.connect()
        self.version = await self._api.version()
        await self._api.device_state()
        (ieee,) = await self._api[NetworkParameter.mac_address]
        self._ieee = zigpy.types.EUI64(ieee)
        await self._api[NetworkParameter.nwk_panid]
        await self._api[NetworkParameter.nwk_address]
        await self._api[NetworkParameter.nwk_extended_panid]
        await self._api[NetworkParameter.channel_mask]
        await self._api[NetworkParameter.aps_extended_panid]
        await self._api[NetworkParameter.trust_center_address]
        await self._api[NetworkParameter.security_mode]
        await self._api[NetworkParameter.current_channel]
        await self._api[NetworkParameter.protocol_version]
        await self._api[NetworkParameter.nwk_update_id]
        self._api[NetworkParameter.aps_designed_coordinator] = 1

        if self._api.protocol_version >= PROTO_VER_WATCHDOG:
            asyncio.ensure_future(self._reset_watchdog())

        if auto_form:
            await self.form_network()
        self.devices[self.ieee] = await ConBeeDevice.new(self, self.ieee, self.nwk)

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

    async def mrequest(
        self,
        group_id,
        profile,
        cluster,
        src_ep,
        sequence,
        data,
        *,
        hops=0,
        non_member_radius=3
    ):
        """Submit and send data out as a multicast transmission.

        :param group_id: destination multicast address
        :param profile: Zigbee Profile ID to use for outgoing message
        :param cluster: cluster id where the message is being sent
        :param src_ep: source endpoint id
        :param sequence: transaction sequence number of the message
        :param data: Zigbee message payload
        :param hops: the message will be delivered to all nodes within this number of
                     hops of the sender. A value of zero is converted to MAX_HOPS
        :param non_member_radius: the number of hops that the message will be forwarded
                                  by devices that are not members of the group. A value
                                  of 7 or greater is treated as infinite
        :returns: return a tuple of a status and an error_message. Original requestor
                  has more context to provide a more meaningful error message
        """
        req_id = self.get_sequence()
        LOGGER.debug(
            "Sending Zigbee multicast with tsn %s under %s request id, data: %s",
            sequence,
            req_id,
            binascii.hexlify(data),
        )
        dst_addr_ep = t.DeconzAddressEndpoint()
        dst_addr_ep.address_mode = t.ADDRESS_MODE.GROUP
        dst_addr_ep.address = group_id

        with self._pending.new(req_id) as req:
            try:
                await self._api.aps_data_request(
                    req_id, dst_addr_ep, profile, cluster, min(1, src_ep), data
                )
            except zigpy_deconz.exception.CommandError as ex:
                return ex.status, "Couldn't enqueue send data request: {}".format(ex)

            r = await asyncio.wait_for(req.result, SEND_CONFIRM_TIMEOUT)
            if r:
                LOGGER.warning("Error while sending %s req id frame: %s", req_id, r)
                return r, "message send failure"

        return Status.SUCCESS, "message send success"

    @zigpy.util.retryable_request
    async def request(
        self,
        device,
        profile,
        cluster,
        src_ep,
        dst_ep,
        sequence,
        data,
        expect_reply=True,
        use_ieee=False,
    ):
        req_id = self.get_sequence()
        LOGGER.debug(
            "Sending Zigbee request with tsn %s under %s request id, data: %s",
            sequence,
            req_id,
            binascii.hexlify(data),
        )
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
                    req_id, dst_addr_ep, profile, cluster, min(1, src_ep), data
                )
            except zigpy_deconz.exception.CommandError as ex:
                return ex.status, "Couldn't enqueue send data request: {}".format(ex)

            r = await asyncio.wait_for(req.result, SEND_CONFIRM_TIMEOUT)

            if r:
                LOGGER.warning("Error while sending %s req id frame: %s", req_id, r)
                return r, "message send failure"

            return r, "message send success"

    async def broadcast(
        self,
        profile,
        cluster,
        src_ep,
        dst_ep,
        grpid,
        radius,
        sequence,
        data,
        broadcast_address=zigpy.types.BroadcastAddress.RX_ON_WHEN_IDLE,
    ):
        req_id = self.get_sequence()
        LOGGER.debug(
            "Sending Zigbee broadcast with tsn %s under %s request id, data: %s",
            sequence,
            req_id,
            binascii.hexlify(data),
        )
        dst_addr_ep = t.DeconzAddressEndpoint()
        dst_addr_ep.address_mode = t.uint8_t(t.ADDRESS_MODE.GROUP.value)
        dst_addr_ep.address = t.uint16_t(broadcast_address)

        with self._pending.new(req_id) as req:
            try:
                await self._api.aps_data_request(
                    req_id, dst_addr_ep, profile, cluster, min(1, src_ep), data
                )
            except zigpy_deconz.exception.CommandError as ex:
                return (
                    ex.status,
                    "Couldn't enqueue send data request for broadcast: {}".format(ex),
                )

            r = await asyncio.wait_for(req.result, SEND_CONFIRM_TIMEOUT)

            if r:
                LOGGER.warning("Error while sending %s req id broadcast: %s", req_id, r)
                return r, "broadcast send failure"
            return r, "broadcast send success"

    async def permit_ncp(self, time_s=60):
        assert 0 <= time_s <= 254
        await self._api.write_parameter(NetworkParameter.permit_join, time_s)

    def handle_rx(
        self, src_addr, src_ep, dst_ep, profile_id, cluster_id, data, lqi, rssi
    ):
        # intercept ZDO device announce frames
        if dst_ep == 0 and cluster_id == 0x13:
            nwk, rest = t.uint16_t.deserialize(data[1:])
            ieee, _ = zigpy.types.EUI64.deserialize(rest)
            LOGGER.info("New device joined: 0x%04x, %s", nwk, ieee)
            self.handle_join(nwk, ieee, 0)

        try:
            if src_addr.address_mode == t.ADDRESS_MODE.NWK_AND_IEEE:
                device = self.get_device(ieee=src_addr.ieee)
            elif src_addr.address_mode == t.ADDRESS_MODE.NWK.value:
                device = self.get_device(nwk=src_addr.address)
            elif src_addr.address_mode == t.ADDRESS_MODE.IEEE.value:
                device = self.get_device(ieee=src_addr.address)
            else:
                raise Exception(
                    "Unsupported address mode in handle_rx: %s"
                    % (src_addr.address_mode)
                )
        except KeyError:
            LOGGER.debug("Received frame from unknown device: 0x%04x", src_addr.address)
            return

        device.radio_details(lqi, rssi)
        self.handle_message(device, profile_id, cluster_id, src_ep, dst_ep, data)

    def handle_tx_confirm(self, req_id, status):
        try:
            self._pending[req_id].result.set_result(status)
            return
        except KeyError:
            LOGGER.warning(
                "Unexpected transmit confirm for request id %s, Status: %s",
                req_id,
                status,
            )
        except asyncio.InvalidStateError as exc:
            LOGGER.debug(
                "Invalid state on future - probably duplicate response: %s", exc
            )


class ConBeeDevice(zigpy.device.Device):
    """Zigpy Device representing Coordinator."""

    async def add_to_group(self, grp_id: int, name: str = None) -> None:
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
        return "ConBee"

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
