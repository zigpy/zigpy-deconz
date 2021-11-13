"""ControllerApplication for deCONZ protocol based adapters."""

from __future__ import annotations

import asyncio
import binascii
import logging
import re
from typing import Any

import zigpy.application
import zigpy.config
import zigpy.device
import zigpy.endpoint
import zigpy.exceptions
from zigpy.exceptions import FormationFailure, NetworkNotFormed
import zigpy.neighbor
import zigpy.state
import zigpy.types
import zigpy.util
import zigpy.zdo.types as zdo_t

from zigpy_deconz import types as t
from zigpy_deconz.api import (
    Deconz,
    NetworkParameter,
    NetworkState,
    SecurityMode,
    Status,
)
from zigpy_deconz.config import CONF_WATCHDOG_TTL, CONFIG_SCHEMA, SCHEMA_DEVICE
import zigpy_deconz.exception

LOGGER = logging.getLogger(__name__)

CHANGE_NETWORK_WAIT = 1
DELAY_NEIGHBOUR_SCAN_S = 1500
SEND_CONFIRM_TIMEOUT = 60
PROTO_VER_WATCHDOG = 0x0108
PROTO_VER_NEIGBOURS = 0x0107
WATCHDOG_TTL = 600


class ControllerApplication(zigpy.application.ControllerApplication):
    SCHEMA = CONFIG_SCHEMA
    SCHEMA_DEVICE = SCHEMA_DEVICE

    def __init__(self, config: dict[str, Any]):
        """Initialize instance."""

        super().__init__(config=zigpy.config.ZIGPY_SCHEMA(config))
        self._api = None
        self._pending = zigpy.util.Requests()
        self._nwk = 0
        self.version = 0
        self._reset_watchdog_task = None

    async def _reset_watchdog(self):
        while True:
            try:
                await self._api.write_parameter(
                    NetworkParameter.watchdog_ttl, self._config[CONF_WATCHDOG_TTL]
                )
            except (asyncio.TimeoutError, zigpy.exceptions.ZigbeeException):
                LOGGER.warning("No watchdog response")
            await asyncio.sleep(self._config[CONF_WATCHDOG_TTL] * 0.75)

    async def connect(self):
        api = Deconz(self, self._config[zigpy.config.CONF_DEVICE])
        await api.connect()
        self.version = await api.version()
        self._api = api

        if self._api.protocol_version >= PROTO_VER_WATCHDOG:
            self._reset_watchdog_task = asyncio.create_task(self._reset_watchdog())

    async def disconnect(self):
        if self._reset_watchdog_task is not None:
            self._reset_watchdog_task.cancel()

        try:
            if self._api.protocol_version >= PROTO_VER_WATCHDOG:
                await self._api.write_parameter(NetworkParameter.watchdog_ttl, 0)
        finally:
            self._api.close()

    async def permit_with_key(self, node: t.EUI64, code: bytes, time_s=60):
        raise NotImplementedError()

    async def start_network(self):
        await self.load_network_info(load_devices=False)

        coordinator = await DeconzDevice.new(
            self,
            self.state.node_info.ieee,
            self.state.node_info.nwk,
            self.version,
            self._config[zigpy.config.CONF_DEVICE][zigpy.config.CONF_DEVICE_PATH],
        )

        coordinator.neighbors.add_context_listener(self._dblistener)
        self.devices[self.state.node_info.ieee] = coordinator
        if self._api.protocol_version >= PROTO_VER_NEIGBOURS:
            await self.restore_neighbours()
        asyncio.create_task(self._delayed_neighbour_scan())

    async def write_network_info(self, *, network_info, node_info):
        await self._api.change_network_state(NetworkState.OFFLINE)

        if node_info.logical_type == zdo_t.LogicalType.Coordinator:
            await self._api.write_parameter(
                NetworkParameter.aps_designed_coordinator, 1
            )
        else:
            await self._api.write_parameter(
                NetworkParameter.aps_designed_coordinator, 0
            )

        await self._api.write_parameter(NetworkParameter.nwk_address, node_info.nwk)
        await self._api.write_parameter(NetworkParameter.mac_address, node_info.ieee)

        # No way to specify both a mask and the logical channel
        logical_channel_mask = zigpy.types.Channels.from_channel_list(
            [network_info.channel]
        )

        if logical_channel_mask != network_info.channel_mask:
            LOGGER.warning(
                "Channel mask %s will be replaced with current logical channel %s",
                network_info.channel_mask,
                logical_channel_mask,
            )

        await self._api.write_parameter(
            NetworkParameter.channel_mask, logical_channel_mask
        )
        await self._api.write_parameter(NetworkParameter.nwk_panid, network_info.pan_id)
        await self._api.write_parameter(
            NetworkParameter.aps_extended_panid, network_info.extended_pan_id
        )
        await self._api.write_parameter(
            NetworkParameter.nwk_update_id, network_info.nwk_update_id
        )

        await self._api.write_parameter(
            NetworkParameter.network_key, 0, network_info.network_key.key
        )

        try:
            await self._api.write_parameter(
                NetworkParameter.nwk_frame_counter, network_info.network_key.tx_counter
            )
        except zigpy_deconz.exception.CommandError as ex:
            assert ex.status == Status.UNSUPPORTED
            LOGGER.warning(
                "Writing network frame counter is not supported with this firmware"
            )

        if network_info.tc_link_key is not None:
            await self._api.write_parameter(
                NetworkParameter.trust_center_address,
                network_info.tc_link_key.partner_ieee,
            )
            await self._api.write_parameter(
                NetworkParameter.link_key,
                network_info.tc_link_key.partner_ieee,
                network_info.tc_link_key.key,
            )

        if self.state.network_info.security_level == 0x00:
            await self._api.write_parameter(
                NetworkParameter.security_mode, SecurityMode.NO_SECURITY
            )
        else:
            await self._api.write_parameter(
                NetworkParameter.security_mode, SecurityMode.PRECONFIGURED_NETWORK_KEY
            )

        # bring network up
        await self._api.change_network_state(NetworkState.CONNECTED)

        for _ in range(10):
            (state, _, _) = await self._api.device_state()
            if state.network_state == NetworkState.CONNECTED:
                break
            await asyncio.sleep(CHANGE_NETWORK_WAIT)
        else:
            raise FormationFailure("Could not form network.")

    async def load_network_info(self, *, load_devices=False):
        device_state, _, _ = await self._api.device_state()

        if device_state.network_state != NetworkState.CONNECTED:
            raise NetworkNotFormed()

        (ieee,) = await self._api[NetworkParameter.mac_address]
        self.state.node_info.ieee = zigpy.types.EUI64(ieee)

        (designed_coord,) = await self._api[NetworkParameter.aps_designed_coordinator]

        if designed_coord == 0x01:
            self.state.node_info.logical_type = zdo_t.LogicalType.Coordinator
        else:
            self.state.node_info.logical_type = zdo_t.LogicalType.Router

        (self.state.node_info.nwk,) = await self._api[NetworkParameter.nwk_address]

        (self.state.network_info.pan_id,) = await self._api[NetworkParameter.nwk_panid]
        (self.state.network_info.extended_pan_id,) = await self._api[
            NetworkParameter.nwk_extended_panid
        ]
        (self.state.network_info.channel_mask,) = await self._api[
            NetworkParameter.channel_mask
        ]
        await self._api[NetworkParameter.aps_extended_panid]

        if self.state.network_info.network_key is None:
            self.state.network_info.network_key = zigpy.state.Key()

        (
            _,
            self.state.network_info.network_key.key,
        ) = await self._api.read_parameter(NetworkParameter.network_key, 0)
        self.state.network_info.network_key.seq = 0
        self.state.network_info.network_key.rx_counter = None
        self.state.network_info.network_key.partner_ieee = None

        try:
            (self.state.network_info.network_key.tx_counter,) = await self._api[
                NetworkParameter.nwk_frame_counter
            ]
        except zigpy_deconz.exception.CommandError as ex:
            assert ex.status == Status.UNSUPPORTED
            self.state.network_info.network_key.tx_counter = None

        if self.state.network_info.tc_link_key is None:
            self.state.network_info.tc_link_key = zigpy.state.Key()

        (self.state.network_info.tc_link_key.partner_ieee,) = await self._api[
            NetworkParameter.trust_center_address
        ]
        (_, self.state.network_info.tc_link_key.key,) = await self._api.read_parameter(
            NetworkParameter.link_key,
            self.state.network_info.tc_link_key.partner_ieee,
        )

        (security_mode,) = await self._api[NetworkParameter.security_mode]

        if security_mode == SecurityMode.NO_SECURITY:
            self.state.network_info.security_level = 0x00
        else:
            self.state.network_info.security_level = 0x05

        (self.state.network_info.channel,) = await self._api[
            NetworkParameter.current_channel
        ]
        (self.state.network_info.nwk_update_id,) = await self._api[
            NetworkParameter.nwk_update_id
        ]

    async def force_remove(self, dev):
        """Forcibly remove device from NCP."""
        pass

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
                LOGGER.debug("Error while sending %s req id frame: %s", req_id, r)
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
                LOGGER.debug("Error while sending %s req id frame: %s", req_id, r)
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
        dst_addr_ep.address_mode = t.uint8_t(t.ADDRESS_MODE.NWK.value)
        dst_addr_ep.address = t.uint16_t(broadcast_address)
        dst_addr_ep.endpoint = dst_ep

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
                LOGGER.debug("Error while sending %s req id broadcast: %s", req_id, r)
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

    async def restore_neighbours(self) -> None:
        """Restore children."""
        coord = self.get_device(ieee=self.ieee)
        devices = (nei.device for nei in coord.neighbors)
        for device in devices:
            if device is None:
                continue
            descr = device.node_desc
            LOGGER.debug(
                "device: 0x%04x - %s %s, FFD=%s, Rx_on_when_idle=%s",
                device.nwk,
                device.manufacturer,
                device.model,
                descr.is_full_function_device if descr is not None else None,
                descr.is_receiver_on_when_idle if descr is not None else None,
            )
            if (
                descr is None
                or descr.is_full_function_device
                or descr.is_receiver_on_when_idle
            ):
                continue
            LOGGER.debug(
                "Restoring %s/0x%04x device as direct child",
                device.ieee,
                device.nwk,
            )
            await self._api.add_neighbour(
                0x01, device.nwk, device.ieee, descr.mac_capability_flags
            )

    async def _delayed_neighbour_scan(self) -> None:
        """Scan coordinator's neighbours."""
        await asyncio.sleep(DELAY_NEIGHBOUR_SCAN_S)
        coord = self.get_device(ieee=self.ieee)
        await coord.neighbors.scan()


class DeconzDevice(zigpy.device.Device):
    """Zigpy Device representing Coordinator."""

    def __init__(self, version: int, device_path: str, *args):
        """Initialize instance."""

        super().__init__(*args)
        is_gpio_device = re.match(r"/dev/tty(S|AMA|ACM)\d+", device_path)
        self._model = "RaspBee" if is_gpio_device else "ConBee"
        self._model += " II" if ((version & 0x0000FF00) == 0x00000700) else ""

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
        return self._model

    @classmethod
    async def new(cls, application, ieee, nwk, version: int, device_path: str):
        """Create or replace zigpy device."""
        dev = cls(version, device_path, application, ieee, nwk)

        if ieee in application.devices:
            from_dev = application.get_device(ieee=ieee)
            dev.status = from_dev.status
            dev.node_desc = from_dev.node_desc
            dev.neighbors = zigpy.neighbor.Neighbors(dev)
            for nei in from_dev.neighbors.neighbors:
                dev.neighbors.add_neighbor(nei.neighbor)
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
            await dev.initialize()

        return dev
