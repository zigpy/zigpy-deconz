"""ControllerApplication for deCONZ protocol based adapters."""

from __future__ import annotations

import asyncio
import binascii
import contextlib
import logging
import re
import time
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

import zigpy_deconz
from zigpy_deconz import types as t
from zigpy_deconz.api import (
    Deconz,
    NetworkParameter,
    NetworkState,
    SecurityMode,
    Status,
)
from zigpy_deconz.config import (
    CONF_DECONZ_CONFIG,
    CONF_MAX_CONCURRENT_REQUESTS,
    CONF_WATCHDOG_TTL,
    CONFIG_SCHEMA,
    SCHEMA_DEVICE,
)
import zigpy_deconz.exception

LOGGER = logging.getLogger(__name__)

CHANGE_NETWORK_WAIT = 1
DELAY_NEIGHBOUR_SCAN_S = 1500
SEND_CONFIRM_TIMEOUT = 60
PROTO_VER_MANUAL_SOURCE_ROUTE = 0x010C
PROTO_VER_WATCHDOG = 0x0108
PROTO_VER_NEIGBOURS = 0x0107
WATCHDOG_TTL = 600
MAX_NUM_ENDPOINTS = 2  # defined in firmware


class ControllerApplication(zigpy.application.ControllerApplication):
    SCHEMA = CONFIG_SCHEMA
    SCHEMA_DEVICE = SCHEMA_DEVICE

    def __init__(self, config: dict[str, Any]):
        """Initialize instance."""

        super().__init__(config=zigpy.config.ZIGPY_SCHEMA(config))
        self._api = None

        self._pending = zigpy.util.Requests()
        self._concurrent_requests_semaphore = asyncio.Semaphore(
            self._config[CONF_DECONZ_CONFIG][CONF_MAX_CONCURRENT_REQUESTS]
        )
        self._currently_waiting_requests = 0

        self._nwk = 0
        self.version = 0
        self._reset_watchdog_task = None

        self._written_endpoints = set()

    async def _reset_watchdog(self):
        while True:
            try:
                await self._api.write_parameter(
                    NetworkParameter.watchdog_ttl, self._config[CONF_WATCHDOG_TTL]
                )
            except Exception as e:
                LOGGER.warning("Failed to reset watchdog", exc_info=e)

            await asyncio.sleep(self._config[CONF_WATCHDOG_TTL] * 0.75)

    async def connect(self):
        api = Deconz(self, self._config[zigpy.config.CONF_DEVICE])
        await api.connect()
        self.version = await api.version()
        self._api = api
        self._written_endpoints.clear()

    async def disconnect(self):
        if self._reset_watchdog_task is not None:
            self._reset_watchdog_task.cancel()

        if self._api is not None:
            self._api.close()

    async def permit_with_key(self, node: t.EUI64, code: bytes, time_s=60):
        raise NotImplementedError()

    async def start_network(self):
        await self.register_endpoints()
        await self.load_network_info(load_devices=False)

        try:
            await self._change_network_state(NetworkState.CONNECTED)
        except asyncio.TimeoutError as e:
            raise FormationFailure() from e

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

    async def _change_network_state(
        self, target_state: NetworkState, *, timeout: int = 10 * CHANGE_NETWORK_WAIT
    ):
        async def change_loop():
            while True:
                (state, _, _) = await self._api.device_state()
                if state.network_state == target_state:
                    break
                await asyncio.sleep(CHANGE_NETWORK_WAIT)

        await self._api.change_network_state(target_state)
        await asyncio.wait_for(change_loop(), timeout=timeout)

        if self._api.protocol_version < PROTO_VER_WATCHDOG:
            return

        if self._reset_watchdog_task is not None:
            self._reset_watchdog_task.cancel()

        if target_state == NetworkState.CONNECTED:
            self._reset_watchdog_task = asyncio.create_task(self._reset_watchdog())

    async def write_network_info(self, *, network_info, node_info):
        try:
            await self._api.write_parameter(
                NetworkParameter.nwk_frame_counter, network_info.network_key.tx_counter
            )
        except zigpy_deconz.exception.CommandError as ex:
            assert ex.status == Status.UNSUPPORTED
            LOGGER.warning(
                "Writing network frame counter is not supported with this firmware"
            )

        if node_info.logical_type == zdo_t.LogicalType.Coordinator:
            await self._api.write_parameter(
                NetworkParameter.aps_designed_coordinator, 1
            )
        else:
            await self._api.write_parameter(
                NetworkParameter.aps_designed_coordinator, 0
            )

        await self._api.write_parameter(NetworkParameter.nwk_address, node_info.nwk)

        if node_info.ieee != zigpy.types.EUI64.UNKNOWN:
            # TODO: is there a way to revert it back to the hardware default? Or is this
            #       information lost when the parameter is overwritten?
            await self._api.write_parameter(
                NetworkParameter.mac_address, node_info.ieee
            )
            node_ieee = node_info.ieee
        else:
            (ieee,) = await self._api[NetworkParameter.mac_address]
            node_ieee = zigpy.types.EUI64(ieee)

        # There is no way to specify both a mask and the logical channel
        if network_info.channel is not None:
            channel_mask = zigpy.types.Channels.from_channel_list(
                [network_info.channel]
            )

            if network_info.channel_mask and channel_mask != network_info.channel_mask:
                LOGGER.warning(
                    "Channel mask %s will be replaced with current logical channel %s",
                    network_info.channel_mask,
                    channel_mask,
                )
        else:
            channel_mask = network_info.channel_mask

        await self._api.write_parameter(NetworkParameter.channel_mask, channel_mask)
        await self._api.write_parameter(NetworkParameter.use_predefined_nwk_panid, True)
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

        if network_info.network_key.seq != 0:
            LOGGER.warning(
                "Non-zero network key sequence number is not supported: %s",
                network_info.network_key.seq,
            )

        tc_link_key_partner_ieee = network_info.tc_link_key.partner_ieee

        if tc_link_key_partner_ieee == zigpy.types.EUI64.UNKNOWN:
            tc_link_key_partner_ieee = node_ieee

        await self._api.write_parameter(
            NetworkParameter.trust_center_address,
            tc_link_key_partner_ieee,
        )
        await self._api.write_parameter(
            NetworkParameter.link_key,
            tc_link_key_partner_ieee,
            network_info.tc_link_key.key,
        )

        if network_info.security_level == 0x00:
            await self._api.write_parameter(
                NetworkParameter.security_mode, SecurityMode.NO_SECURITY
            )
        else:
            await self._api.write_parameter(
                NetworkParameter.security_mode, SecurityMode.ONLY_TCLK
            )

        # Note: Changed network configuration parameters become only affective after
        # sending a Leave Network Request followed by a Create or Join Network Request
        await self._change_network_state(NetworkState.OFFLINE)
        await self._change_network_state(NetworkState.CONNECTED)

    async def load_network_info(self, *, load_devices=False):
        network_info = self.state.network_info
        node_info = self.state.node_info

        network_info.source = f"zigpy-deconz@{zigpy_deconz.__version__}"
        network_info.metadata = {
            "deconz": {
                "version": self.version,
            }
        }

        (ieee,) = await self._api[NetworkParameter.mac_address]
        node_info.ieee = zigpy.types.EUI64(ieee)
        (designed_coord,) = await self._api[NetworkParameter.aps_designed_coordinator]

        if designed_coord == 0x01:
            node_info.logical_type = zdo_t.LogicalType.Coordinator
        else:
            node_info.logical_type = zdo_t.LogicalType.Router

        (node_info.nwk,) = await self._api[NetworkParameter.nwk_address]

        (network_info.pan_id,) = await self._api[NetworkParameter.nwk_panid]
        (network_info.extended_pan_id,) = await self._api[
            NetworkParameter.aps_extended_panid
        ]

        if network_info.extended_pan_id == zigpy.types.EUI64.convert(
            "00:00:00:00:00:00:00:00"
        ):
            (network_info.extended_pan_id,) = await self._api[
                NetworkParameter.nwk_extended_panid
            ]

        (network_info.channel,) = await self._api[NetworkParameter.current_channel]
        (network_info.channel_mask,) = await self._api[NetworkParameter.channel_mask]
        (network_info.nwk_update_id,) = await self._api[NetworkParameter.nwk_update_id]

        if network_info.channel == 0:
            raise NetworkNotFormed("Network channel is zero")

        network_info.network_key = zigpy.state.Key()
        (
            _,
            network_info.network_key.key,
        ) = await self._api.read_parameter(NetworkParameter.network_key, 0)

        try:
            (network_info.network_key.tx_counter,) = await self._api[
                NetworkParameter.nwk_frame_counter
            ]
        except zigpy_deconz.exception.CommandError as ex:
            assert ex.status == Status.UNSUPPORTED

        network_info.tc_link_key = zigpy.state.Key()
        (network_info.tc_link_key.partner_ieee,) = await self._api[
            NetworkParameter.trust_center_address
        ]

        (_, network_info.tc_link_key.key) = await self._api.read_parameter(
            NetworkParameter.link_key,
            network_info.tc_link_key.partner_ieee,
        )

        (security_mode,) = await self._api[NetworkParameter.security_mode]

        if security_mode == SecurityMode.NO_SECURITY:
            network_info.security_level = 0x00
        elif security_mode == SecurityMode.ONLY_TCLK:
            network_info.security_level = 0x05
        else:
            LOGGER.warning("Unsupported security mode %r", security_mode)
            network_info.security_level = 0x05

    async def force_remove(self, dev):
        """Forcibly remove device from NCP."""
        pass

    async def add_endpoint(self, descriptor: zdo_t.SimpleDescriptor) -> None:
        """Register a new endpoint on the device, replacing any with conflicting IDs.

        Only three endpoints can be defined.
        """

        endpoints = {}

        # Read the current endpoints
        for index in range(MAX_NUM_ENDPOINTS):
            try:
                _, current_descriptor = await self._api.read_parameter(
                    NetworkParameter.configure_endpoint, index
                )
            except zigpy_deconz.exception.CommandError as ex:
                assert ex.status == Status.UNSUPPORTED
                current_descriptor = None

            endpoints[index] = current_descriptor

        LOGGER.debug("Got endpoint slots: %r", endpoints)

        # Don't write endpoints unnecessarily
        if descriptor in endpoints.values():
            LOGGER.debug("Endpoint already registered, skipping")

            # Pretend we wrote it
            index = next(i for i, desc in endpoints.items() if desc == descriptor)
            self._written_endpoints.add(index)
            return

        # Keep track of the best endpoint descriptor to replace
        target_index = None

        for index, current_descriptor in endpoints.items():
            # Ignore ones we've already written
            if index in self._written_endpoints:
                continue

            target_index = index

            if (
                current_descriptor is not None
                and current_descriptor.endpoint == descriptor.endpoint
            ):
                # Prefer to replace the endpoint with the same ID
                break

        if target_index is None:
            raise ValueError(f"No available endpoint slots exist: {endpoints!r}")

        LOGGER.debug("Writing %s to slot %r", descriptor, target_index)

        await self._api.write_parameter(
            NetworkParameter.configure_endpoint, target_index, descriptor
        )

    @contextlib.asynccontextmanager
    async def _limit_concurrency(self):
        """Async context manager to prevent devices from being overwhelmed by requests.

        Mainly a thin wrapper around `asyncio.Semaphore` that logs when it has to wait.
        """

        start_time = time.time()
        was_locked = self._concurrent_requests_semaphore.locked()

        if was_locked:
            self._currently_waiting_requests += 1
            LOGGER.debug(
                "Max concurrency (%s) reached, delaying requests (%s enqueued)",
                self._config[CONF_DECONZ_CONFIG][CONF_MAX_CONCURRENT_REQUESTS],
                self._currently_waiting_requests,
            )

        try:
            async with self._concurrent_requests_semaphore:
                if was_locked:
                    LOGGER.debug(
                        "Previously delayed request is now running, "
                        "delayed by %0.2f seconds",
                        time.time() - start_time,
                    )

                yield
        finally:
            if was_locked:
                self._currently_waiting_requests -= 1

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
        non_member_radius=3,
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

        async with self._limit_concurrency():
            with self._pending.new(req_id) as req:
                try:
                    await self._api.aps_data_request(
                        req_id, dst_addr_ep, profile, cluster, min(1, src_ep), data
                    )
                except zigpy_deconz.exception.CommandError as ex:
                    return ex.status, f"Couldn't enqueue send data request: {ex!r}"

                r = await asyncio.wait_for(req.result, SEND_CONFIRM_TIMEOUT)
                if r:
                    LOGGER.debug("Error while sending %s req id frame: %s", req_id, r)
                    return r, f"message send failure: {r}"

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

        tx_options = t.DeconzTransmitOptions.USE_NWK_KEY_SECURITY

        async with self._limit_concurrency():
            with self._pending.new(req_id) as req:
                try:
                    await self._api.aps_data_request(
                        req_id,
                        dst_addr_ep,
                        profile,
                        cluster,
                        min(1, src_ep),
                        data,
                        tx_options=tx_options,
                    )
                except zigpy_deconz.exception.CommandError as ex:
                    return ex.status, f"Couldn't enqueue send data request: {ex!r}"

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

        async with self._limit_concurrency():
            with self._pending.new(req_id) as req:
                try:
                    await self._api.aps_data_request(
                        req_id, dst_addr_ep, profile, cluster, min(1, src_ep), data
                    )
                except zigpy_deconz.exception.CommandError as ex:
                    return (
                        ex.status,
                        f"Couldn't enqueue send data request for broadcast: {ex!r}",
                    )

                r = await asyncio.wait_for(req.result, SEND_CONFIRM_TIMEOUT)

                if r:
                    LOGGER.debug(
                        "Error while sending %s req id broadcast: %s", req_id, r
                    )
                    return r, f"broadcast send failure: {r}"
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
        coord = self.get_device(ieee=self.state.node_info.ieee)
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
        coord = self.get_device(ieee=self.state.node_info.ieee)
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
