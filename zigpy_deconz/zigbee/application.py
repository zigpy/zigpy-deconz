"""ControllerApplication for deCONZ protocol based adapters."""

from __future__ import annotations

import asyncio
import importlib.metadata
import logging
import re
import sys
from typing import Any

if sys.version_info[:2] < (3, 11):
    from async_timeout import timeout as asyncio_timeout  # pragma: no cover
else:
    from asyncio import timeout as asyncio_timeout  # pragma: no cover

import zigpy.application
import zigpy.config
import zigpy.device
import zigpy.endpoint
import zigpy.exceptions
from zigpy.exceptions import FormationFailure, NetworkNotFormed
import zigpy.state
import zigpy.types
import zigpy.util
import zigpy.zdo.types as zdo_t

import zigpy_deconz
from zigpy_deconz import types as t
from zigpy_deconz.api import (
    Deconz,
    FirmwarePlatform,
    IndexedEndpoint,
    IndexedKey,
    LinkKey,
    NetworkParameter,
    NetworkState,
    SecurityMode,
    Status,
    TXStatus,
)
from zigpy_deconz.config import CONFIG_SCHEMA
import zigpy_deconz.exception

LIB_VERSION = importlib.metadata.version("zigpy-deconz")
LOGGER = logging.getLogger(__name__)

CHANGE_NETWORK_POLL_TIME = 1
CHANGE_NETWORK_STATE_DELAY = 2
DELAY_NEIGHBOUR_SCAN_S = 1500
SEND_CONFIRM_TIMEOUT = 60

PROTO_VER_MANUAL_SOURCE_ROUTE = 0x010C
PROTO_VER_WATCHDOG = 0x0108
PROTO_VER_NEIGBOURS = 0x0107

CONBEE_III_ENERGY_SCAN_ATTEMPTS = 5


class ControllerApplication(zigpy.application.ControllerApplication):
    SCHEMA = CONFIG_SCHEMA

    _probe_config_variants = [
        {zigpy.config.CONF_DEVICE_BAUDRATE: 38400},
        {zigpy.config.CONF_DEVICE_BAUDRATE: 115200},
    ]

    _watchdog_period = 30

    def __init__(self, config: dict[str, Any]):
        """Initialize instance."""

        super().__init__(config=config)
        self._api = None

        self._pending_requests = {}

        self._delayed_neighbor_scan_task = None
        self._reconnect_task = None

        self._written_endpoints = set()

    async def _watchdog_feed(self):
        if self._api.protocol_version >= PROTO_VER_WATCHDOG and not (
            self._api.firmware_version.platform == FirmwarePlatform.Conbee_III
            and self._api.firmware_version <= 0x26450900
        ):
            await self._api.write_parameter(
                NetworkParameter.watchdog_ttl, int(2 * self._watchdog_period)
            )
        else:
            await self._api.get_device_state()

    async def connect(self):
        api = Deconz(self, self._config[zigpy.config.CONF_DEVICE])

        try:
            await api.connect()
        except Exception:
            await api.disconnect()
            raise

        self._api = api
        self._written_endpoints.clear()

    async def disconnect(self):
        if self._delayed_neighbor_scan_task is not None:
            self._delayed_neighbor_scan_task.cancel()
            self._delayed_neighbor_scan_task = None

        if self._api is not None:
            await self._api.disconnect()
            self._api = None

    async def permit_with_link_key(self, node: t.EUI64, link_key: t.KeyData, time_s=60):
        await self._api.write_parameter(
            NetworkParameter.link_key,
            LinkKey(ieee=node, key=link_key),
        )
        await self.permit(time_s)

    async def start_network(self):
        await self.register_endpoints()
        await self.load_network_info(load_devices=False)
        await self._change_network_state(NetworkState.CONNECTED)

        coordinator = await DeconzDevice.new(
            self,
            self.state.node_info.ieee,
            self.state.node_info.nwk,
            self.state.node_info.model,
        )

        self.devices[self.state.node_info.ieee] = coordinator
        if self._api.protocol_version >= PROTO_VER_NEIGBOURS and not (
            self._api.firmware_version.platform == FirmwarePlatform.Conbee_III
            and self._api.firmware_version < 0x264D0900
        ):
            await self.restore_neighbours()

        self._delayed_neighbor_scan_task = asyncio.create_task(
            self._delayed_neighbour_scan()
        )

    async def _change_network_state(
        self,
        target_state: NetworkState,
        *,
        timeout: int = 10 * CHANGE_NETWORK_POLL_TIME,
    ):
        async def change_loop():
            while True:
                try:
                    device_state = await self._api.get_device_state()
                except asyncio.TimeoutError:
                    # 0x264B0900 and earlier can reset during device state changes
                    # requiring a firmware reset, causing state polling to fail
                    LOGGER.debug("Failed to poll device state")
                else:
                    if NetworkState(device_state.network_state) == target_state:
                        break

                await asyncio.sleep(CHANGE_NETWORK_POLL_TIME)

        await self._api.change_network_state(target_state)

        try:
            async with asyncio_timeout(timeout):
                await change_loop()
        except asyncio.TimeoutError:
            if target_state != NetworkState.CONNECTED:
                raise

            raise FormationFailure(
                "Network formation refused: there is likely too much RF interference."
                " Make sure your coordinator is on a USB 2.0 extension cable and"
                " away from any sources of interference, like USB 3.0 ports, SSDs,"
                " 2.4GHz routers, motherboards, etc."
            )

    async def reset_network_info(self):
        # TODO: There does not appear to be a way to factory reset a Conbee
        await self.form_network()

    async def write_network_info(self, *, network_info, node_info):
        try:
            await self._api.write_parameter(
                NetworkParameter.nwk_frame_counter, network_info.network_key.tx_counter
            )
        except zigpy_deconz.exception.CommandError as ex:
            assert ex.status == Status.UNSUPPORTED
            fw_version = f"{int(self._api.firmware_version):#010x}"
            raise zigpy.exceptions.ControllerException(
                f"Please upgrade your adapter firmware. Firmware version {fw_version}"
                f" does not support writing the network key frame counter, which is"
                f" required for migration to succeed."
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
            ieee = await self._api.read_parameter(NetworkParameter.mac_address)
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
            NetworkParameter.network_key,
            IndexedKey(index=0, key=network_info.network_key.key),
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
            LinkKey(
                ieee=tc_link_key_partner_ieee,
                key=network_info.tc_link_key.key,
            ),
        )

        if self._api.firmware_version.platform != FirmwarePlatform.Conbee_III:
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
        await asyncio.sleep(CHANGE_NETWORK_STATE_DELAY)
        await self._change_network_state(NetworkState.CONNECTED)

    async def load_network_info(self, *, load_devices=False):
        network_info = self.state.network_info
        node_info = self.state.node_info

        ieee = await self._api.read_parameter(NetworkParameter.mac_address)
        node_info.ieee = zigpy.types.EUI64(ieee)
        designed_coord = await self._api.read_parameter(
            NetworkParameter.aps_designed_coordinator
        )

        if designed_coord == 0x01:
            node_info.logical_type = zdo_t.LogicalType.Coordinator
        else:
            node_info.logical_type = zdo_t.LogicalType.Router

        node_info.nwk = await self._api.read_parameter(NetworkParameter.nwk_address)

        node_info.manufacturer = "dresden elektronik"

        if re.match(
            r"/dev/tty(S|AMA|ACM)\d+",
            self._config[zigpy.config.CONF_DEVICE][zigpy.config.CONF_DEVICE_PATH],
        ):
            node_info.model = "Raspbee"
        else:
            node_info.model = "Conbee"

        node_info.model += {
            FirmwarePlatform.Conbee: "",
            FirmwarePlatform.Conbee_II: " II",
            FirmwarePlatform.Conbee_III: " III",
        }[self._api.firmware_version.platform]

        node_info.version = f"{int(self._api.firmware_version):#010x}"

        network_info.source = f"zigpy-deconz@{LIB_VERSION}"
        network_info.metadata = {
            "deconz": {
                "version": node_info.version,
            }
        }

        network_info.pan_id = await self._api.read_parameter(NetworkParameter.nwk_panid)
        network_info.extended_pan_id = await self._api.read_parameter(
            NetworkParameter.aps_extended_panid
        )

        if network_info.extended_pan_id == zigpy.types.EUI64.convert(
            "00:00:00:00:00:00:00:00"
        ):
            network_info.extended_pan_id = await self._api.read_parameter(
                NetworkParameter.nwk_extended_panid
            )

        network_info.channel = await self._api.read_parameter(
            NetworkParameter.current_channel
        )
        network_info.channel_mask = await self._api.read_parameter(
            NetworkParameter.channel_mask
        )
        network_info.nwk_update_id = await self._api.read_parameter(
            NetworkParameter.nwk_update_id
        )

        if network_info.channel == 0:
            raise NetworkNotFormed("Network channel is zero")

        indexed_key = await self._api.read_parameter(NetworkParameter.network_key, 0)

        network_info.network_key = zigpy.state.Key()
        network_info.network_key.key = indexed_key.key

        try:
            network_info.network_key.tx_counter = await self._api.read_parameter(
                NetworkParameter.nwk_frame_counter
            )
        except zigpy_deconz.exception.CommandError as ex:
            assert ex.status == Status.UNSUPPORTED

        network_info.tc_link_key = zigpy.state.Key()
        network_info.tc_link_key.partner_ieee = await self._api.read_parameter(
            NetworkParameter.trust_center_address
        )

        link_key = await self._api.read_parameter(
            NetworkParameter.link_key,
            network_info.tc_link_key.partner_ieee,
        )
        network_info.tc_link_key.key = link_key.key

        security_mode = await self._api.read_parameter(NetworkParameter.security_mode)

        if security_mode == SecurityMode.NO_SECURITY:
            network_info.security_level = 0x00
        elif security_mode == SecurityMode.ONLY_TCLK:
            network_info.security_level = 0x05
        else:
            LOGGER.warning("Unsupported security mode %r", security_mode)
            network_info.security_level = 0x05

    async def force_remove(self, dev):
        """Forcibly remove device from NCP."""

    async def energy_scan(
        self, channels: t.Channels.ALL_CHANNELS, duration_exp: int, count: int
    ) -> dict[int, float]:
        if self._api.firmware_version.platform in (
            FirmwarePlatform.Conbee,
            FirmwarePlatform.Conbee_II,
        ):
            results = await super().energy_scan(
                channels=channels, duration_exp=duration_exp, count=count
            )

            # The Conbee I/II seems to max out at an LQI of 85, which is exactly 255/3
            return {c: v * 3 for c, v in results.items()}

        for i in range(CONBEE_III_ENERGY_SCAN_ATTEMPTS):
            # The Conbee III energy scan inherits the EmberZNet ZDO bug
            try:
                rsp = await self._device.zdo.Mgmt_NWK_Update_req(
                    zigpy.zdo.types.NwkUpdate(
                        ScanChannels=channels,
                        ScanDuration=duration_exp,
                        ScanCount=count,
                    )
                )
                break
            except (asyncio.TimeoutError, zigpy.exceptions.DeliveryError):
                if i == CONBEE_III_ENERGY_SCAN_ATTEMPTS - 1:
                    raise

                continue

        _, scanned_channels, _, _, energy_values = rsp
        return dict(zip(scanned_channels, energy_values))

    async def _move_network_to_channel(
        self, new_channel: int, new_nwk_update_id: int
    ) -> None:
        """Move device to a new channel."""
        channel_mask = zigpy.types.Channels.from_channel_list([new_channel])
        await self._api.write_parameter(NetworkParameter.channel_mask, channel_mask)
        await self._api.write_parameter(
            NetworkParameter.nwk_update_id, new_nwk_update_id
        )

        await self._change_network_state(NetworkState.OFFLINE)
        await asyncio.sleep(CHANGE_NETWORK_STATE_DELAY)
        await self._change_network_state(NetworkState.CONNECTED)

    async def add_endpoint(self, descriptor: zdo_t.SimpleDescriptor) -> None:
        """Register an endpoint on the device, replacing any with conflicting IDs."""

        endpoints = {}

        # Read and count the current endpoints. Some firmwares have three, others four.
        for index in range(255 + 1):
            try:
                current_descriptor = await self._api.read_parameter(
                    NetworkParameter.configure_endpoint, index
                )
            except zigpy_deconz.exception.CommandError as ex:
                assert ex.status == Status.UNSUPPORTED
                break
            else:
                endpoints[index] = current_descriptor.descriptor

        LOGGER.debug("Got endpoint slots: %r", endpoints)

        # Don't write endpoints unnecessarily
        if descriptor in endpoints.values():
            LOGGER.debug("Endpoint already registered, skipping")

            # Pretend we wrote it
            self._written_endpoints.add(list(endpoints.values()).index(descriptor))
            return

        # Keep track of the best endpoint descriptor to replace
        target_index = None

        for index, current_descriptor in endpoints.items():
            # Ignore ones we've already written
            if index in self._written_endpoints:
                continue

            target_index = index

            if current_descriptor.endpoint == descriptor.endpoint:
                # Prefer to replace the endpoint with the same ID
                break

        if target_index is None:
            raise ValueError(f"No available endpoint slots exist: {endpoints!r}")

        LOGGER.debug("Writing %s to slot %r", descriptor, target_index)

        await self._api.write_parameter(
            NetworkParameter.configure_endpoint,
            IndexedEndpoint(index=target_index, descriptor=descriptor),
        )

    async def send_packet(self, packet):
        LOGGER.debug("Sending packet: %r", packet)

        tx_options = t.DeconzTransmitOptions.USE_NWK_KEY_SECURITY

        if (
            zigpy.types.TransmitOptions.ACK in packet.tx_options
            and packet.dst.addr_mode
            in (zigpy.types.AddrMode.NWK, zigpy.types.AddrMode.IEEE)
        ):
            tx_options |= t.DeconzTransmitOptions.USE_APS_ACKS

        async with self._limit_concurrency(priority=packet.priority):
            req_id = self.get_sequence()

            if req_id in self._pending_requests:
                raise zigpy.exceptions.DeliveryError(
                    f"Request with id {req_id} is already pending, cannot send"
                )

            future = self._pending_requests[req_id] = asyncio.Future()

            try:
                try:
                    await self._api.aps_data_request(
                        req_id=req_id,
                        dst_addr_ep=t.DeconzAddressEndpoint.from_zigpy_type(
                            packet.dst, packet.dst_ep or 0
                        ),
                        profile=packet.profile_id,
                        cluster=packet.cluster_id,
                        src_ep=min(1, packet.src_ep),
                        aps_payload=packet.data.serialize(),
                        tx_options=tx_options,
                        relays=packet.source_route,
                        radius=packet.radius or 0,
                    )
                except zigpy_deconz.exception.CommandError as ex:
                    raise zigpy.exceptions.DeliveryError(
                        f"Failed to enqueue packet: {ex!r}", ex.status
                    )

                async with asyncio_timeout(SEND_CONFIRM_TIMEOUT):
                    status = await future

                if status != TXStatus.SUCCESS:
                    raise zigpy.exceptions.DeliveryError(
                        f"Failed to deliver packet: {status!r}", status
                    )
            finally:
                del self._pending_requests[req_id]

    async def permit_ncp(self, time_s=60):
        assert 0 <= time_s <= 254
        await self._api.write_parameter(NetworkParameter.permit_join, time_s)

    def handle_tx_confirm(self, req_id, status):
        try:
            future = self._pending_requests[req_id]
        except KeyError:
            LOGGER.warning(
                "Unexpected transmit confirm for request id %s, Status: %s",
                req_id,
                status,
            )
        else:
            try:
                future.set_result(status)
            except asyncio.InvalidStateError as exc:
                LOGGER.debug(
                    "Invalid state on future - probably duplicate response: %s", exc
                )

    async def restore_neighbours(self) -> None:
        """Restore children."""
        coord = self.get_device(ieee=self.state.node_info.ieee)

        for neighbor in self.topology.neighbors[coord.ieee]:
            try:
                device = self.get_device(ieee=neighbor.ieee)
            except KeyError:
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

            LOGGER.debug("Restoring %s as direct child", device)

            try:
                await self._api.add_neighbour(
                    nwk=device.nwk,
                    ieee=device.ieee,
                    mac_capability_flags=descr.mac_capability_flags,
                )
            except zigpy_deconz.exception.CommandError as ex:
                assert ex.status == Status.FAILURE
                LOGGER.debug("Failed to add device to neighbor table: %s", ex)

    async def _delayed_neighbour_scan(self) -> None:
        """Scan coordinator's neighbours."""
        await asyncio.sleep(DELAY_NEIGHBOUR_SCAN_S)
        coord = self.get_device(ieee=self.state.node_info.ieee)
        await self.topology.scan(devices=[coord])


class DeconzDevice(zigpy.device.Device):
    """Zigpy Device representing Coordinator."""

    def __init__(self, model: str, *args, **kwargs):
        """Initialize instance."""

        super().__init__(*args, **kwargs)
        self._model = model

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
    async def new(cls, application, ieee, nwk, model: str):
        """Create or replace zigpy device."""
        dev = cls(model, application, ieee, nwk)

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
            await dev.initialize()

        return dev
