"""ControllerApplication for deCONZ protocol based adapters."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

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
    NetworkParameter,
    NetworkState,
    SecurityMode,
    Status,
    TXStatus,
)
from zigpy_deconz.config import CONF_WATCHDOG_TTL, CONFIG_SCHEMA, SCHEMA_DEVICE
import zigpy_deconz.exception

LOGGER = logging.getLogger(__name__)

CHANGE_NETWORK_WAIT = 1
DELAY_NEIGHBOUR_SCAN_S = 1500
SEND_CONFIRM_TIMEOUT = 60

PROTO_VER_MANUAL_SOURCE_ROUTE = 0x010C
PROTO_VER_WATCHDOG = 0x0108
PROTO_VER_NEIGBOURS = 0x0107


class ControllerApplication(zigpy.application.ControllerApplication):
    SCHEMA = CONFIG_SCHEMA
    SCHEMA_DEVICE = SCHEMA_DEVICE

    def __init__(self, config: dict[str, Any]):
        """Initialize instance."""

        super().__init__(config=zigpy.config.ZIGPY_SCHEMA(config))
        self._api = None

        self._pending = zigpy.util.Requests()

        self.version = 0
        self._reset_watchdog_task = None
        self._reconnect_task = None

        self._written_endpoints = set()

    async def _reset_watchdog(self):
        while True:
            try:
                await self._api.write_parameter(
                    NetworkParameter.watchdog_ttl, self._config[CONF_WATCHDOG_TTL]
                )
            except Exception as e:
                LOGGER.warning("Failed to reset watchdog", exc_info=e)
                self.connection_lost(e)
                return

            await asyncio.sleep(self._config[CONF_WATCHDOG_TTL] * 0.75)

    async def connect(self):
        api = Deconz(self, self._config[zigpy.config.CONF_DEVICE])

        try:
            await api.connect()
            self.version = await api.version()
        except Exception:
            api.close()
            raise

        self._api = api
        self._written_endpoints.clear()

    def close(self):
        if self._reset_watchdog_task is not None:
            self._reset_watchdog_task.cancel()
            self._reset_watchdog_task = None

        if self._reconnect_task is not None:
            self._reconnect_task.cancel()
            self._reconnect_task = None

        if self._api is not None:
            self._api.close()
            self._api = None

    async def disconnect(self):
        self.close()

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
            LOGGER.warning(
                "Writing the network frame counter is not supported with this firmware,"
                " please update your Conbee"
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
        """Register an endpoint on the device, replacing any with conflicting IDs."""

        endpoints = {}

        # Read and count the current endpoints. Some firmwares have three, others four.
        for index in range(255 + 1):
            try:
                _, current_descriptor = await self._api.read_parameter(
                    NetworkParameter.configure_endpoint, index
                )
            except zigpy_deconz.exception.CommandError as ex:
                assert ex.status == Status.UNSUPPORTED
                break
            else:
                endpoints[index] = current_descriptor

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
            NetworkParameter.configure_endpoint, target_index, descriptor
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

        async with self._limit_concurrency():
            req_id = self.get_sequence()

            with self._pending.new(req_id) as req:
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

                status = await asyncio.wait_for(req.result, SEND_CONFIRM_TIMEOUT)

                if status != TXStatus.SUCCESS:
                    raise zigpy.exceptions.DeliveryError(
                        f"Failed to deliver packet: {status!r}", status
                    )

    def handle_rx(
        self, src, src_ep, dst, dst_ep, profile_id, cluster_id, data, lqi, rssi
    ):
        self.packet_received(
            zigpy.types.ZigbeePacket(
                src=src.as_zigpy_type(),
                src_ep=src_ep,
                dst=dst.as_zigpy_type(),
                dst_ep=dst_ep,
                tsn=None,
                profile_id=profile_id,
                cluster_id=cluster_id,
                data=zigpy.types.SerializableBytes(data),
                lqi=lqi,
                rssi=rssi,
            )
        )

    async def permit_ncp(self, time_s=60):
        assert 0 <= time_s <= 254
        await self._api.write_parameter(NetworkParameter.permit_join, time_s)

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
        await self.topology.scan(devices=[coord])

    def connection_lost(self, exc: Exception) -> None:
        """Lost connection."""

        if exc is not None:
            LOGGER.warning("Lost connection: %r", exc)

        self.close()
        self._reconnect_task = asyncio.create_task(self._reconnect_loop())

    async def _reconnect_loop(self) -> None:
        attempt = 1

        while True:
            LOGGER.debug("Reconnecting, attempt %s", attempt)

            try:
                await asyncio.wait_for(self.connect(), timeout=10)
                await asyncio.wait_for(self.initialize(), timeout=10)
                break
            except Exception as exc:
                wait = 2 ** min(attempt, 5)
                attempt += 1
                LOGGER.debug(
                    "Couldn't re-open '%s' serial port, retrying in %ss: %s",
                    self._config[zigpy.config.CONF_DEVICE][
                        zigpy.config.CONF_DEVICE_PATH
                    ],
                    wait,
                    str(exc),
                    exc_info=exc,
                )
                await asyncio.sleep(wait)

        LOGGER.debug(
            "Reconnected '%s' serial port after %s attempts",
            self._config[zigpy.config.CONF_DEVICE][zigpy.config.CONF_DEVICE_PATH],
            attempt,
        )


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
