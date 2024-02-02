"""Test sending and receiving Zigbee packets using the zigpy packet API."""

import asyncio
import contextlib
from unittest.mock import patch

import pytest
import zigpy.exceptions
import zigpy.types as zigpy_t

from zigpy_deconz.api import Status, TXStatus
import zigpy_deconz.exception
import zigpy_deconz.types as t

from tests.test_application import api, app, device_path  # noqa: F401


@contextlib.contextmanager
def patch_data_request(app, *, fail_enqueue=False, fail_deliver=False):  # noqa: F811
    with patch.object(app._api, "aps_data_request") as mock_request:

        async def mock_send(req_id, *args, **kwargs):
            await asyncio.sleep(0)

            if fail_enqueue:
                raise zigpy_deconz.exception.CommandError(
                    "Error", status=Status.FAILURE, command=None
                )

            if fail_deliver:
                app.handle_tx_confirm(
                    req_id, TXStatus(int(zigpy_t.APSStatus.APS_NO_ACK))
                )
            else:
                app.handle_tx_confirm(req_id, TXStatus.SUCCESS)

        mock_request.side_effect = mock_send

        yield mock_request


@pytest.fixture
def tx_packet():
    return zigpy_t.ZigbeePacket(
        src=zigpy_t.AddrModeAddress(addr_mode=zigpy_t.AddrMode.NWK, address=0x0000),
        src_ep=0x12,
        dst=zigpy_t.AddrModeAddress(addr_mode=zigpy_t.AddrMode.NWK, address=0x1234),
        dst_ep=0x34,
        tsn=0x56,
        profile_id=0x7890,
        cluster_id=0xABCD,
        data=zigpy_t.SerializableBytes(b"some data"),
        tx_options=zigpy_t.TransmitOptions.ACK,
        radius=0,
    )


async def test_send_packet_nwk(app, tx_packet):  # noqa: F811
    with patch_data_request(app) as mock_req:
        await app.send_packet(tx_packet)

    assert len(mock_req.mock_calls) == 1
    req = mock_req.mock_calls[0].kwargs

    assert req["dst_addr_ep"].address_mode == t.AddressMode.NWK
    assert req["dst_addr_ep"].address == tx_packet.dst.address
    assert req["dst_addr_ep"].endpoint == tx_packet.dst_ep
    assert req["profile"] == tx_packet.profile_id
    assert req["cluster"] == tx_packet.cluster_id
    assert req["aps_payload"] == tx_packet.data.serialize()
    assert req["tx_options"] == (
        t.DeconzTransmitOptions.USE_NWK_KEY_SECURITY
        | t.DeconzTransmitOptions.USE_APS_ACKS
    )
    assert req["relays"] is None
    assert req["radius"] == 0


async def test_send_packet_nwk_no_ack(app, tx_packet):  # noqa: F811
    tx_packet.tx_options &= ~zigpy_t.TransmitOptions.ACK

    with patch_data_request(app) as mock_req:
        await app.send_packet(tx_packet)

    assert len(mock_req.mock_calls) == 1
    req = mock_req.mock_calls[0].kwargs

    assert req["dst_addr_ep"].address_mode == t.AddressMode.NWK
    assert req["dst_addr_ep"].address == tx_packet.dst.address
    assert req["dst_addr_ep"].endpoint == tx_packet.dst_ep
    assert req["profile"] == tx_packet.profile_id
    assert req["cluster"] == tx_packet.cluster_id
    assert req["aps_payload"] == tx_packet.data.serialize()
    assert req["tx_options"] == t.DeconzTransmitOptions.USE_NWK_KEY_SECURITY
    assert req["relays"] is None
    assert req["radius"] == 0


async def test_send_packet_source_route(app, tx_packet):  # noqa: F811
    tx_packet.source_route = [0xAABB, 0xCCDD]

    with patch_data_request(app) as mock_req:
        await app.send_packet(tx_packet)

    assert len(mock_req.mock_calls) == 1
    req = mock_req.mock_calls[0].kwargs

    assert req["dst_addr_ep"].address_mode == t.AddressMode.NWK
    assert req["dst_addr_ep"].address == tx_packet.dst.address
    assert req["dst_addr_ep"].endpoint == tx_packet.dst_ep
    assert req["profile"] == tx_packet.profile_id
    assert req["cluster"] == tx_packet.cluster_id
    assert req["aps_payload"] == tx_packet.data.serialize()
    assert req["tx_options"] == (
        t.DeconzTransmitOptions.USE_NWK_KEY_SECURITY
        | t.DeconzTransmitOptions.USE_APS_ACKS
    )
    assert req["relays"] == [0xAABB, 0xCCDD]
    assert req["radius"] == 0


async def test_send_packet_ieee(app, tx_packet):  # noqa: F811
    tx_packet.dst = zigpy_t.AddrModeAddress(
        addr_mode=zigpy_t.AddrMode.IEEE,
        address=zigpy_t.EUI64.convert("aa:bb:cc:dd:11:22:33:44"),
    )

    with patch_data_request(app) as mock_req:
        await app.send_packet(tx_packet)

    assert len(mock_req.mock_calls) == 1
    req = mock_req.mock_calls[0].kwargs

    assert req["dst_addr_ep"].address_mode == t.AddressMode.IEEE
    assert req["dst_addr_ep"].address == tx_packet.dst.address
    assert req["dst_addr_ep"].endpoint == tx_packet.dst_ep
    assert req["profile"] == tx_packet.profile_id
    assert req["cluster"] == tx_packet.cluster_id
    assert req["aps_payload"] == tx_packet.data.serialize()
    assert req["tx_options"] == (
        t.DeconzTransmitOptions.USE_NWK_KEY_SECURITY
        | t.DeconzTransmitOptions.USE_APS_ACKS
    )
    assert req["relays"] is None
    assert req["radius"] == 0


async def test_send_packet_group(app, tx_packet):  # noqa: F811
    tx_packet.dst = zigpy_t.AddrModeAddress(
        addr_mode=zigpy_t.AddrMode.Group, address=0x1234
    )
    tx_packet.radius = 12

    with patch_data_request(app) as mock_req:
        await app.send_packet(tx_packet)

    assert len(mock_req.mock_calls) == 1
    req = mock_req.mock_calls[0].kwargs

    assert req["dst_addr_ep"].address_mode == t.AddressMode.GROUP
    assert req["dst_addr_ep"].address == tx_packet.dst.address
    assert req["dst_addr_ep"].endpoint == tx_packet.dst_ep
    assert req["profile"] == tx_packet.profile_id
    assert req["cluster"] == tx_packet.cluster_id
    assert req["aps_payload"] == tx_packet.data.serialize()
    assert req["tx_options"] == t.DeconzTransmitOptions.USE_NWK_KEY_SECURITY
    assert req["relays"] is None
    assert req["radius"] == 12


async def test_send_packet_broadcast(app, tx_packet):  # noqa: F811
    tx_packet.dst = zigpy_t.AddrModeAddress(
        addr_mode=zigpy_t.AddrMode.Broadcast,
        address=zigpy_t.BroadcastAddress.ALL_ROUTERS_AND_COORDINATOR,
    )
    tx_packet.radius = 12

    with patch_data_request(app) as mock_req:
        await app.send_packet(tx_packet)

    assert len(mock_req.mock_calls) == 1
    req = mock_req.mock_calls[0].kwargs

    assert req["dst_addr_ep"].address_mode == t.AddressMode.NWK
    assert req["dst_addr_ep"].address == tx_packet.dst.address
    assert req["dst_addr_ep"].endpoint == tx_packet.dst_ep
    assert req["profile"] == tx_packet.profile_id
    assert req["cluster"] == tx_packet.cluster_id
    assert req["aps_payload"] == tx_packet.data.serialize()
    assert req["tx_options"] == t.DeconzTransmitOptions.USE_NWK_KEY_SECURITY
    assert req["relays"] is None
    assert req["radius"] == 12


async def test_send_packet_enqueue_failure(app, tx_packet):  # noqa: F811
    with patch_data_request(app, fail_enqueue=True):  # noqa: F811
        with pytest.raises(zigpy.exceptions.DeliveryError) as e:
            await app.send_packet(tx_packet)

    assert "Failed to enqueue" in str(e)


async def test_send_packet_deliver_failure(app, tx_packet):  # noqa: F811
    with patch_data_request(app, fail_deliver=True):  # noqa: F811
        with pytest.raises(zigpy.exceptions.DeliveryError) as e:
            await app.send_packet(tx_packet)

    assert "Failed to deliver" in str(e)
