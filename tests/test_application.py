"""Test application module."""

import asyncio
import logging

import pytest
import zigpy.config
import zigpy.device
import zigpy.neighbor
from zigpy.types import EUI64
import zigpy.zdo.types as zdo_t

from zigpy_deconz import types as t
import zigpy_deconz.api as deconz_api
import zigpy_deconz.exception
import zigpy_deconz.zigbee.application as application

from .async_mock import AsyncMock, MagicMock, patch, sentinel

ZIGPY_NWK_CONFIG = {
    zigpy.config.CONF_NWK: {
        zigpy.config.CONF_NWK_PAN_ID: 0x4567,
        zigpy.config.CONF_NWK_EXTENDED_PAN_ID: "11:22:33:44:55:66:77:88",
        zigpy.config.CONF_NWK_UPDATE_ID: 22,
        zigpy.config.CONF_NWK_KEY: [0xAA] * 16,
    }
}


@pytest.fixture
def device_path():
    return "/dev/null"


@pytest.fixture
def api():
    """Return API fixture."""
    api = MagicMock(spec_set=zigpy_deconz.api.Deconz(None, None))
    api.device_state = AsyncMock(
        return_value=(deconz_api.DeviceState(deconz_api.NetworkState.CONNECTED), 0, 0)
    )
    api.write_parameter = AsyncMock()

    # So the protocol version is effectively infinite
    api._proto_ver.__ge__.return_value = True
    api._proto_ver.__lt__.return_value = False

    api.protocol_version.__ge__.return_value = True
    api.protocol_version.__lt__.return_value = False

    return api


@pytest.fixture
def app(device_path, api):
    config = application.ControllerApplication.SCHEMA(
        {
            **ZIGPY_NWK_CONFIG,
            zigpy.config.CONF_DEVICE: {zigpy.config.CONF_DEVICE_PATH: device_path},
        }
    )

    app = application.ControllerApplication(config)

    api.change_network_state = AsyncMock()

    device_state = MagicMock()
    device_state.network_state.__eq__.return_value = True
    api.device_state = AsyncMock(return_value=(device_state, 0, 0))

    p1 = patch.object(app, "_api", api)
    p2 = patch.object(app, "_delayed_neighbour_scan")
    p3 = patch.object(app, "_change_network_state", wraps=app._change_network_state)

    with p1, p2, p3:
        yield app


@pytest.fixture
def ieee():
    return EUI64.deserialize(b"\x00\x01\x02\x03\x04\x05\x06\x07")[0]


@pytest.fixture
def nwk():
    return t.uint16_t(0x0100)


@pytest.fixture
def addr_ieee(ieee):
    addr = t.DeconzAddress()
    addr.address_mode = t.ADDRESS_MODE.IEEE
    addr.address = ieee
    return addr


@pytest.fixture
def addr_nwk(nwk):
    addr = t.DeconzAddress()
    addr.address_mode = t.ADDRESS_MODE.NWK
    addr.address = nwk
    return addr


@pytest.fixture
def addr_nwk_and_ieee(nwk, ieee):
    addr = t.DeconzAddress()
    addr.address_mode = t.ADDRESS_MODE.NWK_AND_IEEE
    addr.address = nwk
    addr.ieee = ieee
    return addr


def _test_rx(app, addr_ieee, addr_nwk, device, data):
    app.get_device = MagicMock(return_value=device)
    app.devices = (EUI64(addr_ieee.address),)

    app.handle_rx(
        addr_nwk,
        sentinel.src_ep,
        sentinel.dst_ep,
        sentinel.profile_id,
        sentinel.cluster_id,
        data,
        sentinel.lqi,
        sentinel.rssi,
    )


def test_rx(app, addr_ieee, addr_nwk):
    device = MagicMock()
    app.handle_message = MagicMock()
    _test_rx(app, addr_ieee, addr_nwk, device, sentinel.args)
    assert app.handle_message.call_count == 1
    assert app.handle_message.call_args == (
        (
            device,
            sentinel.profile_id,
            sentinel.cluster_id,
            sentinel.src_ep,
            sentinel.dst_ep,
            sentinel.args,
        ),
    )


def test_rx_ieee(app, addr_ieee, addr_nwk):
    device = MagicMock()
    app.handle_message = MagicMock()
    _test_rx(app, addr_ieee, addr_ieee, device, sentinel.args)
    assert app.handle_message.call_count == 1
    assert app.handle_message.call_args == (
        (
            device,
            sentinel.profile_id,
            sentinel.cluster_id,
            sentinel.src_ep,
            sentinel.dst_ep,
            sentinel.args,
        ),
    )


def test_rx_nwk_ieee(app, addr_ieee, addr_nwk_and_ieee):
    device = MagicMock()
    app.handle_message = MagicMock()
    _test_rx(app, addr_ieee, addr_nwk_and_ieee, device, sentinel.args)
    assert app.handle_message.call_count == 1
    assert app.handle_message.call_args == (
        (
            device,
            sentinel.profile_id,
            sentinel.cluster_id,
            sentinel.src_ep,
            sentinel.dst_ep,
            sentinel.args,
        ),
    )


def test_rx_wrong_addr_mode(app, addr_ieee, addr_nwk, caplog):
    device = MagicMock()
    app.handle_message = MagicMock()
    app.get_device = MagicMock(return_value=device)

    app.devices = (EUI64(addr_ieee.address),)

    with pytest.raises(Exception):  # TODO: don't use broad exceptions
        addr_nwk.address_mode = 0x22
        app.handle_rx(
            addr_nwk,
            sentinel.src_ep,
            sentinel.dst_ep,
            sentinel.profile_id,
            sentinel.cluster_id,
            b"",
            sentinel.lqi,
            sentinel.rssi,
        )

    assert app.handle_message.call_count == 0


def test_rx_unknown_device(app, addr_ieee, addr_nwk, caplog):
    app.handle_message = MagicMock()

    caplog.set_level(logging.DEBUG)
    app.handle_rx(
        addr_nwk,
        sentinel.src_ep,
        sentinel.dst_ep,
        sentinel.profile_id,
        sentinel.cluster_id,
        b"",
        sentinel.lqi,
        sentinel.rssi,
    )

    assert "Received frame from unknown device" in caplog.text
    assert app.handle_message.call_count == 0


@pytest.mark.parametrize(
    "proto_ver, nwk_state, error",
    [
        (0x0107, deconz_api.NetworkState.CONNECTED, None),
        (0x0106, deconz_api.NetworkState.CONNECTED, None),
        (0x0107, deconz_api.NetworkState.OFFLINE, None),
        (0x0107, deconz_api.NetworkState.OFFLINE, asyncio.TimeoutError()),
    ],
)
async def test_start_network(app, proto_ver, nwk_state, error):
    app.load_network_info = AsyncMock()
    app.restore_neighbours = AsyncMock()
    app._change_network_state = AsyncMock(side_effect=error)

    app._api.device_state = AsyncMock(
        return_value=(deconz_api.DeviceState(nwk_state), 0, 0)
    )
    app._api._proto_ver = proto_ver
    app._api.protocol_version = proto_ver

    if nwk_state != deconz_api.NetworkState.CONNECTED and error is not None:
        with pytest.raises(zigpy.exceptions.FormationFailure):
            await app.start_network()

        return

    with patch.object(application.DeconzDevice, "initialize", AsyncMock()):
        await app.start_network()
        assert app.load_network_info.await_count == 1

        if nwk_state != deconz_api.NetworkState.CONNECTED:
            assert app._change_network_state.await_count == 1
            assert (
                app._change_network_state.await_args_list[0][0][0]
                == deconz_api.NetworkState.CONNECTED
            )
        else:
            assert app._change_network_state.await_count == 0

        if proto_ver >= application.PROTO_VER_NEIGBOURS:
            assert app.restore_neighbours.await_count == 1
        else:
            assert app.restore_neighbours.await_count == 0


async def test_permit(app, nwk):
    app._api.write_parameter = AsyncMock()
    time_s = 30
    await app.permit_ncp(time_s)
    assert app._api.write_parameter.call_count == 1
    assert app._api.write_parameter.call_args_list[0][0][1] == time_s


async def _test_request(app, *, send_success=True, aps_data_error=False, **kwargs):
    seq = 123

    async def req_mock(
        req_id,
        dst_addr_ep,
        profile,
        cluster,
        src_ep,
        data,
        *,
        relays=None,
        tx_options=t.DeconzTransmitOptions.USE_NWK_KEY_SECURITY,
        radius=0
    ):
        if aps_data_error:
            raise zigpy_deconz.exception.CommandError(1, "Command Error")
        if send_success:
            app._pending[req_id].result.set_result(0)
        else:
            app._pending[req_id].result.set_result(1)

    app._api.aps_data_request = MagicMock(side_effect=req_mock)
    app._api.protocol_version = 0
    device = zigpy.device.Device(app, sentinel.ieee, 0x1122)
    app.get_device = MagicMock(return_value=device)

    return await app.request(device, 0x0260, 1, 2, 3, seq, b"\x01\x02\x03", **kwargs)


async def test_request_send_success(app):
    req_id = sentinel.req_id
    app.get_sequence = MagicMock(return_value=req_id)
    r = await _test_request(app, send_success=True)
    assert r[0] == 0

    r = await _test_request(app, send_success=True, use_ieee=True)
    assert r[0] == 0


async def test_request_send_fail(app):
    req_id = sentinel.req_id
    app.get_sequence = MagicMock(return_value=req_id)
    r = await _test_request(app, send_success=False)
    assert r[0] != 0


async def test_request_send_aps_data_error(app):
    req_id = sentinel.req_id
    app.get_sequence = MagicMock(return_value=req_id)
    r = await _test_request(app, send_success=False, aps_data_error=True)
    assert r[0] != 0


async def test_request_retry(app):
    req_id = sentinel.req_id
    app.get_sequence = MagicMock(return_value=req_id)

    device = zigpy.device.Device(app, sentinel.ieee, 0x1122)
    device.relays = [0x5678, 0x1234]
    app.get_device = MagicMock(return_value=device)

    async def req_mock(
        req_id,
        dst_addr_ep,
        profile,
        cluster,
        src_ep,
        data,
        *,
        relays=None,
        tx_options=t.DeconzTransmitOptions.USE_NWK_KEY_SECURITY,
        radius=0
    ):
        app._pending[req_id].result.set_result(1)

    app._api.aps_data_request = MagicMock(side_effect=req_mock)
    app._api.protocol_version = application.PROTO_VER_MANUAL_SOURCE_ROUTE

    await app.request(device, 0x0260, 1, 2, 3, 123, b"\x01\x02\x03")

    assert len(app._api.aps_data_request.mock_calls) == 2
    without_relays, with_relays = app._api.aps_data_request.mock_calls

    assert without_relays[2]["relays"] is None
    assert with_relays[2]["relays"] == [0x0000, 0x1234, 0x5678]


async def _test_broadcast(app, send_success=True, aps_data_error=False, **kwargs):
    seq = sentinel.req_id

    async def req_mock(req_id, dst_addr_ep, profile, cluster, src_ep, data):
        if aps_data_error:
            raise zigpy_deconz.exception.CommandError(1, "Command Error")
        if send_success:
            app._pending[req_id].result.set_result(0)
        else:
            app._pending[req_id].result.set_result(1)

    app._api.aps_data_request = MagicMock(side_effect=req_mock)
    app.get_device = MagicMock(spec_set=zigpy.device.Device)

    r = await app.broadcast(
        sentinel.profile,
        sentinel.cluster,
        2,
        sentinel.dst_ep,
        sentinel.grp_id,
        sentinel.radius,
        seq,
        b"\x01\x02\x03",
        **kwargs
    )
    assert app._api.aps_data_request.call_count == 1
    assert app._api.aps_data_request.call_args[0][0] is seq
    assert app._api.aps_data_request.call_args[0][2] is sentinel.profile
    assert app._api.aps_data_request.call_args[0][3] is sentinel.cluster
    assert app._api.aps_data_request.call_args[0][5] == b"\x01\x02\x03"
    return r


async def test_broadcast_send_success(app):
    req_id = sentinel.req_id
    app.get_sequence = MagicMock(return_value=req_id)
    r = await _test_broadcast(app, True)
    assert r[0] == 0


async def test_broadcast_send_fail(app):
    req_id = sentinel.req_id
    app.get_sequence = MagicMock(return_value=req_id)
    r = await _test_broadcast(app, False)
    assert r[0] != 0


async def test_broadcast_send_aps_data_error(app):
    req_id = sentinel.req_id
    app.get_sequence = MagicMock(return_value=req_id)
    r = await _test_broadcast(app, False, aps_data_error=True)
    assert r[0] != 0


def _handle_reply(app, tsn):
    app.handle_message = MagicMock()
    return app._handle_reply(
        sentinel.device,
        sentinel.profile,
        sentinel.cluster,
        sentinel.src_ep,
        sentinel.dst_ep,
        tsn,
        sentinel.command_id,
        sentinel.args,
    )


async def test_connect(app):
    def new_api(*args):
        api = MagicMock()
        api.connect = AsyncMock()
        api.version = AsyncMock(return_value=sentinel.version)

        return api

    with patch.object(application, "Deconz", new=new_api):
        app._api = None
        await app.connect()
        assert app._api is not None

        assert app._api.connect.await_count == 1
        assert app._api.version.await_count == 1
        assert app.version is sentinel.version


async def test_disconnect(app):
    app._reset_watchdog_task = MagicMock()
    app._api.close = MagicMock()

    await app.disconnect()
    assert app._api.close.call_count == 1
    assert app._reset_watchdog_task.cancel.call_count == 1


async def test_disconnect_no_api(app):
    app._api = None
    await app.disconnect()


async def test_disconnect_close_error(app):
    app._api.write_parameter = MagicMock(
        side_effect=zigpy_deconz.exception.CommandError(1, "Error")
    )
    await app.disconnect()


async def test_permit_with_key_not_implemented(app):
    with pytest.raises(NotImplementedError):
        await app.permit_with_key(node=MagicMock(), code=b"abcdef")


def test_rx_device_annce(app, addr_ieee, addr_nwk):
    dst_ep = 0
    cluster_id = zdo_t.ZDOCmd.Device_annce
    device = MagicMock()
    device.status = zigpy.device.Status.NEW
    app.get_device = MagicMock(return_value=device)

    app.handle_join = MagicMock()
    app._handle_reply = MagicMock()
    app.handle_message = MagicMock()

    data = t.uint8_t(0xAA).serialize()
    data += addr_nwk.address.serialize()
    data += addr_ieee.address.serialize()
    data += t.uint8_t(0x8E).serialize()

    app.handle_rx(
        addr_nwk,
        sentinel.src_ep,
        dst_ep,
        sentinel.profile_id,
        cluster_id,
        data,
        sentinel.lqi,
        sentinel.rssi,
    )

    assert app.handle_message.call_count == 1
    assert app.handle_join.call_count == 1
    assert app.handle_join.call_args[0][0] == addr_nwk.address
    assert app.handle_join.call_args[0][1] == addr_ieee.address
    assert app.handle_join.call_args[0][2] == 0


async def test_deconz_dev_add_to_group(app, nwk, device_path):
    group = MagicMock()
    app._groups = MagicMock()
    app._groups.add_group.return_value = group

    deconz = application.DeconzDevice(0, device_path, app, sentinel.ieee, nwk)
    deconz.endpoints = {
        0: sentinel.zdo,
        1: sentinel.ep1,
        2: sentinel.ep2,
    }

    await deconz.add_to_group(sentinel.grp_id, sentinel.grp_name)
    assert group.add_member.call_count == 2

    assert app.groups.add_group.call_count == 1
    assert app.groups.add_group.call_args[0][0] is sentinel.grp_id
    assert app.groups.add_group.call_args[0][1] is sentinel.grp_name


async def test_deconz_dev_remove_from_group(app, nwk, device_path):
    group = MagicMock()
    app.groups[sentinel.grp_id] = group
    deconz = application.DeconzDevice(0, device_path, app, sentinel.ieee, nwk)
    deconz.endpoints = {
        0: sentinel.zdo,
        1: sentinel.ep1,
        2: sentinel.ep2,
    }

    await deconz.remove_from_group(sentinel.grp_id)
    assert group.remove_member.call_count == 2


def test_deconz_props(nwk, device_path):
    deconz = application.DeconzDevice(0, device_path, app, sentinel.ieee, nwk)
    assert deconz.manufacturer is not None
    assert deconz.model is not None


@pytest.mark.parametrize(
    "name, firmware_version, device_path",
    [
        ("ConBee", 0x00000500, "/dev/ttyUSB0"),
        ("ConBee II", 0x00000700, "/dev/ttyUSB0"),
        ("RaspBee", 0x00000500, "/dev/ttyS0"),
        ("RaspBee II", 0x00000700, "/dev/ttyS0"),
        ("RaspBee", 0x00000500, "/dev/ttyAMA0"),
        ("RaspBee II", 0x00000700, "/dev/ttyAMA0"),
    ],
)
def test_deconz_name(nwk, name, firmware_version, device_path):
    deconz = application.DeconzDevice(
        firmware_version, device_path, app, sentinel.ieee, nwk
    )
    assert deconz.model == name


async def test_deconz_new(app, nwk, device_path, monkeypatch):
    mock_init = AsyncMock()
    monkeypatch.setattr(zigpy.device.Device, "_initialize", mock_init)

    deconz = await application.DeconzDevice.new(app, sentinel.ieee, nwk, 0, device_path)
    assert isinstance(deconz, application.DeconzDevice)
    assert mock_init.call_count == 1
    mock_init.reset_mock()

    mock_dev = MagicMock()
    mock_dev.endpoints = {
        0: MagicMock(),
        1: MagicMock(),
        22: MagicMock(),
    }
    app.devices[sentinel.ieee] = mock_dev
    deconz = await application.DeconzDevice.new(app, sentinel.ieee, nwk, 0, device_path)
    assert isinstance(deconz, application.DeconzDevice)
    assert mock_init.call_count == 0


def test_tx_confirm_success(app):
    tsn = 123
    req = app._pending[tsn] = MagicMock()
    app.handle_tx_confirm(tsn, sentinel.status)
    assert req.result.set_result.call_count == 1
    assert req.result.set_result.call_args[0][0] is sentinel.status


def test_tx_confirm_dup(app, caplog):
    caplog.set_level(logging.DEBUG)
    tsn = 123
    req = app._pending[tsn] = MagicMock()
    req.result.set_result.side_effect = asyncio.InvalidStateError
    app.handle_tx_confirm(tsn, sentinel.status)
    assert req.result.set_result.call_count == 1
    assert req.result.set_result.call_args[0][0] is sentinel.status
    assert any(r.levelname == "DEBUG" for r in caplog.records)
    assert "probably duplicate response" in caplog.text


def test_tx_confirm_unexpcted(app, caplog):
    app.handle_tx_confirm(123, 0x00)
    assert any(r.levelname == "WARNING" for r in caplog.records)
    assert "Unexpected transmit confirm for request id" in caplog.text


async def _test_mrequest(app, send_success=True, aps_data_error=False, **kwargs):
    seq = 123
    req_id = sentinel.req_id
    app.get_sequence = MagicMock(return_value=req_id)

    async def req_mock(req_id, dst_addr_ep, profile, cluster, src_ep, data):
        if aps_data_error:
            raise zigpy_deconz.exception.CommandError(1, "Command Error")
        if send_success:
            app._pending[req_id].result.set_result(0)
        else:
            app._pending[req_id].result.set_result(1)

    app._api.aps_data_request = MagicMock(side_effect=req_mock)
    device = zigpy.device.Device(app, sentinel.ieee, 0x1122)
    app.get_device = MagicMock(return_value=device)

    return await app.mrequest(0x55AA, 0x0260, 1, 2, seq, b"\x01\x02\x03", **kwargs)


async def test_mrequest_send_success(app):
    r = await _test_mrequest(app, True)
    assert r[0] == 0


async def test_mrequest_send_fail(app):
    r = await _test_mrequest(app, False)
    assert r[0] != 0


async def test_mrequest_send_aps_data_error(app):
    r = await _test_mrequest(app, False, aps_data_error=True)
    assert r[0] != 0


async def test_reset_watchdog(app):
    """Test watchdog."""
    with patch.object(app._api, "write_parameter") as mock_api:
        dog = asyncio.ensure_future(app._reset_watchdog())
        await asyncio.sleep(0.3)
        dog.cancel()
        assert mock_api.call_count == 1

    with patch.object(app._api, "write_parameter") as mock_api:
        mock_api.side_effect = zigpy_deconz.exception.CommandError
        dog = asyncio.ensure_future(app._reset_watchdog())
        await asyncio.sleep(0.3)
        dog.cancel()
        assert mock_api.call_count == 1


async def test_force_remove(app):
    """Test forcibly removing a device."""
    await app.force_remove(sentinel.device)


async def test_restore_neighbours(app):
    """Test neighbour restoration."""

    # FFD, Rx on when idle
    desc_1 = zdo_t.NodeDescriptor(1, 64, 142, 0xBEEF, 82, 82, 0, 82, 0)
    device_1 = MagicMock()
    device_1.node_desc = desc_1
    device_1.ieee = sentinel.ieee_1
    device_1.nwk = 0x1111
    nei_1 = zigpy.neighbor.Neighbor(sentinel.nei_1, device_1)

    # RFD, Rx on when idle
    desc_2 = zdo_t.NodeDescriptor(1, 64, 142, 0xBEEF, 82, 82, 0, 82, 0)
    device_2 = MagicMock()
    device_2.node_desc = desc_2
    device_2.ieee = sentinel.ieee_2
    device_2.nwk = 0x2222
    nei_2 = zigpy.neighbor.Neighbor(sentinel.nei_2, device_2)

    # Missing node descriptor
    device_3 = MagicMock()
    device_3.node_desc = None
    device_3.ieee = sentinel.ieee_3
    device_3.nwk = 0x3333
    nei_3 = zigpy.neighbor.Neighbor(sentinel.nei_3, device_3)

    # no device
    nei_4 = zigpy.neighbor.Neighbor(sentinel.nei_4, None)

    # RFD, Rx off when idle
    desc_5 = zdo_t.NodeDescriptor(2, 64, 128, 0xBEEF, 82, 82, 0, 82, 0)
    device_5 = MagicMock()
    device_5.node_desc = desc_5
    device_5.ieee = sentinel.ieee_5
    device_5.nwk = 0x5555
    nei_5 = zigpy.neighbor.Neighbor(sentinel.nei_5, device_5)

    coord = MagicMock()
    coord.ieee = sentinel.coord_ieee
    coord.nwk = 0x0000
    neighbours = zigpy.neighbor.Neighbors(coord)
    neighbours.neighbors.append(nei_1)
    neighbours.neighbors.append(nei_2)
    neighbours.neighbors.append(nei_3)
    neighbours.neighbors.append(nei_4)
    neighbours.neighbors.append(nei_5)
    coord.neighbors = neighbours

    p2 = patch.object(app, "_api", spec_set=zigpy_deconz.api.Deconz(None, None))
    with patch.object(app, "get_device", return_value=coord), p2 as api_mock:
        api_mock.add_neighbour = AsyncMock()
        await app.restore_neighbours()

    assert api_mock.add_neighbour.call_count == 1
    assert api_mock.add_neighbour.await_count == 1


@patch("zigpy_deconz.zigbee.application.DELAY_NEIGHBOUR_SCAN_S", 0)
async def test_delayed_scan():
    """Delayed scan."""

    coord = MagicMock()
    coord.neighbors.scan = AsyncMock()
    config = application.ControllerApplication.SCHEMA(
        {
            zigpy.config.CONF_DEVICE: {zigpy.config.CONF_DEVICE_PATH: "usb0"},
            zigpy.config.CONF_DATABASE: "tmp",
        }
    )

    app = application.ControllerApplication(config)
    with patch.object(app, "get_device", return_value=coord):
        await app._delayed_neighbour_scan()
    assert coord.neighbors.scan.await_count == 1


@patch("zigpy_deconz.zigbee.application.CHANGE_NETWORK_WAIT", 0.001)
@pytest.mark.parametrize("support_watchdog", [False, True])
async def test_change_network_state(app, support_watchdog):
    app._reset_watchdog_task = MagicMock()

    app._api.device_state = AsyncMock(
        side_effect=[
            (deconz_api.DeviceState(deconz_api.NetworkState.OFFLINE), 0, 0),
            (deconz_api.DeviceState(deconz_api.NetworkState.JOINING), 0, 0),
            (deconz_api.DeviceState(deconz_api.NetworkState.CONNECTED), 0, 0),
        ]
    )

    if support_watchdog:
        app._api._proto_ver = application.PROTO_VER_WATCHDOG
        app._api.protocol_version = application.PROTO_VER_WATCHDOG
    else:
        app._api._proto_ver = application.PROTO_VER_WATCHDOG - 1
        app._api.protocol_version = application.PROTO_VER_WATCHDOG - 1

    old_watchdog_task = app._reset_watchdog_task
    cancel_mock = app._reset_watchdog_task.cancel = MagicMock()

    await app._change_network_state(deconz_api.NetworkState.CONNECTED, timeout=0.01)

    if support_watchdog:
        assert cancel_mock.call_count == 1
        assert app._reset_watchdog_task is not old_watchdog_task
    else:
        assert cancel_mock.call_count == 0
        assert app._reset_watchdog_task is old_watchdog_task
