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

pytestmark = pytest.mark.asyncio


@pytest.fixture
def device_path():
    return "/dev/null"


@pytest.fixture
def app(device_path, database_file=None):
    config = application.ControllerApplication.SCHEMA(
        {
            zigpy.config.CONF_DEVICE: {zigpy.config.CONF_DEVICE_PATH: device_path},
            zigpy.config.CONF_DATABASE: database_file,
        }
    )

    app = application.ControllerApplication(config)
    api = MagicMock(spec_set=zigpy_deconz.api.Deconz)
    with patch.object(app, "_api", return_value=api):
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


async def test_form_network(app):
    app._api.change_network_state = AsyncMock()
    app._api.device_state = AsyncMock(return_value=deconz_api.NetworkState.CONNECTED)
    app._api.network_state = deconz_api.NetworkState.CONNECTED

    await app.form_network()
    assert app._api.change_network_state.call_count == 0
    assert app._api.change_network_state.await_count == 0
    assert app._api.device_state.await_count == 0

    app._api._device_state = deconz_api.DeviceState(deconz_api.NetworkState.OFFLINE)
    app._api.network_state = deconz_api.NetworkState.OFFLINE
    application.CHANGE_NETWORK_WAIT = 0.001
    with pytest.raises(Exception):
        await app.form_network()
    assert app._api.change_network_state.call_count == 1
    assert app._api.change_network_state.await_count == 1
    assert app._api.device_state.await_count == 10
    assert app._api.device_state.call_count == 10


@pytest.mark.parametrize(
    "protocol_ver, watchdog_cc", [(0x0107, False), (0x0108, True), (0x010B, True)]
)
async def test_startup(protocol_ver, watchdog_cc, app, monkeypatch, version=0):
    async def _version():
        app._api._proto_ver = protocol_ver
        return [version]

    app._reset_watchdog = AsyncMock()
    app.form_network = AsyncMock()

    app._api._command = AsyncMock()
    api = deconz_api.Deconz(app, app._config[zigpy.config.CONF_DEVICE])
    api.connect = AsyncMock()
    api._command = AsyncMock()
    api.read_parameter = AsyncMock(return_value=[[0]])
    api.version = MagicMock(side_effect=_version)
    api.write_parameter = AsyncMock()

    monkeypatch.setattr(application.DeconzDevice, "new", AsyncMock())
    with patch.object(application, "Deconz", return_value=api):
        await app.startup(auto_form=False)
        assert app.form_network.call_count == 0
        assert app._reset_watchdog.call_count == watchdog_cc
        await app.startup(auto_form=True)
        assert app.form_network.call_count == 1


async def test_permit(app, nwk):
    app._api.write_parameter = AsyncMock()
    time_s = 30
    await app.permit_ncp(time_s)
    assert app._api.write_parameter.call_count == 1
    assert app._api.write_parameter.call_args_list[0][0][1] == time_s


async def _test_request(app, send_success=True, aps_data_error=False, **kwargs):
    seq = 123

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

    return await app.request(device, 0x0260, 1, 2, 3, seq, b"\x01\x02\x03", **kwargs)


async def test_request_send_success(app):
    req_id = sentinel.req_id
    app.get_sequence = MagicMock(return_value=req_id)
    r = await _test_request(app, True)
    assert r[0] == 0

    r = await _test_request(app, True, use_ieee=True)
    assert r[0] == 0


async def test_request_send_fail(app):
    req_id = sentinel.req_id
    app.get_sequence = MagicMock(return_value=req_id)
    r = await _test_request(app, False)
    assert r[0] != 0


async def test_request_send_aps_data_error(app):
    req_id = sentinel.req_id
    app.get_sequence = MagicMock(return_value=req_id)
    r = await _test_request(app, False, aps_data_error=True)
    assert r[0] != 0


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


async def test_shutdown(app):
    app._api.close = MagicMock()
    await app.shutdown()
    assert app._api.close.call_count == 1


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
