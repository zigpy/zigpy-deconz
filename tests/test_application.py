import asyncio
from unittest import mock

import pytest

from zigpy.exceptions import DeliveryError
import zigpy.device
from zigpy.types import EUI64
import zigpy.zdo.types as zdo_t
from zigpy_deconz.api import Deconz
import zigpy_deconz.zigbee.application
from zigpy_deconz.zigbee import application
from zigpy_deconz import types as t


@pytest.fixture
def app(monkeypatch, database_file=None):
    app = zigpy_deconz.zigbee.application.ControllerApplication(
        Deconz(), database_file=database_file)
    monkeypatch.setattr(zigpy_deconz.zigbee.application,
                        'TIMEOUT_REPLY_ENDDEV',
                        .1)
    monkeypatch.setattr(zigpy_deconz.zigbee.application,
                        'TIMEOUT_REPLY_ROUTER',
                        .1)
    return app


@pytest.fixture
def ieee():
    return EUI64.deserialize(b'\x00\x01\x02\x03\x04\x05\x06\x07')[0]


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


def _test_rx(app, addr_ieee, addr_nwk, device, deserialized):
    app.get_device = mock.MagicMock(return_value=device)
    app.deserialize = mock.MagicMock(return_value=deserialized)

    app.devices = (EUI64(addr_ieee.address), )

    app.handle_rx(
        addr_nwk,
        mock.sentinel.src_ep,
        mock.sentinel.dst_ep,
        mock.sentinel.profile_id,
        mock.sentinel.cluster_id,
        b'',
        mock.sentinel.lqi,
        mock.sentinel.rssi,
    )

    assert app.deserialize.call_count == 1


def test_rx(app, addr_ieee, addr_nwk):
    device = mock.MagicMock()
    app.handle_message = mock.MagicMock()
    _test_rx(app, addr_ieee, addr_nwk, device, (1, 2, False, []))
    assert app.handle_message.call_count == 1
    assert app.handle_message.call_args == ((
        device,
        False,
        mock.sentinel.profile_id,
        mock.sentinel.cluster_id,
        mock.sentinel.src_ep,
        mock.sentinel.dst_ep,
        1,
        2,
        [],
    ), )


def test_rx_reply(app, addr_ieee, addr_nwk):
    app._handle_reply = mock.MagicMock()
    _test_rx(app, addr_ieee, addr_nwk, mock.MagicMock(), (1, 2, True, []))
    assert app._handle_reply.call_count == 1


def test_rx_failed_deserialize(app, addr_ieee, addr_nwk, caplog):
    app._handle_reply = mock.MagicMock()
    app.handle_message = mock.MagicMock()
    app.get_device = mock.MagicMock(return_value=mock.MagicMock())
    app.deserialize = mock.MagicMock(side_effect=ValueError)

    app.devices = (EUI64(addr_ieee.address), )

    app.handle_rx(
        addr_nwk,
        mock.sentinel.src_ep,
        mock.sentinel.dst_ep,
        mock.sentinel.profile_id,
        mock.sentinel.cluster_id,
        b'',
        mock.sentinel.lqi,
        mock.sentinel.rssi,
    )

    assert any(record.levelname == 'ERROR' for record in caplog.records)

    assert app._handle_reply.call_count == 0
    assert app.handle_message.call_count == 0


@pytest.mark.asyncio
async def test_form_network(app):
    app._api.change_network_state = mock.MagicMock(
        side_effect=asyncio.coroutine(mock.MagicMock()))
    app._api.device_state = mock.MagicMock(
        side_effect=asyncio.coroutine(mock.MagicMock()))

    app._api.network_state = 2
    await app.form_network()
    assert app._api.device_state.call_count == 0

    app._api.network_state = 0
    application.CHANGE_NETWORK_WAIT = 0.001
    with pytest.raises(Exception):
        await app.form_network()
    assert app._api.device_state.call_count == 10


@pytest.mark.asyncio
async def test_startup(app, version=0):

    async def _version():
        return [version]

    app.form_network = mock.MagicMock(
        side_effect=asyncio.coroutine(mock.MagicMock()))
    app._api._command = mock.MagicMock(
        side_effect=asyncio.coroutine(mock.MagicMock()))
    app._api.version = mock.MagicMock(
        side_effect=_version)

    with mock.patch('zigpy_deconz.zigbee.application.ConBeeDevice') as con:
        con.new.side_effect = asyncio.coroutine(mock.MagicMock())
        await app.startup(auto_form=False)
        assert app.form_network.call_count == 0
        await app.startup(auto_form=True)
        assert app.form_network.call_count == 1


@pytest.mark.asyncio
async def test_permit(app, nwk):
    app._api.write_parameter = mock.MagicMock(
        side_effect=asyncio.coroutine(mock.MagicMock()))
    time_s = 30
    await app.permit_ncp(time_s)
    assert app._api.write_parameter.call_count == 1
    assert app._api.write_parameter.call_args_list[0][0][1] == time_s


async def _test_request(app, do_reply=True, expect_reply=True,
                        send_success=True, **kwargs):
    seq = 123
    nwk = 0x2345

    def aps_data_request(req_id, dst_addr_ep, profile, cluster, src_ep, data):
        if send_success:
            app._pending[req_id].send.set_result(0)
        else:
            app._pending[req_id].send.set_result(mock.sentinel.send_fail)
        if expect_reply:
            if do_reply:
                app._pending[req_id].reply.set_result(mock.sentinel.reply_result)

    app._api.aps_data_request = mock.MagicMock(
        side_effect=asyncio.coroutine(aps_data_request))
    app.get_device = mock.MagicMock(
        return_value=zigpy.device.Device(app,
                                         mock.sentinel.ieee,
                                         nwk))

    return await app.request(nwk, 0x0260, 1, 2, 3, seq, b'\x01\x02\x03', expect_reply=expect_reply, **kwargs)


@pytest.mark.asyncio
async def test_request_with_reply(app):
    assert await _test_request(app, True, True) == mock.sentinel.reply_result


@pytest.mark.asyncio
async def test_request_expect_no_reply(app):
    assert await _test_request(app, False, False, tries=2, timeout=0.1) is None


@pytest.mark.asyncio
async def test_request_no_reply(app):
    with pytest.raises(asyncio.TimeoutError):
        await _test_request(app, False, True, tries=2, timeout=0.1)


@pytest.mark.asyncio
async def test_request_send_failure(app):
    with pytest.raises(DeliveryError):
        await _test_request(app, False, True, send_success=False,
                            tries=2, timeout=0.1)


def _handle_reply(app, tsn):
    app.handle_message = mock.MagicMock()
    return app._handle_reply(
        mock.sentinel.device,
        mock.sentinel.profile,
        mock.sentinel.cluster,
        mock.sentinel.src_ep,
        mock.sentinel.dst_ep,
        tsn,
        mock.sentinel.command_id,
        mock.sentinel.args
    )


def test_handle_reply(app):
    tsn = 123
    with app._pending.new(tsn, True) as req:
        _handle_reply(app, tsn)
    assert app.handle_message.call_count == 0
    assert req.reply.result() == mock.sentinel.args


def test_handle_reply_dup(app):
    tsn = 123
    with app._pending.new(tsn, True) as req:
        req.reply.set_result(mock.sentinel.reply_result)
        _handle_reply(app, tsn)
    assert app.handle_message.call_count == 0


def test_handle_reply_unexpected(app):
    tsn = 123
    _handle_reply(app, tsn)
    assert app.handle_message.call_count == 1
    assert app.handle_message.call_args[0][0] == mock.sentinel.device
    assert app.handle_message.call_args[0][1] is True
    assert app.handle_message.call_args[0][2] == mock.sentinel.profile
    assert app.handle_message.call_args[0][3] == mock.sentinel.cluster
    assert app.handle_message.call_args[0][4] == mock.sentinel.src_ep
    assert app.handle_message.call_args[0][5] == mock.sentinel.dst_ep
    assert app.handle_message.call_args[0][6] == tsn
    assert app.handle_message.call_args[0][7] == mock.sentinel.command_id
    assert app.handle_message.call_args[0][8] == mock.sentinel.args


@pytest.mark.asyncio
async def test_shutdown(app):
    app._api.close = mock.MagicMock()
    await app.shutdown()
    assert app._api.close.call_count == 1


def test_rx_device_annce(app, addr_ieee, addr_nwk):
    dst_ep = 0
    cluster_id = zdo_t.ZDOCmd.Device_annce
    device = mock.MagicMock()
    device.status = zigpy.device.Status.NEW
    app.get_device = mock.MagicMock(return_value=device)
    app.deserialize = mock.MagicMock(return_value=(mock.sentinel.tsn,
                                                   mock.sentinel.cmd_id,
                                                   False,
                                                   mock.sentinel.args, ))
    app.handle_join = mock.MagicMock()
    app._handle_reply = mock.MagicMock()
    app.handle_message = mock.MagicMock()

    data = t.uint8_t(0xaa).serialize()
    data += addr_nwk.address.serialize()
    data += addr_ieee.address.serialize()
    data += t.uint8_t(0x8e).serialize()

    app.handle_rx(
        addr_nwk,
        mock.sentinel.src_ep,
        dst_ep,
        mock.sentinel.profile_id,
        cluster_id,
        data,
        mock.sentinel.lqi,
        mock.sentinel.rssi,
    )

    assert app.deserialize.call_count == 1
    assert app.deserialize.call_args[0][2] == cluster_id
    assert app.deserialize.call_args[0][3] == data
    assert app._handle_reply.call_count == 0
    assert app.handle_message.call_count == 1
    assert app.handle_join.call_count == 1
    assert app.handle_join.call_args[0][0] == addr_nwk.address
    assert app.handle_join.call_args[0][1] == addr_ieee.address
    assert app.handle_join.call_args[0][2] == 0


@pytest.mark.asyncio
async def test_conbee_dev_add_to_group(app, nwk):
    group = mock.MagicMock()
    app._groups = mock.MagicMock()
    app._groups.add_group.return_value = group

    conbee = application.ConBeeDevice(app, mock.sentinel.ieee, nwk)

    await conbee.add_to_group(mock.sentinel.grp_id, mock.sentinel.grp_name)
    assert group.add_member.call_count == 1

    assert app.groups.add_group.call_count == 1
    assert app.groups.add_group.call_args[0][0] is mock.sentinel.grp_id
    assert app.groups.add_group.call_args[0][1] is mock.sentinel.grp_name


@pytest.mark.asyncio
async def test_conbee_dev_remove_from_group(app, nwk):
    group = mock.MagicMock()
    app.groups[mock.sentinel.grp_id] = group
    conbee = application.ConBeeDevice(app,
                                      mock.sentinel.ieee, nwk)

    await conbee.remove_from_group(mock.sentinel.grp_id)
    assert group.remove_member.call_count == 1


def test_conbee_props(nwk):
    conbee = application.ConBeeDevice(app, mock.sentinel.ieee, nwk)
    assert conbee.manufacturer is not None
    assert conbee.model is not None


@pytest.mark.asyncio
async def test_conbee_new(app, nwk, monkeypatch):
    mock_init = mock.MagicMock(
        side_effect=asyncio.coroutine(mock.MagicMock())
    )
    monkeypatch.setattr(zigpy.device.Device, '_initialize', mock_init)

    conbee = await application.ConBeeDevice.new(app, mock.sentinel.ieee, nwk)
    assert isinstance(conbee, zigpy_deconz.zigbee.application.ConBeeDevice)
    assert mock_init.call_count == 1
    mock_init.reset_mock()

    app.devices[mock.sentinel.ieee] = mock.MagicMock()
    conbee = await application.ConBeeDevice.new(app, mock.sentinel.ieee, nwk)
    assert isinstance(conbee, zigpy_deconz.zigbee.application.ConBeeDevice)
    assert mock_init.call_count == 0
