import asyncio
from unittest import mock

import pytest

from zigpy.types import EUI64
from zigpy_deconz.api import Deconz
from zigpy_deconz.zigbee.application import ControllerApplication
from zigpy_deconz import types as t


@pytest.fixture
def app(database_file=None):
    return ControllerApplication(Deconz(), database_file=database_file)


@pytest.fixture
def addr_ieee():
    addr = t.DeconzAddress()
    addr.address_mode = t.ADDRESS_MODE.IEEE
    addr.address = b'\x00\x01\x02\x03\x04\x05\x06\x07'
    return addr


@pytest.fixture
def addr_nwk():
    addr = t.DeconzAddress()
    addr.address_mode = t.ADDRESS_MODE.NWK
    addr.address = b'\x00\x01'
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
    with pytest.raises(Exception):
        await app.form_network()
    assert app._api.device_state.call_count == 10


@pytest.mark.asyncio
async def test_startup(app):
    app.form_network = mock.MagicMock(
        side_effect=asyncio.coroutine(mock.MagicMock()))
    app._api._command = mock.MagicMock(
        side_effect=asyncio.coroutine(mock.MagicMock()))

    await app.startup(auto_form=False)
    assert app.form_network.call_count == 0
    await app.startup(auto_form=True)
    assert app.form_network.call_count == 1


@pytest.mark.asyncio
async def test_permit(app):
    app._api.write_parameter = mock.MagicMock(
        side_effect=asyncio.coroutine(mock.MagicMock()))
    time_s = 30
    await app.permit(time_s)
    assert app._api.write_parameter.call_count == 1
    assert app._api.write_parameter.call_args_list[0][0][1] == time_s


async def _test_request(app, do_reply=True, expect_reply=True, **kwargs):
    seq = 123
    nwk = 0x2345
    app._devices_by_nwk[nwk] = 0x22334455

    def aps_data_request(dst_addr, dst_ep, profile, cluster, src_ep, data):
        if expect_reply:
            if do_reply:
                app._pending[seq].set_result(mock.sentinel.reply_result)

    app._api.aps_data_request = mock.MagicMock(
        side_effect=asyncio.coroutine(aps_data_request))

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
    send_fut = asyncio.Future()
    reply_fut = asyncio.Future()
    app._pending[tsn] = (send_fut, reply_fut)
    _handle_reply(app, tsn)
    assert app.handle_message.call_count == 0
    assert reply_fut.result() == mock.sentinel.args


def test_handle_reply_dup(app):
    tsn = 123
    send_fut = asyncio.Future()
    reply_fut = asyncio.Future()
    app._pending[tsn] = (send_fut, reply_fut)
    reply_fut.set_result(mock.sentinel.reply_result)
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
