import asyncio
from unittest import mock

import pytest

from zigpy_deconz import api as deconz_api, types as t, uart


COMMANDS = [*deconz_api.TX_COMMANDS.items(), *deconz_api.RX_COMMANDS.items()]


@pytest.fixture
def api():
    api = deconz_api.Deconz()
    api._uart = mock.MagicMock()
    return api


def test_set_application(api):
    api.set_application(mock.sentinel.app)
    assert api._app == mock.sentinel.app


@pytest.mark.asyncio
async def test_connect(monkeypatch):
    api = deconz_api.Deconz()
    dev = mock.MagicMock()
    monkeypatch.setattr(
        uart, 'connect',
        mock.MagicMock(side_effect=asyncio.coroutine(mock.MagicMock())))
    await api.connect(dev, 115200)


def test_close(api):
    api._uart.close = mock.MagicMock()
    api.close()
    assert api._uart.close.call_count == 1


def test_commands():
    import string
    anum = string.ascii_letters + string.digits + '_'
    for cmd_name, cmd_opts in COMMANDS:
        assert isinstance(cmd_name, str) is True
        assert all([c in anum for c in cmd_name]), cmd_name
        assert len(cmd_opts) == 3
        cmd_id, schema, reply = cmd_opts
        assert isinstance(cmd_id, int) is True
        assert isinstance(schema, tuple) is True
        assert reply is None or isinstance(reply, bool)


@pytest.mark.asyncio
async def test_command(api):
    def mock_api_frame(name, *args):
        c = deconz_api.TX_COMMANDS[name]
        return mock.sentinel.api_frame_data, c[2]
    api._api_frame = mock.MagicMock(side_effect=mock_api_frame)
    api._uart.send = mock.MagicMock()

    for cmd_name, cmd_opts in deconz_api.TX_COMMANDS.items():
        _, _, expect_reply = cmd_opts
        ret = api._command(cmd_name, mock.sentinel.cmd_data)
        if expect_reply:
            assert asyncio.isfuture(ret) is True
            ret.cancel()
        else:
            assert ret is None
        assert api._api_frame.call_count == 1
        assert api._api_frame.call_args[0][0] == cmd_name
        assert api._api_frame.call_args[0][1] == mock.sentinel.cmd_data
        assert api._uart.send.call_count == 1
        assert api._uart.send.call_args[0][0] == mock.sentinel.api_frame_data
        api._api_frame.reset_mock()
        api._uart.send.reset_mock()


def test_api_frame(api):
    addr = t.DeconzAddress()
    addr.address_mode = t.ADDRESS_MODE.NWK
    addr.address = t.uint8_t(0)
    addr.endpoint = t.uint8_t(0)
    for cmd_name, cmd_opts in deconz_api.TX_COMMANDS.items():
        _, schema, _ = cmd_opts
        if schema:
            args = [addr if isinstance(a(), t.DeconzAddressEndpoint) else a() for a in schema]
            api._api_frame(cmd_name, *args)
        else:
            api._api_frame(cmd_name)


def test_data_received(api, monkeypatch):
    monkeypatch.setattr(t, 'deserialize', mock.MagicMock(
        return_value=(mock.sentinel.deserialize_data, b'')))
    my_handler = mock.MagicMock()

    for cmd, cmd_opts in deconz_api.RX_COMMANDS.items():
        cmd_id = cmd_opts[0]
        payload = b'\x01\x02\x03\x04'
        data = cmd_id.to_bytes(1, 'big') + b'\x00\x00\x00\x00' + payload
        setattr(api, '_handle_{}'.format(cmd), my_handler)
        api._awaiting[0] = (mock.MagicMock(), )
        api.data_received(data)
        assert t.deserialize.call_count == 1
        assert t.deserialize.call_args[0][0] == payload
        assert my_handler.call_count == 1
        assert my_handler.call_args[0][0] == mock.sentinel.deserialize_data
        t.deserialize.reset_mock()
        my_handler.reset_mock()
