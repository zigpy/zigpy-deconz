from unittest import mock

import pytest
import serial_asyncio
from zigpy.config import CONF_DEVICE_PATH

from zigpy_deconz import uart


@pytest.fixture
def gw():
    gw = uart.Gateway(mock.MagicMock())
    gw._transport = mock.MagicMock()
    return gw


@pytest.mark.asyncio
async def test_connect(monkeypatch):
    api = mock.MagicMock()

    async def mock_conn(loop, protocol_factory, **kwargs):
        protocol = protocol_factory()
        loop.call_soon(protocol.connection_made, None)
        return None, protocol

    monkeypatch.setattr(serial_asyncio, "create_serial_connection", mock_conn)

    await uart.connect({CONF_DEVICE_PATH: "/dev/null"}, api)


def test_send(gw):
    data = b"\x00"
    gw.send(data)
    assert gw._transport.write.call_count == 1
    assert gw._transport.write.called_once_with(data)


def test_close(gw):
    gw.close()
    assert gw._transport.close.call_count == 1


def test_data_received_chunk_frame(gw):
    data = b"\x07\x01\x00\x08\x00\xaa\x00\x02\x44\xFF\xC0"
    gw.data_received(data[:-4])
    assert gw._api.data_received.call_count == 0
    gw.data_received(data[-4:])
    assert gw._api.data_received.call_count == 1
    assert gw._api.data_received.call_args[0][0] == data[:-3]


def test_data_received_full_frame(gw):
    data = b"\x07\x01\x00\x08\x00\xaa\x00\x02\x44\xFF\xC0"
    gw.data_received(data)
    assert gw._api.data_received.call_count == 1
    assert gw._api.data_received.call_args[0][0] == data[:-3]


def test_data_received_incomplete_frame(gw):
    data = b"~\x00\x00"
    gw.data_received(data)
    assert gw._api.data_received.call_count == 0


def test_data_received_runt_frame(gw):
    data = b"\x02\x44\xC0"
    gw.data_received(data)
    assert gw._api.data_received.call_count == 0


def test_data_received_extra(gw):
    data = b"\x07\x01\x00\x08\x00\xaa\x00\x02\x44\xFF\xC0\x00"
    gw.data_received(data)
    assert gw._api.data_received.call_count == 1
    assert gw._api.data_received.call_args[0][0] == data[:-4]
    assert gw._buffer == b"\x00"


def test_data_received_wrong_checksum(gw):
    data = b"\x07\x01\x00\x08\x00\xaa\x00\x02\x44\xFE\xC0"
    gw.data_received(data)
    assert gw._api.data_received.call_count == 0


def test_unescape(gw):
    data = b"\x00\xDB\xDC\x00\xDB\xDD\x00\x00\x00"
    data_unescaped = b"\x00\xC0\x00\xDB\x00\x00\x00"
    r = gw._unescape(data)
    assert r == data_unescaped


def test_unescape_error(gw):
    data = b"\x00\xDB\xDC\x00\xDB\xDD\x00\x00\x00\xDB"
    r = gw._unescape(data)
    assert r is None


def test_escape(gw):
    data = b"\x00\xC0\x00\xDB\x00\x00\x00"
    data_escaped = b"\x00\xDB\xDC\x00\xDB\xDD\x00\x00\x00"
    r = gw._escape(data)
    assert r == data_escaped


def test_checksum(gw):
    data = b"\x07\x01\x00\x08\x00\xaa\x00\x02"
    checksum = b"\x44\xFF"
    r = gw._checksum(data)
    assert r == checksum


def test_connection_lost_exc(gw):
    gw.connection_lost(mock.sentinel.exception)

    conn_lost = gw._api.connection_lost
    assert conn_lost.call_count == 1
    assert conn_lost.call_args[0][0] is mock.sentinel.exception


def test_connection_closed(gw):
    gw.connection_lost(None)

    assert gw._api.connection_lost.call_count == 0
