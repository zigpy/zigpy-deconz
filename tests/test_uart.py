"""Tests for the uart module."""

import logging
from unittest import mock

import pytest
from zigpy.config import (
    CONF_DEVICE_BAUDRATE,
    CONF_DEVICE_FLOW_CONTROL,
    CONF_DEVICE_PATH,
)
import zigpy.serial

from zigpy_deconz import uart


@pytest.fixture
def gw():
    gw = uart.Gateway(mock.MagicMock())
    gw._transport = mock.MagicMock()
    return gw


async def test_connect(monkeypatch):
    api = mock.MagicMock()

    async def mock_conn(loop, protocol_factory, **kwargs):
        protocol = protocol_factory()
        loop.call_soon(protocol.connection_made, None)
        return None, protocol

    monkeypatch.setattr(zigpy.serial, "create_serial_connection", mock_conn)

    await uart.connect(
        {
            CONF_DEVICE_PATH: "/dev/null",
            CONF_DEVICE_BAUDRATE: 115200,
            CONF_DEVICE_FLOW_CONTROL: None,
        },
        api,
    )


def test_send(gw):
    data = b"test"
    gw.send(data)

    packet = b""
    packet += b"\xc0"  # END
    packet += b"test"  # data
    packet += b"\x40\xfe"  # checksum
    packet += b"\xc0"  # END

    gw._transport.write.assert_called_once_with(packet)


def test_close(gw):
    gw.close()
    assert gw._transport.close.call_count == 1


def test_data_received_chunk_frame(gw):
    data = b"\x07\x01\x00\x08\x00\xaa\x00\x02\x44\xff\xc0"
    gw.data_received(data[:-4])
    assert gw._api.data_received.call_count == 0
    gw.data_received(data[-4:])
    assert gw._api.data_received.call_count == 1
    assert gw._api.data_received.call_args[0][0] == data[:-3]


def test_data_received_full_frame(gw):
    data = b"\x07\x01\x00\x08\x00\xaa\x00\x02\x44\xff\xc0"
    gw.data_received(data)
    assert gw._api.data_received.call_count == 1
    assert gw._api.data_received.call_args[0][0] == data[:-3]


def test_data_received_incomplete_frame(gw):
    data = b"~\x00\x00"
    gw.data_received(data)
    assert gw._api.data_received.call_count == 0


def test_data_received_runt_frame(gw):
    data = b"\x02\x44\xc0"
    gw.data_received(data)
    assert gw._api.data_received.call_count == 0


def test_data_received_extra(gw):
    data = b"\x07\x01\x00\x08\x00\xaa\x00\x02\x44\xff\xc0\x00"
    gw.data_received(data)
    assert gw._api.data_received.call_count == 1
    assert gw._api.data_received.call_args[0][0] == data[:-4]
    assert gw._buffer == b"\x00"


def test_data_received_wrong_checksum(gw):
    data = b"\x07\x01\x00\x08\x00\xaa\x00\x02\x44\xfe\xc0"
    gw.data_received(data)
    assert gw._api.data_received.call_count == 0


def test_data_received_error(gw, caplog):
    data = b"\x07\x01\x00\x08\x00\xaa\x00\x02\x44\xff\xc0"

    gw._api.data_received.side_effect = [RuntimeError("error")]

    with caplog.at_level(logging.ERROR):
        gw.data_received(data)

    assert "RuntimeError" in caplog.text and "handling the frame" in caplog.text

    assert gw._api.data_received.call_count == 1
    assert gw._api.data_received.call_args[0][0] == data[:-3]


def test_unescape(gw):
    data = b"\x00\xdb\xdc\x00\xdb\xdd\x00\x00\x00"
    data_unescaped = b"\x00\xc0\x00\xdb\x00\x00\x00"
    r = gw._unescape(data)
    assert r == data_unescaped


def test_unescape_error(gw):
    data = b"\x00\xdb\xdc\x00\xdb\xdd\x00\x00\x00\xdb"
    r = gw._unescape(data)
    assert r is None


def test_escape(gw):
    data = b"\x00\xc0\x00\xdb\x00\x00\x00"
    data_escaped = b"\x00\xdb\xdc\x00\xdb\xdd\x00\x00\x00"
    r = gw._escape(data)
    assert r == data_escaped


def test_checksum(gw):
    data = b"\x07\x01\x00\x08\x00\xaa\x00\x02"
    checksum = b"\x44\xff"
    r = gw._checksum(data)
    assert r == checksum


def test_connection_lost_exc(gw):
    gw.connection_lost(mock.sentinel.exception)

    conn_lost = gw._api.connection_lost
    assert conn_lost.call_count == 1
    assert conn_lost.call_args[0][0] is mock.sentinel.exception


def test_connection_closed(gw):
    gw.connection_lost(None)

    assert gw._api.connection_lost.call_count == 1
