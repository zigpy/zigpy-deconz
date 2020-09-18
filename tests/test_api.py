"""Test api module."""

import asyncio
import logging

import pytest
import serial
import zigpy.config

from zigpy_deconz import api as deconz_api, types as t, uart
import zigpy_deconz.exception
import zigpy_deconz.zigbee.application

from .async_mock import AsyncMock, MagicMock, patch, sentinel

pytestmark = pytest.mark.asyncio
DEVICE_CONFIG = {zigpy.config.CONF_DEVICE_PATH: "/dev/null"}


@pytest.fixture
def api(event_loop):
    controller = MagicMock(
        spec_set=zigpy_deconz.zigbee.application.ControllerApplication
    )
    api = deconz_api.Deconz(controller, {zigpy.config.CONF_DEVICE_PATH: "/dev/null"})
    api._uart = MagicMock()
    return api


async def test_connect():
    controller = MagicMock(
        spec_set=zigpy_deconz.zigbee.application.ControllerApplication
    )
    api = deconz_api.Deconz(controller, {zigpy.config.CONF_DEVICE_PATH: "/dev/null"})

    with patch.object(uart, "connect", new=AsyncMock()) as conn_mck:
        await api.connect()
        assert conn_mck.call_count == 1
        assert conn_mck.await_count == 1
        assert api._uart == conn_mck.return_value


def test_close(api):
    uart = api._uart
    api.close()
    assert api._uart is None
    assert uart.close.call_count == 1


def test_commands():
    for cmd, cmd_opts in deconz_api.RX_COMMANDS.items():
        assert len(cmd_opts) == 2
        schema, solicited = cmd_opts
        assert isinstance(cmd, int) is True
        assert isinstance(schema, tuple) is True
        assert isinstance(solicited, bool)

    for cmd, schema in deconz_api.TX_COMMANDS.items():
        assert isinstance(cmd, int) is True
        assert isinstance(schema, tuple) is True


async def test_command(api, monkeypatch):
    def mock_api_frame(name, *args):
        return sentinel.api_frame_data, api._seq

    api._api_frame = MagicMock(side_effect=mock_api_frame)
    api._uart.send = MagicMock()

    async def mock_fut():
        return sentinel.cmd_result

    monkeypatch.setattr(asyncio, "Future", mock_fut)

    for cmd, cmd_opts in deconz_api.TX_COMMANDS.items():
        ret = await api._command(cmd, sentinel.cmd_data)
        assert ret is sentinel.cmd_result
        assert api._api_frame.call_count == 1
        assert api._api_frame.call_args[0][0] == cmd
        assert api._api_frame.call_args[0][1] == sentinel.cmd_data
        assert api._uart.send.call_count == 1
        assert api._uart.send.call_args[0][0] == sentinel.api_frame_data
        api._api_frame.reset_mock()
        api._uart.send.reset_mock()


async def test_command_queue(api, monkeypatch):
    def mock_api_frame(name, *args):
        return sentinel.api_frame_data, api._seq

    api._api_frame = MagicMock(side_effect=mock_api_frame)
    api._uart.send = MagicMock()

    monkeypatch.setattr(deconz_api, "COMMAND_TIMEOUT", 0.1)

    for cmd, cmd_opts in deconz_api.TX_COMMANDS.items():
        async with api._command_lock:
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(api._command(cmd, sentinel.cmd_data), 0.1)
        assert api._api_frame.call_count == 0
        assert api._uart.send.call_count == 0
        api._api_frame.reset_mock()
        api._uart.send.reset_mock()


async def test_command_timeout(api, monkeypatch):
    def mock_api_frame(name, *args):
        return sentinel.api_frame_data, api._seq

    api._api_frame = MagicMock(side_effect=mock_api_frame)
    api._uart.send = MagicMock()

    monkeypatch.setattr(deconz_api, "COMMAND_TIMEOUT", 0.1)

    for cmd, cmd_opts in deconz_api.TX_COMMANDS.items():
        with pytest.raises(asyncio.TimeoutError):
            await api._command(cmd, sentinel.cmd_data)
        assert api._api_frame.call_count == 1
        assert api._api_frame.call_args[0][0] == cmd
        assert api._api_frame.call_args[0][1] == sentinel.cmd_data
        assert api._uart.send.call_count == 1
        assert api._uart.send.call_args[0][0] == sentinel.api_frame_data
        api._api_frame.reset_mock()
        api._uart.send.reset_mock()


async def test_command_not_connected(api):
    api._uart = None

    def mock_api_frame(name, *args):
        return sentinel.api_frame_data, api._seq

    api._api_frame = MagicMock(side_effect=mock_api_frame)

    for cmd, cmd_opts in deconz_api.TX_COMMANDS.items():
        with pytest.raises(deconz_api.CommandError):
            await api._command(cmd, sentinel.cmd_data)
        assert api._api_frame.call_count == 0
        api._api_frame.reset_mock()


def _fake_args(arg_type):
    if isinstance(arg_type(), t.DeconzAddressEndpoint):
        addr = t.DeconzAddressEndpoint()
        addr.address_mode = t.ADDRESS_MODE.NWK
        addr.address = t.uint8_t(0)
        addr.endpoint = t.uint8_t(0)
        return addr
    if isinstance(arg_type(), t.EUI64):
        return t.EUI64([0x01] * 8)

    return arg_type()


def test_api_frame(api):
    for cmd, schema in deconz_api.TX_COMMANDS.items():
        if schema:
            args = [_fake_args(a) for a in schema]
            api._api_frame(cmd, *args)
        else:
            api._api_frame(cmd)


def test_data_received(api, monkeypatch):
    monkeypatch.setattr(
        t,
        "deserialize",
        MagicMock(return_value=(sentinel.deserialize_data, b"")),
    )
    my_handler = MagicMock()

    for cmd, cmd_opts in deconz_api.RX_COMMANDS.items():
        payload = b"\x01\x02\x03\x04"
        data = cmd.serialize() + b"\x00\x00\x00\x00" + payload
        setattr(api, "_handle_{}".format(cmd.name), my_handler)
        api._awaiting[0] = MagicMock()
        api.data_received(data)
        assert t.deserialize.call_count == 1
        assert t.deserialize.call_args[0][0] == payload
        assert my_handler.call_count == 1
        assert my_handler.call_args[0][0] == sentinel.deserialize_data
        t.deserialize.reset_mock()
        my_handler.reset_mock()


def test_data_received_unk_status(api, monkeypatch):
    monkeypatch.setattr(
        t,
        "deserialize",
        MagicMock(return_value=(sentinel.deserialize_data, b"")),
    )
    my_handler = MagicMock()

    for cmd, cmd_opts in deconz_api.RX_COMMANDS.items():
        _, unsolicited = cmd_opts
        payload = b"\x01\x02\x03\x04"
        status = t.uint8_t(0xFE).serialize()
        data = cmd.serialize() + b"\x00" + status + b"\x00\x00" + payload
        setattr(api, "_handle_{}".format(cmd.name), my_handler)
        api._awaiting[0] = MagicMock()
        api.data_received(data)
        assert t.deserialize.call_count == 1
        assert t.deserialize.call_args[0][0] == payload
        if unsolicited:
            assert my_handler.call_count == 0
        else:
            assert my_handler.call_count == 1
        t.deserialize.reset_mock()
        my_handler.reset_mock()


def test_data_received_unk_cmd(api, monkeypatch):
    monkeypatch.setattr(
        t,
        "deserialize",
        MagicMock(return_value=(sentinel.deserialize_data, b"")),
    )

    for cmd_id in range(253, 255):
        payload = b"\x01\x02\x03\x04"
        status = t.uint8_t(0x00).serialize()
        data = cmd_id.to_bytes(1, "big") + b"\x00" + status + b"\x00\x00" + payload
        api._awaiting[0] = (MagicMock(),)
        api.data_received(data)
        assert t.deserialize.call_count == 0
        t.deserialize.reset_mock()


def test_simplified_beacon(api):
    api._handle_simplified_beacon((0x0007, 0x1234, 0x5678, 0x19, 0x00, 0x01))


async def test_aps_data_confirm(api, monkeypatch):
    monkeypatch.setattr(deconz_api, "COMMAND_TIMEOUT", 0.1)

    success = True

    def mock_cmd(*args, **kwargs):
        res = asyncio.Future()
        if success:
            res.set_result([7, 0x22, 0x11, sentinel.dst_addr, 1, 0x00, 0, 0, 0, 0])
        return asyncio.wait_for(res, timeout=deconz_api.COMMAND_TIMEOUT)

    api._command = mock_cmd
    api._data_confirm = True

    res = await api._aps_data_confirm()
    assert res is not None
    assert api._data_confirm is True

    success = False
    res = await api._aps_data_confirm()
    assert res is None
    assert api._data_confirm is False


async def test_aps_data_ind(api, monkeypatch):
    monkeypatch.setattr(deconz_api, "COMMAND_TIMEOUT", 0.1)

    success = True

    def mock_cmd(*args, **kwargs):
        res = asyncio.Future()
        s = sentinel
        if success:
            res.set_result(
                [
                    s.len,
                    0x22,
                    t.DeconzAddress(),
                    1,
                    t.DeconzAddress(),
                    1,
                    0x0104,
                    0x0000,
                    b"\x00\x01\x02",
                ]
            )
        return asyncio.wait_for(res, timeout=deconz_api.COMMAND_TIMEOUT)

    api._command = mock_cmd
    api._data_indication = True

    res = await api._aps_data_indication()
    assert res is not None
    assert api._data_indication is True

    success = False
    res = await api._aps_data_indication()
    assert res is None
    assert api._data_indication is False


async def test_aps_data_request(api):
    params = [
        0x00,  # req  id
        t.DeconzAddressEndpoint.deserialize(b"\x02\xaa\x55\x01")[0],  # dst + ep
        0x0104,  # profile id
        0x0007,  # cluster id
        0x01,  # src ep
        b"aps payload",
    ]

    mock_cmd = AsyncMock()
    api._command = mock_cmd

    await api.aps_data_request(*params)
    assert mock_cmd.call_count == 1


async def test_aps_data_request_timeout(api, monkeypatch):
    params = [
        0x00,  # req  id
        t.DeconzAddressEndpoint.deserialize(b"\x02\xaa\x55\x01")[0],  # dst + ep
        0x0104,  # profile id
        0x0007,  # cluster id
        0x01,  # src ep
        b"aps payload",
    ]

    monkeypatch.setattr(deconz_api, "COMMAND_TIMEOUT", 0.1)
    mock_cmd = MagicMock(
        return_value=asyncio.wait_for(
            asyncio.Future(), timeout=deconz_api.COMMAND_TIMEOUT
        )
    )
    api._command = mock_cmd

    with pytest.raises(asyncio.TimeoutError):
        await api.aps_data_request(*params)
        assert mock_cmd.call_count == 1


async def test_aps_data_request_busy(api, monkeypatch):
    params = [
        0x00,  # req  id
        t.DeconzAddressEndpoint.deserialize(b"\x02\xaa\x55\x01")[0],  # dst + ep
        0x0104,  # profile id
        0x0007,  # cluster id
        0x01,  # src ep
        b"aps payload",
    ]

    res = asyncio.Future()
    exc = zigpy_deconz.exception.CommandError(deconz_api.Status.BUSY, "busy")
    res.set_exception(exc)
    mock_cmd = MagicMock(return_value=res)

    api._command = mock_cmd
    monkeypatch.setattr(deconz_api, "COMMAND_TIMEOUT", 0.1)
    sleep = AsyncMock()
    monkeypatch.setattr(asyncio, "sleep", sleep)

    with pytest.raises(zigpy_deconz.exception.CommandError):
        await api.aps_data_request(*params)
        assert mock_cmd.call_count == 4


def test_handle_read_parameter(api):
    api._handle_read_parameter(sentinel.data)


async def test_read_parameter(api):
    api._command = AsyncMock(
        return_value=(sentinel.len, sentinel.param_id, b"\xaa\x55")
    )

    r = await api.read_parameter(deconz_api.NetworkParameter.nwk_panid)
    assert api._command.call_count == 1
    assert r[0] == 0x55AA

    api._command.reset_mock()
    r = await api.read_parameter(0x05)
    assert api._command.call_count == 1
    assert r[0] == 0x55AA

    with pytest.raises(KeyError):
        await api.read_parameter("unknown_param")

    unk_param = 0xFF
    assert unk_param not in list(deconz_api.NetworkParameter)
    with pytest.raises(KeyError):
        await api.read_parameter(unk_param)


def test_handle_write_parameter(api):
    param_id = 0x05
    api._handle_write_parameter([sentinel.len, param_id])

    unk_param = 0xFF
    assert unk_param not in list(deconz_api.NetworkParameter)
    api._handle_write_parameter([sentinel.len, unk_param])


async def test_write_parameter(api):
    api._command = AsyncMock()

    await api.write_parameter(deconz_api.NetworkParameter.nwk_panid, 0x55AA)
    assert api._command.call_count == 1

    api._command.reset_mock()
    await api.write_parameter(0x05, 0x55AA)
    assert api._command.call_count == 1

    with pytest.raises(KeyError):
        await api.write_parameter("unknown_param", 0x55AA)

    unk_param = 0xFF
    assert unk_param not in list(deconz_api.NetworkParameter)
    with pytest.raises(KeyError):
        await api.write_parameter(unk_param, 0x55AA)


@pytest.mark.parametrize(
    "protocol_ver, firmware_version, flags",
    [
        (0x010A, 0x123405DD, 0x01),
        (0x010B, 0x123405DD, 0x04),
        (0x010A, 0x123407DD, 0x01),
        (0x010B, 0x123407DD, 0x01),
    ],
)
async def test_version(protocol_ver, firmware_version, flags, api):
    api.read_parameter = AsyncMock(return_value=[protocol_ver])
    api._command = AsyncMock(return_value=[firmware_version])
    r = await api.version()
    assert r == firmware_version
    assert api._aps_data_ind_flags == flags


def test_handle_version(api):
    api._handle_version([sentinel.version])


@pytest.mark.parametrize(
    "data, network_state",
    ((0x00, "OFFLINE"), (0x01, "JOINING"), (0x02, "CONNECTED"), (0x03, "LEAVING")),
)
def test_device_state_network_state(data, network_state):
    """Test device state flag."""
    extra = b"the rest of the data\xaa\x55"

    for other_fields in (0x04, 0x08, 0x0C, 0x10, 0x24, 0x28, 0x30, 0x2C):
        new_data = t.uint8_t(data | other_fields).serialize()
        state, rest = deconz_api.DeviceState.deserialize(new_data + extra)
        assert rest == extra
        assert state.network_state == deconz_api.NetworkState[network_state]
        assert state.serialize() == new_data


@patch("zigpy_deconz.uart.connect")
async def test_reconnect_multiple_disconnects(connect_mock, caplog):
    api = deconz_api.Deconz(None, DEVICE_CONFIG)
    gw = MagicMock(spec_set=uart.Gateway)
    connect_mock.return_value = gw

    await api.connect()

    caplog.set_level(logging.DEBUG)
    connect_mock.reset_mock()
    connect_mock.return_value = asyncio.Future()
    api.connection_lost("connection lost")
    await asyncio.sleep(0)
    connect_mock.return_value = sentinel.uart_reconnect
    api.connection_lost("connection lost 2")
    await asyncio.sleep(0)

    assert api._uart is sentinel.uart_reconnect
    assert connect_mock.call_count == 1
    assert "Cancelling reconnection attempt" in caplog.messages


@patch("zigpy_deconz.uart.connect")
async def test_reconnect_multiple_attempts(connect_mock, caplog):
    api = deconz_api.Deconz(None, DEVICE_CONFIG)
    gw = MagicMock(spec_set=uart.Gateway)
    connect_mock.return_value = gw

    await api.connect()

    caplog.set_level(logging.DEBUG)
    connect_mock.reset_mock()
    connect_mock.side_effect = [asyncio.TimeoutError, OSError, gw]

    with patch("asyncio.sleep"):
        api.connection_lost("connection lost")
        await api._conn_lost_task

    assert api._uart is gw
    assert connect_mock.call_count == 3


@patch.object(deconz_api.Deconz, "device_state", new_callable=AsyncMock)
@patch("zigpy_deconz.uart.connect", return_value=MagicMock(spec_set=uart.Gateway))
async def test_probe_success(mock_connect, mock_device_state):
    """Test device probing."""

    res = await deconz_api.Deconz.probe(DEVICE_CONFIG)
    assert res is True
    assert mock_connect.call_count == 1
    assert mock_connect.await_count == 1
    assert mock_connect.call_args[0][0] is DEVICE_CONFIG
    assert mock_device_state.call_count == 1
    assert mock_connect.return_value.close.call_count == 1

    mock_connect.reset_mock()
    mock_device_state.reset_mock()
    mock_connect.reset_mock()
    res = await deconz_api.Deconz.probe(DEVICE_CONFIG)
    assert res is True
    assert mock_connect.call_count == 1
    assert mock_connect.await_count == 1
    assert mock_connect.call_args[0][0] is DEVICE_CONFIG
    assert mock_device_state.call_count == 1
    assert mock_connect.return_value.close.call_count == 1


@patch.object(deconz_api.Deconz, "device_state", new_callable=AsyncMock)
@patch("zigpy_deconz.uart.connect", return_value=MagicMock(spec_set=uart.Gateway))
@pytest.mark.parametrize(
    "exception",
    (asyncio.TimeoutError, serial.SerialException, zigpy_deconz.exception.CommandError),
)
async def test_probe_fail(mock_connect, mock_device_state, exception):
    """Test device probing fails."""

    mock_device_state.side_effect = exception
    mock_device_state.reset_mock()
    mock_connect.reset_mock()
    res = await deconz_api.Deconz.probe(DEVICE_CONFIG)
    assert res is False
    assert mock_connect.call_count == 1
    assert mock_connect.await_count == 1
    assert mock_connect.call_args[0][0] is DEVICE_CONFIG
    assert mock_device_state.call_count == 1
    assert mock_connect.return_value.close.call_count == 1


@pytest.mark.parametrize(
    "value, name",
    (
        (0x00, "SUCCESS"),
        (0xA0, "APS_ASDU_TOO_LONG"),
        (0x01, "MAC_PAN_AT_CAPACITY"),
        (0xC9, "NWK_UNSUPPORTED_ATTRIBUTE"),
        (0xFE, "undefined_0xfe"),
    ),
)
def test_tx_status(value, name):
    """Test tx status undefined values."""
    i = deconz_api.TXStatus(value)
    assert i == value
    assert i.value == value
    assert i.name == name

    extra = b"\xaa\55"
    data = t.uint8_t(value).serialize()
    status, rest = deconz_api.TXStatus.deserialize(data + extra)
    assert rest == extra
    assert isinstance(status, deconz_api.TXStatus)
    assert status == value
    assert status.value == value
    assert status.name == name


def test_handle_add_neighbour(api):
    """Test handle_add_neighbour."""
    api._handle_add_neighbour((12, 1, 0x1234, sentinel.ieee, 0x80))
