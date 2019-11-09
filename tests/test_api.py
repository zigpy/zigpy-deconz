import asyncio
from unittest import mock

import pytest

from zigpy_deconz import api as deconz_api, types as t, uart
import zigpy_deconz.exception


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
        uart, "connect", mock.MagicMock(side_effect=asyncio.coroutine(mock.MagicMock()))
    )
    await api.connect(dev, 115200)


def test_close(api):
    api._uart.close = mock.MagicMock()
    api.close()
    assert api._uart.close.call_count == 1


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


@pytest.mark.asyncio
async def test_command(api, monkeypatch):
    def mock_api_frame(name, *args):
        return mock.sentinel.api_frame_data, api._seq

    api._api_frame = mock.MagicMock(side_effect=mock_api_frame)
    api._uart.send = mock.MagicMock()

    async def mock_fut():
        return mock.sentinel.cmd_result

    monkeypatch.setattr(asyncio, "Future", mock_fut)

    for cmd, cmd_opts in deconz_api.TX_COMMANDS.items():
        ret = await api._command(cmd, mock.sentinel.cmd_data)
        assert ret is mock.sentinel.cmd_result
        assert api._api_frame.call_count == 1
        assert api._api_frame.call_args[0][0] == cmd
        assert api._api_frame.call_args[0][1] == mock.sentinel.cmd_data
        assert api._uart.send.call_count == 1
        assert api._uart.send.call_args[0][0] == mock.sentinel.api_frame_data
        api._api_frame.reset_mock()
        api._uart.send.reset_mock()


@pytest.mark.asyncio
async def test_command_timeout(api, monkeypatch):
    def mock_api_frame(name, *args):
        return mock.sentinel.api_frame_data, api._seq

    api._api_frame = mock.MagicMock(side_effect=mock_api_frame)
    api._uart.send = mock.MagicMock()

    monkeypatch.setattr(deconz_api, "COMMAND_TIMEOUT", 0.1)

    for cmd, cmd_opts in deconz_api.TX_COMMANDS.items():
        with pytest.raises(asyncio.TimeoutError):
            await api._command(cmd, mock.sentinel.cmd_data)
        assert api._api_frame.call_count == 1
        assert api._api_frame.call_args[0][0] == cmd
        assert api._api_frame.call_args[0][1] == mock.sentinel.cmd_data
        assert api._uart.send.call_count == 1
        assert api._uart.send.call_args[0][0] == mock.sentinel.api_frame_data
        api._api_frame.reset_mock()
        api._uart.send.reset_mock()


def test_api_frame(api):
    addr = t.DeconzAddressEndpoint()
    addr.address_mode = t.ADDRESS_MODE.NWK
    addr.address = t.uint8_t(0)
    addr.endpoint = t.uint8_t(0)
    for cmd, schema in deconz_api.TX_COMMANDS.items():
        if schema:
            args = [
                addr if isinstance(a(), t.DeconzAddressEndpoint) else a()
                for a in schema
            ]
            api._api_frame(cmd, *args)
        else:
            api._api_frame(cmd)


def test_data_received(api, monkeypatch):
    monkeypatch.setattr(
        t,
        "deserialize",
        mock.MagicMock(return_value=(mock.sentinel.deserialize_data, b"")),
    )
    my_handler = mock.MagicMock()

    for cmd, cmd_opts in deconz_api.RX_COMMANDS.items():
        payload = b"\x01\x02\x03\x04"
        data = cmd.serialize() + b"\x00\x00\x00\x00" + payload
        setattr(api, "_handle_{}".format(cmd.name), my_handler)
        api._awaiting[0] = mock.MagicMock()
        api.data_received(data)
        assert t.deserialize.call_count == 1
        assert t.deserialize.call_args[0][0] == payload
        assert my_handler.call_count == 1
        assert my_handler.call_args[0][0] == mock.sentinel.deserialize_data
        t.deserialize.reset_mock()
        my_handler.reset_mock()


def test_data_received_unk_status(api, monkeypatch):
    monkeypatch.setattr(
        t,
        "deserialize",
        mock.MagicMock(return_value=(mock.sentinel.deserialize_data, b"")),
    )
    my_handler = mock.MagicMock()

    for cmd, cmd_opts in deconz_api.RX_COMMANDS.items():
        _, unsolicited = cmd_opts
        payload = b"\x01\x02\x03\x04"
        status = t.uint8_t(0xFE).serialize()
        data = cmd.serialize() + b"\x00" + status + b"\x00\x00" + payload
        setattr(api, "_handle_{}".format(cmd.name), my_handler)
        api._awaiting[0] = mock.MagicMock()
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
        mock.MagicMock(return_value=(mock.sentinel.deserialize_data, b"")),
    )

    for cmd_id in range(253, 255):
        payload = b"\x01\x02\x03\x04"
        status = t.uint8_t(0x00).serialize()
        data = cmd_id.to_bytes(1, "big") + b"\x00" + status + b"\x00\x00" + payload
        api._awaiting[0] = (mock.MagicMock(),)
        api.data_received(data)
        assert t.deserialize.call_count == 0
        t.deserialize.reset_mock()


def test_simplified_beacon(api):
    api._handle_simplified_beacon((0x0007, 0x1234, 0x5678, 0x19, 0x00, 0x01))


@pytest.mark.asyncio
async def test_aps_data_confirm(api, monkeypatch):
    monkeypatch.setattr(deconz_api, "COMMAND_TIMEOUT", 0.1)

    success = True

    def mock_cmd(*args, **kwargs):
        res = asyncio.Future()
        if success:
            res.set_result([7, 0x22, 0x11, mock.sentinel.dst_addr, 1, 0x00, 0, 0, 0, 0])
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


@pytest.mark.asyncio
async def test_aps_data_ind(api, monkeypatch):
    monkeypatch.setattr(deconz_api, "COMMAND_TIMEOUT", 0.1)

    success = True

    def mock_cmd(*args, **kwargs):
        res = asyncio.Future()
        s = mock.sentinel
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


@pytest.mark.asyncio
async def test_aps_data_request(api):
    params = [
        0x00,  # req  id
        t.DeconzAddressEndpoint.deserialize(b"\x02\xaa\x55\x01")[0],  # dst + ep
        0x0104,  # profile id
        0x0007,  # cluster id
        0x01,  # src ep
        b"aps payload",
    ]

    mock_cmd = mock.MagicMock(side_effect=asyncio.coroutine(mock.MagicMock()))
    api._command = mock_cmd

    await api.aps_data_request(*params)
    assert mock_cmd.call_count == 1


@pytest.mark.asyncio
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
    mock_cmd = mock.MagicMock(
        return_value=asyncio.wait_for(
            asyncio.Future(), timeout=deconz_api.COMMAND_TIMEOUT
        )
    )
    api._command = mock_cmd

    with pytest.raises(asyncio.TimeoutError):
        await api.aps_data_request(*params)
        assert mock_cmd.call_count == 1


@pytest.mark.asyncio
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
    mock_cmd = mock.MagicMock(return_value=res)

    api._command = mock_cmd
    monkeypatch.setattr(deconz_api, "COMMAND_TIMEOUT", 0.1)
    sleep = mock.MagicMock(side_effect=asyncio.coroutine(mock.MagicMock()))
    monkeypatch.setattr(asyncio, "sleep", sleep)

    with pytest.raises(zigpy_deconz.exception.CommandError):
        await api.aps_data_request(*params)
        assert mock_cmd.call_count == 4


def test_handle_read_parameter(api):
    api._handle_read_parameter(mock.sentinel.data)


@pytest.mark.asyncio
async def test_read_parameter(api):
    api._command = mock.MagicMock()
    api._command.side_effect = asyncio.coroutine(
        mock.MagicMock(
            return_value=(mock.sentinel.len, mock.sentinel.param_id, b"\xaa\x55")
        )
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
    api._handle_write_parameter([mock.sentinel.len, param_id])

    unk_param = 0xFF
    assert unk_param not in list(deconz_api.NetworkParameter)
    api._handle_write_parameter([mock.sentinel.len, unk_param])


@pytest.mark.asyncio
async def test_write_parameter(api):
    api._command = mock.MagicMock()
    api._command.side_effect = asyncio.coroutine(mock.MagicMock())

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
@pytest.mark.asyncio
async def test_version(protocol_ver, firmware_version, flags, api):
    api.read_parameter = mock.MagicMock()
    api.read_parameter.side_effect = asyncio.coroutine(
        mock.MagicMock(return_value=[protocol_ver])
    )
    api._command = mock.MagicMock()
    api._command.side_effect = asyncio.coroutine(
        mock.MagicMock(return_value=[firmware_version])
    )
    r = await api.version()
    assert r == firmware_version
    assert api._aps_data_ind_flags == flags


def test_handle_version(api):
    api._handle_version([mock.sentinel.version])
