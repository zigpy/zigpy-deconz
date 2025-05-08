"""Test api module."""

import asyncio
import collections
import inspect
import logging
import sys

import pytest
import zigpy.config
import zigpy.types as zigpy_t

if sys.version_info[:2] < (3, 11):
    from async_timeout import timeout as asyncio_timeout
else:
    from asyncio import timeout as asyncio_timeout

from zigpy_deconz import api as deconz_api, types as t, uart
import zigpy_deconz.exception
import zigpy_deconz.zigbee.application

from .async_mock import AsyncMock, MagicMock, call, patch

DEVICE_CONFIG = {zigpy.config.CONF_DEVICE_PATH: "/dev/null"}


@pytest.fixture
async def gateway():
    return uart.Gateway(api=None)


@pytest.fixture
async def api(gateway, mock_command_rsp):
    loop = asyncio.get_running_loop()

    async def mock_connect(config, api):
        transport = MagicMock()
        transport.close = MagicMock(
            side_effect=lambda: loop.call_soon(gateway.connection_lost, None)
        )

        gateway._api = api
        gateway.connection_made(transport)

        return gateway

    with patch("zigpy_deconz.uart.connect", side_effect=mock_connect):
        controller = MagicMock(
            spec_set=zigpy_deconz.zigbee.application.ControllerApplication
        )
        api = deconz_api.Deconz(
            controller, {zigpy.config.CONF_DEVICE_PATH: "/dev/null"}
        )

        mock_command_rsp(
            command_id=deconz_api.CommandId.device_state,
            params={},
            rsp={
                "status": deconz_api.Status.SUCCESS,
                "frame_length": t.uint16_t(8),
                "device_state": deconz_api.DeviceState(
                    network_state=deconz_api.NetworkState2.CONNECTED,
                    device_state=(
                        deconz_api.DeviceStateFlags.APSDE_DATA_REQUEST_FREE_SLOTS_AVAILABLE
                    ),
                ),
                "reserved1": t.uint8_t(0),
                "reserved2": t.uint8_t(0),
            },
        )

        mock_command_rsp(
            command_id=deconz_api.CommandId.read_parameter,
            params={
                "parameter_id": deconz_api.NetworkParameter.protocol_version,
                "parameter": t.Bytes(b""),
            },
            rsp={
                "status": deconz_api.Status.SUCCESS,
                "frame_length": t.uint16_t(10),
                "payload_length": t.uint16_t(3),
                "parameter_id": deconz_api.NetworkParameter.protocol_version,
                "parameter": t.Bytes(t.uint16_t(270).serialize()),
            },
        )

        mock_command_rsp(
            command_id=deconz_api.CommandId.version,
            params={"reserved": t.uint8_t(0)},
            rsp={
                "status": deconz_api.Status.SUCCESS,
                "frame_length": t.uint16_t(9),
                "version": deconz_api.FirmwareVersion(645400320),
            },
        )

        yield api


@pytest.fixture
async def mock_command_rsp(gateway):
    def inner(command_id, params, rsp, *, rsp_command=None, replace=False):
        if (
            getattr(getattr(gateway.send, "side_effect", None), "_handlers", None)
            is None
        ):

            def receiver(data):
                command, _ = deconz_api.Command.deserialize(data)
                tx_schema, _ = deconz_api.COMMAND_SCHEMAS[command.command_id]
                schema = {}

                for k, v in tx_schema.items():
                    if v in (deconz_api.FRAME_LENGTH, deconz_api.PAYLOAD_LENGTH):
                        v = t.uint16_t
                    elif not inspect.isclass(v):
                        v = type(v)

                    schema[k] = v

                kwargs, rest = t.deserialize_dict(command.payload, schema)

                for params, rsp_command, mock in receiver._handlers[command.command_id]:
                    if rsp_command is None:
                        rsp_command = command.command_id

                    if all(kwargs[k] == v for k, v in params.items()):
                        _, rx_schema = deconz_api.COMMAND_SCHEMAS[rsp_command]
                        ret = mock(**kwargs)

                        asyncio.get_running_loop().call_soon(
                            gateway._api.data_received,
                            deconz_api.Command(
                                command_id=rsp_command,
                                seq=command.seq,
                                payload=t.serialize_dict(ret, rx_schema),
                            ).serialize(),
                        )

            receiver._handlers = collections.defaultdict(list)
            gateway.send = MagicMock(side_effect=receiver)

        if replace:
            gateway.send.side_effect._handlers[command_id].clear()

        mock = MagicMock(return_value=rsp)
        gateway.send.side_effect._handlers[command_id].append(
            (params, rsp_command, mock)
        )

        return mock

    return inner


def send_network_state(
    api,
    network_state: deconz_api.NetworkState2 = deconz_api.NetworkState2.CONNECTED,
    device_state: deconz_api.DeviceStateFlags = (
        deconz_api.DeviceStateFlags.APSDE_DATA_CONFIRM
    ),
):
    _, rx_schema = deconz_api.COMMAND_SCHEMAS[deconz_api.CommandId.device_state_changed]

    data = deconz_api.Command(
        command_id=deconz_api.CommandId.device_state_changed,
        seq=api._seq,
        payload=t.serialize_dict(
            {
                "status": deconz_api.Status.SUCCESS,
                "frame_length": t.uint16_t(7),
                "device_state": deconz_api.DeviceState(
                    network_state=network_state,
                    device_state=device_state,
                ),
                "reserved": t.uint8_t(0),
            },
            rx_schema,
        ),
    ).serialize()

    asyncio.get_running_loop().call_later(0.01, api.data_received, data)


async def test_connect(api, mock_command_rsp):
    await api.connect()


async def test_connect_failure(api, mock_command_rsp):
    transport = None

    def mock_version(*args, **kwargs):
        nonlocal transport
        transport = api._uart._transport

        raise asyncio.TimeoutError()

    with patch.object(api, "version", side_effect=mock_version):
        # We connect but fail to probe
        with pytest.raises(asyncio.TimeoutError):
            await api.connect()

    assert api._uart is None
    assert len(transport.close.mock_calls) == 1


async def test_close(api):
    await api.connect()

    uart = api._uart
    uart.disconnect = AsyncMock()

    await api.disconnect()
    assert api._uart is None
    assert uart.disconnect.call_count == 1


def test_commands():
    for cmd, (tx_schema, rx_schema) in deconz_api.COMMAND_SCHEMAS.items():
        assert isinstance(cmd, deconz_api.CommandId)
        assert isinstance(tx_schema, dict) or tx_schema is None
        assert isinstance(rx_schema, dict)


async def test_command(api):
    await api.connect()

    addr = t.DeconzAddress()
    addr.address_mode = t.AddressMode.NWK
    addr.address = t.NWK(0x0000)

    params = {
        "status": deconz_api.Status.SUCCESS,
        "frame_length": t.uint16_t(61),
        "payload_length": t.uint16_t(54),
        "device_state": deconz_api.DeviceState(
            network_state=deconz_api.NetworkState2.CONNECTED,
            device_state=(
                deconz_api.DeviceStateFlags.APSDE_DATA_REQUEST_FREE_SLOTS_AVAILABLE
            ),
        ),
        "dst_addr": addr,
        "dst_ep": t.uint8_t(0),
        "src_addr": addr,
        "src_ep": t.uint8_t(0),
        "profile_id": t.uint16_t(0),
        "cluster_id": t.uint16_t(32772),
        "asdu": t.LongOctetString(
            b"\x0f\x00\x00\x00\x1a\x01\x04\x01\x00\x04\x00\x05\x00\x00\x06"
            b"\x00\n\x00\x19\x00\x01\x05\x04\x01\x00 \x00\x00\x05\x02\x05"
        ),
        "reserved1": t.uint8_t(0),
        "reserved2": t.uint8_t(175),
        "lqi": t.uint8_t(69),
        "reserved3": t.uint8_t(189),
        "reserved4": t.uint8_t(82),
        "reserved5": t.uint8_t(0),
        "reserved6": t.uint8_t(0),
        "rssi": t.int8s(27),
    }

    data = deconz_api.Command(
        command_id=deconz_api.CommandId.aps_data_indication,
        seq=api._seq,
        payload=t.serialize_dict(
            params,
            deconz_api.COMMAND_SCHEMAS[deconz_api.CommandId.aps_data_indication][1],
        ),
    ).serialize()

    asyncio.get_running_loop().call_later(0.01, api.data_received, data)

    rsp = await api._command(
        cmd=deconz_api.CommandId.aps_data_indication,
        flags=t.DataIndicationFlags.Include_Both_NWK_And_IEEE,
    )
    assert rsp == params


async def test_command_lock(api, mock_command_rsp):
    await api.connect()

    for i in range(4):
        mock_command_rsp(
            command_id=deconz_api.CommandId.version,
            params={"reserved": t.uint8_t(i)},
            rsp={
                "status": deconz_api.Status.SUCCESS,
                "frame_length": t.uint16_t(9),
                "version": deconz_api.FirmwareVersion(i),
            },
            replace=(i == 0),
        )

    async with api._command_lock:
        tasks = [
            asyncio.create_task(
                api._command(cmd=deconz_api.CommandId.version, reserved=0)
            ),
            asyncio.create_task(
                api._command(cmd=deconz_api.CommandId.version, reserved=1)
            ),
            asyncio.create_task(
                api._command(cmd=deconz_api.CommandId.version, reserved=2)
            ),
            asyncio.create_task(
                api._command(cmd=deconz_api.CommandId.version, reserved=3)
            ),
        ]

        await asyncio.sleep(0.1)
        assert not any(t.done() for t in tasks)

    responses = await asyncio.gather(*tasks)

    for index, rsp in enumerate(responses):
        assert rsp["version"] == index


async def test_command_timeout(api):
    await api.connect()

    with patch.object(deconz_api, "COMMAND_TIMEOUT", 0.1):
        with pytest.raises(asyncio.TimeoutError):
            await api._command(
                cmd=deconz_api.CommandId.change_network_state,
                network_state=deconz_api.NetworkState.OFFLINE,
            )


async def test_command_not_connected(api):
    api._uart = None

    with pytest.raises(deconz_api.CommandError):
        await api._command(cmd=deconz_api.CommandId.version, reserved=0)


async def test_data_received(api, mock_command_rsp):
    await api.connect()

    src_addr = t.DeconzAddress()
    src_addr.address_mode = t.AddressMode.NWK
    src_addr.address = t.NWK(0xE695)

    dst_addr = t.DeconzAddress()
    dst_addr.address_mode = t.AddressMode.NWK
    dst_addr.address = t.NWK(0x0000)

    mock_command_rsp(
        command_id=deconz_api.CommandId.aps_data_indication,
        params={},
        rsp={
            "status": deconz_api.Status.SUCCESS,
            "frame_length": t.uint16_t(80),
            "payload_length": t.uint16_t(73),
            "device_state": deconz_api.DeviceState(
                network_state=deconz_api.NetworkState2.CONNECTED,
                device_state=(
                    deconz_api.DeviceStateFlags.APSDE_DATA_REQUEST_FREE_SLOTS_AVAILABLE
                ),
            ),
            "dst_addr": dst_addr,
            "dst_ep": t.uint8_t(1),
            "src_addr": src_addr,
            "src_ep": t.uint8_t(1),
            "profile_id": t.uint16_t(260),
            "cluster_id": t.uint16_t(0x0000),
            "asdu": t.LongOctetString(
                b"\x18\x1b\x01\x04\x00\x00B\x0eIKEA of Sweden"
                b"\x05\x00\x00B\x17TRADFRI wireless dimmer"
            ),
            "reserved1": t.uint8_t(0),
            "reserved2": t.uint8_t(175),
            "lqi": t.uint8_t(255),
            "reserved3": t.uint8_t(142),
            "reserved4": t.uint8_t(98),
            "reserved5": t.uint8_t(0),
            "reserved6": t.uint8_t(0),
            "rssi": t.int8s(-49),
        },
    )

    # Unsolicited device_state_changed
    api.data_received(bytes.fromhex("0e2f000700ae00"))

    await asyncio.sleep(0.1)

    api._app.packet_received.assert_called_once_with(
        zigpy_t.ZigbeePacket(
            src=zigpy_t.AddrModeAddress(addr_mode=zigpy_t.AddrMode.NWK, address=0xE695),
            src_ep=1,
            dst=zigpy_t.AddrModeAddress(addr_mode=zigpy_t.AddrMode.NWK, address=0x0000),
            dst_ep=1,
            source_route=None,
            extended_timeout=False,
            tsn=None,
            profile_id=260,
            cluster_id=0x0000,
            data=zigpy_t.SerializableBytes(
                b"\x18\x1b\x01\x04\x00\x00B\x0eIKEA of Sweden"
                b"\x05\x00\x00B\x17TRADFRI wireless dimmer"
            ),
            tx_options=zigpy_t.TransmitOptions.NONE,
            radius=0,
            non_member_radius=0,
            lqi=255,
            rssi=-49,
        )
    )


async def test_read_parameter(api, mock_command_rsp):
    await api.connect()

    mock_command_rsp(
        command_id=deconz_api.CommandId.read_parameter,
        params={
            "parameter_id": deconz_api.NetworkParameter.nwk_update_id,
            "parameter": t.Bytes(b""),
        },
        rsp={
            "status": deconz_api.Status.SUCCESS,
            "frame_length": t.uint16_t(9),
            "payload_length": t.uint16_t(2),
            "parameter_id": deconz_api.NetworkParameter.nwk_update_id,
            "parameter": t.Bytes(b"\x00"),
        },
    )

    mock_command_rsp(
        command_id=deconz_api.CommandId.read_parameter,
        params={
            "parameter_id": deconz_api.NetworkParameter.network_key,
            "parameter": t.Bytes(b"\x00"),
        },
        rsp={
            "status": deconz_api.Status.SUCCESS,
            "frame_length": t.uint16_t(25),
            "payload_length": t.uint16_t(18),
            "parameter_id": deconz_api.NetworkParameter.network_key,
            "parameter": t.Bytes(b"\x00M\x07p\xb6\x0b|\x90\xad\\\x07\x8a8\xa9M\xf6["),
        },
    )

    rsp = await api.read_parameter(deconz_api.NetworkParameter.nwk_update_id)
    assert rsp == 0x00

    rsp = await api.read_parameter(deconz_api.NetworkParameter.network_key, 0)
    assert rsp == deconz_api.IndexedKey(
        index=0,
        key=deconz_api.KeyData.convert(
            "4d:07:70:b6:0b:7c:90:ad:5c:07:8a:38:a9:4d:f6:5b"
        ),
    )


async def test_write_parameter(api, mock_command_rsp):
    await api.connect()

    mock_command_rsp(
        command_id=deconz_api.CommandId.write_parameter,
        params={
            "parameter_id": deconz_api.NetworkParameter.watchdog_ttl,
            "parameter": t.uint32_t(600).serialize(),
        },
        rsp={
            "status": deconz_api.Status.SUCCESS,
            "frame_length": t.uint16_t(8),
            "payload_length": t.uint16_t(1),
            "parameter_id": deconz_api.NetworkParameter.watchdog_ttl,
        },
    )

    await api.write_parameter(deconz_api.NetworkParameter.watchdog_ttl, 600)


async def test_write_parameter_failure(api, mock_command_rsp):
    await api.connect()

    mock_command_rsp(
        command_id=deconz_api.CommandId.write_parameter,
        params={
            "parameter_id": deconz_api.NetworkParameter.watchdog_ttl,
            "parameter": t.uint32_t(600).serialize(),
        },
        rsp={
            "status": deconz_api.Status.INVALID_VALUE,
            "frame_length": t.uint16_t(8),
            "payload_length": t.uint16_t(1),
            "parameter_id": deconz_api.NetworkParameter.watchdog_ttl,
        },
    )

    with pytest.raises(deconz_api.CommandError):
        await api.write_parameter(deconz_api.NetworkParameter.watchdog_ttl, 600)


@pytest.mark.parametrize(
    "protocol_ver, firmware_ver",
    [
        (0x010A, 0x123405DD),
        (0x010B, 0x123405DD),
        (0x010A, 0x123407DD),
        (0x010B, 0x123407DD),
    ],
)
async def test_version(protocol_ver, firmware_ver, api, mock_command_rsp):
    await api.connect()

    mock_command_rsp(
        command_id=deconz_api.CommandId.read_parameter,
        params={
            "parameter_id": deconz_api.NetworkParameter.protocol_version,
            "parameter": t.Bytes(b""),
        },
        rsp={
            "status": deconz_api.Status.SUCCESS,
            "frame_length": t.uint16_t(10),
            "payload_length": t.uint16_t(3),
            "parameter_id": deconz_api.NetworkParameter.protocol_version,
            "parameter": t.Bytes(t.uint16_t(protocol_ver).serialize()),
        },
        replace=True,
    )

    mock_command_rsp(
        command_id=deconz_api.CommandId.version,
        params={"reserved": t.uint8_t(0)},
        rsp={
            "status": deconz_api.Status.SUCCESS,
            "frame_length": t.uint16_t(9),
            "version": deconz_api.FirmwareVersion(firmware_ver),
        },
        replace=True,
    )

    r = await api.version()
    assert r == firmware_ver

    assert api.protocol_version == protocol_ver
    assert api.firmware_version == firmware_ver


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


@pytest.mark.parametrize("relays", (None, [], [0x1234, 0x5678]))
async def test_aps_data_request_relays(relays, api, mock_command_rsp):
    await api.connect()

    mock_command_rsp(
        command_id=deconz_api.CommandId.aps_data_request,
        params={},
        rsp={
            "status": deconz_api.Status.SUCCESS,
            "frame_length": t.uint16_t(9),
            "payload_length": t.uint16_t(2),
            "device_state": deconz_api.DeviceState(
                network_state=deconz_api.NetworkState2.CONNECTED,
                device_state=(
                    deconz_api.DeviceStateFlags.APSDE_DATA_REQUEST_FREE_SLOTS_AVAILABLE
                ),
            ),
            "request_id": t.uint8_t(0x00),
        },
    )

    await api.aps_data_request(
        req_id=0x00,
        dst_addr_ep=t.DeconzAddressEndpoint.deserialize(b"\x02\xaa\x55\x01")[0],
        profile=0x0104,
        cluster=0x0007,
        src_ep=0x01,
        aps_payload=b"aps payload",
        relays=relays,
    )

    with pytest.raises(ValueError) as exc:
        await api.aps_data_request(
            req_id=0x00,
            dst_addr_ep=t.DeconzAddressEndpoint.deserialize(b"\x02\xaa\x55\x01")[0],
            profile=0x0104,
            cluster=0x0007,
            src_ep=None,  # This is not possible
            aps_payload=b"aps payload",
        )

        assert "has non-trailing optional argument" in str(exc.value)


async def test_aps_data_request_retries_failure(api, mock_command_rsp):
    await api.connect()

    mock_rsp = mock_command_rsp(
        command_id=deconz_api.CommandId.aps_data_request,
        params={},
        rsp={
            "status": deconz_api.Status.FAILURE,
            "frame_length": t.uint16_t(9),
            "payload_length": t.uint16_t(2),
            "device_state": deconz_api.DeviceState(
                network_state=deconz_api.NetworkState2.CONNECTED,
                device_state=(
                    deconz_api.DeviceStateFlags.APSDE_DATA_REQUEST_FREE_SLOTS_AVAILABLE
                ),
            ),
            "request_id": t.uint8_t(0x00),
        },
    )

    with pytest.raises(deconz_api.CommandError):
        await api.aps_data_request(
            req_id=0x00,
            dst_addr_ep=t.DeconzAddressEndpoint.deserialize(b"\x02\xaa\x55\x01")[0],
            profile=0x0104,
            cluster=0x0007,
            src_ep=1,
            aps_payload=b"aps payload",
        )

    assert len(mock_rsp.mock_calls) == 1


async def test_aps_data_request_locking(caplog, api, mock_command_rsp):
    await api.connect()

    # No free slots
    send_network_state(api, device_state=deconz_api.DeviceStateFlags.APSDE_DATA_CONFIRM)

    await asyncio.sleep(0.1)

    mock_rsp = mock_command_rsp(
        command_id=deconz_api.CommandId.aps_data_request,
        params={},
        rsp={
            "status": deconz_api.Status.SUCCESS,
            "frame_length": t.uint16_t(9),
            "payload_length": t.uint16_t(2),
            "device_state": deconz_api.DeviceState(
                network_state=deconz_api.NetworkState2.CONNECTED,
                device_state=(
                    deconz_api.DeviceStateFlags.APSDE_DATA_REQUEST_FREE_SLOTS_AVAILABLE
                ),
            ),
            "request_id": t.uint8_t(0x00),
        },
    )

    with caplog.at_level(logging.DEBUG):
        send = asyncio.create_task(
            api.aps_data_request(
                req_id=0x00,
                dst_addr_ep=t.DeconzAddressEndpoint.deserialize(b"\x02\xaa\x55\x01")[0],
                profile=0x0104,
                cluster=0x0007,
                src_ep=1,
                aps_payload=b"aps payload",
            )
        )

        await asyncio.sleep(0.1)

    assert "Waiting for free slots to become available" in caplog.text

    assert len(mock_rsp.mock_calls) == 0

    send_network_state(
        api,
        device_state=deconz_api.DeviceStateFlags.APSDE_DATA_REQUEST_FREE_SLOTS_AVAILABLE,
    )

    await send

    assert len(mock_rsp.mock_calls) == 1


async def test_connection_lost(api):
    await api.connect()

    app = api._app = MagicMock()

    err = RuntimeError()
    api.connection_lost(err)

    app.connection_lost.assert_called_once_with(err)


async def test_unknown_command(api, caplog):
    await api.connect()

    assert 0xFF not in deconz_api.COMMAND_SCHEMAS

    with caplog.at_level(logging.WARNING):
        api.data_received(b"\xFF\xAA\xBB")

    assert (
        "Unknown command received: Command(command_id=<CommandId.undefined_0xff: 255>,"
        " seq=170, payload=b'\\xbb')"
    ) in caplog.text


async def test_bad_command_parsing(api, caplog):
    await api.connect()

    assert 0xFF not in deconz_api.COMMAND_SCHEMAS

    with caplog.at_level(logging.DEBUG):
        api.data_received(
            bytes.fromhex(
                "172c002f0028002e02000000020000000000"
                "028011000300000010400f3511472b004000"
                # "2b000000af45838600001b"  # truncated
            )
        )

    assert (
        "Failed to parse command Command(command_id="
        "<CommandId.aps_data_indication: 23>"
    ) in caplog.text

    caplog.clear()

    with caplog.at_level(logging.DEBUG):
        api.data_received(bytes.fromhex("0d03000d0000077826") + b"TEST")

    assert (
        "Unparsed data remains after frame" in caplog.text and "b'TEST'" in caplog.text
    )


async def test_bad_response_status(api, mock_command_rsp):
    await api.connect()

    mock_command_rsp(
        command_id=deconz_api.CommandId.write_parameter,
        params={
            "parameter_id": deconz_api.NetworkParameter.nwk_update_id,
            "parameter": t.uint8_t(123).serialize(),
        },
        rsp={
            "status": deconz_api.Status.FAILURE,
            "frame_length": t.uint16_t(8),
            "payload_length": t.uint16_t(1),
            "parameter_id": deconz_api.NetworkParameter.nwk_update_id,
        },
    )

    with pytest.raises(deconz_api.CommandError) as exc:
        await api.write_parameter(deconz_api.NetworkParameter.nwk_update_id, 123)

    assert isinstance(exc.value, deconz_api.CommandError)
    assert exc.value.status == deconz_api.Status.FAILURE


async def test_data_poller(api, mock_command_rsp):
    await api.connect()

    dst_addr_ep = t.DeconzAddressEndpoint()
    dst_addr_ep.address_mode = t.AddressMode.NWK
    dst_addr_ep.address = t.NWK(0x0000)
    dst_addr_ep.endpoint = t.uint8_t(0)

    src_addr = t.DeconzAddress()
    src_addr.address_mode = t.AddressMode.NWK
    src_addr.address = t.NWK(0xE695)

    dst_addr = t.DeconzAddress()
    dst_addr.address_mode = t.AddressMode.NWK
    dst_addr.address = t.NWK(0x0000)

    mock_command_rsp(
        command_id=deconz_api.CommandId.aps_data_confirm,
        params={},
        rsp={
            "status": deconz_api.Status.SUCCESS,
            "frame_length": t.uint16_t(19),
            "payload_length": t.uint16_t(12),
            "device_state": deconz_api.DeviceState(
                network_state=deconz_api.NetworkState2.CONNECTED,
                device_state=(
                    # Include a data indication flag to trigger a poll
                    deconz_api.DeviceStateFlags.APSDE_DATA_REQUEST_FREE_SLOTS_AVAILABLE
                    | deconz_api.DeviceStateFlags.APSDE_DATA_INDICATION
                ),
            ),
            "request_id": t.uint8_t(16),
            "dst_addr": dst_addr_ep,
            "src_ep": t.uint8_t(0),
            "confirm_status": deconz_api.TXStatus.SUCCESS,
            "reserved1": t.uint8_t(0),
            "reserved2": t.uint8_t(0),
            "reserved3": t.uint8_t(0),
            "reserved4": t.uint8_t(0),
        },
    )

    mock_command_rsp(
        command_id=deconz_api.CommandId.aps_data_indication,
        params={},
        rsp={
            "status": deconz_api.Status.SUCCESS,
            "frame_length": t.uint16_t(80),
            "payload_length": t.uint16_t(73),
            "device_state": deconz_api.DeviceState(
                network_state=deconz_api.NetworkState2.CONNECTED,
                device_state=(
                    deconz_api.DeviceStateFlags.APSDE_DATA_REQUEST_FREE_SLOTS_AVAILABLE
                ),
            ),
            "dst_addr": dst_addr,
            "dst_ep": t.uint8_t(1),
            "src_addr": src_addr,
            "src_ep": t.uint8_t(1),
            "profile_id": t.uint16_t(260),
            "cluster_id": t.uint16_t(0x0000),
            "asdu": t.LongOctetString(
                b"\x18\x1b\x01\x04\x00\x00B\x0eIKEA of Sweden"
                b"\x05\x00\x00B\x17TRADFRI wireless dimmer"
            ),
            "reserved1": t.uint8_t(0),
            "reserved2": t.uint8_t(175),
            "lqi": t.uint8_t(255),
            "reserved3": t.uint8_t(142),
            "reserved4": t.uint8_t(98),
            "reserved5": t.uint8_t(0),
            "reserved6": t.uint8_t(0),
            "rssi": t.int8s(-49),
        },
    )

    # Take us offline for a moment
    send_network_state(api, network_state=deconz_api.NetworkState2.OFFLINE)
    await asyncio.sleep(0.1)

    # Bring us back online with just a data confirmation to kick things off
    send_network_state(
        api,
        network_state=deconz_api.NetworkState2.CONNECTED,
        device_state=deconz_api.DeviceStateFlags.APSDE_DATA_CONFIRM,
    )

    await asyncio.sleep(0.1)

    # Both callbacks have been called
    api._app.handle_tx_confirm.assert_called_once_with(16, deconz_api.TXStatus.SUCCESS)
    assert len(api._app.packet_received.mock_calls) == 1

    # The task is cancelled on close
    task = api._data_poller_task
    await api.disconnect()
    assert api._data_poller_task is None
    assert task.done()


async def test_get_device_state(api, mock_command_rsp):
    await api.connect()

    device_state = deconz_api.DeviceState(
        network_state=deconz_api.NetworkState2.CONNECTED,
        device_state=(
            deconz_api.DeviceStateFlags.APSDE_DATA_REQUEST_FREE_SLOTS_AVAILABLE
        ),
    )

    mock_command_rsp(
        command_id=deconz_api.CommandId.device_state,
        params={},
        rsp={
            "status": deconz_api.Status.SUCCESS,
            "frame_length": t.uint16_t(8),
            "device_state": device_state,
            "reserved1": t.uint8_t(0),
            "reserved2": t.uint8_t(0),
        },
    )

    assert (await api.get_device_state()) == device_state


async def test_change_network_state(api, mock_command_rsp):
    api._command = AsyncMock()
    await api.change_network_state(new_state=deconz_api.NetworkState.OFFLINE)

    assert api._command.mock_calls == [
        call(
            deconz_api.CommandId.change_network_state,
            network_state=deconz_api.NetworkState.OFFLINE,
        )
    ]


async def test_add_neighbour(api, mock_command_rsp):
    api._command = AsyncMock()
    await api.add_neighbour(
        nwk=0x1234,
        ieee=t.EUI64.convert("aa:bb:cc:dd:11:22:33:44"),
        mac_capability_flags=0x12,
    )

    assert api._command.mock_calls == [
        call(
            deconz_api.CommandId.update_neighbor,
            action=deconz_api.UpdateNeighborAction.ADD,
            nwk=0x1234,
            ieee=t.EUI64.convert("aa:bb:cc:dd:11:22:33:44"),
            mac_capability_flags=0x12,
        )
    ]


async def test_add_neighbour_conbee3_success(api):
    api._command = AsyncMock(wraps=api._command)
    api._uart = AsyncMock()

    # Simulate a good but invalid response from the Conbee III
    asyncio.get_running_loop().call_later(
        0.001,
        lambda: api.data_received(
            b"\x1d" + bytes([api._seq - 1]) + b"\x00\x06\x00\x01"
        ),
    )

    await api.add_neighbour(
        nwk=0x1234,
        ieee=t.EUI64.convert("aa:bb:cc:dd:11:22:33:44"),
        mac_capability_flags=0x12,
    )

    assert api._command.mock_calls == [
        call(
            deconz_api.CommandId.update_neighbor,
            action=deconz_api.UpdateNeighborAction.ADD,
            nwk=0x1234,
            ieee=t.EUI64.convert("aa:bb:cc:dd:11:22:33:44"),
            mac_capability_flags=0x12,
        )
    ]


async def test_add_neighbour_conbee3_failure(api):
    api._command = AsyncMock(wraps=api._command)
    api._uart = AsyncMock()

    # Simulate a bad response from the Conbee III
    asyncio.get_running_loop().call_later(
        0.001,
        lambda: api.data_received(
            b"\x1d" + bytes([api._seq - 1]) + b"\x01\x06\x00\x01"
        ),
    )

    with pytest.raises(deconz_api.CommandError):
        await api.add_neighbour(
            nwk=0x1234,
            ieee=t.EUI64.convert("aa:bb:cc:dd:11:22:33:44"),
            mac_capability_flags=0x12,
        )

    assert api._command.mock_calls == [
        call(
            deconz_api.CommandId.update_neighbor,
            action=deconz_api.UpdateNeighborAction.ADD,
            nwk=0x1234,
            ieee=t.EUI64.convert("aa:bb:cc:dd:11:22:33:44"),
            mac_capability_flags=0x12,
        )
    ]


async def test_cb3_device_state_callback_bug(api, mock_command_rsp):
    mock_command_rsp(
        command_id=deconz_api.CommandId.version,
        params={"reserved": t.uint8_t(0)},
        rsp={
            "status": deconz_api.Status.SUCCESS,
            "frame_length": t.uint16_t(9),
            "version": deconz_api.FirmwareVersion(0x26450900),
        },
        replace=True,
    )

    await api.connect()

    device_state = deconz_api.DeviceState(
        network_state=deconz_api.NetworkState2.CONNECTED,
        device_state=deconz_api.DeviceStateFlags.APSDE_DATA_CONFIRM,
    )

    assert api._device_state != device_state

    _, rx_schema = deconz_api.COMMAND_SCHEMAS[deconz_api.CommandId.device_state]
    api.data_received(
        deconz_api.Command(
            command_id=deconz_api.CommandId.device_state,
            seq=api._seq,
            payload=t.serialize_dict(
                {
                    "status": deconz_api.Status.SUCCESS,
                    "frame_length": t.uint16_t(8),
                    "device_state": device_state,
                    "reserved1": t.uint8_t(0),
                    "reserved2": t.uint8_t(0),
                },
                rx_schema,
            ),
        ).serialize()
    )

    await asyncio.sleep(0.01)

    assert api._device_state == device_state


async def test_firmware_responding_with_wrong_type_with_correct_seq(
    api, mock_command_rsp, caplog
):
    await api.connect()

    mock_command_rsp(
        command_id=deconz_api.CommandId.aps_data_confirm,
        params={},
        # Completely different response
        rsp_command=deconz_api.CommandId.version,
        rsp={
            "status": deconz_api.Status.SUCCESS,
            "frame_length": t.uint16_t(9),
            "version": deconz_api.FirmwareVersion(0x26450900),
        },
    )

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(asyncio.TimeoutError):
            # We wait beyond 500ms to make sure it triggers
            async with asyncio_timeout(0.6):
                await api.send_command(deconz_api.CommandId.aps_data_confirm)

    assert (
        "Firmware responded incorrectly (Response is mismatched! Sent"
        " <CommandId.aps_data_confirm: 4>, received <CommandId.version: 13>), retrying"
    ) in caplog.text


async def test_firmware_responding_with_wrong_type_with_correct_seq_eventual_response(
    api, mock_command_rsp, caplog
):
    await api.connect()

    mock_command_rsp(
        command_id=deconz_api.CommandId.aps_data_confirm,
        params={},
        # Completely different response
        rsp_command=deconz_api.CommandId.version,
        rsp={
            "status": deconz_api.Status.SUCCESS,
            "frame_length": t.uint16_t(9),
            "version": deconz_api.FirmwareVersion(0x26450900),
        },
    )

    with caplog.at_level(logging.DEBUG):
        _, rx_schema = deconz_api.COMMAND_SCHEMAS[deconz_api.CommandId.aps_data_confirm]

        asyncio.get_running_loop().call_later(
            0.1,
            api.data_received,
            deconz_api.Command(
                command_id=deconz_api.CommandId.aps_data_confirm,
                seq=api._seq,
                payload=t.serialize_dict(
                    {
                        "status": deconz_api.Status.SUCCESS,
                        "frame_length": t.uint16_t(19),
                        "payload_length": t.uint16_t(12),
                        "device_state": deconz_api.DeviceState(
                            network_state=deconz_api.NetworkState2.CONNECTED,
                            device_state=(
                                deconz_api.DeviceStateFlags.APSDE_DATA_REQUEST_FREE_SLOTS_AVAILABLE
                                | deconz_api.DeviceStateFlags.APSDE_DATA_INDICATION
                            ),
                        ),
                        "request_id": t.uint8_t(16),
                        "dst_addr": t.DeconzAddressEndpoint.deserialize(
                            b"\x02\xaa\x55\x01"
                        )[0],
                        "src_ep": t.uint8_t(0),
                        "confirm_status": deconz_api.TXStatus.SUCCESS,
                        "reserved1": t.uint8_t(0),
                        "reserved2": t.uint8_t(0),
                        "reserved3": t.uint8_t(0),
                        "reserved4": t.uint8_t(0),
                    },
                    rx_schema,
                ),
            ).serialize(),
        )

        async with asyncio_timeout(0.2):
            rsp = await api.send_command(deconz_api.CommandId.aps_data_confirm)

    assert rsp["request_id"] == 16

    assert (
        "Firmware responded incorrectly (Response is mismatched! Sent"
        " <CommandId.aps_data_confirm: 4>, received <CommandId.version: 13>), retrying"
    ) not in caplog.text


def test_get_command_priority(api):
    assert (
        api._get_command_priority(
            deconz_api.Command(command_id=deconz_api.CommandId.write_parameter)
        )
        > api._get_command_priority(
            deconz_api.Command(command_id=deconz_api.CommandId.update_neighbor)
        )
        > api._get_command_priority(
            deconz_api.Command(command_id=deconz_api.CommandId.aps_data_request)
        )
    )
