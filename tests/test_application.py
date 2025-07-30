"""Test application module."""

import asyncio
import logging
from unittest import mock

import pytest
import zigpy.application
import zigpy.config
import zigpy.device
from zigpy.types import EUI64, Channels, KeyData
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
    },
}


@pytest.fixture
def device_path():
    return "/dev/null"


@pytest.fixture
def api():
    """Return API fixture."""
    api = MagicMock(spec_set=zigpy_deconz.api.Deconz(None, None))
    api.get_device_state = AsyncMock(
        return_value=deconz_api.DeviceState(deconz_api.NetworkState.CONNECTED)
    )
    api.write_parameter = AsyncMock()
    api.firmware_version = deconz_api.FirmwareVersion(0x26580700)

    # So the protocol version is effectively infinite
    api._protocol_version.__ge__.return_value = True
    api._protocol_version.__lt__.return_value = False

    api.protocol_version.__ge__.return_value = True
    api.protocol_version.__lt__.return_value = False

    return api


@pytest.fixture
def app(device_path, api):
    config = {
        **ZIGPY_NWK_CONFIG,
        zigpy.config.CONF_DEVICE: {zigpy.config.CONF_DEVICE_PATH: device_path},
    }

    app = application.ControllerApplication(config)

    api.change_network_state = AsyncMock()

    device_state = MagicMock()
    device_state.network_state.__eq__.return_value = True
    api.get_device_state = AsyncMock(return_value=device_state)

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
    addr.address_mode = t.AddressMode.IEEE
    addr.address = ieee
    return addr


@pytest.fixture
def addr_nwk(nwk):
    addr = t.DeconzAddress()
    addr.address_mode = t.AddressMode.NWK
    addr.address = nwk
    return addr


@pytest.fixture
def addr_nwk_and_ieee(nwk, ieee):
    addr = t.DeconzAddress()
    addr.address_mode = t.AddressMode.NWK_AND_IEEE
    addr.address = nwk
    addr.ieee = ieee
    return addr


@patch("zigpy_deconz.zigbee.application.CHANGE_NETWORK_POLL_TIME", 0.001)
@pytest.mark.parametrize(
    "proto_ver, target_state, returned_state",
    [
        (0x0107, deconz_api.NetworkState.CONNECTED, deconz_api.NetworkState.CONNECTED),
        (0x0106, deconz_api.NetworkState.CONNECTED, deconz_api.NetworkState.CONNECTED),
        (0x0107, deconz_api.NetworkState.OFFLINE, deconz_api.NetworkState.CONNECTED),
        (0x0107, deconz_api.NetworkState.CONNECTED, deconz_api.NetworkState.OFFLINE),
    ],
)
async def test_start_network(app, proto_ver, target_state, returned_state):
    app.load_network_info = AsyncMock()
    app.restore_neighbours = AsyncMock()
    app.add_endpoint = AsyncMock()

    app._api.get_device_state = AsyncMock(
        return_value=deconz_api.DeviceState(
            device_state=deconz_api.DeviceStateFlags.APSDE_DATA_REQUEST_FREE_SLOTS_AVAILABLE,
            network_state=returned_state,
        )
    )

    app._api._protocol_version = proto_ver
    app._api.protocol_version = proto_ver

    if (
        target_state == deconz_api.NetworkState.CONNECTED
        and returned_state != deconz_api.NetworkState.CONNECTED
    ):
        with pytest.raises(zigpy.exceptions.FormationFailure):
            await app.start_network()

        return

    with patch.object(application.DeconzDevice, "initialize", AsyncMock()):
        await app.start_network()
        assert app.load_network_info.await_count == 1
        assert app._change_network_state.await_count == 1

        assert (
            app._change_network_state.await_args_list[0][0][0]
            == deconz_api.NetworkState.CONNECTED
        )

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


async def test_connect(app):
    def new_api(*args):
        api = MagicMock()
        api.connect = AsyncMock()

        return api

    with patch.object(application, "Deconz", new=new_api):
        app._api = None
        await app.connect()
        assert app._api is not None
        assert app._api.connect.await_count == 1


async def test_connect_failure(app):
    with patch.object(application, "Deconz") as api_mock:
        api = api_mock.return_value = MagicMock()
        api.connect = AsyncMock(side_effect=RuntimeError("Broken"))
        api.disconnect = AsyncMock()

        app._api = None

        with pytest.raises(RuntimeError):
            await app.connect()

        assert app._api is None
        api.connect.assert_called_once()
        api.disconnect.assert_called_once()


async def test_disconnect(app):
    api_disconnect = app._api.disconnect = AsyncMock()

    await app.disconnect()

    assert app._api is None
    assert api_disconnect.call_count == 1


async def test_disconnect_no_api(app):
    app._api = None
    await app.disconnect()


async def test_disconnect_close_error(app):
    app._api.write_parameter = MagicMock(
        side_effect=zigpy_deconz.exception.CommandError("Error", status=1, command=None)
    )
    await app.disconnect()


async def test_permit_with_link_key(app):
    app._api.write_parameter = AsyncMock()
    app.permit = AsyncMock()

    await app.permit_with_link_key(
        node=t.EUI64.convert("00:11:22:33:44:55:66:77"),
        link_key=KeyData.convert("aa:bb:cc:dd:aa:bb:cc:dd:aa:bb:cc:dd:aa:bb:cc:dd"),
    )

    assert app._api.write_parameter.mock_calls == [
        mock.call(
            deconz_api.NetworkParameter.link_key,
            deconz_api.LinkKey(
                ieee=t.EUI64.convert("00:11:22:33:44:55:66:77"),
                key=KeyData.convert("aa:bb:cc:dd:aa:bb:cc:dd:aa:bb:cc:dd:aa:bb:cc:dd"),
            ),
        )
    ]

    assert app.permit.mock_calls == [mock.call(mock.ANY)]


async def test_deconz_dev_add_to_group(app, nwk, device_path):
    group = MagicMock()
    app._groups = MagicMock()
    app._groups.add_group.return_value = group

    deconz = application.DeconzDevice("Conbee II", app, sentinel.ieee, nwk)
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
    deconz = application.DeconzDevice("Conbee II", app, sentinel.ieee, nwk)
    deconz.endpoints = {
        0: sentinel.zdo,
        1: sentinel.ep1,
        2: sentinel.ep2,
    }

    await deconz.remove_from_group(sentinel.grp_id)
    assert group.remove_member.call_count == 2


def test_deconz_props(app, nwk, device_path):
    deconz = application.DeconzDevice("Conbee II", app, sentinel.ieee, nwk)
    assert deconz.manufacturer is not None
    assert deconz.model is not None


async def test_deconz_new(app, nwk, device_path, monkeypatch):
    mock_init = AsyncMock()
    monkeypatch.setattr(zigpy.device.Device, "_initialize", mock_init)

    deconz = await application.DeconzDevice.new(app, sentinel.ieee, nwk, "Conbee II")
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
    deconz = await application.DeconzDevice.new(app, sentinel.ieee, nwk, "Conbee II")
    assert isinstance(deconz, application.DeconzDevice)
    assert mock_init.call_count == 0


def test_tx_confirm_success(app):
    tsn = 123
    req = app._pending_requests[tsn] = MagicMock()
    app.handle_tx_confirm(tsn, sentinel.status)
    assert req.set_result.call_count == 1
    assert req.set_result.call_args[0][0] is sentinel.status


def test_tx_confirm_dup(app, caplog):
    caplog.set_level(logging.DEBUG)
    tsn = 123
    req = app._pending_requests[tsn] = MagicMock()
    req.set_result.side_effect = asyncio.InvalidStateError
    app.handle_tx_confirm(tsn, sentinel.status)
    assert req.set_result.call_count == 1
    assert req.set_result.call_args[0][0] is sentinel.status
    assert any(r.levelname == "DEBUG" for r in caplog.records)
    assert "probably duplicate response" in caplog.text


def test_tx_confirm_unexpcted(app, caplog):
    app.handle_tx_confirm(123, 0x00)
    assert any(r.levelname == "WARNING" for r in caplog.records)
    assert "Unexpected transmit confirm for request id" in caplog.text


async def test_reset_watchdog(app):
    """Test watchdog."""
    app._api.protocol_version = application.PROTO_VER_WATCHDOG
    app._api.get_device_state = AsyncMock()
    app._api.write_parameter = AsyncMock()

    await app._watchdog_feed()
    assert len(app._api.get_device_state.mock_calls) == 0
    assert len(app._api.write_parameter.mock_calls) == 1

    app._api.protocol_version = application.PROTO_VER_WATCHDOG - 1
    app._api.get_device_state.reset_mock()
    app._api.write_parameter.reset_mock()

    await app._watchdog_feed()
    assert len(app._api.get_device_state.mock_calls) == 1
    assert len(app._api.write_parameter.mock_calls) == 0


async def test_force_remove(app):
    """Test forcibly removing a device."""
    await app.force_remove(sentinel.device)


async def test_restore_neighbours(app, caplog):
    """Test neighbour restoration."""

    # FFD, Rx on when idle
    device_1 = app.add_device(nwk=0x0001, ieee=EUI64.convert("00:00:00:00:00:00:00:01"))
    device_1.node_desc = zdo_t.NodeDescriptor(1, 64, 142, 0xBEEF, 82, 82, 0, 82, 0)

    # RFD, Rx on when idle
    device_2 = app.add_device(nwk=0x0002, ieee=EUI64.convert("00:00:00:00:00:00:00:02"))
    device_2.node_desc = zdo_t.NodeDescriptor(1, 64, 142, 0xBEEF, 82, 82, 0, 82, 0)

    device_3 = app.add_device(nwk=0x0003, ieee=EUI64.convert("00:00:00:00:00:00:00:03"))
    device_3.node_desc = None

    # RFD, Rx off when idle
    device_5 = app.add_device(nwk=0x0005, ieee=EUI64.convert("00:00:00:00:00:00:00:05"))
    device_5.node_desc = zdo_t.NodeDescriptor(2, 64, 128, 0xBEEF, 82, 82, 0, 82, 0)

    # RFD, Rx off when idle (duplicate)
    device_6 = app.add_device(nwk=0x0005, ieee=EUI64.convert("00:00:00:00:00:00:00:06"))
    device_6.node_desc = zdo_t.NodeDescriptor(2, 64, 128, 0xBEEF, 82, 82, 0, 82, 0)

    coord = MagicMock()
    coord.ieee = EUI64.convert("aa:aa:aa:aa:aa:aa:aa:aa")

    app.devices[coord.ieee] = coord
    app.state.node_info.ieee = coord.ieee

    app.topology.neighbors[coord.ieee] = [
        zdo_t.Neighbor(ieee=device_1.ieee),
        zdo_t.Neighbor(ieee=device_2.ieee),
        zdo_t.Neighbor(ieee=device_3.ieee),
        zdo_t.Neighbor(ieee=EUI64.convert("00:00:00:00:00:00:00:04")),
        zdo_t.Neighbor(ieee=device_5.ieee),
        zdo_t.Neighbor(ieee=device_6.ieee),
    ]

    max_neighbors = 1

    def mock_add_neighbour(nwk, ieee, mac_capability_flags):
        nonlocal max_neighbors
        max_neighbors -= 1

        if max_neighbors < 0:
            raise zigpy_deconz.exception.CommandError(
                "Failure",
                status=deconz_api.Status.FAILURE,
                command=None,
            )

    p = patch.object(app, "_api", spec_set=zigpy_deconz.api.Deconz(None, None))

    with p as api_mock:
        err = zigpy_deconz.exception.CommandError(
            "Failure", status=deconz_api.Status.FAILURE, command=None
        )
        api_mock.add_neighbour = AsyncMock(side_effect=[None, err, err, err])

        with caplog.at_level(logging.DEBUG):
            await app.restore_neighbours()

        assert caplog.text.count("Failed to add device to neighbor table") == 1

    assert api_mock.add_neighbour.call_count == 2
    assert api_mock.add_neighbour.await_count == 2


@patch("zigpy_deconz.zigbee.application.DELAY_NEIGHBOUR_SCAN_S", 0)
async def test_delayed_scan():
    """Delayed scan."""

    coord = MagicMock()
    config = {
        zigpy.config.CONF_DEVICE: {zigpy.config.CONF_DEVICE_PATH: "usb0"},
        zigpy.config.CONF_DATABASE: "tmp",
    }

    app = application.ControllerApplication(config)
    with patch.object(app, "get_device", return_value=coord):
        with patch.object(app, "topology", AsyncMock()):
            await app._delayed_neighbour_scan()
            app.topology.scan.assert_called_once_with(devices=[coord])


@patch("zigpy_deconz.zigbee.application.CHANGE_NETWORK_POLL_TIME", 0.001)
async def test_change_network_state(app):
    app._api.get_device_state = AsyncMock(
        side_effect=[
            deconz_api.DeviceState(deconz_api.NetworkState.OFFLINE),
            deconz_api.DeviceState(deconz_api.NetworkState.JOINING),
            deconz_api.DeviceState(deconz_api.NetworkState.CONNECTED),
        ]
    )

    app._api._protocol_version = application.PROTO_VER_WATCHDOG
    app._api.protocol_version = application.PROTO_VER_WATCHDOG

    await app._change_network_state(deconz_api.NetworkState.CONNECTED, timeout=0.01)


ENDPOINT = zdo_t.SimpleDescriptor(
    endpoint=None,
    profile=1,
    device_type=2,
    device_version=3,
    input_clusters=[4],
    output_clusters=[5],
)


@pytest.mark.parametrize(
    "descriptor, slots, target_slot",
    [
        (ENDPOINT.replace(endpoint=1), {0: ENDPOINT.replace(endpoint=2)}, 0),
        # Prefer the endpoint with the same ID
        (
            ENDPOINT.replace(endpoint=1),
            {
                0: ENDPOINT.replace(endpoint=2, profile=1234),
                1: ENDPOINT.replace(endpoint=1, profile=1234),
            },
            1,
        ),
    ],
)
async def test_add_endpoint(app, descriptor, slots, target_slot):
    async def read_param(param_id, index):
        assert param_id == deconz_api.NetworkParameter.configure_endpoint

        if index not in slots:
            raise zigpy_deconz.exception.CommandError(
                "Unsupported",
                status=deconz_api.Status.UNSUPPORTED,
                command=None,
            )
        else:
            return deconz_api.IndexedEndpoint(index=index, descriptor=slots[index])

    app._api.read_parameter = AsyncMock(side_effect=read_param)
    app._api.write_parameter = AsyncMock()

    await app.add_endpoint(descriptor)
    app._api.write_parameter.assert_called_once_with(
        deconz_api.NetworkParameter.configure_endpoint,
        deconz_api.IndexedEndpoint(index=target_slot, descriptor=descriptor),
    )


async def test_add_endpoint_no_free_space(app):
    async def read_param(param_id, index):
        assert param_id == deconz_api.NetworkParameter.configure_endpoint
        assert index in (0x00, 0x01)

        raise zigpy_deconz.exception.CommandError(
            "Unsupported",
            status=deconz_api.Status.UNSUPPORTED,
            command=None,
        )

    app._api.read_parameter = AsyncMock(side_effect=read_param)
    app._api.write_parameter = AsyncMock()
    app._written_endpoints.add(0x00)
    app._written_endpoints.add(0x01)

    with pytest.raises(ValueError):
        await app.add_endpoint(ENDPOINT.replace(endpoint=1))

    app._api.write_parameter.assert_not_called()


async def test_add_endpoint_no_unnecessary_writes(app):
    async def read_param(param_id, index):
        assert param_id == deconz_api.NetworkParameter.configure_endpoint

        if index > 0x01:
            raise zigpy_deconz.exception.CommandError(
                "Unsupported",
                status=deconz_api.Status.UNSUPPORTED,
                command=None,
            )

        return deconz_api.IndexedEndpoint(
            index=index, descriptor=ENDPOINT.replace(endpoint=1)
        )

    app._api.read_parameter = AsyncMock(side_effect=read_param)
    app._api.write_parameter = AsyncMock()

    await app.add_endpoint(ENDPOINT.replace(endpoint=1))
    app._api.write_parameter.assert_not_called()

    # Writing another endpoint will cause a write
    await app.add_endpoint(ENDPOINT.replace(endpoint=2))
    app._api.write_parameter.assert_called_once_with(
        deconz_api.NetworkParameter.configure_endpoint,
        deconz_api.IndexedEndpoint(index=1, descriptor=ENDPOINT.replace(endpoint=2)),
    )


async def test_reset_network_info(app):
    app.form_network = AsyncMock()
    await app.reset_network_info()

    app.form_network.assert_called_once()


async def test_energy_scan_conbee_2(app):
    with mock.patch.object(
        zigpy.application.ControllerApplication,
        "energy_scan",
        return_value={c: c for c in Channels.ALL_CHANNELS},
    ):
        results = await app.energy_scan(
            channels=Channels.ALL_CHANNELS, duration_exp=0, count=1
        )

    assert results == {c: c * 3 for c in Channels.ALL_CHANNELS}


async def test_energy_scan_conbee_3(app):
    app._api.firmware_version = deconz_api.FirmwareVersion(0x26580900)

    type(app)._device = AsyncMock()

    app._device.zdo.Mgmt_NWK_Update_req = AsyncMock(
        side_effect=zigpy.exceptions.DeliveryError("error")
    )

    with pytest.raises(zigpy.exceptions.DeliveryError):
        await app.energy_scan(channels=Channels.ALL_CHANNELS, duration_exp=0, count=1)

    app._device.zdo.Mgmt_NWK_Update_req = AsyncMock(
        side_effect=[
            asyncio.TimeoutError(),
            list(
                {
                    "Status": zdo_t.Status.SUCCESS,
                    "ScannedChannels": Channels.ALL_CHANNELS,
                    "TotalTransmissions": 0,
                    "TransmissionFailures": 0,
                    "EnergyValues": [i for i in range(11, 26 + 1)],
                }.values()
            ),
        ]
    )

    results = await app.energy_scan(
        channels=Channels.ALL_CHANNELS, duration_exp=0, count=1
    )

    assert results == {c: c for c in Channels.ALL_CHANNELS}


async def test_channel_migration(app):
    app._api.write_parameter = AsyncMock()
    app._change_network_state = AsyncMock()

    await app._move_network_to_channel(new_channel=26, new_nwk_update_id=0x12)

    assert app._api.write_parameter.mock_calls == [
        mock.call(
            deconz_api.NetworkParameter.channel_mask, Channels.from_channel_list([26])
        ),
        mock.call(deconz_api.NetworkParameter.nwk_update_id, 0x12),
    ]

    assert app._change_network_state.mock_calls == [
        mock.call(deconz_api.NetworkState.OFFLINE),
        mock.call(deconz_api.NetworkState.CONNECTED),
    ]
