"""Test `load_network_info` and `write_network_info` methods."""

import importlib.metadata

import pytest
from zigpy.exceptions import ControllerException, NetworkNotFormed
import zigpy.state as app_state
import zigpy.types as t
import zigpy.zdo.types as zdo_t

import zigpy_deconz
import zigpy_deconz.api
import zigpy_deconz.exception
import zigpy_deconz.zigbee.application as application

from tests.async_mock import AsyncMock, patch
from tests.test_application import api, app, device_path  # noqa: F401


def merge_objects(obj: object, update: dict) -> None:
    for key, value in update.items():
        if "." not in key:
            setattr(obj, key, value)
        else:
            subkey, rest = key.split(".", 1)
            merge_objects(getattr(obj, subkey), {rest: value})


@pytest.fixture
def node_info():
    return app_state.NodeInfo(
        nwk=t.NWK(0x0000),
        ieee=t.EUI64.convert("93:2C:A9:34:D9:D0:5D:12"),
        logical_type=zdo_t.LogicalType.Coordinator,
        manufacturer="dresden elektronik",
        model="Conbee II",
        version="0x26580700",
    )


@pytest.fixture
def network_info(node_info):
    return app_state.NetworkInfo(
        extended_pan_id=t.ExtendedPanId.convert("0D:49:91:99:AE:CD:3C:35"),
        pan_id=t.PanId(0x9BB0),
        nwk_update_id=0x12,
        nwk_manager_id=t.NWK(0x0000),
        channel=t.uint8_t(15),
        channel_mask=t.Channels.from_channel_list([15, 20, 25]),
        security_level=t.uint8_t(5),
        network_key=app_state.Key(
            key=t.KeyData.convert("9A:79:D6:9A:DA:EC:45:C6:F2:EF:EB:AF:DA:A3:07:B6"),
            seq=108,
            tx_counter=39009277,
        ),
        tc_link_key=app_state.Key(
            key=t.KeyData(b"ZigBeeAlliance09"),
            partner_ieee=node_info.ieee,
            tx_counter=8712428,
        ),
        key_table=[],
        children=[],
        nwk_addresses={},
        stack_specific={},
        source=f"zigpy-deconz@{importlib.metadata.version('zigpy-deconz')}",
        metadata={"deconz": {"version": "0x26580700"}},
    )


@patch.object(application, "CHANGE_NETWORK_POLL_TIME", 0.001)
@patch.object(application, "CHANGE_NETWORK_STATE_DELAY", 0.001)
@pytest.mark.parametrize(
    "channel_mask, channel, security_level, fw_supports_fc, logical_type",
    [
        (
            t.Channels.from_channel_list([15]),
            15,
            0,
            True,
            zdo_t.LogicalType.Coordinator,
        ),
        (
            t.Channels.from_channel_list([15]),
            15,
            0,
            False,
            zdo_t.LogicalType.Coordinator,
        ),
        (
            t.Channels.from_channel_list([15, 20]),
            15,
            5,
            True,
            zdo_t.LogicalType.Coordinator,
        ),
        (
            t.Channels.from_channel_list([15, 20, 25]),
            None,
            5,
            True,
            zdo_t.LogicalType.Router,
        ),
        (None, 15, 5, True, zdo_t.LogicalType.Coordinator),
    ],
)
async def test_write_network_info(
    app,  # noqa: F811
    network_info,
    node_info,
    channel_mask,
    channel,
    security_level,
    fw_supports_fc,
    logical_type,
):
    """Test that network info is correctly written."""

    params = {}

    async def write_parameter(param, *args):
        if (
            not fw_supports_fc
            and param == zigpy_deconz.api.NetworkParameter.nwk_frame_counter
        ):
            raise zigpy_deconz.exception.CommandError(
                "Command is unsupported",
                status=zigpy_deconz.api.Status.UNSUPPORTED,
                command=None,
            )

        params[param.name] = args

    app._change_network_state = AsyncMock()
    app._api.write_parameter = AsyncMock(side_effect=write_parameter)

    network_info = network_info.replace(
        channel=channel,
        channel_mask=channel_mask,
        security_level=security_level,
    )

    node_info = node_info.replace(logical_type=logical_type)

    if not fw_supports_fc:
        with pytest.raises(
            ControllerException,
            match=(
                "Please upgrade your adapter firmware. Firmware version 0x26580700 does"
                " not support writing the network key frame counter, which is required"
                " for migration to succeed."
            ),
        ):
            await app.write_network_info(
                network_info=network_info,
                node_info=node_info,
            )
        return

    await app.write_network_info(
        network_info=network_info,
        node_info=node_info,
    )

    params = {
        call[0][0].name: call[0][1:]
        for call in app._api.write_parameter.await_args_list
    }

    assert params["nwk_frame_counter"] == (network_info.network_key.tx_counter,)

    if node_info.logical_type == zdo_t.LogicalType.Coordinator:
        assert params["aps_designed_coordinator"] == (1,)
    else:
        assert params["aps_designed_coordinator"] == (0,)

    assert params["nwk_address"] == (node_info.nwk,)
    assert params["mac_address"] == (node_info.ieee,)

    if channel is not None:
        assert params["channel_mask"] == (
            t.Channels.from_channel_list([network_info.channel]),
        )
    elif channel_mask is not None:
        assert params["channel_mask"] == (network_info.channel_mask,)
    else:
        assert False

    assert params["use_predefined_nwk_panid"] == (True,)
    assert params["nwk_panid"] == (network_info.pan_id,)
    assert params["aps_extended_panid"] == (network_info.extended_pan_id,)
    assert params["nwk_update_id"] == (network_info.nwk_update_id,)
    assert params["network_key"] == (
        zigpy_deconz.api.IndexedKey(index=0, key=network_info.network_key.key),
    )
    assert params["trust_center_address"] == (node_info.ieee,)
    assert params["link_key"] == (
        zigpy_deconz.api.LinkKey(ieee=node_info.ieee, key=network_info.tc_link_key.key),
    )

    if security_level == 0:
        assert params["security_mode"] == (zigpy_deconz.api.SecurityMode.NO_SECURITY,)
    else:
        assert params["security_mode"] == (zigpy_deconz.api.SecurityMode.ONLY_TCLK,)


@patch.object(application, "CHANGE_NETWORK_POLL_TIME", 0.001)
@patch.object(application, "CHANGE_NETWORK_STATE_DELAY", 0.001)
@pytest.mark.parametrize(
    "error, param_overrides, nwk_state_changes, node_state_changes",
    [
        (None, {}, {}, {}),
        (
            None,
            {("aps_designed_coordinator",): 0x00},
            {},
            {"logical_type": zdo_t.LogicalType.Router},
        ),
        (
            None,
            {
                ("aps_extended_panid",): t.EUI64.convert("00:00:00:00:00:00:00:00"),
                ("nwk_extended_panid",): t.EUI64.convert("0D:49:91:99:AE:CD:3C:35"),
            },
            {},
            {},
        ),
        (NetworkNotFormed, {("current_channel",): 0}, {}, {}),
        (
            None,
            {
                ("nwk_frame_counter",): zigpy_deconz.exception.CommandError(
                    "Some error",
                    status=zigpy_deconz.api.Status.UNSUPPORTED,
                    command=None,
                )
            },
            {"network_key.tx_counter": 0},
            {},
        ),
        (
            None,
            {("security_mode",): zigpy_deconz.api.SecurityMode.NO_SECURITY},
            {"security_level": 0},
            {},
        ),
        (
            None,
            {
                (
                    "security_mode",
                ): zigpy_deconz.api.SecurityMode.PRECONFIGURED_NETWORK_KEY
            },
            {"security_level": 5},
            {},
        ),
    ],
)
async def test_load_network_info(
    app,  # noqa: F811
    network_info,
    node_info,
    error,
    param_overrides,
    nwk_state_changes,
    node_state_changes,
):
    """Test that network info is correctly read."""

    params = {
        ("nwk_frame_counter",): network_info.network_key.tx_counter,
        ("aps_designed_coordinator",): 1,
        ("nwk_address",): node_info.nwk,
        ("mac_address",): node_info.ieee,
        ("current_channel",): network_info.channel,
        ("channel_mask",): t.Channels.from_channel_list([network_info.channel]),
        ("use_predefined_nwk_panid",): True,
        ("nwk_panid",): network_info.pan_id,
        ("aps_extended_panid",): network_info.extended_pan_id,
        ("nwk_update_id",): network_info.nwk_update_id,
        ("network_key", 0): zigpy_deconz.api.IndexedKey(
            index=0, key=network_info.network_key.key
        ),
        ("trust_center_address",): node_info.ieee,
        ("link_key", node_info.ieee): zigpy_deconz.api.LinkKey(
            ieee=node_info.ieee, key=network_info.tc_link_key.key
        ),
        ("security_mode",): zigpy_deconz.api.SecurityMode.ONLY_TCLK,
        ("protocol_version",): 0x010E,
    }

    params.update(param_overrides)

    async def read_param(param, *args):
        try:
            value = params[(param.name,) + args]
        except KeyError:
            raise zigpy_deconz.exception.CommandError(
                zigpy_deconz.api.Status.UNSUPPORTED, f"Unsupported: {param!r} {args!r}"
            )

        if isinstance(value, Exception):
            raise value

        return value

    app._api.firmware_version = zigpy_deconz.api.FirmwareVersion(0x26580700)
    app._api.read_parameter = AsyncMock(side_effect=read_param)

    if error is not None:
        with pytest.raises(error):
            await app.load_network_info()

        return

    assert app.state.network_info != network_info
    assert app.state.node_info != node_info

    await app.load_network_info()

    # Almost all of the info matches
    network_info = network_info.replace(
        channel_mask=t.Channels.from_channel_list([network_info.channel]),
        network_key=network_info.network_key.replace(seq=0),
        tc_link_key=network_info.tc_link_key.replace(tx_counter=0),
    )
    merge_objects(network_info, nwk_state_changes)

    assert app.state.network_info == network_info

    assert app.state.node_info == node_info.replace(**node_state_changes)
