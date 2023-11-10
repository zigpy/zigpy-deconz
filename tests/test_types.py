"""Tests for zigpy_deconz.types module."""


import pytest
import zigpy.types as zigpy_t

import zigpy_deconz.types as t


def test_deconz_address_group():
    data = b"\x01\x55\xaa"
    extra = b"the rest of the owl"

    addr, rest = t.DeconzAddress.deserialize(data + extra)
    assert rest == extra
    assert addr.address_mode == t.AddressMode.GROUP
    assert addr.address_mode == 1
    assert addr.address == 0xAA55

    assert addr.serialize() == data

    zigpy_addr = zigpy_t.AddrModeAddress(
        addr_mode=zigpy_t.AddrMode.Group, address=0xAA55
    )
    assert addr.as_zigpy_type() == zigpy_addr

    converted_addr = t.DeconzAddress.from_zigpy_type(zigpy_addr)
    assert converted_addr == addr


def test_deconz_address_nwk():
    data = b"\x02\x55\xaa"
    extra = b"the rest of the owl"

    addr, rest = t.DeconzAddress.deserialize(data + extra)
    assert rest == extra
    assert addr.address_mode == t.AddressMode.NWK
    assert addr.address_mode == 2
    assert addr.address == 0xAA55

    assert addr.serialize() == data

    zigpy_addr = zigpy_t.AddrModeAddress(addr_mode=zigpy_t.AddrMode.NWK, address=0xAA55)
    assert addr.as_zigpy_type() == zigpy_addr

    converted_addr = t.DeconzAddress.from_zigpy_type(zigpy_addr)
    assert converted_addr == addr


def test_deconz_address_nwk_broadcast():
    data = b"\x02\xfc\xff"
    extra = b"the rest of the owl"

    addr, rest = t.DeconzAddress.deserialize(data + extra)
    assert rest == extra
    assert addr.address_mode == t.AddressMode.NWK
    assert addr.address_mode == 2
    assert addr.address == 0xFFFC

    assert addr.serialize() == data

    zigpy_addr = zigpy_t.AddrModeAddress(
        addr_mode=zigpy_t.AddrMode.Broadcast,
        address=zigpy_t.BroadcastAddress.ALL_ROUTERS_AND_COORDINATOR,
    )
    assert addr.as_zigpy_type() == zigpy_addr

    converted_addr = t.DeconzAddress.from_zigpy_type(zigpy_addr)
    assert converted_addr == addr


def test_deconz_address_ieee():
    data = b"\x03\x55\xaa\xbb\xcc\xdd\xee\xef\xbe"
    extra = b"the rest of the owl"

    addr, rest = t.DeconzAddress.deserialize(data + extra)
    assert rest == extra
    assert addr.address_mode == t.AddressMode.IEEE
    assert addr.address_mode == 3
    assert addr.address[0] == 0x55
    assert addr.address[1] == 0xAA
    assert addr.address[2] == 0xBB
    assert addr.address[3] == 0xCC
    assert addr.address[4] == 0xDD
    assert addr.address[5] == 0xEE
    assert addr.address[6] == 0xEF
    assert addr.address[7] == 0xBE

    assert addr.serialize() == data

    zigpy_addr = zigpy_t.AddrModeAddress(
        addr_mode=zigpy_t.AddrMode.IEEE,
        address=zigpy_t.EUI64.convert("BE:EF:EE:DD:CC:BB:AA:55"),
    )
    assert addr.as_zigpy_type() == zigpy_addr

    converted_addr = t.DeconzAddress.from_zigpy_type(zigpy_addr)
    assert converted_addr == addr


def test_deconz_address_nwk_and_ieee():
    data = b"\x04\x55\xaa\x88\x99\xbb\xcc\xdd\xee\xef\xbe"
    extra = b"the rest of the owl"

    addr, rest = t.DeconzAddress.deserialize(data + extra)
    assert rest == extra
    assert addr.address_mode == t.AddressMode.NWK_AND_IEEE
    assert addr.address_mode == 4
    assert addr.ieee[0] == 0x88
    assert addr.ieee[1] == 0x99
    assert addr.ieee[2] == 0xBB
    assert addr.ieee[3] == 0xCC
    assert addr.ieee[4] == 0xDD
    assert addr.ieee[5] == 0xEE
    assert addr.ieee[6] == 0xEF
    assert addr.ieee[7] == 0xBE
    assert addr.address == 0xAA55

    assert addr.serialize() == data

    zigpy_addr = zigpy_t.AddrModeAddress(
        addr_mode=zigpy_t.AddrMode.IEEE,
        address=zigpy_t.EUI64.convert("BE:EF:EE:DD:CC:BB:99:88"),
    )
    assert addr.as_zigpy_type() == zigpy_addr


def test_bytes():
    data = b"abcde\x00\xff"

    r, rest = t.Bytes.deserialize(data)
    assert rest == b""
    assert r == data

    assert r.serialize() == data


def test_addr_ep_nwk():
    data = b"\x02\xaa\x55\xcc"
    extra = b"\x00extra data\xff"

    r, rest = t.DeconzAddressEndpoint.deserialize(data + extra)
    assert rest == extra
    assert r.address_mode == t.AddressMode.NWK
    assert r.address == 0x55AA
    assert r.endpoint == 0xCC


def test_addr_ep_ieee():
    data = b"\x0387654321\xcc"
    extra = b"\x00extra data\xff"

    r, rest = t.DeconzAddressEndpoint.deserialize(data + extra)
    assert rest == extra
    assert r.address_mode == t.AddressMode.IEEE
    assert repr(r.address) == "31:32:33:34:35:36:37:38"
    assert r.endpoint == 0xCC


def test_deconz_addr_ep():
    data = b"\x01\xaa\x55"
    extra = b"the rest of the owl"

    r, rest = t.DeconzAddressEndpoint.deserialize(data + extra)
    assert rest == extra
    assert r.address_mode == t.AddressMode.GROUP
    assert r.address == 0x55AA
    assert r.serialize() == data
    a = t.DeconzAddressEndpoint()
    a.address_mode = 1
    a.address = 0x55AA
    assert a.serialize() == data

    data = b"\x02\xaa\x55\xcc"
    r, rest = t.DeconzAddressEndpoint.deserialize(data + extra)
    assert rest == extra
    assert r.address_mode == t.AddressMode.NWK
    assert r.address == 0x55AA
    assert r.endpoint == 0xCC
    assert r.serialize() == data
    a = t.DeconzAddressEndpoint()
    a.address_mode = 2
    a.address = 0x55AA
    with pytest.raises(TypeError):
        a.serialize()
    a.endpoint = 0xCC
    assert a.serialize() == data

    data = b"\x03\x31\x32\x33\x34\x35\x36\x37\x38\xcc"
    r, rest = t.DeconzAddressEndpoint.deserialize(data + extra)
    assert rest == extra
    assert r.address_mode == t.AddressMode.IEEE
    assert r.address == [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
    assert r.endpoint == 0xCC
    assert r.serialize() == data
    a = t.DeconzAddressEndpoint()
    a.address_mode = 3
    a.address = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
    with pytest.raises(TypeError):
        a.serialize()
    a.endpoint = 0xCC
    assert a.serialize() == data


def test_nwklist():
    assert t.NWKList([]).serialize() == b"\x00"
    assert t.NWKList([0x1234]).serialize() == b"\x01" + t.NWK(0x1234).serialize()
    assert (
        t.NWKList([0x1234, 0x5678]).serialize()
        == b"\x02" + t.NWK(0x1234).serialize() + t.NWK(0x5678).serialize()
    )

    assert t.NWKList.deserialize(b"\x00abc") == (t.NWKList([]), b"abc")
    assert t.NWKList.deserialize(b"\x01\x34\x12abc") == (t.NWKList([0x1234]), b"abc")
    assert t.NWKList.deserialize(b"\x02\x34\x12\x78\x56abc") == (
        t.NWKList([0x1234, 0x5678]),
        b"abc",
    )


def test_serialize_dict():
    assert (
        t.serialize_dict(
            {"foo": 1, "bar": 2, "baz": None},
            {"foo": t.uint8_t, "bar": t.uint16_t, "baz": t.uint8_t},
        )
        == b"\x01\x02\x00"
    )
