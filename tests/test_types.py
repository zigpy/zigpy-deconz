from unittest import mock

import pytest

import zigpy_deconz.types as t


def test_deconz_address_group():
    data = b"\x01\x55\xaa"
    extra = b"the rest of the owl"

    addr, rest = t.DeconzAddress.deserialize(data + extra)
    assert rest == extra
    assert addr.address_mode == t.ADDRESS_MODE.GROUP
    assert addr.address_mode == 1
    assert addr.address == 0xAA55

    assert addr.serialize() == data


def test_deconz_address_nwk():
    data = b"\x02\x55\xaa"
    extra = b"the rest of the owl"

    addr, rest = t.DeconzAddress.deserialize(data + extra)
    assert rest == extra
    assert addr.address_mode == t.ADDRESS_MODE.NWK
    assert addr.address_mode == 2
    assert addr.address == 0xAA55

    assert addr.serialize() == data


def test_deconz_address_ieee():
    data = b"\x03\x55\xaa\xbb\xcc\xdd\xee\xef\xbe"
    extra = b"the rest of the owl"

    addr, rest = t.DeconzAddress.deserialize(data + extra)
    assert rest == extra
    assert addr.address_mode == t.ADDRESS_MODE.IEEE
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


def test_deconz_address_nwk_and_ieee():
    data = b"\x04\x55\xaa\x88\x99\xbb\xcc\xdd\xee\xef\xbe"
    extra = b"the rest of the owl"

    addr, rest = t.DeconzAddress.deserialize(data + extra)
    assert rest == extra
    assert addr.address_mode == t.ADDRESS_MODE.NWK_AND_IEEE
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


def test_pan_id():
    t.PanId()


def test_extended_pan_id():
    t.ExtendedPanId()


def test_key():
    data = b"\x31\x39\x63\x32\x30\x65\x61\x63\x36\x36\x32\x63\x61\x38\x30\x35"
    extra = b"extra data"

    key, rest = t.Key.deserialize(data + extra)
    assert rest == extra
    assert key == [49, 57, 99, 50, 48, 101, 97, 99, 54, 54, 50, 99, 97, 56, 48, 53]

    assert key.serialize() == data


def test_bytes():
    data = b"abcde\x00\xff"

    r, rest = t.Bytes.deserialize(data)
    assert rest == b""
    assert r == data

    assert r.serialize() == data


def test_lvbytes():
    data = b"abcde\x00\xff"
    extra = b"\xffrest of the data\x00"

    r, rest = t.LVBytes.deserialize(len(data).to_bytes(2, "little") + data + extra)
    assert rest == extra
    assert r == data

    assert r.serialize() == len(data).to_bytes(2, "little") + data


def test_struct():
    class TestStruct(t.Struct):
        _fields = [("a", t.uint8_t), ("b", t.uint8_t)]

    ts = TestStruct()
    ts.a = t.uint8_t(0xAA)
    ts.b = t.uint8_t(0xBB)
    ts2 = TestStruct(ts)
    assert ts2.a == ts.a
    assert ts2.b == ts.b

    r = repr(ts)
    assert "TestStruct" in r
    assert r.startswith("<") and r.endswith(">")

    s = ts2.serialize()
    assert s == b"\xaa\xbb"

    extra = b"\x00extra data\xff"
    d, rest = TestStruct.deserialize(s + extra)
    assert rest == extra
    assert d.a == ts.a
    assert d.b == ts.b


def test_list():
    class TestList(t.List):
        _itemtype = t.uint16_t

    r = TestList([1, 2, 3, 0x55AA])
    assert r.serialize() == b"\x01\x00\x02\x00\x03\x00\xaa\x55"


def test_list_deserialize():
    class TestList(t.List):
        _itemtype = t.uint16_t

    data = b"\x34\x12\x55\xaa\x89\xab"
    extra = b"\x00\xff"

    r, rest = TestList.deserialize(data + extra)
    assert rest == b""
    assert r[0] == 0x1234
    assert r[1] == 0xAA55
    assert r[2] == 0xAB89
    assert r[3] == 0xFF00


def test_fixed_list():
    class TestList(t.FixedList):
        _length = 3
        _itemtype = t.uint16_t

    with pytest.raises(AssertionError):
        r = TestList([1, 2, 3, 0x55AA])
        r.serialize()

    with pytest.raises(AssertionError):
        r = TestList([1, 2])
        r.serialize()

    r = TestList([1, 2, 3])

    assert r.serialize() == b"\x01\x00\x02\x00\x03\x00"


def test_fixed_list_deserialize():
    class TestList(t.FixedList):
        _length = 3
        _itemtype = t.uint16_t

    data = b"\x34\x12\x55\xaa\x89\xab"
    extra = b"\x00\xff"

    r, rest = TestList.deserialize(data + extra)
    assert rest == extra
    assert r[0] == 0x1234
    assert r[1] == 0xAA55
    assert r[2] == 0xAB89


def test_eui64():
    r = t.EUI64([0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08])
    ieee = "08:09:0a:0b:0c:0d:0e:0f"
    assert repr(r) == ieee
    i = {}
    i[r] = mock.sentinel.data


def test_hexrepr():
    class TestHR(t.HexRepr, t.uint16_t):
        pass

    i = TestHR(0xAA55)
    assert repr(i) == "0xaa55"
    assert str(i) == "0xaa55"


def test_addr_ep_nwk():
    data = b"\x02\xaa\x55\xcc"
    extra = b"\x00extra data\xff"

    r, rest = t.DeconzAddressEndpoint.deserialize(data + extra)
    assert rest == extra
    assert r.address_mode == t.ADDRESS_MODE.NWK
    assert r.address == 0x55AA
    assert r.endpoint == 0xCC


def test_addr_ep_ieee():
    data = b"\x0387654321\xcc"
    extra = b"\x00extra data\xff"

    r, rest = t.DeconzAddressEndpoint.deserialize(data + extra)
    assert rest == extra
    assert r.address_mode == t.ADDRESS_MODE.IEEE
    assert repr(r.address) == "31:32:33:34:35:36:37:38"
    assert r.endpoint == 0xCC


def test_deconz_addr_ep():
    data = b"\x01\xaa\x55"
    extra = b"the rest of the owl"

    r, rest = t.DeconzAddressEndpoint.deserialize(data + extra)
    assert rest == extra
    assert r.address_mode == t.ADDRESS_MODE.GROUP
    assert r.address == 0x55AA
    assert r.serialize() == data
    a = t.DeconzAddressEndpoint()
    a.address_mode = 1
    a.address = 0x55AA
    assert a.serialize() == data

    data = b"\x02\xaa\x55\xcc"
    r, rest = t.DeconzAddressEndpoint.deserialize(data + extra)
    assert rest == extra
    assert r.address_mode == t.ADDRESS_MODE.NWK
    assert r.address == 0x55AA
    assert r.endpoint == 0xCC
    assert r.serialize() == data
    a = t.DeconzAddressEndpoint()
    a.address_mode = 2
    a.address = 0x55AA
    with pytest.raises(AttributeError):
        a.serialize()
    a.endpoint = 0xCC
    assert a.serialize() == data

    data = b"\x03\x31\x32\x33\x34\x35\x36\x37\x38\xcc"
    r, rest = t.DeconzAddressEndpoint.deserialize(data + extra)
    assert rest == extra
    assert r.address_mode == t.ADDRESS_MODE.IEEE
    assert r.address == [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
    assert r.endpoint == 0xCC
    assert r.serialize() == data
    a = t.DeconzAddressEndpoint()
    a.address_mode = 3
    a.address = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
    with pytest.raises(AttributeError):
        a.serialize()
    a.endpoint = 0xCC
    assert a.serialize() == data
