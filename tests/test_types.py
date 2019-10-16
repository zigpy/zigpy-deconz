import zigpy_deconz.types as t


def test_deconz_address_group():
    data = b'\x01\x55\xaa'
    extra = b'the rest of the owl'

    addr, rest = t.DeconzAddress.deserialize(data + extra)
    assert rest == extra
    assert addr.address_mode == t.ADDRESS_MODE.GROUP
    assert addr.address_mode == 1
    assert addr.address == 0xaa55

    assert addr.serialize() == data


def test_deconz_address_nwk():
    data = b'\x02\x55\xaa'
    extra = b'the rest of the owl'

    addr, rest = t.DeconzAddress.deserialize(data + extra)
    assert rest == extra
    assert addr.address_mode == t.ADDRESS_MODE.NWK
    assert addr.address_mode == 2
    assert addr.address == 0xaa55

    assert addr.serialize() == data


def test_deconz_address_ieee():
    data = b'\x03\x55\xaa\xbb\xcc\xdd\xee\xef\xbe'
    extra = b'the rest of the owl'

    addr, rest = t.DeconzAddress.deserialize(data + extra)
    assert rest == extra
    assert addr.address_mode == t.ADDRESS_MODE.IEEE
    assert addr.address_mode == 3
    assert addr.address[0] == 0x55
    assert addr.address[1] == 0xaa
    assert addr.address[2] == 0xbb
    assert addr.address[3] == 0xcc
    assert addr.address[4] == 0xdd
    assert addr.address[5] == 0xee
    assert addr.address[6] == 0xef
    assert addr.address[7] == 0xbe

    assert addr.serialize() == data


def test_deconz_address_nwk_and_ieee():
    data = b'\x04\x55\xaa\x88\x99\xbb\xcc\xdd\xee\xef\xbe'
    extra = b'the rest of the owl'

    addr, rest = t.DeconzAddress.deserialize(data + extra)
    assert rest == extra
    assert addr.address_mode == t.ADDRESS_MODE.NWK_AND_IEEE
    assert addr.address_mode == 4
    assert addr.ieee[0] == 0x88
    assert addr.ieee[1] == 0x99
    assert addr.ieee[2] == 0xbb
    assert addr.ieee[3] == 0xcc
    assert addr.ieee[4] == 0xdd
    assert addr.ieee[5] == 0xee
    assert addr.ieee[6] == 0xef
    assert addr.ieee[7] == 0xbe
    assert addr.address == 0xaa55

    assert addr.serialize() == data


def test_pan_id():
    t.PanId()


def test_extended_pan_id():
    t.ExtendedPanId()


def test_key():
    data = b'\x31\x39\x63\x32\x30\x65\x61\x63\x36\x36\x32\x63\x61\x38\x30\x35'
    extra = b'extra data'

    key, rest = t.Key.deserialize(data + extra)
    assert rest == extra
    assert key == [49, 57, 99, 50, 48, 101, 97, 99, 54, 54, 50, 99, 97, 56, 48, 53]

    assert key.serialize() == data
