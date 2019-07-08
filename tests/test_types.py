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
    assert addr.address == [0xbe, 0xef, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x55]

    assert addr.serialize() == data


def test_deconz_address_nwk_and_ieee():
    data = b'\x04\x55\xaa\x88\x99\xbb\xcc\xdd\xee\xef\xbe'
    extra = b'the rest of the owl'

    addr, rest = t.DeconzAddress.deserialize(data + extra)
    assert rest == extra
    assert addr.address_mode == t.ADDRESS_MODE.NWK_AND_IEEE
    assert addr.address_mode == 4
    assert addr.ieee == [0xbe, 0xef, 0xee, 0xdd, 0xcc, 0xbb, 0x99, 0x88]
    assert addr.address == 0xaa55

    assert addr.serialize() == data
