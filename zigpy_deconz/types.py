"""Data types module."""

import enum


def deserialize(data, schema):
    result = []
    for type_ in schema:
        value, data = type_.deserialize(data)
        result.append(value)
    return result, data


def serialize(data, schema):
    return b"".join(t(v).serialize() for t, v in zip(schema, data))


class Bytes(bytes):
    def serialize(self):
        return self

    @classmethod
    def deserialize(cls, data):
        return cls(data), b""


class LVBytes(bytes):
    def serialize(self):
        return uint16_t(len(self)).serialize() + self

    @classmethod
    def deserialize(cls, data, byteorder="little"):
        length, data = uint16_t.deserialize(data)
        return cls(data[:length]), data[length:]


class int_t(int):
    _signed = True
    _size = 0

    def serialize(self, byteorder="little"):
        return self.to_bytes(self._size, byteorder, signed=self._signed)

    @classmethod
    def deserialize(cls, data, byteorder="little"):
        # Work around https://bugs.python.org/issue23640
        r = cls(int.from_bytes(data[: cls._size], byteorder, signed=cls._signed))
        data = data[cls._size :]
        return r, data


class int8s(int_t):
    _size = 1


class int16s(int_t):
    _size = 2


class int24s(int_t):
    _size = 3


class int32s(int_t):
    _size = 4


class int40s(int_t):
    _size = 5


class int48s(int_t):
    _size = 6


class int56s(int_t):
    _size = 7


class int64s(int_t):
    _size = 8


class uint_t(int_t):
    _signed = False


class uint8_t(uint_t):
    _size = 1


class uint16_t(uint_t):
    _size = 2


class uint24_t(uint_t):
    _size = 3


class uint32_t(uint_t):
    _size = 4


class uint40_t(uint_t):
    _size = 5


class uint48_t(uint_t):
    _size = 6


class uint56_t(uint_t):
    _size = 7


class uint64_t(uint_t):
    _size = 8


class ADDRESS_MODE(uint8_t, enum.Enum):
    # Address modes used in deconz protocol

    GROUP = 0x01
    NWK = 0x02
    IEEE = 0x03
    NWK_AND_IEEE = 0x04


class Struct:
    _fields = []

    def __init__(self, *args, **kwargs):
        """Initialize instance."""

        if len(args) == 1 and isinstance(args[0], self.__class__):
            # copy constructor
            for field in self._fields:
                if hasattr(args[0], field[0]):
                    setattr(self, field[0], getattr(args[0], field[0]))

    def serialize(self):
        r = b""
        for field in self._fields:
            if hasattr(self, field[0]):
                r += getattr(self, field[0]).serialize()
        return r

    @classmethod
    def deserialize(cls, data):
        """Deserialize data."""
        r = cls()
        for field_name, field_type in cls._fields:
            v, data = field_type.deserialize(data)
            setattr(r, field_name, v)
        return r, data

    def __repr__(self):
        """Instance representation."""
        r = "<%s " % (self.__class__.__name__,)
        r += " ".join(
            ["%s=%s" % (f[0], getattr(self, f[0], None)) for f in self._fields]
        )
        r += ">"
        return r


class List(list):
    _length = None
    _itemtype = None

    def serialize(self):
        assert self._length is None or len(self) == self._length
        return b"".join([self._itemtype(i).serialize() for i in self])

    @classmethod
    def deserialize(cls, data):
        assert cls._itemtype is not None
        r = cls()
        while data:
            item, data = cls._itemtype.deserialize(data)
            r.append(item)
        return r, data


class FixedList(List):
    _length = None
    _itemtype = None

    @classmethod
    def deserialize(cls, data):
        assert cls._itemtype is not None
        r = cls()
        for i in range(cls._length):
            item, data = cls._itemtype.deserialize(data)
            r.append(item)
        return r, data


class EUI64(FixedList):
    _length = 8
    _itemtype = uint8_t

    def __repr__(self):
        """Instance representation."""
        return ":".join("%02x" % i for i in self[::-1])

    def __hash__(self):
        """Hash magic method."""
        return hash(repr(self))


class HexRepr:
    def __repr__(self):
        """Instance representation."""
        return ("0x{:0" + str(self._size * 2) + "x}").format(self)

    def __str__(self):
        """Instance str method."""
        return ("0x{:0" + str(self._size * 2) + "x}").format(self)


class GroupId(HexRepr, uint16_t):
    pass


class NWK(HexRepr, uint16_t):
    pass


class PanId(HexRepr, uint16_t):
    pass


class ExtendedPanId(EUI64):
    pass


class DeconzAddress(Struct):
    _fields = [
        # The address format (AddressMode)
        ("address_mode", ADDRESS_MODE),
        ("address", EUI64),
    ]

    @classmethod
    def deserialize(cls, data):
        r = cls()
        mode, data = ADDRESS_MODE.deserialize(data)
        r.address_mode = mode
        if mode in [ADDRESS_MODE.GROUP, ADDRESS_MODE.NWK, ADDRESS_MODE.NWK_AND_IEEE]:
            r.address, data = NWK.deserialize(data)
        elif mode == ADDRESS_MODE.IEEE:
            r.address, data = EUI64.deserialize(data)
        if mode == ADDRESS_MODE.NWK_AND_IEEE:
            r.ieee, data = EUI64.deserialize(data)
        return r, data

    def serialize(self):
        r = super().serialize()
        if self.address_mode == ADDRESS_MODE.NWK_AND_IEEE:
            r += self.ieee.serialize()
        return r


class DeconzAddressEndpoint(Struct):
    _fields = [
        # The address format (AddressMode)
        ("address_mode", ADDRESS_MODE),
        ("address", EUI64),
        ("endpoint", uint8_t),
    ]

    @classmethod
    def deserialize(cls, data):
        r = cls()
        mode, data = ADDRESS_MODE.deserialize(data)
        r.address_mode = mode
        a = e = None
        if mode == ADDRESS_MODE.GROUP:
            a, data = GroupId.deserialize(data)
        elif mode == ADDRESS_MODE.NWK:
            a, data = NWK.deserialize(data)
        elif mode == ADDRESS_MODE.IEEE:
            a, data = EUI64.deserialize(data)
        setattr(r, cls._fields[1][0], a)
        if mode in [ADDRESS_MODE.NWK, ADDRESS_MODE.IEEE]:
            e, data = uint8_t.deserialize(data)
        setattr(r, cls._fields[2][0], e)
        return r, data

    def serialize(self):
        r = uint8_t(self.address_mode).serialize()
        if self.address_mode == ADDRESS_MODE.NWK:
            r += NWK(self.address).serialize()
        elif self.address_mode == ADDRESS_MODE.GROUP:
            r += GroupId(self.address).serialize()
        elif self.address_mode == ADDRESS_MODE.IEEE:
            r += EUI64(self.address).serialize()
        if self.address_mode in (ADDRESS_MODE.NWK, ADDRESS_MODE.IEEE):
            r += uint8_t(self.endpoint).serialize()
        return r


class Key(FixedList):
    _itemtype = uint8_t
    _length = 16
