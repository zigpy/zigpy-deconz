"""Data types module."""

import enum

import zigpy.types as zigpy_t
from zigpy.types import bitmap8, bitmap16  # noqa: F401


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


class AddressMode(uint8_t, enum.Enum):
    # Address modes used in deconz protocol

    GROUP = 0x01
    NWK = 0x02
    IEEE = 0x03
    NWK_AND_IEEE = 0x04


class DeconzSendDataFlags(bitmap8):
    NONE = 0x00
    NODE_ID = 0x01
    RELAYS = 0x02


class DeconzTransmitOptions(bitmap8):
    NONE = 0x00
    SECURITY_ENABLED = 0x01
    USE_NWK_KEY_SECURITY = 0x02
    USE_APS_ACKS = 0x04
    ALLOW_FRAGMENTATION = 0x08


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

    def __eq__(self, other):
        """Check equality between structs."""
        if not isinstance(other, type(self)):
            return NotImplemented

        return all(getattr(self, n) == getattr(other, n) for n, _ in self._fields)

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


class LVList(list):
    _length_type = None
    _itemtype = None

    def serialize(self):
        return self._length_type(len(self)).serialize() + b"".join(
            [self._itemtype(i).serialize() for i in self]
        )

    @classmethod
    def deserialize(cls, data):
        length, data = cls._length_type.deserialize(data)
        r = cls()
        for _ in range(length):
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


class NWKList(LVList):
    _length_type = uint8_t
    _itemtype = NWK


ZIGPY_ADDR_MODE_MAPPING = {
    zigpy_t.AddrMode.NWK: AddressMode.NWK,
    zigpy_t.AddrMode.IEEE: AddressMode.IEEE,
    zigpy_t.AddrMode.Group: AddressMode.GROUP,
    zigpy_t.AddrMode.Broadcast: AddressMode.NWK,
}


ZIGPY_ADDR_TYPE_MAPPING = {
    zigpy_t.AddrMode.NWK: NWK,
    zigpy_t.AddrMode.IEEE: EUI64,
    zigpy_t.AddrMode.Group: GroupId,
    zigpy_t.AddrMode.Broadcast: NWK,
}


ZIGPY_ADDR_MODE_REVERSE_MAPPING = {
    AddressMode.NWK: zigpy_t.AddrMode.NWK,
    AddressMode.IEEE: zigpy_t.AddrMode.IEEE,
    AddressMode.GROUP: zigpy_t.AddrMode.Group,
    AddressMode.NWK_AND_IEEE: zigpy_t.AddrMode.IEEE,
}


ZIGPY_ADDR_TYPE_REVERSE_MAPPING = {
    AddressMode.NWK: zigpy_t.NWK,
    AddressMode.IEEE: zigpy_t.EUI64,
    AddressMode.GROUP: zigpy_t.Group,
    AddressMode.NWK_AND_IEEE: zigpy_t.NWK,
}


class DeconzAddress(Struct):
    _fields = [
        # The address format (AddressMode)
        ("address_mode", AddressMode),
        ("address", EUI64),
    ]

    @classmethod
    def deserialize(cls, data):
        r = cls()
        mode, data = AddressMode.deserialize(data)
        r.address_mode = mode
        if mode in [AddressMode.GROUP, AddressMode.NWK, AddressMode.NWK_AND_IEEE]:
            r.address, data = NWK.deserialize(data)
        elif mode == AddressMode.IEEE:
            r.address, data = EUI64.deserialize(data)
        if mode == AddressMode.NWK_AND_IEEE:
            r.ieee, data = EUI64.deserialize(data)
        return r, data

    def serialize(self):
        r = super().serialize()
        if self.address_mode == AddressMode.NWK_AND_IEEE:
            r += self.ieee.serialize()
        return r

    def as_zigpy_type(self):
        addr_mode = ZIGPY_ADDR_MODE_REVERSE_MAPPING[self.address_mode]
        address = ZIGPY_ADDR_TYPE_REVERSE_MAPPING[self.address_mode](self.address)

        if self.address_mode == AddressMode.NWK and self.address > 0xFFF7:
            addr_mode = zigpy_t.AddrMode.Broadcast
            address = zigpy_t.BroadcastAddress(self.address)
        elif self.address_mode == AddressMode.NWK_AND_IEEE:
            address = zigpy_t.EUI64(self.ieee)

        return zigpy_t.AddrModeAddress(
            addr_mode=addr_mode,
            address=address,
        )

    @classmethod
    def from_zigpy_type(cls, addr):
        instance = cls()
        instance.address_mode = ZIGPY_ADDR_MODE_MAPPING[addr.addr_mode]
        instance.address = ZIGPY_ADDR_TYPE_MAPPING[addr.addr_mode](addr.address)

        return instance


class DeconzAddressEndpoint(Struct):
    _fields = [
        # The address format (AddressMode)
        ("address_mode", AddressMode),
        ("address", EUI64),
        ("endpoint", uint8_t),
    ]

    @classmethod
    def deserialize(cls, data):
        r, data = DeconzAddress.deserialize.__func__(cls, data)

        if r.address_mode in (
            AddressMode.NWK,
            AddressMode.IEEE,
            AddressMode.NWK_AND_IEEE,
        ):
            r.endpoint, data = uint8_t.deserialize(data)
        else:
            r.endpoint = None

        return r, data

    def serialize(self):
        r = uint8_t(self.address_mode).serialize()

        if self.address_mode in (AddressMode.NWK, AddressMode.NWK_AND_IEEE):
            r += NWK(self.address).serialize()
        elif self.address_mode == AddressMode.GROUP:
            r += GroupId(self.address).serialize()

        if self.address_mode in (AddressMode.IEEE, AddressMode.NWK_AND_IEEE):
            r += EUI64(self.address).serialize()

        if self.address_mode in (
            AddressMode.NWK,
            AddressMode.IEEE,
            AddressMode.NWK_AND_IEEE,
        ):
            r += uint8_t(self.endpoint).serialize()

        return r

    @classmethod
    def from_zigpy_type(cls, addr, endpoint):
        temp_addr = DeconzAddress.from_zigpy_type(addr)

        instance = cls()
        instance.address_mode = temp_addr.address_mode
        instance.address = temp_addr.address
        instance.endpoint = endpoint

        return instance


class Key(FixedList):
    _itemtype = uint8_t
    _length = 16


class DataIndicationFlags(bitmap8):
    Always_Use_NWK_Source_Addr = 0b00000001
    Last_Hop_In_Reserved_Bytes = 0b00000010
    Include_Both_NWK_And_IEEE = 0b00000100
