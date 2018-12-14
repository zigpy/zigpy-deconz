import enum


def deserialize(data, schema):
    result = []
    for type_ in schema:
        value, data = type_.deserialize(data)
        result.append(value)
    return result, data


def serialize(data, schema):
    return b''.join(t(v).serialize() for t, v in zip(schema, data))


class Bytes(bytes):
    def serialize(self):
        return self

    @classmethod
    def deserialize(cls, data):
        return cls(data), b''


class LVBytes(bytes):
    def serialize(self):
        return uint16_t(len(self)).serialize() + self

    @classmethod
    def deserialize(cls, data, byteorder='little'):
        bytes = int.from_bytes(data[:2], byteorder)
        s = data[2:bytes + 2]
        return s, data[bytes + 2:]


class int_t(int):
    _signed = True
    _size = 0

    def serialize(self, byteorder='little'):
        return self.to_bytes(self._size, byteorder, signed=self._signed)

    @classmethod
    def deserialize(cls, data, byteorder='little'):
        # Work around https://bugs.python.org/issue23640
        r = cls(int.from_bytes(data[:cls._size], byteorder, signed=cls._signed))
        data = data[cls._size:]
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


class Struct:
    _fields = []

    def __init__(self, *args, **kwargs):
        if len(args) == 1 and isinstance(args[0], self.__class__):
            # copy constructor
            for field in self._fields:
                setattr(self, field[0], getattr(args[0], field[0]))

    def serialize(self):
        r = b''
        for field in self._fields:
            r += getattr(self, field[0]).serialize()
        return r

    @classmethod
    def deserialize(cls, data):
        r = cls()
        for field_name, field_type in cls._fields:
            v, data = field_type.deserialize(data)
            setattr(r, field_name, v)
        return r, data

    def __repr__(self):
        r = '<%s ' % (self.__class__.__name__, )
        r += ' '.join(
            ['%s=%s' % (f[0], getattr(self, f[0], None)) for f in self._fields]
        )
        r += '>'
        return r


class DeconzAddress(Struct):
    _fields = [
        # The address format (AddressMode)
        ('address_mode', uint8_t),
        ('address', uint64_t),
    ]

    @classmethod
    def deserialize(cls, data):
        r = cls()
        mode, data = data[0], data[1:]
        setattr(r, cls._fields[0][0], mode)
        v = None
        if mode in [ADDRESS_MODE.GROUP, ADDRESS_MODE.NWK]:
            v, data = uint16_t.deserialize(data)
        elif mode == ADDRESS_MODE.IEEE:
            v, data = uint64_t.deserialize(data)
        setattr(r, cls._fields[1][0], v)
        return r, data
