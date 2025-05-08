"""Data types module."""


import zigpy.types as zigpy_t
from zigpy.types import (  # noqa: F401
    EUI64,
    NWK,
    ExtendedPanId,
    IntStruct,
    LongOctetString,
    LVBytes,
    LVList,
    PanId,
    Struct,
    bitmap3,
    bitmap5,
    bitmap6,
    bitmap8,
    bitmap16,
    enum2,
    enum3,
    enum8,
    int8s,
    uint8_t,
    uint16_t,
    uint32_t,
    uint64_t,
)


def serialize_dict(data, schema):
    chunks = []

    for key in schema:
        value = data[key]
        if value is None:
            break

        if not isinstance(value, schema[key]):
            value = schema[key](value)

        chunks.append(value.serialize())

    return b"".join(chunks)


def deserialize_dict(data, schema):
    result = {}
    for name, type_ in schema.items():
        try:
            result[name], data = type_.deserialize(data)
        except ValueError:
            if data:
                raise

            result[name] = None
    return result, data


def list_replace(lst: list, old: object, new: object) -> list:
    """Replace all occurrences of `old` with `new` in `lst`."""
    return [new if x == old else x for x in lst]


class Bytes(bytes):
    def serialize(self):
        return self

    @classmethod
    def deserialize(cls, data):
        return cls(data), b""


class AddressMode(enum8):
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


class NWKList(LVList):
    _length_type = uint8_t
    _item_type = NWK


ZIGPY_ADDR_MODE_MAPPING = {
    zigpy_t.AddrMode.NWK: AddressMode.NWK,
    zigpy_t.AddrMode.IEEE: AddressMode.IEEE,
    zigpy_t.AddrMode.Group: AddressMode.GROUP,
    zigpy_t.AddrMode.Broadcast: AddressMode.NWK,
}


ZIGPY_ADDR_TYPE_MAPPING = {
    zigpy_t.AddrMode.NWK: NWK,
    zigpy_t.AddrMode.IEEE: EUI64,
    zigpy_t.AddrMode.Group: NWK,
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
    address_mode: AddressMode
    address: EUI64
    ieee: EUI64

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
        r = self.address_mode.serialize() + self.address.serialize()
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
    address_mode: AddressMode
    address: EUI64
    ieee: EUI64
    endpoint: uint8_t

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
            r += NWK(self.address).serialize()

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


class DataIndicationFlags(bitmap8):
    Always_Use_NWK_Source_Addr = 0b00000001
    Last_Hop_In_Reserved_Bytes = 0b00000010
    Include_Both_NWK_And_IEEE = 0b00000100
