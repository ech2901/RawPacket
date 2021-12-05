from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address
from struct import pack, unpack

from RawPacket.BaseClasses import InternetLayerPacket, ProtocolLayerPacket
from RawPacket.Tags import EtherType


@dataclass(init=False)
class IPv4(InternetLayerPacket):

    source: IPv4Address
    destination: IPv4Address
    version: int = field(default=4, init=False)
    ihl: int
    dscp: int
    ecn: int
    length: int
    id: int
    flags: int
    offset: int
    ttl: int
    protocol: int
    checksum: int
    options: bytes

    payload: ProtocolLayerPacket

    format: str = '! 2B 3H 2B H 4s 4s'
    identifier: int = EtherType.IP4

    def __init__(self, source: IPv4Address, destination: IPv4Address, payload: ProtocolLayerPacket, **kwargs):
        InternetLayerPacket.__init__(self)

        self.source = source
        self.destination = destination
        # version would go here if it wasn't static
        self.ihl = kwargs.get('ihl', 5)
        self.dscp = kwargs.get('dscp', 0)
        self.ecn = kwargs.get('ecn', 0)
        self.length = kwargs.get('length', (self.ihl * 4) + len(payload))
        self.id = kwargs.get('id', 0)
        self.flags = kwargs.get('flags', 0)
        self.offset = kwargs.get('offset', 0)
        self.ttl = kwargs.get('ttl', 255)
        self.protocol = kwargs.get('protocol', payload.identifier)
        self.checksum = kwargs.get('checksum', 0)
        self.options = kwargs.get('options', b'')

        self.payload = payload

    def build(self):
        ihl_ver = (self.version << 4) | self.ihl
        dscp_ecn = (self.dscp << 2) | self.ecn
        flag_offset = (self.flags << 13) | self.offset

        header = pack(self.format,
                      ihl_ver, dscp_ecn, self.length, self.id,
                      flag_offset, self.ttl, self.protocol,
                      self.checksum, self.source.packed,
                      self.destination.packed)

        return header + self.options + self.payload.build()

    @classmethod
    def disassemble(cls, packet: bytes):
        out = dict()

        keys = ('ver_ihl', 'dscp_ecn', 'length', 'id', 'flags_offset', 'ttl', 'protocol',
                'checksum', 'source', 'destination')
        values = unpack(cls.format, packet[:20])

        for key, value in zip(keys, values):
            if key == 'ver_ihl':
                out['ihl'] = value & 0x0f
            elif key == 'dscp_ecn':
                out['dscp'] = value >> 2
                out['ecn'] = value & 0x03
            elif key == 'flags_offset':
                out['flags'] = value >> 13
                out['offset'] = value & (0xffff >> 3)
            elif key in ('source', 'destination'):
                out[key] = IPv4Address(value)
            else:
                out[key] = value

        out['options'] = packet[20:out['ihl'] * 4]  # If header has options capture them

        # Get the payload of the IP packet
        out['payload'] = ProtocolLayerPacket.classes[out['protocol']].disassemble(packet[out['ihl'] * 4:])

        return cls(**out)

    def calc_checksum(self, *, data=b''):
        pseudo_header = self.source.packed + self.destination.packed
        pseudo_header = pseudo_header + pack('! 2B H', 0, self.protocol, len(self.payload))
        self.payload.calc_checksum(data=pseudo_header)

        calc_bytes = self.build()[:self.ihl * 4]

        self.checksum = self._calc_compliment_(calc_bytes)

    def __len__(self):
        return self.length

    def swap(self):
        self.destination, self.source = self.source, self.destination
        self.payload.swap()


@dataclass(init=False)
class IPv6(InternetLayerPacket):

    source: IPv6Address
    destination: IPv6Address
    version: int = field(default=6, init=False)
    ds: int
    ecn: int
    label: int
    length: int  # Length of payload
    next_header: int
    limit: int
    payload: ProtocolLayerPacket

    format = '! L H 2B 16s 16s'
    identifier = EtherType.IP6

    def __init__(self, source: IPv6Address, destination: IPv6Address, payload: ProtocolLayerPacket, **kwargs):
        self.source = source
        self.destination = destination
        # version would go here if it wasn't static
        self.ds = kwargs.get('ds', 0)
        self.ecn = kwargs.get('ecn', 0)
        self.label = kwargs.get('label', 0)
        self.length = kwargs.get('length', len(payload))
        self.next_header = kwargs.get('next_header', payload.identifier)
        self.limit = kwargs.get('limit', 255)

        self.payload = payload

    def build(self):
        ver_class_label = (self.version << 28) + (self.ds << 22)
        ver_class_label = ver_class_label + (self.ecn << 20) + self.label

        header = pack(self.format, ver_class_label, self.length,
                      self.next_header, self.limit, self.source, self.destination
                      )

        return header + self.payload.build()

    @classmethod
    def disassemble(cls, packet: bytes):
        out = dict()

        keys = ('ver_class_label', 'length', 'next_header', 'limit', 'source', 'destination')
        values = unpack(cls.format, packet[:40])

        for key, value in zip(keys, values):
            if key == 'ver_class_label':
                out['ds'] = (value >> 22) & 0x3f
                out['ecn'] = (value >> 20) & 0x03
                out['label'] = value & 0xf_ffff
            elif key in ('source', 'destination'):
                out[key] = IPv6Address(value)
            else:
                out[key] = value

        out['payload'] = ProtocolLayerPacket.classes[out['next_header']].disassemble(packet[40:out['length']])

        return cls(**out)

    def calc_checksum(self, *, data=b''):
        psuedo_header = self.source.packed + self.destination.packed
        psuedo_header = psuedo_header + pack('! 2L', len(self.payload), self.next_header)

        self.payload.calc_checksum(data=psuedo_header)

    def __len__(self):
        return 40 + self.length

    def swap(self):
        self.destination, self.source = self.source, self.destination
        self.payload.swap()
