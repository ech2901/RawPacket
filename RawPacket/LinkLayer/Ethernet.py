from dataclasses import dataclass, field
from struct import pack, unpack

from RawPacket.BaseClasses import LinkLayerPacket, InternetLayerPacket
from RawPacket.Tags import EtherType
from RawPacket.MACAddress import MACAddress

@dataclass(init=False)
class Ethernet(LinkLayerPacket):

    destination: MACAddress
    source: MACAddress
    vlan_tag: EtherType
    ethertype: EtherType
    payload: InternetLayerPacket

    identifier: int = 1

    def __init__(self, destination: MACAddress, source: MACAddress, payload: InternetLayerPacket, **kwargs):
        LinkLayerPacket.__init__(self)

        self.destination = destination
        self.source = source
        self.vlan_tag = kwargs.get('vlan_tag', None)
        self.ethertype = kwargs.get('type', payload.identifier)
        self.payload = payload

    def build(self):
        if (self.vlan_tag):
            header = pack('! 6s 6s L H', self.destination, self.source,
                          self.vlan_tag.value, self.ethertype.value)
        else:
            header = pack('! 6s 6s H', self.destination.packed, self.source.packed, self.ethertype.value)

        return header + self.payload.build()

    @classmethod
    def disassemble(cls, packet: bytes):
        """
        Disassemble a ethernet packet for inspection.
        Can be used to build a packet later.

        :param packet: bytes: Ethernet packet to disassemble
        :return: dict
        """
        out = dict()

        ethe_tag_test = int.from_bytes(packet[12:14], 'big')
        if ethe_tag_test == EtherType.VLAN or ethe_tag_test == EtherType.SERVICE_VLAN:
            keys = ('destination', 'source', 'tag', 'type')
            values = unpack('! 6s 6s L H', packet[:18])
            out['payload'] = InternetLayerPacket.classes[values[-1]].disassemble(packet[18:])
        else:
            keys = ('destination', 'source', 'type')
            values = unpack('! 6s 6s H', packet[:14])
            out['payload'] = InternetLayerPacket.classes[values[-1]].disassemble(packet[14:])

        for key, value in zip(keys, values):
            if key in ('source', 'destination'):
                out[key] = MACAddress(value)
            else:
                out[key] = EtherType(value)

        return cls(**out)

    def swap(self):
        self.destination, self.source = self.source, self.destination
        self.payload.swap()

    def calc_checksum(self, *, data=b''):
        self.payload.calc_checksum()

    def __len__(self):
        if self.vlan_tag:
            return 18 + len(self.payload)
        return 14 + len(self.payload)
