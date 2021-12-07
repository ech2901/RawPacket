from struct import pack, unpack
from dataclasses import dataclass

from RawPacket.BaseClasses import ProtocolLayerPacket
from RawPacket.Tags import IPProtocol


@dataclass(init=False)
class UDP(ProtocolLayerPacket):

    source: int
    destination: int
    length: int
    checksum: int
    payload: bytes

    format: str = '! 4H'
    identifier: int = IPProtocol.UDP

    def __init__(self, source: int, destination: int, payload: bytes, **kwargs):
        ProtocolLayerPacket.__init__(self)
        self.source = source
        self.destination = destination
        self.length = kwargs.get('length', 8 + len(payload))
        self.checksum = kwargs.get('checksum', 0)
        self.payload = payload

    def build(self):
        header = pack(self.format, self.source, self.destination,
                      self.length, self.checksum)

        return header + self.payload

    @classmethod
    def disassemble(cls, packet: bytes):
        """
        Disassemble a UDP packet for inspection.

        :param packet: bytes: UDP packet to disassemble
        :return: dict
        """

        out = dict()

        keys = ('source', 'destination', 'length', 'checksum')
        values = unpack(cls.format, packet[:8])

        for key, value in zip(keys, values):
            out[key] = value

        out['payload'] = packet[8:]

        return cls(**out)

    def calc_checksum(self, *, data=b''):
        self.checksum = self._calc_compliment_(data + self.build())

    def __len__(self):
        return self.length

    def swap(self):
        self.destination, self.source = self.source, self.destination