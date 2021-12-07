from struct import pack, unpack
from dataclasses import dataclass

from RawPacket.BaseClasses import ProtocolLayerPacket
from RawPacket.Tags import IPProtocol


@dataclass(init=False)
class TCP(ProtocolLayerPacket):

    source: int
    destination: int
    seq: int
    ack_seq: int
    data_offset: int

    ns: bool
    cwr: bool
    ece: bool
    urg: bool
    ack: bool
    psh: bool
    rst: bool
    syn: bool
    fin: bool

    window: int
    checksum: int
    urg_pointer: int

    options: bytes

    payload: bytes

    format: str = '! 2H 2L 2B 3H'
    identifier: int = IPProtocol.TCP

    def __init__(self, source: int, destination: int, payload: bytes, **kwargs):
        ProtocolLayerPacket.__init__(self)
        self.source = source
        self.destination = destination
        self.seq = kwargs.get('seq', 0)
        self.ack_seq = kwargs.get('ack_seq', 0)
        self.data_offset = kwargs.get('offset', 5)

        # TCP Flags
        self.ns = kwargs.get('ns', False)
        self.cwr = kwargs.get('cwr', False)
        self.ece = kwargs.get('ece', False)
        self.urg = kwargs.get('urg', False)
        self.ack = kwargs.get('ack', False)
        self.psh = kwargs.get('psh', False)
        self.rst = kwargs.get('rst', False)
        self.syn = kwargs.get('syn', True)
        self.fin = kwargs.get('fin', False)

        self.window = kwargs.get('window', 5840)
        self.checksum = kwargs.get('checksum', 0)
        self.urg_pointer = kwargs.get('urg_pointer', 0)

        self.options = kwargs.get('options', b'')

        self.payload = payload

    def build(self):
        offset_ns = (self.data_offset << 4) | self.ns

        flags = 0
        for key in ('cwr', 'ece', 'urg', 'ack', 'psh', 'rst', 'syn', 'fin'):
            flags = (flags << 1) | getattr(self, key)

        header = pack(self.format, self.source, self.destination, self.seq,
                      self.ack_seq, offset_ns, flags,
                      self.window, self.checksum, self.urg_pointer
                      )

        return header + self.options + self.payload

    @classmethod
    def disassemble(cls, packet: bytes):
        out = dict()

        keys = ('source', 'destination', 'seq', 'ack_seq', 'offset_ns', 'flags', 'window', 'checksum', 'urg_pointer')
        values = unpack(cls.format, packet[:20])

        for key, value in zip(keys, values):
            if key == 'offset_ns':
                out['offset'] = value >> 4
                out['ns'] = bool(value & 0x01)
            elif key == 'flags':
                for flag in ('fin', 'syn', 'rst', 'psh', 'ack', 'urg', 'ece', 'cwr'):
                    out[flag] = bool(value & 0x01)
                    value = value >> 1
            else:
                out[key] = value

        out['options'] = packet[20:out['offset'] * 4]
        out['payload'] = packet[out['offset'] * 4:]

        return cls(**out)

    def calc_checksum(self, *, data=b''):
        self.checksum = self._calc_compliment_(data + self.build())

    def __len__(self):
        return (self.data_offset * 4) + len(self.payload)

    def swap(self):
        self.destination, self.source = self.source, self.destination