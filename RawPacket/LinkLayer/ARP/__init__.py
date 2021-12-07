from dataclasses import dataclass, field
from ipaddress import IPv4Address
from struct import pack, unpack

from RawPacket.BaseClasses import LinkLayerPacket, ProtocolLayerPacket
from RawPacket.Tags import EtherType
from RawPacket.MACAddress import MACAddress
from .HType import HType
from .Operation import Operation

@dataclass(init=False)
class ARP(LinkLayerPacket):

    htype: HType  # Type of hardware
    ptype: EtherType  # IPv4 vs other protocols
    hlen: int  # byte count of hardware addresses
    plen: int  # byte count of protocol addresses
    operation: Operation  # 1 for request, 2 for reply
    sender_hardware_address: MACAddress  # Might be other things but most basic case it should be this
    sender_protocol_address: IPv4Address  # Might be other things but most basic case should be this
    target_hardware_address: MACAddress  # Might be other things but most basic case it should be this
    target_protocol_address: IPv4Address  # Might be other things but most basic case should be this

    identifier: int = EtherType.ARP
    format: str = '! 2H 2B H'

    def __init__(self, sender_hw_addr: MACAddress, sender_proto_addr, target_proto_addr,  **kwargs):
        LinkLayerPacket.__init__(self)

        self.htype = kwargs.get('htype', HType.ETHERNET)
        self.ptype = kwargs.get('ptype', EtherType.IP4)
        self.hlen = kwargs.get('hlen', 6)
        self.plen = kwargs.get('plen', 4)
        self.operation = kwargs.get('operation', Operation.REQUEST)
        self.sender_hardware_address = sender_hw_addr
        self.sender_protocol_address = sender_proto_addr
        self.target_hardware_address = kwargs.get('target_hw_addr', MACAddress(0))
        self.target_protocol_address = target_proto_addr

        # Verify the byte count of sender and target hardware are as expected
        if self.hlen == len(self.sender_hardware_address.packed) == len(self.target_hardware_address.packed):
            pass
        else:
            print(self.hlen, self.sender_hardware_address, self.target_hardware_address)
            raise ValueError

        # Verify the byte count of sender and target protocols are as expected
        if self.plen == len(self.sender_protocol_address.packed) == len(self.target_protocol_address.packed):
            pass
        else:
            raise ValueError


    def build(self):
        out = pack(self.format, self.htype, self.ptype, self.hlen, self.plen, self.operation)
        out = pack(f'! {len(out)}s {self.hlen}s {self.plen}s {self.hlen}s {self.plen}s',
                   out,
                   self.sender_hardware_address.packed,
                   self.sender_protocol_address.packed,
                   self.target_hardware_address.packed,
                   self.target_protocol_address.packed
                   )
        return out

    @classmethod
    def disassemble(cls, packet: bytes):
        htype, ptype, hlen, plen, operation = unpack(cls.format, packet[:8])
        sender_hardware = MACAddress(packet[8:8+hlen])
        sender_protocol = IPv4Address(packet[8+hlen: 8+hlen+plen])
        target_hardware = MACAddress(packet[8+hlen+plen:8+hlen+plen+hlen])
        target_protocol = IPv4Address(packet[8+hlen+plen+hlen: 8+hlen+plen+hlen+plen])

        return cls(
            htype=HType(htype),
            ptype=EtherType(ptype),
            hlen=hlen,
            plen=plen,
            operation=Operation(operation),
            sender_hw_addr=sender_hardware,
            sender_proto_addr=sender_protocol,
            target_hw_addr=target_hardware,
            target_proto_addr=target_protocol
                   )


    def __len__(self):
        return 8 + (2*self.hlen) + (2*self.plen)

    def swap(self):
        self.sender_hardware_address, self.target_hardware_address = self.target_hardware_address, self.sender_hardware_address
        self.sender_protocol_address, self.target_protocol_address = self.target_protocol_address, self.sender_protocol_address