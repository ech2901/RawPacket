from typing import Dict
from struct import unpack


class MetaPacket(type):

    def __new__(mcs, *args, **kwargs):
        name, superclasses, dictionary, *args = args
        cls = type(name, superclasses, {
                                **dictionary,
                                '__init_subclass__': mcs.__register_identifier__,
                                'classes': dict()
                                        }
                   )

        return cls

    def __register_identifier__(cls):

        if cls.identifier >= 0:
            # super().__init_subclass__()
            cls.classes[cls.identifier] = cls

        for key in ('identifier', 'format'):
            if key in cls.__dict__['__annotations__']:
                del cls.__dict__['__annotations__'][key]


class BasePacket(object):

    classes: Dict = None
    format: str = ''
    identifier: int = -1

    def build(self):
        pass

    @classmethod
    def disassemble(cls, packet: bytes):
        pass

    def calc_checksum(self, *, data=b''):
        pass

    def _calc_compliment_(self, data):
        out = 0

        if len(data) % 2 != 0:
            # Make sure there is an even number of bytes
            data = data + b'\x00'

        # unpack all the bytes into 2 byte integers
        values = unpack(f'! {len(data) // 2}H', data)
        # Sum values together
        out = out + sum(values)

        while out > 0xffff:
            # If sum is bigger than 2 bytes, add the overflow to the sum
            out = (out & 0xffff) + (out >> 16)

        # Calculate the compliment of the sum to get the checksum.
        compliment = -out % 0xffff

        if compliment:
            return compliment

        # If the checksum is calculated to be zero, set to 0xFFFF
        return 0xffff

    def __len__(self):
        pass

    def swap(self):
        pass


class LinkLayerPacket(BasePacket, metaclass=MetaPacket):
    pass


class InternetLayerPacket(BasePacket, metaclass=MetaPacket):
    pass

class ProtocolLayerPacket(BasePacket, metaclass=MetaPacket):
    pass
