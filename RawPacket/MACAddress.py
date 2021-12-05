from struct import pack


class MACAddress(object):
    def __init__(self, address):
        if type(address) == int:
            self.packed = address.to_bytes(6, 'big')
            self.address = ':'.join([hex(i)[2:].rjust(2, '0') for i in self.packed])
            self._address = address
        elif type(address) == bytes:
            self.packed = address
            self.address = ':'.join([hex(i)[2:].rjust(2, '0') for i in self.packed])
            self._address = int.from_bytes(address, 'big')
        elif type(address) == str:
            self.packed = pack('! 6B', *[int(i, 16) for i in address.split(':')])
            self.address = address
            self._address = int.from_bytes(self.packed, 'big')
        elif type(address) == MACAddress:
            self.packed = address.packed
            self.address = address.address
            self._address = address._address
        else:
            raise TypeError(
                f'Argument <address> must be of type bytes, int, or str but type {type(address)} was provided.')

    def __repr__(self):
        return f"MAC_Address('{self.address}')"

    def __str__(self):
        return self.address

    def __eq__(self, other):
        if type(other) == MACAddress:
            return self._address == other._address
        else:
            return self == MACAddress(other)

    def __hash__(self):
        return hash(self._address)
