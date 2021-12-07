from enum import IntEnum

class HType(IntEnum):
    ETHERNET = 1
    EXPERIMENTAL_ETHERNET = 2
    AMATEUUR_RADIO = 3
    PROTEON_PRONET_TOKEN_RING = 4
    CHAOS = 5
    IEEE_802_NETWORKS = 6
    ARCNET = 7
    HYPERCHANNEL = 8
    LANSTAR = 9
    AUTONET_SHORT_ADDRESS = 10
    LOCALTALK = 11
    LOCALNET = 12
    ULTRA_LINK = 13
    SMDS = 14
    FRAME_RELAY = 15
    ATM_1 = 16
    HDLC = 17
    FIBRE_CHANNEL = 18
    ATM_2 = 19
    SERIAL_LINE = 20
    ATM_3 = 21
    MIL_STD_188_220 = 22
    METRICOM = 23
    IEEE_1394_1995 = 24
    MAPOS = 25
    TWINAXIAL = 26
    EUI_64 = 27
    HIPARP = 28
    IP_AND_ARP_OVER_ISO_7816_3 = 29
    ARPSEC = 30
    IPSEC_TUNNEL = 31
    INFINIBAND = 32
    TIA_102_CAI = 33
    WIEGAND_INTERFACE = 34
    PURE_IP = 35
    HW_EXP1 =36
    HFI = 37
    HW_EXP2 = 256
    AETHERNET = 257