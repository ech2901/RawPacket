from enum import IntEnum

class EtherType(IntEnum):
    IP4 = 0x0800
    ARP = 0X0806
    WAKE_ON_LAN = 0X0842
    AVTP = 0X22F0
    TRILL = 0X22F3
    STREAM_RESERVATION = 0X22EA
    DEC_MOP = 0X6002
    DECNET_IV = 0X6003
    DEC_LAT = 0X6004
    RARP = 0X8025
    APPLETALK = 0X809B
    AARP = 0X80F3
    VLAN = 0X8100
    SLPP = 0X8102
    VLACP = 0X8103
    IPX = 0X8137
    QNX_QNET = 0X8204
    IP6 = 0X86DD
    ETHERNET_FLOW_CONTROL = 0X8808
    ETHERNET_SLOW_PROTOCOLS = 0X8809
    COBRANET = 0X8819
    MPLS_UNICAST = 0X8847
    MPLS_MULTICAST = 0X8848
    PPPOE_DISCOVERY = 0X8863
    PPPOE_SESSION = 0X8864
    HOMEPLUG = 0X8878
    EAP_OVER_LAN = 0X888E
    PROFINET = 0X8892
    HYPERSCSI = 0X889A
    ATA_OVER_ETHERNET = 0X88A2
    ETHERCAT = 0X88A4
    SERVICE_VLAN = 0X88A8
    ETHERNET_POWERLINK = 0X88AB
    GOOSE = 0X8888
    GSE = 0X8889
    SV = 0X88BA
    MIKROTIK = 0X88BF
    LLDP = 0X88CC
    SERCOS_III = 0X88CD
    HOMEPLUG_GREEN = 0X88E1
    MEDIA_REDUNDANCY_PROTOCOL = 0X88E3
    MACSEC = 0X88E5
    PBB = 0X88E7
    PTP = 0X88F7
    NCSI = 0X88F8
    PRP = 0X88F8
    CFM = 0X8902
    FCOE = 0X8906
    FCOE_INITIALIZATION = 0X8914
    ROCE = 0X8915
    TTETHERNET_CONTROL_FRAME = 0X891D
    PROTOCOL_1905_1 = 0X893A
    HSR = 0X892F
    ETHERNET_CONFIG_TESTING = 0X9000
    REDUNDANCY_TAG = 0XF1C1


class IPProtocol(IntEnum):
    HOPOPT = 0X00
    ICMP = 0X01
    IGMP = 0X02
    GGP = 0X03
    IP_IN_IP = 0X04
    ST = 0X05
    TCP = 0X06
    CBT = 0X07
    EGP = 0X08
    IGP = 0X09
    BBN_RCC_MON = 0X0A
    NVP_II = 0X0B
    PUP = 0X0C
    ARGUS = 0X0D
    EMCON = 0X0E
    XNET = 0X0F
    CHAOS = 0X10
    UDP = 0X11
    MUX = 0X12
    DCN_MEAS = 0X13
    HMP = 0X14
    PRM = 0X15
    XNS_IDP = 0X16
    TRUNK_1 = 0X17
    TRUNK_2 = 0X18
    LEAF_1 = 0X19
    LEAF_2 = 0X1A
    RDP = 0X1B
    IRTP = 0X1C
    ISO_TP4 = 0X1D
    NETBLT = 0X1E
    MFE_NSP = 0X1F
    MERIT_INP = 0X20
    DCCP = 0X21
    THREEPC = 0X22
    IDPR = 0X23
    XTP = 0X24
    DDP = 0X25
    IDPR_CMTP = 0X26
    TP_PLUS_PLUS = 0X27
    IL = 0X28
    IP6 = 0X29
    SDRP = 0X2A
    IP6_ROUTE = 0X2B
    IP6_FLAG = 0X2C
    IDRP = 0X2D
    RSVP = 0X2E
    GRE = 0X2F
    DSR = 0X30
    BNA = 0X31
    ESP = 0X32
    AH = 0X33
    I_NLSP = 0X34
    SWIPE = 0X35
    NARP = 0X36
    MOBILE = 0X37
    TLSP = 0X38
    SKIP = 0X39
    IP6_ICMP = 0X3A
    IP6_NONXT = 0X3B
    IP6_OPTS = 0X3C
    ANY_HOST = 0X3D
    CFTP = 0X3E
    ANY_LOCAL = 0X3F
    SAT_EXPAK = 0X40
    KRYPTOLAN = 0X41
    RVD = 0X42
    IPPC = 0X43
    ANY_DISTRIBUTED_FS = 0X44
    SAT_MON = 0X45
    VISA = 0X46
    IPCU = 0X47
    CPNX = 0X48
    CPHB = 0X49
    WSN = 0X4A
    PVP = 0X4B
    BR_SAT_MON = 0X4C
    SUN_ND = 0X4D
    WB_MON = 0X4E
    WB_EXPAK = 0X4F
    ISO_IP = 0X50
    VMTP = 0X51
    SECURE_VMTP = 0X52
    VINES = 0X53
    TTP_IPTM = 0X54
    NSFNET_IGP = 0X55
    DGP = 0X56
    TCF = 0X57
    EIGRP = 0X58
    OSPF = 0X59
    SPRITE_RPC = 0X5A
    LARP = 0X5B
    MTP =0X5C
    AX_25 = 0X5D
    OS = 0X5E
    MICP = 0X5F
    SCC_SP = 0X60
    ETHERIP = 0X61
    ENCAP = 0X62
    ANY_PRIVATE_ENCRYPTION_SCHEME = 0X63
    GMTP = 0X64
    IFMP = 0X65
    PNNI = 0X66
    PIM = 0X67
    ARIS = 0X68
    SCPS = 0X69
    QNX = 0X6A
    AN = 0X6B
    IPCOMP = 0X6C
    SNP = 0X6D
    COMPAQ_PEER = 0X6E
    IPX_IN_IP = 0X6F
    VRRP = 0X70
    PGM = 0X71
    ANY_0_HOP = 0X72
    L2TP = 0X73
    DDX = 0X74
    IATP = 0X75
    STP = 0X76
    SRP = 0X77
    UTI = 0X78
    SMP = 0X79
    SM = 0X7A
    PTP = 0X7B
    IS_IS_OVER_IPV4 = 0X7C
    FIRE = 0X7D
    CRTP = 0X7E
    CRUDP = 0X7F
    SSCOPMCE = 0X80
    IPLT = 0X81
    SPS = 0X82
    PIPE = 0X83
    SCTP = 0X84
    FC = 0X85
    RSVP_E2E_IGNORE = 0X86
    MOBILITY_HEADER = 0X87
    UDPLITE = 0X88
    MPLS_IN_IP = 0X89
    MANET = 0X8A
    HIP = 0X8B
    SHIM6 = 0X8C
    WESP = 0X8D
    ROHC = 0X8E
    ETHERNET = 0X8F