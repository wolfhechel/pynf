import struct
from pymnl.message import NLMSG_MIN_TYPE, NLMSG_ALIGN

from socket import (
    IPPROTO_TCP,
    IPPROTO_UDP,
    IPPROTO_ICMP,
    IPPROTO_ICMPV6
)

IPPROTO_DCCP    =  33 # Datagram Congestion Control Protocol
IPPROTO_GRE     =  47 # Cisco GRE tunnels (rfc 1701,1702)
IPPROTO_SCTP    = 132 # Stream Control Transport Protocol
IPPROTO_UDPLITE = 136 # UDP-Lite (RFC 3828)

# General form of address family dependent message.
NFNL_HDRFMT = 'BBH'
NFNL_HDRLEN = NLMSG_ALIGN(struct.calcsize(NFNL_HDRFMT))

# Reserved control nfnetlink messages
NFNL_MSG_BATCH_BEGIN           = NLMSG_MIN_TYPE
NFNL_MSG_BATCH_END             = NLMSG_MIN_TYPE + 1

# nfnetlink_groups
NFNLGRP_NONE = 0x0
NFNLGRP_CONNTRACK_NEW = 0x1
NFNLGRP_CONNTRACK_UPDATE = 0x2
NFNLGRP_CONNTRACK_DESTROY = 0x3
NFNLGRP_CONNTRACK_EXP_NEW = 0x4
NFNLGRP_CONNTRACK_EXP_UPDATE = 0x5
NFNLGRP_CONNTRACK_EXP_DESTROY = 0x6
NFNLGRP_NFTABLES = 0x7

NFNL_SUBSYS_NONE               = 0
NFNL_SUBSYS_CTNETLINK          = 1
NFNL_SUBSYS_CTNETLINK_EXP      = 2
NFNL_SUBSYS_QUEUE              = 3
NFNL_SUBSYS_ULOG               = 4
NFNL_SUBSYS_OSF                = 5
NFNL_SUBSYS_IPSET              = 6
NFNL_SUBSYS_ACCT               = 7
NFNL_SUBSYS_CTNETLINK_TIMEOUT  = 8
NFNL_SUBSYS_CTHELPER           = 9
NFNL_SUBSYS_NFTABLES           = 10
NFNL_SUBSYS_NFT_COMPAT         = 11
NFNL_SUBSYS_COUNT              = 12

NF_NETLINK_CONNTRACK_NEW              = 0x00000001
NF_NETLINK_CONNTRACK_UPDATE           = 0x00000002
NF_NETLINK_CONNTRACK_DESTROY          = 0x00000004
NF_NETLINK_CONNTRACK_EXP_NEW          = 0x00000008
NF_NETLINK_CONNTRACK_EXP_UPDATE       = 0x00000010
NF_NETLINK_CONNTRACK_EXP_DESTROY      = 0x00000020

NFNETLINK_V0 = 0

# netfilter netlink message types are split in two pieces: 8 bit subsystem, 8bit operation.
def NFNL_SUBSYS_ID(x):
    return ((x & 0xff00) >> 8)

def NFNL_MSG_TYPE(x):
    return (x & 0x00ff)