from . import *

from socket import AF_INET, AF_INET6

from .. import (
    IPPROTO_TCP,
    IPPROTO_UDP,
    IPPROTO_UDPLITE,
    IPPROTO_ICMP,
    IPPROTO_ICMPV6,
    IPPROTO_SCTP,
    IPPROTO_GRE,
    IPPROTO_DCCP
)

IPCTNL_MSG_CT_NEW             = 0
IPCTNL_MSG_CT_GET             = 1
IPCTNL_MSG_CT_DELETE          = 2
IPCTNL_MSG_CT_GET_CTRZERO     = 3
IPCTNL_MSG_CT_GET_STATS_CPU   = 4
IPCTNL_MSG_CT_GET_STATS       = 5
IPCTNL_MSG_CT_GET_DYING       = 6
IPCTNL_MSG_CT_GET_UNCONFIRMED = 7
IPCTNL_MSG_MAX                = 8

IPCTNL_MSG_EXP_NEW           = 0
IPCTNL_MSG_EXP_GET           = 1
IPCTNL_MSG_EXP_DELETE        = 2
IPCTNL_MSG_EXP_GET_STATS_CPU = 3
IPCTNL_MSG_EXP_MAX           = 4

# Attribute types
CTA_UNSPEC            = 0
CTA_TUPLE_ORIG        = 1
CTA_TUPLE_REPLY       = 2
CTA_STATUS            = 3
CTA_PROTOINFO         = 4
CTA_HELP              = 5
CTA_NAT_SRC           = 6
CTA_NAT               = CTA_NAT_SRC
CTA_TIMEOUT           = 7
CTA_MARK              = 8
CTA_COUNTERS_ORIG     = 9
CTA_COUNTERS_REPLY    = 10
CTA_USE               = 11
CTA_ID                = 12
CTA_NAT_DST           = 13
CTA_TUPLE_MASTER      = 14
CTA_NAT_SEQ_ADJ_ORIG  = 15
CTA_NAT_SEQ_ADJ_REPLY = 16
CTA_SECMARK           = 17 # Obsolete
CTA_ZONE              = 18
CTA_SECCTX            = 19
CTA_TIMESTAMP         = 20
CTA_MARK_MASK         = 21
CTA_LABELS            = 22
CTA_LABELS_MASK       = 23

# Tuple attribute types
CTA_TUPLE_UNSPEC = 0
CTA_TUPLE_IP 	 = 1
CTA_TUPLE_PROTO  = 2

# IP attribute types
CTA_IP_UNSPEC = 0 
CTA_IP_V4_SRC = 1
CTA_IP_V4_DST = 2
CTA_IP_V6_SRC = 3 
CTA_IP_V6_DST = 4

# Protocol attribute types
CTA_PROTO_UNSPEC      = 0
CTA_PROTO_NUM         = 1
CTA_PROTO_SRC_PORT    = 2
CTA_PROTO_DST_PORT    = 3
CTA_PROTO_ICMP_ID     = 4
CTA_PROTO_ICMP_TYPE   = 5
CTA_PROTO_ICMP_CODE   = 6
CTA_PROTO_ICMPV6_ID   = 7
CTA_PROTO_ICMPV6_TYPE = 8
CTA_PROTO_ICMPV6_CODE = 9

# It's an expected connection: bit 0 set.  This bit never changed
IPS_EXPECTED_BIT = 0
IPS_EXPECTED = (1 << IPS_EXPECTED_BIT)

# We've seen packets both ways: bit 1 set.  Can be set, not unset.
IPS_SEEN_REPLY_BIT = 1
IPS_SEEN_REPLY = (1 << IPS_SEEN_REPLY_BIT)

# Conntrack should never be early-expired.
IPS_ASSURED_BIT = 2
IPS_ASSURED = (1 << IPS_ASSURED_BIT)

# Connection is confirmed: originating packet has left box
IPS_CONFIRMED_BIT = 3
IPS_CONFIRMED = (1 << IPS_CONFIRMED_BIT)

# Connection needs src nat in orig dir.  This bit never changed.
IPS_SRC_NAT_BIT = 4
IPS_SRC_NAT = (1 << IPS_SRC_NAT_BIT)

# Connection needs dst nat in orig dir.  This bit never changed.
IPS_DST_NAT_BIT = 5
IPS_DST_NAT = (1 << IPS_DST_NAT_BIT)

# Both together.
IPS_NAT_MASK = (IPS_DST_NAT | IPS_SRC_NAT)

# Connection needs TCP sequence adjusted.
IPS_SEQ_ADJUST_BIT = 6
IPS_SEQ_ADJUST = (1 << IPS_SEQ_ADJUST_BIT)

# NAT initialization bits.
IPS_SRC_NAT_DONE_BIT = 7
IPS_SRC_NAT_DONE = (1 << IPS_SRC_NAT_DONE_BIT)

IPS_DST_NAT_DONE_BIT = 8
IPS_DST_NAT_DONE = (1 << IPS_DST_NAT_DONE_BIT)

# Both together
IPS_NAT_DONE_MASK = (IPS_DST_NAT_DONE | IPS_SRC_NAT_DONE)

# Connection is dying (removed from lists), can not be unset.
IPS_DYING_BIT = 9
IPS_DYING = (1 << IPS_DYING_BIT)

# Connection has fixed timeout.
IPS_FIXED_TIMEOUT_BIT = 10
IPS_FIXED_TIMEOUT = (1 << IPS_FIXED_TIMEOUT_BIT)

l3proto2str = {
    AF_INET     : "ipv4",
    AF_INET6    : "ipv6"
}

proto2str = {
    IPPROTO_TCP            : "tcp",
    IPPROTO_UDP            : "udp",
    IPPROTO_UDPLITE        : "udplite",
    IPPROTO_ICMP           : "icmp",
    IPPROTO_ICMPV6         : "icmpv6",
    IPPROTO_SCTP           : "sctp",
    IPPROTO_GRE            : "gre",
    IPPROTO_DCCP           : "dccp"
}