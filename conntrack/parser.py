from collections import namedtuple
import socket
import struct

from pymnl.attributes import AttrParser

from . import *

class ConnectionTuple(object):

    family = None

    protonum = None

    src_addr = None
    src_proto = None

    dst_addr = None
    dst_proto = None

    @property
    def protocol(self):
        return proto2str.get(self.protonum, 'unknown')

    @property
    def source_ip(self):
        return socket.inet_ntop(self.family, self.src_addr) if self.src_addr else ''

    @property
    def destination_ip(self):
        return socket.inet_ntop(self.family, self.dst_addr) if self.dst_addr else ''

    def _repr_protocols(self):
        dst_attrs = self.dst_proto._asdict()
        src_attrs = self.src_proto._asdict()

        attrs = {}

        for (key, value) in dst_attrs.iteritems():
            if key in src_attrs:
                attrs['d%s' % key] = value
            else:
                attrs[key] = value

        for (key, value) in src_attrs.iteritems():
            if key in dst_attrs:
                attrs['s%s' % key] = value
            else:
                attrs[key] = value

        return ' '.join(['%s=%r' % i for i in attrs.iteritems()])

    def __str__(self):

        return '%s %d src=%s dst=%s %s' % (
            self.protocol,
            self.protonum,
            self.source_ip,
            self.destination_ip,
            self._repr_protocols()
        )

class Conntrack(object):

    status = 0

    origin = None

    reply = None

    @property
    def is_assured(self):
        return self.status & IPS_ASSURED

    @property
    def is_replied(self):
        return self.status & IPS_SEEN_REPLY

    def __str__(self):
        pieces = []

        if self.origin:
            pieces.append(str(self.origin))

        if not self.is_replied:
            pieces.append('[UNREPLIED]')

        if self.reply:
            pieces.append(str(self.reply))

        if self.is_assured:
            pieces.append('[ASSURED]')

        return ' '.join(pieces)

class ConntrackParser(AttrParser):

    def __init__(self, data_obj=None, offset=0):
        super(ConntrackParser, self).__init__()

        self._cb = {
            CTA_TUPLE_ORIG  : self.parse_orig,
            CTA_TUPLE_REPLY : self.parse_reply,
            CTA_STATUS      : self.parse_status,
            CTA_TIMEOUT     : self.parse_timeout,
            CTA_ID          : self.parse_id
        }

        if data_obj:
            self.parse(data_obj, offset)

    def unhandled_attribute_type(self, attr):
        print 'Unhandled attribute %d' % attr.get_type()

    def parse(self, data_obj, offset=0):
        conntrack_obj = Conntrack()

        for one_attr in self.parse_string(data_obj.get_binary(), offset):
            if one_attr.get_type() in self._cb:
                self._cb[one_attr.get_type()](conntrack_obj, one_attr)
            else:
                self.unhandled_attribute_type(one_attr)

        return conntrack_obj

    def parse_orig(self, conntrack_obj, attr):
        assert attr.is_nested()

        conntrack_obj.origin = self.parse_tuple(attr)

    def parse_reply(self, conntrack_obj, attr):
        assert attr.is_nested()

        conntrack_obj.reply = self.parse_tuple(attr)

    def parse_status(self, conntrack_obj, attr):
        conntrack_obj.status = socket.ntohl(attr.get_u32())

    def parse_timeout(self, conntrack_obj, attr):
        conntrack_obj.timeout = socket.ntohl(attr.get_u32())

    def parse_id(self, conntrack_obj, attr):
        conntrack_obj.id = socket.ntohl(attr.get_u32())

    def parse_tuple(self, attr):
        assert attr.is_nested()

        conn_tuple = ConnectionTuple()

        for attr in self.parse_nested(attr):
            if attr.get_type() == CTA_TUPLE_IP:
                conn_tuple.family, \
                conn_tuple.src_addr, \
                conn_tuple.dst_addr = self.parse_ip(attr)

            elif attr.get_type() == CTA_TUPLE_PROTO:
                conn_tuple.protonum, \
                conn_tuple.src_proto, \
                conn_tuple.dst_proto = self.parse_proto(attr)

        return conn_tuple

    def parse_ip(self, ip_attr):
        assert ip_attr.is_nested()

        src = dst = family = None

        for attr in self.parse_nested(ip_attr):

            attr_type = attr.get_type()

            if not family:
                if attr_type in (CTA_IP_V4_DST, CTA_IP_V4_SRC):
                    family = socket.AF_INET
                elif attr_type in (CTA_IP_V6_DST, CTA_IP_V6_SRC):
                    family = socket.AF_INET6

            if attr_type in (CTA_IP_V4_SRC, CTA_IP_V6_SRC):
                src = attr.get_data()

            elif attr_type in (CTA_IP_V4_DST, CTA_IP_V6_DST):
                dst = attr.get_data()

        return family, src, dst

    def parse_proto(self, proto_attr):
        l4src_attrs = {}
        l4dst_attrs = {}

        protonum = None

        for attr in self.parse_nested(proto_attr):
            if attr.get_type() == CTA_PROTO_NUM:
                protonum = attr.get_u8()
            else:
                if attr.get_type() == CTA_PROTO_DST_PORT:
                    l4dst_attrs['port'] = socket.htons(attr.get_u16())

                elif attr.get_type() == CTA_PROTO_SRC_PORT:
                    l4src_attrs['port'] = socket.htons(attr.get_u16())


                elif attr.get_type() == CTA_PROTO_ICMP_TYPE:
                    l4dst_attrs['type'] = attr.get_u8()

                elif attr.get_type() == CTA_PROTO_ICMP_CODE:
                    l4dst_attrs['code'] = attr.get_u8()

                elif attr.get_type() == CTA_PROTO_ICMP_ID:
                    l4src_attrs['id'] = socket.htons(attr.get_u16())


                elif attr.get_type() == CTA_PROTO_ICMPV6_TYPE:
                    l4dst_attrs['type'] = attr.get_u8()

                elif attr.get_type() == CTA_PROTO_ICMPV6_CODE:
                    l4dst_attrs['code'] = attr.get_u8()

                elif attr.get_type() == CTA_PROTO_ICMPV6_ID:
                    l4src_attrs['id'] = socket.htons(attr.get_u16())


        proto_name = proto2str.get(protonum, 'unknown') if protonum else 'unknown'

        l4src = namedtuple(proto_name, l4src_attrs.keys())(**l4src_attrs)
        l4dst = namedtuple(proto_name, l4dst_attrs.keys())(**l4dst_attrs)

        return protonum, l4src, l4dst

