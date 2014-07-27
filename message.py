import struct

from pymnl.message import Message as NetlinkMessage

from . import NFNL_HDRLEN, NFNL_HDRFMT, NFNL_SUBSYS_ID, NFNL_MSG_TYPE

class Message(NetlinkMessage):

    def __init__(self, buffer=None):
        super(Message, self).__init__(buffer)

        """ The extra NetFilter header

            |<----------------- 4 bytes ------------------->|
            |                Netlink Header                 |
            |-----------------------------------------------|
            |         # The NF header begins here #         |
            |-----------------------------------------------|
            |    Family (AF_XXX)   |        Version         |
            |-----------------------------------------------|
            |                  Resource ID                  |
            |-----------------------------------------------|
            |                                               |
            .                   Payload                     .
            |_______________________________________________|
        """

        binary_payload = self.get_payload().get_binary()

        self._nf_family, self._nf_version, self._nf_res_id = struct.unpack(
            NFNL_HDRFMT, binary_payload[:NFNL_HDRLEN]
        )

        self._payload.set(binary_payload[NFNL_HDRLEN:])

    @staticmethod
    def from_nl_message(message):
        return Message(message.get_binary())

    @property
    def nf_subsys_id(self):
        return NFNL_SUBSYS_ID(self._msg_type)

    @property
    def nf_msg_type(self):
        return NFNL_MSG_TYPE(self._msg_type)



