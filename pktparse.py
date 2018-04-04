from construct import *


######################
# DATA TYPE ADAPTERS #
######################

class MACAddressAdapter(Adapter):
    def _decode(self, obj, context, path):
        return ':'.join(['{:02x}'.format(o) for o in obj])

    def _encode(self, obj, context, path):
        return [int(o, 16) for o in obj.split(':')]

class IPAddressAdapter(Adapter):
    def _decode(self, obj, context, path):
        return '.'.join([str(o) for o in obj])

    def _encode(self, obj, context, path):
        return [int(o) for o in obj.split('.')]

class BytesAdapter(Adapter):
    def _decode(self, obj, context, path):
        return obj.hex()

    def _encode(self, obj, context, path):
        return bytes.fromhex(obj)

class DNSDomainNameAdapter(Adapter):
    def _decode(self, obj, context, path):
        return '.'.join([str(o) for o in obj])

    def _encode(self, obj, context, path):
        return bytes(''.join(obj.split('.')), 'ascii')


############
# CONSTRUCTS
############

##########
# ETHERNET

ETHERNET_STATIC_SIZE = 14

ETHERNET_HEAD = Struct(
    'dest_mac' / MACAddressAdapter(Bytes(6)),
    'src_mac' / MACAddressAdapter(Bytes(6)),
    'ethernet_type' / BytesInteger(2),
    '_header_length' / Computed(ETHERNET_STATIC_SIZE)
)


#########
# ARP

ARP_HEAD = Struct(
    '_start' / Tell,
    'hardware_type' / BytesInteger(2),
    'protocol_type' / BytesInteger(2),
    'hardware_addr_len' / BytesInteger(1),
    'protocol_addr_len' / BytesInteger(1),
    'opcode' / BytesInteger(2),
    'sender_hw_addr' / MACAddressAdapter(Bytes(this.hardware_addr_len)),
    'sender_proto_addr' / IPAddressAdapter(Bytes(this.protocol_addr_len)),
    'target_hw_addr' / MACAddressAdapter(Bytes(this.hardware_addr_len)),
    'target_proto_addr' / IPAddressAdapter(Bytes(this.protocol_addr_len)),  
    '_end' / Tell,
    '_header_length' / Computed(this._end - this._start)
)

#########
# IP

IP_HEAD = BitStruct(
    'version' / BitsInteger(4),
    'IHL' / BitsInteger(4),
    'DSCP' / BitsInteger(6),
    'ECN' / BitsInteger(2),
    'length' / Bytewise(BytesInteger(2)),
    'identification' / Bytewise(BytesInteger(2)),
    'flags' / BitsInteger(3),
    'offset' / BitsInteger(13),
    'TTL' / Bytewise(BytesInteger(1)),
    'protocol' / Bytewise(BytesInteger(1)),
    'checksum' / Bytewise(BytesInteger(2)),
    'src_ip_addr' / Bytewise(IPAddressAdapter(Bytes(4))),
    'dst_ip_addr' / Bytewise(IPAddressAdapter(Bytes(4))),
    'options' / If(this.IHL > 5, Bytewise(Bytes(this.IHL * 4 - 20))),
    '_header_length' / Computed(this.IHL * 4)
)

#########
# TCP

# Bitstruct
TCP_HEAD = BitStruct(
    'src_port' / Bytewise(BytesInteger(2)),
    'dest_port' / Bytewise(BytesInteger(2)),
    'seq_num' / Bytewise(BytesInteger(4)),
    'ack_num' / Bytewise(BytesInteger(4)),
    'data_offset' / BitsInteger(4),
    'reserved' / Padding(3),
    'NS' / Flag,
    'CWR' / Flag,
    'ECE' / Flag,
    'URG' / Flag,
    'ACK' / Flag,
    'PSH' / Flag,
    'RST' / Flag,
    'SYN' / Flag,
    'FIN' / Flag, 
    'options' / If(this.data_offset > 5, Bytewise(Bytes(this.data_offset * 4 - 20))),
    '_header_length' / Computed(this.data_offset * 4)
)

##########
# UDP

UDP_STATIC_SIZE = 8

# Bytestruct
UDP_HEAD = Struct(
    'src_port' / BytesInteger(2),
    'dest_port' / BytesInteger(2),
    'length' / BytesInteger(2),
    'checksum' / BytesInteger(2),
    '_header_length' / Computed(UDP_STATIC_SIZE)
)

##########
# DNS

# DNS Domain Name Format, array of PascalStrings until NullTerminator
DNSDomainNameFragments = RepeatUntil(lambda obj,lst,ctx: obj == '', PascalString(VarInt, 'ascii'))
DNSDomainName = DNSDomainNameAdapter(DNSDomainNameFragments)

# DNS Compressed Name Format
DNSCompressedName = BitStruct(
    '_identifier' / Const(b'\x01\x01'),
    'name_offset' / BitsInteger(14),
)

# DNS Bitcodes Section (to prevent from having to use 1 big Bitstruct)
DNS_BITCODES = BitStruct(
    'query_response' / Flag,
    'op_code' / Nibble,
    'authoritative_answer' / Flag,
    'truncation' / Flag,
    'recursion_desired' / Flag,
    'recursion_available' / Flag,
    'reserved' / Padding(3),
    'response_code' / BitsInteger(4)
)

DNS_QUERY = Struct(
    'qname' / Select(DNSCompressedName, DNSDomainName),
    'qtype' / BytesInteger(2),
    'qclass' / BytesInteger(2),
)

DNS_RESPONSE = Struct(
    'rname' / Select(DNSCompressedName, DNSDomainName),
    'rtype' / BytesInteger(2),
    'rclass' / BytesInteger(2),
    'TTL' / BytesInteger(4),
    'rdata_len' / BytesInteger(2),
    'rdata' / Switch(this.rtype, {1:IPAddressAdapter(Bytes(4)), 5:DNSDomainName}, default=Bytes(this.rdata_len))
)

DNS_HEAD = Struct(
    '_start' / Tell,
    'identifier' / BytesAdapter(Bytes(2)),
    '*bitcodes' / DNS_BITCODES, # 2 Bytes
    'qd_count' / BytesInteger(2),
    'an_count' / BytesInteger(2),
    'ns_count' / BytesInteger(2),
    'ar_count' / BytesInteger(2),
    # Probe(),
    '+Queries' / Array(this.qd_count, DNS_QUERY),
    '+Responses' / Array(this.an_count, DNS_RESPONSE),
    # Probe(),
    '_end' / Tell,
    '_header_length' / Computed(this._end - this._start)
)

#########
# METHODS
#########

HEADERS_CONSTRUCTS = {
    'Ethernet': ETHERNET_HEAD,
    'ARP': ARP_HEAD,
    'IP': IP_HEAD,
    'TCP': TCP_HEAD,
    'UDP': UDP_HEAD,
    'DNS': DNS_HEAD
}

HEADERS_CONDITIONS = {
    'Ethernet': lambda pkt: True,
    'ARP': lambda pkt: pkt['Ethernet'].ethernet_type == 2054,
    'IP': lambda pkt: pkt['Ethernet'].ethernet_type == 2048,
    'TCP': lambda pkt: 'IP' in pkt and pkt['IP'].protocol == 6,
    'UDP': lambda pkt: 'IP' in pkt and pkt['IP'].protocol == 17,
    'DNS': lambda pkt: 'UDP' in pkt and 53 in (pkt['UDP'].src_port, pkt['UDP'].dest_port)
}

HEADERS = ['Ethernet', 'ARP', 'IP', 'TCP', 'UDP', 'DNS']

def parsePacket(data):
    parsed = {}
    offset = 0
    for h in HEADERS:
        if HEADERS_CONDITIONS[h](parsed):
            try:
                parsed[h] = HEADERS_CONSTRUCTS[h].parse(data[offset:])
                offset += parsed[h]._header_length
            except StreamError:
                return None
    return parsed
