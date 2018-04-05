from construct import *


SECTION_HEADER = Struct(
    'block_type' / Const(bytes.fromhex('0A0D0D0A')),
    'block_total_length' / Const(bytes.fromhex('0000001c')),
    'byte_order_magic' / Const(bytes.fromhex('1A2B3C4D')),
    'major_version' / Const(bytes.fromhex('0001')),
    'minor_version' / Const(bytes.fromhex('0000')),
    'section_length' / Const(bytes.fromhex('FFFFFFFFFFFFFFFF')),
    'block_total_length' / Const(bytes.fromhex('0000001c'))
)

INTERFACE_DESCRIPTION = Struct(
    'block_type' / Const(bytes.fromhex('00000001')),
    'block_total_length' / Const(bytes.fromhex('00000014')),
    'link_type' / Const(bytes.fromhex('0001')),
    'reserved' / Const(bytes.fromhex('0000')),
    'snap_len' / BytesInteger(4),
    'block_total_length' / Const(bytes.fromhex('00000014'))
)

ENHANCED_PACKET = AlignedStruct(4, 
    'block_type' / Const(bytes.fromhex('00000006')),
    'block_total_length' / BytesInteger(4),
    'interface_id' / Const(bytes.fromhex('00000000')),
    'timestamp' / BytesInteger(8),
    'captured_packet_length' / BytesInteger(4),
    'original_packet_length' / BytesInteger(4),
    'packet_data' / Bytes(this.captured_packet_length),
    'block_total_length' / BytesInteger(4)
)


def printPcapHeaders(file, maxsize):
    section_header = SECTION_HEADER.build(None)
    file.write(section_header)
    interface_description = INTERFACE_DESCRIPTION.build(dict(snap_len=maxsize))
    file.write(interface_description)


def printPcapEnhancedPacket(file, time, packet):
    blocklen = len(packet) + 32 # length of rest of ENHANCED_PACKET
    enhanced_packet = ENHANCED_PACKET.build(dict(block_total_length=blocklen, 
        timestamp=time, captured_packet_length=len(packet), 
        original_packet_length=len(packet), packet_data=packet))
    file.write(enhanced_packet)
