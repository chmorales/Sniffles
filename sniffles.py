#!/usr/bin/env python3


# Standard libs

import argparse
import calendar
from datetime import datetime
import hexdump
import os
import socket
from sys import stdout

# Project libs

from pcap import printPcapHeaders, printPcapEnhancedPacket
from pktparse import HEADERS, parsePacket
from timeout import timeout


# Constants

MAX_PACKET_SIZE = 65535

TIMEOUT_STRING = 'for {} seconds'
PCAP_STRING = 'and saving to {}'
HEXDUMP_STRING = 'with hexdump'

# Classes

class Sniffer:
    def __init__(self, interface='eth0', ):
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                    socket.ntohs(0x0003))
        self.socket.bind((interface, 0))

    def sniff(self, outfile=stdout, time=0, dump=False, protocols=HEADERS):
        if dump:
            printFunc = _printHex
        elif outfile is stdout:
            printFunc = _printPlaintext
        else:
            printFunc = _printPcap
            printPcapHeaders(outfile, MAX_PACKET_SIZE)
        print(_sniffString(outfile, time, dump))
        try:
            with timeout(time):
                while True:
                    data = self.socket.recvfrom(MAX_PACKET_SIZE)[0]
                    printFunc(data, outfile, protocols)
        except TimeoutError:
            if outfile is not stdout:
                outfile.close()


# Functions

def _sniffString(outfile, time, dump):
    strings = ['Sniffing', ]
    if time != 0:
        strings.append(TIMEOUT_STRING.format(time))
    if outfile is not stdout:
        strings.append(PCAP_STRING.format(os.path.basename(outfile.name)))
    if dump:
        strings.append(HEXDUMP_STRING)
    return ' '.join(strings) + '...'

def _printHex(data, outfile, protocols):
    hexdump.hexdump(data)

def _printPcap(data, outfile, protocols):
    time = calendar.timegm(datetime.now().timetuple()) * 10 ** 6 # uSeconds to seconds
    printPcapEnhancedPacket(outfile, time, data)

def _printPlaintext(data, outfile, protocols):
    packet = parsePacket(data)
    packet_string = _packetString(packet, protocols)
    if len(packet_string) > 0:
        print(packet_string, end='\n\n', file=outfile)

def _normalPrint(key, value):
    return '{}={}'.format(key,value)

def _arrayPrint(key, value):
    elements = [key[1:] + ':', ]
    for e in value:
        elements.append(_headerString('', e))
    return '\n' + '\n\t'.join(elements)

def _nestedPrint(key, value):
    pairs = [_pairString(k,v) for k,v in value.items() if k[0] != '_']
    return ', '.join(pairs)

PRINT_FUNCS = {
    '+': _arrayPrint,
    '*': _nestedPrint,
}

def _pairString(key, value):
    return PRINT_FUNCS.get(key[0], _normalPrint)(key, value)

def _headerString(header_name, header_dict):
    pairs = [_pairString(k,v) for k,v in header_dict.items() if k[0] != '_']
    return header_name + '(' + ', '.join(pairs) + ')'

def _packetString(packet, protocols):
    if packet is None:
        return ''
    heads = [_headerString(h, packet[h]) for h in HEADERS 
             if h in protocols and h in packet and h[0] != '_']
    return '\n'.join(heads)


# Main

if __name__ == '__main__':

    parser = argparse.ArgumentParser(prog='sniffles', description='''Sniff packets.
                        Use on a UNIX machine. Works with construct 2.9.39.''')
    parser.add_argument('interface', metavar='INTERFACE',
                        help='Interface to listen for traffic on.')
    parser.add_argument('-o', '--outfile', metavar='OUTFILE', default=stdout,
                        help='File name to output Pcap to.')
    parser.add_argument('-t', '--timeout', default=0, type=int,
                        help='''Time to capture for (in seconds). If 
                        unspecified, ^C must be sent to close the program.''')
    parser.add_argument('-x', '--hexdump', action='store_true',
                        help='Print hexdump to stdout. Overrides -f and -o.')
    parser.add_argument('-f', '--filter', default=list(HEADERS), nargs='+',
                        choices=list(HEADERS), help='Filter for a protocol.')

    args = vars(parser.parse_args())

    outfile = args['outfile']
    if outfile is not stdout:
        outfile = open(args['outfile'], 'w+b')

    sniffer = Sniffer(args['interface'])
    sniffer.sniff(outfile=outfile, time=args['timeout'],
                  dump=args['hexdump'], protocols=args['filter'])