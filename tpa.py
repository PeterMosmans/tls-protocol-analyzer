#!/usr/bin/env python

import argparse
from binascii import hexlify
from math import log
import socket
import struct
import sys
import textwrap


import dpkt
import pcap

from constants import *
TLS_HANDSHAKE = 22


def analyze_packet(timestamp, packet):
    eth = dpkt.ethernet.Ethernet(packet)
    if isinstance(eth.data, dpkt.ip.IP):
        parse_ip_packet(eth.data)


def parse_arguments():
    """
    Parses command line arguments
    """
    global filename
    global cap_filter
    global interface
    global verboseprint
    parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=textwrap.dedent('''\
Captures, parses and shows TLS Handshake packets

Copyright (C) 2015 Peter Mosmans [Go Forward]
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.'''))
    parser.add_argument('--filter', action='store',
                        default='', help='the pcap filter')
    parser.add_argument('-i', '--interface', action='store',
                        default='eth1', help='the interface to listen on')
    parser.add_argument('-r', '--read', metavar='FILE', action='store',
                        help='read from file (don\'t capture live packets)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='increase output verbosity')
    args = parser.parse_args()
    if args.verbose:
        def verboseprint(*args):
            print '# ',
            for arg in args:
                print arg,
                print
    else:
        verboseprint = lambda *a: None
    interface = args.interface
    cap_filter = args.filter
    filename = None
    if args.read:
        filename = args.read


def parse_ip_packet(ip):
    sys.stdout.flush()
    if isinstance(ip.data, dpkt.tcp.TCP):
        parse_tcp_packet(ip)


def parse_tcp_packet(ip):
    if len(ip.data.data) and (ord(ip.data.data[0]) == TLS_HANDSHAKE):
        parse_tls_handshake(ip)


def parse_tls_handshake(ip):
    tcp = ip.data
    verboseprint('TLS handshake detected')
    records = []
    try:
        records, bytes_used = dpkt.ssl.tls_multi_factory(tcp.data)
    except:
        verboseprint('exception - issue parsing TLS data')
        return
    if len(records) <= 0:
        verboseprint('issue parsing TLS data')
        return
    for record in records:
        if record.type != TLS_HANDSHAKE:
            verboseprint('Not a TLS handshake')
            return
        if len(record.data) == 0:
            verboseprint('Zero length')
            return
        if ord(record.data[0]) != 1:
            verboseprint('Wrong type')
            return
    try:
        handshake = dpkt.ssl.TLSHandshake(record.data)
    except:
        verboseprint('issue parsing TLS handshake')
        return
    if not isinstance(handshake.data, dpkt.ssl.TLSClientHello):
        verboseprint('wrong type')
        return
    print '[+] Client Hello detected ({0}:{1} --> {2}:{3})'.format(socket.inet_ntoa(ip.src), tcp.sport,
                                         socket.inet_ntoa(ip.dst), tcp.dport)
    parse_client_hello(handshake)

def number_of_bytes(number):
    return int(log(number, 256) + 1)


def parse_client_hello(handshake):
    hello = handshake.data
    compressions = []
    cipher_suites = []
    extensions = []
    handshake_length = number_of_bytes(len(hello))
    session_id_len = len(hello.session_id)
    # random is 32 bits time plus 8 bytes random
    pointer = 1 + session_id_len
    cipher_suites_len = struct.unpack('!H', hello.data[pointer:pointer + 2])[0]
    verboseprint('TLS Record Layer Length: {0}'.format(len(handshake)))
    verboseprint('Client Hello Version: {0}'.format(dpkt.ssl.ssl3_versions_str[hello.version]))
    verboseprint('Client Hello Length: {0}'.format(len(hello)))
    verboseprint('Session ID Length: {0}'.format(session_id_len))
    verboseprint('Cipher Suites Length: {0} ({1} cipher suites)'.format(cipher_suites_len,
                                                                   cipher_suites_len / 2))
    pointer += 2
    for i in range(pointer, pointer + cipher_suites_len, 2):
        cipher_suites.append(struct.unpack('!H', hello.data[i:i + 2])[0])
    print('[*] Ciphers:')
    for cipher_suite in cipher_suites:
        print '    {0:6} - {1}'.format(hex(cipher_suite), pretty_print_cipher(cipher_suite))
    pointer += cipher_suites_len
    compression_num = struct.unpack('B', hello.data[pointer])[0]
    pointer += 1
    for i in range(pointer, pointer + compression_num):
        compressions.append(struct.unpack('B', hello.data[i])[0])
    verboseprint('Compression Methods: {0}'.format(compression_num))
    print '[*] Compression methods:'
    for compression in compressions:
        print '    {0:6} - {1}'.format(compression,
                                       pretty_print_compression(compression))
    pointer += compression_num
    if (pointer >= len(hello.data)):
        return
    extension_len = struct.unpack('!H', hello.data[pointer:pointer + 2])[0]
    verboseprint('Extensions Length: {0}'.format(extension_len))
    pointer += 2
    print '[*] Extensions:'
    while (pointer < len(hello.data)):
        extension_type = struct.unpack('!H', hello.data[pointer:pointer + 2])[0]
        pointer += 2
        extension_len = struct.unpack('!H', hello.data[pointer:pointer + 2])[0]
        print '    {0:6} - {1} (Length: {2})'.format(extension_type,
                                               pretty_print_extension(extension_type),
                                               extension_len)
        pointer += 2
        if (extension_type == 0):
            print '             {0}'.format(''.join(struct.unpack('!{0}s'.format(extension_len),
                                            hello.data[pointer:pointer + extension_len])))
        if (extension_type == 16):
            for alpn_protocol in parse_ALPN(hello, pointer):
                print '             {0}'.format(alpn_protocol)
        pointer += extension_len
    sys.stdout.flush() 


def parse_ALPN(hello, pointer):
    alpn_extension_len = struct.unpack('!H', hello.data[pointer:pointer + 2])[0]
    pointer += 2
    alpn_protocols = []
    orig_pointer = pointer
    while (pointer < (orig_pointer + alpn_extension_len)):
        alpn_string_len = struct.unpack('B', hello.data[pointer])[0]
        pointer += 1
        alpn_protocols.append(''.join(struct.unpack('!{0}s'.format(alpn_string_len),
                                            hello.data[pointer:pointer + alpn_string_len])))
        pointer += alpn_string_len
    return alpn_protocols


def pretty_print_cipher(cipher_suite):
    if cipher_suite in CIPHER_NAMES:
        return CIPHER_NAMES[cipher_suite]
    else:
        return 'unknown'


def pretty_print_extension(extension_type):
    if extension_type in EXTENSION_TYPES:
        return EXTENSION_TYPES[extension_type]
    else:
        return 'unknown'


def pretty_print_compression(compression_method):
    if compression_method in COMPRESSION_METHODS:
        return COMPRESSION_METHODS[compression_method]
    else:
        return 'unknown'


def main():
    global cap_filter
    global interface
#    print pcap.findalldevs()
    parse_arguments()
    if filename:
        read_file(filename)
    else:
        start_listening(interface, cap_filter)


def read_file(filename):
 #   try:
    with open(filename, 'rb') as f:
        capture = dpkt.pcap.Reader(f)
        for timestamp, packet in capture:
            analyze_packet(timestamp, packet)
#    except:
#        print 'could not parse {0}'.format(filename)


def start_listening(interface, cap_filter):
    pc = pcap.pcap(name=interface)
    pc.setfilter(cap_filter)
    print 'listening on {0}'.format(pc.name)
    sys.stdout.flush()
    pc.loop(0, analyze_packet)


if __name__ == "__main__":
    main()
