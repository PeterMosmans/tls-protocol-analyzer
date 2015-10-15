#!/usr/bin/env python

import argparse
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
                        default='eth0', help='the interface to listen on')
    parser.add_argument('--list-interfaces', action='store_true',
                        help='list all available interfaces and exit')
    parser.add_argument('-r', '--read', metavar='FILE', action='store',
                        help='read from file (don\'t capture live packets)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='increase output verbosity')
    args = parser.parse_args()
    if args.list_interfaces:
        list_interfaces()
        exit()
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


def list_interfaces():
    i = 0
    for name in pcap.findalldevs():
        prettydevicename = ''
        queryname = name
        if name.startswith('\Device\NPF_'):
            queryname = name[12:]
        if name.endswith('}'):
            prettydevicename = 'eth{0} '.format(i)
            i += 1
        try:
            import netifaces
            print '{1}{0} {2}'.format(name, prettydevicename,
                                      netifaces.ifaddresses(queryname)[netifaces.AF_INET][0]['addr'])
        except:
            print '{0}{1}'.format(prettydevicename, name)


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


def unpacker(type_string, packet):
    """Returns network-order parsed data and the packet minus the parsed data."""
    if type_string.endswith('H'):
        length = 2
    if type_string.endswith('B'):
        length = 1
    if type_string.endswith('s'):
        length = int(type_string[:(len(type_string) - 1)])
    data = struct.unpack('!' + type_string, packet[:length])[0]
    if type_string[0] == 's':
        data = ''.join(data)
    return data, packet[length:]


def parse_client_hello(handshake):
    hello = handshake.data
    compressions = []
    cipher_suites = []
    extensions = []
    handshake_length = number_of_bytes(len(hello))
    session_id_len = len(hello.session_id)
    # random is 32 bits time plus 8 bytes random
    pointer = 1 + session_id_len
    payload = hello.data[pointer:]
    cipher_suites_len, payload = unpacker('H', payload)
    verboseprint('TLS Record Layer Length: {0}'.format(len(handshake)))
    verboseprint('Client Hello Version: {0}'.format(dpkt.ssl.ssl3_versions_str[hello.version]))
    verboseprint('Client Hello Length: {0}'.format(len(hello)))
    verboseprint('Session ID Length: {0}'.format(session_id_len))
    verboseprint('Cipher Suites Length: {0} ({1} cipher suites)'.format(cipher_suites_len,
                                                                   cipher_suites_len / 2))
    print('[*] Ciphers:')
    for i in range(0, cipher_suites_len / 2):
        cipher_suite, payload = unpacker('H', payload)
        print '    {0:6} - {1}'.format(hex(cipher_suite), pretty_print_cipher(cipher_suite))
        cipher_suites.append(cipher_suite)

    print '[*] Compression methods:'
    compression_num, payload = unpacker('B', payload)
    for i in range(0, compression_num):
        compression, payload = unpacker('B', payload)
        compressions.append(compression)
        print '    {0:6} - {1}'.format(compression,
                                       pretty_print_compression(compression))
    if (len(hello.data) <= 0):
        return
    parse_extensions(payload)
    sys.stdout.flush()


def parse_extensions(payload):
    print '[*] Extensions:'
    extension_len, payload = unpacker('H', payload)
    verboseprint('Extensions Length: {0}'.format(extension_len))

    while (len(payload) > 0):
        extension_type, payload = unpacker('H', payload)
        extension_len, payload = unpacker('H', payload)
        print '    {0:6} - {1} (Length: {2})'.format(extension_type,
                                               pretty_print_extension(extension_type),
                                               extension_len)
        if (extension_type == 0):
            server_names = parse_server_names(payload[:extension_len])
        if (extension_type == 16):
            alpn_protocols = parse_ALPN(payload[:extension_len])
        payload = payload[extension_len:]


def parse_ALPN(payload):
    alpn_protocols = []
    alpn_extension_len, payload = unpacker('H', payload)
    while (len(payload) > 0):
        string_len, payload = unpacker('B', payload)
        alpn_protocol, payload = unpacker('{0}s'.format(string_len), payload)
        alpn_protocols.append(alpn_protocol)
        print '             {0}'.format(alpn_protocol)
    return alpn_protocols


def parse_server_names(payload):
    entries = []
    list_length, payload = unpacker('H', payload)
    while (len(payload) > 0):
        entry_type, payload = unpacker('B', payload)
        entry_length, payload = unpacker('H', payload)
        server_name, payload = unpacker('{0}s'.format(entry_length), payload)
        print '             {0}'.format(server_name)
    return entries


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
    try:
        pc = pcap.pcap(name=interface)
        pc.setfilter(cap_filter)
        while True:
            print '[+] listening on {0}'.format(pc.name)
            sys.stdout.flush()
            pc.loop(0, analyze_packet)
        print ('[-] stopping')
    except:
        print '[-] issue while opening interface'


if __name__ == "__main__":
    main()
