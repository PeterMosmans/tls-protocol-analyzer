#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import print_function
import argparse
from binascii import hexlify
import socket
import struct
import sys
import textwrap


import dpkt
import pcap

from constants import PRETTY_NAMES
TLS_HANDSHAKE = 22


class Extension:
    """Encapsulates TLS extensions."""

    def __init__(self, payload):
        self._type_id, payload = unpacker('H', payload)
        self._type_name = pretty_print_name('extension_type', self._type_id)
        self._length, payload = unpacker('H', payload)
        # Data contains an array with the 'raw' contents
        self._data = None
        # pretty_data contains an array with the 'beautified' contents
        self._pretty_data = None
        if self._length > 0:
            self._data, self._pretty_data = parse_extension(payload[:self._length],
                                                            self._type_name)

    def __str__(self):
        # Prints out data array in textual format
        return '{0}: {1}'.format(self._type_name, self._pretty_data)


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
            print('# ', end="")
            for arg in args:
                print(arg, end="")
            print()
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
            print('{1}{0} {2}'.format(name, prettydevicename,
                                      netifaces.ifaddresses(queryname)[netifaces.AF_INET][0]['addr']))
        except:
            print('{0}{1}'.format(prettydevicename, name))


def parse_ip_packet(ip):
    sys.stdout.flush()
    if isinstance(ip.data, dpkt.tcp.TCP):
        parse_tcp_packet(ip)


def parse_tcp_packet(ip):
    if len(ip.data.data) and (ord(ip.data.data[0]) == TLS_HANDSHAKE):
        parse_tls_handshake(ip)


def parse_tls_handshake(ip):
    tcp = ip.data
    records = []
    try:
        records, bytes_used = dpkt.ssl.tls_multi_factory(tcp.data)
    except:
        verboseprint('exception - issue parsing TLS data')
        return
    for record in records:
        try:
            handshake = dpkt.ssl.TLSHandshake(record.data)
        except:
            verboseprint('exception while parsing TLS handshake record')
            return
        client = '{0}:{1}'.format(socket.inet_ntoa(ip.src), tcp.sport)
        server = '{0}:{1}'.format(socket.inet_ntoa(ip.dst), tcp.dport)
        if isinstance(handshake.data, dpkt.ssl.TLSClientHello):  # 1
            print('--> ClientHello {0} -> {1}'.format(client, server))
            parse_client_hello(handshake)
            return
        if isinstance(handshake.data, dpkt.ssl.TLSServerHello):  # 2
            print('<-- ServerHello {1} <- {0}'.format(client, server))
            parse_server_hello(handshake.data)
            return
        if isinstance(handshake.data, dpkt.ssl.TLSCertificate):  # 11
            print('<-- Certificate {0} <- {1}'.format(client, server))
            return
        if isinstance(handshake.data, dpkt.ssl.TLSServerKeyExchange):  # 12
            print('<-- ServerKeyExchange {1} <- {0}'.format(server, client))
            return
        if isinstance(handshake.data, dpkt.ssl.TLSCertificateRequest):  # 13
            print('<-- CertificateRequest {1} <- {0}'.format(client, server))
            return
        if isinstance(handshake.data, dpkt.ssl.TLSServerHelloDone):  # 14
            print('<-- ServerHelloDone {1} <- {0}'.format(client, server))
            return
        if isinstance(handshake.data, dpkt.ssl.TLSCertificateVerify):  # 15
            print('--> CertificateVerify {0} -> {1}'.format(client, server))
            return
        if isinstance(handshake.data, dpkt.ssl.TLSClientKeyExchange):  # 16
            print('[+++] --> ClientKeyExchange {0} -> {1}'.format(client, server))
            return
        if isinstance(handshake.data, dpkt.ssl.TLSFinished):  # 20
            print('--> Finished {0} -> {1}'.format(client, server))
            return
        print('[-] Unrecognized handshake type: {0}'.format(handshake.data[0]))
    sys.stdout.flush()


def number_of_bytes(number):
    return int(log(number, 256) + 1)


def unpacker(type_string, packet):
    """Returns network-order parsed data and the packet minus the parsed data."""
    if type_string.endswith('H'):
        length = 2
    if type_string.endswith('B'):
        length = 1
    if type_string.endswith('P'):  # 2 bytes for the length of the string
        length, packet = unpacker('H', packet)
        type_string = '{0}s'.format(length)
    if type_string.endswith('p'):  # 1 byte for the length of the string
        length, packet = unpacker('B', packet)
        type_string = '{0}s'.format(length)
    data = struct.unpack('!' + type_string, packet[:length])[0]
    if type_string.endswith('s'):
        data = ''.join(data)
    return data, packet[length:]


def parse_server_hello(handshake):
    payload = handshake.data
    session_id, payload = unpacker('p', payload)
    cipher_suite, payload = unpacker('H', payload)
    print('[*]   Cipher: {0}'.format(pretty_print_name('cipher_suites', cipher_suite)))


def parse_client_hello(handshake):
    hello = handshake.data
    compressions = []
    cipher_suites = []
    extensions = []
#    handshake_length = number_of_bytes(len(hello))
    payload = handshake.data.data
    session_id, payload = unpacker('p', payload)
    cipher_suites, pretty_cipher_suites = parse_extension(payload, 'cipher_suites')
    verboseprint('TLS Record Layer Length: {0}'.format(len(handshake)))
    verboseprint('Client Hello Version: {0}'.format(dpkt.ssl.ssl3_versions_str[hello.version]))
    verboseprint('Client Hello Length: {0}'.format(len(hello)))
    verboseprint('Session ID: {0}'.format(hexlify(session_id)))
    print('[*]   Ciphers: {0}'.format(pretty_cipher_suites))
    # consume 2 bytes for each cipher suite plus 2 length bytes
    payload = payload[(len(cipher_suites) * 2) + 2:]
    compressions, pretty_compressions = parse_extension(payload, 'compression_methods')
    print('[*]   Compression methods: {0}'.format(pretty_compressions))
    # consume 1 byte for each compression method plus 1 length byte
    payload = payload[len(compressions) + 1:]
    extensions = parse_extensions(payload)
    for extension in extensions:
        print('      {0}'.format(extension))


def parse_extensions(payload):
    extensions = []
    if (len(payload) <= 0):
        return

    print('[*]   Extensions:')
    extensions_len, payload = unpacker('H', payload)
    verboseprint('Extensions Length: {0}'.format(extensions_len))

    while (len(payload) > 0):
        extension = Extension(payload)
        extensions.append(extension)
        # consume 2 bytes for type and 2 bytes for length
        payload = payload[extension._length + 4:]
    return extensions


def parse_extension(payload, type_name):
    """
    Parses the extension within the payload based on the type_name
    Returns an array of raw values as well as an array of prettified values
    """
    entries = []
    pretty_entries = []
    format_list_length = 'H'
    list_length = 0
    if type_name == 'ec_point_formats':
        format_list_length = 'B'
    if type_name == 'compression_methods':
        format_list_length = 'B'
        format_entry = 'B'
    if len(payload) > 1:  # contents are a list
        list_length, payload = unpacker(format_list_length, payload)
        verboseprint('type {0}, list length is {1}'.format(type_name, list_length))
    if type_name == 'status_request':
        _type, payload = unpacker('B', payload)
        format_entry = 'H'
    if type_name  == 'padding':
        return payload, hexlify(payload)
    if type_name == 'SessionTicket_TLS':
        return payload, hexlify(payload)
    format_entry = 'B'
    if type_name == 'cipher_suites':
        format_entry = 'H'
    if type_name == 'supported_groups':
        format_entry = 'H'
    if type_name == 'signature_algorithms':
        format_entry = 'H'
    if type_name == 'cipher_suites':
        format_entry = 'H'
    payload = payload[:list_length]
    while (len(payload) > 0):
        if type_name == 'server_name':
            _type, payload = unpacker('H', payload)
            format_entry = 'p'
        if type_name == 'application_layer_protocol_negotiation':
            format_entry = 'p'
        entry, payload = unpacker(format_entry, payload)
        entries.append(entry)
        if type_name == 'signature_algorithms':
            pretty_entries.append('{0}-{1}'.format(pretty_print_name('signature_algorithms_hash', entry >> 8),
                                                    pretty_print_name('signature_algorithms_signature', entry % 256)))
        else:
            pretty_entries.append(pretty_print_name(type_name, entry))
    return entries, pretty_entries


def pretty_print_name(name_type, name_value):
    """Returns the pretty name for type name_type."""
    if name_type in PRETTY_NAMES:
        if name_value in PRETTY_NAMES[name_type]:
            name_value = PRETTY_NAMES[name_type][name_value]
    return name_value


def main():
    global cap_filter
    global interface
    parse_arguments()
    if filename:
        read_file(filename)
    else:
        start_listening(interface, cap_filter)


def read_file(filename):
    try:
        with open(filename, 'rb') as f:
            capture = dpkt.pcap.Reader(f)
            for timestamp, packet in capture:
                analyze_packet(timestamp, packet)
    except IOError:
        print('could not parse {0}'.format(filename))


def start_listening(interface, cap_filter):
    """
    Starts the listening process with an optional filter.
    """
 #   try:
    pc = pcap.pcap(name=interface)
    pc.setfilter(cap_filter)
    while True:
        print('[+] listening on {0}'.format(pc.name))
        sys.stdout.flush()
        pc.loop(0, analyze_packet)
        print('[-] stopping')
#    except:
        print('[-] issue while opening interface')


if __name__ == "__main__":
    main()
