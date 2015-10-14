# SSL/TLS Protocol Analyzer
Passively listens on interface and shows information about SSL/TLS connections.
Yes, scapy does something similar (and much, much more), but you'll need several dependencies. Getting scapy to run on Windows for example can be quite a hassle.
This script 'only' depends on dpkt, and pypcap if you want to sniff live traffic.

Please note that you need correct permissions to sniff traffic (root or Administrator privileges).


Dependencies
------------
+ dpkt
+ pypcap

Optional (to show IP addresses per interface):
+ netifaces


Installation
------------
```pip install -r requirements.txt```
Note that this also installs netifaces


Usage
----
```
./tpa.py
```
Listens on default interface eth0 and shows information about SSL/TLS handshakes. Currently only the Client Hello parser is implemented, so that's the information that will be displayed.

```
./tpa.py -i eth3
```

Listens on interface eth3

When running on Linux environments (including Cygwin, MSYS and MSYS2 under Windows), you can specify the standard name (e.g. `eth1`) for the interface.
When running native on Windows you need to specify the extremely unfriendly looking device name, e.g. `\\DEVICE\NPF_{C0FFEE-15-G00D}`
Note that you can retrieve a list of these device names using the `--list-interfaces` option

```
./tpa.py -r PCAPFILE
```
Reads a pcap file and displays information about SSL/TLS connections.

```
./tpa.py --list-interfaces
```
Lists all available interfaces with their IP addresses 

Example output
--------------
```
[+] Client Hello detected (172.1.2.3:31337 --> 192.30.252.131:443)
[*] Ciphers:
    0xc02b - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xc02f - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xc00a - TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    0xc009 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    0xc013 - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xc014 - TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0x33   - TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    0x39   - TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    0x2f   - TLS_RSA_WITH_AES_128_CBC_SHA
    0x35   - TLS_RSA_WITH_AES_256_CBC_SHA
    0xa    - TLS_RSA_WITH_3DES_EDE_CBC_SHA
[*] Compression methods:
         0 - null
[*] Extensions:
         0 - server_name (Length: 15)
             github.com (Type host name)
     65281 - renegotiation_info (Length: 1)
        10 - supported_groups (Length: 8)
        11 - ec_point_formats (Length: 2)
        35 - SessionTicket TLS (Length: 0)
     13172 - next_protocol_negotiation (Length: 0)
        16 - application_layer_protocol_negotiation (Length: 23)
             h2
             spdy/3.1
             http/1.1
         5 - status_request (Length: 5)
        13 - signature_algorithms (Length: 22)

```

