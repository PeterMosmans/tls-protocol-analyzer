# SSL/TLS Protocol Analyzer
Passively listens on interface and shows information about SSL/TLS connections.
scapy does something similar (and much, much more), but you'll need several dependencies. This script depends on dpkt and pypcap (if you want to sniff live traffic).

Dependencies
------------
dpkt
pypcap

Installation
------------
```pip install -r requirements.txt```

Usage
----
```
./tpa.py
```
Listens on default interface eth1 and shows information about SSL/TLS connections. Currently only the Client Hello parser is implemented, so that's the information that will be displayed.

```
./tpa.py -i eth3
```

Listens on interface eth3

```
./tpa.py -r PCAPFILE
```
Reads a pcap file and displays information about SSL/TLS connections.


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
         0 - DEFLATE
[*] Extensions:
         0 - server_name (Length: 15)
             github.com
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

