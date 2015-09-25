# SSL/TLS Protocol Analyzer
Passively listens on interface and shows information about SSL/TLS connections.

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
Listens on your interface and shows information about SSL/TLS connections. Currently only the Client Hello parser is implemented, so that's the information that will be displayed.


```
./tpa.py -r PCAPFILE
```
Reads a pcap file and displays information about SSL/TLS connections.

