# Sniffles Packet Sniffer

### How to run

Make sure you have the newest version of the Construct library installed (>=2.9).

This project is also reliant on the 'hexdump' library.

`pip install construct`

`pip install hexdump`

#### Usage


```
usage: sniffles [-h] [-o OUTPUT] [-t TIMEOUT] [-x]
                [-f {Ethernet, ARP, IP, TCP, UDP, DNS}]
                INTERFACE

positional arguments:
  INTERFACE             interface to listen for traffic on

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        File name to output to
  -t TIMEOUT, --timeout TIMEOUT
                        Amount of time to capture for before quitting. If no
                        time specified ^C must be sent to close program
  -x, --hexdump         Print hexdump to stdout
  -f {Ethernet, ARP, IP, TCP, UDP, DNS}, --filter {Ethernet, ARP, IP, TCP, UDP, DNS}
                        Filter for one specified protocol`
```