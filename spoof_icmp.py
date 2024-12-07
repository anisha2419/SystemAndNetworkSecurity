#!/usr/bin/env python3
from scapy.all import *

# Create IP packet
ip = IP()
ip.src = '10.9.0.99'  # Spoofed source IP
ip.dst = '10.9.0.5'   # Target IP (hostA)

# Create ICMP packet
icmp = ICMP()
icmp.type = 8  # Echo request
icmp.code = 0

# Stack them together and send
packet = ip/icmp
send(packet)
