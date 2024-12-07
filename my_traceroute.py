#!/usr/bin/env python3
from scapy.all import *

def traceroute(destination):
    print(f"Traceroute to {destination}")
    for ttl in range(1, 15):
        ip = IP(dst=destination, ttl=ttl)
        icmp = ICMP()
        reply = sr1(ip/icmp, timeout=2, verbose=0)
        
        if reply is None:
            print(f"{ttl}\t*****")
        else:
            print(f"{ttl}\t{reply.src}")
            if reply.src == destination:
                break

# Test the traceroute
traceroute('8.8.8.8')
