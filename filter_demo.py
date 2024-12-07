#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
    print("\n=== Captured Packet ===")
    print(f"Source IP: {pkt[IP].src if IP in pkt else 'No IP'}")
    print(f"Destination IP: {pkt[IP].dst if IP in pkt else 'No IP'}")
    if TCP in pkt:
        print(f"TCP Port: {pkt[TCP].dport}")
    elif ICMP in pkt:
        print(f"ICMP Type: {pkt[ICMP].type}")
    print("=====================")

# Test each filter
print("Testing ICMP filter...")
sniff(iface='eth0', filter='icmp', prn=print_pkt, count=5)

print("\nTesting TCP filter...")
sniff(iface='eth0', filter='tcp and src host 10.9.0.5 and dst port 23', prn=print_pkt, count=5)

print("\nTesting subnet filter...")
sniff(iface='eth0', filter='net 128.230.0.0/16', prn=print_pkt, count=5)
