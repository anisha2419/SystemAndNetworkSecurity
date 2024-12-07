#!/usr/bin/env python3
from scapy.all import *

def spoof_reply(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:
        print(f"Spoofing reply to {pkt[IP].dst}")
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        icmp = ICMP(type=0, code=0)
        icmp.id = pkt[ICMP].id
        icmp.seq = pkt[ICMP].seq
        reply = ip/icmp
        send(reply, verbose=0)

print("Starting sniffing and spoofing...")
sniff(iface='eth0',  # Replace with your interface name
      filter='icmp[icmptype] = icmp-echo',
      prn=spoof_reply)
