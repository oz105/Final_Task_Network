#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
	pkt.show()
pkt = sniff(iface="br-85803742d13f", filter="tcp", prn=print_pkt)
