from scapy.all import *
from scapy.layers.inet import ICMP, IP

def q2():
    ip = IP()
    ip.src = '10.0.2.7' # change the src ip
    ip.dst = '13.225.225.110'# send to walla
    icmp = ICMP()
    pkt = ip / icmp
    send(pkt)
    
q2()

