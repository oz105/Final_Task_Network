from scapy.all import *

a = IP()
a.dst = "8.8.8.8"
a.ttl = 0 

for i in range (1,12):
	a.ttl = i 
	icmp = ICMP()
	p = a/icmp
	send(p)
