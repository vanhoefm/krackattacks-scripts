#!/usr/bin/env python2
from scapy.all import *
import sys

def main(clientmac):
	discover = Ether(dst='ff:ff:ff:ff:ff:ff', src=clientmac, type=0x0800) \
		/ IP(src='0.0.0.0', dst='255.255.255.255') \
		/ UDP(dport=67, sport=68) \
		/ BOOTP(op=1, chaddr=clientmac, flags=0x8000) \
		/ DHCP(options=[('message-type', 'discover'), ('end')])

	sendp(discover)

if __name__ == "__main__":
	if len(sys.argv) != 3:
		print "Usage:", sys.argv[0], "interface clientmac"
		quit(1)

	conf.iface = sys.argv[1]
	main(sys.argv[2])
