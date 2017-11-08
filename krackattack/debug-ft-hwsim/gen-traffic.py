#!/usr/bin/env python2
import logging, time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

p = Ether(dst="02:00:00:00:02:00")/ARP(op=2, pdst="192.168.100.12", hwdst="02:00:00:00:02:00")

while True:
	sendp(p, iface="wlan0")
	sendp(p, iface="wlan1")
	time.sleep(1)
