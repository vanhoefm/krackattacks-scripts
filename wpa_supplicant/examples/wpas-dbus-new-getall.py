#!/usr/bin/python

import dbus
import sys, os
import time
import gobject

WPAS_DBUS_SERVICE = "fi.w1.wpa_supplicant1"
WPAS_DBUS_INTERFACE = "fi.w1.wpa_supplicant1"
WPAS_DBUS_OPATH = "/fi/w1/wpa_supplicant1"

WPAS_DBUS_INTERFACES_INTERFACE = "fi.w1.wpa_supplicant1.Interface"
WPAS_DBUS_INTERFACES_OPATH = "/fi/w1/wpa_supplicant1/Interfaces"
WPAS_DBUS_BSS_INTERFACE = "fi.w1.wpa_supplicant1.Interface.BSS"

def showBss(bss):
	net_obj = bus.get_object(WPAS_DBUS_SERVICE, bss)
	net = dbus.Interface(net_obj, WPAS_DBUS_BSS_INTERFACE)
	props = net_obj.GetAll(WPAS_DBUS_BSS_INTERFACE,
			       dbus_interface=dbus.PROPERTIES_IFACE)
	print props
	props = net_obj.Get(WPAS_DBUS_BSS_INTERFACE, 'Properties',
			    dbus_interface=dbus.PROPERTIES_IFACE)
	#print props

	# Convert the byte-array for SSID and BSSID to printable strings
	bssid = ""
	for item in props['BSSID']:
		bssid = bssid + ":%02x" % item
	bssid = bssid[1:]
	ssid = byte_array_to_string(props["SSID"])

	wpa = "no"
	if props.has_key("WPAIE"):
		wpa = "yes"
	wpa2 = "no"
	if props.has_key("RSNIE"):
		wpa2 = "yes"
	freq = 0
	if props.has_key("Frequency"):
		freq = props["Frequency"]
	caps = props["Capabilities"]
	qual = props["Quality"]
	level = props["Level"]
	noise = props["Noise"]
	maxrate = props["MaxRate"] / 1000000

	print "  %s  ::  ssid='%s'  wpa=%s  wpa2=%s  quality=%d%%  rate=%d  freq=%d" % (bssid, ssid, wpa, wpa2, qual, maxrate, freq)

def scanDone(success):
	gobject.MainLoop().quit()
	print "Scan done: success=%s" % success
	
	res = if_obj.Get(WPAS_DBUS_INTERFACES_INTERFACE, 'BSSs',
			 dbus_interface=dbus.PROPERTIES_IFACE)
	props = if_obj.GetAll(WPAS_DBUS_INTERFACES_INTERFACE,
			      dbus_interface=dbus.PROPERTIES_IFACE)
	print props

	print "Scanned wireless networks:"
	for opath in res:
		print opath
		showBss(opath)

def main():
	bus = dbus.SystemBus()
	wpas_obj = bus.get_object("fi.w1.wpa_supplicant1",
				  "/fi/w1/wpa_supplicant1")
	props = wpas_obj.GetAll("fi.w1.wpa_supplicant1",
				dbus_interface=dbus.PROPERTIES_IFACE)
	print "GetAll(fi.w1.wpa_supplicant1, /fi/w1/wpa_supplicant1):"
	print props

	if len(sys.argv) != 2:
		os._exit(1)

	ifname = sys.argv[1]

	wpas = dbus.Interface(wpas_obj, "fi.w1.wpa_supplicant1")
	path = wpas.GetInterface(ifname)
	if_obj = bus.get_object("fi.w1.wpa_supplicant1", path)
	props = if_obj.GetAll("fi.w1.wpa_supplicant1.Interface",
			      dbus_interface=dbus.PROPERTIES_IFACE)
	print
	print "GetAll(fi.w1.wpa_supplicant1.Interface, %s):" % (path)
	print props

	props = if_obj.GetAll("fi.w1.wpa_supplicant1.Interface.WPS",
			      dbus_interface=dbus.PROPERTIES_IFACE)
	print
	print "GetAll(fi.w1.wpa_supplicant1.Interface.WPS, %s):" % (path)
	print props

	res = if_obj.Get("fi.w1.wpa_supplicant1.Interface", 'BSSs',
			 dbus_interface=dbus.PROPERTIES_IFACE)
	if len(res) > 0:
		bss_obj = bus.get_object("fi.w1.wpa_supplicant1", res[0])
		props = bss_obj.GetAll("fi.w1.wpa_supplicant1.Interface.BSS",
				       dbus_interface=dbus.PROPERTIES_IFACE)
		print
		print "GetAll(fi.w1.wpa_supplicant1.Interface.BSS, %s):" % (res[0])
		print props

	res = if_obj.Get("fi.w1.wpa_supplicant1.Interface", 'Networks',
			 dbus_interface=dbus.PROPERTIES_IFACE)
	if len(res) > 0:
		net_obj = bus.get_object("fi.w1.wpa_supplicant1", res[0])
		props = net_obj.GetAll("fi.w1.wpa_supplicant1.Interface.Network",
				       dbus_interface=dbus.PROPERTIES_IFACE)
		print
		print "GetAll(fi.w1.wpa_supplicant1.Interface.Network, %s):" % (res[0])
		print props

if __name__ == "__main__":
	main()

