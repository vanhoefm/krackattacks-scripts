#!/usr/bin/python

import dbus
import sys, os
import time
import gobject
from dbus.mainloop.glib import DBusGMainLoop

WPAS_DBUS_SERVICE = "fi.w1.wpa_supplicant1"
WPAS_DBUS_INTERFACE = "fi.w1.wpa_supplicant1"
WPAS_DBUS_OPATH = "/fi/w1/wpa_supplicant1"

WPAS_DBUS_INTERFACES_INTERFACE = "fi.w1.wpa_supplicant1.Interface"
WPAS_DBUS_INTERFACES_OPATH = "/fi/w1/wpa_supplicant1/Interfaces"
WPAS_DBUS_BSS_INTERFACE = "fi.w1.wpa_supplicant1.Interface.BSS"

def byte_array_to_string(s):
	import urllib
	r = ""    
	for c in s:
		if c >= 32 and c < 127:
			r += "%c" % c
		else:
			r += urllib.quote(chr(c))
	return r

def list_interfaces(wpas_obj):
	ifaces = wpas_obj.Interfaces
	for i in ifaces:
		print "%s" (i)

def stateChanged(newState, oldState):
	print "StateChanged(%s -> %s)" % (oldState, newState)

def scanDone(success):
	gobject.MainLoop().quit()
	print "Scan done: success=%s" % success
	
	res = if_obj.Get(WPAS_DBUS_INTERFACES_INTERFACE, 'BSSs',
			 dbus_interface=dbus.PROPERTIES_IFACE)

	print "Scanned wireless networks:"
	for opath in res:
		print opath
		net_obj = bus.get_object(WPAS_DBUS_SERVICE, opath)
		net = dbus.Interface(net_obj, WPAS_DBUS_BSS_INTERFACE)
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

def main():
	dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
	global bus
	bus = dbus.SystemBus()
	wpas_obj = bus.get_object(WPAS_DBUS_SERVICE, WPAS_DBUS_OPATH)
	wpas = dbus.Interface(wpas_obj, WPAS_DBUS_INTERFACE)
	bus.add_signal_receiver(scanDone,
				dbus_interface=WPAS_DBUS_INTERFACES_INTERFACE,
				signal_name="ScanDone")
	bus.add_signal_receiver(stateChanged,
				dbus_interface=WPAS_DBUS_INTERFACES_INTERFACE,
				signal_name="StateChanged")

	if len(sys.argv) != 2:
		list_interfaces(wpas_obj)
		os._exit(1)

	ifname = sys.argv[1]

	# See if wpa_supplicant already knows about this interface
	path = None
	try:
		path = wpas.GetInterface(ifname)
	except dbus.DBusException, exc:
		if not str(exc).startswith("fi.w1.wpa_supplicant1.InterfaceUnknown:"):
			raise exc
		try:
			path = wpas.CreateInterface({'Ifname': ifname, 'Driver': 'test'})
			time.sleep(1)

		except dbus.DBusException, exc:
			if not str(exc).startswith("fi.w1.wpa_supplicant1.InterfaceExists:"):
				raise exc

	global if_obj
	if_obj = bus.get_object(WPAS_DBUS_SERVICE, path)
	global iface
	iface = dbus.Interface(if_obj, WPAS_DBUS_INTERFACES_INTERFACE)
	iface.Scan({'Type': 'active'})

	gobject.MainLoop().run()

	wpas.RemoveInterface(dbus.ObjectPath(path))

if __name__ == "__main__":
	main()

