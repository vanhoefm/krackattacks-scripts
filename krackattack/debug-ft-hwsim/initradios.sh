#!/bin/bash
set -e

function bridgeup {
	ifconfig $1 down 2> /dev/null || true
	brctl delbr $1 2> /dev/null || true
	brctl addbr $1
	brctl setfd $1 0
	brctl addif $1 $2
	ifconfig $1 $3
	ifconfig $1 up
}

# Configure the virtual or real interfaces
rfkill unblock wifi 2> /dev/null || true
rmmod mac80211_hwsim 2> /dev/null || true
modprobe mac80211_hwsim radios=3
sleep 1

macchanger -m 02:00:00:00:00:00 wlan0 > /dev/null || true
macchanger -m 02:00:00:00:01:00 wlan1 > /dev/null || true
macchanger -m 02:00:00:00:02:00 wlan2 > /dev/null || true

vtund -s -f vtund.server.conf
vtund -f vtund.client.conf conn1 127.0.0.1
sleep 0.4
ifconfig tap0 up
ifconfig tap1 up

bridgeup br0 tap0 192.168.168.101
bridgeup br1 tap1 192.168.168.102

ifconfig wlan0 192.168.100.10
ifconfig wlan1 192.168.100.11
ifconfig wlan2 192.168.100.12

echo "Done. It's recommended to execute this script twice. Remember to disable Wi-Fi in the OS."

