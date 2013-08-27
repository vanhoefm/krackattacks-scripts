#!/bin/sh

if pidof wpa_supplicant hostapd valgrind.bin > /dev/null; then
    RUNNING=yes
else
    RUNNING=no
fi

sudo killall -q hostapd
sudo killall -q wpa_supplicant
for i in `pidof valgrind.bin`; do
    if ps $i | grep -q -E "wpa_supplicant|hostapd"; then
	sudo kill $i
    fi
done
sudo killall -q wlantest
sudo killall -q tcpdump
if grep -q hwsim0 /proc/net/dev; then
    sudo ifconfig hwsim0 down
fi

if [ "$RUNNING" = "yes" ]; then
    # give some time for hostapd and wpa_supplicant to complete deinit
    sleep 4
fi

if pidof wpa_supplicant hostapd > /dev/null; then
    echo "wpa_supplicant/hostapd did not exit - try to force them to die"
    sudo killall -9 -q hostapd
    sudo killall -9 -q wpa_supplicant
    sleep 5
fi

for i in `pidof valgrind.bin`; do
    if ps $i | grep -q -E "wpa_supplicant|hostapd"; then
	echo "wpa_supplicant/hostapd(valgrind) did not exit - try to force it to die"
	sudo kill -9 $i
    fi
done

for i in /tmp/wpas-wlan0 /tmp/wpas-wlan1 /tmp/wpas-wlan2 /var/run/hostapd-global; do
    if [ -e $i ]; then
	sleep 1
	if [ -e $i ]; then
	    echo "Control interface file $i exists - remove it"
	    sudo rm $i
	fi
    fi
done

if grep -q mac80211_hwsim /proc/modules ; then
    sudo rmmod mac80211_hwsim 
    # wait at the end to avoid issues starting something new immediately after
    # this script returns
    sleep 1
fi
