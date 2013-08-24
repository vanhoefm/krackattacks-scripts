#!/bin/sh

sudo killall -q hostapd
sudo killall -q wpa_supplicant
if [ "x$1" = "xvalgrind" ]; then
    sudo kill `pidof valgrind.bin`
fi
sudo killall -q wlantest
sudo killall -q tcpdump
if grep -q hwsim0 /proc/net/dev; then
    sudo ifconfig hwsim0 down
fi
if grep -q mac80211_hwsim /proc/modules ; then
    sudo rmmod mac80211_hwsim 
fi
