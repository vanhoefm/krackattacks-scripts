#!/bin/sh

sudo killall -q hostapd
sudo killall -q wpa_supplicant
if grep -q mac80211_hwsim /proc/modules ; then
    sudo rmmod mac80211_hwsim 
fi
