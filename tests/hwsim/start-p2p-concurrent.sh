#!/bin/sh

DIR="$( cd "$( dirname "$0" )" && pwd )"
WPAS=$DIR/../../wpa_supplicant/wpa_supplicant
WLANTEST=$DIR/../../wlantest/wlantest

$DIR/stop-wifi.sh
sudo modprobe mac80211_hwsim radios=3
sudo iw wlan0 interface add sta0 type station
sudo iw wlan1 interface add sta1 type station
sudo iw wlan2 interface add sta2 type station
mkdir -p $DIR/logs
DATE=`date +%s`
sudo ifconfig hwsim0 up
sudo $WLANTEST -i hwsim0 -c -d > $DIR/logs/$DATE-hwsim0 &
sudo $WPAS -Dnl80211 -iwlan0 -c $DIR/p2p0.conf -N -Dnl80211 -ista0 -c $DIR/sta-dummy.conf -ddKt > $DIR/logs/$DATE-log0 &
sudo $WPAS -Dnl80211 -iwlan1 -c $DIR/p2p1.conf -N -Dnl80211 -ista1 -c $DIR/sta-dummy.conf -ddKt > $DIR/logs/$DATE-log1 &
sudo $WPAS -Dnl80211 -iwlan2 -c $DIR/p2p2.conf -N -Dnl80211 -ista2 -c $DIR/sta-dummy.conf -ddKt > $DIR/logs/$DATE-log2 &
sleep 1
