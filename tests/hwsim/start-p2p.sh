#!/bin/sh

DIR="$( cd "$( dirname "$0" )" && pwd )"
WPAS=$DIR/../../wpa_supplicant/wpa_supplicant
WLANTEST=$DIR/../../wlantest/wlantest

$DIR/stop-wifi.sh
sudo modprobe mac80211_hwsim radios=3
mkdir -p $DIR/logs
DATE=`date +%s`
sudo ifconfig hwsim0 up
sudo $WLANTEST -i hwsim0 -c -d > $DIR/logs/$DATE-hwsim0 &
sudo $WPAS -Dnl80211 -iwlan0 -c $DIR/p2p0.conf -ddKt > $DIR/logs/$DATE-log0 &
sudo $WPAS -Dnl80211 -iwlan1 -c $DIR/p2p1.conf -ddKt > $DIR/logs/$DATE-log1 &
sudo $WPAS -Dnl80211 -iwlan2 -c $DIR/p2p2.conf -ddKt > $DIR/logs/$DATE-log2 &
sleep 1
