#!/bin/sh

DIR="$( cd "$( dirname "$0" )" && pwd )"
WPAS=$DIR/../../wpa_supplicant/wpa_supplicant
HAPD=$DIR/../../hostapd/hostapd
WLANTEST=$DIR/../../wlantest/wlantest

$DIR/stop-wifi.sh
sudo modprobe mac80211_hwsim radios=5
sudo iw wlan0 interface add sta0 type station
sudo iw wlan1 interface add sta1 type station
sudo iw wlan2 interface add sta2 type station
mkdir -p $DIR/logs
DATE=`date +%s`
sudo ifconfig hwsim0 up
sudo $WLANTEST -i hwsim0 -c -d > $DIR/logs/$DATE-hwsim0 &
sudo tcpdump -ni hwsim0 -s 2500 -w $DIR/logs/$DATE-hwsim0.dump &
sudo $WPAS -g /tmp/wpas-wlan0 -Gadmin -Dnl80211 -iwlan0 -c $DIR/p2p0.conf -N -Dnl80211 -ista0 -c $DIR/sta-dummy.conf -ddKt > $DIR/logs/$DATE-log0 &
sudo $WPAS -g /tmp/wpas-wlan1 -Gadmin -Dnl80211 -iwlan1 -c $DIR/p2p1.conf -N -Dnl80211 -ista1 -c $DIR/sta-dummy.conf -ddKt > $DIR/logs/$DATE-log1 &
sudo $WPAS -g /tmp/wpas-wlan2 -Gadmin -Dnl80211 -iwlan2 -c $DIR/p2p2.conf -N -Dnl80211 -ista2 -c $DIR/sta-dummy.conf -ddKt > $DIR/logs/$DATE-log2 &
sudo $HAPD -ddKt -g /var/run/hostapd-global -G admin -ddKt > $DIR/logs/$DATE-hostapd &
sleep 1
sudo chown $USER $DIR/logs/$DATE-hwsim0.dump
