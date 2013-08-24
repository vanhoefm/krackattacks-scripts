#!/bin/sh

DIR="$( cd "$( dirname "$0" )" && pwd )"
WPAS=$DIR/../../wpa_supplicant/wpa_supplicant
HAPD=$DIR/../../hostapd/hostapd
WLANTEST=$DIR/../../wlantest/wlantest

if [ "x$1" = "xvalgrind" ]; then
    VALGRIND=y
else
    unset VALGRIND
fi

$DIR/stop-wifi.sh
sudo modprobe mac80211_hwsim radios=5
mkdir -p $DIR/logs
DATE=`date +%s`
sudo ifconfig hwsim0 up
sudo $WLANTEST -i hwsim0 -c -d > $DIR/logs/$DATE-hwsim0 &
sudo tcpdump -ni hwsim0 -s 2500 -w $DIR/logs/$DATE-hwsim0.dump &
if [ "x$VALGRIND" = "xy" ]; then
    for i in 0 1 2; do
	sudo valgrind --log-file=$DIR/logs/$DATE-valgrind-wlan$i $WPAS -g /tmp/wpas-wlan$i -Gadmin -Dnl80211 -iwlan$i -c $DIR/p2p$i.conf -ddKt > $DIR/logs/$DATE-log$i &
    done
    sudo valgrind --log-file=$DIR/logs/$DATE-valgrind-hostapd $HAPD -ddKt -g /var/run/hostapd-global -G admin -ddKt > $DIR/logs/$DATE-hostapd &
else
    for i in 0 1 2; do
	sudo $WPAS -g /tmp/wpas-wlan$i -Gadmin -Dnl80211 -iwlan$i -c $DIR/p2p$i.conf -ddKt > $DIR/logs/$DATE-log$i &
    done
    sudo $HAPD -ddKt -g /var/run/hostapd-global -G admin -ddKt > $DIR/logs/$DATE-hostapd &
fi
sleep 1
sudo chown $USER $DIR/logs/$DATE-hwsim0.dump
if [ "x$VALGRIND" = "xy" ]; then
    sudo chown $USER $DIR/logs/$DATE-*valgrind*
    sleep 2
fi
