#!/bin/sh

DIR="$( cd "$( dirname "$0" )" && pwd )"
WPAS=$DIR/../../wpa_supplicant/wpa_supplicant
WPACLI=$DIR/../../wpa_supplicant/wpa_cli
HAPD=$DIR/../../hostapd/hostapd
WLANTEST=$DIR/../../wlantest/wlantest

if [ "x$1" = "xvalgrind" ]; then
    VALGRIND=y
else
    unset VALGRIND
fi

$DIR/stop-wifi.sh
sudo modprobe mac80211_hwsim radios=5
sudo iw wlan0 interface add sta0 type station
sudo iw wlan1 interface add sta1 type station
sudo iw wlan2 interface add sta2 type station
mkdir -p $DIR/logs
DATE=`date +%s`
sudo ifconfig hwsim0 up
sudo $WLANTEST -i hwsim0 -c -d > $DIR/logs/$DATE-hwsim0 &
sudo tcpdump -ni hwsim0 -s 2500 -w $DIR/logs/$DATE-hwsim0.dump > $DIR/logs/$DATE-tcpdump 2>&1 &
if [ "x$VALGRIND" = "xy" ]; then
    for i in 0 1 2; do
	sudo valgrind --log-file=$DIR/logs/$DATE-valgrind-wlan$i $WPAS -g /tmp/wpas-wlan$i -Gadmin -Dnl80211 -iwlan$i -c $DIR/p2p$i.conf -N -Dnl80211 -ista$i -c $DIR/sta-dummy.conf -ddKt > $DIR/logs/$DATE-log$i &
    done
    sudo valgrind --log-file=$DIR/logs/$DATE-valgrind-hostapd $HAPD -ddKt -g /var/run/hostapd-global -G admin -ddKt > $DIR/logs/$DATE-hostapd &
else
    for i in 0 1 2; do
	sudo $WPAS -g /tmp/wpas-wlan$i -Gadmin -Dnl80211 -iwlan$i -c $DIR/p2p$i.conf -N -Dnl80211 -ista$i -c $DIR/sta-dummy.conf -ddKt > $DIR/logs/$DATE-log$i &
    done
    sudo $HAPD -ddKt -g /var/run/hostapd-global -G admin -ddKt > $DIR/logs/$DATE-hostapd &
fi
sleep 1
sudo chown $USER $DIR/logs/$DATE-hwsim0.dump
if [ "x$VALGRIND" = "xy" ]; then
    sudo chown $USER $DIR/logs/$DATE-valgrind*
fi

# wait for programs to be fully initialized
for i in 0 1 2; do
    for j in `seq 1 10`; do
	if $WPACLI -g /tmp/wpas-wlan$i ping | grep -q PONG; then
	    break
	fi
	if [ $j = "10" ]; then
	    echo "Could not connect to /tmp/wpas-wlan$i"
	    exit 1
	fi
	sleep 1
    done
done

for j in `seq 1 10`; do
    if $WPACLI -g /var/run/hostapd-global ping | grep -q PONG; then
	break
    fi
    if [ $j = "10" ]; then
	echo "Could not connect to /var/run/hostapd-global"
	exit 1
    fi
    sleep 1
done

exit 0
