#!/bin/sh

DIR="$( cd "$( dirname "$0" )" && pwd )"
WPAS=$DIR/../../wpa_supplicant/wpa_supplicant
WPACLI=$DIR/../../wpa_supplicant/wpa_cli
HAPD=$DIR/../../hostapd/hostapd
WLANTEST=$DIR/../../wlantest/wlantest
HLR_AUC_GW=$DIR/../../hostapd/hlr_auc_gw

if groups | tr ' ' "\n" | grep -q ^admin$; then
    GROUP=admin
else
    GROUP=adm
fi

if [ "$1" = "concurrent" ]; then
    CONCURRENT=y
    shift
else
    unset CONCURRENT
fi

if [ "$1" = "valgrind" ]; then
    VALGRIND=y
    shift
else
    unset VALGRIND
fi

if [ "$1" = "trace" ]; then
    TRACE="T"
    shift
else
    TRACE=""
fi

$DIR/stop-wifi.sh
git show -s --format=%H > commit
sudo modprobe mac80211_hwsim radios=5
if [ "$CONCURRENT" = "y" ]; then
    sudo iw wlan0 interface add sta0 type station
    sudo iw wlan1 interface add sta1 type station
    sudo iw wlan2 interface add sta2 type station
fi
mkdir -p $DIR/logs
DATE=`date +%s`
sudo ifconfig hwsim0 up
sudo $WLANTEST -i hwsim0 -c -d > $DIR/logs/$DATE-hwsim0 &
sudo tcpdump -ni hwsim0 -s 2500 -w $DIR/logs/$DATE-hwsim0.dump > $DIR/logs/$DATE-tcpdump 2>&1 &
if [ "$VALGRIND" = "y" ]; then
    for i in 0 1 2; do
	chmod a+rx $WPAS
	if [ "$CONCURRENT" = "y" ]; then
	    sudo valgrind --log-file=$DIR/logs/$DATE-valgrind-wlan$i $WPAS -g /tmp/wpas-wlan$i -G$GROUP -Dnl80211 -iwlan$i -c $DIR/p2p$i.conf -N -Dnl80211 -ista$i -c $DIR/sta-dummy.conf -ddKt$TRACE > $DIR/logs/$DATE-log$i &
	else
	    sudo valgrind --log-file=$DIR/logs/$DATE-valgrind-wlan$i $WPAS -g /tmp/wpas-wlan$i -G$GROUP -Dnl80211 -iwlan$i -c $DIR/p2p$i.conf -ddKt$TRACE > $DIR/logs/$DATE-log$i &
	fi
    done
    chmod a+rx $HAPD
    sudo valgrind --log-file=$DIR/logs/$DATE-valgrind-hostapd $HAPD -ddKt -g /var/run/hostapd-global -G $GROUP -ddKt > $DIR/logs/$DATE-hostapd &
else
    for i in 0 1 2; do
	if [ "$CONCURRENT" = "y" ]; then
	    sudo $WPAS -g /tmp/wpas-wlan$i -G$GROUP -Dnl80211 -iwlan$i -c $DIR/p2p$i.conf -N -Dnl80211 -ista$i -c $DIR/sta-dummy.conf -ddKt$TRACE > $DIR/logs/$DATE-log$i &
	else
	    sudo $WPAS -g /tmp/wpas-wlan$i -G$GROUP -Dnl80211 -iwlan$i -c $DIR/p2p$i.conf -ddKt$TRACE > $DIR/logs/$DATE-log$i &
	fi
    done
    sudo $HAPD -ddKt -g /var/run/hostapd-global -G $GROUP -ddKt > $DIR/logs/$DATE-hostapd &
fi
sleep 1
sudo chown $USER $DIR/logs/$DATE-hwsim0.dump
if [ "x$VALGRIND" = "xy" ]; then
    sudo chown $USER $DIR/logs/$DATE-*valgrind*
fi

if [ -x $HLR_AUC_GW ]; then
    $HLR_AUC_GW -m $DIR/auth_serv/hlr_auc_gw.milenage_db > $DIR/logs/$DATE-hlr_auc_gw &
fi

$HAPD -ddKt $DIR/auth_serv/as.conf > $DIR/logs/$DATE-auth_serv &

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
