#!/bin/sh

DIR="$( cd "$( dirname "$0" )" && pwd )"
WPAS=$DIR/../../wpa_supplicant/wpa_supplicant
WPACLI=$DIR/../../wpa_supplicant/wpa_cli
HAPD=$DIR/../../hostapd/hostapd
WLANTEST=$DIR/../../wlantest/wlantest
HLR_AUC_GW=$DIR/../../hostapd/hlr_auc_gw

DATE=`date +%s`

if [ -z "$LOGDIR" ] ; then
    LOGDIR=$DIR/logs
fi
export LOGDIR

if groups | tr ' ' "\n" | grep -q ^admin$; then
    GROUP=admin
else
    GROUP=adm
fi

if [ "$1" = "concurrent" ]; then
    CONCURRENT=y
    CONCURRENT_ARGS="-N -Dnl80211 -ista%d -c $DIR/sta-dummy.conf"
    shift
else
    unset CONCURRENT
    CONCURRENT_ARGS=
fi

if [ "$1" = "valgrind" ]; then
    VALGRIND=y
    VALGRIND_WPAS="valgrind --log-file=$LOGDIR/$DATE-valgrind-wlan%d"
    VALGRIND_HAPD="valgrind --log-file=$LOGDIR/$DATE-valgrind-hostapd"
    chmod a+rx $WPAS
    chmod a+rx $HAPD
    shift
else
    unset VALGRIND
    VALGRIND_WPAS=
    VALGRIND_HAPD=
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
mkdir -p $LOGDIR
sudo ifconfig hwsim0 up
sudo $WLANTEST -i hwsim0 -c -d > $LOGDIR/$DATE-hwsim0 &
sudo tcpdump -ni hwsim0 -s 2500 -w $LOGDIR/$DATE-hwsim0.dump > $LOGDIR/$DATE-tcpdump 2>&1 &
for i in 0 1 2; do
    sudo $(printf -- "$VALGRIND_WPAS" $i) $WPAS -g /tmp/wpas-wlan$i -G$GROUP -Dnl80211 -iwlan$i -c $DIR/p2p$i.conf \
         $(printf -- "$CONCURRENT_ARGS" $i) -ddKt$TRACE > $LOGDIR/$DATE-log$i &
done
sudo $VALGRIND_HAPD $HAPD -ddKt -g /var/run/hostapd-global -G $GROUP -ddKt > $LOGDIR/$DATE-hostapd &

sleep 1
sudo chown $USER $LOGDIR/$DATE-hwsim0.dump
if [ "x$VALGRIND" = "xy" ]; then
    sudo chown $USER $LOGDIR/$DATE-*valgrind*
fi

if [ -x $HLR_AUC_GW ]; then
    $HLR_AUC_GW -m $DIR/auth_serv/hlr_auc_gw.milenage_db > $LOGDIR/$DATE-hlr_auc_gw &
fi

$HAPD -ddKt $DIR/auth_serv/as.conf > $LOGDIR/$DATE-auth_serv &

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
