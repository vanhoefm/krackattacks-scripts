#!/bin/sh

DIR="$( cd "$( dirname "$0" )" && pwd )"
WPAS=$DIR/../../wpa_supplicant/wpa_supplicant
WPACLI=$DIR/../../wpa_supplicant/wpa_cli
HAPD=$DIR/../../hostapd/hostapd
WLANTEST=$DIR/../../wlantest/wlantest
HLR_AUC_GW=$DIR/../../hostapd/hlr_auc_gw

if [ -z "$LOGDIR" ] ; then
    DATE="$(date +%s)"
    LOGDIR="$DIR/logs/$DATE"
    mkdir -p $LOGDIR
    rm -rf $DIR/logs/current
    ln -sf $DATE $DIR/logs/current
fi

if groups | tr ' ' "\n" | grep -q ^admin$; then
    GROUP=admin
else
    GROUP=adm
fi

sed "s/ GROUP=.*$/ GROUP=$GROUP/" "$DIR/sta-dummy.conf" > "$LOGDIR/sta-dummy.conf"
for i in 0 1 2; do
    sed "s/ GROUP=.*$/ GROUP=$GROUP/" "$DIR/p2p$i.conf" > "$LOGDIR/p2p$i.conf"
done

if [ "$1" = "concurrent" ]; then
    CONCURRENT=y
    CONCURRENT_ARGS="-N -Dnl80211 -ista%d -c $LOGDIR/sta-dummy.conf"
    shift
else
    unset CONCURRENT
    CONCURRENT_ARGS=
fi

if [ "$1" = "valgrind" ]; then
    VALGRIND=y
    VALGRIND_WPAS="valgrind --log-file=$LOGDIR/valgrind-wlan%d"
    VALGRIND_HAPD="valgrind --log-file=$LOGDIR/valgrind-hostapd"
    chmod -f a+rx $WPAS
    chmod -f a+rx $HAPD
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

$DIR/stop.sh
test -f /proc/modules && sudo modprobe mac80211_hwsim radios=5
if [ "$CONCURRENT" = "y" ]; then
    sudo iw wlan0 interface add sta0 type station
    sudo iw wlan1 interface add sta1 type station
    sudo iw wlan2 interface add sta2 type station
fi
sudo ifconfig hwsim0 up
sudo $WLANTEST -i hwsim0 -n $LOGDIR/hwsim0.pcapng -c -dt -L $LOGDIR/hwsim0 &
for i in 0 1 2; do
    sudo $(printf -- "$VALGRIND_WPAS" $i) $WPAS -g /tmp/wpas-wlan$i -G$GROUP -Dnl80211 -iwlan$i -c $LOGDIR/p2p$i.conf \
         $(printf -- "$CONCURRENT_ARGS" $i) -ddKt$TRACE -f $LOGDIR/log$i &
done
sudo $VALGRIND_HAPD $HAPD -ddKt$TRACE -g /var/run/hostapd-global -G $GROUP -ddKt -f $LOGDIR/hostapd &

sleep 1
sudo chown -f $USER $LOGDIR/hwsim0.pcapng $LOGDIR/hwsim0 $LOGDIR/log* $LOGDIR/hostapd
if [ "x$VALGRIND" = "xy" ]; then
    sudo chown -f $USER $LOGDIR/*valgrind*
fi

if [ -x $HLR_AUC_GW ]; then
    $HLR_AUC_GW -m $DIR/auth_serv/hlr_auc_gw.milenage_db > $LOGDIR/hlr_auc_gw &
fi

$HAPD -ddKt $DIR/auth_serv/as.conf > $LOGDIR/auth_serv &

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
