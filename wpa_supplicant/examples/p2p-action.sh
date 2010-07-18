#!/bin/sh

IFNAME=$1
CMD=$2

kill_daemon() {
    NAME=$1
    PF=$2

    if [ ! -r $PF ]; then
	return
    fi

    PID=`cat $PF`
    if [ $PID -gt 0 ]; then
	if ps $PID | grep -q $NAME; then
	    kill $PID
	fi
    fi
    rm $PF
}

if [ "$CMD" = "P2P-GROUP-STARTED" ]; then
    GIFNAME=$3
    if [ "$4" = "GO" ]; then
	kill_daemon dhclient /var/run/dhclient-$GIFNAME.pid
	rm /var/run/dhclient.leases-$GIFNAME
	kill_daemon dnsmasq /var/run/dnsmasq.pid-$GIFNAME
	ifconfig $GIFNAME 192.168.42.1 up
	dnsmasq -x /var/run/dnsmasq.pid-$GIFNAME \
	    -i $GIFNAME \
	    -F192.168.42.11,192.168.42.99
    fi
    if [ "$4" = "client" ]; then
	kill_daemon dhclient /var/run/dhclient-$GIFNAME.pid
	rm /var/run/dhclient.leases-$GIFNAME
	kill_daemon dnsmasq /var/run/dnsmasq.pid-$GIFNAME
	dhclient -pf /var/run/dhclient-$GIFNAME.pid \
	    -lf /var/run/dhclient.leases-$GIFNAME \
	    -nw \
	    $GIFNAME
    fi
fi

if [ "$CMD" = "P2P-GROUP-REMOVED" ]; then
    GIFNAME=$3
    if [ "$4" = "GO" ]; then
	kill_daemon dnsmasq /var/run/dnsmasq.pid-$GIFNAME
	ifconfig $GIFNAME 0.0.0.0
    fi
    if [ "$4" = "client" ]; then
	kill_daemon dhclient /var/run/dhclient-$GIFNAME.pid
	rm /var/run/dhclient.leases-$GIFNAME
	ifconfig $GIFNAME 0.0.0.0
    fi
fi
