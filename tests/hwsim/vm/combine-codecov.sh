#!/bin/bash

LOGDIR=$1
if [ -n "$2" ]; then
    ODIR=$2
else
    ODIR=.
fi
TMPDIR=/tmp/logs

mv $LOGDIR/alt-* $TMPDIR

cd $TMPDIR
args=""
for i in lcov-*.info-*; do
    args="$args -a $i"
done

lcov $args -o $LOGDIR/combined.info > $LOGDIR/combined-lcov.log 2>&1
cd $LOGDIR
genhtml -t "wpa_supplicant/hostapd combined for hwsim test run $(date +%s)" combined.info --output-directory $ODIR > lcov.log 2>&1

rm -r /tmp/logs/alt-wpa_supplicant
rm -r /tmp/logs/alt-hostapd
rm -r /tmp/logs/alt-hostapd-as
rm -r /tmp/logs/alt-hlr_auc_gw
rm /tmp/logs/lcov-*info-*
rmdir /tmp/logs
