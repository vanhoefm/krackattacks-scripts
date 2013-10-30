#!/bin/sh

errors=0
umask 0002

if [ -z "$LOGDIR" ]; then
	LOGDIR=logs
fi

if [ -z "$DBFILE" ]; then
    DB=""
else
    DB="-S $DBFILE"
    if [ -n "$BUILD" ]; then
	DB="$DB -b $BUILD"
    fi
fi

if [ "x$1" = "xconcurrent-valgrind" ]; then
    if ! ./start.sh concurrent valgrind; then
	echo "Could not start test environment" > $LOGDIR/last-debug
	exit 1
    fi
    DATE=`ls -1tr $LOGDIR | tail -1 | cut -f1 -d-`
    rm $LOGDIR/last-debug
    for i in autogo discovery grpform; do
	./run-tests.py -l $LOGDIR/$DATE-run-$i $DB -e $LOGDIR/$DATE-failed-$i -r $LOGDIR/results.txt -f test_p2p_$i.py || errors=1
	cat $LOGDIR/$DATE-run-$i >> $LOGDIR/last-debug
    done
    ./stop-wifi.sh
    failures=`grep "ERROR SUMMARY" $LOGDIR/$DATE-valgrind-* | grep -v " 0 errors" | wc -l`
    if [ $failures -gt 0 ]; then
	echo "Mark as failed due to valgrind errors"
	errors=1
    fi
    if [ $errors -gt 0 ]; then
	tar czf /tmp/hwsim-tests-$DATE-FAILED-concurrent-valgrind.tar.gz $LOGDIR/$DATE*
	exit 1
    fi
elif [ "x$1" = "xconcurrent" ]; then
    if ! ./start.sh concurrent; then
	echo "Could not start test environment" > $LOGDIR/last-debug
	exit 1
    fi
    DATE=`ls -1tr $LOGDIR | tail -1 | cut -f1 -d-`
    rm $LOGDIR/last-debug
    for i in autogo discovery grpform; do
	./run-tests.py -l $LOGDIR/$DATE-run-$i $DB -e $LOGDIR/$DATE-failed-$i -r $LOGDIR/results.txt -f test_p2p_$i.py || errors=1
	cat $LOGDIR/$DATE-run-$i >> $LOGDIR/last-debug
    done
    ./stop-wifi.sh
    if [ $errors -gt 0 ]; then
	tar czf /tmp/hwsim-tests-$DATE-FAILED-concurrent.tar.gz $LOGDIR/$DATE*
	exit 1
    fi
elif [ "x$1" = "xvalgrind" ]; then
    if ! ./start.sh valgrind; then
	echo "Could not start test environment" > $LOGDIR/last-debug
	exit 1
    fi
    DATE=`ls -1tr $LOGDIR | tail -1 | cut -f1 -d-`
    ./run-tests.py -l $LOGDIR/$DATE-run $DB -e $LOGDIR/$DATE-failed -r $LOGDIR/results.txt || errors=1
    cat $LOGDIR/$DATE-run > $LOGDIR/last-debug
    ./stop-wifi.sh
    failures=`grep "ERROR SUMMARY" $LOGDIR/$DATE-valgrind-* | grep -v " 0 errors" | wc -l`
    if [ $failures -gt 0 ]; then
	echo "Mark as failed due to valgrind errors"
	errors=1
    fi
    if [ $errors -gt 0 ]; then
	tar czf /tmp/hwsim-tests-$DATE-FAILED-valgrind.tar.gz $LOGDIR/$DATE*
	exit 1
    fi
elif [ "x$1" = "xtrace" ]; then
    if ! ./start.sh trace; then
	echo "Could not start test environment" > $LOGDIR/last-debug
	exit 1
    fi
    DATE=`ls -1tr $LOGDIR | tail -1 | cut -f1 -d-`
    sudo trace-cmd record -o $LOGDIR/$DATE-trace.dat -e mac80211 -e cfg80211 su $USER -c "./run-tests.py -l $LOGDIR/$DATE-run $DB -e $LOGDIR/$DATE-failed -r $LOGDIR/results.txt" || errors=1
    if [ -e $LOGDIR/$DATE-failed ]; then
	error=1
    fi
    sudo chown $USER $LOGDIR/$DATE-trace.dat
    cat $LOGDIR/$DATE-run > $LOGDIR/last-debug
    ./stop-wifi.sh
    if [ $errors -gt 0 ]; then
	tar czf /tmp/hwsim-tests-$DATE-FAILED-trace.tar.gz $LOGDIR/$DATE*
	exit 1
    fi
else
    if ! ./start.sh; then
	echo "Could not start test environment" > $LOGDIR/last-debug
	exit 1
    fi
    DATE=`ls -1tr $LOGDIR | tail -1 | cut -f1 -d-`
    ./run-tests.py -l $LOGDIR/$DATE-run $DB -e $LOGDIR/$DATE-failed -r $LOGDIR/results.txt || errors=1
    cat $LOGDIR/$DATE-run > $LOGDIR/last-debug
    ./stop-wifi.sh
    if [ $errors -gt 0 ]; then
	tar czf /tmp/hwsim-tests-$DATE-FAILED.tar.gz $LOGDIR/$DATE*
	exit 1
    fi
fi

echo "ALL-PASSED"
