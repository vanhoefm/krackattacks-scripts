#!/bin/sh

errors=0
umask 0002

if [ -z "$LOGDIR" ]; then
	LOGDIR=logs
fi

if [ -z "$DBFILE" ]; then
    DB=""
else
    DB="-S $DBFILE --commit $(git rev-parse HEAD)"
    if [ -n "$BUILD" ]; then
	DB="$DB -b $BUILD"
    fi
fi

if [ "x$1" = "xconcurrent-valgrind" ]; then
	VALGRIND=valgrind
	CONCURRENT=concurrent
	CONCURRENT_TESTS="-f test_p2p_autogo test_p2p_discovery test_p2p_grpform"
	SUFFIX=-concurrent-valgrind
	shift
elif [ "x$1" = "xconcurrent" ]; then
	CONCURRENT=concurrent
	CONCURRENT_TESTS="-f test_p2p_autogo test_p2p_discovery test_p2p_grpform"
	unset VALGRIND
	SUFFIX=-concurrent
	shift
elif [ "x$1" = "xvalgrind" ]; then
	VALGRIND=valgrind
	unset CONCURRENT
	unset CONCURRENT_TESTS
	SUFFIX=-valgrind
	shift
else
	unset VALGRIND
	unset CONCURRENT
	unset CONCURRENT_TESTS
	SUFFIX=
fi

if [ "x$1" = "xtrace" ] ; then
	TRACE=trace
	SUFFIX=$SUFFIX-trace
else
	unset TRACE
fi

if ! ./start.sh $CONCURRENT $VALGRIND $TRACE; then
	echo "Could not start test environment" > $LOGDIR/last-debug
	exit 1
fi
DATE=`ls -1tr $LOGDIR | tail -1 | cut -f1 -d-`
rm $LOGDIR/last-debug 2>/dev/null
RUNTESTS="./run-tests.py -l $LOGDIR/$DATE-run $DB -e $LOGDIR/$DATE-failed -r $LOGDIR/results.txt $CONCURRENT_TESTS"

if [ "$TRACE" != "" ] ; then
	sudo trace-cmd record -o $LOGDIR/$DATE-trace.dat -e mac80211 -e cfg80211 su $USER -c $RUNTESTS || errors=1
else
	$RUNTESTS || errors=1
fi


cat $LOGDIR/$DATE-run >> $LOGDIR/last-debug
./stop-wifi.sh

if [ ! -z "$VALGRIND" ] ; then
    failures=`grep "ERROR SUMMARY" $LOGDIR/$DATE-valgrind-* | grep -v " 0 errors" | wc -l`
    if [ $failures -gt 0 ]; then
	echo "Mark as failed due to valgrind errors"
	errors=1
    fi
fi
if [ $errors -gt 0 ]; then
    tar czf /tmp/hwsim-tests-$DATE-FAILED$SUFFIX.tar.gz $LOGDIR/$DATE*
    exit 1
fi

echo "ALL-PASSED"
