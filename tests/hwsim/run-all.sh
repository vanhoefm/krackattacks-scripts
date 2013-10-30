#!/bin/sh

errors=0
umask 0002

DATE="$(date +%s)"
unset LOGBASEDIR
if [ -z "$LOGDIR" ]; then
	LOGBASEDIR=logs
	LOGDIR=$LOGBASEDIR/$DATE
	mkdir -p $LOGDIR
fi
export LOGDIR

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
	TRACE_ARGS="-T"
	shift
else
	unset TRACE
	unset TRACE_ARGS
fi

if ! ./start.sh $CONCURRENT $VALGRIND $TRACE; then
	if ! [ -z "$LOGBASEDIR" ] ; then
		echo "Could not start test environment" > $LOGDIR/run
	fi
	exit 1
fi

if ! [ -z "$LOGBASEDIR" ] ; then
	rm $LOGBASEDIR/last-debug 2>/dev/null
fi
./run-tests.py --logdir "$LOGDIR" $TRACE_ARGS -l run $DB -e failed -r results.txt $CONCURRENT_TESTS $@ || errors=1

if ! [ -z "$LOGBASEDIR" ] ; then
	cat $LOGDIR/run >> $LOGBASEDIR/last-debug
fi

./stop-wifi.sh

if [ ! -z "$VALGRIND" ] ; then
    failures=`grep "ERROR SUMMARY" $LOGDIR/valgrind-* | grep -v " 0 errors" | wc -l`
    if [ $failures -gt 0 ]; then
	echo "Mark as failed due to valgrind errors"
	errors=1
    fi
fi
if [ $errors -gt 0 ]; then
    tar czf /tmp/hwsim-tests-$DATE-FAILED$SUFFIX.tar.gz $LOGDIR/
    exit 1
fi

echo "ALL-PASSED"
