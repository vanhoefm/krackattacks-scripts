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
    if [ "$PREFILL_DB" = "y" ] ; then
        DB="$DB --prefill-tests"
    fi
fi

if [ "x$1" = "xvalgrind" ]; then
	VALGRIND=valgrind
	SUFFIX=-valgrind
	shift
else
	unset VALGRIND
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

if ! ./start.sh $VALGRIND $TRACE; then
	if ! [ -z "$LOGBASEDIR" ] ; then
		echo "Could not start test environment" > $LOGDIR/run
	fi
	exit 1
fi

./run-tests.py -D --logdir "$LOGDIR" $TRACE_ARGS -q $DB $@ || errors=1

./stop.sh

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
