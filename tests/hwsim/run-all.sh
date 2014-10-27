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

unset VALGRIND
unset TRACE
unset TRACE_ARGS
unset RUN_TEST_ARGS
while [ "$1" != "" ]; do
	case $1 in
		-v | --valgrind | valgrind)
			shift
			echo "$0: using valgrind"
			VALGRIND=valgrind
			;;
		-t | --trace | trace)
			shift
			echo "$0: using Trace"
			TRACE=trace
			;;
		-n | --channels)
			shift
			NUM_CH=$1
			shift
			echo "$0: using channels=$NUM_CH"
			;;
		*)
			RUN_TEST_ARGS="$RUN_TEST_ARGS$1 "
			shift
			;;
	esac
done

if [ ! -z "$RUN_TEST_ARGS" ]; then
	echo "$0: passing the following args to run-tests.py: $RUN_TEST_ARGS"
fi

unset SUFFIX
if [ ! -z "$VALGRIND" ]; then
	SUFFIX=-valgrind
fi

if [ ! -z "$TRACE" ]; then
	SUFFIX=$SUFFIX-trace
	TRACE_ARGS="-T"
fi

if ! ./start.sh $VALGRIND $TRACE $NUM_CH; then
	if ! [ -z "$LOGBASEDIR" ] ; then
		echo "Could not start test environment" > $LOGDIR/run
	fi
	exit 1
fi

sudo ./run-tests.py -D --logdir "$LOGDIR" $TRACE_ARGS -q $DB $RUN_TEST_ARGS || errors=1

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
