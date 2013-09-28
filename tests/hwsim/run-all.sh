#!/bin/sh

errors=0
umask 0002

if [ "x$1" = "xconcurrent-valgrind" ]; then
    if ! ./start-p2p-concurrent.sh valgrind; then
	echo "Could not start test environment" > logs/last-debug
	exit 1
    fi
    DATE=`ls -1tr logs | tail -1 | cut -f1 -d-`
    rm logs/last-debug
    for i in autogo discovery grpform; do
	./run-tests.py -l logs/$DATE-run-$i -e logs/$DATE-failed-$i -r logs/results.txt -f test_p2p_$i.py || errors=1
	cat logs/$DATE-run-$i >> logs/last-debug
    done
    ./stop-wifi.sh
    failures=`grep "ERROR SUMMARY" logs/$DATE-valgrind-* | grep -v " 0 errors" | wc -l`
    if [ $failures -gt 0 ]; then
	echo "Mark as failed due to valgrind errors"
	errors=1
    fi
    if [ $errors -gt 0 ]; then
	tar czf /tmp/hwsim-tests-$DATE-FAILED-concurrent-valgrind.tar.gz logs/$DATE*
	exit 1
    fi
elif [ "x$1" = "xconcurrent" ]; then
    if ! ./start-p2p-concurrent.sh; then
	echo "Could not start test environment" > logs/last-debug
	exit 1
    fi
    DATE=`ls -1tr logs | tail -1 | cut -f1 -d-`
    rm logs/last-debug
    for i in autogo discovery grpform; do
	./run-tests.py -l logs/$DATE-run-$i -e logs/$DATE-failed-$i -r logs/results.txt -f test_p2p_$i.py || errors=1
	cat logs/$DATE-run-$i >> logs/last-debug
    done
    ./stop-wifi.sh
    if [ $errors -gt 0 ]; then
	tar czf /tmp/hwsim-tests-$DATE-FAILED-concurrent.tar.gz logs/$DATE*
	exit 1
    fi
elif [ "x$1" = "xvalgrind" ]; then
    if ! ./start.sh valgrind; then
	echo "Could not start test environment" > logs/last-debug
	exit 1
    fi
    DATE=`ls -1tr logs | tail -1 | cut -f1 -d-`
    ./run-tests.py -l logs/$DATE-run -e logs/$DATE-failed -r logs/results.txt || errors=1
    cat logs/$DATE-run > logs/last-debug
    ./stop-wifi.sh
    failures=`grep "ERROR SUMMARY" logs/$DATE-valgrind-* | grep -v " 0 errors" | wc -l`
    if [ $failures -gt 0 ]; then
	echo "Mark as failed due to valgrind errors"
	errors=1
    fi
    if [ $errors -gt 0 ]; then
	tar czf /tmp/hwsim-tests-$DATE-FAILED-valgrind.tar.gz logs/$DATE*
	exit 1
    fi
elif [ "x$1" = "xtrace" ]; then
    if ! ./start.sh trace; then
	echo "Could not start test environment" > logs/last-debug
	exit 1
    fi
    DATE=`ls -1tr logs | tail -1 | cut -f1 -d-`
    sudo trace-cmd record -o logs/$DATE-trace.dat -e mac80211 -e cfg80211 su $USER -c "./run-tests.py -l logs/$DATE-run -e logs/$DATE-failed -r logs/results.txt" || errors=1
    if [ -e logs/$DATE-failed ]; then
	error=1
    fi
    sudo chown $USER logs/$DATE-trace.dat
    cat logs/$DATE-run > logs/last-debug
    ./stop-wifi.sh
    if [ $errors -gt 0 ]; then
	tar czf /tmp/hwsim-tests-$DATE-FAILED-trace.tar.gz logs/$DATE*
	exit 1
    fi
else
    if ! ./start.sh; then
	echo "Could not start test environment" > logs/last-debug
	exit 1
    fi
    DATE=`ls -1tr logs | tail -1 | cut -f1 -d-`
    ./run-tests.py -l logs/$DATE-run -e logs/$DATE-failed -r logs/results.txt || errors=1
    cat logs/$DATE-run > logs/last-debug
    ./stop-wifi.sh
    if [ $errors -gt 0 ]; then
	tar czf /tmp/hwsim-tests-$DATE-FAILED.tar.gz logs/$DATE*
	exit 1
    fi
fi

echo "ALL-PASSED"
