#!/bin/sh

errors=0
umask 0002

if [ "x$1" = "xconcurrent-valgrind" ]; then
    ./start-p2p-concurrent.sh valgrind
    DATE=`ls -1tr logs | tail -1 | cut -f1 -d-`
    rm logs/last-debug
    for i in autogo discovery grpform; do
	./run-tests.py -l logs/$DATE-run-$i -e logs/$DATE-failed-$i -f test_p2p_$i.py || errors=1
	cat logs/$DATE-run-$i >> logs/last-debug
    done
    ./stop-wifi.sh valgrind
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
    ./start-p2p-concurrent.sh
    DATE=`ls -1tr logs | tail -1 | cut -f1 -d-`
    rm logs/last-debug
    for i in autogo discovery grpform; do
	./run-tests.py -l logs/$DATE-run-$i -e logs/$DATE-failed-$i -f test_p2p_$i.py || errors=1
	cat logs/$DATE-run-$i >> logs/last-debug
    done
    ./stop-wifi.sh
    if [ $errors -gt 0 ]; then
	tar czf /tmp/hwsim-tests-$DATE-FAILED-concurrent.tar.gz logs/$DATE*
	exit 1
    fi
elif [ "x$1" = "xvalgrind" ]; then
    ./start.sh valgrind
    DATE=`ls -1tr logs | tail -1 | cut -f1 -d-`
    ./run-tests.py -l logs/$DATE-run -e logs/$DATE-failed || errors=1
    cat logs/$DATE-run > logs/last-debug
    ./stop-wifi.sh valgrind
    failures=`grep "ERROR SUMMARY" logs/$DATE-valgrind-* | grep -v " 0 errors" | wc -l`
    if [ $failures -gt 0 ]; then
	echo "Mark as failed due to valgrind errors"
	errors=1
    fi
    if [ $errors -gt 0 ]; then
	tar czf /tmp/hwsim-tests-$DATE-FAILED-valgrind.tar.gz logs/$DATE*
	exit 1
    fi
else
    ./start.sh
    DATE=`ls -1tr logs | tail -1 | cut -f1 -d-`
    ./run-tests.py -l logs/$DATE-run -e logs/$DATE-failed || errors=1
    cat logs/$DATE-run > logs/last-debug
    ./stop-wifi.sh
    if [ $errors -gt 0 ]; then
	tar czf /tmp/hwsim-tests-$DATE-FAILED.tar.gz logs/$DATE*
	exit 1
    fi
fi
