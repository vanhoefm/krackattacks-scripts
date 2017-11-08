#!/bin/bash

cd "$(dirname $0)"

NUM=$1
if [ -z "$NUM" ]; then
    echo "usage: $0 <num servers> [params..]"
    exit 1
fi
shift

if [ -n "$HWSIM_TEST_LOG_DIR" ] ; then
	LOGS="$HWSIM_TEST_LOG_DIR"
else
	LOGS=/tmp/hwsim-test-logs
fi
mkdir -p $LOGS
DATE=$(date +%s)

for i in `seq 1 $NUM`; do
    printf "\rStarting virtual machine $i/$NUM"
    ./vm-run.sh --timestamp $DATE --ext srv.$i --split $i/$NUM $* >> $LOGS/parallel-$DATE.srv.$i 2>&1 &
done
echo

echo "Waiting for virtual machines to complete testing"
count=$NUM
for i in `seq 1 $NUM`; do
    printf "\r$count VM(s) remaining   "
    wait -n
    count=$((count-1))
done
printf "\rTesting completed       "
echo

echo -n "PASS count: "
grep ^PASS $LOGS/parallel-$DATE.srv.* | wc -l
cat $LOGS/parallel-$DATE.srv.* | grep FAIL | sort
