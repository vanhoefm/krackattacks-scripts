#!/bin/sh

cd "$(dirname $0)"

NUM=$1
if [ -z "$NUM" ]; then
    echo "usage: $0 <num servers> [params..]"
    exit 1
fi
shift

LOGS=/tmp/hwsim-test-logs
mkdir -p $LOGS
DATE=$(date +%s)

for i in `seq 1 $NUM`; do
    echo "Starting virtual machine $i/$NUM"
    ./vm-run.sh --ext srv.$i --split $i/$NUM $* >> $LOGS/parallel-$DATE.srv.$i 2>&1 &
done

echo "Waiting for virtual machines to complete testing"
wait
echo "Testing completed"

echo -n "PASS count: "
grep ^PASS $LOGS/parallel-$DATE.srv.* | wc -l
cat $LOGS/parallel-$DATE.srv.* | grep FAIL | sort
