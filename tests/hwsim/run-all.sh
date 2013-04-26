#!/bin/sh

errors=0
umask 0002
./start.sh
DATE=`ls -1tr logs | tail -1 | cut -f1 -d-`
./run-tests.py -e logs/$DATE-failed || errors=1
./stop-wifi.sh
if [ $errors -gt 0 ]; then
    tar czf /tmp/hwsim-tests-$DATE-FAILED.tar.gz logs/$DATE*
    exit 1
fi
