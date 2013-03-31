#!/bin/sh

errors=0
umask 0002
./start.sh
./run-tests.py || errors=1
./stop-wifi.sh
if [ $errors -gt 0 ]; then
    exit 1
fi
