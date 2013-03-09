#!/bin/sh

errors=0
./start-p2p.sh
./run-p2p-tests.py || errors=1
./stop-wifi.sh
if [ $errors -gt 0 ]; then
    exit 1
fi
