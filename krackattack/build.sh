#!/bin/bash

cd ../hostapd/
make clean

cp defconfig .config
make -j 2
