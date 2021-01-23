#!/bin/bash
cd ../hostapd/
cp defconfig .config
make -j 2
