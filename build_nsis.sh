#!/bin/sh

if [ -d nsis.in ]; then
	/bin/rm -r nsis.in
fi

unzip -j -d nsis.in $1
VER=`echo $1 | sed "s/.*wpa_supplicant-windows-bin-\(.*\).zip/\1/"`

cat wpa_supplicant/wpa_supplicant.nsi |
	sed "s/@WPAVER@/$VER/g" \
	> nsis.in/wpa_supplicant.nsi

makensis nsis.in/wpa_supplicant.nsi

/bin/rm -r nsis.in
