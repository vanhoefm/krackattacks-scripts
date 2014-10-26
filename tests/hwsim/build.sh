#!/bin/sh

set -e

cd $(dirname $0)

use_lcov=0
force_config=0
while [ "$1" != "" ]; do
	case $1 in
		-c | --codecov ) shift
			echo "$0: use code coverage specified"
			use_lcov=1
			;;
		-f | --force-config ) shift
			force_config=1
			echo "$0: force copy config specified"
			;;
		* ) exit 1
	esac
done

cd ../../wpa_supplicant
if [ ! -e .config -o $force_config -eq 1 ]; then
    cp ../tests/hwsim/example-wpa_supplicant.config .config
else
    echo "wpa_supplicant config file exists"
fi

if [ $use_lcov -eq 1 ]; then
    if ! grep -q CONFIG_CODE_COVERAGE .config; then
	    echo CONFIG_CODE_COVERAGE=y >> .config
    else
	    echo "CONFIG_CODE_COVERAGE already exists in wpa_supplicant/.config. Ignore"
    fi
fi

make clean
make -j8

cd ../hostapd
if [ ! -e .config -o $force_config -eq 1 ]; then
    cp ../tests/hwsim/example-hostapd.config .config
else
    echo "hostapd config file exists"
fi

if [ $use_lcov -eq 1 ]; then
    if ! grep -q CONFIG_CODE_COVERAGE .config; then
	    echo CONFIG_CODE_COVERAGE=y >> .config
    else
	    echo "CONFIG_CODE_COVERAGE already exists in hostapd/.config. Ignore"
    fi
fi

make clean
make -j8 hostapd hlr_auc_gw
cd ../wlantest
make clean
make -j8
cd ../mac80211_hwsim/tools
make clean
make -j8
cd ../../tests/hwsim/tnc
make clean
make -j8
cd ..
