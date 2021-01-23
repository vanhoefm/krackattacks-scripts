#!/bin/bash

# Copyright (c) 2021, Mathy Vanhoef <Mathy.Vanhoef@cs.kuleuven.be>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

set -e

NOHWCRYPT="ath5k ath9k ath9k_htc rt2800usb carl9170 b43 p54common rt2500usb rt2800pci rt2800usb rt73usb"
SWCRYPTO="iwlwifi iwl3945 iwl4965"
HWCRYPTO="ipw2200"


# 1. Create nohwcrypt.conf options file

rm -f /etc/modprobe.d/nohwcrypt.conf


# 2. Remove loaded modules so they'll reload parameters

for MODULE in $NOHWCRYPT $SWCRYPTO $HWCRYPTO
do
	rmmod $MODULE 2> /dev/null || true;
done


# 3. Done. To be sure parameters are reloaded, reboot computer.

echo "Hardware decryption re-enabled. Reboot your computer."
