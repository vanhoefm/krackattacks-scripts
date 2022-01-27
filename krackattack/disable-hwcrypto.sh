#!/bin/bash

# Copyright (c) 2017, Mathy Vanhoef <Mathy.Vanhoef@cs.kuleuven.be>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

set -e

NOHWCRYPT="ath5k ath9k ath9k_htc rt2800usb carl9170 b43 p54common rt2500usb rt2800pci rt73usb"
SWCRYPTO="iwlwifi iwl3945 iwl4965"
HWCRYPTO="ipw2200"
MODFILE="/etc/modprobe.d/nohwcrypt.conf"

# 0. Check if we have root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi


# 1. Create nohwcrypt.conf options file

rm $MODFILE 2> /dev/null || true

for MODULE in $NOHWCRYPT
do echo "options $MODULE nohwcrypt=1" >> $MODFILE; done

for MODULE in $SWCRYPTO
do echo "options $MODULE swcrypto=1" >> $MODFILE; done

for MODULE in $HWCRYPTO
do echo "options $MODULE hwcrypto=0" >> $MODFILE; done


# 2. Remove loaded modules so they'll reload parameters. Note that modules that
#    are in use by others won't be removed (e.g. iwlwifi won't be removed).

for MODULE in $NOHWCRYPT $SWCRYPTO $HWCRYPTO
do rmmod $MODULE 2> /dev/null || true; done


# 3. Done. To be sure parameters are reloaded, reboot computer.

echo "Created config file $MODFILE to disable hardware decryption."
echo "Reboot your computer to apply the changes."
