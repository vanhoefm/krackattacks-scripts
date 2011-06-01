#!/bin/bash
#
# Copyright (C) 2010 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Generate a wpa_supplicant.conf from the template.
# $1: the template file name
if [ -n "$WIFI_DRIVER_SOCKET_IFACE" ]
then
  sed -e 's/#.*$//' -e 's/[ \t]*$//' -e '/^$/d' < $1 | sed -e "s/wlan0/$WIFI_DRIVER_SOCKET_IFACE/"
else
  sed -e 's/#.*$//' -e 's/[ \t]*$//' -e '/^$/d' < $1
fi
