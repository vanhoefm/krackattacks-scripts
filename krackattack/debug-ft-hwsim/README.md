To verify the script is working correctly, try it out against a virtualized Wi-Fi network as follows:

	apt-get install vtun bridge-utils hostapd
	./initradios.sh
	./hostap0.sh # Start fist access point in window 1
	./hostap1.sh # Start second access point in window 2

Now read the documentation in `krack-ft-test.py`. Go to step 3 and start the tool using:

	../krack-ft-test.py wpa_supplicant -D nl80211 -i wlan2 -c supplicant.conf

Follow the next steps. To generate traffic in step 5 use `./gen-traffic.py`.
