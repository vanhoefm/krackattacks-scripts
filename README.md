This project contains scripts to test if clients or access points (APs) are affected by the KRACK attack against WPA2. For [details behind this attack see our website](https://www.krackattacks.com) and [the research paper](https://papers.mathyvanhoef.com/ccs2017.pdf).

Remember that our scripts are not attack scripts! You will need the appropriate network credentials in order to test if an access point or client is affected by the KRACK attack.

**21 January 2021**: the scripts have been made compatible with Python3 and has been updated to better support newer Linux distributions. If you want to revert to the old version, execute `git fetch --tags && git checkout v1` after cloning the repository (and switch back to the latest version using `git checkout research`).


# Prerequisites

Our scripts were tested on Kali Linux. To install the required dependencies on Kali, execute:

	sudo apt update
	sudo apt install libnl-3-dev libnl-genl-3-dev pkg-config libssl-dev net-tools git sysfsutils virtualenv

Now compile our modified hostapd instance and create a python virtual environment. This assure you're using compatible python libraries (those listed in `krackattack/requirements.txt`):

	git clone https://github.com/vanhoefm/krackattacks-scripts.git
	cd krackattacks-scripts/krackattack
	./build.sh
	./pysetup.sh

Then **disable hardware encryption** for optimal results:

	cd krackattack
	sudo ./disable-hwcrypto.sh

Note that if needed you can later re-enable hardware encryption using the script `sudo ./reenable-hwcrypto.sh`. It's recommended to reboot after disabling hardware encryption. We tested our scripts with an Intel Dual Band Wireless-AC 7260 and a TP-Link TL-WN722N v1 on Kali Linux.

# Before every usage

Every time before you use the scripts you must **disable Wi-Fi** in your network manager. Then execute:

	sudo rfkill unblock wifi
	cd krackattack
	sudo su
	source venv/bin/activate

After doing this you can executing the scripts multiple times as long as you don't close the terminal.


If you want to undo the effects of the `disable-hwcrypto.sh` then delete the file `/etc/modprobe.d/nohwcrypt.conf`.

# Testing Clients

First modify `hostapd/hostapd.conf` and **edit the line `interface=` to specify the Wi-Fi interface** that will be used to execute the tests. Note that for all tests, once the script is running, you must let the device being tested connect to the **SSID testnetwork using the password abcdefgh**. You can change settings of the AP by modifying `hostapd/hostapd.conf`. In all tests the **client must use DHCP to get an IP** after connecting to the Wi-Fi network. This is because some tests only start after the client has requested an IP using DHCP!

You should now run the following tests located in the `krackattacks/` directory:

1. **`./krack-test-client.py --replay-broadcast`**. This tests whether the client accepts replayed broadcast frames. If the client accepts replayed broadcast frames, this must be patched first. If you do not patch the client, our script will not be able to determine if the group key is being reinstalled (because then the script will always say the group key is being reinstalled).

2. **`./krack-test-client.py --group --gtkinit`**. This tests whether the client installs the group key in the group key handshake with the given receive sequence counter (RSC). See section 6.4 of our [follow-up research paper(https://papers.mathyvanhoef.com/ccs2018.pdf)] for the details behind this vulnerability.

3. **`./krack-test-client.py --group`**. This tests whether the client reinstalls the group key in the group key handshake. In other words, it **tests if the client is vulnerable to CVE-2017-13080**. The script tests for reinstallations of the group key by sending broadcast ARP requests to the client using an already used (replayed) packet number (here packet number = nonce = IV). Note that if the client always accepts replayed broadcast frames (see `--replay-broadcast`), this test might incorrectly conclude the group key is being reinstalled.

4. **`./krack-test-client.py`**. This tests for key reinstallations in the 4-way handshake by repeatedly sending encrypted message 3's to the client. **In other words, this tests for CVE-2017-13077 (the vulnerability with the highest impact) and for CVE-2017-13078 .** The script monitors traffic sent by the client to see if the pairwise key is being reinstalled. Note that this effectively performs two tests: whether the pairwise key is reinstalled, and whether the group key is reinstalled. Make sure the client requests an IP using DHCP for the group key reinstallation test to start. To assure the client is sending enough unicast frames, you can optionally ping the AP: `ping 192.168.100.254`.

5. **`./krack-test-client.py --tptk`**. Identical to test 4, except that a forged message 1 is injected before sending the encrypted message 3. This variant of the test is important because some clients (e.g. wpa_supplicant v2.6) are only vulnerable to pairwise key reinstallations in the 4-way handshake when a forged message 1 is injected before sending a retransmitted message 3.

6. **`./krack-test-client.py --tptk-rand`**. Same as the above test, except that the forged message 1 contains a random ANonce.

7. **`./krack-test-client.py --gtkinit`**. This tests whether the client installs the group key in the 4-way handshake with the given receive sequence counter (RSC). The script will continously execute new 4-way handshakes to test this. Unfortunately, this test can be rather unreliable, because any missed handshake messages cause synchronization issues, making the test unreliable. You should only execute this test in environments with little background noise, and execute it several times.


Some additional remarks:

* The most important test is `./krack-test-client`, which tests for ordinary key reinstallations in the 4-way handshake.

* Perform these tests in a room with little interference. A high amount of packet loss will make this script less reliable!

* Optionally you can manually inspect network traffic to confirm the output of the script (some Wi-Fi NICs may interfere with our scripts):

	- Use an extra Wi-Fi NIC in monitor mode to conform that our script (the AP) sends out frames using the proper packet numbers (IVs). In particular, check whether replayed broadcast frames indeed are sent using an already used packet number (IV).

	- Use an extra Wi-Fi NIC in monitor mode to check pairwise key reinstalls by monitoring the IVs of frames sent by the client.

	- Capture traffic on the client to see if the replayed broadcast ARP requests are accepted or not.

* If the client can use multiple Wi-Fi radios/NICs, perform the test using several Wi-Fi NICs.

* You can add the `--debug` parameter for more debugging output.

* All unrecognized parameters are passed on to hostapd, so you can include something like `-dd -K` to make hostapd output all debug info.


## Correspondence to Wi-Fi Alliance tests

The [Wi-Fi Alliance created a custom vulnerability detection tool](https://www.wi-fi.org/security-update-october-2017) based on our scripts.
At the time of writing, this tool is only accessible to Wi-Fi Alliance members.
Their tools supports several different tests, and these tests correspond to the functionality in our script as follows:

- 4.1.1 (Plaintext retransmission of EAPOL Message 3). We currently do not support this test. This test is not necessary anyway. Make sure the device being tested passes test 4.1.3, and then it will also pass this test.

- 4.1.2 (Immediate retransmission of EAPOL M3 in plaintext). We currently do not suppor this test. Again, make sure the device being tested passes test 4.1.3, and then it will also pass this test.

- 4.1.3 (Immediate retransmission of encrypted EAPOL M3 during pairwise rekey handshake). This corresponds to `./krack-test-client.py`, except that encrypted EAPOL M3 are sent periodically instead of immediately.

- 4.1.5 (PTK reinstallation in 4-way handshake when STA uses Temporal PTK construction, same ANonce). Execute this test using `./krack-test-client.py --tptk`.

- 4.1.6 (PTK reinstallation in 4-way handshake when STA uses Temporal PTK construction, random ANonce). Execute this test using `./krack-test-client.py --tptk-rand`.

- 4.2.1 (Group key handshake vulnerability test on STA). Execue this test using `./krack-test-client.py --group`.

- 4.3.1 (Reinstallation of GTK and IGTK on STA supporting WNM sleep mode). We currently do not support this test (and neither does the Wi-Fi Alliance actually!).


# Testing Access Points: Detecting a vulnerable FT Handshake (802.11r)

1. Create a wpa_supplicant configuration file that can be used to connect to the network. A basic example is:

		ctrl_interface=/var/run/wpa_supplicant
		network={
		  ssid="testnet"
		  key_mgmt=FT-PSK
		  psk="password"
		}

	Note the use of "FT-PSK". Save it as network.conf or similar. For more info see [wpa_supplicant.conf](https://w1.fi/cgit/hostap/plain/wpa_supplicant/wpa_supplicant.conf).

2. Try to connect to the network using your platform's wpa_supplicant. This will likely require a command such as:

		sudo wpa_supplicant -D nl80211 -i wlan0 -c network.conf

	If this fails, either the AP does not support FT, or you provided the wrong network configuration options in step 1. Note that if the AP does not support FT, it is not affected by this vulnerability.

3. Use this script as a wrapper over the previous wpa_supplicant command:

		sudo su
		source venv/bin/activate
		./krack-ft-test.py wpa_supplicant -D nl80211 -i wlan0 -c network.conf

	This will execute the wpa_supplicant command using the provided parameters, and will add a virtual monitor interface that will perform attack tests. It's important to first become root and then load the python virtual environment (see above how to create this virtual environment).

4. Use wpa_cli to roam to a different AP of the same network. For example:

		wpa_cli -i wlan0
		> status
		bssid=c4:e9:84:db:fb:7b
		ssid=testnet
		...
		> scan_results 
		bssid / frequency / signal level / flags / ssid
		c4:e9:84:db:fb:7b	2412  -21  [WPA2-PSK+FT/PSK-CCMP][ESS] testnet
		c4:e9:84:1d:a5:bc	2412  -31  [WPA2-PSK+FT/PSK-CCMP][ESS] testnet
		...
		> roam c4:e9:84:1d:a5:bc
		...
   
	In this example we were connected to AP c4:e9:84:db:fb:7b of testnet (see status command). The scan_results command shows this network also has a second AP with MAC c4:e9:84:1d:a5:bc. We then roam to this second AP.

5. Generate traffic between the AP and client. For example:

		arping -I wlan0 192.168.1.10

6. Now look at the output of ./krack-ft-test.py to see if the AP is vulnerable.

	1. First it should say "Detected FT reassociation frame". Then it will start replaying this frame to try the attack.
	2. The script shows which IVs (= packet numbers) the AP is using when sending data frames.
	3. Message `IV reuse detected (IV=X, seq=Y). AP is vulnerable!` means we confirmed it's vulnerable.

	Be sure to manually check network traces as well, to confirm this script is replaying the reassociation request properly, and to manually confirm whether there is IV (= packet number) reuse or not.

	Example output of vulnerable AP:
	
		[15:59:24] Replaying Reassociation Request
		[15:59:25] AP transmitted data using IV=1 (seq=0)
		[15:59:25] Replaying Reassociation Request
		[15:59:26] AP transmitted data using IV=1 (seq=0)
		[15:59:26] IV reuse detected (IV=1, seq=0). AP is vulnerable!

	Example output of patched AP (note that IVs are never reused):
	
		[16:00:49] Replaying Reassociation Request
		[16:00:49] AP transmitted data using IV=1 (seq=0)
		[16:00:50] AP transmitted data using IV=2 (seq=1)
		[16:00:50] Replaying Reassociation Request
		[16:00:51] AP transmitted data using IV=3 (seq=2)
		[16:00:51] Replaying Reassociation Request
		[16:00:52] AP transmitted data using IV=4 (seq=3)


# Extra: Hardware Decryption

To confirm that hardware decryption is disable, execute `systool -vm ath9k_htc` or similar after plugging in your Wi-Fi NIC to confirm the nohwcript/swcrypto/hwcrypto parameter has been set. Note that you must replace `ath9k_htc` with the kernel module for your wireless network card.


# Extra: 5 GHz not supported

There's no official support for testing devices in the 5 GHz band.

If you nevertheless want to use the tool on 5 GHz channels, the network card being used must allow the injection of frames in the 5 GHz channel. Unfortunately, this is not always possible due to regulatory constraints. To see on which channels you can inject frames you can execute `iw list` and look under Frequencies for channels that are not marked as disabled, no IR, or radar detection. Note that these conditions may depend on your network card, the current configured country, and the AP you are connected to. For more information see, for example, the [Arch Linux documentation](https://wiki.archlinux.org/index.php/Network_configuration/Wireless#Respecting_the_regulatory_domain).

Note that the Linux kernel may not allow the injection of frames even though it is allowed to send normal frames. This is because in the function `ieee80211_monitor_start_xmit` the kernel refuses to inject frames when `cfg80211_reg_can_beacon` returns false. As a result, Linux may refuse to inject frames even though this is actually allowed. Making `cfg80211_reg_can_beacon` return true under the correct (or all) conditions prevents this bug. So you'll have to patch the Linux drivers so that `cfg80211_reg_can_beacon` always returns true, for instance, by manually patching the [packport driver](https://backports.wiki.kernel.org/index.php/Main_Page) code.


# Extra: Manual Tests

It's also possible to manually perform (more detailed) tests by cloning the hostap git repository:

	git clone git://w1.fi/srv/git/hostap.git
	
And following the instructions in [tests/cipher-and-key-mgmt-testing.txt](https://w1.fi/cgit/hostap/tree/tests/cipher-and-key-mgmt-testing.txt).
