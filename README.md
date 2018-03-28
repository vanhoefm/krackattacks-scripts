This project contains scripts to test if clients or access points (APs) are affected by the KRACK attack against WPA2. For [details behind this attack see our website](https://www.krackattacks.com) and [the research paper](https://papers.mathyvanhoef.com/ccs2017.pdf).

Remember that our scripts are not attack scripts! You require network credentials in order to test if an access point or client is affected by the attack.

# Prerequisites

Our scripts were tested on Kali Linux. To install the required dependencies on Kali, execute:

	apt-get update
	apt-get install libnl-3-dev libnl-genl-3-dev pkg-config libssl-dev net-tools git sysfsutils python-scapy python-pycryptodome

Then **disable hardware encryption** using the script `./krackattack/disable-hwcrypto.sh`. It's recommended to reboot after executing this script. After plugging in your Wi-Fi NIC, use `systool -vm ath9k_htc` or similar to confirm the nohwcript/.. param has been set. We tested our scripts with an Intel Dual Band Wireless-AC 7260 and a TP-Link TL-WN722N v1 on Kali Linux.

Finally compile our modified hostapd instance:

      cd ../hostapd
      cp defconfig .config
      make -j 2

Remember to disable Wi-Fi in your network manager before using our scripts. After disabling Wi-Fi, execute `sudo rfkill unblock wifi` so our scripts can still use Wi-Fi though.

# Testing Clients: detecting a vulnerable 4-way and group key handshake

To test wheter a client is vulnerable to Key Reinstallation Attack against the 4-way handshake or group key handshake, take the following steps:

1. Execute `krackattack/krack-test-client.py`. Accepted parameters are:

		--group      Test the group key handshake instead of the 4-way handshake
		--debug      Show more debug messages
		--tptk       See step 3 (forge Msg1/4 with replayed ANonce before Msg3/4)
		--tptk-rand  See step 3 (forge Msg1/4 with random ANonce before Msg3/4)

	All other supplied arguments are passed on to hostapd. The main commands you will execute are:

		krack-test-client.py
		krack-test-client.py --tptk
		krack-test-client.py --tptk-rand
		krack-test-client.py --group
		
	These commands are further explained below. In all tests, once the script is running, the device being tested must connect to the **SSID testnetwork with password abcdefgh**. You can change settings of the AP by modifying `hostapd.conf`. In particular you will have to **edit the line `interface=` to specify the correct Wi-Fi interface to use for the AP**. The script assumes the client will use DHCP to get an IP after connecting to the Wi-Fi network.

2. To test key reinstallations in the 4-way handshake, the script will keep sending encrypted message 3's to the client. To start the script execute:

	      krack-test-client.py

	Connect to the AP and the following tests will be performed automatically:

	1. The script monitors traffic sent by the client to see if the pairwise key is being reinstalled. To assure the client is sending enough frames, you can optionally ping the AP: ping 192.168.100.254 . If the client is vulnerable, the script will show something like:

			[19:02:37] 78:31:c1:c4:88:92: IV reuse detected (IV=1, seq=10). Client is vulnerable to pairwise key reinstallations in the 4-way handshake!

		If the client is patched, the script will show (this can take a minute):
	
			[18:58:11] 90:18:7c:6e:6b:20: client DOESN'T seem vulnerable to pairwise key reinstallation in the 4-way handshake.

	2. Once the client has requested an IP using DHCP, the script tests for reinstallations of the group key by sending broadcast ARP requests to the client using an already used (replayed) packet number (= IV). The client *must* request an IP using DHCP for this test to start. If the client is vulnerable, the script will show something like:

			[19:03:08] 78:31:c1:c4:88:92: Received 5 unique replies to replayed broadcast ARP requests. Client is vulnerable to group
			[19:03:08]                    key reinstallations in the 4-way handshake (or client accepts replayed broadcast frames)!

		If the client is patched, the script will show (this can take a minute):
	
			[19:03:08] 78:31:c1:c4:88:92: client DOESN'T seem vulnerable to group key reinstallation in the 4-way handshake handshake.

     Note that this scripts *indirectly* tests for reinstallations of the group key, by testing if replayed broadcast frames are accepted by the client. This may mean that the device will be reported as vulnerable if it accepts replayed broadcast frames, even though it's not reinstalling the group key

3. Some supplicants (e.g. wpa_supplicant v2.6) are only vulnerable to pairwise key reinstallations in the 4-way handshake when a forged message 1 is injected before sending a retransmitted message 3. To test for this variant of the attack, you can execute:

		krack-test-client.py --tptk         # Inject message 1 with a replayed ANonce
		krack-test-client.py --tptk-rand    # Inject message 1 with a random ANonce

	Now follow the same steps as in step 4 to see if a supplicant is vulnerable. Try both these attack variants after running the normal tests of step 4.

4. To test key reinstallations in the group key handshake, the script will keep performing new group key handshakes using an identical (static) group key. The client *must* request an IP using DHCP for this test to start. To start the script execute:

		krack-test-client.py --group

	Connect the the AP and all tests will be performed automatically. The working and output of the script is now similar as in step 2b.

5. Some final recommendations:

	* Perform these tests in a room with little interference. A high amount of packet loss will make this script unreliable!
	* Manually inspect network traffic to confirm the output of the script:
		- Use an extra Wi-Fi NIC in monitor mode to check pairwise key reinstalls by monitoring the IVs of frames sent by the client.
		- Capture traffic on the client to see if the replayed broadcast ARP requests are accepted or not.
	* If the client being tested can use multiple Wi-Fi radios/NICs, test using a few different ones.

## Correspondence to Wi-Fi Alliance tests

The [Wi-Fi Alliance created a custom vulnerability detection tool](https://www.wi-fi.org/security-update-october-2017) based on our scripts.
At the time of writing, this tool is only accessible to Wi-Fi Alliance members.
Their tools supports several different tests, and these tests correspond to the functionality in our script as follows:

- 4.1.1 (Plaintext retransmission of EAPOL Message 3). We currently do not support this test.
- 4.1.2 (Immediate retransmission of EAPOL M3 in plaintext). We currently do not suppor this test.
- 4.1.3 (Immediate retransmission of encrypted EAPOL M3 during pairwise rekey handshake). This corresponds to `./krack-test-client.py` except that encrypted EAPOL M3 are sent periodically instead of immediately.
- 4.1.5 (PTK reinstallation in 4-way handshake when STA uses Temporal PTK construction, same ANonce). Execue this test using `./krack-test-client.py --tptk`.
- 4.1.6 (PTK reinstallation in 4-way handshake when STA uses Temporal PTK construction, random ANonce). Execue this test using `./krack-test-client.py --tptk-rand`.
- 4.2.1 (Group key handshake vulnerability test on STA). Execue this test using `./krack-test-client.py --group`.
- 4.3.1 (Reinstallation of GTK and IGTK on STA supporting WNM sleep mode). We currently do not support this test (and neither does the Wi-Fi Alliance).


# Testing Access Points: Detecting a vulnerable FT Handshake (802.11r)

1. Create a wpa_supplicant configuration file that can be used to connect to the network. A basic example is:

		ctrl_interface=/var/run/wpa_supplicant
		network={{
		  ssid="testnet"
		  key_mgmt=FT-PSK
		  psk="password"
		}}

	Note the use of "FT-PSK". Save it as network.conf or similar. For more info see [wpa_supplicant.conf](https://w1.fi/cgit/hostap/plain/wpa_supplicant/wpa_supplicant.conf).

2. Try to connect to the network using your platform's wpa_supplicant. This will likely require a command such as:

		sudo wpa_supplicant -D nl80211 -i wlan0 -c network.conf

	If this fails, either the AP does not support FT, or you provided the wrong network configuration options in step 1.

3. Use this script as a wrapper over the previous wpa_supplicant command:

		sudo ./krack-ft-test.py wpa_supplicant -D nl80211 -i wlan0 -c network.conf

	This will execute the wpa_supplicant command using the provided parameters, and will add a virtual monitor interface that will perform attack tests.

4. Use wpa_cli to roam to a different AP of the same network. For example:

		sudo wpa_cli -i wlan0
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

		sudo arping -I wlan0 192.168.1.10

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

# Extra: Ubuntu 16.04

Our scripts are officially only supported on Kali Linux. Nevertheless, some users have been able to get it running on Ubuntu 16.04. These users remarked that the `python-pycryptodome` package is not present on Ubuntu, but can be installed as follows:

1. Install python-pip package
2. Execute `pip install pycryptodomex`

They further recommended to install this python module under a virtual python environment using virtualenv.

# Extra: Manual Tests

It's also possible to manually perform (more detailed) tests by cloning the hostap git repository:

	git clone git://w1.fi/srv/git/hostap.git
	
And following the instructions in [tests/cipher-and-key-mgmt-testing.txt](https://w1.fi/cgit/hostap/tree/tests/cipher-and-key-mgmt-testing.txt).
