This project contains scripts to test if clients or access points (APs) are affected by the KRACK attack against WPA2. For [details behind this attack see our website](https://www.krackattacks.com) and [the research paper](https://papers.mathyvanhoef.com/ccs2017.pdf).

Remember that our scripts are not attack scripts! You require network credentials in order to test if an access point or client is affected by the attack.


# Prerequisites

Our scripts were tested on Kali Linux. To install the required dependencies on Kali, execute:

	apt-get update
	apt-get install libnl-3-dev libnl-genl-3-dev pkg-config libssl-dev net-tools git sysfsutils python-scapy python-pycryptodome

Then **disable hardware encryption** using the script `./krackattack/disable-hwcrypto.sh`. We tested our scripts on a Kali Linux distribution using a TP-Link WN722N v1.

Remember to disable Wi-Fi in your network manager before using our scripts. After disabling Wi-Fi, execute `sudo rfkill unblock wifi` so our scripts can still use Wi-Fi.


# Testing Clients: detecting a vulnerable 4-way and group key handshake

To simulate an attack against a client follow the detailed instructions in `krackattack/krack-test-client.py`:

	cd krackattack/
	./krack-test-client.py --help

**Now follow the detail instructions that the script outputs.**
The script assumes the client will use DHCP to get an IP.
Remember to also perform extra tests using the `--tptk` and `--tptk-rand` parameters, and using `--group` to test the group key handshake.
So concretely, we recommend running the following tests:

1. `./krack-test-client.py`
2. `./krack-test-client.py --tptk`
3. `./krack-test-client.py --tptk-rand`
4. `./krack-test-client.py --group`

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

The attached Linux script `krack-ft-test.py` can be used to determine if an AP is vulnerable to our attack. The script contains detailed documentation on how to use it:

	cd krackattack/
	./krack-ft-test.py --help

**Now follow the detail instructions that the script outputs.**
Essentially, it wraps a normal `wpa_supplicant` client, and will keep replaying the FT Reassociation Request (making the AP reinstall the PTK).


# Extra: Ubuntu 16.04

Our scripts are officially only supported on Kali Linux. Nevertheless, some users have been able to get it running on Ubuntu 16.04. These users remarked that the `python-pycryptodome` package is not present on Ubuntu, but can be installed as follows:

1. Install python-pip package
2. Execute `pip install pycryptodomex`

They further recommended to install this python module under a virtual python environment using virtualenv.

# Extra: Manual Tests

It's also possible to manually perform tests by cloning the hostap git repository:

	git clone git://w1.fi/srv/git/hostap.git
	
And following the instructions in [tests/cipher-and-key-mgmt-testing.txt](https://w1.fi/cgit/hostap/tree/tests/cipher-and-key-mgmt-testing.txt).
