This project contains scripts to tests if clients or access points (APs) are affected by the KRACK attack against WPA2. For [details behind this attack see our website](https://www.krackattacks.com) and [the research paper](https://papers.mathyvanhoef.com/ccs2017.pdf).

Remember that our scripts are not attack scripts! You require network credentials in order to test if an access point or client is affected by the attack.


# Prerequisites

Our scripts were tested on Kali Linux. To install the required dependencies on Kali, execute:

	apt-get update
	apt-get install libnl-3-dev libnl-genl-3-dev pkg-config libssl-dev net-tools git sysfsutils python-scapy python-pycryptodome

Then **disable hardware encryption** using the script `./disable-hwcrypto.sh`. We tested our scripts on a Kali Linux distribution using a TP-Link WN722N v1.

Remember to disable Wi-Fi in your network manager before using our scripts. After disabling Wi-Fi, execute `sudo rfkill unblock wifi` so our scripts can still use Wi-Fi.


# Testing Clients: detecting a vulnerable 4-way and group key handshake

To simulate an attack against a client follow the detailed instructions in `krackattack/krack-test-client.py`:

	cd krackattack/
	./krack-test-client.py --help

**Now follow the detail instructions that the script outputs.**
The script assumes the client will use DHCP to get an IP.
Remember to also perform extra tests using the `--tptk` and `--tptk-rand` parameters.

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
