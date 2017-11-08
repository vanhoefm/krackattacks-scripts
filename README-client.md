# Extra: Client Attacks Details

## Vulnerability in the 4-way handshake

WPA1/2 clients most likely have a vulnerable implementation of the 4-way handshake. The problem is that, when a client receives a retransmitted message 3 of the 4-way handshake, it will reinstall the already in-use pairwise key. Additionally, when WPA2 is used, the client will also reinstall the already in-use group key (and the IGTK if protected management frames are being used). In case the client does not reinstall any keys, it is not vulnerable to our attack. If it does reinstall one of these keys, the associated packet number (PN) is likely reset. Because of this, the client will subsequently reuse packet numbers when sending frames protect using TKIP, CCMP, or GCMP. This causes nonce reuse (sometimes also called Initialization Vector reuse). Since the packet number is also used as a replay counter for received frames, frames sent *towards* the client can also be replayed.

Note that the AP retransmits message 3 of the 4-way handshake if it did not receive message 4. Hence an attacker can trigger retransmissions of message 3 by blocking the arrival of message 4 (see "how to exploit" section below for more details).

Figure 3 [in the paper](https://papers.mathyvanhoef.com/ccs2017.pdf) illustrates the problem graphically. Here, when a client process the first message 3, it goes to the PTK-NEGOTIATING and PTK-DONE state. While doing so, it installs the pairwise key (PTK) and group key (GTK) using the MLME-SETKEYS.request primitive (optionally the IGTK is also installed). Unfortunately, when it receives a retransmitted message 3, it will re-enter the PTK-NEGOTIATING and PTK-DONE state. As a result, the client will reinstall the PTK and GTK.

The suggested patch is to not reinstall any keys when receiving a retransmitting message 3 (but still reply using a new message 4). This can be accomplished by adding a boolean variable to the state machine. It is initialized to false, and set to true when generating a fresh SNonce and PTK in PTK-START. If the boolean is true when entering PTK-DONE, keys are installed and the boolean is set to false. If the boolean is false when entering PTK-DONE, installation of keys is skipped, but a new message 4 reply is still transmitted.

### Attack and impact details

The basic idea behind the attack is shown in Figure 4 of the paper, and relies on our channel-based MitM attack. Summarized, the 4-way handshake starts normally, but the adversary does not forward message 4 of the 4-way handshake to the AP (stage 1). After some duration the AP will retransmit message 3, and the adversary forwards it to the client (stage 3). When the client process the retransmitted message 3, it will reinstall the PTK. As a result, the client (victim) will reuse packet numbers (nonces) when sending new data packets (stage 5). For more details see section 3.3 in the paper.

### TPTK Construction

Supplicants that use a TPTK construction generate a Temporal PTK (PTK) on the reception of message 1's, and try to verify the Message Integrity Code (MIC) of message 3 using *both* the TPTK and, if available, the currently installed PTK. If one of these two keys correctly verifies the MIC, the incoming message 3 is accepted. A supplicant using the TPTK construction may be vulnerable to the following attack, even when an attempt was made to patch it:

1. The supplicant receives message 3/4
2. The supplicant receives a forged message 1/4 (using either a random ANonce or the same ANonce from the previous/current handshake).
3. The supplicant receives a (possibly encrypted) retransmitted message 3/4

Although we believe few supplicants use the TPTK construction, we strongly recommend everyone to double-check their patches with this attack in mind. Our `./krack-test-client.py` script in can be used to test for this attack variant by executing it using the `--tptk` argument:

	./krack-test-client.py --help   # see step 1 and 5 in particular
	./krack-test-client.py --tptk

Note that `wpa_supplicant` 2.6 uses the TPTK construction, and that it can be tricked into installing an all-zero encryption key. As a result, a man-in-the-middle position can be obtained where traffic can be trivially replayed, decrypted, and forged. Therefore, it is essential you update `wpa_supplicant` even when using version 2.6. The capture `example-tptk-attack.pcapng` contains an example of such an attack. Packet 99 is the forged message 1/4, and packet 101 is the retransmitted message 3/4 causing a key reinstallation. The client is 02:00:00:00:01:00.

## Vulnerability in the group-key handshake

WPA1/2 clients most likely also have a vulnerable implementation of the group key handshake. Here, a retransmitted group message 1 will reinstall the already in-use group key. Hence the associated packet number is lowered (or reset). This allows an attacker to replay group-addressed frames (i.e. broadcast and multicast frames) to the client. However, it does not allow the attacker to decrypt or inject broadcast packets.

Note that only the AP sends real group-addressed frames. Client send them as unicast frames to the AP, after which the AP broadcasts them to all connected Clients. Additionally, we remark that group message 1 contains the last used packet number by the AP (the Key RSC field in the EAPOL-Key frame). The client normally installs the group key along with the given packet number. However, a client should never *lower* the last used packet number. This may happen with our attack technique though: the packet number in group message 1 will be *lower* than the last group-addressed frame that the client received. In this case the client should not be lowering the packet number.

The suggested patch is to track the currently installed group key, and to not reinstall an already in-use key, while still replying with a new group message 2.

An attacker can trigger transmissions of group message 1 by blocking the arrival of group message 2 using a channel-based MitM position (see below for details).

### Attack and impact details

The precise instantiation of our attack depends on the behavior of the AP. For simplicity, we assume the client (victim) is connected to an AP that uses Linux's widely used hostapd. Our attack in this case is illustrated in figure 8 of the paper. Notice that we again use a channel-based MitM attack. Summarized, the adversary blocks group message 2 from arriving at the AP (end of stage 1). The AP will then transmit a new group message 1 (stage 2). The adversary then forwards the previously blocked group message 2 to the AP (stage 3). This completes the group key handshake, making hostapd install the new group key (GTK) in stage 3. Now, the adversary can forward the retransmitted group message 1 to the client, making it reinstall the group key (stage 5). As a result, previously transmitted broadcast or multicast data (i.e. those transmitted in stage 4) can now be replayed towards the client (see stage 6).

Note that the group key handshake messages are unicast data frames and are encrypted using the pairwise key (e.g. using TKIP or CCMP). Even though they are encrypted, an attacker can identify these messages based on their length. Additionally, several APs send EAPOL-Key frames (i.e. handshake messages) using a non-zero Quality of Service (QoS) Traffic Identifier (TID). This is important because all clients must maintain a separate replay counter for each QoS TID (see for example 12.5.3.4.4b in the 802.11-2016 standard). Combined, this means that when we capture an encrypted group message 1 which uses a packet number of x, we can forward other encrypted data frames to the client, without affecting the attack. This is because other data frames generally use a different QoS TID. Therefore, the packet number (= replay counter) of the captured group message 2 will still accepted. Put differently, normal data frames use a QoS TID of zero, meaning they do not affect the replay counter associated to the QoS TID of EAPOL-Key frames. As a result, we can forward the group message 1 whenever we want, even after forwarding normal data frames to the client. This gives a high amount of flexibility to the attack, making it easy to execute the attack in practice.

The main limitation of this attack is that an adversary can only abuse it to replay broadcast or multicast traffic (whereas the other attacks also allow decryption and/or injection of frames).
