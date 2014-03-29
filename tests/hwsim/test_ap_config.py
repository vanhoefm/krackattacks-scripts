# hostapd configuration tests
# Copyright (c) 2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import hostapd

def test_ap_config_errors(dev, apdev):
    """Various hostapd configuration errors"""
    hapd_global = hostapd.HostapdGlobal()
    ifname = apdev[0]['ifname']

    # IEEE 802.11d without country code
    params = { "ssid": "foo", "ieee80211d": "1" }
    hapd = hostapd.add_ap(ifname, params, no_enable=True)
    if "FAIL" not in hapd.request("ENABLE"):
        raise Exception("Unexpected ENABLE success (ieee80211d without country_code)")
    hapd_global.remove(ifname)

    # IEEE 802.11h without IEEE 802.11d
    params = { "ssid": "foo", "ieee80211h": "1" }
    hapd = hostapd.add_ap(ifname, params, no_enable=True)
    if "FAIL" not in hapd.request("ENABLE"):
        raise Exception("Unexpected ENABLE success (ieee80211h without ieee80211d")
    hapd_global.remove(ifname)

    # Power Constraint without IEEE 802.11d
    params = { "ssid": "foo", "local_pwr_constraint": "1" }
    hapd = hostapd.add_ap(ifname, params, no_enable=True)
    if "FAIL" not in hapd.request("ENABLE"):
        raise Exception("Unexpected ENABLE success (local_pwr_constraint without ieee80211d)")
    hapd_global.remove(ifname)

    # Spectrum management without Power Constraint
    params = { "ssid": "foo", "spectrum_mgmt_required": "1" }
    hapd = hostapd.add_ap(ifname, params, no_enable=True)
    if "FAIL" not in hapd.request("ENABLE"):
        raise Exception("Unexpected ENABLE success (spectrum_mgmt_required without local_pwr_constraint)")
    hapd_global.remove(ifname)

    # IEEE 802.1X without authentication server
    params = { "ssid": "foo", "ieee8021x": "1" }
    hapd = hostapd.add_ap(ifname, params, no_enable=True)
    if "FAIL" not in hapd.request("ENABLE"):
        raise Exception("Unexpected ENABLE success (ieee8021x)")
    hapd_global.remove(ifname)

    # RADIUS-PSK without macaddr_acl=2
    params = hostapd.wpa2_params(ssid="foo", passphrase="12345678")
    params["wpa_psk_radius"] = "1"
    hapd = hostapd.add_ap(ifname, params, no_enable=True)
    if "FAIL" not in hapd.request("ENABLE"):
        raise Exception("Unexpected ENABLE success (wpa_psk_radius)")
    hapd_global.remove(ifname)

    # FT without NAS-Identifier
    params = { "wpa": "2",
               "wpa_key_mgmt": "FT-PSK",
               "rsn_pairwise": "CCMP",
               "wpa_passphrase": "12345678" }
    hapd = hostapd.add_ap(ifname, params, no_enable=True)
    if "FAIL" not in hapd.request("ENABLE"):
        raise Exception("Unexpected ENABLE success (FT without nas_identifier)")
    hapd_global.remove(ifname)

    # Hotspot 2.0 without WPA2/CCMP
    params = hostapd.wpa2_params(ssid="foo")
    params['wpa_key_mgmt'] = "WPA-EAP"
    params['ieee8021x'] = "1"
    params['auth_server_addr'] = "127.0.0.1"
    params['auth_server_port'] = "1812"
    params['auth_server_shared_secret'] = "radius"
    params['interworking'] = "1"
    params['hs20'] = "1"
    params['wpa'] = "1"
    hapd = hostapd.add_ap(ifname, params, no_enable=True)
    if "FAIL" not in hapd.request("ENABLE"):
        raise Exception("Unexpected ENABLE success (HS 2.0 without WPA2/CCMP)")
    hapd_global.remove(ifname)
