# Test cases for Device Provisioning Protocol (DPP)
# Copyright (c) 2017, Qualcomm Atheros, Inc.
# Copyright (c) 2018, The Linux Foundation
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import subprocess
import time

import hostapd
import hwsim_utils
from utils import HwsimSkip, alloc_fail, fail_test, wait_fail_trigger
from wpasupplicant import WpaSupplicant

def check_dpp_capab(dev, brainpool=False):
    if "UNKNOWN COMMAND" in dev.request("DPP_BOOTSTRAP_GET_URI 0"):
        raise HwsimSkip("DPP not supported")
    if brainpool:
        tls = dev.request("GET tls_library")
        if not tls.startswith("OpenSSL") or "run=BoringSSL" in tls:
            raise HwsimSkip("Crypto library does not support Brainpool curves: " + tls)

def test_dpp_qr_code_parsing(dev, apdev):
    """DPP QR Code parsing"""
    check_dpp_capab(dev[0])
    id = []

    tests = [ "DPP:C:81/1,115/36;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADM2206avxHJaHXgLMkq/24e0rsrfMP9K1Tm8gx+ovP0I=;;",
              "DPP:I:SN=4774LH2b4044;M:010203040506;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADURzxmttZoIRIPWGoQMV00XHWCAQIhXruVWOz0NjlkIA=;;",
              "DPP:I:;M:010203040506;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADURzxmttZoIRIPWGoQMV00XHWCAQIhXruVWOz0NjlkIA=;;" ]
    for uri in tests:
        res = dev[0].request("DPP_QR_CODE " + uri)
        if "FAIL" in res:
            raise Exception("Failed to parse QR Code")
        id.append(int(res))

        uri2 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id[-1])
        if uri != uri2:
            raise Exception("Returned URI does not match")

    tests = [ "foo",
              "DPP:",
              "DPP:;;",
              "DPP:C:1/2;M:;K;;",
              "DPP:I:;M:01020304050;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADURzxmttZoIRIPWGoQMV00XHWCAQIhXruVWOz0NjlkIA=;;" ]
    for t in tests:
        res = dev[0].request("DPP_QR_CODE " + t)
        if "FAIL" not in res:
            raise Exception("Accepted invalid QR Code: " + t)

    logger.info("ID: " + str(id))
    if id[0] == id[1] or id[0] == id[2] or id[1] == id[2]:
        raise Exception("Duplicate ID returned")

    if "FAIL" not in dev[0].request("DPP_BOOTSTRAP_REMOVE 12345678"):
        raise Exception("DPP_BOOTSTRAP_REMOVE accepted unexpectedly")
    if "OK" not in dev[0].request("DPP_BOOTSTRAP_REMOVE %d" % id[1]):
        raise Exception("DPP_BOOTSTRAP_REMOVE failed")

    res = dev[0].request("DPP_BOOTSTRAP_GEN type=qrcode")
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    uri = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % int(res))
    logger.info("Generated URI: " + uri)

    res = dev[0].request("DPP_QR_CODE " + uri)
    if "FAIL" in res:
        raise Exception("Failed to parse self-generated QR Code URI")

    res = dev[0].request("DPP_BOOTSTRAP_GEN type=qrcode chan=81/1,115/36 mac=010203040506 info=foo")
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    uri = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % int(res))
    logger.info("Generated URI: " + uri)

    res = dev[0].request("DPP_QR_CODE " + uri)
    if "FAIL" in res:
        raise Exception("Failed to parse self-generated QR Code URI")

dpp_key_p256 ="30570201010420777fc55dc51e967c10ec051b91d860b5f1e6c934e48d5daffef98d032c64b170a00a06082a8648ce3d030107a124032200020c804188c7f85beb6e91070d2b3e5e39b90ca77b4d3c5251bc1844d6ca29dcad"
dpp_key_p384 = "307402010104302f56fdd83b5345cacb630eb7c22fa5ad5daba37307c95191e2a75756d137003bd8b32dbcb00eb5650c1eb499ecfcaec0a00706052b81040022a13403320003615ec2141b5b77aebb6523f8a012755f9a34405a8398d2ceeeebca7f5ce868bf55056cba4c4ec62fad3ed26dd29e0f23"
dpp_key_p521 = "308198020101044200c8010d5357204c252551aaf4e210343111e503fd1dc615b257058997c49b6b643c975226e93be8181cca3d83a7072defd161dfbdf433c19abe1f2ad51867a05761a00706052b81040023a1460344000301cdf3608b1305fe34a1f976095dcf001182b9973354efe156291a66830292f9babd8f412ad462958663e7a75d1d0610abdfc3dd95d40669f7ab3bc001668cfb3b7c"
dpp_key_bp256 = "3058020101042057133a676fb60bf2a3e6797e19833c7b0f89dc192ab99ab5fa377ae23a157765a00b06092b2403030208010107a12403220002945d9bf7ce30c9c1ac0ff21ca62b984d5bb80ff69d2be8c9716ab39a10d2caf0"
dpp_key_bp384 = "307802010104304902df9f3033a9b7128554c0851dc7127c3573eed150671dae74c0013e9896a9b1c22b6f7d43d8a2ebb7cd474dc55039a00b06092b240303020801010ba13403320003623cb5e68787f351faababf3425161571560add2e6f9a306fcbffb507735bf955bb46dd20ba246b0d5cadce73e5bd6a6"
dpp_key_bp512 = "30819802010104405803494226eb7e50bf0e90633f37e7e35d33f5fa502165eeba721d927f9f846caf12e925701d18e123abaaaf4a7edb4fc4de21ce18bc10c4d12e8b3439f74e40a00b06092b240303020801010da144034200033b086ccd47486522d35dc16fbb2229642c2e9e87897d45abbf21f9fb52acb5a6272b31d1b227c3e53720769cc16b4cb181b26cd0d35fe463218aaedf3b6ec00a"

def test_dpp_qr_code_curves(dev, apdev):
    """DPP QR Code and supported curves"""
    check_dpp_capab(dev[0])
    tests = [ ("prime256v1", dpp_key_p256),
              ("secp384r1", dpp_key_p384),
              ("secp521r1", dpp_key_p521) ]
    for curve, hex in tests:
        id = dev[0].request("DPP_BOOTSTRAP_GEN type=qrcode key=" + hex)
        if "FAIL" in id:
            raise Exception("Failed to set key for " + curve)
        info = dev[0].request("DPP_BOOTSTRAP_INFO " + id)
        if "FAIL" in info:
            raise Exception("Failed to get info for " + curve)
        if "curve=" + curve not in info:
            raise Exception("Curve mismatch for " + curve)

def test_dpp_qr_code_curves_brainpool(dev, apdev):
    """DPP QR Code and supported Brainpool curves"""
    check_dpp_capab(dev[0], brainpool=True)
    tests = [ ("brainpoolP256r1", dpp_key_bp256),
              ("brainpoolP384r1", dpp_key_bp384),
              ("brainpoolP512r1", dpp_key_bp512) ]
    for curve, hex in tests:
        id = dev[0].request("DPP_BOOTSTRAP_GEN type=qrcode key=" + hex)
        if "FAIL" in id:
            raise Exception("Failed to set key for " + curve)
        info = dev[0].request("DPP_BOOTSTRAP_INFO " + id)
        if "FAIL" in info:
            raise Exception("Failed to get info for " + curve)
        if "curve=" + curve not in info:
            raise Exception("Curve mismatch for " + curve)

def test_dpp_qr_code_curve_select(dev, apdev):
    """DPP QR Code and curve selection"""
    check_dpp_capab(dev[0], brainpool=True)
    check_dpp_capab(dev[1], brainpool=True)

    addr = dev[0].own_addr().replace(':', '')
    bi = []
    for key in [ dpp_key_p256, dpp_key_p384, dpp_key_p521,
                 dpp_key_bp256, dpp_key_bp384, dpp_key_bp512 ]:
        id = dev[0].request("DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr + " key=" + key)
        if "FAIL" in id:
            raise Exception("Failed to set key for " + curve)
        info = dev[0].request("DPP_BOOTSTRAP_INFO " + id)
        for i in info.splitlines():
            if '=' in i:
                name, val = i.split('=')
                if name == "curve":
                    curve = val
                    break
        uri = dev[0].request("DPP_BOOTSTRAP_GET_URI " + id)
        bi.append((curve, uri))

    for curve, uri in bi:
        logger.info("Curve: " + curve)
        logger.info("URI: " + uri)

        if "OK" not in dev[0].request("DPP_LISTEN 2412"):
            raise Exception("Failed to start listen operation")

        res = dev[1].request("DPP_QR_CODE " + uri)
        if "FAIL" in res:
            raise Exception("Failed to parse QR Code URI")
        if "OK" not in dev[1].request("DPP_AUTH_INIT peer=" + res):
            raise Exception("Failed to initiate DPP Authentication")
        ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
        if ev is None:
            raise Exception("DPP authentication did not succeed (Responder)")
        ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
        if ev is None:
            raise Exception("DPP authentication did not succeed (Initiator)")
        ev = dev[0].wait_event(["DPP-CONF-FAILED"], timeout=2)
        if ev is None:
            raise Exception("DPP configuration result not seen (Enrollee)")
        ev = dev[1].wait_event(["DPP-CONF-SENT"], timeout=2)
        if ev is None:
            raise Exception("DPP configuration result not seen (Responder)")
        dev[0].request("DPP_STOP_LISTEN")
        dev[1].request("DPP_STOP_LISTEN")
        dev[0].dump_monitor()
        dev[1].dump_monitor()

def test_dpp_qr_code_auth_broadcast(dev, apdev):
    """DPP QR Code and authentication exchange (broadcast)"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    logger.info("dev0 displays QR Code")
    res = dev[0].request("DPP_BOOTSTRAP_GEN type=qrcode chan=81/1")
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    logger.info("dev1 scans QR Code")
    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    logger.info("dev1 initiates DPP Authentication")
    if "OK" not in dev[0].request("DPP_LISTEN 2412"):
        raise Exception("Failed to start listen operation")
    if "OK" not in dev[1].request("DPP_AUTH_INIT peer=%d" % id1):
        raise Exception("Failed to initiate DPP Authentication")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    dev[0].request("DPP_STOP_LISTEN")

def test_dpp_qr_code_auth_unicast(dev, apdev):
    """DPP QR Code and authentication exchange (unicast)"""
    run_dpp_qr_code_auth_unicast(dev, apdev, None)

def test_dpp_qr_code_auth_unicast_ap_enrollee(dev, apdev):
    """DPP QR Code and authentication exchange (AP enrollee)"""
    run_dpp_qr_code_auth_unicast(dev, apdev, None, netrole="ap")

def test_dpp_qr_code_curve_prime256v1(dev, apdev):
    """DPP QR Code and curve prime256v1"""
    run_dpp_qr_code_auth_unicast(dev, apdev, "prime256v1")

def test_dpp_qr_code_curve_secp384r1(dev, apdev):
    """DPP QR Code and curve secp384r1"""
    run_dpp_qr_code_auth_unicast(dev, apdev, "secp384r1")

def test_dpp_qr_code_curve_secp521r1(dev, apdev):
    """DPP QR Code and curve secp521r1"""
    run_dpp_qr_code_auth_unicast(dev, apdev, "secp521r1")

def test_dpp_qr_code_curve_brainpoolP256r1(dev, apdev):
    """DPP QR Code and curve brainpoolP256r1"""
    run_dpp_qr_code_auth_unicast(dev, apdev, "brainpoolP256r1")

def test_dpp_qr_code_curve_brainpoolP384r1(dev, apdev):
    """DPP QR Code and curve brainpoolP384r1"""
    run_dpp_qr_code_auth_unicast(dev, apdev, "brainpoolP384r1")

def test_dpp_qr_code_curve_brainpoolP512r1(dev, apdev):
    """DPP QR Code and curve brainpoolP512r1"""
    run_dpp_qr_code_auth_unicast(dev, apdev, "brainpoolP512r1")

def test_dpp_qr_code_set_key(dev, apdev):
    """DPP QR Code and fixed bootstrapping key"""
    run_dpp_qr_code_auth_unicast(dev, apdev, None, key="30770201010420e5143ac74682cc6869a830e8f5301a5fa569130ac329b1d7dd6f2a7495dbcbe1a00a06082a8648ce3d030107a144034200045e13e167c33dbc7d85541e5509600aa8139bbb3e39e25898992c5d01be92039ee2850f17e71506ded0d6b25677441eae249f8e225c68dd15a6354dca54006383")

def run_dpp_qr_code_auth_unicast(dev, apdev, curve, netrole=None, key=None,
                                 require_conf_success=False, init_extra=None,
                                 require_conf_failure=False,
                                 configurator=False, conf_curve=None):
    check_dpp_capab(dev[0], curve and "brainpool" in curve)
    check_dpp_capab(dev[1], curve and "brainpool" in curve)
    if configurator:
        logger.info("Create configurator on dev1")
        cmd = "DPP_CONFIGURATOR_ADD"
        if conf_curve:
            cmd += " curve=" + conf_curve
        res = dev[1].request(cmd);
        if "FAIL" in res:
            raise Exception("Failed to add configurator")
        conf_id = int(res)

    logger.info("dev0 displays QR Code")
    addr = dev[0].own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr
    if curve:
        cmd += " curve=" + curve
    if key:
        cmd += " key=" + key
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    logger.info("dev1 scans QR Code")
    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    logger.info("dev1 initiates DPP Authentication")
    cmd = "DPP_LISTEN 2412"
    if netrole:
        cmd += " netrole=" + netrole
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")
    cmd = "DPP_AUTH_INIT peer=%d" % id1
    if init_extra:
        cmd += " " + init_extra
    if configurator:
        cmd += " configurator=%d" % conf_id
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to initiate DPP Authentication")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    ev = dev[1].wait_event(["DPP-CONF-SENT"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator)")
    ev = dev[0].wait_event(["DPP-CONF-RECEIVED", "DPP-CONF-FAILED"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee)")
    if require_conf_success:
        if "DPP-CONF-FAILED" in ev:
            raise Exception("DPP configuration failed")
    if require_conf_failure:
        if "DPP-CONF-SUCCESS" in ev:
            raise Exception("DPP configuration succeeded unexpectedly")
    dev[0].request("DPP_STOP_LISTEN")
    dev[0].dump_monitor()
    dev[1].dump_monitor()

def test_dpp_qr_code_auth_mutual(dev, apdev):
    """DPP QR Code and authentication exchange (mutual)"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    logger.info("dev0 displays QR Code")
    addr = dev[0].own_addr().replace(':', '')
    res = dev[0].request("DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    logger.info("dev1 scans QR Code")
    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    logger.info("dev1 displays QR Code")
    addr = dev[1].own_addr().replace(':', '')
    res = dev[1].request("DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id1b = int(res)
    uri1b = dev[1].request("DPP_BOOTSTRAP_GET_URI %d" % id1b)

    logger.info("dev0 scans QR Code")
    res = dev[0].request("DPP_QR_CODE " + uri1b)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id0b = int(res)

    logger.info("dev1 initiates DPP Authentication")
    if "OK" not in dev[0].request("DPP_LISTEN 2412"):
        raise Exception("Failed to start listen operation")
    if "OK" not in dev[1].request("DPP_AUTH_INIT peer=%d own=%d" % (id1, id1b)):
        raise Exception("Failed to initiate DPP Authentication")

    ev = dev[1].wait_event(["DPP-AUTH-DIRECTION"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication direction not indicated (Initiator)")
    if "mutual=1" not in ev:
        raise Exception("Mutual authentication not used")

    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    dev[0].request("DPP_STOP_LISTEN")

def test_dpp_qr_code_auth_mutual2(dev, apdev):
    """DPP QR Code and authentication exchange (mutual2)"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    logger.info("dev0 displays QR Code")
    addr = dev[0].own_addr().replace(':', '')
    res = dev[0].request("DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    logger.info("dev1 scans QR Code")
    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    logger.info("dev1 displays QR Code")
    addr = dev[1].own_addr().replace(':', '')
    res = dev[1].request("DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id1b = int(res)
    uri1b = dev[1].request("DPP_BOOTSTRAP_GET_URI %d" % id1b)

    logger.info("dev1 initiates DPP Authentication")
    if "OK" not in dev[0].request("DPP_LISTEN 2412 qr=mutual"):
        raise Exception("Failed to start listen operation")
    if "OK" not in dev[1].request("DPP_AUTH_INIT peer=%d own=%d" % (id1, id1b)):
        raise Exception("Failed to initiate DPP Authentication")

    ev = dev[1].wait_event(["DPP-RESPONSE-PENDING"], timeout=5)
    if ev is None:
        raise Exception("Pending response not reported")
    ev = dev[0].wait_event(["DPP-SCAN-PEER-QR-CODE"], timeout=5)
    if ev is None:
        raise Exception("QR Code scan for mutual authentication not requested")

    logger.info("dev0 scans QR Code")
    res = dev[0].request("DPP_QR_CODE " + uri1b)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id0b = int(res)

    ev = dev[1].wait_event(["DPP-AUTH-DIRECTION"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication direction not indicated (Initiator)")
    if "mutual=1" not in ev:
        raise Exception("Mutual authentication not used")

    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    dev[0].request("DPP_STOP_LISTEN")

def test_dpp_qr_code_auth_mutual_p_256(dev, apdev):
    """DPP QR Code and authentication exchange (mutual, autogen P-256)"""
    run_dpp_qr_code_auth_mutual(dev, apdev, "P-256")

def test_dpp_qr_code_auth_mutual_p_384(dev, apdev):
    """DPP QR Code and authentication exchange (mutual, autogen P-384)"""
    run_dpp_qr_code_auth_mutual(dev, apdev, "P-384")

def test_dpp_qr_code_auth_mutual_p_521(dev, apdev):
    """DPP QR Code and authentication exchange (mutual, autogen P-521)"""
    run_dpp_qr_code_auth_mutual(dev, apdev, "P-521")

def test_dpp_qr_code_auth_mutual_bp_256(dev, apdev):
    """DPP QR Code and authentication exchange (mutual, autogen BP-256)"""
    run_dpp_qr_code_auth_mutual(dev, apdev, "BP-256")

def test_dpp_qr_code_auth_mutual_bp_384(dev, apdev):
    """DPP QR Code and authentication exchange (mutual, autogen BP-384)"""
    run_dpp_qr_code_auth_mutual(dev, apdev, "BP-384")

def test_dpp_qr_code_auth_mutual_bp_512(dev, apdev):
    """DPP QR Code and authentication exchange (mutual, autogen BP-512)"""
    run_dpp_qr_code_auth_mutual(dev, apdev, "BP-512")

def run_dpp_qr_code_auth_mutual(dev, apdev, curve):
    check_dpp_capab(dev[0], curve and "BP-" in curve)
    check_dpp_capab(dev[1], curve and "BP-" in curve)
    logger.info("dev0 displays QR Code")
    addr = dev[0].own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr
    cmd += " curve=" + curve
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    logger.info("dev1 scans QR Code")
    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    logger.info("dev1 initiates DPP Authentication")
    if "OK" not in dev[0].request("DPP_LISTEN 2412 qr=mutual"):
        raise Exception("Failed to start listen operation")
    if "OK" not in dev[1].request("DPP_AUTH_INIT peer=%d" % (id1)):
        raise Exception("Failed to initiate DPP Authentication")

    ev = dev[1].wait_event(["DPP-RESPONSE-PENDING"], timeout=5)
    if ev is None:
        raise Exception("Pending response not reported")
    uri = ev.split(' ')[1]

    ev = dev[0].wait_event(["DPP-SCAN-PEER-QR-CODE"], timeout=5)
    if ev is None:
        raise Exception("QR Code scan for mutual authentication not requested")

    logger.info("dev0 scans QR Code")
    res = dev[0].request("DPP_QR_CODE " + uri)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")

    ev = dev[1].wait_event(["DPP-AUTH-DIRECTION"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication direction not indicated (Initiator)")
    if "mutual=1" not in ev:
        raise Exception("Mutual authentication not used")

    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    dev[0].request("DPP_STOP_LISTEN")

def test_dpp_auth_resp_retries(dev, apdev):
    """DPP Authentication Response retries"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    dev[0].set("dpp_resp_max_tries", "3")
    dev[0].set("dpp_resp_retry_time", "100")

    logger.info("dev0 displays QR Code")
    addr = dev[0].own_addr().replace(':', '')
    res = dev[0].request("DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    logger.info("dev1 scans QR Code")
    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    logger.info("dev1 displays QR Code")
    addr = dev[1].own_addr().replace(':', '')
    res = dev[1].request("DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id1b = int(res)
    uri1b = dev[1].request("DPP_BOOTSTRAP_GET_URI %d" % id1b)

    logger.info("dev1 initiates DPP Authentication")
    if "OK" not in dev[0].request("DPP_LISTEN 2412 qr=mutual"):
        raise Exception("Failed to start listen operation")
    if "OK" not in dev[1].request("DPP_AUTH_INIT peer=%d own=%d" % (id1, id1b)):
        raise Exception("Failed to initiate DPP Authentication")

    ev = dev[1].wait_event(["DPP-RESPONSE-PENDING"], timeout=5)
    if ev is None:
        raise Exception("Pending response not reported")
    ev = dev[0].wait_event(["DPP-SCAN-PEER-QR-CODE"], timeout=5)
    if ev is None:
        raise Exception("QR Code scan for mutual authentication not requested")

    # Stop Initiator from listening to frames to force retransmission of the
    # DPP Authentication Response frame with Status=0
    dev[1].request("DPP_STOP_LISTEN")

    dev[1].dump_monitor()
    dev[0].dump_monitor()

    logger.info("dev0 scans QR Code")
    res = dev[0].request("DPP_QR_CODE " + uri1b)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id0b = int(res)

    ev = dev[0].wait_event(["DPP-TX"], timeout=5)
    if ev is None or "type=1" not in ev:
        raise Exception("DPP Authentication Response not sent")
    ev = dev[0].wait_event(["DPP-TX-STATUS"], timeout=5)
    if ev is None:
        raise Exception("TX status for DPP Authentication Response not reported")
    if "result=no-ACK" not in ev:
        raise Exception("Unexpected TX status for Authentication Response: " + ev)

    ev = dev[0].wait_event(["DPP-TX"], timeout=15)
    if ev is None or "type=1" not in ev:
        raise Exception("DPP Authentication Response retransmission not sent")

def test_dpp_qr_code_auth_mutual_not_used(dev, apdev):
    """DPP QR Code and authentication exchange (mutual not used)"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    logger.info("dev0 displays QR Code")
    addr = dev[0].own_addr().replace(':', '')
    res = dev[0].request("DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    logger.info("dev1 scans QR Code")
    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    logger.info("dev1 displays QR Code")
    addr = dev[1].own_addr().replace(':', '')
    res = dev[1].request("DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id1b = int(res)
    uri1b = dev[1].request("DPP_BOOTSTRAP_GET_URI %d" % id1b)

    logger.info("dev0 does not scan QR Code")

    logger.info("dev1 initiates DPP Authentication")
    if "OK" not in dev[0].request("DPP_LISTEN 2412"):
        raise Exception("Failed to start listen operation")
    if "OK" not in dev[1].request("DPP_AUTH_INIT peer=%d own=%d" % (id1, id1b)):
        raise Exception("Failed to initiate DPP Authentication")

    ev = dev[1].wait_event(["DPP-AUTH-DIRECTION"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication direction not indicated (Initiator)")
    if "mutual=0" not in ev:
        raise Exception("Mutual authentication not used")

    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    dev[0].request("DPP_STOP_LISTEN")

def test_dpp_qr_code_auth_mutual_curve_mismatch(dev, apdev):
    """DPP QR Code and authentication exchange (mutual/mismatch)"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    logger.info("dev0 displays QR Code")
    addr = dev[0].own_addr().replace(':', '')
    res = dev[0].request("DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    logger.info("dev1 scans QR Code")
    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    logger.info("dev1 displays QR Code")
    addr = dev[1].own_addr().replace(':', '')
    res = dev[1].request("DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr + " curve=secp384r1")
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id1b = int(res)
    uri1b = dev[1].request("DPP_BOOTSTRAP_GET_URI %d" % id1b)

    logger.info("dev0 scans QR Code")
    res = dev[0].request("DPP_QR_CODE " + uri1b)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id0b = int(res)

    res = dev[1].request("DPP_AUTH_INIT peer=%d own=%d" % (id1, id1b))
    if "FAIL" not in res:
        raise Exception("DPP_AUTH_INIT accepted unexpectedly")

def test_dpp_qr_code_auth_hostapd_mutual2(dev, apdev):
    """DPP QR Code and authentication exchange (hostapd mutual2)"""
    check_dpp_capab(dev[0])
    hapd = hostapd.add_ap(apdev[0], { "ssid": "unconfigured" })
    check_dpp_capab(hapd)

    logger.info("AP displays QR Code")
    addr = hapd.own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr
    res = hapd.request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id_h = int(res)
    uri_h = hapd.request("DPP_BOOTSTRAP_GET_URI %d" % id_h)

    logger.info("dev0 scans QR Code")
    res = dev[0].request("DPP_QR_CODE " + uri_h)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id0 = int(res)

    logger.info("dev0 displays QR Code")
    addr = dev[0].own_addr().replace(':', '')
    res = dev[0].request("DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0b = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0b)

    logger.info("dev0 initiates DPP Authentication")
    if "OK" not in hapd.request("DPP_LISTEN 2412 qr=mutual"):
        raise Exception("Failed to start listen operation")
    if "OK" not in dev[0].request("DPP_AUTH_INIT peer=%d own=%d" % (id0, id0b)):
        raise Exception("Failed to initiate DPP Authentication")

    ev = dev[0].wait_event(["DPP-RESPONSE-PENDING"], timeout=5)
    if ev is None:
        raise Exception("Pending response not reported")
    ev = hapd.wait_event(["DPP-SCAN-PEER-QR-CODE"], timeout=5)
    if ev is None:
        raise Exception("QR Code scan for mutual authentication not requested")

    logger.info("AP scans QR Code")
    res = hapd.request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")

    ev = hapd.wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    hapd.request("DPP_STOP_LISTEN")

def test_dpp_qr_code_listen_continue(dev, apdev):
    """DPP QR Code and listen operation needing continuation"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    logger.info("dev0 displays QR Code")
    addr = dev[0].own_addr().replace(':', '')
    res = dev[0].request("DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    logger.info("dev1 scans QR Code")
    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    if "OK" not in dev[0].request("DPP_LISTEN 2412"):
        raise Exception("Failed to start listen operation")
    logger.info("Wait for listen to expire and get restarted")
    time.sleep(5.5)
    logger.info("dev1 initiates DPP Authentication")
    if "OK" not in dev[1].request("DPP_AUTH_INIT peer=%d" % id1):
        raise Exception("Failed to initiate DPP Authentication")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    dev[0].request("DPP_STOP_LISTEN")

def test_dpp_qr_code_auth_initiator_enrollee(dev, apdev):
    """DPP QR Code and authentication exchange (Initiator in Enrollee role)"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    dev[0].request("SET gas_address3 1")
    dev[1].request("SET gas_address3 1")
    logger.info("dev0 displays QR Code")
    addr = dev[0].own_addr().replace(':', '')
    res = dev[0].request("DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    logger.info("dev1 scans QR Code")
    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    logger.info("dev1 initiates DPP Authentication")
    if "OK" not in dev[0].request("DPP_LISTEN 2412"):
        raise Exception("Failed to start listen operation")
    if "OK" not in dev[1].request("DPP_AUTH_INIT peer=%d role=enrollee" % id1):
        raise Exception("Failed to initiate DPP Authentication")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")

    ev = dev[0].wait_event(["DPP-CONF-SENT"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration did not succeed (Configurator)")
    ev = dev[1].wait_event(["DPP-CONF-FAILED"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration did not succeed (Enrollee)")

    dev[0].request("DPP_STOP_LISTEN")

def test_dpp_qr_code_auth_initiator_either_1(dev, apdev):
    """DPP QR Code and authentication exchange (Initiator in either role)"""
    run_dpp_qr_code_auth_initiator_either(dev, apdev, None, dev[1], dev[0])

def test_dpp_qr_code_auth_initiator_either_2(dev, apdev):
    """DPP QR Code and authentication exchange (Initiator in either role)"""
    run_dpp_qr_code_auth_initiator_either(dev, apdev, "enrollee",
                                          dev[1], dev[0])

def test_dpp_qr_code_auth_initiator_either_3(dev, apdev):
    """DPP QR Code and authentication exchange (Initiator in either role)"""
    run_dpp_qr_code_auth_initiator_either(dev, apdev, "configurator",
                                          dev[0], dev[1])

def run_dpp_qr_code_auth_initiator_either(dev, apdev, resp_role,
                                          conf_dev, enrollee_dev):
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    logger.info("dev0 displays QR Code")
    addr = dev[0].own_addr().replace(':', '')
    res = dev[0].request("DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    logger.info("dev1 scans QR Code")
    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    logger.info("dev1 initiates DPP Authentication")
    cmd = "DPP_LISTEN 2412"
    if resp_role:
        cmd += " role=" + resp_role
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")
    if "OK" not in dev[1].request("DPP_AUTH_INIT peer=%d role=either" % id1):
        raise Exception("Failed to initiate DPP Authentication")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")

    ev = conf_dev.wait_event(["DPP-CONF-SENT"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration did not succeed (Configurator)")
    ev = enrollee_dev.wait_event(["DPP-CONF-FAILED"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration did not succeed (Enrollee)")

    dev[0].request("DPP_STOP_LISTEN")

def test_dpp_qr_code_auth_incompatible_roles(dev, apdev):
    """DPP QR Code and authentication exchange (incompatible roles)"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    logger.info("dev0 displays QR Code")
    addr = dev[0].own_addr().replace(':', '')
    res = dev[0].request("DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    logger.info("dev1 scans QR Code")
    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    logger.info("dev1 initiates DPP Authentication")
    if "OK" not in dev[0].request("DPP_LISTEN 2412 role=enrollee"):
        raise Exception("Failed to start listen operation")
    if "OK" not in dev[1].request("DPP_AUTH_INIT peer=%d role=enrollee" % id1):
        raise Exception("Failed to initiate DPP Authentication")
    ev = dev[1].wait_event(["DPP-NOT-COMPATIBLE"], timeout=5)
    if ev is None:
        raise Exception("DPP-NOT-COMPATIBLE event on initiator timed out")
    ev = dev[0].wait_event(["DPP-NOT-COMPATIBLE"], timeout=1)
    if ev is None:
        raise Exception("DPP-NOT-COMPATIBLE event on responder timed out")

    if "OK" not in dev[1].request("DPP_AUTH_INIT peer=%d role=configurator" % id1):
        raise Exception("Failed to initiate DPP Authentication")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    dev[0].request("DPP_STOP_LISTEN")

def test_dpp_qr_code_auth_neg_chan(dev, apdev):
    """DPP QR Code and authentication exchange with requested different channel"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    logger.info("Create configurator on dev1")
    cmd = "DPP_CONFIGURATOR_ADD"
    res = dev[1].request(cmd);
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id = int(res)

    logger.info("dev0 displays QR Code")
    addr = dev[0].own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    logger.info("dev1 scans QR Code")
    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    logger.info("dev1 initiates DPP Authentication")
    cmd = "DPP_LISTEN 2412"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")
    cmd = "DPP_AUTH_INIT peer=%d configurator=%d conf=sta-dpp neg_freq=2462" % (id1, conf_id)
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to initiate DPP Authentication")

    ev = dev[1].wait_event(["DPP-TX"], timeout=5)
    if ev is None:
        raise Exception("DPP Authentication Request not sent")
    if "freq=2412 type=0" not in ev:
        raise Exception("Unexpected TX data for Authentication Request: " + ev)

    ev = dev[0].wait_event(["DPP-RX"], timeout=5)
    if ev is None:
        raise Exception("DPP Authentication Request not received")
    if "freq=2412 type=0" not in ev:
        raise Exception("Unexpected RX data for Authentication Request: " + ev)

    ev = dev[1].wait_event(["DPP-TX-STATUS"], timeout=5)
    if ev is None:
        raise Exception("TX status for DPP Authentication Request not reported")
    if "freq=2412 result=SUCCESS" not in ev:
        raise Exception("Unexpected TX status for Authentication Request: " + ev)

    ev = dev[0].wait_event(["DPP-TX"], timeout=5)
    if ev is None:
        raise Exception("DPP Authentication Response not sent")
    if "freq=2462 type=1" not in ev:
        raise Exception("Unexpected TX data for Authentication Response: " + ev)

    ev = dev[1].wait_event(["DPP-RX"], timeout=5)
    if ev is None:
        raise Exception("DPP Authentication Response not received")
    if "freq=2462 type=1" not in ev:
        raise Exception("Unexpected RX data for Authentication Response: " + ev)

    ev = dev[0].wait_event(["DPP-TX-STATUS"], timeout=5)
    if ev is None:
        raise Exception("TX status for DPP Authentication Response not reported")
    if "freq=2462 result=SUCCESS" not in ev:
        raise Exception("Unexpected TX status for Authentication Response: " + ev)

    ev = dev[1].wait_event(["DPP-TX"], timeout=5)
    if ev is None:
        raise Exception("DPP Authentication Confirm not sent")
    if "freq=2462 type=2" not in ev:
        raise Exception("Unexpected TX data for Authentication Confirm: " + ev)

    ev = dev[0].wait_event(["DPP-RX"], timeout=5)
    if ev is None:
        raise Exception("DPP Authentication Confirm not received")
    if "freq=2462 type=2" not in ev:
        raise Exception("Unexpected RX data for Authentication Confirm: " + ev)

    ev = dev[1].wait_event(["DPP-TX-STATUS"], timeout=5)
    if ev is None:
        raise Exception("TX status for DPP Authentication Confirm not reported")
    if "freq=2462 result=SUCCESS" not in ev:
        raise Exception("Unexpected TX status for Authentication Confirm: " + ev)

    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    ev = dev[1].wait_event(["DPP-CONF-SENT"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator)")
    ev = dev[0].wait_event(["DPP-CONF-RECEIVED", "DPP-CONF-FAILED"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee)")
    if "DPP-CONF-FAILED" in ev:
        raise Exception("DPP configuration failed")
    dev[0].request("DPP_STOP_LISTEN")
    dev[0].dump_monitor()
    dev[1].dump_monitor()

def test_dpp_config_legacy(dev, apdev):
    """DPP Config Object for legacy network using passphrase"""
    check_dpp_capab(dev[1])
    conf = '{"wi-fi_tech":"infra", "discovery":{"ssid":"test"},"cred":{"akm":"psk","pass":"secret passphrase"}}'
    dev[1].set("dpp_config_obj_override", conf)
    run_dpp_qr_code_auth_unicast(dev, apdev, "prime256v1",
                                 require_conf_success=True)

def test_dpp_config_legacy_psk_hex(dev, apdev):
    """DPP Config Object for legacy network using PSK"""
    check_dpp_capab(dev[1])
    conf = '{"wi-fi_tech":"infra", "discovery":{"ssid":"test"},"cred":{"akm":"psk","psk_hex":"' + 32*"12" + '"}}'
    dev[1].set("dpp_config_obj_override", conf)
    run_dpp_qr_code_auth_unicast(dev, apdev, "prime256v1",
                                 require_conf_success=True)

def test_dpp_config_fragmentation(dev, apdev):
    """DPP Config Object for legacy network requiring fragmentation"""
    check_dpp_capab(dev[1])
    conf = '{"wi-fi_tech":"infra", "discovery":{"ssid":"test"},"cred":{"akm":"psk","pass":"secret passphrase"}}' + 3000*' '
    dev[1].set("dpp_config_obj_override", conf)
    run_dpp_qr_code_auth_unicast(dev, apdev, "prime256v1",
                                 require_conf_success=True)

def test_dpp_config_legacy_gen(dev, apdev):
    """Generate DPP Config Object for legacy network"""
    run_dpp_qr_code_auth_unicast(dev, apdev, "prime256v1",
                                 init_extra="conf=sta-psk pass=%s" % "passphrase".encode("hex"),
                                 require_conf_success=True)

def test_dpp_config_legacy_gen_psk(dev, apdev):
    """Generate DPP Config Object for legacy network (PSK)"""
    run_dpp_qr_code_auth_unicast(dev, apdev, "prime256v1",
                                 init_extra="conf=sta-psk psk=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                                 require_conf_success=True)

def test_dpp_config_dpp_gen_prime256v1(dev, apdev):
    """Generate DPP Config Object for DPP network (P-256)"""
    run_dpp_qr_code_auth_unicast(dev, apdev, "prime256v1",
                                 init_extra="conf=sta-dpp",
                                 require_conf_success=True,
                                 configurator=True)

def test_dpp_config_dpp_gen_secp384r1(dev, apdev):
    """Generate DPP Config Object for DPP network (P-384)"""
    run_dpp_qr_code_auth_unicast(dev, apdev, "secp384r1",
                                 init_extra="conf=sta-dpp",
                                 require_conf_success=True,
                                 configurator=True)

def test_dpp_config_dpp_gen_secp521r1(dev, apdev):
    """Generate DPP Config Object for DPP network (P-521)"""
    run_dpp_qr_code_auth_unicast(dev, apdev, "secp521r1",
                                 init_extra="conf=sta-dpp",
                                 require_conf_success=True,
                                 configurator=True)

def test_dpp_config_dpp_gen_prime256v1_prime256v1(dev, apdev):
    """Generate DPP Config Object for DPP network (P-256 + P-256)"""
    run_dpp_qr_code_auth_unicast(dev, apdev, "prime256v1",
                                 init_extra="conf=sta-dpp",
                                 require_conf_success=True,
                                 configurator=True,
                                 conf_curve="prime256v1")

def test_dpp_config_dpp_gen_prime256v1_secp384r1(dev, apdev):
    """Generate DPP Config Object for DPP network (P-256 + P-384)"""
    run_dpp_qr_code_auth_unicast(dev, apdev, "prime256v1",
                                 init_extra="conf=sta-dpp",
                                 require_conf_success=True,
                                 configurator=True,
                                 conf_curve="secp384r1")

def test_dpp_config_dpp_gen_prime256v1_secp521r1(dev, apdev):
    """Generate DPP Config Object for DPP network (P-256 + P-521)"""
    run_dpp_qr_code_auth_unicast(dev, apdev, "prime256v1",
                                 init_extra="conf=sta-dpp",
                                 require_conf_success=True,
                                 configurator=True,
                                 conf_curve="secp521r1")

def test_dpp_config_dpp_gen_secp384r1_prime256v1(dev, apdev):
    """Generate DPP Config Object for DPP network (P-384 + P-256)"""
    run_dpp_qr_code_auth_unicast(dev, apdev, "secp384r1",
                                 init_extra="conf=sta-dpp",
                                 require_conf_success=True,
                                 configurator=True,
                                 conf_curve="prime256v1")

def test_dpp_config_dpp_gen_secp384r1_secp384r1(dev, apdev):
    """Generate DPP Config Object for DPP network (P-384 + P-384)"""
    run_dpp_qr_code_auth_unicast(dev, apdev, "secp384r1",
                                 init_extra="conf=sta-dpp",
                                 require_conf_success=True,
                                 configurator=True,
                                 conf_curve="secp384r1")

def test_dpp_config_dpp_gen_secp384r1_secp521r1(dev, apdev):
    """Generate DPP Config Object for DPP network (P-384 + P-521)"""
    run_dpp_qr_code_auth_unicast(dev, apdev, "secp384r1",
                                 init_extra="conf=sta-dpp",
                                 require_conf_success=True,
                                 configurator=True,
                                 conf_curve="secp521r1")

def test_dpp_config_dpp_gen_secp521r1_prime256v1(dev, apdev):
    """Generate DPP Config Object for DPP network (P-521 + P-256)"""
    run_dpp_qr_code_auth_unicast(dev, apdev, "secp521r1",
                                 init_extra="conf=sta-dpp",
                                 require_conf_success=True,
                                 configurator=True,
                                 conf_curve="prime256v1")

def test_dpp_config_dpp_gen_secp521r1_secp384r1(dev, apdev):
    """Generate DPP Config Object for DPP network (P-521 + P-384)"""
    run_dpp_qr_code_auth_unicast(dev, apdev, "secp521r1",
                                 init_extra="conf=sta-dpp",
                                 require_conf_success=True,
                                 configurator=True,
                                 conf_curve="secp384r1")

def test_dpp_config_dpp_gen_secp521r1_secp521r1(dev, apdev):
    """Generate DPP Config Object for DPP network (P-521 + P-521)"""
    run_dpp_qr_code_auth_unicast(dev, apdev, "secp521r1",
                                 init_extra="conf=sta-dpp",
                                 require_conf_success=True,
                                 configurator=True,
                                 conf_curve="secp521r1")

def test_dpp_config_dpp_gen_expiry(dev, apdev):
    """Generate DPP Config Object for DPP network with expiry value"""
    run_dpp_qr_code_auth_unicast(dev, apdev, "prime256v1",
                                 init_extra="conf=sta-dpp expiry=%d" % (time.time() + 1000),
                                 require_conf_success=True,
                                 configurator=True)

def test_dpp_config_dpp_gen_expired_key(dev, apdev):
    """Generate DPP Config Object for DPP network with expiry value"""
    run_dpp_qr_code_auth_unicast(dev, apdev, "prime256v1",
                                 init_extra="conf=sta-dpp expiry=%d" % (time.time() - 10),
                                 require_conf_failure=True,
                                 configurator=True)

def test_dpp_config_dpp_override_prime256v1(dev, apdev):
    """DPP Config Object override (P-256)"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    conf = '{"wi-fi_tech":"infra","discovery":{"ssid":"test"},"cred":{"akm":"dpp","signedConnector":"eyJ0eXAiOiJkcHBDb24iLCJraWQiOiJUbkdLaklsTlphYXRyRUFZcmJiamlCNjdyamtMX0FHVldYTzZxOWhESktVIiwiYWxnIjoiRVMyNTYifQ.eyJncm91cHMiOlt7Imdyb3VwSWQiOiIqIiwibmV0Um9sZSI6InN0YSJ9XSwibmV0QWNjZXNzS2V5Ijp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiYVRGNEpFR0lQS1NaMFh2OXpkQ01qbS10bjVYcE1zWUlWWjl3eVNBejFnSSIsInkiOiJRR2NIV0FfNnJiVTlYRFhBenRvWC1NNVEzc3VUbk1hcUVoVUx0bjdTU1h3In19._sm6YswxMf6hJLVTyYoU1uYUeY2VVkUNjrzjSiEhY42StD_RWowStEE-9CRsdCvLmsTptZ72_g40vTFwdId20A","csign":{"kty":"EC","crv":"P-256","x":"W4-Y5N1Pkos3UWb9A5qme0KUYRtY3CVUpekx_MapZ9s","y":"Et-M4NSF4NGjvh2VCh4B1sJ9eSCZ4RNzP2DBdP137VE","kid":"TnGKjIlNZaatrEAYrbbjiB67rjkL_AGVWXO6q9hDJKU"}}}'
    dev[0].set("dpp_ignore_netaccesskey_mismatch", "1")
    dev[1].set("dpp_config_obj_override", conf)
    run_dpp_qr_code_auth_unicast(dev, apdev, "prime256v1",
                                 require_conf_success=True)

def test_dpp_config_dpp_override_secp384r1(dev, apdev):
    """DPP Config Object override (P-384)"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    conf = '{"wi-fi_tech":"infra","discovery":{"ssid":"test"},"cred":{"akm":"dpp","signedConnector":"eyJ0eXAiOiJkcHBDb24iLCJraWQiOiJabi1iMndjbjRLM2pGQklkYmhGZkpVTHJTXzdESS0yMWxFQi02R3gxNjl3IiwiYWxnIjoiRVMzODQifQ.eyJncm91cHMiOlt7Imdyb3VwSWQiOiIqIiwibmV0Um9sZSI6InN0YSJ9XSwibmV0QWNjZXNzS2V5Ijp7Imt0eSI6IkVDIiwiY3J2IjoiUC0zODQiLCJ4IjoickdrSGg1UUZsOUtfWjdqYUZkVVhmbThoY1RTRjM1b25Xb1NIRXVsbVNzWW9oX1RXZGpoRjhiVGdiS0ZRN2tBViIsInkiOiJBbU1QVDA5VmFENWpGdzMwTUFKQlp2VkZXeGNlVVlKLXR5blQ0bVJ5N0xOZWxhZ0dEWHpfOExaRlpOU2FaNUdLIn19.Yn_F7m-bbOQ5PlaYQJ9-1qsuqYQ6V-rAv8nWw1COKiCYwwbt3WFBJ8DljY0dPrlg5CHJC4saXwkytpI-CpELW1yUdzYb4Lrun07d20Eo_g10ICyOl5sqQCAUElKMe_Xr","csign":{"kty":"EC","crv":"P-384","x":"dmTyXXiPV2Y8a01fujL-jo08gvzyby23XmzOtzjAiujKQZZgPJsbhfEKrZDlc6ey","y":"H5Z0av5c7bqInxYb2_OOJdNiMhVf3zlcULR0516ZZitOY4U31KhL4wl4KGV7g2XW","kid":"Zn-b2wcn4K3jFBIdbhFfJULrS_7DI-21lEB-6Gx169w"}}}'
    dev[0].set("dpp_ignore_netaccesskey_mismatch", "1")
    dev[1].set("dpp_config_obj_override", conf)
    run_dpp_qr_code_auth_unicast(dev, apdev, "secp384r1",
                                 require_conf_success=True)

def test_dpp_config_dpp_override_secp521r1(dev, apdev):
    """DPP Config Object override (P-521)"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    conf = '{"wi-fi_tech":"infra","discovery":{"ssid":"test"},"cred":{"akm":"dpp","signedConnector":"eyJ0eXAiOiJkcHBDb24iLCJraWQiOiJMZkhKY3hnV2ZKcG1uS2IwenZRT0F2VDB2b0ZKc0JjZnBmYzgxY3Y5ZXFnIiwiYWxnIjoiRVM1MTIifQ.eyJncm91cHMiOlt7Imdyb3VwSWQiOiIqIiwibmV0Um9sZSI6InN0YSJ9XSwibmV0QWNjZXNzS2V5Ijp7Imt0eSI6IkVDIiwiY3J2IjoiUC01MjEiLCJ4IjoiQVJlUFBrMFNISkRRR2NWbnlmM3lfbTlaQllHNjFJeElIbDN1NkdwRHVhMkU1WVd4TE1BSUtMMnZuUGtlSGFVRXljRmZaZlpYZ2JlNkViUUxMVkRVUm1VUSIsInkiOiJBWUtaYlNwUkFFNjJVYm9YZ2c1ZWRBVENzbEpzTlpwcm9RR1dUcW9Md04weXkzQkVoT3ZRZmZrOWhaR2lKZ295TzFobXFRRVRrS0pXb2tIYTBCQUpLSGZtIn19.ACEZLyPk13cM_OFScpLoCElQ2t1sxq5z2d_W_3_QslTQQe5SFiH_o8ycL4632YLAH4RV0gZcMKKRMtZdHgBYHjkzASDqgY-_aYN2SBmpfl8hw0YdDlUJWX3DJf-ofqNAlTbnGmhpSg69cEAhFn41Xgvx2MdwYcPVncxxESVOtWl5zNLK","csign":{"kty":"EC","crv":"P-521","x":"ADiOI_YJOAipEXHB-SpGl4KqokX8m8h3BVYCc8dgiwssZ061-nIIY3O1SIO6Re4Jjfy53RPgzDG6jitOgOGLtzZs","y":"AZKggKaQi0ExutSpJAU3-lqDV03sBQLA9C7KabfWoAn8qD6Vk4jU0WAJdt-wBBTF9o1nVuiqS2OxMVYrxN4lOz79","kid":"LfHJcxgWfJpmnKb0zvQOAvT0voFJsBcfpfc81cv9eqg"}}}'
    dev[0].set("dpp_ignore_netaccesskey_mismatch", "1")
    dev[1].set("dpp_config_obj_override", conf)
    run_dpp_qr_code_auth_unicast(dev, apdev, "secp521r1",
                                 require_conf_success=True)

def test_dpp_config_override_objects(dev, apdev):
    """Generate DPP Config Object and override objects)"""
    check_dpp_capab(dev[1])
    discovery = '{\n"ssid":"mywifi"\n}'
    groups = '[\n  {"groupId":"home","netRole":"sta"},\n  {"groupId":"cottage","netRole":"sta"}\n]'
    dev[1].set("dpp_discovery_override", discovery)
    dev[1].set("dpp_groups_override", groups)
    run_dpp_qr_code_auth_unicast(dev, apdev, "prime256v1",
                                 init_extra="conf=sta-dpp",
                                 require_conf_success=True,
                                 configurator=True)

def test_dpp_gas_timeout(dev, apdev):
    """DPP and GAS server timeout for a query"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    logger.info("dev0 displays QR Code")
    addr = dev[0].own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    logger.info("dev1 scans QR Code")
    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    logger.info("dev1 initiates DPP Authentication")
    dev[0].set("ext_mgmt_frame_handling", "1")
    cmd = "DPP_LISTEN 2412"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")

    # Force GAS fragmentation
    conf = '{"wi-fi_tech":"infra", "discovery":{"ssid":"test"},"cred":{"akm":"psk","pass":"secret passphrase"}}' + 3000*' '
    dev[1].set("dpp_config_obj_override", conf)

    cmd = "DPP_AUTH_INIT peer=%d" % id1
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to initiate DPP Authentication")

    # DPP Authentication Request
    msg = dev[0].mgmt_rx()
    if "OK" not in dev[0].request("MGMT_RX_PROCESS freq={} datarate={} ssi_signal={} frame={}".format(msg['freq'], msg['datarate'], msg['ssi_signal'], msg['frame'].encode('hex'))):
        raise Exception("MGMT_RX_PROCESS failed")

    # DPP Authentication Confirmation
    msg = dev[0].mgmt_rx()
    if "OK" not in dev[0].request("MGMT_RX_PROCESS freq={} datarate={} ssi_signal={} frame={}".format(msg['freq'], msg['datarate'], msg['ssi_signal'], msg['frame'].encode('hex'))):
        raise Exception("MGMT_RX_PROCESS failed")

    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")

    # DPP Configuration Response (GAS Initial Response frame)
    msg = dev[0].mgmt_rx()
    if "OK" not in dev[0].request("MGMT_RX_PROCESS freq={} datarate={} ssi_signal={} frame={}".format(msg['freq'], msg['datarate'], msg['ssi_signal'], msg['frame'].encode('hex'))):
        raise Exception("MGMT_RX_PROCESS failed")

    # GAS Comeback Response frame
    msg = dev[0].mgmt_rx()
    # Do not continue to force timeout on GAS server

    ev = dev[0].wait_event(["GAS-QUERY-DONE"], timeout=10)
    if ev is None:
        raise Exception("GAS result not reported (Enrollee)")
    if "result=TIMEOUT" not in ev:
        raise Exception("Unexpected GAS result (Enrollee): " + ev)
    dev[0].set("ext_mgmt_frame_handling", "0")

    ev = dev[1].wait_event(["DPP-CONF-FAILED"], timeout=15)
    if ev is None:
        raise Exception("DPP configuration failure not reported (Configurator)")

    ev = dev[0].wait_event(["DPP-CONF-FAILED"], timeout=1)
    if ev is None:
        raise Exception("DPP configuration failure not reported (Enrollee)")

def test_dpp_akm_sha256(dev, apdev):
    """DPP AKM (SHA256)"""
    run_dpp_akm(dev, apdev, 32)

def test_dpp_akm_sha384(dev, apdev):
    """DPP AKM (SHA384)"""
    run_dpp_akm(dev, apdev, 48)

def test_dpp_akm_sha512(dev, apdev):
    """DPP AKM (SHA512)"""
    run_dpp_akm(dev, apdev, 64)

def run_dpp_akm(dev, apdev, pmk_len):
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    params = { "ssid": "dpp",
               "wpa": "2",
               "wpa_key_mgmt": "DPP",
               "rsn_pairwise": "CCMP",
               "ieee80211w": "2" }
    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except:
        raise HwsimSkip("DPP not supported")

    id = dev[0].connect("dpp", key_mgmt="DPP", ieee80211w="2", scan_freq="2412",
                        wait_connect=False)
    ev = dev[0].wait_event(["CTRL-EVENT-NETWORK-NOT-FOUND"], timeout=2)
    if not ev:
        raise Exception("Network mismatch not reported")
    dev[0].request("DISCONNECT")
    dev[0].dump_monitor()

    bssid = hapd.own_addr()
    pmkid = 16*'11'
    akmp = 2**23
    pmk = pmk_len*'22'
    cmd = "PMKSA_ADD %d %s %s %s 30240 43200 %d 0" % (id, bssid, pmkid, pmk, akmp)
    if "OK" not in dev[0].request(cmd):
        raise Exception("PMKSA_ADD failed (wpa_supplicant)")
    dev[0].select_network(id, freq="2412")
    ev = dev[0].wait_event(["CTRL-EVENT-ASSOC-REJECT"], timeout=2)
    dev[0].request("DISCONNECT")
    dev[0].dump_monitor()
    if not ev:
        raise Exception("Association attempt was not rejected")
    if "status_code=53" not in ev:
        raise Exception("Unexpected status code: " + ev)

    addr = dev[0].own_addr()
    cmd = "PMKSA_ADD %s %s %s 0 %d" % (addr, pmkid, pmk, akmp)
    if "OK" not in hapd.request(cmd):
        raise Exception("PMKSA_ADD failed (hostapd)")

    dev[0].select_network(id, freq="2412")
    dev[0].wait_connected()
    val = dev[0].get_status_field("key_mgmt")
    if val != "DPP":
        raise Exception("Unexpected key_mgmt: " + val)

def test_dpp_network_introduction(dev, apdev):
    """DPP network introduction"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    csign = "3059301306072a8648ce3d020106082a8648ce3d03010703420004d02e5bd81a120762b5f0f2994777f5d40297238a6c294fd575cdf35fabec44c050a6421c401d98d659fd2ed13c961cc8287944dd3202f516977800d3ab2f39ee"
    ap_connector = "eyJ0eXAiOiJkcHBDb24iLCJraWQiOiJzOEFrYjg5bTV4UGhoYk5UbTVmVVo0eVBzNU5VMkdxYXNRY3hXUWhtQVFRIiwiYWxnIjoiRVMyNTYifQ.eyJncm91cHMiOlt7Imdyb3VwSWQiOiIqIiwibmV0Um9sZSI6ImFwIn1dLCJuZXRBY2Nlc3NLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiIwOHF4TlNYRzRWemdCV3BjVUdNSmc1czNvbElOVFJsRVQ1aERpNkRKY3ZjIiwieSI6IlVhaGFYQXpKRVpRQk1YaHRUQnlZZVlrOWtJYjk5UDA3UV9NcW9TVVZTVEkifX0.a5_nfMVr7Qe1SW0ZL3u6oQRm5NUCYUSfixDAJOUFN3XUfECBZ6E8fm8xjeSfdOytgRidTz0CTlIRjzPQo82dmQ"
    ap_netaccesskey = "30770201010420f6531d17f29dfab655b7c9e923478d5a345164c489aadd44a3519c3e9dcc792da00a06082a8648ce3d030107a14403420004d3cab13525c6e15ce0056a5c506309839b37a2520d4d19444f98438ba0c972f751a85a5c0cc911940131786d4c1c9879893d9086fdf4fd3b43f32aa125154932"
    sta_connector = "eyJ0eXAiOiJkcHBDb24iLCJraWQiOiJzOEFrYjg5bTV4UGhoYk5UbTVmVVo0eVBzNU5VMkdxYXNRY3hXUWhtQVFRIiwiYWxnIjoiRVMyNTYifQ.eyJncm91cHMiOlt7Imdyb3VwSWQiOiIqIiwibmV0Um9sZSI6InN0YSJ9XSwibmV0QWNjZXNzS2V5Ijp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZWMzR3NqQ3lQMzVBUUZOQUJJdEltQnN4WXVyMGJZX1dES1lfSE9zUGdjNCIsInkiOiJTRS1HVllkdWVnTFhLMU1TQXZNMEx2QWdLREpTNWoyQVhCbE9PMTdUSTRBIn19.PDK9zsGlK-e1pEOmNxVeJfCS8pNeay6ckIS1TXCQsR64AR-9wFPCNVjqOxWvVKltehyMFqVAtOcv0IrjtMJFqQ"
    sta_netaccesskey = "30770201010420bc33380c26fd2168b69cd8242ed1df07ba89aa4813f8d4e8523de6ca3f8dd28ba00a06082a8648ce3d030107a1440342000479cdc6b230b23f7e40405340048b48981b3162eaf46d8fd60ca63f1ceb0f81ce484f8655876e7a02d72b531202f3342ef020283252e63d805c194e3b5ed32380"

    params = { "ssid": "dpp",
               "wpa": "2",
               "wpa_key_mgmt": "DPP",
               "ieee80211w": "2",
               "rsn_pairwise": "CCMP",
               "dpp_connector": ap_connector,
               "dpp_csign": csign,
               "dpp_netaccesskey": ap_netaccesskey }
    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except:
        raise HwsimSkip("DPP not supported")

    id = dev[0].connect("dpp", key_mgmt="DPP", scan_freq="2412",
                        ieee80211w="2",
                        dpp_csign=csign,
                        dpp_connector=sta_connector,
                        dpp_netaccesskey=sta_netaccesskey)
    val = dev[0].get_status_field("key_mgmt")
    if val != "DPP":
        raise Exception("Unexpected key_mgmt: " + val)

def test_dpp_ap_config(dev, apdev):
    """DPP and AP configuration"""
    run_dpp_ap_config(dev, apdev)

def test_dpp_ap_config_p256_p256(dev, apdev):
    """DPP and AP configuration (P-256 + P-256)"""
    run_dpp_ap_config(dev, apdev, curve="P-256", conf_curve="P-256")

def test_dpp_ap_config_p256_p384(dev, apdev):
    """DPP and AP configuration (P-256 + P-384)"""
    run_dpp_ap_config(dev, apdev, curve="P-256", conf_curve="P-384")

def test_dpp_ap_config_p256_p521(dev, apdev):
    """DPP and AP configuration (P-256 + P-521)"""
    run_dpp_ap_config(dev, apdev, curve="P-256", conf_curve="P-521")

def test_dpp_ap_config_p384_p256(dev, apdev):
    """DPP and AP configuration (P-384 + P-256)"""
    run_dpp_ap_config(dev, apdev, curve="P-384", conf_curve="P-256")

def test_dpp_ap_config_p384_p384(dev, apdev):
    """DPP and AP configuration (P-384 + P-384)"""
    run_dpp_ap_config(dev, apdev, curve="P-384", conf_curve="P-384")

def test_dpp_ap_config_p384_p521(dev, apdev):
    """DPP and AP configuration (P-384 + P-521)"""
    run_dpp_ap_config(dev, apdev, curve="P-384", conf_curve="P-521")

def test_dpp_ap_config_p521_p256(dev, apdev):
    """DPP and AP configuration (P-521 + P-256)"""
    run_dpp_ap_config(dev, apdev, curve="P-521", conf_curve="P-256")

def test_dpp_ap_config_p521_p384(dev, apdev):
    """DPP and AP configuration (P-521 + P-384)"""
    run_dpp_ap_config(dev, apdev, curve="P-521", conf_curve="P-384")

def test_dpp_ap_config_p521_p521(dev, apdev):
    """DPP and AP configuration (P-521 + P-521)"""
    run_dpp_ap_config(dev, apdev, curve="P-521", conf_curve="P-521")

def update_hapd_config(hapd):
    ev = hapd.wait_event(["DPP-CONFOBJ-SSID"], timeout=1)
    if ev is None:
        raise Exception("SSID not reported (AP)")
    ssid = ev.split(' ')[1]

    ev = hapd.wait_event(["DPP-CONNECTOR"], timeout=1)
    if ev is None:
        raise Exception("Connector not reported (AP)")
    connector = ev.split(' ')[1]

    ev = hapd.wait_event(["DPP-C-SIGN-KEY"], timeout=1)
    if ev is None:
        raise Exception("C-sign-key not reported (AP)")
    p = ev.split(' ')
    csign = p[1]

    ev = hapd.wait_event(["DPP-NET-ACCESS-KEY"], timeout=1)
    if ev is None:
        raise Exception("netAccessKey not reported (AP)")
    p = ev.split(' ')
    net_access_key = p[1]
    net_access_key_expiry = p[2] if len(p) > 2 else None

    logger.info("Update AP configuration to use key_mgmt=DPP")
    hapd.disable()
    hapd.set("ssid", ssid)
    hapd.set("wpa", "2")
    hapd.set("wpa_key_mgmt", "DPP")
    hapd.set("ieee80211w", "2")
    hapd.set("rsn_pairwise", "CCMP")
    hapd.set("dpp_connector", connector)
    hapd.set("dpp_csign", csign)
    hapd.set("dpp_netaccesskey", net_access_key)
    if net_access_key_expiry:
        hapd.set("dpp_netaccesskey_expiry", net_access_key_expiry)
    hapd.enable()

def run_dpp_ap_config(dev, apdev, curve=None, conf_curve=None):
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    hapd = hostapd.add_ap(apdev[0], { "ssid": "unconfigured" })
    check_dpp_capab(hapd)

    addr = hapd.own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr
    if curve:
        cmd += " curve=" + curve
    res = hapd.request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id_h = int(res)
    uri = hapd.request("DPP_BOOTSTRAP_GET_URI %d" % id_h)

    cmd = "DPP_CONFIGURATOR_ADD"
    if conf_curve:
        cmd += " curve=" + conf_curve
    res = dev[0].request(cmd);
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id = int(res)

    res = dev[0].request("DPP_QR_CODE " + uri)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id = int(res)

    cmd = "DPP_AUTH_INIT peer=%d conf=ap-dpp configurator=%d" % (id, conf_id)
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to initiate DPP Authentication")
    ev = hapd.wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    ev = dev[0].wait_event(["DPP-CONF-SENT"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator)")
    ev = hapd.wait_event(["DPP-CONF-RECEIVED", "DPP-CONF-FAILED"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee)")
    if "DPP-CONF-FAILED" in ev:
        raise Exception("DPP configuration failed")

    update_hapd_config(hapd)

    addr = dev[1].own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr
    if curve:
        cmd += " curve=" + curve
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id1 = int(res)
    uri1 = dev[1].request("DPP_BOOTSTRAP_GET_URI %d" % id1)

    res = dev[0].request("DPP_QR_CODE " + uri1)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id0b = int(res)

    cmd = "DPP_LISTEN 2412"
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to start listen operation")
    cmd = "DPP_AUTH_INIT peer=%d conf=sta-dpp configurator=%d" % (id0b, conf_id)
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to initiate DPP Authentication")
    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    ev = dev[0].wait_event(["DPP-CONF-SENT"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator)")
    ev = dev[1].wait_event(["DPP-CONF-RECEIVED"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee)")
    dev[1].request("DPP_STOP_LISTEN")

    ev = dev[1].wait_event(["DPP-CONFOBJ-SSID"], timeout=1)
    if ev is None:
        raise Exception("SSID not reported")
    ssid = ev.split(' ')[1]

    ev = dev[1].wait_event(["DPP-CONNECTOR"], timeout=1)
    if ev is None:
        raise Exception("Connector not reported")
    connector = ev.split(' ')[1]

    ev = dev[1].wait_event(["DPP-C-SIGN-KEY"], timeout=1)
    if ev is None:
        raise Exception("C-sign-key not reported")
    p = ev.split(' ')
    csign = p[1]

    ev = dev[1].wait_event(["DPP-NET-ACCESS-KEY"], timeout=1)
    if ev is None:
        raise Exception("netAccessKey not reported")
    p = ev.split(' ')
    net_access_key = p[1]
    net_access_key_expiry = p[2] if len(p) > 2 else None

    dev[1].dump_monitor()

    id = dev[1].connect(ssid, key_mgmt="DPP", ieee80211w="2", scan_freq="2412",
                        only_add_network=True)
    dev[1].set_network_quoted(id, "dpp_connector", connector)
    dev[1].set_network(id, "dpp_csign", csign)
    dev[1].set_network(id, "dpp_netaccesskey", net_access_key)
    if net_access_key_expiry:
        dev[1].set_network(id, "dpp_netaccess_expiry", net_access_key_expiry)

    logger.info("Check data connection")
    dev[1].select_network(id, freq="2412")
    dev[1].wait_connected()

def test_dpp_auto_connect_1(dev, apdev):
    """DPP and auto connect (1)"""
    try:
        run_dpp_auto_connect(dev, apdev, 1)
    finally:
        dev[0].set("dpp_config_processing", "0")

def test_dpp_auto_connect_2(dev, apdev):
    """DPP and auto connect (2)"""
    try:
        run_dpp_auto_connect(dev, apdev, 2)
    finally:
        dev[0].set("dpp_config_processing", "0")

def test_dpp_auto_connect_2_connect_cmd(dev, apdev):
    """DPP and auto connect (2) using connect_cmd"""
    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
    wpas.interface_add("wlan5", drv_params="force_connect_cmd=1")
    dev_new = [ wpas, dev[1] ]
    try:
        run_dpp_auto_connect(dev_new, apdev, 2)
    finally:
        wpas.set("dpp_config_processing", "0")

def run_dpp_auto_connect(dev, apdev, processing):
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    csign = "30770201010420768240a3fc89d6662d9782f120527fe7fb9edc6366ab0b9c7dde96125cfd250fa00a06082a8648ce3d030107a144034200042908e1baf7bf413cc66f9e878a03e8bb1835ba94b033dbe3d6969fc8575d5eb5dfda1cb81c95cee21d0cd7d92ba30541ffa05cb6296f5dd808b0c1c2a83c0708"
    csign_pub = "3059301306072a8648ce3d020106082a8648ce3d030107034200042908e1baf7bf413cc66f9e878a03e8bb1835ba94b033dbe3d6969fc8575d5eb5dfda1cb81c95cee21d0cd7d92ba30541ffa05cb6296f5dd808b0c1c2a83c0708"
    ap_connector = "eyJ0eXAiOiJkcHBDb24iLCJraWQiOiJwYWtZbXVzd1dCdWpSYTl5OEsweDViaTVrT3VNT3dzZHRlaml2UG55ZHZzIiwiYWxnIjoiRVMyNTYifQ.eyJncm91cHMiOlt7Imdyb3VwSWQiOiIqIiwibmV0Um9sZSI6ImFwIn1dLCJuZXRBY2Nlc3NLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiIybU5vNXZuRkI5bEw3d1VWb1hJbGVPYzBNSEE1QXZKbnpwZXZULVVTYzVNIiwieSI6IlhzS3dqVHJlLTg5WWdpU3pKaG9CN1haeUttTU05OTl3V2ZaSVl0bi01Q3MifX0.XhjFpZgcSa7G2lHy0OCYTvaZFRo5Hyx6b7g7oYyusLC7C_73AJ4_BxEZQVYJXAtDuGvb3dXSkHEKxREP9Q6Qeg"
    ap_netaccesskey = "30770201010420ceba752db2ad5200fa7bc565b9c05c69b7eb006751b0b329b0279de1c19ca67ca00a06082a8648ce3d030107a14403420004da6368e6f9c507d94bef0515a1722578e73430703902f267ce97af4fe51273935ec2b08d3adefbcf588224b3261a01ed76722a630cf7df7059f64862d9fee42b"

    params = { "ssid": "test",
               "wpa": "2",
               "wpa_key_mgmt": "DPP",
               "ieee80211w": "2",
               "rsn_pairwise": "CCMP",
               "dpp_connector": ap_connector,
               "dpp_csign": csign_pub,
               "dpp_netaccesskey": ap_netaccesskey }
    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except:
        raise HwsimSkip("DPP not supported")

    cmd = "DPP_CONFIGURATOR_ADD key=" + csign
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("DPP_CONFIGURATOR_ADD failed")
    conf_id = int(res)

    dev[0].set("dpp_config_processing", str(processing))
    addr = dev[0].own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    cmd = "DPP_LISTEN 2412"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")

    cmd = "DPP_AUTH_INIT peer=%d conf=sta-dpp configurator=%d" % (id1, conf_id)
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to initiate DPP Authentication")
    ev = dev[1].wait_event(["DPP-CONF-SENT"], timeout=10)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator)")
    ev = dev[0].wait_event(["DPP-CONF-RECEIVED"], timeout=2)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee)")
    ev = dev[0].wait_event(["DPP-NETWORK-ID"], timeout=1)
    if ev is None:
        raise Exception("DPP network profile not generated")
    id = ev.split(' ')[1]

    if processing == 1:
        dev[0].select_network(id, freq=2412)

    dev[0].wait_connected()
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_dpp_auto_connect_legacy(dev, apdev):
    """DPP and auto connect (legacy)"""
    try:
        run_dpp_auto_connect_legacy(dev, apdev)
    finally:
        dev[0].set("dpp_config_processing", "0")

def test_dpp_auto_connect_legacy_sae_1(dev, apdev):
    """DPP and auto connect (legacy SAE)"""
    try:
        run_dpp_auto_connect_legacy(dev, apdev, conf='sta-sae', psk_sae=True)
    finally:
        dev[0].set("dpp_config_processing", "0")

def test_dpp_auto_connect_legacy_sae_2(dev, apdev):
    """DPP and auto connect (legacy SAE)"""
    try:
        run_dpp_auto_connect_legacy(dev, apdev, conf='sta-sae', sae_only=True)
    finally:
        dev[0].set("dpp_config_processing", "0")

def test_dpp_auto_connect_legacy_psk_sae_1(dev, apdev):
    """DPP and auto connect (legacy PSK+SAE)"""
    try:
        run_dpp_auto_connect_legacy(dev, apdev, conf='sta-psk-sae',
                                    psk_sae=True)
    finally:
        dev[0].set("dpp_config_processing", "0")

def test_dpp_auto_connect_legacy_psk_sae_2(dev, apdev):
    """DPP and auto connect (legacy PSK+SAE)"""
    try:
        run_dpp_auto_connect_legacy(dev, apdev, conf='sta-psk-sae',
                                    sae_only=True)
    finally:
        dev[0].set("dpp_config_processing", "0")

def test_dpp_auto_connect_legacy_psk_sae_3(dev, apdev):
    """DPP and auto connect (legacy PSK+SAE)"""
    try:
        run_dpp_auto_connect_legacy(dev, apdev, conf='sta-psk-sae')
    finally:
        dev[0].set("dpp_config_processing", "0")

def run_dpp_auto_connect_legacy(dev, apdev, conf='sta-psk',
                                psk_sae=False, sae_only=False):
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    params = hostapd.wpa2_params(ssid="dpp-legacy",
                                 passphrase="secret passphrase")
    if sae_only:
            params['wpa_key_mgmt'] = 'SAE'
            params['ieee80211w'] = '2'
    elif psk_sae:
            params['wpa_key_mgmt'] = 'WPA-PSK SAE'
            params['ieee80211w'] = '1'
            params['sae_require_mfp'] = '1'

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].set("dpp_config_processing", "2")
    addr = dev[0].own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    cmd = "DPP_LISTEN 2412"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")

    cmd = "DPP_AUTH_INIT peer=%d conf=%s ssid=%s pass=%s" % (id1, conf, "dpp-legacy".encode("hex"), "secret passphrase".encode("hex"))
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to initiate DPP Authentication")
    ev = dev[1].wait_event(["DPP-CONF-SENT"], timeout=10)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator)")
    ev = dev[0].wait_event(["DPP-CONF-RECEIVED"], timeout=2)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee)")
    ev = dev[0].wait_event(["DPP-NETWORK-ID"], timeout=1)
    if ev is None:
        raise Exception("DPP network profile not generated")
    id = ev.split(' ')[1]

    dev[0].wait_connected()

def test_dpp_auto_connect_legacy_pmf_required(dev, apdev):
    """DPP and auto connect (legacy, PMF required)"""
    try:
        run_dpp_auto_connect_legacy_pmf_required(dev, apdev)
    finally:
        dev[0].set("dpp_config_processing", "0")

def run_dpp_auto_connect_legacy_pmf_required(dev, apdev):
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    params = hostapd.wpa2_params(ssid="dpp-legacy",
                                 passphrase="secret passphrase")
    params['wpa_key_mgmt'] = "WPA-PSK-SHA256"
    params['ieee80211w'] = "2"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].set("dpp_config_processing", "2")
    addr = dev[0].own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    cmd = "DPP_LISTEN 2412"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")

    cmd = "DPP_AUTH_INIT peer=%d conf=sta-psk ssid=%s pass=%s" % (id1, "dpp-legacy".encode("hex"), "secret passphrase".encode("hex"))
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to initiate DPP Authentication")
    ev = dev[1].wait_event(["DPP-CONF-SENT"], timeout=10)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator)")
    ev = dev[0].wait_event(["DPP-CONF-RECEIVED"], timeout=2)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee)")
    ev = dev[0].wait_event(["DPP-NETWORK-ID"], timeout=1)
    if ev is None:
        raise Exception("DPP network profile not generated")
    id = ev.split(' ')[1]

    dev[0].wait_connected()

def test_dpp_qr_code_auth_responder_configurator(dev, apdev):
    """DPP QR Code and responder as the configurator"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    cmd = "DPP_CONFIGURATOR_ADD"
    res = dev[0].request(cmd);
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id = int(res)

    addr = dev[0].own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    dev[0].set("dpp_configurator_params", " conf=sta-dpp configurator=%d" % conf_id);
    cmd = "DPP_LISTEN 2412 role=configurator"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")
    cmd = "DPP_AUTH_INIT peer=%d role=enrollee" % id1
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to initiate DPP Authentication")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    ev = dev[0].wait_event(["DPP-CONF-SENT"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator)")
    ev = dev[1].wait_event(["DPP-CONF-RECEIVED"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee)")
    dev[0].request("DPP_STOP_LISTEN")
    dev[0].dump_monitor()
    dev[1].dump_monitor()

def test_dpp_qr_code_hostapd_init(dev, apdev):
    """DPP QR Code and hostapd as initiator"""
    check_dpp_capab(dev[0])
    hapd = hostapd.add_ap(apdev[0], { "ssid": "unconfigured",
                                      "channel": "6" })
    check_dpp_capab(hapd)

    cmd = "DPP_CONFIGURATOR_ADD"
    res = dev[0].request(cmd);
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id = int(res)

    addr = dev[0].own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/6 mac=" + addr
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    dev[0].set("dpp_configurator_params",
               " conf=ap-dpp configurator=%d" % conf_id);
    cmd = "DPP_LISTEN 2437 role=configurator"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")

    res = hapd.request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    cmd = "DPP_AUTH_INIT peer=%d role=enrollee" % id1
    if "OK" not in hapd.request(cmd):
        raise Exception("Failed to initiate DPP Authentication")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = hapd.wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    ev = dev[0].wait_event(["DPP-CONF-SENT"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator)")
    ev = hapd.wait_event(["DPP-CONF-RECEIVED"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee)")
    dev[0].request("DPP_STOP_LISTEN")
    dev[0].dump_monitor()

def test_dpp_qr_code_hostapd_init_offchannel(dev, apdev):
    """DPP QR Code and hostapd as initiator (offchannel)"""
    run_dpp_qr_code_hostapd_init_offchannel(dev, apdev, None)

def test_dpp_qr_code_hostapd_init_offchannel_neg_freq(dev, apdev):
    """DPP QR Code and hostapd as initiator (offchannel, neg_freq)"""
    run_dpp_qr_code_hostapd_init_offchannel(dev, apdev, "neg_freq=2437")

def run_dpp_qr_code_hostapd_init_offchannel(dev, apdev, extra):
    check_dpp_capab(dev[0])
    hapd = hostapd.add_ap(apdev[0], { "ssid": "unconfigured",
                                      "channel": "6" })
    check_dpp_capab(hapd)

    cmd = "DPP_CONFIGURATOR_ADD"
    res = dev[0].request(cmd);
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id = int(res)

    addr = dev[0].own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/1,81/11 mac=" + addr
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    dev[0].set("dpp_configurator_params",
               " conf=ap-dpp configurator=%d" % conf_id);
    cmd = "DPP_LISTEN 2462 role=configurator"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")

    res = hapd.request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    cmd = "DPP_AUTH_INIT peer=%d role=enrollee" % id1
    if extra:
        cmd += " " + extra
    if "OK" not in hapd.request(cmd):
        raise Exception("Failed to initiate DPP Authentication")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = hapd.wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    ev = dev[0].wait_event(["DPP-CONF-SENT"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator)")
    ev = hapd.wait_event(["DPP-CONF-RECEIVED"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee)")
    dev[0].request("DPP_STOP_LISTEN")
    dev[0].dump_monitor()

def test_dpp_test_vector_p_256(dev, apdev):
    """DPP P-256 test vector (mutual auth)"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    # Responder bootstrapping key
    priv = "54ce181a98525f217216f59b245f60e9df30ac7f6b26c939418cfc3c42d1afa0"
    addr = dev[0].own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/11 mac=" + addr + " key=30310201010420" + priv + "a00a06082a8648ce3d030107"
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    # Responder protocol keypair override
    priv = "f798ed2e19286f6a6efe210b1863badb99af2a14b497634dbfd2a97394fb5aa5"
    dev[0].set("dpp_protocol_key_override",
               "30310201010420" + priv + "a00a06082a8648ce3d030107")

    dev[0].set("dpp_nonce_override", "3d0cfb011ca916d796f7029ff0b43393")

    # Initiator bootstrapping key
    priv = "15b2a83c5a0a38b61f2aa8200ee4994b8afdc01c58507d10d0a38f7eedf051bb"
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode key=30310201010420" + priv + "a00a06082a8648ce3d030107"
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id1 = int(res)
    uri1 = dev[1].request("DPP_BOOTSTRAP_GET_URI %d" % id1)

    # Initiator protocol keypair override
    priv = "a87de9afbb406c96e5f79a3df895ecac3ad406f95da66314c8cb3165e0c61783"
    dev[1].set("dpp_protocol_key_override",
               "30310201010420" + priv + "a00a06082a8648ce3d030107")

    dev[1].set("dpp_nonce_override", "13f4602a16daeb69712263b9c46cba31")

    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1peer = int(res)

    res = dev[0].request("DPP_QR_CODE " + uri1)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id0peer = int(res)

    cmd = "DPP_LISTEN 2462 qr=mutual"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")

    cmd = "DPP_AUTH_INIT peer=%d own=%d neg_freq=2412" % (id1peer, id1)
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to initiate operation")

    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")

def test_dpp_test_vector_p_256_b(dev, apdev):
    """DPP P-256 test vector (Responder-only auth)"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    # Responder bootstrapping key
    priv = "54ce181a98525f217216f59b245f60e9df30ac7f6b26c939418cfc3c42d1afa0"
    addr = dev[0].own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/11 mac=" + addr + " key=30310201010420" + priv + "a00a06082a8648ce3d030107"
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    # Responder protocol keypair override
    priv = "f798ed2e19286f6a6efe210b1863badb99af2a14b497634dbfd2a97394fb5aa5"
    dev[0].set("dpp_protocol_key_override",
               "30310201010420" + priv + "a00a06082a8648ce3d030107")

    dev[0].set("dpp_nonce_override", "3d0cfb011ca916d796f7029ff0b43393")

    # Initiator bootstrapping key
    priv = "15b2a83c5a0a38b61f2aa8200ee4994b8afdc01c58507d10d0a38f7eedf051bb"
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode key=30310201010420" + priv + "a00a06082a8648ce3d030107"
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id1 = int(res)
    uri1 = dev[1].request("DPP_BOOTSTRAP_GET_URI %d" % id1)

    # Initiator protocol keypair override
    priv = "a87de9afbb406c96e5f79a3df895ecac3ad406f95da66314c8cb3165e0c61783"
    dev[1].set("dpp_protocol_key_override",
               "30310201010420" + priv + "a00a06082a8648ce3d030107")

    dev[1].set("dpp_nonce_override", "13f4602a16daeb69712263b9c46cba31")

    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1peer = int(res)

    cmd = "DPP_LISTEN 2462"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")

    cmd = "DPP_AUTH_INIT peer=%d own=%d neg_freq=2412" % (id1peer, id1)
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to initiate operation")

    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")

def der_priv_key_p_521(priv):
    if len(priv) != 2 * 66:
        raise Exception("Unexpected der_priv_key_p_521 parameter: " + priv)
    der_prefix = "3081500201010442"
    der_postfix = "a00706052b81040023"
    return der_prefix + priv + der_postfix

def test_dpp_test_vector_p_521(dev, apdev):
    """DPP P-521 test vector (mutual auth)"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    # Responder bootstrapping key
    priv = "0061e54f518cdf859735da3dd64c6f72c2f086f41a6fd52915152ea2fe0f24ddaecd8883730c9c9fd82cf7c043a41021696388cf5190b731dd83638bcd56d8b6c743"
    addr = dev[0].own_addr().replace(':', '')
    #cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/11 mac=" + addr + " key=" + der_prefix + priv + der_postfix
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/11 mac=" + addr + " key=" + der_priv_key_p_521(priv)
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    # Responder protocol keypair override
    priv = "01d8b7b17cd1b0a33f7c66fb4220999329cdaf4f8b44b2ffadde8ab8ed8abffa9f5358c5b1caae26709ca4fb78e52a4d08f2e4f24111a36a6f440d20a0000ff51597"
    dev[0].set("dpp_protocol_key_override", der_priv_key_p_521(priv))

    dev[0].set("dpp_nonce_override",
               "d749a782012eb0a8595af30b2dfc8d0880d004ebddb55ecc5afbdef18c400e01")

    # Initiator bootstrapping key
    priv = "0060c10df14af5ef27f6e362d31bdd9eeb44be77a323ba64b08f3f03d58b92cbfe05c182a91660caa081ca344243c47b5aa088bcdf738840eb35f0218b9f26881e02"
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode key=" + der_priv_key_p_521(priv)
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id1 = int(res)
    uri1 = dev[1].request("DPP_BOOTSTRAP_GET_URI %d" % id1)

    # Initiator protocol keypair override
    priv = "019c1c08caaeec38fb931894699b095bc3ab8c1ec7ef0622d2e3eba821477c8c6fca41774f21166ad98aebda37c067d9aa08a8a2e1b5c44c61f2bae02a61f85d9661"
    dev[1].set("dpp_protocol_key_override", der_priv_key_p_521(priv))

    dev[1].set("dpp_nonce_override",
               "de972af3847bec3ba2aedd9f5c21cfdec7bf0bc5fe8b276cbcd0267807fb15b0")

    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1peer = int(res)

    res = dev[0].request("DPP_QR_CODE " + uri1)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id0peer = int(res)

    cmd = "DPP_LISTEN 2462 qr=mutual"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")

    cmd = "DPP_AUTH_INIT peer=%d own=%d neg_freq=2412" % (id1peer, id1)
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to initiate operation")

    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")

def test_dpp_pkex(dev, apdev):
    """DPP and PKEX"""
    run_dpp_pkex(dev, apdev)

def test_dpp_pkex_p256(dev, apdev):
    """DPP and PKEX (P-256)"""
    run_dpp_pkex(dev, apdev, "P-256")

def test_dpp_pkex_p384(dev, apdev):
    """DPP and PKEX (P-384)"""
    run_dpp_pkex(dev, apdev, "P-384")

def test_dpp_pkex_p521(dev, apdev):
    """DPP and PKEX (P-521)"""
    run_dpp_pkex(dev, apdev, "P-521")

def test_dpp_pkex_bp256(dev, apdev):
    """DPP and PKEX (BP-256)"""
    run_dpp_pkex(dev, apdev, "brainpoolP256r1")

def test_dpp_pkex_bp384(dev, apdev):
    """DPP and PKEX (BP-384)"""
    run_dpp_pkex(dev, apdev, "brainpoolP384r1")

def test_dpp_pkex_bp512(dev, apdev):
    """DPP and PKEX (BP-512)"""
    run_dpp_pkex(dev, apdev, "brainpoolP512r1")

def test_dpp_pkex_config(dev, apdev):
    """DPP and PKEX with initiator as the configurator"""
    check_dpp_capab(dev[1])

    cmd = "DPP_CONFIGURATOR_ADD"
    res = dev[1].request(cmd);
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id = int(res)

    run_dpp_pkex(dev, apdev,
                 init_extra="conf=sta-dpp configurator=%d" % (conf_id),
                 check_config=True)

def run_dpp_pkex(dev, apdev, curve=None, init_extra="", check_config=False):
    check_dpp_capab(dev[0], curve and "brainpool" in curve)
    check_dpp_capab(dev[1], curve and "brainpool" in curve)

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    if curve:
        cmd += " curve=" + curve
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    if curve:
        cmd += " curve=" + curve
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id1 = int(res)

    cmd = "DPP_PKEX_ADD own=%d identifier=test code=secret" % (id0)
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (responder)")
    cmd = "DPP_LISTEN 2437"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")

    cmd = "DPP_PKEX_ADD own=%d identifier=test init=1 %s code=secret" % (id1, init_extra)
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (initiator)")

    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")

    if check_config:
        ev = dev[1].wait_event(["DPP-CONF-SENT"], timeout=5)
        if ev is None:
            raise Exception("DPP configuration not completed (Configurator)")
        ev = dev[0].wait_event(["DPP-CONF-RECEIVED"], timeout=5)
        if ev is None:
            raise Exception("DPP configuration not completed (Enrollee)")

def test_dpp_pkex_5ghz(dev, apdev):
    """DPP and PKEX on 5 GHz"""
    try:
        dev[0].request("SET country US")
        dev[1].request("SET country US")
        ev = dev[0].wait_event(["CTRL-EVENT-REGDOM-CHANGE"], timeout=1)
        if ev is None:
            ev = dev[0].wait_global_event(["CTRL-EVENT-REGDOM-CHANGE"],
                                          timeout=1)
        run_dpp_pkex_5ghz(dev, apdev)
    finally:
        dev[0].request("SET country 00")
        dev[1].request("SET country 00")
        subprocess.call(['iw', 'reg', 'set', '00'])

def run_dpp_pkex_5ghz(dev, apdev):
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id1 = int(res)

    cmd = "DPP_PKEX_ADD own=%d identifier=test code=secret" % (id0)
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (responder)")
    cmd = "DPP_LISTEN 5745"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")

    cmd = "DPP_PKEX_ADD own=%d identifier=test init=1 code=secret" % (id1)
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (initiator)")

    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS", "DPP-FAIL"], timeout=20)
    if ev is None or "DPP-AUTH-SUCCESS" not in ev:
        raise Exception("DPP authentication did not succeed (Initiator)")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")

def test_dpp_pkex_test_vector(dev, apdev):
    """DPP and PKEX (P-256) test vector"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    init_addr = "ac:64:91:f4:52:07"
    resp_addr = "6e:5e:ce:6e:f3:dd"

    identifier = "joes_key"
    code = "thisisreallysecret"

    # Initiator bootstrapping private key
    init_priv = "5941b51acfc702cdc1c347264beb2920db88eb1a0bf03a211868b1632233c269"

    # Responder bootstrapping private key
    resp_priv = "2ae8956293f49986b6d0b8169a86805d9232babb5f6813fdfe96f19d59536c60"

    # Initiator x/X keypair override
    init_x_priv = "8365c5ed93d751bef2d92b410dc6adfd95670889183fac1bd66759ad85c3187a"

    # Responder y/Y keypair override
    resp_y_priv = "d98faa24d7dd3f592665d71a95c862bfd02c4c48acb0c515a41cbc6e929675ea"

    p256_prefix = "30310201010420"
    p256_postfix = "a00a06082a8648ce3d030107"

    dev[0].set("dpp_pkex_own_mac_override", resp_addr)
    dev[0].set("dpp_pkex_peer_mac_override", init_addr)
    dev[1].set("dpp_pkex_own_mac_override", init_addr)
    dev[1].set("dpp_pkex_peer_mac_override", resp_addr)

    # Responder bootstrapping key
    cmd = "DPP_BOOTSTRAP_GEN type=pkex key=" + p256_prefix + resp_priv + p256_postfix
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)

    # Responder y/Y keypair override
    dev[0].set("dpp_pkex_ephemeral_key_override",
               p256_prefix + resp_y_priv + p256_postfix)

    # Initiator bootstrapping key
    cmd = "DPP_BOOTSTRAP_GEN type=pkex key=" + p256_prefix + init_priv + p256_postfix
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id1 = int(res)

    # Initiator x/X keypair override
    dev[1].set("dpp_pkex_ephemeral_key_override",
               p256_prefix + init_x_priv + p256_postfix)

    cmd = "DPP_PKEX_ADD own=%d identifier=%s code=%s" % (id0, identifier, code)
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (responder)")
    cmd = "DPP_LISTEN 2437"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")

    cmd = "DPP_PKEX_ADD own=%d identifier=%s init=1 code=%s" % (id1, identifier, code)
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (initiator)")

    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")

def test_dpp_pkex_code_mismatch(dev, apdev):
    """DPP and PKEX with mismatching code"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id1 = int(res)

    cmd = "DPP_PKEX_ADD own=%d identifier=test code=secret" % (id0)
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (responder)")
    cmd = "DPP_LISTEN 2437"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")

    cmd = "DPP_PKEX_ADD own=%d identifier=test init=1 code=unknown" % id1
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (initiator)")

    ev = dev[0].wait_event(["DPP-FAIL"], timeout=5)
    if ev is None:
        raise Exception("Failure not reported")
    if "possible PKEX code mismatch" not in ev:
        raise Exception("Unexpected result: " + ev)

    dev[0].dump_monitor()
    dev[1].dump_monitor()

    cmd = "DPP_PKEX_ADD own=%d identifier=test init=1 code=secret" % id1
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (initiator, retry)")

    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator, retry)")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder, retry)")

def test_dpp_pkex_code_mismatch_limit(dev, apdev):
    """DPP and PKEX with mismatching code limit"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id1 = int(res)

    cmd = "DPP_PKEX_ADD own=%d identifier=test code=secret" % (id0)
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (responder)")
    cmd = "DPP_LISTEN 2437"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")

    for i in range(5):
        dev[0].dump_monitor()
        dev[1].dump_monitor()
        cmd = "DPP_PKEX_ADD own=%d identifier=test init=1 code=unknown" % id1
        res = dev[1].request(cmd)
        if "FAIL" in res:
            raise Exception("Failed to set PKEX data (initiator)")

        ev = dev[0].wait_event(["DPP-FAIL"], timeout=5)
        if ev is None:
            raise Exception("Failure not reported")
        if "possible PKEX code mismatch" not in ev:
            raise Exception("Unexpected result: " + ev)

    ev = dev[0].wait_event(["DPP-PKEX-T-LIMIT"], timeout=1)
    if ev is None:
        raise Exception("PKEX t limit not reported")

def test_dpp_pkex_curve_mismatch(dev, apdev):
    """DPP and PKEX with mismatching curve"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    cmd = "DPP_BOOTSTRAP_GEN type=pkex curve=P-256"
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)

    cmd = "DPP_BOOTSTRAP_GEN type=pkex curve=P-384"
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id1 = int(res)

    cmd = "DPP_PKEX_ADD own=%d identifier=test code=secret" % (id0)
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (responder)")
    cmd = "DPP_LISTEN 2437"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")

    cmd = "DPP_PKEX_ADD own=%d identifier=test init=1 code=secret" % id1
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (initiator)")

    ev = dev[0].wait_event(["DPP-FAIL"], timeout=5)
    if ev is None:
        raise Exception("Failure not reported (dev 0)")
    if "Mismatching PKEX curve: peer=20 own=19" not in ev:
        raise Exception("Unexpected result: " + ev)

    ev = dev[1].wait_event(["DPP-FAIL"], timeout=5)
    if ev is None:
        raise Exception("Failure not reported (dev 1)")
    if "Peer indicated mismatching PKEX group - proposed 19" not in ev:
        raise Exception("Unexpected result: " + ev)

def test_dpp_pkex_config2(dev, apdev):
    """DPP and PKEX with responder as the configurator"""
    check_dpp_capab(dev[0])

    cmd = "DPP_CONFIGURATOR_ADD"
    res = dev[0].request(cmd);
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id = int(res)

    dev[0].set("dpp_configurator_params",
               " conf=sta-dpp configurator=%d" % conf_id);
    run_dpp_pkex2(dev, apdev)

def run_dpp_pkex2(dev, apdev, curve=None, init_extra=""):
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    if curve:
        cmd += " curve=" + curve
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    if curve:
        cmd += " curve=" + curve
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id1 = int(res)

    cmd = "DPP_PKEX_ADD own=%d identifier=test code=secret" % (id0)
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (responder)")
    cmd = "DPP_LISTEN 2437 role=configurator"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")

    cmd = "DPP_PKEX_ADD own=%d identifier=test init=1 role=enrollee %s code=secret" % (id1, init_extra)
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (initiator)")

    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")

    ev = dev[0].wait_event(["DPP-CONF-SENT"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator)")
    ev = dev[1].wait_event(["DPP-CONF-RECEIVED"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee)")

def test_dpp_pkex_no_responder(dev, apdev):
    """DPP and PKEX with no responder (retry behavior)"""
    check_dpp_capab(dev[0])

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)

    cmd = "DPP_PKEX_ADD own=%d init=1 identifier=test code=secret" % (id0)
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (initiator)")

    ev = dev[0].wait_event(["DPP-FAIL"], timeout=15)
    if ev is None:
        raise Exception("DPP PKEX failure not reported")
    if "No response from PKEX peer" not in ev:
        raise Exception("Unexpected failure reason: " + ev)

def test_dpp_pkex_after_retry(dev, apdev):
    """DPP and PKEX completing after retry"""
    check_dpp_capab(dev[0])

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)

    cmd = "DPP_PKEX_ADD own=%d init=1 identifier=test code=secret" % (id0)
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (initiator)")

    time.sleep(0.1)
    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id1 = int(res)

    cmd = "DPP_PKEX_ADD own=%d identifier=test code=secret" % (id1)
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (responder)")
    cmd = "DPP_LISTEN 2437"
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to start listen operation")

    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=10)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    ev = dev[0].wait_event(["DPP-CONF-SENT"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator)")
    # Ignore Enrollee result since configurator was not set here

def test_dpp_pkex_hostapd_responder(dev, apdev):
    """DPP PKEX with hostapd as responder"""
    check_dpp_capab(dev[0])
    hapd = hostapd.add_ap(apdev[0], { "ssid": "unconfigured",
                                      "channel": "6" })
    check_dpp_capab(hapd)

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    res = hapd.request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info (hostapd)")
    id_h = int(res)

    cmd = "DPP_PKEX_ADD own=%d identifier=test code=secret" % (id_h)
    res = hapd.request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (responder/hostapd)")

    cmd = "DPP_CONFIGURATOR_ADD"
    res = dev[0].request(cmd);
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id = int(res)

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info (wpa_supplicant)")
    id0 = int(res)

    cmd = "DPP_PKEX_ADD own=%d identifier=test init=1 conf=ap-dpp configurator=%d code=secret" % (id0, conf_id)
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (initiator/wpa_supplicant)")

    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    ev = hapd.wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = dev[0].wait_event(["DPP-CONF-SENT"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator)")
    ev = hapd.wait_event(["DPP-CONF-RECEIVED"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee)")
    dev[0].request("DPP_STOP_LISTEN")
    dev[0].dump_monitor()

def test_dpp_pkex_hostapd_initiator(dev, apdev):
    """DPP PKEX with hostapd as initiator"""
    check_dpp_capab(dev[0])
    hapd = hostapd.add_ap(apdev[0], { "ssid": "unconfigured",
                                      "channel": "6" })
    check_dpp_capab(hapd)

    cmd = "DPP_CONFIGURATOR_ADD"
    res = dev[0].request(cmd);
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id = int(res)

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info (wpa_supplicant)")
    id0 = int(res)

    dev[0].set("dpp_configurator_params",
               " conf=ap-dpp configurator=%d" % conf_id);

    cmd = "DPP_PKEX_ADD own=%d identifier=test code=secret" % (id0)
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (responder/wpa_supplicant)")

    cmd = "DPP_LISTEN 2437 role=configurator"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    res = hapd.request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info (hostapd)")
    id_h = int(res)

    cmd = "DPP_PKEX_ADD own=%d identifier=test init=1 role=enrollee code=secret" % (id_h)
    res = hapd.request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (initiator/hostapd)")

    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    ev = hapd.wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = dev[0].wait_event(["DPP-CONF-SENT"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator)")
    ev = hapd.wait_event(["DPP-CONF-RECEIVED"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee)")
    dev[0].request("DPP_STOP_LISTEN")
    dev[0].dump_monitor()

def test_dpp_hostapd_configurator(dev, apdev):
    """DPP with hostapd as configurator/initiator"""
    check_dpp_capab(dev[0])
    hapd = hostapd.add_ap(apdev[0], { "ssid": "unconfigured",
                                      "channel": "1" })
    check_dpp_capab(hapd)

    cmd = "DPP_CONFIGURATOR_ADD"
    res = hapd.request(cmd);
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id = int(res)

    addr = dev[0].own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    res = hapd.request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    res = hapd.request("DPP_BOOTSTRAP_INFO %d" % id0)
    if "FAIL" in res:
        raise Exception("DPP_BOOTSTRAP_INFO failed")
    if "type=QRCODE" not in res:
        raise Exception("DPP_BOOTSTRAP_INFO did not report correct type")
    if "mac_addr=" + dev[0].own_addr() not in res:
        raise Exception("DPP_BOOTSTRAP_INFO did not report correct mac_addr")

    cmd = "DPP_LISTEN 2412"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")
    cmd = "DPP_AUTH_INIT peer=%d configurator=%d conf=sta-dpp" % (id1, conf_id)
    if "OK" not in hapd.request(cmd):
        raise Exception("Failed to initiate DPP Authentication")

    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = hapd.wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    ev = hapd.wait_event(["DPP-CONF-SENT"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator)")
    ev = dev[0].wait_event(["DPP-CONF-RECEIVED"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee)")
    dev[0].request("DPP_STOP_LISTEN")
    dev[0].dump_monitor()

def test_dpp_hostapd_configurator_responder(dev, apdev):
    """DPP with hostapd as configurator/responder"""
    check_dpp_capab(dev[0])
    hapd = hostapd.add_ap(apdev[0], { "ssid": "unconfigured",
                                      "channel": "1" })
    check_dpp_capab(hapd)

    cmd = "DPP_CONFIGURATOR_ADD"
    res = hapd.request(cmd);
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id = int(res)

    hapd.set("dpp_configurator_params",
             " conf=sta-dpp configurator=%d" % conf_id);

    addr = hapd.own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr
    res = hapd.request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = hapd.request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    res = dev[0].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    cmd = "DPP_AUTH_INIT peer=%d role=enrollee" % (id1)
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to initiate DPP Authentication")

    ev = hapd.wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    ev = hapd.wait_event(["DPP-CONF-SENT"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator)")
    ev = dev[0].wait_event(["DPP-CONF-RECEIVED"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee)")
    dev[0].request("DPP_STOP_LISTEN")
    dev[0].dump_monitor()

def test_dpp_own_config(dev, apdev):
    """DPP configurator signing own connector"""
    try:
        run_dpp_own_config(dev, apdev)
    finally:
        dev[0].set("dpp_config_processing", "0")

def test_dpp_own_config_curve_mismatch(dev, apdev):
    """DPP configurator signing own connector using mismatching curve"""
    try:
        run_dpp_own_config(dev, apdev, own_curve="BP-384", expect_failure=True)
    finally:
        dev[0].set("dpp_config_processing", "0")

def run_dpp_own_config(dev, apdev, own_curve=None, expect_failure=False):
    check_dpp_capab(dev[0], own_curve and "BP" in own_curve)
    hapd = hostapd.add_ap(apdev[0], { "ssid": "unconfigured" })
    check_dpp_capab(hapd)

    addr = hapd.own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr
    res = hapd.request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id_h = int(res)
    uri = hapd.request("DPP_BOOTSTRAP_GET_URI %d" % id_h)

    cmd = "DPP_CONFIGURATOR_ADD"
    res = dev[0].request(cmd);
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id = int(res)

    res = dev[0].request("DPP_QR_CODE " + uri)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id = int(res)

    cmd = "DPP_AUTH_INIT peer=%d conf=ap-dpp configurator=%d" % (id, conf_id)
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to initiate DPP Authentication")
    ev = hapd.wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    ev = dev[0].wait_event(["DPP-CONF-SENT"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator)")
    ev = hapd.wait_event(["DPP-CONF-RECEIVED"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee)")

    update_hapd_config(hapd)

    dev[0].set("dpp_config_processing", "1")
    cmd = "DPP_CONFIGURATOR_SIGN  conf=sta-dpp configurator=%d" % (conf_id)
    if own_curve:
        cmd += " curve=" + own_curve
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate own configuration")

    ev = dev[0].wait_event(["DPP-NETWORK-ID"], timeout=1)
    if ev is None:
        raise Exception("DPP network profile not generated")
    id = ev.split(' ')[1]
    dev[0].select_network(id, freq="2412")
    if expect_failure:
        ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=1)
        if ev is not None:
            raise Exception("Unexpected connection");
        dev[0].request("DISCONNECT")
    else:
        dev[0].wait_connected()

def test_dpp_own_config_ap(dev, apdev):
    """DPP configurator (AP) signing own connector"""
    try:
        run_dpp_own_config_ap(dev, apdev)
    finally:
        dev[0].set("dpp_config_processing", "0")

def run_dpp_own_config_ap(dev, apdev):
    check_dpp_capab(dev[0])
    hapd = hostapd.add_ap(apdev[0], { "ssid": "unconfigured" })
    check_dpp_capab(hapd)

    cmd = "DPP_CONFIGURATOR_ADD"
    res = hapd.request(cmd);
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id = int(res)

    cmd = "DPP_CONFIGURATOR_SIGN  conf=ap-dpp configurator=%d" % (conf_id)
    res = hapd.request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate own configuration")
    update_hapd_config(hapd)

    addr = dev[0].own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id = int(res)
    uri = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id)

    res = hapd.request("DPP_QR_CODE " + uri)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id = int(res)

    dev[0].set("dpp_config_processing", "2")
    if "OK" not in dev[0].request("DPP_LISTEN 2412"):
        raise Exception("Failed to start listen operation")
    cmd = "DPP_AUTH_INIT peer=%d conf=sta-dpp configurator=%d" % (id, conf_id)
    if "OK" not in hapd.request(cmd):
        raise Exception("Failed to initiate DPP Authentication")
    ev = hapd.wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    ev = hapd.wait_event(["DPP-CONF-SENT"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator)")
    ev = dev[0].wait_event(["DPP-CONF-RECEIVED", "DPP-CONF-FAILED"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee)")
    if "DPP-CONF-RECEIVED" not in ev:
        raise Exception("DPP configuration failed (Enrollee)")

    dev[0].wait_connected()

def test_dpp_intro_mismatch(dev, apdev):
    """DPP network introduction mismatch cases"""
    try:
        wpas = None
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add("wlan5")
        check_dpp_capab(wpas)
        run_dpp_intro_mismatch(dev, apdev, wpas)
    finally:
        dev[0].set("dpp_config_processing", "0")
        dev[2].set("dpp_config_processing", "0")
        if wpas:
            wpas.set("dpp_config_processing", "0")

def run_dpp_intro_mismatch(dev, apdev, wpas):
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    check_dpp_capab(dev[2])

    logger.info("Start AP in unconfigured state")
    hapd = hostapd.add_ap(apdev[0], { "ssid": "unconfigured" })
    check_dpp_capab(hapd)

    addr = hapd.own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr
    res = hapd.request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id_h = int(res)
    uri = hapd.request("DPP_BOOTSTRAP_GET_URI %d" % id_h)

    logger.info("Provision AP with DPP configuration")
    res = dev[1].request("DPP_CONFIGURATOR_ADD");
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id = int(res)

    res = dev[1].request("DPP_QR_CODE " + uri)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id = int(res)

    dev[1].set("dpp_groups_override", '[{"groupId":"a","netRole":"ap"}]')
    cmd = "DPP_AUTH_INIT peer=%d conf=ap-dpp configurator=%d" % (id, conf_id)
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to initiate DPP Authentication")
    update_hapd_config(hapd)

    logger.info("Provision STA0 with DPP Connector that has mismatching groupId")
    dev[0].set("dpp_config_processing", "2")
    addr = dev[0].own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    cmd = "DPP_LISTEN 2412"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")

    dev[1].set("dpp_groups_override", '[{"groupId":"b","netRole":"sta"}]')
    cmd = "DPP_AUTH_INIT peer=%d conf=sta-dpp configurator=%d" % (id1, conf_id)
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to initiate DPP Authentication")
    ev = dev[1].wait_event(["DPP-CONF-SENT"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator for STA0)")
    ev = dev[0].wait_event(["DPP-CONF-RECEIVED"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee STA0)")

    logger.info("Provision STA2 with DPP Connector that has mismatching C-sign-key")
    dev[2].set("dpp_config_processing", "2")
    addr = dev[2].own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr
    res = dev[2].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id2 = int(res)
    uri2 = dev[2].request("DPP_BOOTSTRAP_GET_URI %d" % id2)

    res = dev[1].request("DPP_QR_CODE " + uri2)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    cmd = "DPP_LISTEN 2412"
    if "OK" not in dev[2].request(cmd):
        raise Exception("Failed to start listen operation")

    res = dev[1].request("DPP_CONFIGURATOR_ADD");
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id_2 = int(res)
    dev[1].set("dpp_groups_override", '')
    cmd = "DPP_AUTH_INIT peer=%d conf=sta-dpp configurator=%d" % (id1, conf_id_2)
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to initiate DPP Authentication")
    ev = dev[1].wait_event(["DPP-CONF-SENT"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator for STA2)")
    ev = dev[2].wait_event(["DPP-CONF-RECEIVED"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee STA2)")

    logger.info("Provision STA5 with DPP Connector that has mismatching netAccessKey EC group")
    wpas.set("dpp_config_processing", "2")
    addr = wpas.own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr
    cmd += " curve=P-521"
    res = wpas.request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id5 = int(res)
    uri5 = wpas.request("DPP_BOOTSTRAP_GET_URI %d" % id5)

    res = dev[1].request("DPP_QR_CODE " + uri5)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    cmd = "DPP_LISTEN 2412"
    if "OK" not in wpas.request(cmd):
        raise Exception("Failed to start listen operation")

    dev[1].set("dpp_groups_override", '')
    cmd = "DPP_AUTH_INIT peer=%d conf=sta-dpp configurator=%d" % (id1, conf_id)
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to initiate DPP Authentication")
    ev = dev[1].wait_event(["DPP-CONF-SENT"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Configurator for STA0)")
    ev = wpas.wait_event(["DPP-CONF-RECEIVED"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee STA5)")

    logger.info("Verify network introduction results")
    ev = dev[0].wait_event(["DPP-INTRO"], timeout=10)
    if ev is None:
        raise Exception("DPP network introduction result not seen on STA0")
    if "status=8" not in ev:
        raise Exception("Unexpected network introduction result on STA0: " + ev)

    ev = dev[2].wait_event(["DPP-INTRO"], timeout=5)
    if ev is None:
        raise Exception("DPP network introduction result not seen on STA2")
    if "status=8" not in ev:
        raise Exception("Unexpected network introduction result on STA2: " + ev)

    ev = wpas.wait_event(["DPP-INTRO"], timeout=10)
    if ev is None:
        raise Exception("DPP network introduction result not seen on STA5")
    if "status=7" not in ev:
        raise Exception("Unexpected network introduction result on STA5: " + ev)

def run_dpp_proto_init(dev, test_dev, test, mutual=False, unicast=True,
                       listen=True, chan="81/1", init_enrollee=False):
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    dev[test_dev].set("dpp_test", str(test))

    cmd = "DPP_CONFIGURATOR_ADD"
    if init_enrollee:
        res = dev[0].request(cmd)
    else:
        res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id = int(res)

    addr = dev[0].own_addr().replace(':', '')
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode"
    if chan:
        cmd += " chan=" + chan
    if unicast:
        cmd += " mac=" + addr
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    if mutual:
        addr = dev[1].own_addr().replace(':', '')
        res = dev[1].request("DPP_BOOTSTRAP_GEN type=qrcode chan=81/1 mac=" + addr)
        if "FAIL" in res:
            raise Exception("Failed to generate bootstrapping info")
        id1b = int(res)
        uri1b = dev[1].request("DPP_BOOTSTRAP_GET_URI %d" % id1b)

        res = dev[0].request("DPP_QR_CODE " + uri1b)
        if "FAIL" in res:
            raise Exception("Failed to parse QR Code URI")
        id0b = int(res)

        cmd = "DPP_LISTEN 2412 qr=mutual"
    else:
        cmd = "DPP_LISTEN 2412"

    if init_enrollee:
        cmd += " role=configurator"
        dev[0].set("dpp_configurator_params",
                   " conf=sta-dpp configurator=%d" % conf_id);

    if listen:
        if "OK" not in dev[0].request(cmd):
            raise Exception("Failed to start listen operation")

    if init_enrollee:
        cmd = "DPP_AUTH_INIT peer=%d role=enrollee" % (id1)
    else:
        cmd = "DPP_AUTH_INIT peer=%d configurator=%d conf=sta-dpp" % (id1, conf_id)
    if mutual:
        cmd += " own=%d" % id1b
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to initiate DPP Authentication")

def test_dpp_proto_after_wrapped_data_auth_req(dev, apdev):
    """DPP protocol testing - attribute after Wrapped Data in Auth Req"""
    run_dpp_proto_init(dev, 1, 1)
    ev = dev[0].wait_event(["DPP-RX"], timeout=5)
    if ev is None:
        raise Exception("DPP Authentication Request not seen")
    if "type=0" not in ev or "ignore=invalid-attributes" not in ev:
        raise Exception("Unexpected RX info: " + ev)
    ev = dev[1].wait_event(["DPP-RX"], timeout=0.1)
    if ev is not None:
        raise Exception("Unexpected DPP message seen")

def test_dpp_auth_req_stop_after_ack(dev, apdev):
    """DPP initiator stopping after ACK, but no response"""
    run_dpp_proto_init(dev, 1, 1, listen=True)
    ev = dev[1].wait_event(["DPP-AUTH-INIT-FAILED"], timeout=5)
    if ev is None:
        raise Exception("Authentication failure not reported")

def test_dpp_auth_req_retries(dev, apdev):
    """DPP initiator retries with no ACK"""
    check_dpp_capab(dev[1])
    dev[1].set("dpp_init_max_tries", "3")
    dev[1].set("dpp_init_retry_time", "1000")
    dev[1].set("dpp_resp_wait_time", "100")
    run_dpp_proto_init(dev, 1, 1, unicast=False, listen=False)

    for i in range(3):
        ev = dev[1].wait_event(["DPP-TX "], timeout=5)
        if ev is None:
            raise Exception("Auth Req not sent (%d)" % i)

    ev = dev[1].wait_event(["DPP-AUTH-INIT-FAILED"], timeout=5)
    if ev is None:
        raise Exception("Authentication failure not reported")

def test_dpp_auth_req_retries_multi_chan(dev, apdev):
    """DPP initiator retries with no ACK and multiple channels"""
    check_dpp_capab(dev[1])
    dev[1].set("dpp_init_max_tries", "3")
    dev[1].set("dpp_init_retry_time", "1000")
    dev[1].set("dpp_resp_wait_time", "100")
    run_dpp_proto_init(dev, 1, 1, unicast=False, listen=False,
                       chan="81/1,81/6,81/11")

    for i in range(3 * 3):
        ev = dev[1].wait_event(["DPP-TX "], timeout=5)
        if ev is None:
            raise Exception("Auth Req not sent (%d)" % i)

    ev = dev[1].wait_event(["DPP-AUTH-INIT-FAILED"], timeout=5)
    if ev is None:
        raise Exception("Authentication failure not reported")

def test_dpp_proto_after_wrapped_data_auth_resp(dev, apdev):
    """DPP protocol testing - attribute after Wrapped Data in Auth Resp"""
    run_dpp_proto_init(dev, 0, 2)
    ev = dev[1].wait_event(["DPP-RX"], timeout=5)
    if ev is None:
        raise Exception("DPP Authentication Response not seen")
    if "type=1" not in ev or "ignore=invalid-attributes" not in ev:
        raise Exception("Unexpected RX info: " + ev)
    ev = dev[0].wait_event(["DPP-RX"], timeout=1)
    if ev is None or "type=0" not in ev:
        raise Exception("DPP Authentication Request not seen")
    ev = dev[0].wait_event(["DPP-RX"], timeout=0.1)
    if ev is not None:
        raise Exception("Unexpected DPP message seen")

def test_dpp_proto_after_wrapped_data_auth_conf(dev, apdev):
    """DPP protocol testing - attribute after Wrapped Data in Auth Conf"""
    run_dpp_proto_init(dev, 1, 3)
    ev = dev[0].wait_event(["DPP-RX"], timeout=5)
    if ev is None or "type=0" not in ev:
        raise Exception("DPP Authentication Request not seen")
    ev = dev[0].wait_event(["DPP-RX"], timeout=5)
    if ev is None:
        raise Exception("DPP Authentication Confirm not seen")
    if "type=2" not in ev or "ignore=invalid-attributes" not in ev:
        raise Exception("Unexpected RX info: " + ev)

def test_dpp_proto_after_wrapped_data_conf_req(dev, apdev):
    """DPP protocol testing - attribute after Wrapped Data in Conf Req"""
    run_dpp_proto_init(dev, 0, 6)
    ev = dev[1].wait_event(["DPP-CONF-FAILED"], timeout=10)
    if ev is None:
        raise Exception("DPP Configuration failure not seen")

def test_dpp_proto_after_wrapped_data_conf_resp(dev, apdev):
    """DPP protocol testing - attribute after Wrapped Data in Conf Resp"""
    run_dpp_proto_init(dev, 1, 7)
    ev = dev[0].wait_event(["DPP-CONF-FAILED"], timeout=10)
    if ev is None:
        raise Exception("DPP Configuration failure not seen")

def test_dpp_proto_zero_i_capab(dev, apdev):
    """DPP protocol testing - zero I-capability in Auth Req"""
    run_dpp_proto_init(dev, 1, 8)
    ev = dev[0].wait_event(["DPP-FAIL"], timeout=5)
    if ev is None:
        raise Exception("DPP failure not seen")
    if "Invalid role in I-capabilities 0x00" not in ev:
        raise Exception("Unexpected failure: " + ev)
    ev = dev[1].wait_event(["DPP-RX"], timeout=0.1)
    if ev is not None:
        raise Exception("Unexpected DPP message seen")

def test_dpp_proto_zero_r_capab(dev, apdev):
    """DPP protocol testing - zero R-capability in Auth Resp"""
    run_dpp_proto_init(dev, 0, 9)
    ev = dev[1].wait_event(["DPP-FAIL"], timeout=5)
    if ev is None:
        raise Exception("DPP failure not seen")
    if "Unexpected role in R-capabilities 0x00" not in ev:
        raise Exception("Unexpected failure: " + ev)
    ev = dev[0].wait_event(["DPP-RX"], timeout=1)
    if ev is None or "type=0" not in ev:
        raise Exception("DPP Authentication Request not seen")
    ev = dev[0].wait_event(["DPP-RX"], timeout=0.1)
    if ev is not None:
        raise Exception("Unexpected DPP message seen")

def run_dpp_proto_auth_req_missing(dev, test, reason, mutual=False):
    run_dpp_proto_init(dev, 1, test, mutual=mutual)
    ev = dev[0].wait_event(["DPP-FAIL"], timeout=5)
    if ev is None:
        raise Exception("DPP failure not seen")
    if reason not in ev:
        raise Exception("Unexpected failure: " + ev)
    ev = dev[1].wait_event(["DPP-RX"], timeout=0.1)
    if ev is not None:
        raise Exception("Unexpected DPP message seen")

def test_dpp_proto_auth_req_no_r_bootstrap_key(dev, apdev):
    """DPP protocol testing - no R-bootstrap key in Auth Req"""
    run_dpp_proto_auth_req_missing(dev, 10, "Missing or invalid required Responder Bootstrapping Key Hash attribute")

def test_dpp_proto_auth_req_invalid_r_bootstrap_key(dev, apdev):
    """DPP protocol testing - invalid R-bootstrap key in Auth Req"""
    run_dpp_proto_auth_req_missing(dev, 68, "No matching own bootstrapping key found - ignore message")

def test_dpp_proto_auth_req_no_i_bootstrap_key(dev, apdev):
    """DPP protocol testing - no I-bootstrap key in Auth Req"""
    run_dpp_proto_auth_req_missing(dev, 11, "Missing or invalid required Initiator Bootstrapping Key Hash attribute")

def test_dpp_proto_auth_req_invalid_i_bootstrap_key(dev, apdev):
    """DPP protocol testing - invalid I-bootstrap key in Auth Req"""
    run_dpp_proto_init(dev, 1, 69, mutual=True)
    ev = dev[0].wait_event(["DPP-SCAN-PEER-QR-CODE"], timeout=5)
    if ev is None:
        raise Exception("DPP scan request not seen")
    ev = dev[1].wait_event(["DPP-RESPONSE-PENDING"], timeout=5)
    if ev is None:
        raise Exception("DPP response pending indivation not seen")

def test_dpp_proto_auth_req_no_i_proto_key(dev, apdev):
    """DPP protocol testing - no I-proto key in Auth Req"""
    run_dpp_proto_auth_req_missing(dev, 12, "Missing required Initiator Protocol Key attribute")

def test_dpp_proto_auth_req_invalid_i_proto_key(dev, apdev):
    """DPP protocol testing - invalid I-proto key in Auth Req"""
    run_dpp_proto_auth_req_missing(dev, 66, "Invalid Initiator Protocol Key")

def test_dpp_proto_auth_req_no_i_nonce(dev, apdev):
    """DPP protocol testing - no I-nonce in Auth Req"""
    run_dpp_proto_auth_req_missing(dev, 13, "Missing or invalid I-nonce")

def test_dpp_proto_auth_req_invalid_i_nonce(dev, apdev):
    """DPP protocol testing - invalid I-nonce in Auth Req"""
    run_dpp_proto_auth_req_missing(dev, 81, "Missing or invalid I-nonce")

def test_dpp_proto_auth_req_no_i_capab(dev, apdev):
    """DPP protocol testing - no I-capab in Auth Req"""
    run_dpp_proto_auth_req_missing(dev, 14, "Missing or invalid I-capab")

def test_dpp_proto_auth_req_no_wrapped_data(dev, apdev):
    """DPP protocol testing - no Wrapped Data in Auth Req"""
    run_dpp_proto_auth_req_missing(dev, 15, "Missing or invalid required Wrapped Data attribute")

def run_dpp_proto_auth_resp_missing(dev, test, reason):
    run_dpp_proto_init(dev, 0, test, mutual=True)
    if reason is None:
        time.sleep(0.1)
        return
    ev = dev[1].wait_event(["DPP-FAIL"], timeout=5)
    if ev is None:
        raise Exception("DPP failure not seen")
    if reason not in ev:
        raise Exception("Unexpected failure: " + ev)
    ev = dev[0].wait_event(["DPP-RX"], timeout=1)
    if ev is None or "type=0" not in ev:
        raise Exception("DPP Authentication Request not seen")
    ev = dev[0].wait_event(["DPP-RX"], timeout=0.1)
    if ev is not None:
        raise Exception("Unexpected DPP message seen")

def test_dpp_proto_auth_resp_no_status(dev, apdev):
    """DPP protocol testing - no Status in Auth Resp"""
    run_dpp_proto_auth_resp_missing(dev, 16, "Missing or invalid required DPP Status attribute")

def test_dpp_proto_auth_resp_invalid_status(dev, apdev):
    """DPP protocol testing - invalid Status in Auth Resp"""
    run_dpp_proto_auth_resp_missing(dev, 74, "Responder reported failure")

def test_dpp_proto_auth_resp_no_r_bootstrap_key(dev, apdev):
    """DPP protocol testing - no R-bootstrap key in Auth Resp"""
    run_dpp_proto_auth_resp_missing(dev, 17, "Missing or invalid required Responder Bootstrapping Key Hash attribute")

def test_dpp_proto_auth_resp_invalid_r_bootstrap_key(dev, apdev):
    """DPP protocol testing - invalid R-bootstrap key in Auth Resp"""
    run_dpp_proto_auth_resp_missing(dev, 70, "Unexpected Responder Bootstrapping Key Hash value")

def test_dpp_proto_auth_resp_no_i_bootstrap_key(dev, apdev):
    """DPP protocol testing - no I-bootstrap key in Auth Resp"""
    run_dpp_proto_auth_resp_missing(dev, 18, None)

def test_dpp_proto_auth_resp_invalid_i_bootstrap_key(dev, apdev):
    """DPP protocol testing - invalid I-bootstrap key in Auth Resp"""
    run_dpp_proto_auth_resp_missing(dev, 71, "Initiator Bootstrapping Key Hash attribute did not match")

def test_dpp_proto_auth_resp_no_r_proto_key(dev, apdev):
    """DPP protocol testing - no R-Proto Key in Auth Resp"""
    run_dpp_proto_auth_resp_missing(dev, 19, "Missing required Responder Protocol Key attribute")

def test_dpp_proto_auth_resp_invalid_r_proto_key(dev, apdev):
    """DPP protocol testing - invalid R-Proto Key in Auth Resp"""
    run_dpp_proto_auth_resp_missing(dev, 67, "Invalid Responder Protocol Key")

def test_dpp_proto_auth_resp_no_r_nonce(dev, apdev):
    """DPP protocol testing - no R-nonce in Auth Resp"""
    run_dpp_proto_auth_resp_missing(dev, 20, "Missing or invalid R-nonce")

def test_dpp_proto_auth_resp_no_i_nonce(dev, apdev):
    """DPP protocol testing - no I-nonce in Auth Resp"""
    run_dpp_proto_auth_resp_missing(dev, 21, "Missing or invalid I-nonce")

def test_dpp_proto_auth_resp_no_r_capab(dev, apdev):
    """DPP protocol testing - no R-capab in Auth Resp"""
    run_dpp_proto_auth_resp_missing(dev, 22, "Missing or invalid R-capabilities")

def test_dpp_proto_auth_resp_no_r_auth(dev, apdev):
    """DPP protocol testing - no R-auth in Auth Resp"""
    run_dpp_proto_auth_resp_missing(dev, 23, "Missing or invalid Secondary Wrapped Data")

def test_dpp_proto_auth_resp_no_wrapped_data(dev, apdev):
    """DPP protocol testing - no Wrapped Data in Auth Resp"""
    run_dpp_proto_auth_resp_missing(dev, 24, "Missing or invalid required Wrapped Data attribute")

def test_dpp_proto_auth_resp_i_nonce_mismatch(dev, apdev):
    """DPP protocol testing - I-nonce mismatch in Auth Resp"""
    run_dpp_proto_init(dev, 0, 30, mutual=True)
    ev = dev[1].wait_event(["DPP-FAIL"], timeout=5)
    if ev is None:
        raise Exception("DPP failure not seen")
    if "I-nonce mismatch" not in ev:
        raise Exception("Unexpected failure: " + ev)
    ev = dev[0].wait_event(["DPP-RX"], timeout=1)
    if ev is None or "type=0" not in ev:
        raise Exception("DPP Authentication Request not seen")
    ev = dev[0].wait_event(["DPP-RX"], timeout=0.1)
    if ev is not None:
        raise Exception("Unexpected DPP message seen")

def test_dpp_proto_auth_resp_incompatible_r_capab(dev, apdev):
    """DPP protocol testing - Incompatible R-capab in Auth Resp"""
    run_dpp_proto_init(dev, 0, 31, mutual=True)
    ev = dev[1].wait_event(["DPP-FAIL"], timeout=5)
    if ev is None:
        raise Exception("DPP failure not seen")
    if "Unexpected role in R-capabilities 0x02" not in ev:
        raise Exception("Unexpected failure: " + ev)
    ev = dev[0].wait_event(["DPP-FAIL"], timeout=5)
    if ev is None:
        raise Exception("DPP failure not seen")
    if "Peer reported incompatible R-capab role" not in ev:
        raise Exception("Unexpected failure: " + ev)

def test_dpp_proto_auth_resp_r_auth_mismatch(dev, apdev):
    """DPP protocol testing - R-auth mismatch in Auth Resp"""
    run_dpp_proto_init(dev, 0, 32, mutual=True)
    ev = dev[1].wait_event(["DPP-FAIL"], timeout=5)
    if ev is None:
        raise Exception("DPP failure not seen")
    if "Mismatching Responder Authenticating Tag" not in ev:
        raise Exception("Unexpected failure: " + ev)
    ev = dev[0].wait_event(["DPP-FAIL"], timeout=5)
    if ev is None:
        raise Exception("DPP failure not seen")
    if "Peer reported authentication failure" not in ev:
        raise Exception("Unexpected failure: " + ev)

def run_dpp_proto_auth_conf_missing(dev, test, reason):
    run_dpp_proto_init(dev, 1, test, mutual=True)
    if reason is None:
        time.sleep(0.1)
        return
    ev = dev[0].wait_event(["DPP-FAIL"], timeout=5)
    if ev is None:
        raise Exception("DPP failure not seen")
    if reason not in ev:
        raise Exception("Unexpected failure: " + ev)

def test_dpp_proto_auth_conf_no_status(dev, apdev):
    """DPP protocol testing - no Status in Auth Conf"""
    run_dpp_proto_auth_conf_missing(dev, 25, "Missing or invalid required DPP Status attribute")

def test_dpp_proto_auth_conf_invalid_status(dev, apdev):
    """DPP protocol testing - invalid Status in Auth Conf"""
    run_dpp_proto_auth_conf_missing(dev, 75, "Authentication failed")

def test_dpp_proto_auth_conf_no_r_bootstrap_key(dev, apdev):
    """DPP protocol testing - no R-bootstrap key in Auth Conf"""
    run_dpp_proto_auth_conf_missing(dev, 26, "Missing or invalid required Responder Bootstrapping Key Hash attribute")

def test_dpp_proto_auth_conf_invalid_r_bootstrap_key(dev, apdev):
    """DPP protocol testing - invalid R-bootstrap key in Auth Conf"""
    run_dpp_proto_auth_conf_missing(dev, 72, "Responder Bootstrapping Key Hash mismatch")

def test_dpp_proto_auth_conf_no_i_bootstrap_key(dev, apdev):
    """DPP protocol testing - no I-bootstrap key in Auth Conf"""
    run_dpp_proto_auth_conf_missing(dev, 27, "Missing Initiator Bootstrapping Key Hash attribute")

def test_dpp_proto_auth_conf_invalid_i_bootstrap_key(dev, apdev):
    """DPP protocol testing - invalid I-bootstrap key in Auth Conf"""
    run_dpp_proto_auth_conf_missing(dev, 73, "Initiator Bootstrapping Key Hash mismatch")

def test_dpp_proto_auth_conf_no_i_auth(dev, apdev):
    """DPP protocol testing - no I-Auth in Auth Conf"""
    run_dpp_proto_auth_conf_missing(dev, 28, "Missing or invalid Initiator Authenticating Tag")

def test_dpp_proto_auth_conf_no_wrapped_data(dev, apdev):
    """DPP protocol testing - no Wrapped Data in Auth Conf"""
    run_dpp_proto_auth_conf_missing(dev, 29, "Missing or invalid required Wrapped Data attribute")

def test_dpp_proto_auth_conf_i_auth_mismatch(dev, apdev):
    """DPP protocol testing - I-auth mismatch in Auth Conf"""
    run_dpp_proto_init(dev, 1, 33, mutual=True)
    ev = dev[0].wait_event(["DPP-FAIL"], timeout=5)
    if ev is None:
        raise Exception("DPP failure not seen")
    if "Mismatching Initiator Authenticating Tag" not in ev:
        raise Excception("Unexpected failure: " + ev)

def test_dpp_proto_auth_conf_replaced_by_resp(dev, apdev):
    """DPP protocol testing - Auth Conf replaced by Resp"""
    run_dpp_proto_init(dev, 1, 65, mutual=True)
    ev = dev[0].wait_event(["DPP-FAIL"], timeout=5)
    if ev is None:
        raise Exception("DPP failure not seen")
    if "Unexpected Authentication Response" not in ev:
        raise Excception("Unexpected failure: " + ev)

def run_dpp_proto_conf_req_missing(dev, test, reason):
    run_dpp_proto_init(dev, 0, test)
    ev = dev[1].wait_event(["DPP-FAIL"], timeout=5)
    if ev is None:
        raise Exception("DPP failure not seen")
    if reason not in ev:
        raise Exception("Unexpected failure: " + ev)

def test_dpp_proto_conf_req_no_e_nonce(dev, apdev):
    """DPP protocol testing - no E-nonce in Conf Req"""
    run_dpp_proto_conf_req_missing(dev, 51,
                                   "Missing or invalid Enrollee Nonce attribute")

def test_dpp_proto_conf_req_invalid_e_nonce(dev, apdev):
    """DPP protocol testing - invalid E-nonce in Conf Req"""
    run_dpp_proto_conf_req_missing(dev, 83,
                                   "Missing or invalid Enrollee Nonce attribute")

def test_dpp_proto_conf_req_no_config_attr_obj(dev, apdev):
    """DPP protocol testing - no Config Attr Obj in Conf Req"""
    run_dpp_proto_conf_req_missing(dev, 52,
                                   "Missing or invalid Config Attributes attribute")

def test_dpp_proto_conf_req_invalid_config_attr_obj(dev, apdev):
    """DPP protocol testing - invalid Config Attr Obj in Conf Req"""
    run_dpp_proto_conf_req_missing(dev, 76,
                                   "Unsupported wi-fi_tech")

def test_dpp_proto_conf_req_no_wrapped_data(dev, apdev):
    """DPP protocol testing - no Wrapped Data in Conf Req"""
    run_dpp_proto_conf_req_missing(dev, 53,
                                   "Missing or invalid required Wrapped Data attribute")

def run_dpp_proto_conf_resp_missing(dev, test, reason):
    run_dpp_proto_init(dev, 1, test)
    ev = dev[0].wait_event(["DPP-FAIL"], timeout=5)
    if ev is None:
        raise Exception("DPP failure not seen")
    if reason not in ev:
        raise Exception("Unexpected failure: " + ev)

def test_dpp_proto_conf_resp_no_e_nonce(dev, apdev):
    """DPP protocol testing - no E-nonce in Conf Resp"""
    run_dpp_proto_conf_resp_missing(dev, 54,
                                    "Missing or invalid Enrollee Nonce attribute")

def test_dpp_proto_conf_resp_no_config_obj(dev, apdev):
    """DPP protocol testing - no Config Object in Conf Resp"""
    run_dpp_proto_conf_resp_missing(dev, 55,
                                    "Missing required Configuration Object attribute")

def test_dpp_proto_conf_resp_no_status(dev, apdev):
    """DPP protocol testing - no Status in Conf Resp"""
    run_dpp_proto_conf_resp_missing(dev, 56,
                                    "Missing or invalid required DPP Status attribute")

def test_dpp_proto_conf_resp_no_wrapped_data(dev, apdev):
    """DPP protocol testing - no Wrapped Data in Conf Resp"""
    run_dpp_proto_conf_resp_missing(dev, 57,
                                    "Missing or invalid required Wrapped Data attribute")

def test_dpp_proto_conf_resp_invalid_status(dev, apdev):
    """DPP protocol testing - invalid Status in Conf Resp"""
    run_dpp_proto_conf_resp_missing(dev, 58,
                                    "Configurator rejected configuration")

def test_dpp_proto_conf_resp_e_nonce_mismatch(dev, apdev):
    """DPP protocol testing - E-nonce mismatch in Conf Resp"""
    run_dpp_proto_conf_resp_missing(dev, 59,
                                    "Enrollee Nonce mismatch")

def test_dpp_proto_stop_at_auth_req(dev, apdev):
    """DPP protocol testing - stop when receiving Auth Req"""
    run_dpp_proto_init(dev, 0, 87)
    ev = dev[1].wait_event(["DPP-AUTH-INIT-FAILED"], timeout=5)
    if ev is None:
        raise Exception("Authentication init failure not reported")

def test_dpp_proto_stop_at_auth_resp(dev, apdev):
    """DPP protocol testing - stop when receiving Auth Resp"""
    run_dpp_proto_init(dev, 1, 88)

    ev = dev[1].wait_event(["DPP-TX "], timeout=5)
    if ev is None:
        raise Exception("Auth Req TX not seen")

    ev = dev[0].wait_event(["DPP-TX "], timeout=5)
    if ev is None:
        raise Exception("Auth Resp TX not seen")

    ev = dev[1].wait_event(["DPP-TX "], timeout=0.1)
    if ev is not None:
        raise Exception("Unexpected Auth Conf TX")

def test_dpp_proto_stop_at_auth_conf(dev, apdev):
    """DPP protocol testing - stop when receiving Auth Conf"""
    run_dpp_proto_init(dev, 0, 89, init_enrollee=True)
    ev = dev[1].wait_event(["GAS-QUERY-START"], timeout=10)
    if ev is None:
        raise Exception("Enrollee did not start GAS")
    ev = dev[1].wait_event(["GAS-QUERY-DONE"], timeout=10)
    if ev is None:
        raise Exception("Enrollee did not time out GAS")
    if "result=TIMEOUT" not in ev:
        raise Exception("Unexpected GAS result: " + ev)

def test_dpp_proto_stop_at_conf_req(dev, apdev):
    """DPP protocol testing - stop when receiving Auth Req"""
    run_dpp_proto_init(dev, 1, 90)
    ev = dev[0].wait_event(["GAS-QUERY-START"], timeout=10)
    if ev is None:
        raise Exception("Enrollee did not start GAS")
    ev = dev[0].wait_event(["GAS-QUERY-DONE"], timeout=10)
    if ev is None:
        raise Exception("Enrollee did not time out GAS")
    if "result=TIMEOUT" not in ev:
        raise Exception("Unexpected GAS result: " + ev)

def run_dpp_proto_init_pkex(dev, test_dev, test):
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    dev[test_dev].set("dpp_test", str(test))

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id1 = int(res)

    cmd = "DPP_PKEX_ADD own=%d identifier=test code=secret" % (id0)
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (responder)")
    cmd = "DPP_LISTEN 2437"
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")

    cmd = "DPP_PKEX_ADD own=%d identifier=test init=1 code=secret" % id1
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to set PKEX data (initiator)")

def test_dpp_proto_after_wrapped_data_pkex_cr_req(dev, apdev):
    """DPP protocol testing - attribute after Wrapped Data in PKEX CR Req"""
    run_dpp_proto_init_pkex(dev, 1, 4)
    ev = dev[0].wait_event(["DPP-RX"], timeout=5)
    if ev is None or "type=7" not in ev:
        raise Exception("PKEX Exchange Request not seen")
    ev = dev[0].wait_event(["DPP-RX"], timeout=5)
    if ev is None or "type=9" not in ev:
        raise Exception("PKEX Commit-Reveal Request not seen")
    if "ignore=invalid-attributes" not in ev:
        raise Exception("Unexpected RX info: " + ev)

def test_dpp_proto_after_wrapped_data_pkex_cr_resp(dev, apdev):
    """DPP protocol testing - attribute after Wrapped Data in PKEX CR Resp"""
    run_dpp_proto_init_pkex(dev, 0, 5)
    ev = dev[1].wait_event(["DPP-RX"], timeout=5)
    if ev is None or "type=8" not in ev:
        raise Exception("PKEX Exchange Response not seen")
    ev = dev[1].wait_event(["DPP-RX"], timeout=5)
    if ev is None or "type=10" not in ev:
        raise Exception("PKEX Commit-Reveal Response not seen")
    if "ignore=invalid-attributes" not in ev:
        raise Exception("Unexpected RX info: " + ev)

def run_dpp_proto_pkex_req_missing(dev, test, reason):
    run_dpp_proto_init_pkex(dev, 1, test)
    ev = dev[0].wait_event(["DPP-FAIL"], timeout=5)
    if ev is None:
        raise Exception("DPP failure not seen")
    if reason not in ev:
        raise Exception("Unexpected failure: " + ev)

def run_dpp_proto_pkex_resp_missing(dev, test, reason):
    run_dpp_proto_init_pkex(dev, 0, test)
    ev = dev[1].wait_event(["DPP-FAIL"], timeout=5)
    if ev is None:
        raise Exception("DPP failure not seen")
    if reason not in ev:
        raise Exception("Unexpected failure: " + ev)

def test_dpp_proto_pkex_exchange_req_no_finite_cyclic_group(dev, apdev):
    """DPP protocol testing - no Finite Cyclic Group in PKEX Exchange Request"""
    run_dpp_proto_pkex_req_missing(dev, 34,
                                   "Missing or invalid Finite Cyclic Group attribute")

def test_dpp_proto_pkex_exchange_req_no_encrypted_key(dev, apdev):
    """DPP protocol testing - no Encrypted Key in PKEX Exchange Request"""
    run_dpp_proto_pkex_req_missing(dev, 35,
                                   "Missing Encrypted Key attribute")

def test_dpp_proto_pkex_exchange_resp_no_status(dev, apdev):
    """DPP protocol testing - no Status in PKEX Exchange Response"""
    run_dpp_proto_pkex_resp_missing(dev, 36, "No DPP Status attribute")

def test_dpp_proto_pkex_exchange_resp_no_encrypted_key(dev, apdev):
    """DPP protocol testing - no Encrypted Key in PKEX Exchange Response"""
    run_dpp_proto_pkex_resp_missing(dev, 37, "Missing Encrypted Key attribute")

def test_dpp_proto_pkex_cr_req_no_bootstrap_key(dev, apdev):
    """DPP protocol testing - no Bootstrap Key in PKEX Commit-Reveal Request"""
    run_dpp_proto_pkex_req_missing(dev, 38,
                                   "No valid peer bootstrapping key found")

def test_dpp_proto_pkex_cr_req_no_i_auth_tag(dev, apdev):
    """DPP protocol testing - no I-Auth Tag in PKEX Commit-Reveal Request"""
    run_dpp_proto_pkex_req_missing(dev, 39, "No valid u (I-Auth tag) found")

def test_dpp_proto_pkex_cr_req_no_wrapped_data(dev, apdev):
    """DPP protocol testing - no Wrapped Data in PKEX Commit-Reveal Request"""
    run_dpp_proto_pkex_req_missing(dev, 40, "Missing or invalid required Wrapped Data attribute")

def test_dpp_proto_pkex_cr_resp_no_bootstrap_key(dev, apdev):
    """DPP protocol testing - no Bootstrap Key in PKEX Commit-Reveal Response"""
    run_dpp_proto_pkex_resp_missing(dev, 41,
                                   "No valid peer bootstrapping key found")

def test_dpp_proto_pkex_cr_resp_no_r_auth_tag(dev, apdev):
    """DPP protocol testing - no R-Auth Tag in PKEX Commit-Reveal Response"""
    run_dpp_proto_pkex_resp_missing(dev, 42, "No valid v (R-Auth tag) found")

def test_dpp_proto_pkex_cr_resp_no_wrapped_data(dev, apdev):
    """DPP protocol testing - no Wrapped Data in PKEX Commit-Reveal Response"""
    run_dpp_proto_pkex_resp_missing(dev, 43, "Missing or invalid required Wrapped Data attribute")

def test_dpp_proto_pkex_exchange_req_invalid_encrypted_key(dev, apdev):
    """DPP protocol testing - invalid Encrypted Key in PKEX Exchange Request"""
    run_dpp_proto_pkex_req_missing(dev, 44,
                                   "Invalid Encrypted Key value")

def test_dpp_proto_pkex_exchange_resp_invalid_encrypted_key(dev, apdev):
    """DPP protocol testing - invalid Encrypted Key in PKEX Exchange Response"""
    run_dpp_proto_pkex_resp_missing(dev, 45,
                                    "Invalid Encrypted Key value")

def test_dpp_proto_pkex_exchange_resp_invalid_status(dev, apdev):
    """DPP protocol testing - invalid Status in PKEX Exchange Response"""
    run_dpp_proto_pkex_resp_missing(dev, 46,
                                    "PKEX failed (peer indicated failure)")

def test_dpp_proto_pkex_cr_req_invalid_bootstrap_key(dev, apdev):
    """DPP protocol testing - invalid Bootstrap Key in PKEX Commit-Reveal Request"""
    run_dpp_proto_pkex_req_missing(dev, 47,
                                   "Peer bootstrapping key is invalid")

def test_dpp_proto_pkex_cr_resp_invalid_bootstrap_key(dev, apdev):
    """DPP protocol testing - invalid Bootstrap Key in PKEX Commit-Reveal Response"""
    run_dpp_proto_pkex_resp_missing(dev, 48,
                                    "Peer bootstrapping key is invalid")

def test_dpp_proto_pkex_cr_req_i_auth_tag_mismatch(dev, apdev):
    """DPP protocol testing - I-auth tag mismatch in PKEX Commit-Reveal Request"""
    run_dpp_proto_pkex_req_missing(dev, 49, "No valid u (I-Auth tag) found")

def test_dpp_proto_pkex_cr_resp_r_auth_tag_mismatch(dev, apdev):
    """DPP protocol testing - R-auth tag mismatch in PKEX Commit-Reveal Response"""
    run_dpp_proto_pkex_resp_missing(dev, 50, "No valid v (R-Auth tag) found")

def test_dpp_proto_stop_at_pkex_exchange_resp(dev, apdev):
    """DPP protocol testing - stop when receiving PKEX Exchange Response"""
    run_dpp_proto_init_pkex(dev, 1, 84)

    ev = dev[1].wait_event(["DPP-TX "], timeout=5)
    if ev is None:
        raise Exception("PKEX Exchange Req TX not seen")

    ev = dev[0].wait_event(["DPP-TX "], timeout=5)
    if ev is None:
        raise Exception("PKEX Exchange Resp not seen")

    ev = dev[1].wait_event(["DPP-TX "], timeout=0.1)
    if ev is not None:
        raise Exception("Unexpected PKEX CR Req TX")

def test_dpp_proto_stop_at_pkex_cr_req(dev, apdev):
    """DPP protocol testing - stop when receiving PKEX CR Request"""
    run_dpp_proto_init_pkex(dev, 0, 85)

    ev = dev[1].wait_event(["DPP-TX "], timeout=5)
    if ev is None:
        raise Exception("PKEX Exchange Req TX not seen")

    ev = dev[0].wait_event(["DPP-TX "], timeout=5)
    if ev is None:
        raise Exception("PKEX Exchange Resp not seen")

    ev = dev[1].wait_event(["DPP-TX "], timeout=5)
    if ev is None:
        raise Exception("PKEX CR Req TX not seen")

    ev = dev[0].wait_event(["DPP-TX "], timeout=0.1)
    if ev is not None:
        raise Exception("Unexpected PKEX CR Resp TX")

def test_dpp_proto_stop_at_pkex_cr_resp(dev, apdev):
    """DPP protocol testing - stop when receiving PKEX CR Response"""
    run_dpp_proto_init_pkex(dev, 1, 86)

    ev = dev[1].wait_event(["DPP-TX "], timeout=5)
    if ev is None:
        raise Exception("PKEX Exchange Req TX not seen")

    ev = dev[0].wait_event(["DPP-TX "], timeout=5)
    if ev is None:
        raise Exception("PKEX Exchange Resp not seen")

    ev = dev[1].wait_event(["DPP-TX "], timeout=5)
    if ev is None:
        raise Exception("PKEX CR Req TX not seen")

    ev = dev[0].wait_event(["DPP-TX "], timeout=5)
    if ev is None:
        raise Exception("PKEX CR Resp TX not seen")

    ev = dev[1].wait_event(["DPP-TX "], timeout=0.1)
    if ev is not None:
        raise Exception("Unexpected Auth Req TX")

def test_dpp_proto_network_introduction(dev, apdev):
    """DPP protocol testing - network introduction"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    csign = "3059301306072a8648ce3d020106082a8648ce3d03010703420004d02e5bd81a120762b5f0f2994777f5d40297238a6c294fd575cdf35fabec44c050a6421c401d98d659fd2ed13c961cc8287944dd3202f516977800d3ab2f39ee"
    ap_connector = "eyJ0eXAiOiJkcHBDb24iLCJraWQiOiJzOEFrYjg5bTV4UGhoYk5UbTVmVVo0eVBzNU5VMkdxYXNRY3hXUWhtQVFRIiwiYWxnIjoiRVMyNTYifQ.eyJncm91cHMiOlt7Imdyb3VwSWQiOiIqIiwibmV0Um9sZSI6ImFwIn1dLCJuZXRBY2Nlc3NLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiIwOHF4TlNYRzRWemdCV3BjVUdNSmc1czNvbElOVFJsRVQ1aERpNkRKY3ZjIiwieSI6IlVhaGFYQXpKRVpRQk1YaHRUQnlZZVlrOWtJYjk5UDA3UV9NcW9TVVZTVEkifX0.a5_nfMVr7Qe1SW0ZL3u6oQRm5NUCYUSfixDAJOUFN3XUfECBZ6E8fm8xjeSfdOytgRidTz0CTlIRjzPQo82dmQ"
    ap_netaccesskey = "30770201010420f6531d17f29dfab655b7c9e923478d5a345164c489aadd44a3519c3e9dcc792da00a06082a8648ce3d030107a14403420004d3cab13525c6e15ce0056a5c506309839b37a2520d4d19444f98438ba0c972f751a85a5c0cc911940131786d4c1c9879893d9086fdf4fd3b43f32aa125154932"
    sta_connector = "eyJ0eXAiOiJkcHBDb24iLCJraWQiOiJzOEFrYjg5bTV4UGhoYk5UbTVmVVo0eVBzNU5VMkdxYXNRY3hXUWhtQVFRIiwiYWxnIjoiRVMyNTYifQ.eyJncm91cHMiOlt7Imdyb3VwSWQiOiIqIiwibmV0Um9sZSI6InN0YSJ9XSwibmV0QWNjZXNzS2V5Ijp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZWMzR3NqQ3lQMzVBUUZOQUJJdEltQnN4WXVyMGJZX1dES1lfSE9zUGdjNCIsInkiOiJTRS1HVllkdWVnTFhLMU1TQXZNMEx2QWdLREpTNWoyQVhCbE9PMTdUSTRBIn19.PDK9zsGlK-e1pEOmNxVeJfCS8pNeay6ckIS1TXCQsR64AR-9wFPCNVjqOxWvVKltehyMFqVAtOcv0IrjtMJFqQ"
    sta_netaccesskey = "30770201010420bc33380c26fd2168b69cd8242ed1df07ba89aa4813f8d4e8523de6ca3f8dd28ba00a06082a8648ce3d030107a1440342000479cdc6b230b23f7e40405340048b48981b3162eaf46d8fd60ca63f1ceb0f81ce484f8655876e7a02d72b531202f3342ef020283252e63d805c194e3b5ed32380"

    params = { "ssid": "dpp",
               "wpa": "2",
               "wpa_key_mgmt": "DPP",
               "ieee80211w": "2",
               "rsn_pairwise": "CCMP",
               "dpp_connector": ap_connector,
               "dpp_csign": csign,
               "dpp_netaccesskey": ap_netaccesskey }
    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except:
        raise HwsimSkip("DPP not supported")

    for test in [ 60, 61, 80, 82 ]:
        dev[0].set("dpp_test", str(test))
        dev[0].connect("dpp", key_mgmt="DPP", scan_freq="2412", ieee80211w="2",
                       dpp_csign=csign, dpp_connector=sta_connector,
                       dpp_netaccesskey=sta_netaccesskey, wait_connect=False)

        ev = dev[0].wait_event(["DPP-TX"], timeout=10)
        if ev is None or "type=5" not in ev:
            raise Exception("Peer Discovery Request TX not reported")
        ev = dev[0].wait_event(["DPP-TX-STATUS"], timeout=2)
        if ev is None or "result=SUCCESS" not in ev:
            raise Exception("Peer Discovery Request TX status not reported")

        ev = hapd.wait_event(["DPP-RX"], timeout=10)
        if ev is None or "type=5" not in ev:
            raise Exception("Peer Discovery Request RX not reported")

        if test == 80:
            ev = dev[0].wait_event(["DPP-INTRO"], timeout=10)
            if ev is None:
                raise Exception("DPP-INTRO not reported for test 80")
            if "status=7" not in ev:
                raise Exception("Unexpected result in test 80: " + ev)

        dev[0].request("REMOVE_NETWORK all")
        dev[0].dump_monitor()
        hapd.dump_monitor()
    dev[0].set("dpp_test", "0")

    for test in [ 62, 63, 64, 77, 78, 79 ]:
        hapd.set("dpp_test", str(test))
        dev[0].connect("dpp", key_mgmt="DPP", scan_freq="2412", ieee80211w="2",
                       dpp_csign=csign, dpp_connector=sta_connector,
                       dpp_netaccesskey=sta_netaccesskey, wait_connect=False)

        ev = dev[0].wait_event(["DPP-INTRO"], timeout=10)
        if ev is None:
            raise Exception("Peer introduction result not reported (test %d)" % test)
        if test == 77:
            if "fail=transaction_id_mismatch" not in ev:
                raise Exception("Connector validation failure not reported")
        elif test == 78:
            if "status=254" not in ev:
                raise Exception("Invalid status value not reported")
        elif test == 79:
            if "fail=peer_connector_validation_failed" not in ev:
                raise Exception("Connector validation failure not reported")
        elif "status=" in ev:
            raise Exception("Unexpected peer introduction result (test %d): " % test + ev)

        dev[0].request("REMOVE_NETWORK all")
        dev[0].dump_monitor()
        hapd.dump_monitor()
    hapd.set("dpp_test", "0")

    dev[0].connect("dpp", key_mgmt="DPP", scan_freq="2412", ieee80211w="2",
                   dpp_csign=csign, dpp_connector=sta_connector,
                   dpp_netaccesskey=sta_netaccesskey)

def test_dpp_qr_code_no_chan_list_unicast(dev, apdev):
    """DPP QR Code and no channel list (unicast)"""
    run_dpp_qr_code_chan_list(dev, apdev, True, 2417, None)

def test_dpp_qr_code_chan_list_unicast(dev, apdev):
    """DPP QR Code and 2.4 GHz channels (unicast)"""
    run_dpp_qr_code_chan_list(dev, apdev, True, 2417,
                              "81/1,81/2,81/3,81/4,81/5,81/6,81/7,81/8,81/9,81/10,81/11,81/12,81/13")

def test_dpp_qr_code_chan_list_no_peer_unicast(dev, apdev):
    """DPP QR Code and channel list and no peer (unicast)"""
    run_dpp_qr_code_chan_list(dev, apdev, True, 2417, "81/1,81/6,81/11",
                              no_wait=True)
    ev = dev[1].wait_event(["DPP-AUTH-INIT-FAILED"], timeout=5)
    if ev is None:
        raise Exception("Initiation failure not reported")

def test_dpp_qr_code_no_chan_list_broadcast(dev, apdev):
    """DPP QR Code and no channel list (broadcast)"""
    run_dpp_qr_code_chan_list(dev, apdev, False, 2412, None)

def test_dpp_qr_code_chan_list_broadcast(dev, apdev):
    """DPP QR Code and some 2.4 GHz channels (broadcast)"""
    run_dpp_qr_code_chan_list(dev, apdev, False, 2412, "81/1,81/6,81/11",
                              timeout=10)

def run_dpp_qr_code_chan_list(dev, apdev, unicast, listen_freq, chanlist,
                              no_wait=False, timeout=5):
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])
    dev[1].set("dpp_init_max_tries", "3")
    dev[1].set("dpp_init_retry_time", "100")
    dev[1].set("dpp_resp_wait_time", "1000")

    logger.info("dev0 displays QR Code")
    cmd = "DPP_BOOTSTRAP_GEN type=qrcode"
    if chanlist:
        cmd += " chan=" + chanlist
    if unicast:
        addr = dev[0].own_addr().replace(':', '')
        cmd += " mac=" + addr
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    logger.info("dev1 scans QR Code")
    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    logger.info("dev1 initiates DPP Authentication")
    cmd = "DPP_LISTEN %d" % listen_freq
    if "OK" not in dev[0].request(cmd):
        raise Exception("Failed to start listen operation")
    cmd = "DPP_AUTH_INIT peer=%d" % id1
    if "OK" not in dev[1].request(cmd):
        raise Exception("Failed to initiate DPP Authentication")
    if no_wait:
        return
    ev = dev[0].wait_event(["DPP-AUTH-SUCCESS"], timeout=timeout)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Responder)")
    ev = dev[1].wait_event(["DPP-AUTH-SUCCESS"], timeout=5)
    if ev is None:
        raise Exception("DPP authentication did not succeed (Initiator)")
    ev = dev[0].wait_event(["DPP-CONF-RECEIVED", "DPP-CONF-FAILED"], timeout=5)
    if ev is None:
        raise Exception("DPP configuration not completed (Enrollee)")
    dev[0].request("DPP_STOP_LISTEN")
    dev[0].dump_monitor()
    dev[1].dump_monitor()

def test_dpp_qr_code_chan_list_no_match(dev, apdev):
    """DPP QR Code and no matching supported channel"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    cmd = "DPP_BOOTSTRAP_GEN type=qrcode chan=123/123"
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)
    uri0 = dev[0].request("DPP_BOOTSTRAP_GET_URI %d" % id0)

    res = dev[1].request("DPP_QR_CODE " + uri0)
    if "FAIL" in res:
        raise Exception("Failed to parse QR Code URI")
    id1 = int(res)

    cmd = "DPP_AUTH_INIT peer=%d" % id1
    if "FAIL" not in dev[1].request(cmd):
        raise Exception("DPP Authentication started unexpectedly")

def test_dpp_pkex_alloc_fail(dev, apdev):
    """DPP/PKEX and memory allocation failures"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    tests = [ (1, "=dpp_keygen_configurator"),
              (1, "base64_gen_encode;dpp_keygen_configurator") ]
    for count, func in tests:
        with alloc_fail(dev[1], count, func):
            cmd = "DPP_CONFIGURATOR_ADD"
            res = dev[1].request(cmd);
            if "FAIL" not in res:
                raise Exception("Unexpected DPP_CONFIGURATOR_ADD success")

    cmd = "DPP_CONFIGURATOR_ADD"
    res = dev[1].request(cmd);
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id = int(res)

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id1 = int(res)

    # Local error cases on the Initiator
    tests = [ (1, "dpp_get_pubkey_point"),
              (1, "dpp_alloc_msg;dpp_pkex_build_exchange_req"),
              (1, "dpp_alloc_msg;dpp_pkex_build_commit_reveal_req"),
              (1, "dpp_alloc_msg;dpp_auth_build_req"),
              (1, "dpp_alloc_msg;dpp_auth_build_conf"),
              (1, "dpp_bootstrap_key_hash"),
              (1, "dpp_auth_init"),
              (1, "=dpp_auth_resp_rx"),
              (2, "=dpp_auth_resp_rx"),
              (1, "dpp_build_conf_start"),
              (1, "dpp_build_conf_obj_dpp"),
              (2, "dpp_build_conf_obj_dpp"),
              (3, "dpp_build_conf_obj_dpp"),
              (4, "dpp_build_conf_obj_dpp"),
              (5, "dpp_build_conf_obj_dpp"),
              (6, "dpp_build_conf_obj_dpp"),
              (7, "dpp_build_conf_obj_dpp"),
              (8, "dpp_build_conf_obj_dpp"),
              (1, "dpp_conf_req_rx"),
              (2, "dpp_conf_req_rx"),
              (3, "dpp_conf_req_rx"),
              (4, "dpp_conf_req_rx"),
              (5, "dpp_conf_req_rx"),
              (6, "dpp_conf_req_rx"),
              (7, "dpp_conf_req_rx"),
              (1, "dpp_pkex_init"),
              (2, "dpp_pkex_init"),
              (3, "dpp_pkex_init"),
              (1, "dpp_pkex_derive_z"),
              (1, "=dpp_pkex_rx_commit_reveal_resp"),
              (1, "dpp_get_pubkey_point;dpp_build_jwk"),
              (2, "dpp_get_pubkey_point;dpp_build_jwk"),
              (1, "dpp_get_pubkey_point;dpp_auth_init") ]
    for count, func in tests:
        dev[0].request("DPP_STOP_LISTEN")
        dev[1].request("DPP_STOP_LISTEN")
        dev[0].dump_monitor()
        dev[1].dump_monitor()

        cmd = "DPP_PKEX_ADD own=%d identifier=test code=secret" % (id0)
        res = dev[0].request(cmd)
        if "FAIL" in res:
            raise Exception("Failed to set PKEX data (responder)")
        cmd = "DPP_LISTEN 2437"
        if "OK" not in dev[0].request(cmd):
            raise Exception("Failed to start listen operation")

        with alloc_fail(dev[1], count, func):
            cmd = "DPP_PKEX_ADD own=%d identifier=test init=1 conf=sta-dpp configurator=%d code=secret" % (id1, conf_id)
            dev[1].request(cmd)
            wait_fail_trigger(dev[1], "GET_ALLOC_FAIL", max_iter=100)
            ev = dev[0].wait_event(["GAS-QUERY-START"], timeout=0.01)
            if ev:
                dev[0].request("DPP_STOP_LISTEN")
                dev[0].wait_event(["GAS-QUERY-DONE"], timeout=3)

    # Local error cases on the Responder
    tests = [ (1, "dpp_get_pubkey_point"),
              (1, "dpp_alloc_msg;dpp_pkex_build_exchange_resp"),
              (1, "dpp_alloc_msg;dpp_pkex_build_commit_reveal_resp"),
              (1, "dpp_alloc_msg;dpp_auth_build_resp"),
              (1, "dpp_get_pubkey_point;dpp_auth_build_resp_ok"),
              (1, "=dpp_auth_req_rx"),
              (2, "=dpp_auth_req_rx"),
              (1, "=dpp_auth_conf_rx"),
              (1, "json_parse;dpp_parse_jws_prot_hdr"),
              (1, "json_get_member_base64url;dpp_parse_jws_prot_hdr"),
              (1, "json_get_member_base64url;dpp_parse_jwk"),
              (2, "json_get_member_base64url;dpp_parse_jwk"),
              (1, "json_parse;dpp_parse_connector"),
              (1, "dpp_parse_jwk;dpp_parse_connector"),
              (1, "dpp_parse_jwk;dpp_parse_cred_dpp"),
              (1, "dpp_get_pubkey_point;dpp_check_pubkey_match"),
              (1, "base64_gen_decode;dpp_process_signed_connector"),
              (1, "dpp_parse_jws_prot_hdr;dpp_process_signed_connector"),
              (2, "base64_gen_decode;dpp_process_signed_connector"),
              (3, "base64_gen_decode;dpp_process_signed_connector"),
              (4, "base64_gen_decode;dpp_process_signed_connector"),
              (1, "json_parse;dpp_parse_conf_obj"),
              (1, "dpp_conf_resp_rx"),
              (1, "=dpp_pkex_derive_z"),
              (1, "=dpp_pkex_rx_exchange_req"),
              (2, "=dpp_pkex_rx_exchange_req"),
              (3, "=dpp_pkex_rx_exchange_req"),
              (1, "=dpp_pkex_rx_commit_reveal_req"),
              (1, "dpp_get_pubkey_point;dpp_pkex_rx_commit_reveal_req"),
              (1, "dpp_bootstrap_key_hash") ]
    for count, func in tests:
        dev[0].request("DPP_STOP_LISTEN")
        dev[1].request("DPP_STOP_LISTEN")
        dev[0].dump_monitor()
        dev[1].dump_monitor()

        cmd = "DPP_PKEX_ADD own=%d identifier=test code=secret" % (id0)
        res = dev[0].request(cmd)
        if "FAIL" in res:
            raise Exception("Failed to set PKEX data (responder)")
        cmd = "DPP_LISTEN 2437"
        if "OK" not in dev[0].request(cmd):
            raise Exception("Failed to start listen operation")

        with alloc_fail(dev[0], count, func):
            cmd = "DPP_PKEX_ADD own=%d identifier=test init=1 conf=sta-dpp configurator=%d code=secret" % (id1, conf_id)
            dev[1].request(cmd)
            wait_fail_trigger(dev[0], "GET_ALLOC_FAIL", max_iter=100)
            ev = dev[0].wait_event(["GAS-QUERY-START"], timeout=0.01)
            if ev:
                dev[0].request("DPP_STOP_LISTEN")
                dev[0].wait_event(["GAS-QUERY-DONE"], timeout=3)

def test_dpp_pkex_test_fail(dev, apdev):
    """DPP/PKEX and local failures"""
    check_dpp_capab(dev[0])
    check_dpp_capab(dev[1])

    tests = [ (1, "dpp_keygen_configurator") ]
    for count, func in tests:
        with fail_test(dev[1], count, func):
            cmd = "DPP_CONFIGURATOR_ADD"
            res = dev[1].request(cmd);
            if "FAIL" not in res:
                raise Exception("Unexpected DPP_CONFIGURATOR_ADD success")

    tests = [ (1, "dpp_keygen") ]
    for count, func in tests:
        with fail_test(dev[1], count, func):
            cmd = "DPP_BOOTSTRAP_GEN type=pkex"
            res = dev[1].request(cmd);
            if "FAIL" not in res:
                raise Exception("Unexpected DPP_BOOTSTRAP_GEN success")

    cmd = "DPP_CONFIGURATOR_ADD"
    res = dev[1].request(cmd);
    if "FAIL" in res:
        raise Exception("Failed to add configurator")
    conf_id = int(res)

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    res = dev[0].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id0 = int(res)

    cmd = "DPP_BOOTSTRAP_GEN type=pkex"
    res = dev[1].request(cmd)
    if "FAIL" in res:
        raise Exception("Failed to generate bootstrapping info")
    id1 = int(res)

    # Local error cases on the Initiator
    tests = [ (1, "aes_siv_encrypt;dpp_auth_build_req"),
              (1, "os_get_random;dpp_auth_init"),
              (1, "dpp_derive_k1;dpp_auth_init"),
              (1, "dpp_hkdf_expand;dpp_derive_k1;dpp_auth_init"),
              (1, "dpp_gen_i_auth;dpp_auth_build_conf"),
              (1, "aes_siv_encrypt;dpp_auth_build_conf"),
              (1, "dpp_derive_k2;dpp_auth_resp_rx"),
              (1, "dpp_hkdf_expand;dpp_derive_k2;dpp_auth_resp_rx"),
              (1, "dpp_derive_ke;dpp_auth_resp_rx"),
              (1, "dpp_hkdf_expand;dpp_derive_ke;dpp_auth_resp_rx"),
              (1, "dpp_gen_r_auth;dpp_auth_resp_rx"),
              (1, "aes_siv_encrypt;dpp_build_conf_resp"),
              (1, "dpp_pkex_derive_Qi;dpp_pkex_build_exchange_req"),
              (1, "aes_siv_encrypt;dpp_pkex_build_commit_reveal_req"),
              (1, "hmac_sha256_vector;dpp_pkex_rx_exchange_resp"),
              (1, "aes_siv_decrypt;dpp_pkex_rx_commit_reveal_resp"),
              (1, "hmac_sha256_vector;dpp_pkex_rx_commit_reveal_resp") ]
    for count, func in tests:
        dev[0].request("DPP_STOP_LISTEN")
        dev[1].request("DPP_STOP_LISTEN")
        dev[0].dump_monitor()
        dev[1].dump_monitor()

        cmd = "DPP_PKEX_ADD own=%d identifier=test code=secret" % (id0)
        res = dev[0].request(cmd)
        if "FAIL" in res:
            raise Exception("Failed to set PKEX data (responder)")
        cmd = "DPP_LISTEN 2437"
        if "OK" not in dev[0].request(cmd):
            raise Exception("Failed to start listen operation")

        with fail_test(dev[1], count, func):
            cmd = "DPP_PKEX_ADD own=%d identifier=test init=1 conf=sta-dpp configurator=%d code=secret" % (id1, conf_id)
            dev[1].request(cmd)
            wait_fail_trigger(dev[1], "GET_FAIL", max_iter=100)
            ev = dev[0].wait_event(["GAS-QUERY-START"], timeout=0.01)
            if ev:
                dev[0].request("DPP_STOP_LISTEN")
                dev[0].wait_event(["GAS-QUERY-DONE"], timeout=3)

    # Local error cases on the Responder
    tests = [ (1, "aes_siv_encrypt;dpp_auth_build_resp"),
              (1, "os_get_random;dpp_build_conf_req"),
              (1, "aes_siv_encrypt;dpp_build_conf_req"),
              (1, "os_get_random;dpp_auth_build_resp_ok"),
              (1, "dpp_derive_k2;dpp_auth_build_resp_ok"),
              (1, "dpp_derive_ke;dpp_auth_build_resp_ok"),
              (1, "dpp_gen_r_auth;dpp_auth_build_resp_ok"),
              (1, "aes_siv_encrypt;dpp_auth_build_resp_ok"),
              (1, "dpp_derive_k1;dpp_auth_req_rx"),
              (1, "aes_siv_decrypt;dpp_auth_req_rx"),
              (1, "aes_siv_decrypt;dpp_auth_conf_rx"),
              (1, "dpp_gen_i_auth;dpp_auth_conf_rx"),
              (1, "dpp_check_pubkey_match"),
              (1, "aes_siv_decrypt;dpp_conf_resp_rx"),
              (1, "hmac_sha256_kdf;dpp_pkex_derive_z"),
              (1, "dpp_pkex_derive_Qi;dpp_pkex_rx_exchange_req"),
              (1, "dpp_pkex_derive_Qr;dpp_pkex_rx_exchange_req"),
              (1, "aes_siv_encrypt;dpp_pkex_build_commit_reveal_resp"),
              (1, "aes_siv_decrypt;dpp_pkex_rx_commit_reveal_req"),
              (1, "hmac_sha256_vector;dpp_pkex_rx_commit_reveal_req"),
              (2, "hmac_sha256_vector;dpp_pkex_rx_commit_reveal_req") ]
    for count, func in tests:
        dev[0].request("DPP_STOP_LISTEN")
        dev[1].request("DPP_STOP_LISTEN")
        dev[0].dump_monitor()
        dev[1].dump_monitor()

        cmd = "DPP_PKEX_ADD own=%d identifier=test code=secret" % (id0)
        res = dev[0].request(cmd)
        if "FAIL" in res:
            raise Exception("Failed to set PKEX data (responder)")
        cmd = "DPP_LISTEN 2437"
        if "OK" not in dev[0].request(cmd):
            raise Exception("Failed to start listen operation")

        with fail_test(dev[0], count, func):
            cmd = "DPP_PKEX_ADD own=%d identifier=test init=1 conf=sta-dpp configurator=%d code=secret" % (id1, conf_id)
            dev[1].request(cmd)
            wait_fail_trigger(dev[0], "GET_FAIL", max_iter=100)
            ev = dev[0].wait_event(["GAS-QUERY-START"], timeout=0.01)
            if ev:
                dev[0].request("DPP_STOP_LISTEN")
                dev[0].wait_event(["GAS-QUERY-DONE"], timeout=3)
