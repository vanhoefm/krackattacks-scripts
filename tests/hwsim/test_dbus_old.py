# wpa_supplicant D-Bus old interface tests
# Copyright (c) 2014-2015, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()

try:
    import gobject
    import dbus
    dbus_imported = True
except ImportError:
    dbus_imported = False

import hostapd
from utils import HwsimSkip
from test_dbus import TestDbus, alloc_fail_dbus, start_ap

WPAS_DBUS_OLD_SERVICE = "fi.epitest.hostap.WPASupplicant"
WPAS_DBUS_OLD_PATH = "/fi/epitest/hostap/WPASupplicant"
WPAS_DBUS_OLD_IFACE = "fi.epitest.hostap.WPASupplicant.Interface"
WPAS_DBUS_OLD_BSSID = "fi.epitest.hostap.WPASupplicant.BSSID"
WPAS_DBUS_OLD_NETWORK = "fi.epitest.hostap.WPASupplicant.Network"

def prepare_dbus(dev):
    if not dbus_imported:
        raise HwsimSkip("No dbus module available")
    try:
        from dbus.mainloop.glib import DBusGMainLoop
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        bus = dbus.SystemBus()
        wpas_obj = bus.get_object(WPAS_DBUS_OLD_SERVICE, WPAS_DBUS_OLD_PATH)
        wpas = dbus.Interface(wpas_obj, WPAS_DBUS_OLD_SERVICE)
        path = wpas.getInterface(dev.ifname)
        if_obj = bus.get_object(WPAS_DBUS_OLD_SERVICE, path)
        return (bus,wpas_obj,path,if_obj)
    except Exception, e:
        raise HwsimSkip("Could not connect to D-Bus: %s" % e)

class TestDbusOldWps(TestDbus):
    def __init__(self, bus):
        TestDbus.__init__(self, bus)
        self.event_ok = False

    def __enter__(self):
        gobject.timeout_add(1, self.run_wps)
        gobject.timeout_add(15000, self.timeout)
        self.add_signal(self.wpsCred, WPAS_DBUS_OLD_IFACE, "WpsCred")
        self.loop.run()
        return self

    def wpsCred(self, cred):
        logger.debug("wpsCred: " + str(cred))
        self.event_ok = True
        self.loop.quit()

    def success(self):
        return self.event_ok

def test_dbus_old(dev, apdev):
    """The old D-Bus interface"""
    (bus,wpas_obj,path,if_obj) = prepare_dbus(dev[0])

    res = if_obj.capabilities(dbus_interface=WPAS_DBUS_OLD_IFACE)
    logger.debug("capabilities(): " + str(res))
    if 'auth_alg' not in res or "OPEN" not in res['auth_alg']:
        raise Exception("Unexpected capabilities")
    res2 = if_obj.capabilities(dbus.Boolean(True),
                               dbus_interface=WPAS_DBUS_OLD_IFACE)
    logger.debug("capabilities(strict): " + str(res2))
    res = if_obj.state(dbus_interface=WPAS_DBUS_OLD_IFACE)
    logger.debug("State: " + res)

    res = if_obj.scanning(dbus_interface=WPAS_DBUS_OLD_IFACE)
    if res != 0:
        raise Exception("Unexpected scanning: " + str(res))

    if_obj.setAPScan(dbus.UInt32(1), dbus_interface=WPAS_DBUS_OLD_IFACE)

    for t in [ dbus.UInt32(123), "foo" ]:
        try:
            if_obj.setAPScan(t, dbus_interface=WPAS_DBUS_OLD_IFACE)
            raise Exception("Invalid setAPScan() accepted")
        except dbus.exceptions.DBusException, e:
            if "InvalidOptions" not in str(e):
                raise Exception("Unexpected error message for invalid setAPScan: " + str(e))

    for p in [ path + "/Networks/12345",
               path + "/Networks/foo" ]:
        obj = bus.get_object(WPAS_DBUS_OLD_SERVICE, p)
        try:
            obj.disable(dbus_interface=WPAS_DBUS_OLD_NETWORK)
            raise Exception("Invalid disable() accepted")
        except dbus.exceptions.DBusException, e:
            if "InvalidNetwork" not in str(e):
                raise Exception("Unexpected error message for invalid disable: " + str(e))

    for p in [ path + "/BSSIDs/foo",
               path + "/BSSIDs/001122334455"]:
        obj = bus.get_object(WPAS_DBUS_OLD_SERVICE, p)
        try:
            obj.properties(dbus_interface=WPAS_DBUS_OLD_BSSID)
            raise Exception("Invalid properties() accepted")
        except dbus.exceptions.DBusException, e:
            if "InvalidBSSID" not in str(e):
                raise Exception("Unexpected error message for invalid properties: " + str(e))

def test_dbus_old_scan(dev, apdev):
    """The old D-Bus interface - scanning"""
    (bus,wpas_obj,path,if_obj) = prepare_dbus(dev[0])

    hapd = hostapd.add_ap(apdev[0], { "ssid": "open" })

    params = hostapd.wpa2_eap_params(ssid="test-wpa2-eap")
    params['wpa'] = '3'
    hapd2 = hostapd.add_ap(apdev[1], params)

    class TestDbusScan(TestDbus):
        def __init__(self, bus):
            TestDbus.__init__(self, bus)
            self.scan_completed = False

        def __enter__(self):
            gobject.timeout_add(1, self.run_scan)
            gobject.timeout_add(7000, self.timeout)
            self.add_signal(self.scanDone, WPAS_DBUS_OLD_IFACE,
                            "ScanResultsAvailable")
            self.loop.run()
            return self

        def scanDone(self):
            logger.debug("scanDone")
            self.scan_completed = True
            self.loop.quit()

        def run_scan(self, *args):
            logger.debug("run_scan")
            if not if_obj.scan(dbus_interface=WPAS_DBUS_OLD_IFACE):
                raise Exception("Failed to trigger scan")
            return False

        def success(self):
            return self.scan_completed

    with TestDbusScan(bus) as t:
        if not t.success():
            raise Exception("Expected signals not seen")

    res = if_obj.scanResults(dbus_interface=WPAS_DBUS_OLD_IFACE)
    if len(res) != 2:
        raise Exception("Unexpected number of scan results: " + str(res))
    for i in range(2):
        logger.debug("Scan result BSS path: " + res[i])
        bss_obj = bus.get_object(WPAS_DBUS_OLD_SERVICE, res[i])
        bss = bss_obj.properties(dbus_interface=WPAS_DBUS_OLD_BSSID,
                                 byte_arrays=True)
        logger.debug("BSS: " + str(bss))

    obj = bus.get_object(WPAS_DBUS_OLD_SERVICE, res[0])
    try:
        bss_obj.properties2(dbus_interface=WPAS_DBUS_OLD_BSSID)
        raise Exception("Unknown BSSID method accepted")
    except Exception, e:
        logger.debug("Unknown BSSID method exception: " + str(e))

    if not if_obj.flush(0, dbus_interface=WPAS_DBUS_OLD_IFACE):
        raise Exception("Failed to issue flush(0)")
    res = if_obj.scanResults(dbus_interface=WPAS_DBUS_OLD_IFACE)
    if len(res) != 0:
        raise Exception("Unexpected BSS entry after flush")
    if not if_obj.flush(1, dbus_interface=WPAS_DBUS_OLD_IFACE):
        raise Exception("Failed to issue flush(1)")
    try:
        if_obj.flush("foo", dbus_interface=WPAS_DBUS_OLD_IFACE)
        raise Exception("Invalid flush arguments accepted")
    except dbus.exceptions.DBusException, e:
        if not str(e).startswith("fi.epitest.hostap.WPASupplicant.InvalidOptions"):
            raise Exception("Unexpected error message for invalid flush: " + str(e))
    try:
        bss_obj.properties(dbus_interface=WPAS_DBUS_OLD_BSSID,
                           byte_arrays=True)
    except dbus.exceptions.DBusException, e:
        if not str(e).startswith("fi.epitest.hostap.WPASupplicant.Interface.InvalidBSSID"):
            raise Exception("Unexpected error message for invalid BSS: " + str(e))

def test_dbus_old_debug(dev, apdev):
    """The old D-Bus interface - debug"""
    (bus,wpas_obj,path,if_obj) = prepare_dbus(dev[0])
    wpas = dbus.Interface(wpas_obj, WPAS_DBUS_OLD_SERVICE)

    try:
        wpas.setDebugParams(123)
        raise Exception("Invalid setDebugParams accepted")
    except dbus.exceptions.DBusException, e:
        if "InvalidOptions" not in str(e):
            raise Exception("Unexpected error message for invalid setDebugParam: " + str(e))

    try:
        wpas.setDebugParams(123, True, True)
        raise Exception("Invalid setDebugParams accepted")
    except dbus.exceptions.DBusException, e:
        if "InvalidOptions" not in str(e):
            raise Exception("Unexpected error message for invalid setDebugParam: " + str(e))

    wpas.setDebugParams(1, True, True)
    dev[0].request("LOG_LEVEL MSGDUMP")

def test_dbus_old_smartcard(dev, apdev):
    """The old D-Bus interface - smartcard"""
    (bus,wpas_obj,path,if_obj) = prepare_dbus(dev[0])

    params = dbus.Dictionary(signature='sv')
    if_obj.setSmartcardModules(params, dbus_interface=WPAS_DBUS_OLD_IFACE)

    params = dbus.Dictionary({ 'opensc_engine_path': "foobar1",
                               'pkcs11_engine_path': "foobar2",
                               'pkcs11_module_path': "foobar3",
                               'foo': 'bar' },
                             signature='sv')
    params2 = dbus.Dictionary({ 'pkcs11_engine_path': "foobar2",
                                'foo': 'bar' },
                              signature='sv')
    params3 = dbus.Dictionary({ 'pkcs11_module_path': "foobar3",
                                'foo2': 'bar' },
                              signature='sv')
    params4 = dbus.Dictionary({ 'opensc_engine_path': "foobar4",
                                'foo3': 'bar' },
                              signature='sv')
    tests = [ 1, params, params2, params3, params4 ]
    for t in tests:
        try:
            if_obj.setSmartcardModules(t, dbus_interface=WPAS_DBUS_OLD_IFACE)
            raise Exception("Invalid setSmartcardModules accepted: " + str(t))
        except dbus.exceptions.DBusException, e:
            if not str(e).startswith("fi.epitest.hostap.WPASupplicant.InvalidOptions"):
                raise Exception("Unexpected error message for invalid setSmartcardModules(%s): %s" % (str(t), str(e)))

def test_dbus_old_smartcard_oom(dev, apdev):
    """The old D-Bus interface - smartcard (OOM)"""
    (bus,wpas_obj,path,if_obj) = prepare_dbus(dev[0])

    for arg in [ 'opensc_engine_path', 'pkcs11_engine_path', 'pkcs11_module_path' ]:
        with alloc_fail_dbus(dev[0], 1,
                             "=wpas_dbus_iface_set_smartcard_modules",
                             "setSmartcardModules",
                             "InvalidOptions"):
            params = dbus.Dictionary({ arg : "foo", }, signature='sv')
            if_obj.setSmartcardModules(params,
                                       dbus_interface=WPAS_DBUS_OLD_IFACE)

    with alloc_fail_dbus(dev[0], 1, "=_wpa_dbus_dict_fill_value_from_variant;wpas_dbus_iface_set_smartcard_modules",
                         "setSmartcardModules", "InvalidOptions"):
        params = dbus.Dictionary({ arg : "foo", }, signature='sv')
        if_obj.setSmartcardModules(params, dbus_interface=WPAS_DBUS_OLD_IFACE)

def test_dbus_old_interface(dev, apdev):
    """The old D-Bus interface - interface get/add/remove"""
    (bus,wpas_obj,path,if_obj) = prepare_dbus(dev[0])
    wpas = dbus.Interface(wpas_obj, WPAS_DBUS_OLD_SERVICE)

    tests = [ (123, "InvalidOptions"),
              ("foo", "InvalidInterface") ]
    for (ifname,err) in tests:
        try:
            wpas.getInterface(ifname)
            raise Exception("Invalid getInterface accepted")
        except dbus.exceptions.DBusException, e:
            if err not in str(e):
                raise Exception("Unexpected error message for invalid getInterface: " + str(e))

    params = dbus.Dictionary({ 'driver': 'none' }, signature='sv')
    wpas.addInterface("lo", params)
    path = wpas.getInterface("lo")
    logger.debug("New interface path: " + str(path))
    wpas.removeInterface(path)
    try:
        wpas.removeInterface(path)
        raise Exception("Invalid removeInterface() accepted")
    except dbus.exceptions.DBusException, e:
        if "InvalidInterface" not in str(e):
            raise Exception("Unexpected error message for invalid removeInterface: " + str(e))

    params1 = dbus.Dictionary({ 'driver': 'foo',
                                'driver-params': 'foo',
                                'config-file': 'foo',
                                'bridge-ifname': 'foo' },
                              signature='sv')
    params2 = dbus.Dictionary({ 'foo': 'bar' }, signature='sv')
    tests = [ (123, None, "InvalidOptions"),
              ("", None, "InvalidOptions"),
              ("foo", None, "AddError"),
              ("foo", params1, "AddError"),
              ("foo", params2, "InvalidOptions"),
              ("foo", 1234, "InvalidOptions"),
              (dev[0].ifname, None, "ExistsError" ) ]
    for (ifname,params,err) in tests:
        try:
            if params is None:
                wpas.addInterface(ifname)
            else:
                wpas.addInterface(ifname, params)
            raise Exception("Invalid addInterface accepted: " + str(params))
        except dbus.exceptions.DBusException, e:
            if err not in str(e):
                raise Exception("Unexpected error message for invalid addInterface(%s): %s" % (str(params), str(e)))

    try:
        wpas.removeInterface(123)
        raise Exception("Invalid removeInterface accepted")
    except dbus.exceptions.DBusException, e:
        if not str(e).startswith("fi.epitest.hostap.WPASupplicant.InvalidOptions"):
            raise Exception("Unexpected error message for invalid removeInterface: " + str(e))

def test_dbus_old_interface_oom(dev, apdev):
    """The old D-Bus interface - interface get/add/remove (OOM)"""
    (bus,wpas_obj,path,if_obj) = prepare_dbus(dev[0])
    wpas = dbus.Interface(wpas_obj, WPAS_DBUS_OLD_SERVICE)

    with alloc_fail_dbus(dev[0], 1, "=_wpa_dbus_dict_fill_value_from_variant;wpas_dbus_global_add_interface",
                         "addInterface", "InvalidOptions"):
        params = dbus.Dictionary({ 'driver': 'none' }, signature='sv')
        wpas.addInterface("lo", params)

    for arg in [ "driver", "driver-params", "config-file", "bridge-ifname" ]:
        with alloc_fail_dbus(dev[0], 1, "=wpas_dbus_global_add_interface",
                             "addInterface", "InvalidOptions"):
            params = dbus.Dictionary({ arg: 'foo' }, signature='sv')
            wpas.addInterface("lo", params)

def test_dbus_old_blob(dev, apdev):
    """The old D-Bus interface - blob operations"""
    (bus,wpas_obj,path,if_obj) = prepare_dbus(dev[0])

    param1 = dbus.Dictionary({ 'blob3': 123 }, signature='sv')
    param2 = dbus.Dictionary({ 'blob3': "foo" })
    param3 = dbus.Dictionary({ '': dbus.ByteArray([ 1, 2 ]) },
                             signature='sv')
    tests = [ (1, "InvalidOptions"),
              (param1, "InvalidOptions"),
              (param2, "InvalidOptions"),
              (param3, "InvalidOptions") ]
    for (arg,err) in tests:
        try:
            if_obj.setBlobs(arg, dbus_interface=WPAS_DBUS_OLD_IFACE)
            raise Exception("Invalid setBlobs() accepted: " + str(arg))
        except dbus.exceptions.DBusException, e:
            logger.debug("setBlobs(%s): %s" % (str(arg), str(e)))
            if err not in str(e):
                raise Exception("Unexpected error message for invalid setBlobs: " + str(e))

    tests = [ (["foo"], "RemoveError: Error removing blob"),
              ([""], "RemoveError: Invalid blob name"),
              ([1], "InvalidOptions"),
              ("foo", "InvalidOptions") ]
    for (arg,err) in tests:
        try:
            if_obj.removeBlobs(arg, dbus_interface=WPAS_DBUS_OLD_IFACE)
            raise Exception("Invalid removeBlobs() accepted: " + str(arg))
        except dbus.exceptions.DBusException, e:
            logger.debug("removeBlobs(%s): %s" % (str(arg), str(e)))
            if err not in str(e):
                raise Exception("Unexpected error message for invalid removeBlobs: " + str(e))

    blobs = dbus.Dictionary({ 'blob1': dbus.ByteArray([ 1, 2, 3 ]),
                              'blob2': dbus.ByteArray([ 1, 2 ]) },
                            signature='sv')
    if_obj.setBlobs(blobs, dbus_interface=WPAS_DBUS_OLD_IFACE)
    if_obj.removeBlobs(['blob1', 'blob2'], dbus_interface=WPAS_DBUS_OLD_IFACE)

def test_dbus_old_blob_oom(dev, apdev):
    """The old D-Bus interface - blob operations (OOM)"""
    (bus,wpas_obj,path,if_obj) = prepare_dbus(dev[0])

    blobs = dbus.Dictionary({ 'blob1': dbus.ByteArray([ 1, 2, 3 ]),
                              'blob2': dbus.ByteArray([ 1, 2 ]) },
                            signature='sv')

    with alloc_fail_dbus(dev[0], 1, "=wpas_dbus_iface_set_blobs", "setBlobs",
                         "AddError: Not enough memory to add blob"):
        if_obj.setBlobs(blobs, dbus_interface=WPAS_DBUS_OLD_IFACE)

    with alloc_fail_dbus(dev[0], 2, "=wpas_dbus_iface_set_blobs", "setBlobs",
                         "AddError: Not enough memory to add blob data"):
        if_obj.setBlobs(blobs, dbus_interface=WPAS_DBUS_OLD_IFACE)

    with alloc_fail_dbus(dev[0], 3, "=wpas_dbus_iface_set_blobs", "setBlobs",
                         "AddError: Error adding blob"):
        if_obj.setBlobs(blobs, dbus_interface=WPAS_DBUS_OLD_IFACE)

    with alloc_fail_dbus(dev[0], 1, "=wpas_dbus_decompose_object_path;wpas_iface_message_handler",
                         "setBlobs",
                         "InvalidInterface: wpa_supplicant knows nothing about this interface"):
        if_obj.setBlobs(blobs, dbus_interface=WPAS_DBUS_OLD_IFACE)

def test_dbus_old_connect(dev, apdev):
    """The old D-Bus interface - add a network and connect"""
    (bus,wpas_obj,path,if_obj) = prepare_dbus(dev[0])

    ssid = "test-wpa2-psk"
    passphrase = 'qwertyuiop'
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    hapd = hostapd.add_ap(apdev[0], params)

    for p in [ "/no/where/to/be/found",
               path + "/Networks/12345",
               path + "/Networks/foo",
               "/fi/epitest/hostap/WPASupplicant/Interfaces",
               "/fi/epitest/hostap/WPASupplicant/Interfaces/12345/Networks/0" ]:
        obj = bus.get_object(WPAS_DBUS_OLD_SERVICE, p)
        try:
            if_obj.removeNetwork(obj, dbus_interface=WPAS_DBUS_OLD_IFACE)
            raise Exception("Invalid removeNetwork accepted: " + p)
        except dbus.exceptions.DBusException, e:
            if not str(e).startswith("fi.epitest.hostap.WPASupplicant.Interface.InvalidNetwork"):
                raise Exception("Unexpected error message for invalid removeNetwork: " + str(e))

    try:
        if_obj.removeNetwork("foo", dbus_interface=WPAS_DBUS_OLD_IFACE)
        raise Exception("Invalid removeNetwork accepted")
    except dbus.exceptions.DBusException, e:
        if not str(e).startswith("fi.epitest.hostap.WPASupplicant.InvalidOptions"):
            raise Exception("Unexpected error message for invalid removeNetwork: " + str(e))

    try:
        if_obj.removeNetwork(path, dbus_interface=WPAS_DBUS_OLD_IFACE)
        raise Exception("Invalid removeNetwork accepted")
    except dbus.exceptions.DBusException, e:
        if not str(e).startswith("fi.epitest.hostap.WPASupplicant.Interface.InvalidNetwork"):
            raise Exception("Unexpected error message for invalid removeNetwork: " + str(e))

    tests = [ (path, "InvalidNetwork"),
              (bus.get_object(WPAS_DBUS_OLD_SERVICE, "/no/where"),
               "InvalidInterface"),
              (bus.get_object(WPAS_DBUS_OLD_SERVICE, path + "/Networks/1234"),
               "InvalidNetwork"),
              (bus.get_object(WPAS_DBUS_OLD_SERVICE, path + "/Networks/foo"),
               "InvalidNetwork"),
              (1, "InvalidOptions") ]
    for t,err in tests:
        try:
            if_obj.selectNetwork(t, dbus_interface=WPAS_DBUS_OLD_IFACE)
            raise Exception("Invalid selectNetwork accepted: " + str(t))
        except dbus.exceptions.DBusException, e:
            if err not in str(e):
                raise Exception("Unexpected error message for invalid selectNetwork(%s): %s" % (str(t), str(e)))

    npath = if_obj.addNetwork(dbus_interface=WPAS_DBUS_OLD_IFACE)
    if not npath.startswith(WPAS_DBUS_OLD_PATH):
        raise Exception("Unexpected addNetwork result: " + path)
    netw_obj = bus.get_object(WPAS_DBUS_OLD_SERVICE, npath)
    tests = [ 123,
              dbus.Dictionary({ 'foo': 'bar' }, signature='sv') ]
    for t in tests:
        try:
            netw_obj.set(t, dbus_interface=WPAS_DBUS_OLD_NETWORK)
            raise Exception("Invalid set() accepted: " + str(t))
        except dbus.exceptions.DBusException, e:
            if "InvalidOptions" not in str(e):
                raise Exception("Unexpected error message for invalid set: " + str(e))
    params = dbus.Dictionary({ 'ssid': ssid,
                               'key_mgmt': 'WPA-PSK',
                               'psk': passphrase,
                               'identity': dbus.ByteArray([ 1, 2 ]),
                               'priority': dbus.Int32(0),
                               'scan_freq': dbus.UInt32(2412) },
                             signature='sv')
    netw_obj.set(params, dbus_interface=WPAS_DBUS_OLD_NETWORK)
    id = int(dev[0].list_networks()[0]['id'])
    val = dev[0].get_network(id, "scan_freq")
    if val != "2412":
        raise Exception("Invalid scan_freq value: " + str(val))
    params = dbus.Dictionary({ 'scan_freq': "2412 2432",
                               'freq_list': "2412 2417 2432" },
                             signature='sv')
    netw_obj.set(params, dbus_interface=WPAS_DBUS_OLD_NETWORK)
    val = dev[0].get_network(id, "scan_freq")
    if val != "2412 2432":
        raise Exception("Invalid scan_freq value (2): " + str(val))
    val = dev[0].get_network(id, "freq_list")
    if val != "2412 2417 2432":
        raise Exception("Invalid freq_list value: " + str(val))
    if_obj.removeNetwork(npath, dbus_interface=WPAS_DBUS_OLD_IFACE)

    class TestDbusConnect(TestDbus):
        def __init__(self, bus):
            TestDbus.__init__(self, bus)
            self.state = 0

        def __enter__(self):
            gobject.timeout_add(1, self.run_connect)
            gobject.timeout_add(15000, self.timeout)
            self.add_signal(self.scanDone, WPAS_DBUS_OLD_IFACE,
                            "ScanResultsAvailable")
            self.add_signal(self.stateChange, WPAS_DBUS_OLD_IFACE,
                            "StateChange")
            self.loop.run()
            return self

        def scanDone(self):
            logger.debug("scanDone")

        def stateChange(self, new, old):
            logger.debug("stateChange(%d): %s --> %s" % (self.state, old, new))
            if new == "COMPLETED":
                if self.state == 0:
                    self.state = 1
                    self.netw_obj.disable(dbus_interface=WPAS_DBUS_OLD_NETWORK)
                elif self.state == 2:
                    self.state = 3
                    if_obj.disconnect(dbus_interface=WPAS_DBUS_OLD_IFACE)
                elif self.state == 4:
                    self.state = 5
                    if_obj.disconnect(dbus_interface=WPAS_DBUS_OLD_IFACE)
                elif self.state == 6:
                    self.state = 7
                    if_obj.removeNetwork(self.path,
                                         dbus_interface=WPAS_DBUS_OLD_IFACE)
                    try:
                        if_obj.removeNetwork(self.path,
                                             dbus_interface=WPAS_DBUS_OLD_IFACE)
                        raise Exception("Invalid removeNetwork accepted")
                    except dbus.exceptions.DBusException, e:
                        if not str(e).startswith("fi.epitest.hostap.WPASupplicant.Interface.InvalidNetwork"):
                            raise Exception("Unexpected error message for invalid wpsPbc: " + str(e))

                    self.loop.quit()
            elif new == "DISCONNECTED":
                if self.state == 1:
                    self.state = 2
                    self.netw_obj.enable(dbus_interface=WPAS_DBUS_OLD_NETWORK)
                elif self.state == 3:
                    self.state = 4
                    if_obj.selectNetwork(dbus_interface=WPAS_DBUS_OLD_IFACE)
                elif self.state == 5:
                    self.state = 6
                    if_obj.selectNetwork(self.path,
                                         dbus_interface=WPAS_DBUS_OLD_IFACE)

        def run_connect(self, *args):
            logger.debug("run_connect")
            path = if_obj.addNetwork(dbus_interface=WPAS_DBUS_OLD_IFACE)
            netw_obj = bus.get_object(WPAS_DBUS_OLD_SERVICE, path)
            netw_obj.disable(dbus_interface=WPAS_DBUS_OLD_NETWORK)
            params = dbus.Dictionary({ 'ssid': ssid,
                                       'key_mgmt': 'WPA-PSK',
                                       'psk': passphrase,
                                       'scan_freq': 2412 },
                                     signature='sv')
            netw_obj.set(params, dbus_interface=WPAS_DBUS_OLD_NETWORK)
            netw_obj.enable(dbus_interface=WPAS_DBUS_OLD_NETWORK)
            self.path = path
            self.netw_obj = netw_obj
            return False

        def success(self):
            return self.state == 7

    with TestDbusConnect(bus) as t:
        if not t.success():
            raise Exception("Expected signals not seen")

    if len(dev[0].list_networks()) != 0:
        raise Exception("Unexpected network")

def test_dbus_old_connect_eap(dev, apdev):
    """The old D-Bus interface - add an EAP network and connect"""
    (bus,wpas_obj,path,if_obj) = prepare_dbus(dev[0])

    ssid = "test-wpa2-eap"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    hapd = hostapd.add_ap(apdev[0], params)

    class TestDbusConnect(TestDbus):
        def __init__(self, bus):
            TestDbus.__init__(self, bus)
            self.connected = False
            self.certification_received = False

        def __enter__(self):
            gobject.timeout_add(1, self.run_connect)
            gobject.timeout_add(15000, self.timeout)
            self.add_signal(self.stateChange, WPAS_DBUS_OLD_IFACE,
                            "StateChange")
            self.add_signal(self.certification, WPAS_DBUS_OLD_IFACE,
                            "Certification")
            self.loop.run()
            return self

        def stateChange(self, new, old):
            logger.debug("stateChange: %s --> %s" % (old, new))
            if new == "COMPLETED":
                self.connected = True
                self.loop.quit()

        def certification(self, depth, subject, hash, cert_hex):
            logger.debug("certification: depth={} subject={} hash={} cert_hex={}".format(depth, subject, hash, cert_hex))
            self.certification_received = True

        def run_connect(self, *args):
            logger.debug("run_connect")
            path = if_obj.addNetwork(dbus_interface=WPAS_DBUS_OLD_IFACE)
            netw_obj = bus.get_object(WPAS_DBUS_OLD_SERVICE, path)
            params = dbus.Dictionary({ 'ssid': ssid,
                                       'key_mgmt': 'WPA-EAP',
                                       'eap': 'TTLS',
                                       'anonymous_identity': 'ttls',
                                       'identity': 'pap user',
                                       'ca_cert': 'auth_serv/ca.pem',
                                       'phase2': 'auth=PAP',
                                       'password': 'password',
                                       'scan_freq': 2412 },
                                     signature='sv')
            netw_obj.set(params, dbus_interface=WPAS_DBUS_OLD_NETWORK)
            netw_obj.enable(dbus_interface=WPAS_DBUS_OLD_NETWORK)
            self.path = path
            self.netw_obj = netw_obj
            return False

        def success(self):
            return self.connected and self.certification_received

    with TestDbusConnect(bus) as t:
        if not t.success():
            raise Exception("Expected signals not seen")

def test_dbus_old_network_set(dev, apdev):
    """The old D-Bus interface and network set method"""
    (bus,wpas_obj,path,if_obj) = prepare_dbus(dev[0])

    path = if_obj.addNetwork(dbus_interface=WPAS_DBUS_OLD_IFACE)
    netw_obj = bus.get_object(WPAS_DBUS_OLD_SERVICE, path)
    netw_obj.disable(dbus_interface=WPAS_DBUS_OLD_NETWORK)

    params = dbus.Dictionary({ 'priority': dbus.UInt64(1) }, signature='sv')
    try:
        netw_obj.set(params, dbus_interface=WPAS_DBUS_OLD_NETWORK)
        raise Exception("set succeeded with unexpected type")
    except dbus.exceptions.DBusException, e:
        if "InvalidOptions" not in str(e):
            raise Exception("Unexpected error message for unexpected type: " + str(e))

def test_dbus_old_wps_pbc(dev, apdev):
    """The old D-Bus interface and WPS/PBC"""
    try:
        _test_dbus_old_wps_pbc(dev, apdev)
    finally:
        dev[0].request("SET wps_cred_processing 0")

def _test_dbus_old_wps_pbc(dev, apdev):
    (bus,wpas_obj,path,if_obj) = prepare_dbus(dev[0])

    dev[0].flush_scan_cache()
    hapd = start_ap(apdev[0])
    hapd.request("WPS_PBC")
    bssid = apdev[0]['bssid']
    dev[0].scan_for_bss(bssid, freq="2412")
    dev[0].request("SET wps_cred_processing 2")

    for arg in [ 123, "123" ]:
        try:
            if_obj.wpsPbc(arg, dbus_interface=WPAS_DBUS_OLD_IFACE)
            raise Exception("Invalid wpsPbc arguments accepted: " + str(arg))
        except dbus.exceptions.DBusException, e:
            if not str(e).startswith("fi.epitest.hostap.WPASupplicant.InvalidOptions"):
                raise Exception("Unexpected error message for invalid wpsPbc: " + str(e))

    class TestDbusWps(TestDbusOldWps):
        def __init__(self, bus, pbc_param):
            TestDbusOldWps.__init__(self, bus)
            self.pbc_param = pbc_param

        def run_wps(self, *args):
            logger.debug("run_wps: pbc_param=" + self.pbc_param)
            if_obj.wpsPbc(self.pbc_param, dbus_interface=WPAS_DBUS_OLD_IFACE)
            return False

    with TestDbusWps(bus, "any") as t:
        if not t.success():
            raise Exception("Expected signals not seen")

    res = if_obj.scanResults(dbus_interface=WPAS_DBUS_OLD_IFACE)
    if len(res) != 1:
        raise Exception("Unexpected number of scan results: " + str(res))
    for i in range(1):
        logger.debug("Scan result BSS path: " + res[i])
        bss_obj = bus.get_object(WPAS_DBUS_OLD_SERVICE, res[i])
        bss = bss_obj.properties(dbus_interface=WPAS_DBUS_OLD_BSSID,
                                 byte_arrays=True)
        logger.debug("BSS: " + str(bss))

    dev[0].wait_connected(timeout=10)
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected(timeout=10)
    dev[0].request("FLUSH")

    hapd.request("WPS_PBC")
    dev[0].scan_for_bss(bssid, freq="2412")

    with TestDbusWps(bus, bssid) as t:
        if not t.success():
            raise Exception("Expected signals not seen")

    dev[0].wait_connected(timeout=10)
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected(timeout=10)

    hapd.disable()
    dev[0].flush_scan_cache()

def test_dbus_old_wps_pin(dev, apdev):
    """The old D-Bus interface and WPS/PIN"""
    try:
        _test_dbus_old_wps_pin(dev, apdev)
    finally:
        dev[0].request("SET wps_cred_processing 0")

def _test_dbus_old_wps_pin(dev, apdev):
    (bus,wpas_obj,path,if_obj) = prepare_dbus(dev[0])

    hapd = start_ap(apdev[0])
    hapd.request("WPS_PIN any 12345670")
    bssid = apdev[0]['bssid']
    dev[0].scan_for_bss(bssid, freq="2412")
    dev[0].request("SET wps_cred_processing 2")

    for arg in [ (123, "12345670"),
                 ("123", "12345670") ]:
        try:
            if_obj.wpsPin(arg[0], arg[1], dbus_interface=WPAS_DBUS_OLD_IFACE)
            raise Exception("Invalid wpsPin arguments accepted: " + str(arg))
        except dbus.exceptions.DBusException, e:
            if not str(e).startswith("fi.epitest.hostap.WPASupplicant.InvalidOptions"):
                raise Exception("Unexpected error message for invalid wpsPbc: " + str(e))

    class TestDbusWps(TestDbusOldWps):
        def __init__(self, bus, bssid, pin):
            TestDbusOldWps.__init__(self, bus)
            self.bssid = bssid
            self.pin = pin

        def run_wps(self, *args):
            logger.debug("run_wps %s %s" % (self.bssid, self.pin))
            pin = if_obj.wpsPin(self.bssid, self.pin,
                                dbus_interface=WPAS_DBUS_OLD_IFACE)
            if len(self.pin) == 0:
                h = hostapd.Hostapd(apdev[0]['ifname'])
                h.request("WPS_PIN any " + pin)
            return False

    with TestDbusWps(bus, bssid, "12345670") as t:
        if not t.success():
            raise Exception("Expected signals not seen")

    dev[0].wait_connected(timeout=10)
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected(timeout=10)
    dev[0].request("FLUSH")

    dev[0].scan_for_bss(bssid, freq="2412")

    with TestDbusWps(bus, "any", "") as t:
        if not t.success():
            raise Exception("Expected signals not seen")

def test_dbus_old_wps_reg(dev, apdev):
    """The old D-Bus interface and WPS/Registar"""
    try:
        _test_dbus_old_wps_reg(dev, apdev)
    finally:
        dev[0].request("SET wps_cred_processing 0")

def _test_dbus_old_wps_reg(dev, apdev):
    (bus,wpas_obj,path,if_obj) = prepare_dbus(dev[0])

    hapd = start_ap(apdev[0])
    bssid = apdev[0]['bssid']
    dev[0].scan_for_bss(bssid, freq="2412")
    dev[0].request("SET wps_cred_processing 2")

    for arg in [ (123, "12345670"),
                 ("123", "12345670") ]:
        try:
            if_obj.wpsReg(arg[0], arg[1], dbus_interface=WPAS_DBUS_OLD_IFACE)
            raise Exception("Invalid wpsReg arguments accepted: " + str(arg))
        except dbus.exceptions.DBusException, e:
            if not str(e).startswith("fi.epitest.hostap.WPASupplicant.InvalidOptions"):
                raise Exception("Unexpected error message for invalid wpsPbc: " + str(e))

    class TestDbusWps(TestDbusOldWps):
        def run_wps(self, *args):
            logger.debug("run_wps")
            if_obj.wpsReg(bssid, "12345670", dbus_interface=WPAS_DBUS_OLD_IFACE)
            return False

    with TestDbusWps(bus) as t:
        if not t.success():
            raise Exception("Expected signals not seen")

    dev[0].wait_connected(timeout=10)

def test_dbus_old_wps_oom(dev, apdev):
    """The old D-Bus interface and WPS (OOM)"""
    (bus,wpas_obj,path,if_obj) = prepare_dbus(dev[0])
    bssid = apdev[0]['bssid']

    with alloc_fail_dbus(dev[0], 1,
                         "=wpa_config_add_network;wpas_dbus_iface_wps_pbc",
                         "wpsPbc",
                         "WpsPbcError: Could not start PBC negotiation"):
        if_obj.wpsPbc("any", dbus_interface=WPAS_DBUS_OLD_IFACE)

    with alloc_fail_dbus(dev[0], 1,
                         "=wpa_config_add_network;wpas_dbus_iface_wps_pin",
                         "wpsPin", "WpsPinError: Could not init PIN"):
        if_obj.wpsPin("any", "", dbus_interface=WPAS_DBUS_OLD_IFACE)

    with alloc_fail_dbus(dev[0], 1,
                         "=wpa_config_add_network;wpas_dbus_iface_wps_reg",
                         "wpsReg",
                         "WpsRegError: Could not request credentials"):
        if_obj.wpsReg(bssid, "12345670", dbus_interface=WPAS_DBUS_OLD_IFACE)

def test_dbus_old_network_set_oom(dev, apdev):
    """The old D-Bus interface and network set method (OOM)"""
    (bus,wpas_obj,path,if_obj) = prepare_dbus(dev[0])

    with alloc_fail_dbus(dev[0], 1,
                         "=wpa_config_add_network;wpas_dbus_iface_add_network",
                         "addNetwork",
                         "AddNetworkError: wpa_supplicant could not add"):
        if_obj.addNetwork(dbus_interface=WPAS_DBUS_OLD_IFACE)

    path = if_obj.addNetwork(dbus_interface=WPAS_DBUS_OLD_IFACE)
    netw_obj = bus.get_object(WPAS_DBUS_OLD_SERVICE, path)
    netw_obj.disable(dbus_interface=WPAS_DBUS_OLD_NETWORK)

    with alloc_fail_dbus(dev[0], 1,
                         "_wpa_dbus_dict_fill_value_from_variant;wpas_dbus_iface_set_network",
                         "set", "InvalidOptions"):
        params = dbus.Dictionary({ 'ssid': "foo" }, signature='sv')
        netw_obj.set(params, dbus_interface=WPAS_DBUS_OLD_NETWORK)

    tests = [ { 'identity': dbus.ByteArray([ 1, 2 ]) },
              { 'scan_freq': dbus.UInt32(2412) },
              { 'priority': dbus.Int32(0) },
              { 'identity': "user" },
              { 'eap': "TLS" }]
    for arg in tests:
        with alloc_fail_dbus(dev[0], 1, "=wpas_dbus_iface_set_network",
                             "set", "InvalidOptions"):
            params = dbus.Dictionary(arg, signature='sv')
            netw_obj.set(params, dbus_interface=WPAS_DBUS_OLD_NETWORK)
