var conf_ap_scan = -1;
var conf_wired = false;

function configure_os()
{
  var os = document.os_driver.os.value;
  document.os_driver.driver.disabled = false;
  document.os_driver.driver[0] = new Option("Select your driver", "select");
  if (os == "linux") {
    document.os_driver.driver[1] = new Option("madwifi", "madwifi");
    document.os_driver.driver[2] = new Option("Host AP (Prism2/2.5/3)", "hostap");
    document.os_driver.driver[3] = new Option("Intel ipw2100/2200", "ipw");
    document.os_driver.driver[4] = new Option("Any wired Ethernet driver", "linux_wired");
    document.os_driver.driver[5] = new Option("Other", "other linux");
  } else if (os == "windows") {
    document.os_driver.driver[1] = new Option("Any wireless NDIS driver", "ndis_wireless");
    document.os_driver.driver[2] = new Option("Any wired (Ethernet) NDIS driver", "ndis_wired");
  }
}


function configure_driver()
{
  var drv = document.os_driver.driver.value;
  var t = document.getElementById("os_desc");

  t.innerHTML = "";
  t.style.visibility = "hidden";

  if (drv == "ndis_wireless") {
    conf_ap_scan = 2;
    t.innerHTML = "All wireless Windows NDIS drivers support AP selection " +
      "and roaming, so in most cases, configuring the driver to take care " +
      "of this by setting ap_scan=2 is the recommended configuration for " +
      "Windows.";
    t.style.visibility = "visible";
  } else if (drv == "ndis_wired" || drv == "linux_wired") {
    conf_ap_scan = 0;
    conf_wired = true;
  } else
    conf_ap_scan = 1;

  update_conf();
}


function update_encr()
{
  var auth = document.authmode.auth.value;
  var t = document.getElementById("encr_desc");

  for (i = 0; i < 6; i++)
    document.encrmode.encr[i] = null;
  if (auth == "open") {
    document.encrmode.encr[0] = new Option("None (unencrypted open network)", "none");
    document.encrmode.encr.selectedIndex = 0;
    t.innerHTML = "Based on the selected authentication mode (open network), only 'None' is an allowed encryption mode.";
    t.style.visibility = "visible";
  } else if (auth == "wep") {
    document.encrmode.encr[0] = new Option("WEP (Wired Equivalent Privacy)", "wep");
    document.encrmode.encr.selectedIndex = 0;
    t.innerHTML = "Based on the selected authentication mode (WEP), only 'WEP' is an allowed encryption mode.";
    t.style.visibility = "visible";
  } else if (auth == "ieee8021x") {
    document.encrmode.encr[0] = new Option("None (unencrypted open network)", "none");
    document.encrmode.encr[1] = new Option("WEP (Wired Equivalent Privacy)", "wep");
    document.encrmode.encr.selectedIndex = conf_wired ? 0 : 1;
    t.innerHTML = "Based on the selected authentication mode (IEEE 802.1X), either 'None' or 'WEP' can be selected. In wireless networks, this is most likely going to be 'WEP' and in wired networks, only 'None' is allowed.";
    t.style.visibility = "visible";
  } else if (auth == "wpa-psk" || auth == "wpa-eap") {
    document.encrmode.encr[0] = new Option("TKIP (Temporal Key Integrity Protocol)", "tkip");
    document.encrmode.encr[1] = new Option("CCMP (AES Counter-Mode/CBC-MAC Protocol)", "ccmp");
    document.encrmode.encr.selectedIndex = (document.authmode.auth2.value == "wpa1") ? 0 : 1;
    t.innerHTML = "Based on the selected authentication mode (WPA/WPA2), either 'TKIP' or 'CCMP' can be selected. Most WPA networks are using TKIP whereas WPA2 defaults to CCMP.";
    t.style.visibility = "visible";
  } else {
    t.innerHTML = "";
    t.style.visibility = "hidden";
  }
}


function update_cred()
{
  var auth = document.authmode.auth.value;
  var t;

  t = document.getElementById("cred_unknown");
  t.style.display = "none";
  t = document.getElementById("cred_open");
  t.style.display = "none";
  t = document.getElementById("cred_wep");
  t.style.display = "none";
  t = document.getElementById("cred_psk");
  t.style.display = "none";
  t = document.getElementById("cred_eap");
  t.style.display = "none";

  if (auth == "open") {
    t = document.getElementById("cred_open");
    t.style.display = "block";
  } else if (auth == "wep") {
    t = document.getElementById("cred_wep");
    t.style.display = "block";
  } else if (auth == "wpa-psk") {
    t = document.getElementById("cred_psk");
    t.style.display = "block";
  } else if (auth == "ieee8021x" || auth == "wpa-eap") {
    t = document.getElementById("cred_eap");
    t.style.display = "block";
  } else {
    t = document.getElementById("cred_unknown");
    t.style.display = "block";
  }
}


function configure_auth()
{
  var auth = document.authmode.auth.value;

  document.authmode.auth2[0] = null;
  document.authmode.auth2[1] = null;
  document.authmode.auth2.disabled = true;
  if (auth == "wep") {
    document.authmode.auth2[0] = new Option("Open System authentication", "open");
    document.authmode.auth2[1] = new Option("Shared Key authentication", "shared");
    document.authmode.auth2.disabled = false;
  } else if (auth == "wpa-psk" || auth == "wpa-eap") {
    document.authmode.auth2[0] = new Option("WPA (version 1)", "wpa1");
    document.authmode.auth2[1] = new Option("WPA2 (IEEE 802.11i)", "wpa2");
    document.authmode.auth2.disabled = false;
  }

  update_encr();
  update_cred();
  update_conf();
}


function configure_auth2()
{
  update_encr();
  update_conf();
}


function configure_encr()
{
  update_conf();
}


function configure_passphrase()
{
  var passphrase = document.cred_psk_form.passphrase.value;
  var psk = document.cred_psk_form.psk.value;
  var t = document.getElementById("cred_desc");

  if (psk.length && (psk.length != 64 || !is_hex(psk))) {
    t.innerHTML = "<p class=\"error\">Note: Invalid PSK</p>";
    t.style.visibility = "visible";
  } else if (psk.length == 0 && passphrase.length &&
	     (passphrase.length < 8 || passphrase.length > 63)) {
    t.innerHTML = "<p class=\"error\">Note: Invalid passphrase</p>";
    t.style.visibility = "visible";
  } else {
    t.innerHTML = "";
    t.style.visibility = "hidden";
  }

  if (psk.length) {
    document.cred_psk_form.passphrase.disabled = true;
    document.cred_psk_form.psk.disabled = false;
  } else if (passphrase.length) {
    document.cred_psk_form.passphrase.disabled = false;
    document.cred_psk_form.psk.disabled = true;
  } else {
    document.cred_psk_form.passphrase.disabled = false;
    document.cred_psk_form.psk.disabled = false;
  }

  update_conf();
}


function is_hex(s)
{
  if (s.length % 2)
    return false;

  for (i = 0; i < s.length; i++) {
    if (s[i] >= 'a' && s[i] <= 'f')
      continue;
    if (s[i] >= 'A' && s[i] <= 'F')
      continue;
    if (s[i] >= '0' && s[i] <= '9')
      continue;
    return false;
  }

  return true;
}


function valid_wep_key(key)
{
  if (key.length == 0)
    return true;

  if (key[0] == '"') {
    if (key[key.length - 1] != '"')
      return false;
    return (key.length == 5 + 2 || key.length == 13 + 2 ||
	    key.length == 16 + 2);
  }

  return (is_hex(key) &&
	  (key.length == 10 || key.length == 26 || key.length == 32));
}


function configure_wep()
{
  var t = document.getElementById("cred_desc");
  var txt = "";
  var wep;

  wep = document.cred_wep_form.wep0.value;
  if (!valid_wep_key(wep))
    txt += "<p class=\"error\">Note: Invalid WEP key: " + wep + "</p>\n";
  wep = document.cred_wep_form.wep1.value;
  if (!valid_wep_key(wep))
    txt += "<p class=\"error\">Note: Invalid WEP key: " + wep + "</p>\n";
  wep = document.cred_wep_form.wep2.value;
  if (!valid_wep_key(wep))
    txt += "<p class=\"error\">Note: Invalid WEP key: " + wep + "</p>\n";
  wep = document.cred_wep_form.wep3.value;
  if (!valid_wep_key(wep))
    txt += "<p class=\"error\">Note: Invalid WEP key: " + wep + "</p>\n";

  if (txt.length) {
    t.innerHTML = txt;
    t.style.visibility = "visible";
  } else if (t.style.visibility != "hidden")
    t.style.visibility = "hidden";

  update_conf();
}


function update_eap()
{
  var eap = document.cred_eap_form.eap.value;
  var n = 0;

  if (eap == "PEAP" || eap == "TTLS" || eap == "FAST") {
    document.cred_eap_form.phase2[n++] = new Option("EAP-MSCHAPv2", "MSCHAPV2");
    document.cred_eap_form.phase2.selectedIndex = n - 1;
    if (eap != "FAST") {
      document.cred_eap_form.phase2[n++] = new Option("EAP-GTC", "GTC");
      document.cred_eap_form.phase2[n++] = new Option("EAP-MD5", "MD5");
      document.cred_eap_form.phase2[n++] = new Option("EAP-TLS", "TLS");
      document.cred_eap_form.phase2[n++] = new Option("EAP-OTP", "OTP");
    }
    if (eap == "TTLS") {
      document.cred_eap_form.phase2[n++] = new Option("MSCHAPv2", "_MSCHAPV2");
      document.cred_eap_form.phase2.selectedIndex = n - 1;
      document.cred_eap_form.phase2[n++] = new Option("MSCHAP", "_MSCHAP");
      document.cred_eap_form.phase2[n++] = new Option("PAP", "_PAP");
      document.cred_eap_form.phase2[n++] = new Option("CHAP", "_CHAP");
    }
    document.cred_eap_form.phase2.disabled = false;
  } else {
    document.cred_eap_form.phase2.disabled = true;
  }

  for (i = 20; i >= n; i--)
    document.cred_eap_form.phase2[i] = null;

  update_eap2();
}


function update_eap2()
{
  var eap = document.cred_eap_form.eap.value;
  var password = false;
  var ca_cert = false;
  var user_cert = false;

  if (eap == "PEAP" || eap == "TTLS") {
    ca_cert = true;
    if (document.cred_eap_form.phase2.value == "TLS")
      user_cert = true;
    else
      password = true;
  } else if (eap == "FAST") {
    password = true;
  } else if (eap == "GTC") {
    password = true;
  } else if (eap == "LEAP" || eap == "MD5" || eap == "MSCHAPV2") {
    password = true;
  } else if (eap == "TLS") {
    ca_cert = true;
    user_cert = true;
  }

  if (eap == "TTLS") {
    document.cred_eap_form.anon_identity.disabled = false;
    document.cred_eap_form.anon_identity.value = "anonymous";
  } else if (eap == "FAST") {
    document.cred_eap_form.anon_identity.disabled = false;
    document.cred_eap_form.anon_identity.value = "FAST-000000000000";
  } else {
    document.cred_eap_form.anon_identity.disabled = true;
  }
  document.cred_eap_form.password.disabled = !password;
  if (ca_cert) {
    document.cred_eap_form.ca_cert.disabled = false;
    if (document.cred_eap_form.ca_cert.value.length == 0)
      document.cred_eap_form.ca_cert.value = "/etc/ca.pem";
  } else {
    document.cred_eap_form.ca_cert.disabled = true;
  }
  document.cred_eap_form.client_cert.disabled = !user_cert;
  document.cred_eap_form.private_key.disabled = !user_cert;
  document.cred_eap_form.private_key_passwd.disabled = !user_cert;

  if (eap == "FAST") {
    document.cred_eap_form.pac_file.disabled = false;
    if (document.cred_eap_form.pac_file.value.length == 0)
      document.cred_eap_form.pac_file.value = "/etc/fast.pac";
  } else {
    document.cred_eap_form.pac_file.disabled = true;
  }

  configure_eap();
}


function configure_eap()
{
  update_conf();
}


function update_conf()
{
  var t = document.getElementById("exampleconf");
  var txt = "";
  var indent = "&nbsp;&nbsp;&nbsp;&nbsp;";
  var ap_scan = conf_ap_scan;
  var drv = document.os_driver.driver.value;

  update_cred();

  if (document.network.hidden_ssid.checked && ap_scan == 1 &&
      drv != "hostap" && drv != "madwifi") {
    /* if the selected driver does not support scan_ssid, must use
     * ap_scan=2 mode with hidden SSIDs */
    txt += "# this driver requires ap_scan=2 mode when using hidden SSIDs<br>\n";
    ap_scan = 2;
  }

  switch (ap_scan) {
  case -1:
    txt += "# example configuration will be generated here<br>\n";
    break;
  case 0:
    txt += "# wired drivers do not use scanning<br>\n" +
      "ap_scan=0<br><br>\n";
    break;
  case 1:
    txt += "# request AP scanning and decide which AP to use<br>\n" +
      "ap_scan=1<br><br>\n";
    break;
  case 2:
    txt += "# request driver to take care of AP selection and roaming<br>\n" +
      "ap_scan=2<br><br>\n";
    break;
  }

  if (document.os_driver.os.value == "windows") {
    txt += "# enable control interface using local UDP socket<br>\n" +
      "ctrl_interface=udp<br>\n";
  } else {
    txt += "# enable control interface using UNIX domain sockets<br>\n" +
      "ctrl_interface=/var/run/wpa_supplicant<br>\n";
  }

  txt += "<br>\n" +
    "# you can include one or more network blocks here<br>\n" +
    "network={<br>\n";

  if (conf_wired) {
    txt += indent + "# wired network - must not configure SSID here<br>\n";
  } else {
    if (document.network.ssid.value.length == 0)
      txt += indent + "# must configure SSID here (Step 2)<br>\n";
    txt += indent + "ssid=\"" + document.network.ssid.value + "\"<br>\n";
    if (ap_scan == 1 && document.network.hidden_ssid.checked)
      txt += indent + "scan_ssid=1<br>\n";
  }

  var auth = document.authmode.auth.value;
  var auth2 = document.authmode.auth2.value;

  if (auth == "open" || auth == "wep")
    txt += indent + "key_mgmt=NONE<br>\n";
  else if (auth == "ieee8021x")
    txt += indent + "key_mgmt=IEEE8021X<br>\n";
  else if (auth == "wpa-psk")
    txt += indent + "key_mgmt=WPA-PSK<br>\n";
  else if (auth == "wpa-eap")
    txt += indent + "key_mgmt=WPA-EAP<br>\n";
  else
    txt += indent + "# must set key_mgmt here (Step 3)<br>\n";

  if (auth == "wep") {
    if (auth2 == "open")
      txt += indent + "auth_alg=OPEN<br>\n";
    else if (auth2 == "shared")
      txt += indent + "auth_alg=SHARED<br>\n";
  } else if (auth == "wpa-psk" || auth == "wpa-eap") {
    if (auth2 == "wpa1")
      txt += indent + "proto=WPA<br>\n";
    else if (auth2 == "wpa2")
      txt += indent + "proto=WPA2<br>\n";
    else
      txt += indent + "# WPA proto (v1/v2) should be configured here (Step 3)<br>\n";
  }


  if (auth == "wpa-psk" || auth == "wpa-eap") {
    var encr = document.encrmode.encr.value;
    if (encr == "tkip")
      txt += indent + "pairwise=TKIP<br>\n";
    else if (encr == "ccmp")
      txt += indent + "pairwise=CCMP<br>\n";
    else
      txt += indent + "# should configure pairwise encryption cipher (Step 4)<br>\n";
  }

  if (auth == "wep") {
    var wep;
    wep = document.cred_wep_form.wep0.value;
    if (wep.length)
      txt += indent + "wep_key0=" + wep + "<br>\n";
    wep = document.cred_wep_form.wep1.value;
    if (wep.length)
      txt += indent + "wep_key1=" + wep + "<br>\n";
    wep = document.cred_wep_form.wep2.value;
    if (wep.length)
      txt += indent + "wep_key2=" + wep + "<br>\n";
    wep = document.cred_wep_form.wep3.value;
    if (wep.length)
      txt += indent + "wep_key3=" + wep + "<br>\n";
    txt += indent + "wep_tx_keyidx=" + document.cred_wep_form.wep_tx_idx.value + "<br>\n";
  } else if (auth == "wpa-psk") {
    var passphrase = document.cred_psk_form.passphrase.value;
    var psk = document.cred_psk_form.psk.value;
    if (psk.length) {
      if (psk.length != 64)
	txt += indent + "# WPA PSK 64-character hex string<br>\n";
      txt += indent + "psk=" + psk + "<br>\n";
    } else {
      if (passphrase.length < 8)
	txt += indent + "# WPA passphrase must be at least 8 characters long<br>\n";
      if (passphrase.length > 63)
	txt += indent + "# WPA passphrase must be at most 63 characters long<br>\n";
      txt += indent + "psk=\"" + passphrase + "\"<br>\n";
    }
  } else if (auth == "ieee8021x" || auth == "wpa-eap") {
    var eap = document.cred_eap_form.eap.value;
    if (eap == "select")
      txt += indent + "# EAP method needs to be selected (Step 5)<br>\n";
    else
      txt += indent + "eap=" + eap + "<br>\n";

    var phase2 = document.cred_eap_form.phase2;
    var eap2 = phase2.value;
    if (eap == "PEAP" || eap == "TTLS" || eap == "FAST") {
      txt += indent + "phase2=\"auth";
      if (eap == "TTLS") {
	if (eap2[0] == '_') {
	  eap2 = eap2.substring(1);
	} else
	  txt += "eap";
      }
      txt += "=" + eap2 + "\"<br>\n";
    }

    var identity = document.cred_eap_form.identity.value;
    if (identity.length)
      txt += indent + "identity=\"" + identity + "\"<br>\n";

    var anon = document.cred_eap_form.anon_identity;
    if (!anon.disabled && anon.value.length)
      txt += indent + "anonymous_identity=\"" + anon.value + "\"<br>\n";

    var password = document.cred_eap_form.password;
    if (!password.disabled && password.value.length)
      txt += indent + "password=\"" + password.value + "\"<br>\n";

    var ca_cert = document.cred_eap_form.ca_cert;
    if (!ca_cert.disabled) {
      txt += indent + "ca_cert=\"" + ca_cert.value + "\"<br>\n";
      if (!phase2.disabled && eap2 == "TLS")
	txt += indent + "ca_cert2=\"" + ca_cert.value + "\"<br>\n";
    }

    var client_cert = document.cred_eap_form.client_cert;
    if (!client_cert.disabled) {
      var e = "";
      if (!phase2.disabled && eap2 == "TLS")
	e = "2";

      if (client_cert.value.length)
	txt += indent + "client_cert" + e + "=\"" + client_cert.value + "\"<br>\n";

      var key = document.cred_eap_form.private_key.value;
      if (key.length)
	txt += indent + "private_key" + e + "=\"" + key + "\"<br>\n";

      var passwd = document.cred_eap_form.private_key_passwd.value;
      if (passwd.length)
	txt += indent + "private_key_passwd" + e + "=\"" + passwd + "\"<br>\n";
    }

    var pac = document.cred_eap_form.pac_file;
    if (!pac.disabled && pac.value.length)
      txt += indent + "pac_file=\"" + pac.value + "\"<br>\n";
    if (eap == "FAST")
      txt += indent + "phase1=\"fast_provisioning=1\"<br>\n";
  }

  txt += "}<br>\n";


  txt += "</p>\n";

  t.innerHTML = txt;
}
