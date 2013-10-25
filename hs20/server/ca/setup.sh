#!/bin/sh

if [ -z "$OPENSSL" ]; then
    OPENSSL=openssl
fi
export OPENSSL_CONF=$PWD/openssl.cnf
PASS=whatever

fail()
{
    echo "$*"
    exit 1
}

echo
echo "---[ Root CA ]----------------------------------------------------------"
echo

cat openssl-root.cnf | sed "s/#@CN@/commonName_default = Hotspot 2.0 Trust Root CA - 99/" > openssl.cnf.tmp
mkdir -p rootCA/certs rootCA/crl rootCA/newcerts rootCA/private
touch rootCA/index.txt
if [ -e rootCA/private/cakey.pem ]; then
    echo " * Use existing Root CA"
else
    echo " * Generate Root CA private key"
    $OPENSSL req -config openssl.cnf.tmp -batch -new -newkey rsa:4096 -keyout rootCA/private/cakey.pem -out rootCA/careq.pem || fail "Failed to generate Root CA private key"
    echo " * Sign Root CA certificate"
    $OPENSSL ca -config openssl.cnf.tmp -md sha256 -create_serial -out rootCA/cacert.pem -days 10957 -batch -keyfile rootCA/private/cakey.pem -passin pass:$PASS -selfsign -extensions v3_ca -outdir rootCA/newcerts -infiles rootCA/careq.pem || fail "Failed to sign Root CA certificate"
fi
if [ ! -e rootCA/crlnumber ]; then
    echo 00 > rootCA/crlnumber
fi

echo
echo "---[ Intermediate CA ]--------------------------------------------------"
echo

cat openssl.cnf | sed "s/#@CN@/commonName_default = w1.fi Hotspot 2.0 Intermediate CA/" > openssl.cnf.tmp
mkdir -p demoCA/certs demoCA/crl demoCA/newcerts demoCA/private
touch demoCA/index.txt
if [ -e demoCA/private/cakey.pem ]; then
    echo " * Use existing Intermediate CA"
else
    echo " * Generate Intermediate CA private key"
    $OPENSSL req -config openssl.cnf.tmp -batch -new -newkey rsa:2048 -keyout demoCA/private/cakey.pem -out demoCA/careq.pem || fail "Failed to generate Intermediate CA private key"
    echo " * Sign Intermediate CA certificate"
    $OPENSSL ca -config openssl.cnf.tmp -md sha256 -create_serial -out demoCA/cacert.pem -days 3652 -batch -keyfile rootCA/private/cakey.pem -cert rootCA/cacert.pem -passin pass:$PASS -extensions v3_ca -infiles demoCA/careq.pem || fail "Failed to sign Intermediate CA certificate"
    # horrible from security view point, but for testing purposes since OCSP responder does not seem to support -passin
    openssl rsa -in demoCA/private/cakey.pem -out demoCA/private/cakey-plain.pem -passin pass:$PASS
fi
if [ ! -e demoCA/crlnumber ]; then
    echo 00 > demoCA/crlnumber
fi

echo
echo "OCSP responder"
echo

cat openssl.cnf | sed "s/#@CN@/commonName_default = ocsp.w1.fi/" > openssl.cnf.tmp
$OPENSSL req -config $PWD/openssl.cnf.tmp -batch -new -newkey rsa:2048 -nodes -out ocsp.csr -keyout ocsp.key -extensions v3_OCSP
$OPENSSL ca -config $PWD/openssl.cnf.tmp -batch -md sha256 -keyfile demoCA/private/cakey.pem -passin pass:$PASS -in ocsp.csr -out ocsp.pem -days 730 -extensions v3_OCSP

echo
echo "---[ Server - to be revoked ] ------------------------------------------"
echo

cat openssl.cnf | sed "s/#@CN@/commonName_default = osu-revoked.w1.fi/" > openssl.cnf.tmp
$OPENSSL req -config $PWD/openssl.cnf.tmp -batch -new -newkey rsa:2048 -nodes -out server-revoked.csr -keyout server-revoked.key
$OPENSSL ca -config $PWD/openssl.cnf.tmp -batch -md sha256 -in server-revoked.csr -out server-revoked.pem -key $PASS -days 730 -extensions ext_server
$OPENSSL ca -revoke server-revoked.pem -key $PASS

echo
echo "---[ Server - with client ext key use ] ---------------------------------"
echo

cat openssl.cnf | sed "s/#@CN@/commonName_default = osu-client.w1.fi/" > openssl.cnf.tmp
$OPENSSL req -config $PWD/openssl.cnf.tmp -batch -new -newkey rsa:2048 -nodes -out server-client.csr -keyout server-client.key
$OPENSSL ca -config $PWD/openssl.cnf.tmp -batch -md sha256 -in server-client.csr -out server-client.pem -key $PASS -days 730 -extensions ext_client

echo
echo "---[ User ]-------------------------------------------------------------"
echo

cat openssl.cnf | sed "s/#@CN@/commonName_default = User/" > openssl.cnf.tmp
$OPENSSL req -config $PWD/openssl.cnf.tmp -batch -new -newkey rsa:2048 -nodes -out user.csr -keyout user.key
$OPENSSL ca -config $PWD/openssl.cnf.tmp -batch -md sha256 -in user.csr -out user.pem -key $PASS -days 730 -extensions ext_client

echo
echo "---[ Server ]-----------------------------------------------------------"
echo

ALT="DNS:osu.w1.fi"
ALT="$ALT,otherName:1.3.6.1.4.1.40808.1.1.1;UTF8String:engw1.fi TESTING USE"
ALT="$ALT,otherName:1.3.6.1.4.1.40808.1.1.1;UTF8String:finw1.fi TESTIKÄYTTÖ"

cat openssl.cnf |
	sed "s/#@CN@/commonName_default = osu.w1.fi/" |
	sed "s/^##organizationalUnitName/organizationalUnitName/" |
	sed "s/#@OU@/organizationalUnitName_default = Hotspot 2.0 Online Sign Up Server/" |
	sed "s/#@ALTNAME@/subjectAltName=critical,$ALT/" \
	> openssl.cnf.tmp
echo $OPENSSL req -config $PWD/openssl.cnf.tmp -batch -sha256 -new -newkey rsa:2048 -nodes -out server.csr -keyout server.key -reqexts v3_osu_server
$OPENSSL req -config $PWD/openssl.cnf.tmp -batch -sha256 -new -newkey rsa:2048 -nodes -out server.csr -keyout server.key -reqexts v3_osu_server || fail "Failed to generate server request"
$OPENSSL ca -config $PWD/openssl.cnf.tmp -batch -md sha256 -in server.csr -out server.pem -key $PASS -days 730 -extensions ext_server -policy policy_osu_server || fail "Failed to sign server certificate"

#dump logotype details for debugging
$OPENSSL x509 -in server.pem -out server.der -outform DER
openssl asn1parse -in server.der -inform DER | grep HEX | tail -1 | sed 's/.*://' | xxd -r -p > logo.der
openssl asn1parse -in logo.der -inform DER > logo.asn1


echo
echo "---[ CRL ]---------------------------------------------------------------"
echo

$OPENSSL ca -config $PWD/openssl.cnf -gencrl -md sha256 -out demoCA/crl/crl.pem -passin pass:$PASS

echo
echo "---[ Verify ]------------------------------------------------------------"
echo

$OPENSSL verify -CAfile rootCA/cacert.pem demoCA/cacert.pem
$OPENSSL verify -CAfile rootCA/cacert.pem -untrusted demoCA/cacert.pem *.pem

cat rootCA/cacert.pem demoCA/cacert.pem > ca.pem
