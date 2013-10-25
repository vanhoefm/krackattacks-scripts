#!/bin/sh

for i in server-client server server-revoked user ocsp; do
    rm -f $i.csr $i.key $i.pem
done

rm -f openssl.cnf.tmp
rm -r demoCA
rm -f ca.pem logo.asn1 logo.der server.der ocsp-server-cache.der
#rm -r rootCA
