#!/bin/bash

if test \! -x ./generate.sh
then
  echo "Must be run from the resources directory"
  exit 1
fi
if test -z "$(command -v openssl)"
then
  echo "Need openssl."
  exit 1
fi

PASS="foobar"
VALIDITY_DAYS="7000"
RSA_BITS=4096

echo "Generating root ca."
openssl req -new -x509 -days "$VALIDITY_DAYS" -keyout ca.key -out ca.crt -subj "/C=NO/CN=CA" -passout "pass:$PASS"

CERT=cn-cert
cat > conf.conf <<EOT
[v3_ca]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
EOT
openssl genrsa -out "$CERT.key" "$RSA_BITS"
openssl req -new -subj "/CN=$CERT" -key "$CERT.key" -out "$CERT.csr"
openssl x509 -req -CA ca.crt -CAkey ca.key -in "$CERT.csr" -out "$CERT.crt" -extensions client -extensions v3_ca -extfile ./conf.conf -days "$VALIDITY_DAYS" -CAcreateserial -passin "pass:$PASS"

CERT=spiffe-cert
cat > conf.conf <<EOT
[v3_ca]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = DNS:foo.example.com, URI:spiffe://foo/ns/bar/sa/gazonk
EOT
openssl genrsa -out "$CERT.key" "$RSA_BITS"
openssl req -new -subj "/CN=$CERT" -key "$CERT.key" -out "$CERT.csr"
openssl x509 -req -CA ca.crt -CAkey ca.key -in "$CERT.csr" -out "$CERT.crt" -extensions client -extensions v3_ca -extfile ./conf.conf -days "$VALIDITY_DAYS" -CAcreateserial -passin "pass:$PASS"

rm -f -- ca.crt *.key *.csr *.srl conf.conf
