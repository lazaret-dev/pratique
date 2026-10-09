#!/bin/sh
# A throwaway P-256 CA and a certificate for localhost (127.0.0.1) signed by it, for the TLS part of the comparison: what a
# real server's chain of two ECDSA certificates costs a client to check. Written to certs/; nothing else is touched.
set -eu
cd "$(dirname "$0")"
mkdir -p certs
cd certs
openssl ecparam -genkey -name prime256v1 -noout -out ca.key 2>/dev/null
openssl req -x509 -new -key ca.key -sha256 -days 3650 -subj "/CN=bench CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.pem 2>/dev/null
openssl ecparam -genkey -name prime256v1 -noout | openssl pkcs8 -topk8 -nocrypt -out leaf.key
openssl req -new -key leaf.key -subj "/CN=localhost" -out leaf.csr 2>/dev/null
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n' > leaf.ext
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -sha256 -days 825 -extfile leaf.ext -out leaf.pem 2>/dev/null
cat leaf.pem ca.pem > chain.pem
rm -f ca.key leaf.csr leaf.ext ca.srl
openssl verify -CAfile ca.pem leaf.pem
