#!/bin/bash

# Changes these CN's to match your hosts in your environment if needed.
SERVER_CN=localhost

echo Generate CA key:
openssl genrsa -passout pass:1111 -des3 -out ca.key 4096
echo Generate CA certificate:
# Generates ca.crt which is the trustCertCollectionFile
openssl req -passin pass:1111 -new -x509 -days 365 -key ca.key -out ca.crt -subj "/CN=${SERVER_CN}"

echo Generate server key:
openssl genrsa -passout pass:1111 -des3 -out ttp.key 4096
echo Generate server signing request:
openssl req -passin pass:1111 -new -key ttp.key -out ttp.csr -subj "/CN=${SERVER_CN}"
echo Self-signed server certificate:
# Generates ttp.crt which is the certChainFile for the server
openssl x509 -req -passin pass:1111 -days 365 -in ttp.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out ttp.crt 
echo Remove passphrase from server key:
openssl rsa -passin pass:1111 -in ttp.key -out ttp.key
# Generates ttp.pem which is the privateKeyFile for the Server
openssl pkcs8 -topk8 -nocrypt -in ttp.key -out ttp.pem