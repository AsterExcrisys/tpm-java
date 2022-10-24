#!/bin/bash

# Generate certificate
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 10000 -out certificate.pem
# Export private and public key to a PKCS12 file
openssl pkcs12 -inkey key.pem -in certificate.pem -export -passout pass:pass1234 -out certificate.p12