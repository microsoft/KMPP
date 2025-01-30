#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Set variables
PRIVATE_KEY="private.key"
CERTIFICATE="certificate.crt"
PFX_FILE="certificate.pfx"
PASSWORD="example"

# Generate a private key
openssl genpkey -algorithm RSA -out $PRIVATE_KEY

# Generate a self-signed certificate
openssl req -new -x509 -key $PRIVATE_KEY -out $CERTIFICATE -days 365 -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=example.com"

# Generate the PFX file
openssl pkcs12 -export -out $PFX_FILE -inkey $PRIVATE_KEY -in $CERTIFICATE -passout pass:$PASSWORD

echo "PFX file generated: $PFX_FILE"