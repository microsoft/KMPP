#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Exit immediately if a command exits with a non-zero status
set -e

# Runs from root directory
mkdir -p certs
cd certs

# Define output file
OUTPUT_FILE="certs.pem"


# Function to generate a certificate
generate_cert() {
    local cert_name=$1
    local subject=$2

    # Generate a private key
    openssl genpkey -algorithm RSA -out ${cert_name}.key

    # Generate a certificate signing request (CSR)
    openssl req -new -key ${cert_name}.key -out ${cert_name}.csr -subj "$subject"

    # Generate a self-signed certificate
    openssl x509 -req -days 365 -in ${cert_name}.csr -signkey ${cert_name}.key -out ${cert_name}.crt

    # Append the certificate to the output file
    echo "# Certificate ${cert_name}" >> $OUTPUT_FILE
    cat ${cert_name}.crt >> $OUTPUT_FILE

    # Clean up temporary files
    rm -f ${cert_name}.key ${cert_name}.csr
    mv ${cert_name}.crt ${cert_name}
}

# Generate certificates
for i in {1..5}; do
    generate_cert "dummy${i}.0" "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=dummy${i}.0"
done

# Create certs.version file with the current date
VERSION_FILE="certs.version"
CURRENT_DATE=$(date +%Y%m%d)
echo "imagecerts_${CURRENT_DATE}.installed" > $VERSION_FILE

echo "Certificates generated and written to $OUTPUT_FILE"
echo "Version file created at $VERSION_FILE with date $CURRENT_DATE"
