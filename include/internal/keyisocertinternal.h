/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once 

#ifdef KEYISO_TEST_WINDOWS
typedef unsigned char uuid_t[16];
# else
#include <uuid/uuid.h>
# endif

#include <openssl/x509.h>

// Certificates
int KeyIsoP_install_image_certs(
    const uuid_t correlationId);
    
const char *KeyIsoP_get_cert_ctrl_title(
    int ctrl,
    int location);

int KeyIsoP_load_pfx_certs(
    const uuid_t correlationId,
    int pfxLength,
    const unsigned char *pfxBytes,
    X509 **cert,
    STACK_OF(X509) **ca);       // Optional

int KeyIsoP_pem_from_certs(
    const uuid_t correlationId,
    X509 *cert,                     // Optional
    STACK_OF(X509) *ca,             // Optional
    int *pemCertLength,             // Excludes NULL terminator
    char **pemCert);                // KeyIso_free()

int KeyIso_load_pfx_pubkey(
    const uuid_t correlationId,
    int pfxLength,
    const unsigned char *pfxBytes,
    EVP_PKEY **pkey,
    X509 **cert,                    // Optional
    STACK_OF(X509) **ca);           // Optional

int KeyIso_load_pem_pubkey(
    const uuid_t correlationId,
    int certLength,
    const unsigned char *certBytes,
    EVP_PKEY **pkey,
    X509 **cert,                    // Optional
    STACK_OF(X509) **ca);           // Optional

/*
//   Version
//   Installs service version file inside the cert store dir
*/
int KeyIsoP_install_service_version(
const uuid_t correlationId);