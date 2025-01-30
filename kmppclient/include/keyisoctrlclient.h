/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once 

#include <openssl/x509.h>

#ifdef KEYISO_TEST_WINDOWS
typedef unsigned char uuid_t[16];
#else
#include <uuid/uuid.h>
#endif

#ifdef  __cplusplus
extern "C" {
#endif

// Return:
//  +1 - Success with all certificates removed.
//  -1 - Partial Success. Removed at least one certificate. Failed to
//       remove one or more certificates.
//   0 - Error, unable to remove any certificates.
int KeyIso_remove_trusted_certs(
    const uuid_t correlationId,
    int certFormat,
    int certLength,
    const unsigned char *certBytes);

// Return:
//  +1 - Success with all certificates imported.
//  -1 - Partial Success. Imported at least one certificate. Failed to
//       import one or more certificates.
//   0 - Error, unable to import any certificates.
int KeyIso_import_disallowed_certs(
    const uuid_t correlationId,
    int certFormat,
    int certLength,
    const unsigned char *certBytes);

// Return:
//  +1 - Success with all certificates removed.
//  -1 - Partial Success. Removed at least one certificate. Failed to
//       remove one or more certificates.
//   0 - Error, unable to remove any certificates.
int KeyIso_remove_disallowed_certs(
    const uuid_t correlationId,
    int certFormat,
    int certLength,
    const unsigned char *certBytes);
    
// Return:
//  1 - Certificate is disallowed.
//  0 - Certificate not found in the disallowed certificates directory.
int KeyIso_is_disallowed_cert(
    const uuid_t correlationId,
    X509 *cert);

// Return:
//  +1 - Success with all certificates imported.
//  -1 - Partial Success. Imported at least one certificate. Failed to
//       import one or more certificates.
//   0 - Error, unable to import any certificates.
int KeyIso_import_trusted_certs(
    const uuid_t correlationId,
    int certFormat,
    int certLength,
    const unsigned char *certBytes);
    

#ifdef  __cplusplus
}
#endif