/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#ifdef KEYISO_TEST_WINDOWS
typedef unsigned char uuid_t[16];
#else
#include <uuid/uuid.h>
# endif

#include <openssl/x509.h>

#ifdef  __cplusplus
extern "C" {
#endif

// KEYISO Flags
#define KEYISO_EXCLUDE_ROOT_FLAG                          0x00000001
#define KEYISO_EXCLUDE_EXTRA_CA_FLAG                      0x00000002
#define KEYISO_EXCLUDE_END_FLAG                           0x00000004
#define KEYISO_IGNORE_DEPTH_ZERO_SELF_SIGNED_ERROR_FLAG   0x00000008
#define KEYISO_SKIP_VALIDATE_CERT                         0x00000010

// The key usage flags' values are intentionally non-sequential compared to the 
// existing flags to accommodate potential future flags related to certificates.
#define KEYISO_KEY_USAGE_SIGN_FLAG                        0x00001000
#define KEYISO_KEY_USAGE_ENCRYPT_FLAG                     0x00002000
#define KEYISO_KEY_USAGE_KEY_AGREEMENT_FLAG               0x00004000


#define KEYISO_CERT_FORMAT_DER         1
#define KEYISO_CERT_FORMAT_PEM         2
#define KEYISO_CERT_FORMAT_SST         3



/*
*  Implemented: keyisocert.c
*/

typedef struct KeyIso_cert_dir_st KEYISO_CERT_DIR;

// Returns directory handle or NULL on error.
KEYISO_CERT_DIR *KeyIso_open_trusted_cert_dir(
    const uuid_t correlationId,
    int keyisoFlags);

KEYISO_CERT_DIR*KeyIso_open_disallowed_cert_dir(
    const uuid_t correlationId,
    int keyisoFlags);

// Return:
//  +1 - Success with *cert updated
//  -1 - No more certs. *cert is set to NULL.
//   0 - Error
int KeyIso_read_cert_dir(
    KEYISO_CERT_DIR*certDir,
    X509 **cert);               // X509_free()

void KeyIso_close_cert_dir(
    KEYISO_CERT_DIR*certDir);


typedef struct KeyIso_verify_cert_ctx_st KEYISO_VERIFY_CERT_CTX;

KEYISO_VERIFY_CERT_CTX *KeyIso_create_verify_cert_ctx(
    const uuid_t correlationId);

void KeyIso_free_verify_cert_ctx(
    KEYISO_VERIFY_CERT_CTX *ctx);

typedef int (*KEYISO_PFN_VERIFY_CERT_CALLBACK)(
    const uuid_t correlationId,
    X509_STORE_CTX *storeCtx,
    int *verifyChainError,
    void *arg);

int KeyIso_register_verify_cert_callback(
    KEYISO_VERIFY_CERT_CTX *ctx,
    KEYISO_PFN_VERIFY_CERT_CALLBACK callback,
    void *arg);

void KeyIso_set_verify_cert_param(
    KEYISO_VERIFY_CERT_CTX *ctx,
    const X509_VERIFY_PARAM *param);

// Helper function for certificate verification.
// Create ctx with KeyIso_create_verify_cert_ctx,
// and call KeyIso_verify_cert2 for verification.
int KeyIso_validate_certificate(
    const uuid_t correlationId,
    int keyisoFlags,
    X509 *cert,
    STACK_OF(X509) *ca,             // Optional
    int *verifyChainError,
    STACK_OF(X509) **chain);        // Optional

// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to build chain
//
// Following keyisoFlags can be set to exclude certificates in the
// returned STACK_OF(X509) **chain.
//  #define KEYISO_EXCLUDE_ROOT_FLAG                          0x00000001
//  #define KEYISO_EXCLUDE_EXTRA_CA_FLAG                      0x00000002
//  #define KEYISO_EXCLUDE_END_FLAG                           0x00000004
//
// Following keyisoFlags can be set to allow self signed certificate
//  #define KEYISO_IGNORE_DEPTH_ZERO_SELF_SIGNED_ERROR_FLAG   0x00000008
int KeyIso_verify_cert2(
    KEYISO_VERIFY_CERT_CTX *ctx,   // Optional
    int keyisoFlags,
    X509 *cert,
    STACK_OF(X509) *ca,             // Optional
    int *verifyChainError,
    STACK_OF(X509) **chain);        // Optional

// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, other errors, such as, invalid input certificate.
//
// Following keyisoFlags can be set to exclude certificates in the
// returned PEM chain
//  #define KEYISO_EXCLUDE_ROOT_FLAG                          0x00000001
//  #define KEYISO_EXCLUDE_EXTRA_CA_FLAG                      0x00000002
//  #define KEYISO_EXCLUDE_END_FLAG                           0x00000004
//
// Following keyisoFlags can be set to allow self signed certificate
//  #define KEYISO_IGNORE_DEPTH_ZERO_SELF_SIGNED_ERROR_FLAG   0x00000008
int KeyIso_verify_cert(
    KEYISO_VERIFY_CERT_CTX *ctx,       // Optional
    int keyisoFlags,
    int certFormat,                     // Only DER and PEM
    int certLength,
    const unsigned char *certBytes,
    int *verifyChainError,
    int *pemChainLength,                // Optional, excludes NULL terminator
    char **pemChain);                   // Optional, KeyIso_free()

int KeyIso_load_pem_cert(
    const uuid_t correlationId,
    int certLength,
    const unsigned char *certBytes,
    EVP_PKEY **pkey,                    // Optional
    X509 **cert,
    STACK_OF(X509) **ca);

void KeyIsoP_get_verify_cert_ctx_correlationId(
    KEYISO_VERIFY_CERT_CTX *ctx,
    uuid_t correlationId);

//
// Wrapper for openSSL!X509_verify_cert().
//
// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to build chain
int KeyIsoP_X509_verify_cert(
    KEYISO_VERIFY_CERT_CTX *ctx,
    X509_STORE_CTX *storeCtx,
    int keyisoFlags,
    int *verifyChainError);
    

#ifdef  __cplusplus
}
#endif