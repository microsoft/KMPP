/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once


# ifdef KEYISO_TEST_WINDOWS
typedef unsigned char uuid_t[16];
# else
#   include <uuid/uuid.h>
# endif

#include <openssl/evp.h>

#ifdef  __cplusplus
extern "C" {
#endif



// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to import PFX.
int KeyIso_import_pfx(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *password,             // Optional
    int *verifyChainError,
    int *pfxLength,
    unsigned char **pfxBytes,         // KeyIso_clear_free()
    char **salt);                     // KeyIso_clear_free_string()

// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to import PFX.
int KeyIso_import_pfx_to_key_id(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *password,             // Optional
    int *verifyChainError,
    char **keyId);                    // KeyIso_clear_free_string()


// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to import PFX.
int KeyIso_build_cert_chain_from_pfx(
    const uuid_t correlationId,
    int keyisoFlags,
    int pfxLength,
    const unsigned char *pfxBytes,
    int *verifyChainError,
    int *pemCertLength,              // Excludes NULL terminator
    char **pemCert);                 // KeyIso_free()                   

// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to import PFX.
int KeyIso_build_cert_chain_from_key_id(
    const uuid_t correlationId,
    int keyisoFlags,
    const char *keyId,
    int *verifyChainError,
    int *pemCertLength,              // Excludes NULL terminator
    char **pemCert);                 // KeyIso_free()     

// Returns 1 for success and 0 for an error
int KeyIso_create_self_sign_pfx(
    const uuid_t correlationId,
    int keyisoFlags,
    const char *confStr,
    int *pfxLength,
    unsigned char **pfxBytes,           // KeyIso_clear_free()
    char **salt);                       // KeyIso_clear_free_string()

// Returns 1 for success and 0 for an error
int KeyIso_create_self_sign_pfx_to_key_id(
    const uuid_t correlationId,
    int keyisoFlags,
    const char *confStr,
    char **keyId);                    // KeyIso_clear_free_string()

// Returns 1 for success and 0 for an error
// The pemCert consists of the end certificate followed by
// 1 or more CA certificates
int KeyIso_replace_pfx_certs(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *inSalt,
    int pemCertLength,
    const unsigned char *pemCertBytes,
    int *outPfxLength,
    unsigned char **outPfxBytes,        // KeyIso_clear_free()
    char **outSalt);                    // KeyIso_clear_free_string()

// Returns 1 for success and 0 for an error
int KeyIso_replace_key_id_certs(
    const uuid_t correlationId,
    int keyisoFlags,
    const char *inKeyId,
    int pemCertLength,
    const unsigned char *pemCertBytes,
    char **outKeyId);                   // KeyIso_clear_free_string()

// Returns 1 for success and 0 for an error
int KeyIso_replace_key_id_certs2(
    const uuid_t correlationId,
    int keyisoFlags,
    const char *inKeyId,
    X509 *cert,
    STACK_OF(X509) *ca,                 // Optional
    char **outKeyId);                   // KeyIso_clear_free_string()   


// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to import PFX.
int KeyIso_import_pfx_from_pem(
    const uuid_t correlationId,
    int keyisoFlags,
    int inKeyLength,
    const unsigned char *inKeyBytes,
    int inCertLength,
    const unsigned char *inCertBytes,
    const char *password,             			// Optional
    int *verifyChainError,
    int *outPfxLength,
    unsigned char **outPfxBytes,      			// KeyIso_free()
    char **salt);

// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to import PFX.
int KeyIso_import_pfx_from_pem_to_key_id(
    const uuid_t correlationId,
    int keyisoFlags,
    int inKeyLength,
    const unsigned char *inKeyBytes,
    int inCertLength,
    const unsigned char *inCertBytes,
    const char *password,             			// Optional
    int *verifyChainError,
    char **keyId);                              // KeyIso_free()
                        			

// Return An integer status code indicating the result of the validation.
// +1 - Success with Opening the key using the Machine Secret.
//  0 - Error, unable to open the key.
int KeyIso_validate_keyid(
    const uuid_t correlationId,
    const char *keyId);

// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to import PFX.
int KeyIso_import_pfx_to_disk(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *password,             // Optional
    int *verifyChainError, 
    const char *outFilename);           // Optional)

#ifdef  __cplusplus
}
#endif