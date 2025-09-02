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

#ifdef  __cplusplus
extern "C" {
#endif

int KeyIso_SERVER_pfx_open(
    const uuid_t correlationId,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *salt,
    void **pkey);
    
int KeyIso_SERVER_import_pfx(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *inPassword,             // Optional
    int *outVerifyChainError,
    int *outPfxLength,
    unsigned char **outPfxBytes,        // KeyIso_free()
    char **outPfxSalt);                 // KeyIso_free()

int KeyIso_SERVER_rsa_private_encrypt_ossl(
    const uuid_t correlationId,
    void *pkey,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding);

int KeyIso_SERVER_rsa_private_decrypt_ossl(
    const uuid_t correlationId,
    void *pkey,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding);

int KeyIso_SERVER_rsa_sign_ossl(
    const uuid_t correlationId,
    void *pkey,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding);

int KeyIso_SERVER_pkey_rsa_sign_ossl(
    const uuid_t correlationId,
    void *pkey,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding);

int KeyIso_SERVER_ecdsa_sign_ossl(
    const uuid_t correlationId,
    void *pkey,
    int type,
    const unsigned char *dgst,
    int dlen,
    unsigned char *sig,
    unsigned int siglen,
    unsigned int *outlen);

int KeyIso_SERVER_create_self_sign_pfx(
    const uuid_t correlationId,
    int keyisoFlags,
    const char *confStr,
    int *outPfxLength,
    unsigned char **outPfxBytes,        // KeyIso_free()
    char **outPfxSalt);                 // KeyIso_free()

// The pemCert consists of the end certificate followed by
// 1 or more CA certificates
int KeyIso_SERVER_replace_pfx_certs(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *inSalt,
    int pemCertLength,
    const unsigned char *pemCertBytes,
    int *outPfxLength,
    unsigned char **outPfxBytes,    // KeyIso_free()
    char **outSalt);                // KeyIso_free()

void KeyIso_SERVER_pfx_free(
    void *pkey);

/* 
//    Secret
*/

int KeyIso_is_valid_salt(
    const uuid_t correlationId,
    const char *salt,
    const unsigned char* secret);

char *KeyIso_get_pfx_secret_filename();

// Legacy function to create(or read) a PFX secret file
int KeyIsoP_create_pfx_secret(
    const uuid_t correlationId);

#ifdef  __cplusplus
}
#endif