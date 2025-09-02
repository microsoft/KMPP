/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include "keyisocommon.h"
#ifdef  __cplusplus
extern "C" {
#endif

/*
    Client Implementation: keyisoclient.c 
*/

int KeyIso_CLIENT_pfx_open(
    const uuid_t correlationId,
    int pfxLength,
    const unsigned char* pfxBytes,
    const char* salt,
    KEYISO_KEY_CTX** keyCtx);

void KeyIso_CLIENT_pfx_close(
    KEYISO_KEY_CTX *keyCtx);

int KeyIso_CLIENT_import_pfx(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *inPassword,             // Optional
    int *outVerifyChainError,
    int *outPfxLength,
    unsigned char **outPfxBytes,        // KeyIso_free()
    char **outPfxSalt);                 // KeyIso_free()

int KeyIso_CLIENT_rsa_private_encrypt(
    KEYISO_KEY_CTX *keyCtx,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding);

int KeyIso_CLIENT_rsa_private_decrypt(
    KEYISO_KEY_CTX *keyCtx,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding,
    int labelLen);

int KeyIso_CLIENT_rsa_sign(
    KEYISO_KEY_CTX *keyCtx,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding);

int KeyIso_CLIENT_pkey_rsa_sign(
    KEYISO_KEY_CTX *keyCtx,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding);
    
int KeyIso_CLIENT_ecdsa_sign(
    KEYISO_KEY_CTX *keyCtx,
    int type,
    const unsigned char *dgst,
    int dlen,
    unsigned char *sig,
    unsigned int siglen,
    unsigned int *outlen);
    
int KeyIso_CLIENT_self_sign_pfx(
    const uuid_t correlationId,
    int keyisoFlags,
    const char *confStr,
    int *pfxLength,
    unsigned char **pfxBytes,
    char **pfxSalt);

int KeyIso_CLIENT_replace_pfx_certs(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *inSalt,
    int pemCertLength,
    const unsigned char *pemCertBytes,
    int *outPfxLength,
    unsigned char **outPfxBytes,    
    char **outSalt); 

void KeyIso_CLIENT_pkey_rsa_sign_serialization(
    unsigned char* from,
    const unsigned char* tbs,
    size_t tbsLen,
    int saltLen,
    int mdType,
    int mgfmdType,
    size_t sigLen,
    int getMaxLen);

void KeyIso_rsa_sign_serialization(
    unsigned char* from,
    int type,
    const unsigned char* m,
    unsigned int m_len);

#ifdef  __cplusplus
}
#endif