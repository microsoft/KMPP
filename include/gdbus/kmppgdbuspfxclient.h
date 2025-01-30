/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <gio/gio.h>

#ifdef  __cplusplus
extern "C" {
#endif

int KMPP_GDBUS_CLIENT_import_pfx(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *inPassword,             // Optional
    int *outVerifyChainError,
    int *outPfxLength,
    unsigned char **outPfxBytes,        // KeyIso_free()
    char **outPfxSalt);                 // KeyIso_free()

int KMPP_GDBUS_CLIENT_pfx_open(
    KEYISO_KEY_CTX *keyCtx,
    int pfxLength,
    const unsigned char *pfxBytes,
    const char *salt);


void KMPP_GDBUS_CLIENT_pfx_close(
    KEYISO_KEY_CTX *keyCtx);

int KMPP_GDBUS_CLIENT_get_version(
    unsigned int *outVersion);

// For nginx we must defer GLib/GDBus calls to the forked processes
// From load engine phase we must use low-level dbus API to retrieve the version.
int KMPP_RAW_DBUS_CLIENT_get_version(
    const uuid_t correlationId,
    unsigned int *outVersion);

int KMPP_GDBUS_CLIENT_rsa_private_encrypt_decrypt(
    KEYISO_KEY_CTX *keyCtx,
    int decrypt,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding);

int KMPP_GDBUS_CLIENT_ecdsa_sign(
    KEYISO_KEY_CTX *keyCtx,
    int type,
    const unsigned char *dgst,
    int dlen,
    unsigned char *sig,
    unsigned int siglen,
    unsigned int *outlen);

int KMPP_GDBUS_CLIENT_create_self_sign_pfx(
    const uuid_t correlationId,
    int keyisoFlags,
    const char *confStr,
    int *outPfxLength,
    unsigned char **outPfxBytes,        // KeyIso_free()
    char **outPfxSalt);                 // KeyIso_free()

// The pemCert consists of the end certificate followed by
// 1 or more CA certificates
int KMPP_GDBUS_CLIENT_replace_pfx_certs(
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


#ifdef  __cplusplus
}
#endif
