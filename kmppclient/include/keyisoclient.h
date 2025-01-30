/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#ifdef KEYISO_TEST_WINDOWS
typedef unsigned char uuid_t[16];
#else
#include <uuid/uuid.h>
#endif

#include <openssl/x509.h>

#ifdef  __cplusplus
extern "C" {
#endif

EVP_PKEY *KeyIso_load_engine_private_key(
    const uuid_t correlationId,
    const char *engineName,
    const char *engineKeyId);  

ENGINE *KeyIso_load_engine(
    const uuid_t correlationId,
    const char *engineName);  

int KeyIso_parse_pfx_engine_key_id(
    const uuid_t correlationId,
    const char *keyId,
    int *pfxLength,
    unsigned char **pfxBytes,         // KeyIso_clear_free()
    char **salt);                     // Optional, KeyIso_clear_free_string()

int KeyIso_format_pfx_engine_key_id(
    const uuid_t correlationId,
    int pfxLength,
    const unsigned char *pfxBytes,
    const char *salt,
    char **keyId);                    // KeyIso_clear_free_string()

// Returns BIO_s_mem().
// Ensures a NULL terminator is always appended to the read file contents.
BIO *KeyIsoP_read_file_string(
    const uuid_t correlationId,
    const char *fileName,
    int disableTraceLog,
    char **str);

#ifdef  __cplusplus
}
#endif