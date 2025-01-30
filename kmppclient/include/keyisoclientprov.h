/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <openssl/store.h>

#include <uuid/uuid.h>

EVP_PKEY *KeyIso_load_provider_private_key(
    OSSL_LIB_CTX *libCtx,
    const char *providerKeyId);

int KeyIso_parse_pfx_provider_key_id(
    const uuid_t correlationId,
    const char *keyId,
    int *pfxLength,
    unsigned char **pfxBytes,         // KeyIso_clear_free()
    char **salt);                     // Optional, KeyIso_clear_free_string()

int KeyIso_format_pfx_provider_key_id(
    const uuid_t correlationId,
    int pfxLength,
    const unsigned char *pfxBytes,
    const char *salt,
    char **keyId);                    // KeyIso_clear_free_string()