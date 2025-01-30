/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <uuid/uuid.h>
#include "keyisocommon.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*
    Client Implementation: keyisoclient.c 
*/

int KeyIso_CLIENT_import_symmetric_key(
    const uuid_t correlationId,
    const int inKeyLength,
    const unsigned char *inKeyBytes,
    const unsigned char *inImportKeyId, // Unique identifier to the imported key
    unsigned int *outKeyLength,
    unsigned char **outKeyBytes);       // KeyIso_free()

int KeyIso_CLIENT_symmetric_key_encrypt_decrypt(
    KEYISO_KEY_CTX *keyCtx,
    const int mode,
    const unsigned char *from,
    const unsigned int fromLen,
    unsigned char *to,
    unsigned int *toLen);       

#ifdef  __cplusplus
}
#endif