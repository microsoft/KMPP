/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <uuid/uuid.h>

#ifdef  __cplusplus
extern "C" {
#endif

// Return:
//  +1 - Success
//   0 - Error, unable to import symmetric key.
int KeyIso_import_symmetric_key_to_key_id(
    const uuid_t correlationId,
    const int inKeyLength,
    const unsigned char *inKeyBytes,
    const unsigned char *inImportKeyId, // Unique identifier to the imported key
    unsigned char **keyId);             // KeyIso_free()

#ifdef  __cplusplus
}
#endif
