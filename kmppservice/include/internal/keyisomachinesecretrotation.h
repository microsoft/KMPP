
/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

 #pragma once 

#include <uuid/uuid.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef  __cplusplus
extern "C" {
#endif

int KeyIso_get_current_valid_secret(
    const uuid_t correlationId,
    uint32_t *outGuidSize,
    uint8_t  *outGuid,        // Static buffer, only sizeof(uuid_t) is being used in process based
    uint32_t *outValueSize,
    uint8_t  **outValue);    // Caller must free this memory, KeyIso_clear_free


int KeyIso_get_secret_by_id(
    const uuid_t correlationId,
    uint32_t guidSize,
    const uint8_t *guid, // Static buffer, only sizeof(uuid_t) is being used in process based
    uint32_t *outValueSize,
    uint8_t **outValue);  // Caller must free this memory, KeyIso_clear_free

// Get the pfx.0 file content, which is the legacy secret.
// Static global variables 
const uint8_t* KeyIso_get_legacy_machine_secret(void);

// Machine secret rotation and legacy secret initialization
// Generate latest secret GUID and write it to the latest file(if file does not exist, or need rotation).
// Generate legacy pfx.0 file content, which is the legacy secret(if file does not exist).
int KeyIso_secret_rotation_initialize(uint32_t secretRotationDays);

int KeyIso_secret_rotation_cleanup(void);


#ifdef  __cplusplus
}
#endif