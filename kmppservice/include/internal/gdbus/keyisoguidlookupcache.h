/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */
#pragma once

#include <uuid/uuid.h>
#include <stdint.h>
#include <stddef.h>

#include "keyisocommon.h"
#include "keyisomemory.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct KeyIso_guid_lookup_cache_entry_st KEYISO_GUID_LOOKUP_CACHE_ENTRY;
struct KeyIso_guid_lookup_cache_entry_st {
    uuid_t guid;
    uint8_t* value;
    uint32_t valueLength;
};

typedef struct KeyIso_guid_lookup_cache_st KEYISO_GUID_LOOKUP_CACHE;

// Creates a new GUID lookup cache.
KEYISO_GUID_LOOKUP_CACHE* KeyIso_create_guid_lookup_cache();

// Frees a GUID lookup cache and all its entries.
void KeyIso_free_guid_lookup_cache(
    KEYISO_GUID_LOOKUP_CACHE* cache);

// Adds a value in the GUID lookup cache.
// If the cache is at max capacity, uses round-robin eviction.
// Ensures that secret data are securely cleared before being overwritten or freed.
// Otherwise, grows the cache by doubling its size.
int KeyIso_guid_lookup_cache_put(
    KEYISO_GUID_LOOKUP_CACHE* cache,
    const uuid_t guid,
    const uint8_t* value,
    uint32_t  valueLength);

// Retrieves a value from the GUID lookup cache.
int KeyIso_guid_lookup_cache_get(
    KEYISO_GUID_LOOKUP_CACHE* cache,
    const uuid_t guid,
    uint8_t** outValue,    // KeyIso_free()
    uint32_t* outValueLength);

#ifdef __cplusplus
}
#endif
