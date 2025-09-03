/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <string.h>
#include <uuid/uuid.h>

#include "keyisocommon.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisoguidlookupcache.h"


// Initial capacity of the secrets cache
// This is the number of entries allocated when the cache is created.
// The cache can grow up to max capacity.
#define KEYISO_GUID_LOOKUP_CACHE_INITIAL_CAPACITY   20
#define KEYISO_GUID_LOOKUP_CACHE_MAX_CAPACITY       100

#define INVALID_INDEX -1

struct KeyIso_guid_lookup_cache_st {
    KEYISO_GUID_LOOKUP_CACHE_ENTRY* entries;
    uint32_t capacity;           // Current array capacity
    uint32_t maxCapacity;        // Maximum allowed capacity
    uint32_t counter;            // Total number of entries added to the cache. counter % capacity gives the next position to write to.
};

static void _free_secret(KEYISO_GUID_LOOKUP_CACHE_ENTRY* secret)
{
    if (secret == NULL) {
        return;
    }

    if (secret->value != NULL) {
        KeyIso_clear_free(secret->value, secret->valueLength);
        secret->value = NULL;
    }

    memset(secret->guid, 0, sizeof(uuid_t));
    secret->valueLength = 0;
}

static int _try_grow_cache(KEYISO_GUID_LOOKUP_CACHE* cache)
{
    if (cache == NULL) {
        return STATUS_FAILED;
    }

    if (cache->capacity >= cache->maxCapacity) {
        // Cache is already at maximum capacity
        KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_CACHE_TITLE, "reached max capacity, will evict an old entry", "maxCapacity: %u", cache->maxCapacity);
        return STATUS_FAILED;
    }

    // Double the capacity, but do not exceed max capacity
    uint32_t newCapacity = cache->capacity * 2;
    if (newCapacity > cache->maxCapacity) {
        newCapacity = cache->maxCapacity;
    }

    KEYISO_GUID_LOOKUP_CACHE_ENTRY *newEntries = (KEYISO_GUID_LOOKUP_CACHE_ENTRY *)KeyIso_clear_realloc(cache->entries, cache->capacity * sizeof(KEYISO_GUID_LOOKUP_CACHE_ENTRY), newCapacity * sizeof(KEYISO_GUID_LOOKUP_CACHE_ENTRY));
    if (newEntries == NULL) {
        return STATUS_FAILED;
    }
    // Zero second half of the new list
    memset(&newEntries[cache->capacity], 0, (newCapacity - cache->capacity) * sizeof(KEYISO_GUID_LOOKUP_CACHE_ENTRY)); 

    cache->entries = newEntries;
    cache->capacity = newCapacity;

    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_CACHE_TITLE, "Successfully grew cache", "new capacity: %u", cache->capacity);

    return STATUS_OK;
}

KEYISO_GUID_LOOKUP_CACHE* KeyIso_create_guid_lookup_cache()
{
    KEYISO_GUID_LOOKUP_CACHE* cache = KeyIso_zalloc(sizeof(KEYISO_GUID_LOOKUP_CACHE));
    if (cache == NULL) {
        return NULL;
    }

    cache->entries = KeyIso_zalloc(KEYISO_GUID_LOOKUP_CACHE_INITIAL_CAPACITY * sizeof(KEYISO_GUID_LOOKUP_CACHE_ENTRY));
    if (cache->entries == NULL) {
        KeyIso_free(cache);
        return NULL;
    }

    cache->capacity = KEYISO_GUID_LOOKUP_CACHE_INITIAL_CAPACITY;
    cache->maxCapacity = KEYISO_GUID_LOOKUP_CACHE_MAX_CAPACITY;
    cache->counter = 0;

    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_CACHE_TITLE, "Successfully initialize cache", "capacity: %u", cache->capacity);

    return cache;
}

void KeyIso_free_guid_lookup_cache(KEYISO_GUID_LOOKUP_CACHE* cache)
{
    if (cache == NULL) {
        return;
    }

    if (cache->entries != NULL) {
        for (uint32_t i = 0; i < cache->capacity; i++) {
            _free_secret(&cache->entries[i]);
        }
        KeyIso_free(cache->entries);
    }

    KeyIso_free(cache);
}

static int _find_guid_index(KEYISO_GUID_LOOKUP_CACHE* cache, const uuid_t guid)
{
    for (uint32_t i = 0; i < cache->capacity; i++) {
        if (uuid_compare(cache->entries[i].guid, guid) == 0) {
            return i;
        }
    }
    return INVALID_INDEX;
}

static int _find_value_index(KEYISO_GUID_LOOKUP_CACHE* cache, const uuid_t guid, const uint8_t* value, uint32_t valueLength, int *index)
{
    int status = STATUS_FAILED;
    *index = INVALID_INDEX;

    *index = _find_guid_index(cache, guid);
    if (*index > INVALID_INDEX) {
        // Guid already exists in cache
        if (cache->entries[*index].valueLength == valueLength &&
            memcmp(cache->entries[*index].value, value, valueLength) == 0) {
            status = STATUS_OK;
        }
    }

    return status;
}

int KeyIso_guid_lookup_cache_put(
    KEYISO_GUID_LOOKUP_CACHE* cache,
    const uuid_t guid,
    const uint8_t* value,
    uint32_t valueLength)
{
    if (cache == NULL || cache->entries == NULL || value == NULL || valueLength == 0) {
        return STATUS_FAILED;
    }

    if (cache->maxCapacity == 0) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_CACHE_TITLE, "Failed", "maxCapacity is 0");
        return STATUS_FAILED;
    }

    // Check if value is already in cache
    int index = INVALID_INDEX;
    int status = _find_value_index(cache, guid, value, valueLength, &index);
    if (index > INVALID_INDEX) {
        // Guid already exists in cache
        if (status == STATUS_OK) {
            KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_CACHE_TITLE, "Guid already exists in cache with the same value");
        } else {
            KEYISOP_trace_log_error(NULL, 0, KEYISOP_CACHE_TITLE, "Failed", "Guid already exists in cache with a different value");
        }
        return status;
    }

    // Value does not exist in cache, proceed to add it
    if (cache->counter >= cache->capacity) {
        // At current capacity, try growing the cache
        if (cache->capacity < cache->maxCapacity) {
            // case 1: Current capacity is lower than the maximum capacity
            status = _try_grow_cache(cache);
            if (status != STATUS_OK) {
                // Failed to grow cache
                KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_CACHE_TITLE,
                    "Failed to grow cache", "capacity: %u, max capacity: %u", cache->capacity, cache->maxCapacity);
            } else {
                KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_CACHE_TITLE,
                    "Successfully grew cache", "new capacity: %u", cache->capacity);
            }
        } else {
            // case 2: At max capacity
            KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_CACHE_TITLE,
                    "Failed to grow cache", "capacity: %u, max capacity: %u", cache->capacity, cache->maxCapacity);
        }
    }

    // Evict current entry if needed (do nothing if is an unused entry)
    uint32_t nextPosition = cache->counter % cache->capacity;
    if (cache->counter >= cache->capacity) {
        KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_CACHE_TITLE,
            "Evicting old entry", "position: %u", nextPosition);
        _free_secret(&cache->entries[nextPosition]);
    }

    // Create new entry
    uint8_t* newSecret = KeyIso_zalloc(valueLength);
    if (newSecret != NULL) {
        memcpy(newSecret, value, valueLength);
        uuid_copy(cache->entries[nextPosition].guid, guid);
        cache->entries[nextPosition].value = newSecret;
        cache->entries[nextPosition].valueLength = valueLength;
        cache->counter++;
        status = STATUS_OK;
    } else {
        // Failed to allocate memory for the new value
        status = STATUS_FAILED;
    }

    return status;
}

int KeyIso_guid_lookup_cache_get(
    KEYISO_GUID_LOOKUP_CACHE* cache,
    const uuid_t guid,
    uint8_t** outValue,    // KeyIso_free()
    uint32_t* outLength)
{
    if (cache == NULL || cache->entries == NULL || outValue == NULL || outLength == NULL) {
        return STATUS_FAILED;
    }
    *outValue = NULL;
    *outLength = 0;

    int status = STATUS_FAILED;

    int index = _find_guid_index(cache, guid);
    if (index >= 0) {
        uint32_t valueLength = cache->entries[index].valueLength;
        uint8_t *value = (uint8_t *)KeyIso_zalloc(valueLength);
        if (value != NULL) {
            memcpy(value, cache->entries[index].value, valueLength);
            *outValue = value;
            *outLength = valueLength;
            status = STATUS_OK;
        }
    } else {
        KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_CACHE_TITLE, "not in cache");
    }

    return status;
}
