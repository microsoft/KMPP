/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */
#pragma once
#include <stdlib.h>
#include <stdint.h>

#ifdef  __cplusplus
extern "C" {
#endif


typedef void (*ValueFreeFunction)(void *);

typedef struct KMPP_cache_entry_st KMPP_CACHE_ENTRY_ST;

struct KMPP_cache_entry_st {
    char* tag; // Tag needed to group elements so we can delete all elements that have the same tag
    uint64_t hashKey;
    void* value;
    KMPP_CACHE_ENTRY_ST* prev;
    KMPP_CACHE_ENTRY_ST* next;
};

typedef struct KMPP_cache_st KMPP_LRU_CACHE;
struct KMPP_cache_st {
    KMPP_CACHE_ENTRY_ST **table;
    KMPP_CACHE_ENTRY_ST* head;
    KMPP_CACHE_ENTRY_ST* tail;
    ValueFreeFunction valueFreeFunc; // Will be called on the value when it is removed so the ref count can be decreased or the memory freed if the stored value is a dynamically allocated memory
    uint32_t capacity;
    uint32_t size;
};

// Create a cache according to the given capacity
KMPP_LRU_CACHE *KeyIso_create_cache(uint32_t capacity, ValueFreeFunction valueFreeFunc);

// Returns the unique hash key or 0 for error
uint64_t KeyIso_cache_put(KMPP_LRU_CACHE *cache, uint32_t random, void* value, const char *tag);

// Return the value or NULL if not found
void* KeyIso_cache_get(KMPP_LRU_CACHE *cache, uint64_t uniqueHashKey, const char *tag);

void KeyIso_cache_remove(KMPP_LRU_CACHE *cache, uint64_t uniqueHashKey, const char *tag);

// Free the cache
void KeyIso_cache_free(KMPP_LRU_CACHE *cache);

void KeyIso_cache_print(KMPP_LRU_CACHE *cache);

// Delete all elements that have the same tag
void KeyIso_cache_remove_tag(KMPP_LRU_CACHE *cache, const char *tag);


#ifdef  __cplusplus
}
#endif