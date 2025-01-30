/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */
#include <stdio.h>
#include <string.h>
#include "keyisomemory.h"
#include "keyisolog.h"
#include "keyisocommon.h"
#include "keyisolrucache.h"

#define KEYISO_MAX_TAG_LEN 256 

// Hash function - returns the index in the cache for the given uniqueHashKey
static uint32_t _hash(uint64_t uniqueHashKey)
{
    return (uint32_t) (uniqueHashKey & 0x00000000FFFFFFFFULL); // Get the index(first 32 bits)
}

// Create a cache according to the given capacity
KMPP_LRU_CACHE *KeyIso_create_cache(uint32_t capacity, ValueFreeFunction valueFreeFunc)
{
    const char *title = KEYISOP_CACHE_TITLE;
    if (capacity <= 0) {
        KEYISOP_trace_log_error(NULL, 0, title, "Failed to create the cache", "Invalid capacity");
        return NULL;
    }
    KMPP_LRU_CACHE *cache = KeyIso_zalloc(sizeof(KMPP_LRU_CACHE));
    if (cache == NULL) {
        return NULL;
    }
    cache->capacity = capacity;
    cache->table = KeyIso_zalloc(capacity*sizeof(KMPP_CACHE_ENTRY_ST *));
    if (cache->table == NULL) {
        KeyIso_free(cache);
        return NULL;
    }
    cache->head = NULL;
    cache->tail = NULL;
    cache->size = 0;
    cache->valueFreeFunc = valueFreeFunc;
    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Cache created", "capacity: %u", capacity);
    return cache;
}

uint32_t _get_next_free_index(KMPP_LRU_CACHE *cache)
{
    const char *title = KEYISOP_CACHE_TITLE;
    uint32_t index = 0;
    for (uint32_t i = 0; i < cache->capacity; i++) {
        if (cache->table[i] == NULL) {
            index = i;
            break;
        }
    }
    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Next free index", "index: %u", index);
    return index;
}

static void _cache_move_to_front(KMPP_LRU_CACHE *cache, KMPP_CACHE_ENTRY_ST *entry)
{
   const char *title = KEYISOP_CACHE_TITLE;
   KMPP_CACHE_ENTRY_ST *head = cache->head;
   if (entry == head) {
        return;
   }

    KMPP_CACHE_ENTRY_ST *prev = entry->prev;
    KMPP_CACHE_ENTRY_ST *next = entry->next;
    // If this is not a new entry make its prev and next point to each other as we remove the entry from its position and move it to the front
    if (prev) {
        prev->next = next;
    }
    if (next) {
        next->prev = prev;
    }

    // Checks if the entry being moved is the tail and updates the tail to the previous entry if so
    if (entry == cache->tail) {
        cache->tail = prev;
    }

    // The new entry points to previous head as its the new head
    entry->next =  head;
    // The new entry points has no prev as its the new head
    entry->prev = NULL;
    if (head) {
        // The previous head points to the new head as its prev node
        head->prev = entry;
    }
    // The cache head is updated to the new entry
    cache->head = entry;
    if (!cache->tail) {
        // If the tail is NULL, this is the first entry in the cache, so its also the tail
        cache->tail = entry;
    }
    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Moved to front", "uniqueHashKey: 0x%016llx", entry->hashKey);
}

static void _free_elem(KMPP_CACHE_ENTRY_ST **elem)
{
    if (elem == NULL || *elem == NULL) {
        return;
    }
    // Free the TAG
    KeyIso_free((*elem)->tag);
    (*elem)->tag = NULL;
    // Free the entry
    KeyIso_free(*elem);
    *elem = NULL;
}

// Remove LRU entry
static void _cache_evict(KMPP_LRU_CACHE *cache, uint32_t *evictedIndex)
{
    const char *title = KEYISOP_CACHE_TITLE;
    KMPP_CACHE_ENTRY_ST *tail = cache->tail;
    if (tail == NULL) {
        KEYISOP_trace_log_error(NULL, 0, title, "Failed to evict", "Tail is NULL");
        return;
    }

    KMPP_CACHE_ENTRY_ST *prev = tail->prev;
    if (prev) {
        // The previous entry of a tail has no next node now
        prev->next = NULL;
    }
    
    // The previous node of the evicted tail is now the new tail
    cache->tail = prev;

    size_t index = _hash(tail->hashKey);
    // The entry is removed from the cache
    cache->table[index] = NULL;
    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Evicted", "uniqueHashKey: 0x%016llx", tail->hashKey);
    if (cache->valueFreeFunc) {
        // Callback to free the value
        cache->valueFreeFunc(tail->value);
        tail->value = NULL;
    }
    _free_elem(&tail);
    cache->size -= 1;
    *evictedIndex = index;
}

// Put a value into the cache
uint64_t KeyIso_cache_put(KMPP_LRU_CACHE *cache, uint32_t random, void* value, const char *tag)
{
    const char *title = KEYISOP_CACHE_TITLE;
    uint64_t uniqueHashKey = 0;
    uint32_t index = 0;
    if (cache == NULL) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_CACHE_TITLE, "Put to cache failed", "Cache is NULL");
        return 0;
    } 

    if (random == 0) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_CACHE_TITLE, "Failed to add element", "Random value cant be 0");
        return 0;
    }
    if (cache->size >= cache->capacity) {
        // Evict the LRU entry and get the freed slot index
        _cache_evict(cache, &index);
    } else {
        // The list is not full, search for the next free index
        index = _get_next_free_index(cache);
    }

    if (index >= cache->capacity) {
        KEYISOP_trace_log_error( NULL, 0, KEYISOP_CACHE_TITLE, "Failed to add element", "Invalid index");
        return 0;
    }

    uniqueHashKey = (uint64_t) index | (((uint64_t) random) << 32);
    KMPP_CACHE_ENTRY_ST *newEntry = KeyIso_zalloc(sizeof(*newEntry));
    if (!newEntry) {
        return 0;
    }
    newEntry->hashKey = uniqueHashKey;
    newEntry->value = value;
    newEntry->prev = NULL;
    newEntry->next = NULL;
    newEntry->tag = KeyIso_strndup(tag, KEYISO_MAX_TAG_LEN);
    if (newEntry->tag == NULL) {
        _free_elem(&newEntry);
        KEYISOP_trace_log_error( NULL, 0, KEYISOP_CACHE_TITLE, "Failed to create the cache entry", "Failed to strdup the tag");
        return 0;
    }

    cache->table[index] = newEntry;
    _cache_move_to_front(cache, newEntry);
    cache->size += 1;
    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Added", "index: %u,uniqueHashKey: 0x%016llx", index, uniqueHashKey);
    return uniqueHashKey;
}

// Get a value from the cache
void* KeyIso_cache_get(KMPP_LRU_CACHE *cache, uint64_t uniqueHashKey, const char *tag)
{
    const char *title = KEYISOP_CACHE_TITLE;
    uint32_t index = _hash(uniqueHashKey);
    if (cache == NULL) {
        KEYISOP_trace_log_error( NULL, 0, KEYISOP_CACHE_TITLE, "Get from cache failed", "Cache is NULL");
        return NULL;
    } 
    KMPP_CACHE_ENTRY_ST *entry = cache->table[index];
    // We expect all the 64 bits to match(both the 32 bits index that are returned by the hash function and 32 bits rand
    // otherwise this is not the same entry
    if (!entry || entry->hashKey != uniqueHashKey || strcmp(entry->tag, tag) != 0 ) { 
        // Not an error, the value might be evicted by the time we try to get it, printing a debug message
        KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Entry was not found", "uniqueHashKey: 0x%016llx, tag: %s", uniqueHashKey, tag);
        return NULL;
    }
    _cache_move_to_front(cache, entry);
    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Get value", "index: %u, uniqueHashKey: 0x%016llx", index, uniqueHashKey);
    return entry->value; 
}

// Clean up the cache
void KeyIso_cache_free(KMPP_LRU_CACHE *cache)
{
    if (cache == NULL) {
        return;
    } 
    KMPP_CACHE_ENTRY_ST *entry = cache->head;
    while (entry) {
        KMPP_CACHE_ENTRY_ST *next = entry->next;
        if (cache->valueFreeFunc) {
            // Callback to free the value
            cache->valueFreeFunc(entry->value);
            entry->value = NULL;
        }
        _free_elem(&entry);
        entry = next;
    }
    cache->head = NULL;
    cache->tail = NULL;

    // Zero the hash table
    for (size_t i = 0; i < cache->capacity; i++) {
        cache->table[i] = NULL;
    }
    KeyIso_free(cache->table);
    KeyIso_free(cache);
}


// Remove an entry from the cache by its uniqueHashKey
void KeyIso_cache_remove(KMPP_LRU_CACHE *cache, uint64_t uniqueHashKey, const char *tag) 
{
    const char *title = KEYISOP_CACHE_TITLE;
    uint32_t index = _hash(uniqueHashKey);
    if (cache == NULL) {
        KEYISOP_trace_log_error( NULL, 0, KEYISOP_CACHE_TITLE, "Error", "Cache is NULL");
        return;
    }
    if (index >= cache->capacity) {
        KEYISOP_trace_log_error_para(NULL, 0, title, "Failed to remove element", "Invalid index", "uniqueHashKey: 0x%016llx, capacity: %u", uniqueHashKey, cache->capacity);    
        return;
    }
    KMPP_CACHE_ENTRY_ST *entryToRemove = cache->table[index];
    if (entryToRemove == NULL) {
        // Not an error because the entry might be already evicted by the time we try to remove it, printing a debug message
        KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Entry was not found", "uniqueHashKey: 0x%016llx", uniqueHashKey);    
        return;
    }
    
    if (entryToRemove->hashKey != uniqueHashKey || strcmp(entryToRemove->tag, tag) != 0) {
        // The entry is not the one we are looking for, this is not an error, printing a debug message
        KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Entry was not found- the removed entry was probably evicted", "uniqueHashKey: 0x%016llx, index:%u", uniqueHashKey, index);
        return;
    }

    KMPP_CACHE_ENTRY_ST *prev = entryToRemove->prev;
    KMPP_CACHE_ENTRY_ST *next = entryToRemove->next;
    // If there is a previous node, make it point to the next node of the removed entry
    if (prev) {
        prev->next = next;
    } else {
        // If there is no previous entry, this entry is the head
        cache->head = next;
    }

    if (next) {
        next->prev = prev;
    } else {
        // If there is no next entry, this entry is the tail
        cache->tail = prev;
    }

    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Removed", "uniqueHashKey: 0x%016llx", uniqueHashKey);

    // Remove the entry from the table
    cache->table[index] = NULL;

    // Decrement the size of the cache
    cache->size-= 1;
    if (cache->valueFreeFunc) {
        // Callback to free the value
        cache->valueFreeFunc(entryToRemove->value);
        entryToRemove->value = NULL;
    }

    // Free the entry
    _free_elem(&entryToRemove);
}

// Delete all entries with the same tag
void KeyIso_cache_remove_tag(KMPP_LRU_CACHE *cache, const char *tag)
{
    const char *title = KEYISOP_CACHE_TITLE;
    
    if (!cache || !tag) {
        KEYISOP_trace_log_error(NULL, 0, title, "Failed to remove elements", "Invalid parameters");
        return;
    }
    KMPP_CACHE_ENTRY_ST *current = cache->head;
    while (current != NULL) {
        KMPP_CACHE_ENTRY_ST *next = current->next;
        
        if (current->tag && strcmp(current->tag, tag) == 0) {
            // Adjust links
            if (current->prev) {
                current->prev->next = current->next;
            } else {
                cache->head = current->next;
            }

            if (current->next) {
                current->next->prev = current->prev;
            } else {
                cache->tail = current->prev;
            }

            // Remove from cache table
            size_t index = _hash(current->hashKey);
            if (cache->table[index] == current) {
                cache->table[index] = NULL;
            } else {
                KEYISOP_trace_log_error_para(NULL, 0, title, "Entry does not match to the list", "Mismatch", "tag: %s, hashkey:%u", tag, current->hashKey);
            }
            
            // Free memory
            if (cache->valueFreeFunc) {
                // Free the value
                cache->valueFreeFunc(current->value);
                current->value = NULL;
            }
            KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Remove", "tag: %s, hashkey:%u", tag, current->hashKey);
            // We duplicated the tag when we created the entry, so we need to free 
            _free_elem(&current);
            cache->size--;
        }
        current = next;
    }
}

void KeyIso_cache_print(KMPP_LRU_CACHE *cache)
{
    KMPP_CACHE_ENTRY_ST *entry = cache->head;
    while (entry) {
        printf("hashKey: %lu, tag: %s", entry->hashKey, entry->tag);
        entry = entry->next;
    }
    printf("\n");
}