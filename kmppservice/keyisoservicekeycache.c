/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <string.h>

#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisoservicekeylist.h"
#include "keyisolrucache.h"
#include "keyisoutils.h"

////////////////////////
// Key list
////////////////////////
static KMPP_LRU_CACHE *KMPP_keyCache = NULL;
extern const KEY_LIST_ASSIST_FUNCTIONS_TABLE_ST keyListFunctionTable; 

///////////////////////////
//  Key list Functions
///////////////////////////
static void _free_key_cb(void *value) {
    // Cast to the appropriate type and free
    PKMPP_KEY pkeyPtr = (PKMPP_KEY)value;
    // Decrement the ref count of the key
    KeyIso_SERVER_free_key(NULL, pkeyPtr);
}

// For success, does KeyIso_SERVER_key_up_ref() of pkey
uint64_t KeyIso_add_key_to_list(
    const uuid_t correlationId,
    const char *sender,
    PKMPP_KEY pkeyPtr)
{
    const char *title = KEYISOP_SERVICE_TITLE;
    uint64_t keyId = 0;
    uint32_t rand = 0;
    
    // Ensure rand is nonzero. It is the upper 32 bits of the returned 64 bit
    // keyId. The lower 32 bits is an index that can be zero.
    if (KeyIso_rand_bytes((unsigned char *)&rand, sizeof(rand)) != STATUS_OK) {
		KEYISOP_trace_log_error(correlationId, 0, title, "KeyIso_rand_bytes", "failed to get rand bytes");
        return 0;
    }

    if (rand == 0) {
        // Ensure rand is nonzero, uniqueHashKey cant be 0
        rand = 1;
    }

    if (keyListFunctionTable.writeLock != NULL) {
        keyListFunctionTable.writeLock();
    } 

    if (KMPP_keyCache == NULL) {
        KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Add", "Capacity: %d", g_keyCacheCapacity);
        KMPP_keyCache = KeyIso_create_cache(g_keyCacheCapacity, _free_key_cb);
    } 
    
    keyId = KeyIso_cache_put(KMPP_keyCache, rand, pkeyPtr, sender);

    if (keyId > 0) {
        KeyIso_SERVER_key_up_ref(pkeyPtr);
        KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Add", "keyId: 0x%016llx", keyId);
    } else {
        // keyid is 0 (failure)
        KEYISOP_trace_log_error(correlationId, 0, title, "Add", "Failed");
    }
    if (keyListFunctionTable.writeUnlock != NULL) {
        keyListFunctionTable.writeUnlock();
    }  
    return keyId;
}

// Returned key needs to be freed
PKMPP_KEY KeyIso_get_key_in_list(
    const uuid_t correlationId,
    const char *sender,
    uint64_t keyId)
{
    const char *title = KEYISOP_SERVICE_TITLE;
    PKMPP_KEY pkeyPtr = NULL;
    
    if (keyListFunctionTable.readLock != NULL) {
        keyListFunctionTable.readLock();
    } 

    pkeyPtr = (PKMPP_KEY)KeyIso_cache_get(KMPP_keyCache, keyId, sender);
    if (pkeyPtr == NULL) {
        KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Get", "Failed", "keyId: 0x%016llx", keyId);
    } else {
        KeyIso_SERVER_key_up_ref(pkeyPtr);
        KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Get", "keyId: 0x%016llx", keyId);
    }

    if (keyListFunctionTable.readUnlock != NULL) {
        keyListFunctionTable.readUnlock();
    }  
    return pkeyPtr;
}


int KeyIso_remove_key_from_list(
    const uuid_t correlationId,
    const char *sender,
    uint64_t keyId)
{
    if (keyListFunctionTable.writeLock != NULL) {
        keyListFunctionTable.writeLock();
    } 
    KeyIso_cache_remove(KMPP_keyCache, keyId, sender);
    if (keyListFunctionTable.writeUnlock != NULL) {
        keyListFunctionTable.writeUnlock();
    }  

    return STATUS_OK;
}

void KeyIso_remove_sender_keys_from_list(const char *sender)
{
    if (keyListFunctionTable.writeLock != NULL) {
        keyListFunctionTable.writeLock();
    } 
    KeyIso_cache_remove_tag(KMPP_keyCache, sender);
    if (keyListFunctionTable.writeUnlock != NULL) {
        keyListFunctionTable.writeUnlock();
    }  
}