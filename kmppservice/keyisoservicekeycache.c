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
 static inline void _free_key_cb(void *value) {
    // Decrement the ref count of the key
    KeyIso_SERVER_free_key(NULL, (PKMPP_KEY)value);
 }

 static inline void _ref_count_increment(void *value) {
    KeyIso_SERVER_key_up_ref((PKMPP_KEY)value);
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
     keyId = KeyIso_cache_put(KMPP_keyCache, rand, pkeyPtr, sender);
 
     if (keyId > 0 && pkeyPtr != NULL) {
         KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Add", "keyId: 0x%016llx", keyId);
     } else {
         // keyid is 0 (failure)
         KEYISOP_trace_log_error(correlationId, 0, title, "Add", "Failed");
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
     
 
     pkeyPtr = (PKMPP_KEY)KeyIso_cache_get(KMPP_keyCache, keyId, sender);
     if (pkeyPtr == NULL) {
         KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Get", "Failed", "keyId: 0x%016llx", keyId);
     } else {
        KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Get", "keyId: 0x%016llx", keyId);
     }
     return pkeyPtr;
 }
 
 
 int KeyIso_remove_key_from_list(
     const uuid_t correlationId,
     const char *sender,
     uint64_t keyId)
 {
     KeyIso_cache_remove(KMPP_keyCache, keyId, sender);
 
     return STATUS_OK;
 }
 
 void KeyIso_remove_sender_keys_from_list(const char *sender)
 {
     KeyIso_cache_remove_tag(KMPP_keyCache, sender); 
 }
 
 void KeyIso_initialize_key_list(const uuid_t correlationId,uint32_t capacity)
 {
     const char *title = KEYISOP_SERVICE_TITLE;
     KMPP_keyCache = KeyIso_cache_create(capacity, _free_key_cb, _ref_count_increment);
     KEYISOP_trace_log_para(correlationId, 0, title, "Initialize key LRU cache ", "cache capacity: %d", capacity);
 }
 
 void KeyIso_clear_key_list()
 {
     KeyIso_cache_free(KMPP_keyCache);
     KMPP_keyCache = NULL;
     KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_SERVICE_TITLE, "Clear key list", "Cleared");
 }