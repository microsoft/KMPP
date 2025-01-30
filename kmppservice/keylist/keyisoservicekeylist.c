/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <string.h>

#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisoutils.h"
#include "keyisoservicekeylist.h"

#define KEYISO_MAX_SENDER_LEN 256 // == DBUS_MAXIMUM_NAME_LENGTH == NAME_MAX (which are not supported for TA compilation) +1 for NULL terminator

////////////////////////
// Key list
////////////////////////

typedef struct KMPP_key_element_st KMPP_KEY_ELEMENT;
struct KMPP_key_element_st {
    char             *sender;        // g_free()
    PKMPP_KEY        pkeyPtr;           // KeyIso_SERVER_free_key()
    uint32_t         rand;
};

static KMPP_KEY_ELEMENT *KMPP_keyList;
static int KMPP_keyAllocCount;
static int KMPP_keyUseCount;

extern const KEY_LIST_ASSIST_FUNCTIONS_TABLE_ST keyListFunctionTable; 


///////////////////////////
//  Key list Functions
///////////////////////////

// For success, does KeyIso_SERVER_key_up_ref() of pkey
uint64_t KeyIso_add_key_to_list(
    const uuid_t correlationId,
    const char *sender,
    PKMPP_KEY pkeyPtr)
{
    const char *title = KEYISOP_SERVICE_TITLE;
    const char *loc = "";
    uint64_t result = 0;
    int addKeyIndex = -1;
    uint32_t rand;

    // Ensure rand is nonzero. It is the upper 32 bits of the returned 64 bit
    // keyId. The lower 32 bits is an index that can be zero.
    // For success keyId != 0.
    if (KeyIso_rand_bytes((unsigned char *)&rand, sizeof(rand)) != STATUS_OK) {
        loc = "failed to get rand bytes";
        goto err;
    }
    if (rand == 0) {
        rand = 1;
    }

    if (keyListFunctionTable.writeLock != NULL) {
        keyListFunctionTable.writeLock();
    }

    for (int i = 0; i < KMPP_keyUseCount; i++) {
        if (KMPP_keyList[i].sender == NULL) {
            addKeyIndex = i;
            break;
        }
    }

    if (addKeyIndex < 0) {
        if (KMPP_keyUseCount == KMPP_keyAllocCount) {
            KMPP_KEY_ELEMENT *newList = NULL;
            if (KMPP_keyList == NULL) {
                newList = (KMPP_KEY_ELEMENT *) KeyIso_zalloc(sizeof(KMPP_KEY_ELEMENT) * g_keyCacheCapacity);
                if (newList != NULL) {
                    KMPP_keyAllocCount = g_keyCacheCapacity;
                }
            } else {
                size_t oldSize = 0;
                size_t newSize = 0;
                if (!KEYISO_MUL_OVERFLOW(sizeof(KMPP_KEY_ELEMENT), KMPP_keyAllocCount, &oldSize) &&
                    !KEYISO_MUL_OVERFLOW(oldSize, 2, &newSize)) {
                    KEYISOP_trace_log_error_para(correlationId, 0, title, "", "Warning",
                        "newSize: %zu", newSize);
                    newList = (KMPP_KEY_ELEMENT *) KeyIso_clear_realloc(KMPP_keyList, oldSize, newSize);
                    if (newList != NULL) {
                        memset(&newList[KMPP_keyAllocCount], 0, oldSize); // Zero second half of the new list
                        KMPP_keyAllocCount += KMPP_keyAllocCount;
                    }
                } else {
                    if (keyListFunctionTable.writeUnlock != NULL) {
                        keyListFunctionTable.writeUnlock();
                    }
                    loc = "multiplication overflow in realloc";
                    goto err;
                }
            }

            if (newList == NULL) {

                if (keyListFunctionTable.writeUnlock != NULL) {
                    keyListFunctionTable.writeUnlock();
                }
                
                loc = "alloc";
                goto err;
            }
            KMPP_keyList = newList;
        } else if (KMPP_keyUseCount > KMPP_keyAllocCount) {            
            if (keyListFunctionTable.writeUnlock != NULL) {
                keyListFunctionTable.writeUnlock();
            }             
            loc = "InvalidCount";
            goto err;
        }

        addKeyIndex = KMPP_keyUseCount++;
    }

    KMPP_keyList[addKeyIndex].sender = KeyIso_strndup(sender, KEYISO_MAX_SENDER_LEN);
    if (KMPP_keyList[addKeyIndex].sender == NULL) {
        if (keyListFunctionTable.writeUnlock != NULL) {
            keyListFunctionTable.writeUnlock();
        }  
        loc = "g_strdup";
        goto err;
    }

    KeyIso_SERVER_key_up_ref(pkeyPtr);
    KMPP_keyList[addKeyIndex].pkeyPtr = pkeyPtr;
    KMPP_keyList[addKeyIndex].rand = rand;

    if (keyListFunctionTable.writeUnlock != NULL) {
        keyListFunctionTable.writeUnlock();
    }  

    result = (uint64_t) addKeyIndex | (((uint64_t) rand) << 32);

    KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Add",
        "keyId: 0x%016llx index: %d rand: 0x%x useCount: %d", result, addKeyIndex, rand, KMPP_keyUseCount);

end:
    return result;
err:
    KEYISOP_trace_log_error(correlationId, 0, title, loc, "Add failed");
    goto end;
}

// Returned key needs to be freed
PKMPP_KEY KeyIso_get_key_in_list(
    const uuid_t correlationId,
    const char *sender,
    uint64_t keyId)
{
    const char *title = KEYISOP_SERVICE_TITLE;
    PKMPP_KEY pkeyPtr = NULL;
    uint32_t keyIndex = (keyId & 0x00000000FFFFFFFFULL);
    uint32_t rand = (uint32_t) ((keyId & 0xFFFFFFFF00000000ULL) >> 32);

    if (keyListFunctionTable.readLock != NULL) {
        keyListFunctionTable.readLock();
    }

    if (keyIndex < (uint32_t) KMPP_keyUseCount && KMPP_keyList != NULL) {
        KMPP_KEY_ELEMENT *keyElem = &KMPP_keyList[keyIndex];

        if (rand == keyElem->rand &&
                keyElem->sender != NULL &&
                keyListFunctionTable.compareSender(sender, keyElem->sender) == 0) {
            pkeyPtr = keyElem->pkeyPtr;
            KeyIso_SERVER_key_up_ref(pkeyPtr);
        }
    }
    if (keyListFunctionTable.readUnlock != NULL) {
        keyListFunctionTable.readUnlock();
    }  

    if (pkeyPtr == NULL) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "CompareKey", "No match",
            "keyId: 0x%016llx index: %d rand: 0x%x", keyId, keyIndex, rand);
    }

    return pkeyPtr;
}


int KeyIso_remove_key_from_list(
    const uuid_t correlationId,
    const char *sender,
    uint64_t keyId)
{
    const char *title = KEYISOP_SERVICE_TITLE;
    PKMPP_KEY pkeyPtr = NULL;
    uint32_t keyIndex = (keyId & 0x00000000FFFFFFFFULL);
    uint32_t rand = (uint32_t) ((keyId & 0xFFFFFFFF00000000ULL) >> 32);

    if (keyListFunctionTable.writeLock != NULL) {
        keyListFunctionTable.writeLock();
    }  

    if (keyIndex < (uint32_t) KMPP_keyUseCount && KMPP_keyList != NULL) {
        KMPP_KEY_ELEMENT *keyElem = &KMPP_keyList[keyIndex];
        if (rand == keyElem->rand &&
                keyElem->sender != NULL &&
                keyListFunctionTable.compareSender(sender, keyElem->sender) == 0) {
            KeyIso_free(keyElem->sender);
            keyElem->sender = NULL;

            pkeyPtr = keyElem->pkeyPtr;
            keyElem->pkeyPtr = NULL;
            keyElem->rand = 0;
        }
    }
    if (keyListFunctionTable.writeUnlock != NULL) {
        keyListFunctionTable.writeUnlock();
    }  

    if (pkeyPtr) {
        KeyIso_SERVER_free_key(correlationId, pkeyPtr);
        KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Remove",
            "keyId: 0x%016llx index: %d rand: 0x%x", keyId, keyIndex, rand);
    } else {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "CompareKey", "No match",
            "keyId: 0x%016llx index: %d rand: 0x%x", keyId, keyIndex, rand);
    }
    return (pkeyPtr) ? 1 : 0;
}

void KeyIso_remove_sender_keys_from_list(
    const char *sender)
{
    const char *title = KEYISOP_SERVICE_TITLE;
    int lastUseIndexPlusOne = 0;
    int removeIndex = -1;
    int removeCount = 0;

    if (keyListFunctionTable.writeLock != NULL) {
        keyListFunctionTable.writeLock();
    }  

    for (int i = 0; i < KMPP_keyUseCount; i++) {
        KMPP_KEY_ELEMENT *keyElem = &KMPP_keyList[i];
        if (keyElem != NULL && keyElem->sender != NULL) {
            if (keyListFunctionTable.compareSender(sender, keyElem->sender) == 0) {
                KeyIso_free(keyElem->sender);
                keyElem->sender = NULL;
                KeyIso_SERVER_free_key(NULL, keyElem->pkeyPtr);
                keyElem->pkeyPtr = NULL;
                keyElem->rand = 0;
                removeIndex = i;
                removeCount++;
            } else {
                lastUseIndexPlusOne = i + 1;
            }
        }
    }

    KMPP_keyUseCount = lastUseIndexPlusOne;
    
    if (keyListFunctionTable.writeUnlock != NULL) {
        keyListFunctionTable.writeUnlock();
    }  

    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Remove",
        "removeCount: %d lastIndex: %d useCount: %d", removeCount, removeIndex, KMPP_keyUseCount);
}