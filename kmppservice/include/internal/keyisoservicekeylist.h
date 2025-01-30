/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once 

#include "keyisoservicekey.h"

extern uint32_t g_keyCacheCapacity;

// Assist functions table definition 
typedef struct key_list_assist_functions_table_st KEY_LIST_ASSIST_FUNCTIONS_TABLE_ST;
struct key_list_assist_functions_table_st {
    void (*readLock)(void);
    void (*readUnlock)(void);
    void (*writeLock)(void);
    void (*writeUnlock)(void);
    int (*compareSender)(const char*, const char*);
};
// TOD: Rename LIST -> CACHE
// For success, does KeyIso_SERVER_key_up_ref() of pkey
uint64_t KeyIso_add_key_to_list(
    const uuid_t correlationId,
    const char *senderName,
    PKMPP_KEY pkeyPtr);

// Returned key needs to be freed
PKMPP_KEY KeyIso_get_key_in_list(
    const uuid_t correlationId,
    const char *senderName,
    uint64_t keyId);

int KeyIso_remove_key_from_list(
    const uuid_t correlationId,
    const char *senderName,
    uint64_t keyId);

void KeyIso_remove_sender_keys_from_list(
    const char *senderName);