/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include "keyisocommon.h"

typedef struct KEYISO_GDBUS_shared_mem_st KEYISO_GDBUS_SHARED_MEM;

typedef struct KEYISO_shared_mem_st KEYISO_SHARED_MEM;
struct KEYISO_shared_mem_st {
    uuid_t                      correlationId;
    int                         memLength;
    unsigned char               *memBytes;
    KEYISO_GDBUS_SHARED_MEM     *gdbus;
};


// Shared memory
KEYISO_SHARED_MEM *KeyIso_open_shared_mem(
    const uuid_t correlationId,
    int memLength,
    unsigned char **memBytes);

void KeyIso_close_shared_mem(
    KEYISO_SHARED_MEM *sharedMem);
    
// Functions

// ctrl client 
    int KeyIso_CLIENT_cert_ctrl(
    const uuid_t correlationId,
    KEYISO_SHARED_MEM *sharedMem,
    int ctrl,
    int location,
    int format,
    int length,
    const unsigned char *bytes);

int KeyIso_SERVER_cert_ctrl(
    const uuid_t correlationId,
    int ctrl,
    int location,
    int format,
    int length,
    const unsigned char *bytes);