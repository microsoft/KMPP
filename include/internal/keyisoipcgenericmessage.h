/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <inttypes.h> 
#include <uuid/uuid.h>

#define IPC_FAILURE      -1   //compatible with previous versions error codes
#define IPC_NO_OPERATION_NEEDED -2 
#define IPC_UNKNOWN_METHOD  -3

//
// IPC structures - to be sent on the IPC
//

typedef struct ipc_send_receive_st IPC_SEND_RECEIVE_ST;
struct ipc_send_receive_st {
    uint32_t command; //IpcCommand
    uint32_t inLen;
    uint8_t *inSt;
};

typedef struct ipc_reply_st IPC_REPLY_ST;
struct ipc_reply_st {
    uint32_t command; //IpcCommand
    uint32_t outLen;
    uint8_t *outSt;
};
