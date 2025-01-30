/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <stdbool.h>

#include "keyisocommon.h"
#include "keyisoipcgenericmessage.h"

///////////////////////////////////////////////////////////////////////
//                           IN-PROC IPC                             //
///////////////////////////////////////////////////////////////////////

IPC_REPLY_ST* KeyIso_send_ipc(
    KEYISO_KEY_CTX *keyCtx, 
    IPC_SEND_RECEIVE_ST *ipcSt, 
    int *result,
    bool isPermanentSessionRequired);