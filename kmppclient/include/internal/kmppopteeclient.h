/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <stdbool.h>
#include <pthread.h>

#include <tee_client_api.h>

#include "keyisocommon.h"
#include "keyisoipcgenericmessage.h"

typedef struct KeyIso_optee_session_st KEYISO_OPTEE_SESSION;
struct KeyIso_optee_session_st
{ 
    TEEC_Session          *teecSess;  // OP-TEE session identification 
    pthread_mutex_t       mutex;      // Mutex for session
}; 

// Implementation details for initializing op-tee IPC
int KeyIso_init_optee_in_keyDetails(KEYISO_KEY_DETAILS *keyDetails);

// Implementation details for open the IPC connection and sending open key message
IPC_REPLY_ST* KeyIso_create_optee_session_and_send_open_key(KEYISO_KEY_CTX *keyCtx, IPC_SEND_RECEIVE_ST *ipcSt, int *result);

// Implementation details for open only the IPC connection for stateless operations
int KeyIso_optee_open_session(KEYISO_KEY_CTX *keyCtx);

// Implementation details for sending a message over OP-TEE
IPC_REPLY_ST* KeyIso_optee_send(KEYISO_KEY_CTX *keyCtx, IPC_SEND_RECEIVE_ST *ipcSt, int *result, bool isPermanentSessionRequired);

// Implementation details for checking the IPC connection
bool KeyIso_optee_check_connection(KEYISO_KEY_CTX *keyCtx);

// Implementation details for close the IPC connection and sending close key message
void KeyIso_optee_close_session(KEYISO_KEY_CTX *keyCtx);

// Config for optee
int KeyIso_get_isolation_solution_for_tz();