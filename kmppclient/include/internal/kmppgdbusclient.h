/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <stdbool.h>

#include "keyisocommon.h" 
#include "keyisoipcgenericmessage.h"

//
// Define the GDBus implementation of the IPC client abstraction functions
//


// Implementation details for open the IPC connection and sending open key message
IPC_REPLY_ST* KeyIso_create_gdbus_proxy_and_send_open_key(KEYISO_KEY_CTX *keyCtx, IPC_SEND_RECEIVE_ST *ipcSt, int *result);

// Implementation details for open only the IPC connection for stateless operations
int KeyIso_gdbus_open_ipc(KEYISO_KEY_CTX *keyCtx);

// Implementation details for sending a message over GDBus
IPC_REPLY_ST* KeyIso_send_gdbus(KEYISO_KEY_CTX *keyCtx, IPC_SEND_RECEIVE_ST *ipcSt, int *result, bool isPermanentSessionRequired);

// Implementation details for checking if the IPC requires encoding
bool KeyIso_gdbus_is_encoding();

// Implementation details for checking the IPC connection
bool KeyIso_check_gdbus(KEYISO_KEY_CTX *keyCtx);

// Implementation details for close the IPC connection and sending close key message
void KeyIso_close_gdbus(KEYISO_KEY_CTX *keyCtx);

// Signals that open key operation has completed
void KeyIso_signal_open_key_completed_gdbus(KEYISO_KEY_CTX *keyCtx);

// Check if the key was already opened by a different thread
bool KeyIso_is_key_already_opened_gdbus(IPC_REPLY_ST *reply, int result);

// Validate the service compatibility from the result
bool KeyIso_is_service_compatiblity_error_gdbus(KEYISO_KEY_CTX *keyCtx, int result);