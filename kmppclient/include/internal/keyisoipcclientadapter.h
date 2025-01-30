/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <stdbool.h>

#include "keyisocommon.h" 
#include "keyisoipcgenericmessage.h"

IPC_REPLY_ST* KeyIso_client_adapter_send_ipc(KEYISO_KEY_CTX *keyCtx, IPC_SEND_RECEIVE_ST *ipcSt, int *result, bool isPermanentSessionRequired);
IPC_REPLY_ST* KeyIso_client_adapter_send_open_ipc_and_key(KEYISO_KEY_CTX *keyCtx, IPC_SEND_RECEIVE_ST *ipcSt, int *result);
void KeyIso_client_adapter_key_open_completed(KEYISO_KEY_CTX *keyCtx); // Signal that key was opened and key contex data(key id) is initlized with a value(in case of success)
bool KeyIso_client_adapter_is_key_already_opened(IPC_REPLY_ST *reply, int result);

int KeyIso_client_adapter_init_keyCtx(KEYISO_KEY_CTX *keyCtx, int keyLength, const unsigned char *keyBytes, const char *salt);
void KeyIso_client_adapter_free_keyCtx(KEYISO_KEY_CTX *keyCtx);

bool KeyIso_client_adapter_is_encoding();

bool KeyIso_client_adapter_is_connection(KEYISO_KEY_CTX *keyCtx);
int KeyIso_client_adapter_open_ipc(KEYISO_KEY_CTX *keyCtx);

void KeyIso_client_set_ipcImp(KeyIsoSolutionType solutionType);

bool KeyIso_client_adapter_is_service_compatiblity_error(KEYISO_KEY_CTX *keyCtx, int result);