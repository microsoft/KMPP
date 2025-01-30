/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <string.h>

#include "keyisocommon.h"
#include "keyisoipcgenericmessage.h"
#include "keyisomemory.h"

#include "kmppgdbusclientcommon.h"  // gdbus
#include "kmppgdbusclient.h"        // gdbus

#ifndef KMPP_GENERAL_PURPOSE_TARGET
#include "kmppopteeclient.h"        // optee
#endif

#include "keyisoinprocmsghandler.h" // in-proc

// Define the functions table
typedef struct ipc_client_functions_table_st IPC_CLIENT_FUNCTIONS_TABLE_ST;
struct ipc_client_functions_table_st {
    int (*init)(KEYISO_KEY_DETAILS *keyDetail);
    bool (*isEncoding)();
    bool (*checkConnection)(KEYISO_KEY_CTX *keyCtx);
    int (*openConnection)(KEYISO_KEY_CTX *keyCtx); //stateless operation: Open only IPC
    IPC_REPLY_ST* (*openConnectionAndKey)(KEYISO_KEY_CTX *keyCtx, IPC_SEND_RECEIVE_ST *ipcSt, int *result); //Stateful connection: Open IPC and send key to service
    IPC_REPLY_ST* (*send)(KEYISO_KEY_CTX *keyCtx, IPC_SEND_RECEIVE_ST *ipcSt, int *result, bool isPermanentSessionRequired);
    void (*closeConnection)(KEYISO_KEY_CTX *keyCtx);
    void (*signalOpenKeyCompleted)(KEYISO_KEY_CTX *keyCtx);
    bool (*isKeyAlreadyOpened)(IPC_REPLY_ST *reply, int result);
    bool (*KeyIso_is_service_compatiblity_error)(KEYISO_KEY_CTX *keyCtx, int result);
};

static IPC_CLIENT_FUNCTIONS_TABLE_ST ipcImp;

//////////////////////////////////////////////////////////////////////////////////////
//
// Define the GDBUS implementation of the IPC client functions
//
//////////////////////////////////////////////////////////////////////////////////////
const IPC_CLIENT_FUNCTIONS_TABLE_ST GDBusClientImplementation = {
    .init = KeyIso_init_gdbus_in_keyDetails,
    .isEncoding = KeyIso_gdbus_is_encoding,
    .checkConnection = KeyIso_check_gdbus,
    .openConnection = KeyIso_gdbus_open_ipc,
    .openConnectionAndKey = KeyIso_create_gdbus_proxy_and_send_open_key, 
    .send = KeyIso_send_gdbus,
    .closeConnection = KeyIso_close_gdbus,
    .signalOpenKeyCompleted = KeyIso_signal_open_key_completed_gdbus,
    .isKeyAlreadyOpened = KeyIso_is_key_already_opened_gdbus,
    .KeyIso_is_service_compatiblity_error = KeyIso_is_service_compatiblity_error_gdbus,
};

//////////////////////////////////////////////////////////////////////////////////////
//
// Define the OP-TEE implementation of the IPC client functions
//
//////////////////////////////////////////////////////////////////////////////////////
#ifndef KMPP_GENERAL_PURPOSE_TARGET
const IPC_CLIENT_FUNCTIONS_TABLE_ST OpteeImplementation = {
    .init = KeyIso_init_optee_in_keyDetails,
    .isEncoding = NULL,
    .checkConnection = KeyIso_optee_check_connection,
    .openConnection = KeyIso_optee_open_session,
    .openConnectionAndKey = KeyIso_create_optee_session_and_send_open_key, 
    .send = KeyIso_optee_send,
    .closeConnection = KeyIso_optee_close_session,
    .signalOpenKeyCompleted = NULL,
    .isKeyAlreadyOpened = NULL,
    .KeyIso_is_service_compatiblity_error = NULL,
};
#endif 
//////////////////////////////////////////////////////////////////////////////////////
//
// Define the IN-PROC implementation of the IPC client functions
//
//////////////////////////////////////////////////////////////////////////////////////
const IPC_CLIENT_FUNCTIONS_TABLE_ST InProcClientImplementation = {
    .init = NULL,
    .isEncoding = NULL,
    .checkConnection = NULL,    // no connection to check (in-proc)
    .openConnection = NULL,     // no connection to open (in-proc)
    .openConnectionAndKey = NULL, 
    .send = KeyIso_send_ipc,
    .closeConnection = NULL,    // no connection to close (in-proc)
    .signalOpenKeyCompleted = NULL,
    .isKeyAlreadyOpened = NULL,
    .KeyIso_is_service_compatiblity_error = NULL,
};
static const IPC_CLIENT_FUNCTIONS_TABLE_ST ipcInProcImp = InProcClientImplementation;

//////////////////////////////////////////////////////////////////////////////////////


void KeyIso_client_set_ipcImp(KeyIsoSolutionType solutionType)
{
    if (solutionType == KeyIsoSolutionType_process) {
        ipcImp = GDBusClientImplementation;
    }
     
#ifndef KMPP_GENERAL_PURPOSE_TARGET 
    if (solutionType == KeyIsoSolutionType_tz) {
        ipcImp = OpteeImplementation;
    }
#endif

}   

//////////////////////////////////////////////////////////////////////////////////////

int KeyIso_client_adapter_init_keyCtx(KEYISO_KEY_CTX *keyCtx, int keyLength, const unsigned char *keyBytes, const char *salt)
{
    size_t saltLength = (salt != NULL) ? (strlen(salt) + 1) : 0;
    size_t dynamicLen = saltLength + keyLength;
    KEYISO_KEY_DETAILS *keyDetails = (KEYISO_KEY_DETAILS *)KeyIso_zalloc(sizeof(KEYISO_KEY_DETAILS) + dynamicLen);
    if (keyDetails == NULL) 
        return STATUS_FAILED;

    keyCtx->keyDetails = keyDetails;
    if (ipcImp.init(keyCtx->keyDetails) == 0)
        return STATUS_FAILED;
    
    keyDetails->keyLength = keyLength;
    keyDetails->keyBytes = (unsigned char *) &keyDetails[1];
    if (keyBytes)
        memcpy(keyDetails->keyBytes, keyBytes, keyLength);
    if (salt) {
        keyDetails->salt = (char *) (keyDetails->keyBytes + keyLength);
        memcpy(keyDetails->salt, salt, saltLength);
    }
    return STATUS_OK;    
}


void KeyIso_client_adapter_free_keyCtx(KEYISO_KEY_CTX *keyCtx)
{
    if(keyCtx == NULL)
        return;
        
    KEYISO_KEY_DETAILS *keyDetails = (KEYISO_KEY_DETAILS*)keyCtx->keyDetails;
    if (keyDetails == NULL) 
        return;

    ipcImp.closeConnection(keyCtx);

    if (keyDetails->keyBytes != NULL && keyDetails->keyLength != 0) {
        KeyIso_cleanse(keyDetails->keyBytes, keyDetails->keyLength);
    }
    if (keyDetails->salt != NULL) {
        KeyIso_cleanse(keyDetails->salt, strlen(keyDetails->salt));
    }

    KeyIso_free(keyDetails->interfaceSession);
    keyDetails->interfaceSession = NULL;

    KeyIso_free(keyDetails);
    keyDetails = NULL;
}


bool KeyIso_client_adapter_is_encoding()
{
    if (KEYISOP_inProc) {
        return false;
    } else {
        return (ipcImp.isEncoding) ? ipcImp.isEncoding() : false;
    }
}


bool KeyIso_client_adapter_is_connection(KEYISO_KEY_CTX *keyCtx)
{
    if (KEYISOP_inProc) {
        return false;
    } else {
        return ipcImp.checkConnection(keyCtx);
    }
}


int KeyIso_client_adapter_open_ipc(KEYISO_KEY_CTX *keyCtx)
{
    if (KEYISOP_inProc) {
        return STATUS_OK;
    } else {
        return ipcImp.openConnection(keyCtx);
    }
}


IPC_REPLY_ST* KeyIso_client_adapter_send_open_ipc_and_key(KEYISO_KEY_CTX *keyCtx, IPC_SEND_RECEIVE_ST *ipcSt, int *result)
{
    if (KEYISOP_inProc) {
        return ipcInProcImp.send(keyCtx, ipcSt, result, true);
    }
    return ipcImp.openConnectionAndKey(keyCtx, ipcSt, result);    
}


IPC_REPLY_ST* KeyIso_client_adapter_send_ipc(KEYISO_KEY_CTX *keyCtx, IPC_SEND_RECEIVE_ST *ipcSt, int *result, bool isPermanentSessionRequired)
{        
    if (KEYISOP_inProc) {
        return ipcInProcImp.send(keyCtx, ipcSt, result, isPermanentSessionRequired);
    } 
    return ipcImp.send(keyCtx, ipcSt, result, isPermanentSessionRequired);   
}

void KeyIso_client_adapter_key_open_completed(KEYISO_KEY_CTX *keyCtx)
{
  if (ipcImp.signalOpenKeyCompleted != NULL) {
    ipcImp.signalOpenKeyCompleted(keyCtx);
  }
}

bool KeyIso_client_adapter_is_key_already_opened(IPC_REPLY_ST *reply, int result)
{
    if (ipcImp.isKeyAlreadyOpened != NULL) {
        return ipcImp.isKeyAlreadyOpened(reply, result);
    }
    return false;
}

bool KeyIso_client_adapter_is_service_compatiblity_error(KEYISO_KEY_CTX *keyCtx, int result)
{
    if (ipcImp.KeyIso_is_service_compatiblity_error != NULL) {
        return ipcImp.KeyIso_is_service_compatiblity_error(keyCtx, result);
    }
    return false;
}