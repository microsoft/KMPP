/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <string.h>

#include "keyisocommon.h"
#include "keyisoipcgenericmessage.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisoutils.h"

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

static int _decode_client_data(
    const uuid_t correlationId,
    const char *clientData,
    void **outClientData,
    uint32_t *outDataSize)
{
    const char *title = KEYISOP_INIT_KEY_CONTEXT_TITLE;
    
    if (clientData == NULL || outClientData == NULL || outDataSize == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "null arg", "Invalid argument");
        return STATUS_FAILED;
    }

    *outClientData = NULL;
    *outDataSize = 0;

    // Decode base64 once
    unsigned char *decodedData = NULL;
    int decodedDataLen = KeyIso_base64_decode(correlationId, clientData, &decodedData);
    if (decodedDataLen <= 0) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "Base64 decode", "Failed or invalid decoded length", "length: %d", decodedDataLen);
        return STATUS_FAILED;
    }

    const uint32_t headerSize = sizeof(KEYISO_CLIENT_KEYID_HEADER_ST);
    if ((uint32_t)decodedDataLen < headerSize) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "Size mismatch", "Decoded data is too short", "length: %d, min expected: %u", decodedDataLen, headerSize);
        KeyIso_clear_free(decodedData, decodedDataLen);
        return STATUS_FAILED;
    }

    // Check key type from header - copy to ensure proper alignment
    KEYISO_CLIENT_KEYID_HEADER_ST header;
    memcpy(&header, decodedData, headerSize);
    
    if (header.keyType == KmppKeyIdType_symmetric) {
        // For symmetric keys, we expect only header
        *outClientData = KeyIso_zalloc(headerSize);
        if (*outClientData == NULL) {
            KeyIso_clear_free(decodedData, decodedDataLen);
            return STATUS_FAILED;
        }
        memcpy(*outClientData, decodedData, headerSize);
        *outDataSize = headerSize;
        KeyIso_clear_free(decodedData, decodedDataLen);
    } else if (header.keyType == KmppKeyIdType_asymmetric) {
        // For asymmetric keys we expect the client data structure
        if ((uint32_t)decodedDataLen < sizeof(KEYISO_CLIENT_DATA_ST)) {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "Invalid size - Expected asymmetric key data structure", "Decoded data is too short", "length: %d, expected: %u", decodedDataLen, sizeof(KEYISO_CLIENT_DATA_ST));
            KeyIso_clear_free(decodedData, decodedDataLen);
            return STATUS_FAILED;
        }
        
        // Return the full decoded data
        *outClientData = decodedData;
        *outDataSize = (uint32_t)decodedDataLen;
        decodedData = NULL; // Transfer ownership
    } else {
        // Unrecognized key type
        KEYISOP_trace_log_error_para(correlationId, 0, title, "Invalid key type", "Key type not recognized", "keyType: %d", header.keyType);
        KeyIso_clear_free(decodedData, decodedDataLen);
        return STATUS_FAILED;
    }

    return STATUS_OK;
}

int KeyIso_client_adapter_init_keyCtx(KEYISO_KEY_CTX *keyCtx, int keyLength, const unsigned char *keyBytes, const char *clientData)
{
    const char *title = KEYISOP_INIT_KEY_CONTEXT_TITLE;
    if (keyCtx == NULL || keyLength <= 0 || keyLength > UINT32_MAX || keyBytes == NULL || clientData == NULL) {
        KEYISOP_trace_log_error(NULL, 0, title, "null arg", "Invalid argument");
        return STATUS_FAILED;
    }
    
    uint32_t clientDataLen = strnlen(clientData, MAX_CLIENT_DATA_BASE64_LENGTH);
    if (clientDataLen == 0 || clientDataLen >= MAX_CLIENT_DATA_BASE64_LENGTH) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, title, "clientData", "Invalid argument");
        return STATUS_FAILED;
    }

    // Decode the client data efficiently - decode once and determine what to keep
    void *clientDataToStore = NULL;
    uint32_t clientDataSize = 0;
    
    // First decode to get just the header and determine key type
    if (_decode_client_data(keyCtx->correlationId, clientData, &clientDataToStore, &clientDataSize) != STATUS_OK) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, title, "Failed to decode keys metadata header", "");
        return STATUS_FAILED;
    }
    
    // Calculate total size for key details structure
    uint32_t totalSize = 0;
    if (KEYISO_ADD_OVERFLOW((uint32_t)keyLength, clientDataSize, &totalSize) || 
        KEYISO_ADD_OVERFLOW(totalSize, sizeof(KEYISO_KEY_DETAILS), &totalSize)) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, title, "Overflow", "Key length overflow");
        KeyIso_clear_free(clientDataToStore, clientDataSize);
        return STATUS_FAILED;
    }

    KEYISO_KEY_DETAILS *keyDetails = (KEYISO_KEY_DETAILS *)KeyIso_zalloc(totalSize);
    if (keyDetails == NULL) {
        KeyIso_clear_free(clientDataToStore, clientDataSize);
        return STATUS_FAILED;
    }
 
    // Setup the key bytes pointer to the memory right after the struct
    keyDetails->keyBytes = (unsigned char *) &keyDetails[1];
    memcpy(keyDetails->keyBytes, keyBytes, keyLength);
    keyDetails->keyLength = keyLength;
    
    // Store the client data
    if (clientDataSize > 0) {
        keyDetails->clientData = keyDetails->keyBytes + keyLength; // Point to the memory right after the key bytes
        // clientDataToStore contains either KEYISO_CLIENT_KEYID_HEADER_ST (symmetric) or KEYISO_CLIENT_DATA_ST (asymmetric)
        memcpy(keyDetails->clientData, clientDataToStore, clientDataSize);
    }
    
    KeyIso_clear_free(clientDataToStore, clientDataSize);
    keyCtx->keyDetails = keyDetails;

    // Init session, per IPC implementation
    if (ipcImp.init(keyDetails) == 0) {   
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, title, "init", "Failed to init IPC session");
        KeyIso_free(keyDetails);
        return STATUS_FAILED;
    }
    return STATUS_OK;    
}

void KeyIso_client_adapter_free_keyCtx(KEYISO_KEY_CTX *keyCtx)
{
    if (keyCtx == NULL)
        return;
        
    KEYISO_KEY_DETAILS *keyDetails = (KEYISO_KEY_DETAILS*)keyCtx->keyDetails;
    if (keyDetails == NULL) 
        return;

    ipcImp.closeConnection(keyCtx);

    if (keyDetails->keyBytes != NULL && keyDetails->keyLength != 0) {
        KeyIso_cleanse(keyDetails->keyBytes, keyDetails->keyLength);
    }

    if (keyDetails->interfaceSession != NULL) {
        KeyIso_free(keyDetails->interfaceSession);
        keyDetails->interfaceSession = NULL;
    }

    KeyIso_free(keyDetails);
    keyCtx->keyDetails = NULL;
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