/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include "kmppopteeclient.h"
#include "keyisocommon.h"
#include "keyisomemory.h"
#include "keyisoipcgenericmessage.h"
#include "keyisoipccommands.h"
#include "keyisoclientinternal.h"
#include "keyisolog.h"
#include "kmppopteeutils.h"

// For the UUID
#include "kmppta.h"

#define KEYISO_TA_STATELESS_SESSION        0
#define KEYISO_TA_STATEFULL_SESSION        1


///////////////////////////////////////////////////////////////////////////////////
////////////////////////// INTERNAL FUNCTIONS /////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////

static const char *command_strings[] = {
    [IpcCommand_OpenPrivateKey] = "OpenPrivateKey",
    [IpcCommand_CloseKey] = "CloseKey",
    [IpcCommand_EcdsaSign] = "EcdsaSign",
    [IpcCommand_RsaPrivateEncryptDecrypt] = "RsaPrivateEncryptDecrypt",
    [IpcCommand_GenerateRsaKeyPair] = "GenerateRsaKeyPair",
    [IpcCommand_GenerateEcKeyPair] = "GenerateEcKeyPair",
    [IpcCommand_ImportRsaPrivateKey] = "ImportRsaPrivateKey",
    [IpcCommand_ImportEcPrivateKey] = "ImportEcPrivateKey",
    [IpcCommand_ImportSymmetricKey] = "ImportSymmetricKey",
    [IpcCommand_SymmetricKeyEncryptDecrypt] = "SymmetricKeyEncryptDecrypt"
};

static const char *_get_command_string(int command)
{
    if (command < 0 || command >= sizeof(command_strings) / sizeof(command_strings[0])) {
        return "Unknown";
    }
    return command_strings[command];
}

static void _free_optee_session(TEEC_Session **teecSess)
{    
    if (*teecSess) {
        TEEC_CloseSession(*teecSess);
        if ((*teecSess)->ctx) {
            TEEC_FinalizeContext((*teecSess)->ctx);
            KeyIso_free((*teecSess)->ctx);
            (*teecSess)->ctx = NULL;            
        }
        KeyIso_free(*teecSess);
        *teecSess = NULL;        
    }
}

// Allocate new OP-TEE context and session
static int _optee_session_alloc(TEEC_Context **teecCtx, TEEC_Session **teecSess)
{
    if (!teecCtx || !teecSess) {
        return STATUS_FAILED;
    }
    *teecCtx = NULL;
    *teecSess = NULL;

    //1. Create new initialized OP-TEE context
    TEEC_Context *ctx = (TEEC_Context *)KeyIso_zalloc(sizeof(TEEC_Context));
    if (!ctx) {
        return STATUS_FAILED;
    }

	TEEC_Result res = TEEC_InitializeContext(NULL, ctx);    // NULL 'name' means default TEE to connect to
	if (res != TEEC_SUCCESS) {
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_OPTEE_CLIENT_TITLE, "TEEC_InitializeContext", "Failed", "error code: 0x%x", res);
        KeyIso_free(ctx);
        return STATUS_FAILED;
    }

    //2. Allocate a new OP-TEE session
    TEEC_Session *sess = (TEEC_Session *)KeyIso_zalloc(sizeof(TEEC_Session));
    if (!sess) {
        TEEC_FinalizeContext(ctx);
        KeyIso_free(ctx);
        return STATUS_FAILED;
    }

    *teecCtx = ctx;
    *teecSess = sess;

    return STATUS_OK;
}

// Open a new OP-TEE session
// state = KEYISO_TA_STATELESS_SESSION - stateless session (do not allocate memory for session in the TA)
// state = KEYISO_TA_STATEFULL_SESSION - statefull session (allocate memory for session in the TA)
static int _open_optee_session(TEEC_Session **sess, uint32_t state)
{
    if (!sess) {
        return STATUS_FAILED;
    }
    *sess = NULL;

    TEEC_Operation op;
    TEEC_Context *teecCtx = NULL;
    TEEC_UUID uuid = TA_KMPP_UUID;
    TEEC_Result res = TEEC_ERROR_GENERIC;
    uint32_t err_origin = 0;

    //1. Create new OP-TEE context and session
    if (_optee_session_alloc(&teecCtx, sess) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPTEE_CLIENT_TITLE, "_optee_session_alloc", "Failed");
        return STATUS_FAILED;
    }

    //2. Invoke the open command
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE);
    op.params[0].value.a = state;    // allocate or don't allocate
    
    res = TEEC_OpenSession(teecCtx, *sess, &uuid, TEEC_LOGIN_USER, NULL, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_OPTEE_CLIENT_TITLE, "TEEC_OpenSession", "Failed", "error code 0x%x origin 0x%x", res, err_origin);
        TEEC_FinalizeContext(teecCtx);
        KeyIso_free(teecCtx);
        teecCtx = NULL;       
        if (*sess) {
            KeyIso_free(*sess);
            *sess = NULL;
        }
        return STATUS_FAILED;
    }

    uint32_t serviceVersion = op.params[1].value.a;
    uint32_t taVersion = op.params[1].value.b;
    KEYISOP_trace_log_para(NULL, 0, KEYISOP_OPTEE_CLIENT_TITLE, "TEEC_OpenSession", "Opened session with service version %d and TA version %d", serviceVersion, taVersion);    
    
    return STATUS_OK;
}

static KEYISO_OPTEE_SESSION* _get_key_interface_session(KEYISO_KEY_CTX *keyCtx)
{
    if (!keyCtx)
        return NULL;

    KEYISO_KEY_DETAILS* keyDetails = (KEYISO_KEY_DETAILS*)keyCtx->keyDetails;
    if (!keyDetails || !keyDetails->interfaceSession) {
        return NULL;
    }

    KEYISO_OPTEE_SESSION *session = (KEYISO_OPTEE_SESSION *)keyDetails->interfaceSession;
    return session;
}

// Get the OP-TEE session from the keyCtx under lock
static int _get_optee_session(KEYISO_OPTEE_SESSION *session, TEEC_Session **teecSess)
{
    int ret = STATUS_FAILED;
    if (!session || !teecSess) {
        return ret;
    }

    *teecSess = NULL;
    pthread_mutex_lock(&session->mutex);
    if (session->teecSess != NULL) {
        *teecSess = session->teecSess;
        ret = STATUS_OK;
    }
    pthread_mutex_unlock(&session->mutex);
    
    return ret;
}

// Set an OP-TEE session in the keyCtx under lock
static int _set_optee_session(KEYISO_KEY_CTX *keyCtx, TEEC_Session *teecSess)
{
    int ret = STATUS_FAILED;

    KEYISO_OPTEE_SESSION *session  = _get_key_interface_session(keyCtx);
    if (!session || !teecSess) {
        return ret;
    }

    pthread_mutex_lock(&session->mutex);
    session->teecSess = teecSess;
    ret = STATUS_OK;
    pthread_mutex_unlock(&session->mutex);

    return ret;
}

///////////////////////////////////////////////////////////////////////////////////
////////////////////////// EXTERNAL FUNCTIONS /////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////

// Implementation details for initializing op-tee IPC
int KeyIso_init_optee_in_keyDetails(KEYISO_KEY_DETAILS *keyDetails)
{    
    KEYISO_OPTEE_SESSION *session = (KEYISO_OPTEE_SESSION *)KeyIso_zalloc(sizeof(KEYISO_OPTEE_SESSION));
    if (session != NULL) {
        int ret = pthread_mutex_init(&session->mutex, NULL);
        if (ret != 0) {
            KeyIso_free(session);
            session = NULL;
            return STATUS_FAILED;
        } 
        session->teecSess = NULL;        
        keyDetails->interfaceSession = session;
        return STATUS_OK;
    }

    return STATUS_FAILED;
}

// Implementation details for checking the IPC connection
bool KeyIso_optee_check_connection(KEYISO_KEY_CTX *keyCtx)
{    
    KEYISO_OPTEE_SESSION *session  = _get_key_interface_session(keyCtx);
    if (!session)
        return false;

    KEYISO_KEY_DETAILS* keyDetails = (KEYISO_KEY_DETAILS*)keyCtx->keyDetails;
    if (!keyDetails)
        return false;

    pthread_mutex_lock(&session->mutex);
    bool ret = (session->teecSess != NULL) && (keyDetails->keyId > 0);
    pthread_mutex_unlock(&session->mutex);

    return ret;
}

// Implementation details for sending a message over OP-TEE
IPC_REPLY_ST* KeyIso_optee_send(KEYISO_KEY_CTX *keyCtx, IPC_SEND_RECEIVE_ST *ipcSt, int *result, bool isPermanentSessionRequired)
{    
    if (!ipcSt || !ipcSt->inSt || !result)
        return NULL;    
    
    KEYISO_OPTEE_SESSION *session  = _get_key_interface_session(keyCtx);
    if (isPermanentSessionRequired && !session) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_OPTEE_CLIENT_TITLE, "_get_key_interface_session", "failed");
        return NULL;       
    }
    TEEC_Operation op;
    TEEC_Result res = TEEC_ERROR_GENERIC;
    TEEC_Session *teecSess = NULL;
    IPC_REPLY_ST *reply = NULL;
    uint32_t returnOrigin = 0;
    *result = STATUS_OK;

    //1. Retrieve the session
    if ((isPermanentSessionRequired && (_get_optee_session(session, &teecSess) != STATUS_OK)) ||
        (!isPermanentSessionRequired && (_open_optee_session(&teecSess, KEYISO_TA_STATELESS_SESSION) != STATUS_OK))) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_OPTEE_CLIENT_TITLE, "Retrieve session", "Failed");
        *result = IPC_FAILURE;             
        return NULL;
    }

    //2. Prepare to send
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);    
	op.params[0].tmpref.buffer = ipcSt->inSt;
	op.params[0].tmpref.size = ipcSt->inLen;    

    //3. Allocate the output buffer
    int estimatedOutStuctSize = KeyIso_get_estimate_out_len(ipcSt->command, ipcSt);
    uint8_t *outSt = (uint8_t *)KeyIso_zalloc(estimatedOutStuctSize);

    if (!outSt) {
        return NULL;
    }
	
	op.params[1].tmpref.buffer = outSt;
	op.params[1].tmpref.size = estimatedOutStuctSize;

    //2. Send on IPC
	res = TEEC_InvokeCommand(teecSess, ipcSt->command, &op, &returnOrigin);
    KEYISOP_trace_log_para(keyCtx->correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_OPTEE_CLIENT_TITLE, "TEEC_InvokeCommand", 
        "Received %s response from KMPP TA - %lu", _get_command_string(ipcSt->command), op.params[1].tmpref.size);

    if ((res == TEEC_ERROR_SHORT_BUFFER) && (op.params[1].tmpref.size > estimatedOutStuctSize)) {
        KEYISOP_trace_log_para(keyCtx->correlationId, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_OPTEE_CLIENT_TITLE, "TEEC_InvokeCommand",
            "KMPP TA asked for a larger output buf - estimated = %d actual = %lu\n", estimatedOutStuctSize, op.params[1].tmpref.size);

        uint8_t *biggerOutSt = (uint8_t *)KeyIso_realloc(outSt, op.params[1].tmpref.size);
        if (!biggerOutSt) {
            KeyIso_free(outSt);
            *result = IPC_FAILURE;
            return NULL;
        }

        memset(biggerOutSt, 0, op.params[1].tmpref.size);
        outSt = biggerOutSt;
        op.params[1].tmpref.buffer = outSt;
        res = TEEC_InvokeCommand(teecSess, ipcSt->command, &op, &returnOrigin);

        KEYISOP_trace_log_para(keyCtx->correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_OPTEE_CLIENT_TITLE, "TEEC_InvokeCommand",
            "Received %s response from KMPP TA - %lu", _get_command_string(ipcSt->command), op.params[1].tmpref.size);
	}

    //3. Error handling
	if (res != TEEC_SUCCESS) {
        KEYISOP_trace_log_error_para(keyCtx->correlationId, 0, KEYISOP_OPTEE_CLIENT_TITLE, "TEEC_InvokeCommand", "Failed", 
                "Error code code 0x%x origin 0x%x", ipcSt->command, res, returnOrigin);

        if (!isPermanentSessionRequired) {              
            _free_optee_session(&teecSess);            
        }
        KeyIso_free(outSt);
        *result = IPC_FAILURE;
        return NULL;
    }
    
    //4. Receive reply
    reply = (IPC_REPLY_ST *)KeyIso_zalloc(sizeof(IPC_REPLY_ST) + op.params[1].tmpref.size);
    if (!reply) {
        if (!isPermanentSessionRequired) {              
            _free_optee_session(&teecSess);            
        }
        KeyIso_free(outSt);
        *result = IPC_FAILURE;
        return NULL;
    }
    
    reply->command = ipcSt->command;
    reply->outLen = op.params[1].tmpref.size;
    reply->outSt = (uint8_t *)outSt;    

    return reply;
}

// Implementation details for open the IPC connection and sending open key message
IPC_REPLY_ST* KeyIso_create_optee_session_and_send_open_key(KEYISO_KEY_CTX *keyCtx, IPC_SEND_RECEIVE_ST *ipcSt, int *result)
{    
    KEYISO_OPTEE_SESSION *session = _get_key_interface_session(keyCtx);
    if (!session) {  
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_OPTEE_CLIENT_TITLE, "_get_key_interface_session", "failed");      
        return NULL;
    }
    
    int status = STATUS_FAILED;
    IPC_REPLY_ST *reply = NULL;
    TEEC_Session *teecSess = NULL;
    *result = STATUS_OK;

    //1. Open the session
    if (_open_optee_session(&teecSess, KEYISO_TA_STATEFULL_SESSION) != STATUS_OK) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_OPTEE_CLIENT_TITLE, "_open_optee_session", "failed");
        return NULL;
    }
    
    //2. Set the session to the keyCtx
    status = _set_optee_session(keyCtx, teecSess);
    if (status != STATUS_OK) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_OPTEE_CLIENT_TITLE, "_set_optee_session", "failed");        
        _free_optee_session(&teecSess);
        
    } else {
        //3. Send the open command
        reply = KeyIso_optee_send(keyCtx, ipcSt, result, true);
        if (result && *result != STATUS_OK) {
            KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_OPTEE_CLIENT_TITLE, "KeyIso_optee_send", "failed");   

            // Since the open command has failed this time, we want to make sure that before next crypto operation, the open command will take place again.
            // That is why we are closing and freeing the session (TEEC_Session).
            if (session && session->teecSess) {                                
                pthread_mutex_lock(&session->mutex);
                _free_optee_session(&(session->teecSess));
                pthread_mutex_unlock(&session->mutex);
            }
        }
    }

    return reply;
}

// Implementation details for open only the IPC connection for stateless operations
int KeyIso_optee_open_session(KEYISO_KEY_CTX *keyCtx)
{    
    KEYISO_OPTEE_SESSION *session = _get_key_interface_session(keyCtx);
    if (!session) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_OPTEE_CLIENT_TITLE, "_get_key_interface_session", "failed");
        return STATUS_FAILED;
    }
    
    TEEC_Session *teecSess = NULL;
    if (_open_optee_session(&teecSess, KEYISO_TA_STATELESS_SESSION) != STATUS_OK) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_OPTEE_CLIENT_TITLE, "_open_optee_session", "failed");
        return STATUS_FAILED;
    }

    return _set_optee_session(keyCtx, teecSess);
}

// Implementation details for close the IPC connection and sending close key message
void KeyIso_optee_close_session(KEYISO_KEY_CTX *keyCtx)
{    
    KEYISO_OPTEE_SESSION *session = _get_key_interface_session(keyCtx);
    if (!session) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_OPTEE_CLIENT_TITLE, "_get_key_interface_session", "failed");
        return;
    }
    
    pthread_mutex_lock(&session->mutex);
    _free_optee_session(&(session->teecSess));
    pthread_mutex_unlock(&session->mutex);    
    
    pthread_mutex_destroy(&session->mutex);
} 