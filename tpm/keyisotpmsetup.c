/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <string.h>
#include <tss2/tss2_tctildr.h>

#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisotpmsetup.h"

///////////////////////////////       Configuration         ////////////////////////
KEYISO_TPM_CONFIG_ST tpmConfig = { 
    .nvIndex = DEFAULT_NV_INDEX,
    .tctiNameConf = DEFAULT_TCTI_CONFIG 
};

static TPM2_HANDLE primaryKeyHandle = 0; 
///////////////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////////////
// TODO: A parent key authentication and owner hierarchy authentication are not supported yet
//static TPM2B_DIGEST ownerHierarchyAuth = { .size = 0 };
//static TPM2B_DIGEST parentKeyAuth = { .size = 0 };
///////////////////////////////////////////////////////////////////////////////////////////////

void KeyIso_tpm_config_set(const KEYISO_TPM_CONFIG_ST newConfig)
{
    tpmConfig = newConfig;
}

static TSS2_RC _tpm_create_tcti_context(
    const uuid_t correlationId,
    const char* tctiNameConf,
    TSS2_TCTI_CONTEXT** outTctiCtx)
{
    const char* title = KEYISOP_TPM_KEY_TITLE;
    if (outTctiCtx == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "can't create tcti context", "received NULL pointer");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    
    *outTctiCtx = NULL;
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT* tctiCtx = NULL;
    rc = Tss2_TctiLdr_Initialize(tctiNameConf, &tctiCtx);
    if (rc != TSS2_RC_SUCCESS) 
    {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "can't create tcti context", "Tss2_TctiLdr_Initialize_Ex failed", "error: %d", rc);
        return rc;
    }

    *outTctiCtx = tctiCtx;
    return rc;
}

TSS2_RC KeyIso_tpm_create_context(
    const uuid_t correlationId,
    KEYISO_TPM_CONTEXT** outCtx)
{
    TSS2_RC rc;
    KEYISO_TPM_CONTEXT* ctx = NULL;
    const char* title = KEYISOP_TPM_KEY_TITLE;
    
    if (outCtx == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "can't create tpm context", "received NULL pointer");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    *outCtx = NULL;
    ctx = (KEYISO_TPM_CONTEXT*)KeyIso_zalloc(sizeof(KEYISO_TPM_CONTEXT));
    if(ctx == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "can't create tpm context", "failed allocating tpm context");
        return TSS2_ESYS_RC_MEMORY;
    }

    TSS2_TCTI_CONTEXT *tctiCtx = NULL;
    // Set the TCTI context
    rc = _tpm_create_tcti_context(correlationId, tpmConfig.tctiNameConf, &tctiCtx);
    if (rc != TSS2_RC_SUCCESS) {
        KEYISOP_trace_log_error(correlationId, 0, title, "can't create tcti  context", "_tpm_create_tcti_context failed");
        KeyIso_tpm_free_context(&ctx);
        return rc;
    }
    rc = Esys_Initialize(&ctx->ectx, tctiCtx, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        KEYISOP_trace_log_error(correlationId, 0, title, "can't create tpm context", "Esys_Initialize failed");
        Tss2_TctiLdr_Finalize(&tctiCtx);
        KeyIso_tpm_free_context(&ctx);
        return rc;
    }
    
    *outCtx = ctx;
    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete: tpm context created");
    return rc;
}

void KeyIso_tpm_free_context(KEYISO_TPM_CONTEXT** pCtx)
{
    if (pCtx != NULL && *pCtx != NULL) {
        KEYISO_TPM_CONTEXT* ctx = *pCtx;
        if (ctx->ectx) {
            TSS2_TCTI_CONTEXT* tctiContext = NULL;
            TSS2_RC rc = Esys_GetTcti(ctx->ectx, &tctiContext);
            Esys_Finalize(&ctx->ectx);
            if  (rc == TSS2_RC_SUCCESS && tctiContext != NULL) {
                Tss2_TctiLdr_Finalize(&tctiContext);
            }
        }
        KeyIso_free(ctx);
        *pCtx = NULL;
    }
}

TSS2_RC KeyIso_tpm_create_session(
    const uuid_t correlationId,
    KEYISO_TPM_CONTEXT* tpmContext,
    ESYS_TR tpmKey, 
    TPM2B_AUTH const* authValue,
    KEYISO_TPM_SESSION** outSession) // The session should be freed by the caller - KeyIso_tpm_session_free
{
    TSS2_RC rc = 0;
    KEYISO_TPM_SESSION* session = NULL;
    const char* title = KEYISOP_TPM_KEY_TITLE;

    if (outSession == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "session creation failed", "Invalid parameter - session pointer is NULL");
        rc = TSS2_ESYS_RC_BAD_REFERENCE;
        return rc;
    }
    
    *outSession = NULL;
    session = (KEYISO_TPM_SESSION*)KeyIso_zalloc(sizeof(KEYISO_TPM_SESSION));
    if (session == NULL) {
        rc = TSS2_ESYS_RC_MEMORY;
        KEYISOP_trace_log_error(correlationId, 0, title, "session creation failed", "Allocation failed");
        return rc;
    }

    session->tpmContext = tpmContext;
    session->params.tpmKey = tpmKey;            // The key to bind the session to
    session->params.bind = ESYS_TR_NONE;        // When you want to bind the session to a specific entity (like an NV index)
    session->params.sessionType = TPM2_SE_HMAC; // Use HMAC session(that uses HMAC for authorization)
    session->params.authHash = TPM2_ALG_SHA256; // Use SHA256 for authorization
    session->params.symmetric.algorithm = TPM2_ALG_NULL; 
    session->sessionHandle = ESYS_TR_NONE;

    rc = Esys_StartAuthSession(
                tpmContext->ectx,
                session->params.tpmKey,
                session->params.bind,
                ESYS_TR_NONE, 
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                NULL,
                session->params.sessionType,
                &session->params.symmetric,
                session->params.authHash,
                &session->sessionHandle);

    if (rc != TSS2_RC_SUCCESS) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "can't create session", "Esys_StartAuthSession failed", "error: %d", rc);
        KeyIso_tpm_session_free(correlationId, session);
        return rc;
    }
    if (authValue) {
        rc =  Esys_TR_SetAuth(tpmContext->ectx, session->sessionHandle, authValue);
        if (rc != TSS2_RC_SUCCESS) {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "can't create session", "Esys_TR_SetAuth failed", "error: %d", rc);
            KeyIso_tpm_session_free(correlationId, session);
            return rc;
        }
        memcpy(&session->auth, authValue, sizeof(*authValue));
    }

    *outSession = session;
    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete: tpm session created");
    return TSS2_RC_SUCCESS;
}

void KeyIso_tpm_session_free(
    const uuid_t correlationId,
    KEYISO_TPM_SESSION* session)
{
    const char* title = KEYISOP_TPM_KEY_TITLE;

    if (session) {
        if (session->tpmContext != NULL) {
            if (session->sessionHandle != ESYS_TR_NONE) {
                TSS2_RC rc = Esys_FlushContext(
                                    session->tpmContext->ectx,
                                    session->sessionHandle);
                if (rc != TSS2_RC_SUCCESS) {
                    KEYISOP_trace_log_error_para(correlationId, 0, title, "can't free session", "Esys_FlushContext failed", "error: %d", rc);
                }
                session->sessionHandle = ESYS_TR_NONE;
            }
            session->tpmContext = NULL;
        }
        KeyIso_free(session);
    }
}

// Retrieve the parent handle from NMRAM 
// We do not load the parent key to the TPM, we just retrieve its handle from NVRAM, the assumption is that in the NVRAM there is a handle of the loaded SRK
static TSS2_RC _tpm_init_primary_key_handle(
    const uuid_t correlationId,
    KEYISO_TPM_CONTEXT* ctx,
    ESYS_TR* outParent)
{
    TSS2_RC rc;
    ESYS_TR nvIndexHandle = ESYS_TR_NONE;
    KEYISO_TPM_SESSION* session = NULL;
    const char* title = KEYISOP_TPM_KEY_TITLE;
    
    if (ctx == NULL || outParent == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "can't init parent", "Invalid parameter - context or parent pointer is NULL");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    if (primaryKeyHandle == 0) {

        rc = Esys_TR_FromTPMPublic(ctx->ectx, tpmConfig.nvIndex, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &nvIndexHandle);
        if (rc != TSS2_RC_SUCCESS) {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "can't init parent", "Esys_TR_FromTPMPublic failed", "error: %d", rc);
            return rc;
        }

        // Start a session
        rc = KeyIso_tpm_create_session(correlationId, ctx, ESYS_TR_NONE, NULL, &session);
        if (rc != TSS2_RC_SUCCESS) {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "Can't acquire parent", "KeyIso_tpm_create_session failed", "error: %d", rc);
            return rc;
        }

        TPM2B_NV_PUBLIC *nvPublic = NULL;
        rc = Esys_NV_ReadPublic(ctx->ectx, nvIndexHandle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &nvPublic, NULL);
        if (rc != TSS2_RC_SUCCESS) {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "Can't init parent", "Esys_NV_ReadPublic failed", "handle: 0x%x,  error: %d", nvIndexHandle, rc);
            KeyIso_tpm_session_free(correlationId, session);
            return rc;
        }

        UINT16 offset = 0; // Start reading from the beginning of the NV index
        TPM2B_MAX_NV_BUFFER *data = NULL;
        // Our assumption is that the NV index created with the TPMA_NV_AUTHREAD attribute so it does not require owner authorization to read it only to write it
        // Otherwise we will need to pass here a different handle, for example if defined with ownerread need to be set to ESYS_TR_RH_OWNER as the authHierarchyHandle
        ESYS_TR authHandle = nvIndexHandle; // The entity providing the authorization
        // The shandle should be the handle of a session that is the authorization session for the command, the session should have the correct authorization value for the NV index
        ESYS_TR shandle1 = session->sessionHandle;

        rc = Esys_NV_Read(ctx->ectx, nvIndexHandle, authHandle, shandle1, ESYS_TR_NONE, ESYS_TR_NONE, nvPublic->nvPublic.dataSize, offset, &data);
        if (rc != TSS2_RC_SUCCESS) {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "Can't init parent", "Esys_NV_Read failed", "error: %d", rc);
            KeyIso_tpm_session_free(correlationId, session);
            return rc;
        }
        
        // Free the NV public structure
        Esys_Free(nvPublic);

        // Free the authorization session
        KeyIso_tpm_session_free(correlationId, session);
        uint32_t value;
        sscanf((char*)data->buffer, "%x", &value);
        
        // Clean up data buffer
        Esys_Free(data);
        primaryKeyHandle = value;
    }

    ESYS_TR esysParentHandle;
    // Takes TPM object's handle and created a ESYS_TR object for it, which you can then use with other ESAPI functions.
    rc = Esys_TR_FromTPMPublic(ctx->ectx, primaryKeyHandle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &esysParentHandle);
    if (rc != TSS2_RC_SUCCESS) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "can't init parent", "Esys_TR_FromTPMPublic for the parent handle failed", "error: %d", rc);
        return rc;
    }
    // A parent key assumed to not have a password, when the parent key password we will need to set provide the key authentication value on the key handle
    // rc = Esys_TR_SetAuth(ctx->ectx,
    //                          esysParentHandle,
    //                          &parentKeyAuth);

    // if(rc != TSS2_RC_SUCCESS) {
    //     KEYISOP_trace_log_error_para(correlationId, 0, title, "can't init parent", "Esys_TR_SetAuth failed", "error: %d", rc);
    //     return rc;
    // }

    // Set the parent handle
    *outParent = esysParentHandle;

    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete: primary key was successfully initalized");
    return TSS2_RC_SUCCESS;
}

//////////////////////////////////////////////
//
//  keyisotpmutils.h header implementation
//
/////////////////////////////////////////////
KEYISO_TPM_RET KeyIso_convert_ret_val(TSS2_RC rc)
{
    if (rc == TSS2_RC_SUCCESS) {
        return KEYISO_TPM_RET_SUCCESS;
    }

    if (rc == TSS2_TCTI_RC_MEMORY) {
        return KEYISO_TPM_RET_MEMORY;
    }

    if (rc == TSS2_TCTI_RC_BAD_VALUE) {
        return KEYISO_TPM_RET_BAD_PARAM;
    }

    return KEYISO_TPM_RET_FAILURE;
}

// Retrieve the parent handle from NMRAM 
TSS2_RC KeyIso_tpm_acquire_parent(
    const uuid_t correlationId,
    KEYISO_TPM_CONTEXT* ctx,
    const TPM2_HANDLE parentHandle,
    ESYS_TR* outParent)
{
    TSS2_RC rc;
    ESYS_TR sessionHandle1 = ESYS_TR_NONE;
    ESYS_TR sessionHandle2 = ESYS_TR_NONE;
    ESYS_TR sessionHandle3 = ESYS_TR_NONE;
    ESYS_TR esysParent = ESYS_TR_NONE;

    const char* title = KEYISOP_TPM_KEY_TITLE;
    if (outParent == NULL) {
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    *outParent = ESYS_TR_NONE;  

    if (parentHandle != ESYS_TR_NONE && parentHandle !=  TPM2_RH_OWNER) { 
        // Initialize the ESYS obj persistent parent handle if provided 
        rc = Esys_TR_FromTPMPublic(ctx->ectx,
                                  parentHandle,
                                  sessionHandle1, sessionHandle2, sessionHandle3,
                                  &esysParent);
        if(rc != TSS2_RC_SUCCESS) {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "can't acquire parent", "Esys_TR_FromTPMPublic failed", "error: %d", rc);
            return rc;
        }
    } else {
        // Create under the parent key handle that retrievd from NVRAM
        rc = _tpm_init_primary_key_handle(correlationId, ctx, &esysParent);
        if (rc != TSS2_RC_SUCCESS) {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "can't acquire parent", "_tpm_init_primary_key_handle failed", "error: %d", rc);
            return rc;
        }
    }
    *outParent = esysParent;
    return TSS2_RC_SUCCESS;
}