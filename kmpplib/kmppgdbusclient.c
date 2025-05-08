/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdbool.h>

#include "keyisoclientinternal.h"
#include "keyisoipccommands.h"
#include "keyisoipcgenericmessage.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "kmppgdbusclientcommon.h"
#include "kmppgdbusgenerated.h"



static int _get_gdbus_session_proxy(KEYISO_KEY_CTX *keyCtx, GdbusKmpp **proxy)       // GDBUS_g_object_unref())
{
    const char *title = KEYISOP_GDBUS_CLIENT_TITLE;
    if (keyCtx == NULL ) {
        return STATUS_FAILED;
    }

    KEYISO_KEY_DETAILS* keyDetails = (KEYISO_KEY_DETAILS*)keyCtx->keyDetails;
    if (!keyDetails) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, title, "_get_gdbus_session_proxy", "no keyDetails");
        return STATUS_FAILED;
    }

    int ret = STATUS_FAILED;
    GDBUS_SESSION *session = (GDBUS_SESSION*)keyDetails->interfaceSession;
    if (session == NULL) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, title, "_get_gdbus_session_proxy", "no session");
        return STATUS_FAILED;
    }

    *proxy = NULL;
    g_mutex_lock(&session->mutex);
    if (session->proxy != NULL) {
        *proxy = session->proxy;
        g_object_ref(*proxy);
        ret = STATUS_OK;
    } else {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, title, "_get_gdbus_session_proxy", "no proxy");
    }
    g_mutex_unlock(&session->mutex);
    
    return ret;
}

int KeyIso_gdbus_open_ipc(KEYISO_KEY_CTX *keyCtx)
{ 
    if (keyCtx == NULL) {
        return STATUS_FAILED;
    }

    KEYISOP_trace_log(keyCtx->correlationId, 0, KEYISOP_GDBUS_CLIENT_TITLE, "opening ipc");
    KEYISO_KEY_DETAILS* keyDetails = (KEYISO_KEY_DETAILS*)keyCtx->keyDetails;
    if (!keyDetails) {
        return STATUS_FAILED;
    }

    GdbusKmpp *proxy = NULL;
    int retryCount = 0;    
    int status = STATUS_FAILED;

    GDBUS_SESSION *session = (GDBUS_SESSION*)keyDetails->interfaceSession;
    g_mutex_lock(&session->mutex);
    
    while (retryCount < MAX_DBUS_RETRY ) {
        if (retryCount > 0) { //sleep 500 milliseconds
            g_usleep((gulong)(SLEEP_BETWEEN_RETRIES_MILLI * 1000)); // Microseconds
        }
        proxy = GDBUS_get_kmpp_proxy(keyCtx->correlationId);

        if (proxy != NULL) {    
            GDBUS_g_object_unref(session->proxy);
            session->proxy = proxy;
            proxy = NULL;
            GDBUS_g_object_unref(proxy);
            status = STATUS_OK;
            break;
        } else {
            retryCount++;
        }
    }
    g_mutex_unlock(&session->mutex);
    
    if (retryCount > 0) {
        KEYISOP_trace_log_error_para(keyCtx->correlationId, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_GDBUS_CLIENT_TITLE, "Retry", "counter", "= %d", retryCount);       
    }

    GDBUS_exhaust_main_loop_events();
    return status;
}

bool KeyIso_gdbus_is_encoding()
{
    return true;
}

bool KeyIso_check_gdbus(KEYISO_KEY_CTX *keyCtx)
{ 
    if (keyCtx == NULL) {
        return false;
    }
    
    KEYISO_KEY_DETAILS* keyDetails = (KEYISO_KEY_DETAILS*)keyCtx->keyDetails;
    if (!keyDetails) {
        return false;
    }

    GDBUS_SESSION *session = (GDBUS_SESSION*)keyDetails->interfaceSession;
    if (!session) {
        return false;
    }

    g_mutex_lock(&session->mutex);
    bool result = (session->proxy != NULL && keyDetails->keyId > 0);
    g_mutex_unlock(&session->mutex);

    return result;
}
IPC_REPLY_ST* KeyIso_send_gdbus(KEYISO_KEY_CTX *keyCtx, const IPC_SEND_RECEIVE_ST *ipcSt, int *result, bool isPermanentSessionRequired)
{
    // Some commands do not require session
    if (keyCtx == NULL) {
        return NULL;
    }

    KEYISO_KEY_DETAILS *keyDetails = (KEYISO_KEY_DETAILS*)keyCtx->keyDetails;
    if (isPermanentSessionRequired && (keyDetails == NULL || keyDetails->interfaceSession == NULL)) {
        return NULL;
    }

    GVariant *fromVariant = NULL;
    GVariant *toVariant = NULL;
    GError *error = NULL;   // KMPP_GDBUS_trace_log_glib_error() frees
    GdbusKmpp *proxy = NULL;
    gboolean callRet = FALSE;
    *result = STATUS_OK;

    // 1. Prepare to send
    fromVariant = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, ipcSt->inSt, (gsize)ipcSt->inLen, sizeof(*(ipcSt->inSt)));
    if (fromVariant == NULL) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_GDBUS_CLIENT_TITLE, "fromVariant", "NULL - IPC_FAILURE");
        *result = IPC_FAILURE;        
    } 
    else if (!isPermanentSessionRequired) {
        proxy = GDBUS_get_kmpp_proxy(keyCtx->correlationId);
        if (proxy == NULL) {
            GDBUS_g_variant_unref(fromVariant);
            fromVariant = NULL;
            KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_GDBUS_CLIENT_TITLE, "GDBUS_get_kmpp_proxy", "no proxy - IPC_FAILURE");
            *result = IPC_FAILURE;
        }
    }
    else if (_get_gdbus_session_proxy(keyCtx, &proxy) == STATUS_FAILED) {
        GDBUS_g_variant_unref(fromVariant);
        fromVariant = NULL;
        KEYISOP_trace_log_error_para(keyCtx->correlationId, 0, KEYISOP_GDBUS_CLIENT_TITLE, "_get_gdbus_session_proxy", "no proxy - IPC_FAILURE", "IPC command: %u", ipcSt->command);
        *result = IPC_FAILURE;
    } 
    if (*result == IPC_FAILURE)
        return NULL;

    //2. Send on IPC
    int retryCount = 0;    
    while (retryCount < MAX_DBUS_RETRY) {
        if (retryCount > 0) { // sleep 500 milliseconds and unref previous toVariant
            if (toVariant) {
                GDBUS_g_variant_unref(toVariant);
                toVariant = NULL;
            }
            g_usleep((gulong)(SLEEP_BETWEEN_RETRIES_MILLI * 1000)); // Microseconds
            KEYISOP_trace_log_error(keyCtx->correlationId, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_GDBUS_CLIENT_TITLE, "UpdateRetry", "Warning");
        }

        callRet = gdbus_kmpp_call_client_message_sync(
            proxy,
            ipcSt->command,
            g_variant_ref(fromVariant),
            &toVariant,
            NULL,  // cancellable
            &error);       
  
        if (callRet && error == NULL && toVariant != NULL) {
            break;
        }
        //3. Handle sending failures
        if (error && g_error_matches(error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED)) {
            // Service might be downgraded; report unsupported method.
            KMPP_GDBUS_trace_log_glib_error(keyCtx->correlationId, 0, KEYISOP_GDBUS_CLIENT_TITLE, "The method is not supported", &error);
            *result = IPC_UNKNOWN_METHOD;
        } else {
            *result = IPC_FAILURE;
        }
        KEYISOP_trace_log_error_para(keyCtx->correlationId, 0, KEYISOP_GDBUS_CLIENT_TITLE, "gdbus_kmpp_call_client_message_sync", "failure", "error code= %d", error ? error->code : -1);
        KMPP_GDBUS_trace_log_glib_error(keyCtx->correlationId, 0, KEYISOP_GDBUS_CLIENT_TITLE, "failure", &error);

        if (isPermanentSessionRequired && error && GDBUS_is_gdbus_retry_error(error)) {
            retryCount++;
        }
        else {
            break;
        }

        if (error) {
            g_clear_error(&error);
        }
    }
    if (error) {
        g_clear_error(&error);
    }
 
    GDBUS_g_variant_unref(fromVariant);
    fromVariant = NULL;
    if (proxy != NULL) {
        GDBUS_g_object_unref(proxy);
        proxy = NULL;
    }
 
    bool needToGetReply = (*result == STATUS_OK);
    if (!needToGetReply) {
        GDBUS_g_variant_unref(toVariant);  
        toVariant = NULL;
        if (ipcSt->command == IpcCommand_CloseKey)
            *result = callRet;
        return NULL;
    }

    //4. Receive reply  
    const guchar *toBytes = NULL;
    gsize toLength = 0;   
    IPC_REPLY_ST *reply = NULL;  

    toBytes = (const guchar *) g_variant_get_fixed_array(toVariant, &toLength, sizeof(guchar));
    if (toBytes == NULL || toLength <= 0) {
        *result = IPC_FAILURE;
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_GDBUS_CLIENT_TITLE, "toVariant", "Format error");
    } else {
        reply = (IPC_REPLY_ST *)KeyIso_zalloc(sizeof(IPC_REPLY_ST) + (int)toLength);
        if (reply == NULL) {
            *result = IPC_FAILURE;
            KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_GDBUS_CLIENT_TITLE, "reply", "allocation error");
        } else {
            reply->command = ipcSt->command;
            reply->outLen = (int)toLength;
            reply->outSt = (uint8_t *)KeyIso_zalloc(reply->outLen);
            memcpy(reply->outSt, toBytes, reply->outLen);           
        }
    }

    GDBUS_g_variant_unref(toVariant);  
    toVariant = NULL;

    if (!isPermanentSessionRequired)
        GDBUS_exhaust_main_loop_events();

    return reply;  
}
IPC_REPLY_ST* KeyIso_create_gdbus_proxy_and_send_open_key(KEYISO_KEY_CTX *keyCtx, const IPC_SEND_RECEIVE_ST *ipcSt, int *result) 
{
    const char* title = KEYISOP_GDBUS_CLIENT_TITLE;
    if (keyCtx == NULL) {
        return NULL;
    }

    KEYISO_KEY_DETAILS* keyDetails = (KEYISO_KEY_DETAILS*)keyCtx->keyDetails;
    if (keyDetails == NULL || keyDetails->interfaceSession == NULL) {
        return NULL;
    }

    IPC_REPLY_ST *reply = NULL;  
    GdbusKmpp *proxy = NULL;

    //1. open the proxy under lock
    GDBUS_SESSION *session = (GDBUS_SESSION*)keyDetails->interfaceSession;
    if (!session) {
        return NULL;
    }

    g_mutex_lock(&session->mutex);
    while (session->isOpening == true) {
        g_cond_wait(&session->isOpeningCond, &session->mutex);
    }
    session->isOpening  = true;
    if (session->proxy != NULL &&  keyDetails->keyId > 0 ) {
        // The key was opened already by a different thread
        *result = IPC_NO_OPERATION_NEEDED ;
        g_mutex_unlock(&session->mutex);       
        return NULL;
    }
    proxy = GDBUS_get_kmpp_proxy(keyCtx->correlationId);
    //2. Send the open command
    if (proxy != NULL) {
        GDBUS_g_object_unref(session->proxy);
        session->proxy = proxy;
        proxy = NULL; 
        GDBUS_g_object_unref(proxy);
        g_mutex_unlock(&session->mutex);

        reply = KeyIso_send_gdbus(keyCtx, ipcSt, result, true);
        if (*result == STATUS_FAILED) {
            GDBUS_g_object_unref(session->proxy);
            session->proxy = NULL;
        }   
    }
    else {
        g_mutex_unlock(&session->mutex);
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, title, "_get_kmpp_proxy", "No proxy");      
    }
    return reply;

}

void KeyIso_close_gdbus(KEYISO_KEY_CTX *keyCtx)
{
    if (keyCtx == NULL ) {
        return;
    }

    KEYISO_KEY_DETAILS* keyDetails = (KEYISO_KEY_DETAILS*)keyCtx->keyDetails;
    if (keyDetails == NULL || keyDetails->interfaceSession == NULL) {
        return ;
    }

    GDBUS_SESSION *session = (GDBUS_SESSION*)keyDetails->interfaceSession;
    KeyIso_destroy_gdbus_session(session);
    GDBUS_exhaust_main_loop_events();
}

void KeyIso_signal_open_key_completed_gdbus(KEYISO_KEY_CTX *keyCtx)
{
    if (keyCtx == NULL) {
        return;
    }

    KEYISO_KEY_DETAILS* keyDetails = (KEYISO_KEY_DETAILS*)keyCtx->keyDetails;
    if (!keyDetails) {
        return;
    }

    GDBUS_SESSION *session = (GDBUS_SESSION*)keyDetails->interfaceSession;
    g_mutex_lock(&session->mutex);
    session->isOpening = false;
    g_cond_signal(&session->isOpeningCond); // Wake up threads waiting on the condition
    g_mutex_unlock(&session->mutex);
}

bool KeyIso_is_key_already_opened_gdbus(IPC_REPLY_ST *reply, int result)
{
    // Check if the key was already opened by a different thread
    return (reply == NULL) && (result == IPC_NO_OPERATION_NEEDED);
}

bool KeyIso_is_service_compatiblity_error_gdbus(KEYISO_KEY_CTX *keyCtx, int result)
{
    if (result == IPC_UNKNOWN_METHOD) {
        // Validate service version if we received an unknown method error this is probably due to service version downgrade
        // This error indicates that the sent message is not supported by the service
        int p8Compatible = KeyIso_validate_current_service_compatibility_mode(
            keyCtx->correlationId,
            KeyisoCompatibilityMode_pkcs8);
        
        if (p8Compatible == NOT_PKCS8_COMPATIBLE) {
            return true;
        }
    }
    return false;
}