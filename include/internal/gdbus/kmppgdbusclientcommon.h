/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <glib.h>

#include "keyisocommon.h" 
#include "kmppgdbusgenerated.h"

#define SLEEP_BETWEEN_RETRIES_MILLI  500
#define MAX_DBUS_RETRY 5


//////////////////////////////
/*   GDBUS structures       */
//////////////////////////////

typedef struct KeyIso_gdbus_session_st GDBUS_SESSION;
struct KeyIso_gdbus_session_st
{ 
    GdbusKmpp            *proxy;         // gdbus session identification 
    GMutex                mutex;         // glib parameter used by gdbus  
    gboolean              isOpening;     // gdbus session status, if an open request was already sent once to the service
    GCond                 isOpeningCond; // Condition variable for isOpening flag
}; 

int KeyIso_init_gdbus_in_keyDetails(KEYISO_KEY_DETAILS *keyDetails); // Implementation details for initializing GDBus IPC

////////////////////////////////
/*   GDBUS IPC handling       */
////////////////////////////////

void GDBUS_g_variant_unref(GVariant *value);
void GDBUS_g_object_unref(gpointer object);
void GDBUS_exhaust_main_loop_events();
GdbusKmpp *GDBUS_get_kmpp_proxy(const uuid_t correlationId);
gboolean GDBUS_is_gdbus_retry_error(GError *error);
int GDBUS_gdbus_retry_update(KEYISO_KEY_CTX *keyCtx);
void KeyIso_init_gdbus_session(GDBUS_SESSION *session);
void KeyIso_destroy_gdbus_session(GDBUS_SESSION *session);

////////////////////////////////
/*   GDBUS logging            */
////////////////////////////////

// Before returning
//  g_error_free(*error)
//  *error = NULL;
void _KMPP_GDBUS_trace_log_glib_error_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    GError **error,           // Before returning, g_error_free(*error)
    const char *format, ...);
#define KMPP_GDBUS_trace_log_glib_error_para(correlationId, flags, title, loc, error, ...) \
    _KMPP_GDBUS_trace_log_glib_error_para(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc, error, __VA_ARGS__)

// Before returning
//  g_error_free(*error)
//  *error = NULL;
void _KMPP_GDBUS_trace_log_glib_error(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    GError **error);          // Before returning, g_error_free(*error)
#define KMPP_GDBUS_trace_log_glib_error(correlationId, flags, title, loc, error) \
    _KMPP_GDBUS_trace_log_glib_error(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc, error)
