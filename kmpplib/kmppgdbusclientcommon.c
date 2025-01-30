/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdbool.h>
#include <stdio.h>

#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisoutils.h"
#include "kmppgdbusclientcommon.h"
#include "kmppgdbusgenerated.h"

void GDBUS_g_variant_unref(GVariant *value)
{
    if (value != NULL) {
        g_variant_unref(value);
    }
}

void GDBUS_g_object_unref(gpointer object)
{
    if (object != NULL) {
        g_object_unref(object);
    }
}

void GDBUS_exhaust_main_loop_events()
{
    GMainContext *ctx = g_main_context_default();

    if (!g_main_context_acquire(ctx)) {
        // Another thread iterates right now.
        return;
    }

#define MAX_IT 1000
    uint32_t i = 0;
    while (g_main_context_pending(ctx) && i++ < MAX_IT) {
        (void)g_main_context_iteration(ctx, 0);
    }
#undef MAX_IT

    g_main_context_release(ctx);
}

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
    const char *format, ...)
{
    va_list args;
    va_start(args, format);
    const char *errorStr = "error: ???";
    char *errorStrAlloc = NULL;               // KeyIsoFree()

    if (*error && (*error)->message != NULL) {
        const char *errorFormat = "glibError: <%s>";
        const char *message = (*error)->message;
        size_t errorStrLength = strlen(errorFormat) + strlen(message) + 1;

        errorStrAlloc = (char *) KeyIso_zalloc(errorStrLength);
        if (errorStrAlloc != NULL) {
            if (snprintf(errorStrAlloc, errorStrLength,
                    errorFormat,
                    message) > 0) {
                errorStr = errorStrAlloc;
            }
        }
    }

    _KeyIsoP_trace_log_output(
        file,
        func,
        line,
        correlationId,
        flags,
        title,
        loc,
        errorStr,
        format,
        args);

    if (*error) {
        g_error_free(*error);
        *error = NULL;
    }

    KeyIso_free(errorStrAlloc);
}

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
    GError **error)           // Before returning, g_error_free(*error)
{
    _KMPP_GDBUS_trace_log_glib_error_para(
        file,
        func,
        line,
        correlationId,
        flags,
        title,
        loc,
        error,
        "");                    // format
}

GdbusKmpp *GDBUS_get_kmpp_proxy(const uuid_t correlationId)
{
    const char *title = KEYISOP_GDBUS_CLIENT_TITLE;
    GdbusKmpp *proxy = NULL;
    GError *error = NULL;   // KMPP_GDBUS_trace_log_glib_error() frees

    proxy = gdbus_kmpp_proxy_new_for_bus_sync(
        G_BUS_TYPE_SYSTEM,
        0,                          // flags
        KMPP_BUS_NAME,
        "/" ,                       // object_path
        NULL,
        &error);
    if (error) {
        KMPP_GDBUS_trace_log_glib_error(correlationId, 0, title, NULL, &error);
    }

    return proxy;
}

gboolean GDBUS_is_gdbus_retry_error(GError *error)
{
    gboolean retry = FALSE;

    if (error && error->domain == G_DBUS_ERROR) {
        switch (error->code) {
            case G_DBUS_ERROR_FAILED:
            case G_DBUS_ERROR_INVALID_ARGS:
            case G_DBUS_ERROR_NO_MEMORY:
            case G_DBUS_ERROR_ACCESS_DENIED:
            case G_DBUS_ERROR_NOT_SUPPORTED:
                break;
            default:
                retry = TRUE;
                break;
        }
    }

    return retry;
}

void KeyIso_init_gdbus_session(GDBUS_SESSION *session) {
    session->proxy = NULL;
    g_mutex_init(&session->mutex);
    session->isOpening = false;
    g_cond_init(&session->isOpeningCond);
}

void KeyIso_destroy_gdbus_session(GDBUS_SESSION *session) {
    if (session->proxy) {
        g_object_unref(session->proxy);
        session->proxy = NULL;
    }
    g_mutex_clear(&session->mutex);
    session->isOpening = false;
    g_cond_clear(&session->isOpeningCond);
}

int KeyIso_init_gdbus_in_keyDetails(KEYISO_KEY_DETAILS *keyDetails)
{
    GDBUS_SESSION *session = (GDBUS_SESSION *)KeyIso_zalloc(sizeof(GDBUS_SESSION));
    if (session != NULL) {
        KeyIso_init_gdbus_session(session);
        keyDetails->interfaceSession = session;
    }
    return (session != NULL);
}