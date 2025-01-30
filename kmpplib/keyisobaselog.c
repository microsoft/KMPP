/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <string.h>
#include <stdio.h>
#include "keyisocommon.h"
#include "keyisomemory.h"
#include "keyisolog.h"
#include "keyisoutils.h"

#define KEYISOP_CORRELATION_ID_PREFIX   "correlationId: "
#define KEYISOP_MAX_LINE_LEN 10 // line is integer

int KEYISOP_traceLogTest = 0;
int KEYISOP_traceLogVerbose = 0;
int KEYISOP_traceLogConstructor = 0; // Will be set to 1 during contractor stage

extern KeyIso_log_provider_ptr KeyIso_log_provider_fn;

void _KeyIsoP_trace_output(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    const char *error,
    const char *initialStr,
    const char *paraFormat,
    va_list paraArgs)
{
    char paraBuf[KEYISOP_TRACELOG_PARA_LENGTH];
    char idBuf[UUID_STR_LEN];
    (void)initialStr;  // suppress unused parameter warning
    LogLevel logLevel = LogLevel_Info;
    const char *priorityStr = " info";
    const char *description = "";
    char *descriptionAlloc = NULL;               // KeyIsoFree()
    size_t descriptionLength = 0;
    const char *shortFilename = "";

    if ((flags & KEYISOP_TRACELOG_VERBOSE_FLAG) != 0 &&
            !KEYISOP_traceLogVerbose) {
        return;
    }

    if (file == NULL) {
        file = "";
    }

    if (func == NULL) {
        func = "";
    }

    if (title == NULL) {
        title = "";
    }

    if (loc == NULL) {
        loc = "";
    }

    if (error == NULL) {
        error = "";
    }

    if (paraFormat == NULL) {
        paraFormat = "";
    }

    if (*error != '\0') {
        if (flags & KEYISOP_TRACELOG_WARNING_FLAG) {
            logLevel = LogLevel_Warning;
            priorityStr = " warn";
        } else {
            logLevel = LogLevel_Error;
            priorityStr = "error";
        }
    } else if (flags & KEYISOP_TRACELOG_VERBOSE_FLAG) {
        logLevel = LogLevel_Debug;
        priorityStr = "debug";
    }

    if (*loc == '\0') {
        loc = func;
    }

    if (correlationId != NULL) {
        uuid_unparse_lower(correlationId, idBuf);
    } else {
        idBuf[0] = '\0';
    }

    if (vsnprintf(paraBuf, sizeof(paraBuf), paraFormat, paraArgs) < 0) {
        *paraBuf = '\0';
    }

    // Description. Where para, error and correlationId are optional
    //  <loc>":: "<para>" "<error>" ""correlationId: "<correlationId>

    descriptionLength =
        strlen(loc) + 3 +
        strlen(paraBuf) + 1 +
        strlen(error) + 1 +
        strlen(KEYISOP_CORRELATION_ID_PREFIX) + strlen(idBuf) + 1;

    descriptionAlloc = (char *) KeyIso_zalloc(descriptionLength);
    if (descriptionAlloc != NULL) {
        if (snprintf(descriptionAlloc, descriptionLength,
                "%s:: %s%s%s%s%s%s",
                loc,
                paraBuf, *paraBuf == '\0' ? "" : " ",
                error, *error == '\0' ? "" : " ",
                correlationId == NULL ? "" : KEYISOP_CORRELATION_ID_PREFIX,
                correlationId == NULL ? "" : idBuf) > 0) {
            description = descriptionAlloc;
        }
    }

    // Extract the rightmost filename component. Address Windows and Linux.
    shortFilename = file;
    for (int i = 0; i <= 1; i++) {
        const char *p = strrchr(file, i == 0 ? '/' : '\\');

        if (p != NULL) {
            p++;
            if (*p != '\0' && p > shortFilename) {
                shortFilename = p;
            }
        }
    }

    size_t logStrLength = 0;
    char* logStrAlloc = NULL;  // KeyIsoFree()


    size_t initialStrLen = 0;
#ifndef KMPP_TELEMETRY_DISABLED // KMPP_TELEMETRY_DISABLED=OFF
    if (initialStr != NULL) {
        initialStrLen = strlen(initialStr) + 1;
    }
    else {
        initialStr = "";
    }
#else // KMPP_TELEMETRY_DISABLED=ON
    initialStr = ""; // no print of initialStr when telemetry is disabled
#endif

    logStrLength =
            initialStrLen +
            strlen(priorityStr) + 3 +
            strlen(title) + 1 +
            strlen(func) + 1 +
            strlen(shortFilename) + 1 +
            KEYISOP_MAX_LINE_LEN + 2 +
            strlen(description);

    logStrAlloc = (char*)KeyIso_zalloc(logStrLength);
    if (logStrAlloc != NULL) {
        snprintf(logStrAlloc, logStrLength, "%s [%s] %s %s %s(%d) %s",
            initialStr,
            priorityStr,
            title,
            func,
            shortFilename,
            line,
            description);

        // Using the configured log provider
        KeyIso_log_provider_fn(logLevel, logStrAlloc);

        KeyIso_free(logStrAlloc);
    }
    KeyIso_free(descriptionAlloc);
}

void _KeyIsoP_trace_log_error(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    const char *errStr)
{
    _KeyIsoP_trace_log_error_para(
        file,
        func,
        line,
        correlationId,
        flags,
        title,
        loc,
        errStr,
        "");
}

void _KeyIsoP_trace_log_error_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    const char *errStr,
    const char *format, ...)
{
    va_list args;
    va_start(args, format);
    char errorBuf[KEYISOP_TRACELOG_ERROR_LENGTH];
    const char *error = "error: ???";

    if (errStr == NULL) {
        errStr = "";
    }

    if (*errStr != '\0') {
        if (snprintf(errorBuf, sizeof(errorBuf), "error: <%s>", errStr) > 0) {
            error = errorBuf;
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
        error,
        format,
        args);
}

void _KeyIsoP_trace_log(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc)
{
    _KeyIsoP_trace_log_para(
        file,
        func,
        line,
        correlationId,
        flags,
        title,
        loc,
        "");
}

void _KeyIsoP_trace_log_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    const char *format, ...)
{
    va_list args;
    va_start(args, format);

    _KeyIsoP_trace_log_output(
        file,
        func,
        line,
        correlationId,
        flags,
        title,
        loc,
        "",                         // error
        format,
        args);
}

void _KeyIsoP_trace_log_output(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    const char *error,
    const char *paraFormat,
    va_list paraArgs)
{
     const char* initialStr = "kmpp_log";
     _KeyIsoP_trace_output(
     file,
     func,
     line,
     correlationId,
     flags,
     title,
     loc,
     error,
     initialStr,
     paraFormat,
     paraArgs);
}

void _KeyIsoP_trace_log_errno(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    int err)
{
    _KeyIsoP_trace_log_errno_para(
        file,
        func,
        line,
        correlationId,
        flags,
        title,
        loc,
        err,
        "");                    // format
}