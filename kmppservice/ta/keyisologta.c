/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <tee_internal_api.h>
#include "keyisolog.h"
#include "keyisocommon.h"

void KeyIsoP_internal_set_trace_log_filename(const char *filename)
{
    //suppressed unused parameter warning
    (void)filename;
}

static void _KeyIso_log(int logLevel, const char* msg)
{
    if (logLevel == LogLevel_Error || logLevel == LogLevel_Warning)
        EMSG("%s\n", msg);
    else if (logLevel == LogLevel_Info)
        IMSG("%s\n", msg);
    else 
        DMSG("%s\n", msg);
}

KeyIso_log_provider_ptr KeyIso_log_provider_fn = _KeyIso_log;
void KeyIso_set_log_provider(KeyisoLogProvider logProvider)
{
    //suppressed unused parameter warning
    (void)logProvider;

    // Updating the log provider to the only one there is
    KeyIso_log_provider_fn = _KeyIso_log;
}

void _KeyIsoP_trace_log_errno_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    int err,
    const char *format, ...)
{
    //empty function since errno and strerror are not supported in ta

    //suppressed unused parameter warning
    (void)file;
    (void)func;
    (void)line;
    (void)correlationId;
    (void)flags;
    (void)title;
    (void)loc;
    (void)err;
    (void)format;
}