/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <string.h>
#include <stdio.h>
#include <syslog.h>

#include "keyisocommon.h"
#include "keyisomemory.h"
#include "keyisolog.h"
#include "keyisoutils.h"

#ifdef KMPP_OPENSSL_SUPPORT
#include <openssl/err.h>
#endif //KMPP_OPENSSL_SUPPORT

static char *KEYISOP_traceLogFilename = NULL;

void KeyIsoP_internal_set_trace_log_filename(
    const char *filename)
{
    KeyIso_free(KEYISOP_traceLogFilename);
    KEYISOP_traceLogFilename = KeyIso_strndup(filename, KEYISO_MAX_PATH_LEN); // PATH_MAX includes NULL terminator
}

static FILE *_open_trace_log_filename()
{
    FILE *fp = stdout;

    if (KEYISOP_traceLogFilename != NULL) {
        fp = fopen(KEYISOP_traceLogFilename, "a");
        if (fp == NULL) {
            fp = stdout;
        }
    }

    return fp;
}

static void _close_trace_log_filename(
    FILE *fp)
{
    if (fp != stdout) {
        fflush(fp);
        fclose(fp);
    }
}

static void _KeyIso_log_to_file(int logLevel, const char* msg)
{
    // in case the file exist, print to file, otherwise print to stdout
    //suppressed unused parameter warning
    (void)logLevel;
    struct timeval tv;
    int sec = 0;
    int usec_100 = 0;
    FILE *fp = NULL;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    if (gettimeofday(&tv, NULL) == 0) {
        sec = tv.tv_sec % 100000;
        usec_100 = tv.tv_usec / 100;
    }
    fp = _open_trace_log_filename();

    // <time>" - "<logLevel>" "<title>" "<func>" "<file>"("<line>") "<description>
    fprintf(fp, "%05d.%04d - %s\n", sec, usec_100, msg);
    _close_trace_log_filename(fp);
}


void _KeyIso_log_syslog(int logLevel, const char* msg)
{
    syslog(logLevel, "%s", msg);
    if (KEYISOP_traceLogTest || KEYISOP_traceLogConstructor) {
        _KeyIso_log_to_file(logLevel, msg);
    }
}

static void _KeyIso_log_stdout(int logLevel, const char* msg)
{
    printf("%s\n", msg);
    if (KEYISOP_traceLogTest || KEYISOP_traceLogConstructor) {
        _KeyIso_log_to_file(logLevel, msg);
    }
}

static const KeyIso_log_provider_ptr KeyIsoP_log_provider_arr[] = {_KeyIso_log_syslog, _KeyIso_log_stdout};
KeyIso_log_provider_ptr KeyIso_log_provider_fn = KeyIsoP_log_provider_arr[KEYISO_PROVIDER_DEFAULT];

void KeyIso_set_log_provider(KeyisoLogProvider logProvider) 
{
    size_t arrSize = sizeof(KeyIsoP_log_provider_arr) / sizeof(KeyIsoP_log_provider_arr[0]);
    const char* title = KEYISOP_SUPPORT_TITLE;
    int curLogProvider;

    if (logProvider < arrSize && logProvider >= 0) {
        curLogProvider = logProvider;
    }
    else {
        curLogProvider = KEYISO_PROVIDER_DEFAULT;
        KEYISOP_trace_log_error_para(NULL, 0, title, "set_log_provider", "Invalid log provider Id", "provider Id: %u", logProvider);
    }
        
    // Updating the log provider
    KeyIso_log_provider_fn = KeyIsoP_log_provider_arr[curLogProvider];
}

#ifdef KMPP_OPENSSL_SUPPORT
void _KeyIsoP_trace_log_openssl_error_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    const char *format, ...)
{
    unsigned long lastErr = ERR_peek_last_error();
    va_list args;
    va_start(args, format);
    char errorBuf[KEYISOP_TRACELOG_ERROR_LENGTH];
    const char *error = "error: ???";

    if (snprintf(errorBuf, sizeof(errorBuf), "openSslError: %08lX", lastErr) > 0) {
        error = errorBuf;
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

    for (int i = 0; i < 10; i++) {
        char errBuf[128];
        const char *data = NULL;
        int errflags = 0;
        int count    = 0;
        unsigned long err = ERR_get_error_line_data(NULL, NULL, &data, &errflags);
        if (err == 0) {
            break;
        }

        errBuf[0] = '\0';
        ERR_error_string_n(err, errBuf, sizeof(errBuf));
        errBuf[sizeof(errBuf) - 1] = '\0';

        // data contains a string if (errflags & ERR_TXT_STRING) is true.
        // In thit case we want to add that data to the error buffer errorBuf.
        if (data && (*data != '\0')) {
            count = snprintf(errorBuf, sizeof(errorBuf), "openSslError[%d]: <%s> data:<%s>", 
                                i, errBuf, data);
        }
        // If data is an empty string or if data overflows the error buffer we will store 
        // the error without the data.
        if (count <= 0 ) {
            count = snprintf(errorBuf, sizeof(errorBuf), "openSslError[%d]: <%s>", i, errBuf);
        }
        if (count > 0) {
            _KeyIsoP_trace_log_output(
                file,
                func,
                line,
                correlationId,
                flags,
                KEYISOP_ERROR_STACK_TITLE,
                loc,
                errorBuf,
                "",                     // format
                args);
        }
    }

    ERR_clear_error();
}

void _KeyIsoP_trace_log_openssl_error(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc)
{
    _KeyIsoP_trace_log_openssl_error_para(
        file,
        func,
        line,
        correlationId,
        flags,
        title,
        loc,
        "");                    // format
}

void _KeyIsoP_trace_log_openssl_verify_cert_error_para(
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
    va_list args;
    va_start(args, format);
    char errorBuf[KEYISOP_TRACELOG_ERROR_LENGTH];
    const char *error = "error: ???";

    if (snprintf(errorBuf, sizeof(errorBuf),
            "verifyCertError: %d <%s>",
            err,
            X509_verify_cert_error_string(err)) > 0) {
        error = errorBuf;
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

void _KeyIsoP_trace_log_openssl_verify_cert_error(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    int err)
{
    _KeyIsoP_trace_log_openssl_verify_cert_error_para(
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
#endif //KMPP_OPENSSL_SUPPORT

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
    va_list args;
    va_start(args, format);
    char errorBuf[KEYISOP_TRACELOG_ERROR_LENGTH];
    const char *error = "error: ???";

    if (snprintf(errorBuf, sizeof(errorBuf),
            "errno: %d (0x%x) <%s>",
            err,
            err,
            strerror(err)) > 0) {
        error = errorBuf;
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