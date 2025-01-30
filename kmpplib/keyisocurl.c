/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <openssl/ssl.h>
#include <openssl/engine.h>

#include "keyisocert.h"
#include "keyisocurl.h"
#include "keyisoutils.h"
#include "keyisolog.h"

static void _KeyIsoP_trace_log_curl_error_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    CURLcode err,
    const char *format, ...)
{
    va_list args;
    va_start(args, format);
    char errorBuf[KEYISOP_TRACELOG_ERROR_LENGTH];
    const char *error = "error: ???";

    if (snprintf(errorBuf, sizeof(errorBuf),
            "curlError: %d <%s>",
            err,
            curl_easy_strerror(err)) > 0) {
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
#define KEYISOP_trace_log_curl_error_para(correlationId, flags, title, loc, err, ...) \
    _KeyIsoP_trace_log_curl_error_para(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc, err, __VA_ARGS__)

static void _KeyIsoP_trace_log_curl_error(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    CURLcode err)
{
    _KeyIsoP_trace_log_curl_error_para(
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
#define KEYISOP_trace_log_curl_error(correlationId, flags, title, loc, err) \
    _KeyIsoP_trace_log_curl_error(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc, err)

static int _curl_ssl_cert_verify_callback(
    X509_STORE_CTX *storeCtx,
    void *arg)
{
    const char *title = KEYISOP_CURL_TITLE;
    KEYISO_VERIFY_CERT_CTX *ctx = (KEYISO_VERIFY_CERT_CTX *) arg;
    KEYISO_VERIFY_CERT_CTX *allocCtx = NULL;
    uuid_t correlationId;
    int ret = 0;
    int verifyChainError = 0;

    if (ctx == NULL) {
        allocCtx = KeyIso_create_verify_cert_ctx(NULL);
        if (allocCtx == NULL) {
            return 0;
        }

        ctx = allocCtx;
    }

    KeyIsoP_get_verify_cert_ctx_correlationId(ctx, correlationId);
    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Start");

    ret = KeyIsoP_X509_verify_cert(
        ctx,
        storeCtx,
        0,              // keyisoFlags
        &verifyChainError);
    if (ret < 0) {
        ret = 0;
    }

    KeyIso_free_verify_cert_ctx(allocCtx);

    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete");
    return ret;
}

static CURLcode _curl_ssl_ctx_function(
    CURL *curl,
    void *sslCtx,
    void *arg)
{
    const char *title = KEYISOP_CURL_TITLE;
    KEYISO_VERIFY_CERT_CTX *ctx = (KEYISO_VERIFY_CERT_CTX *) arg;
    uuid_t correlationId;

    KeyIsoP_get_verify_cert_ctx_correlationId(ctx, correlationId);
    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Start");

    SSL_CTX_set_cert_verify_callback((SSL_CTX *) sslCtx, _curl_ssl_cert_verify_callback, ctx);

    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete");

    return CURLE_OK;
}

CURLcode KeyIso_curl_setopt_ssl_client(
    CURL *curl,
    KEYISO_VERIFY_CERT_CTX *ctx,   // Optional
    const char *pemFilename,        // Optional, set for client auth
    const char *engineName,         // Optional, set for client auth
    const char *engineKeyId)        // Optional, set for client auth
{
    const char *title = KEYISOP_CURL_TITLE;
    const char *loc = "";
    CURLcode ret = CURLE_OK;
    uuid_t correlationId;

    KeyIsoP_get_verify_cert_ctx_correlationId(ctx, correlationId);

    if (pemFilename && engineName && engineKeyId) {
        ret = curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
        if (ret != CURLE_OK) {
            loc = "SSLCERTTYPE";
            goto curlErr;
        }
        ret = curl_easy_setopt(curl, CURLOPT_SSLCERT, pemFilename);
        if (ret != CURLE_OK) {
            loc = "SSLCERT";
            goto curlErr;
        }

        ret = curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "ENG");
        if (ret != CURLE_OK) {
            loc = "SSLKEYTYPE";
            goto curlErr;
        }

        // The following is needed so the dynamic engine is first loaded
        ENGINE_load_dynamic();

        ret = curl_easy_setopt(curl, CURLOPT_SSLENGINE, engineName);
        if (ret != CURLE_OK) {
            loc = "SSLENGINE";
            goto curlErr;
        }
        ret = curl_easy_setopt(curl, CURLOPT_SSLKEY, engineKeyId);
        if (ret != CURLE_OK) {
            loc = "SSLKEY";
            goto curlErr;
        }
    } else if (pemFilename || engineName || engineKeyId) {
        loc = "MissingClientAuthArg";
        ret = CURLE_BAD_FUNCTION_ARGUMENT;
        goto curlErr;
    }

    ret = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1);
    if (ret != CURLE_OK) {
        loc = "SSL_VERIFYPEER";
        goto curlErr;
    }
    ret = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2);
    if (ret != CURLE_OK) {
        loc = "SSL_VERIFYHOST";
        goto curlErr;
    }
    ret = curl_easy_setopt(curl, CURLOPT_CAPATH, KeyIsoP_get_default_cert_dir());
    if (ret != CURLE_OK) {
        loc = "CAPATH";
        goto curlErr;
    }

    // Disable CAfile
    ret = curl_easy_setopt(curl, CURLOPT_CAINFO, NULL);
    if (ret != CURLE_OK) {
        loc = "CAINFO";
        goto curlErr;
    }

    ret = curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, ctx);
    if (ret != CURLE_OK) {
        loc = "SSL_CTX_DATA";
        goto curlErr;
    }

    ret = curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, _curl_ssl_ctx_function);
    if (ret != CURLE_OK) {
        loc = "SSL_CTX_FUNCTION";
        goto curlErr;
    }

end:
    return ret;

curlErr:
    KEYISOP_trace_log_curl_error(correlationId, 0, title, loc, ret);
    goto end;
}

