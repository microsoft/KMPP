/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <stdarg.h>
#include <openssl/err.h>

#include "keyisolog.h"

#define KMPPerr(r) ERR_KMPP_error(r)
#define KMPPerr_para(r, fmt, ...) ERR_KMPP_error_para(r, fmt, __VA_ARGS__)
#define KMPPerr_log(r, l) ({ \
    ERR_KMPP_error(r); \
    KEYISOP_trace_log_error(NULL, 0, KEYISOP_PROVIDER_TITLE, l, ERR_reason_error_string(ERR_get_error())); \
    })

#ifdef  __cplusplus
extern "C" {
#endif

int ERR_load_KMPP_strings(void);
void ERR_unload_KMPP_strings(void);
void ERR_KMPP_error(int reason);
void ERR_KMPP_error_para(int reason, const char *fmt, ...);
const char *ERR_KMPP_get_string(int reason);

#ifdef  __cplusplus
}
#endif

/*
 * KMPP provider reason codes.
 */

 typedef enum {
    KeyIsoErrReason_NoError = 0,
    KeyIsoErrReason_AllocFailure = 100,
    KeyIsoErrReason_OperationFailed,
    KeyIsoErrReason_ImportFailed,
    KeyIsoErrReason_ExportFailed,
    KeyIsoErrReason_FailedToGetLibCtx,
    KeyIsoErrReason_FailedToGetParams,
    KeyIsoErrReason_FailedToGetPadding,
    KeyIsoErrReason_FailedToGetKeyBytes,
    KeyIsoErrReason_FailedToGetPubkey,
    KeyIsoErrReason_FailedToGetKeyCtx,
    KeyIsoErrReason_FailedToGetProvKey,
    KeyIsoErrReason_FailedToGetUri,
    KeyIsoErrReason_FailedToSetParams,
    KeyIsoErrReason_UnsupportedScheme,
    KeyIsoErrReason_UnsupportedPadding,
    KeyIsoErrReason_UnsupportedDataType,
    KeyIsoErrReason_UnsupportedSaltLen,
    KeyIsoErrReason_UnsupportedAlgorithm,
    KeyIsoErrReason_InvalidStoreCtx,
    KeyIsoErrReason_InvalidMsgDigest,
    KeyIsoErrReason_InvalidParams,
    KeyIsoErrReason_InvalidSignatureLength,
} KeyIsoErrReason;
