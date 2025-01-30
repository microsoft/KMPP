/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include "keyisocert.h"
# include <curl/curl.h>

#ifdef  __cplusplus
extern "C" {
#endif

CURLcode KeyIso_curl_setopt_ssl_client(
    CURL *curl,
    KEYISO_VERIFY_CERT_CTX *ctx,    // Optional
    const char *pemFilename,        // Optional, set for client auth
    const char *engineName,         // Optional, set for client auth
    const char *engineKeyId);       // Optional, set for client auth

#ifdef  __cplusplus
}
#endif