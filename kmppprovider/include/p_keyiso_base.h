/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#ifdef  __cplusplus
extern "C" {
#endif 

#include <p_keyiso.h>

OSSL_provider_init_fn OSSL_provider_init;

/** Common function for Base provider **/
extern const OSSL_ALGORITHM keyIso_prov_decoder_algs[];

int KeyIso_prov_is_running();

const OSSL_ALGORITHM* KeyIso_query_operation(
    ossl_unused void* provCtx,
    int operation,
    int* noCache);

int KeyIso_provider_get_capabilities(
    ossl_unused void* provCtx, 
    const char* capability,
    OSSL_CALLBACK* cb,
    void* arg);

const OSSL_PARAM* KeyIso_gettable_params(
    ossl_unused void* provCtx);

void KeyIso_provider_teardown(
    KEYISO_PROV_PROVCTX* provCtx);

int KeyIso_kmpp_prov_init(
    const OSSL_CORE_HANDLE* handle,
    const OSSL_DISPATCH* in,
    const OSSL_DISPATCH** out,
    void** provCtx,
    const OSSL_DISPATCH* outTable);

#ifdef  __cplusplus
}
#endif