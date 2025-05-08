/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <string.h>
#include <openssl/core_names.h>

#include "keyisoclientinternal.h"
#include "keyisojsonutils.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "p_keyiso_base.h"
#include "p_keyiso_err.h"

extern KEYISO_CLIENT_CONFIG_ST g_config;
extern const OSSL_DISPATCH keyIso_prov_decoder_pem_funcs[];

////////////////////////////////////////////////////////////////////////
//                     KMPP default provider                          //
////////////////////////////////////////////////////////////////////////

/*
 * In order to support decoding of plain-text keys that are not encrypted by the kmpp encoder, 
 * it is necessary to define different names for the decoder between the provider's default 
 * and non-default mode.
 * In the default mode, the decoder name must be unique so that it will be detected by only by
 * collect_extra_decoder.
 */
const OSSL_ALGORITHM keyIso_prov_decoder_algs[] = {
    { KEYISO_NAME_PEM, KEYISO_PROV_PROPQ ",input=pem", keyIso_prov_decoder_pem_funcs, "KMPP pem2key decoder" },
    { NULL, NULL, NULL, NULL }
};

static int _get_params(ossl_unused void *provCtx, OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, KEYISO_PROV_DEFAULT_NAME)) {
        KMPPerr_para(KeyIsoErrReason_FailedToSetParams, "name :%s", KEYISO_PROV_DEFAULT_NAME);
        return STATUS_FAILED;
    }     
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, KEYISO_PROV_OPENSSL_VERSION_STR)) {
        KMPPerr_para(KeyIsoErrReason_FailedToGetParams, "version :%s", KEYISO_PROV_OPENSSL_VERSION_STR);
        return STATUS_FAILED;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, KEYISO_PROV_OPENSSL_VERSION_STR)) {
        KMPPerr_para(KeyIsoErrReason_FailedToGetParams, "version str :%s", KEYISO_PROV_OPENSSL_VERSION_STR);
        return STATUS_FAILED;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, KeyIso_prov_is_running())) {
        KMPPerr_para(KeyIsoErrReason_FailedToGetParams, "status :%d", KeyIso_prov_is_running());
        return STATUS_FAILED;
    }

    return STATUS_OK;
}

static const OSSL_DISPATCH _kmpp_dflt_prov_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))KeyIso_provider_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))KeyIso_query_operation },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void)) _get_params },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void)) KeyIso_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))KeyIso_provider_get_capabilities },
    { 0, NULL }
};

////////////////////////////////////////////////////////////////////////
//                        Empty  provider                             //
////////////////////////////////////////////////////////////////////////

static const OSSL_ALGORITHM *_empty_query_operation(ossl_unused void *provctx, ossl_unused int operation_id, ossl_unused int *no_store) {
    return NULL;
}

// Empty dispatch table
static const OSSL_DISPATCH _kmpp_prov_empty_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))_empty_query_operation },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))KeyIso_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))_get_params },
    { 0, NULL }
};

static int _empty_prov_init(ossl_unused const OSSL_CORE_HANDLE *handle, ossl_unused const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provCtx)
{
    *provCtx = NULL;
    *out = _kmpp_prov_empty_dispatch_table;
    return STATUS_OK;
}

///////////////////////////////////////////////////////////////////////
//                         Init provider                             //
///////////////////////////////////////////////////////////////////////


/* This is the initialization function for "kmppprovider_dflt.so", 
 * which serves as the default provider and should not be called explicitly. 
 * The provider is loaded by OpenSSL's core provider loader as a default  
 * provider, given that the necessary configurations are included in openssl.cnf.  
 * Currently, for an application to use this default provider, it must be enabled 
 * in the configuration file under the "KMPP_CUSTOM_CONFIG_PATH" path and added 
 * to the application's allow list under the "KMPP_ALLOWED_APPS_JSON_CONFIG" path.
 */
int OSSL_provider_init(const OSSL_CORE_HANDLE* handle, const OSSL_DISPATCH* in, const OSSL_DISPATCH** out, void** provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start kmppprovider_dflt");

	// Checking if the admin has enabled KMPP by default in the config file
    if (!g_config.isKmppEnabledByDefault) {
        return _empty_prov_init(handle, in, out, provCtx);
    }

    // Only check allowed process list if KMPP is enabled by default
    char* procName = KeyIso_get_process_name();
    if (procName == NULL) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_PROVIDER_TITLE, "", "Process Name is NULL");
        return _empty_prov_init(handle, in, out, provCtx);
    }

    if (!KeyIso_is_app_allowed(procName)) {
        KEYISOP_trace_log_para(NULL, 0, KEYISOP_PROVIDER_TITLE, "", "Process is not allowed: %s", procName);
        KeyIso_clear_free_string(procName);
        return _empty_prov_init(handle, in, out, provCtx);
    } else {
        KEYISOP_trace_log_para(NULL, 0, KEYISOP_PROVIDER_TITLE, "", "Process is allowed: %s", procName);
        KeyIso_clear_free_string(procName);
        return KeyIso_kmpp_prov_init(handle, in, out, provCtx, _kmpp_dflt_prov_dispatch_table);
    }
}
