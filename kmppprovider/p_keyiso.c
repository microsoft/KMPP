/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <openssl/core_names.h>

#include "keyisoclientinternal.h"
#include "keyisolog.h"
#include "keyisosymcryptcommon.h"
#include "p_keyiso_base.h"
#include "p_keyiso_err.h"

extern const OSSL_DISPATCH keyIso_prov_decoder_pem_funcs[];

/*
 * In order to support decoding of plain-text keys that are not encrypted by the kmpp encoder, 
 * it is necessary to define different names for the decoder between the provider's default 
 * and non-default mode.
 * In the non-default mode, the decoder name must be the same as the key type supported by the
 * provider's keymgmt, so it will be detected by collect_decoder.
 */
const OSSL_ALGORITHM keyIso_prov_decoder_algs[] = {
    { KEYISO_NAME_RSA, KEYISO_PROV_PROPQ ",input=pem", keyIso_prov_decoder_pem_funcs, "KMPP pem2rsa decoder" },
    { KEYISO_NAME_RSA_PSS, KEYISO_PROV_PROPQ ",input=pem", keyIso_prov_decoder_pem_funcs, "KMPP pem2rsapss decoder" },
    { NULL, NULL, NULL, NULL }
};

static int _get_params(ossl_unused void *provCtx, OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, KEYISO_PROV_NAME)) {
        KMPPerr_para(KeyIsoErrReason_FailedToSetParams, "name :%s", KEYISO_PROV_NAME);
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

static void _provider_teardown(KEYISO_PROV_PROVCTX *provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

	// Calling the ECC free function to free the ECC curves - currently relevant only for non-default provider
    KEYISO_EC_free_static();

    KeyIso_provider_teardown(provCtx);
}

/* Functions we provide to the core */
static const OSSL_DISPATCH _kmpp_prov_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))_provider_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))KeyIso_query_operation },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void)) _get_params },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void)) KeyIso_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))KeyIso_provider_get_capabilities },
    { 0, NULL }
};


///////////////////////////////////////////////////////////////////////
//                         Init provider                             //
///////////////////////////////////////////////////////////////////////

/* This is the initialization function for "kmppprovider.so", 
 * which serves as the standard KMPP provider and should be used explicitly. 
 * The provider is loaded by OpenSSL's core provider loader upon manually adding it 
 * to OpenSSL configuration (openssl.cnf) or calling it explicitly by using OSSL_PROVIDER_load
 */
int OSSL_provider_init(const OSSL_CORE_HANDLE* handle, const OSSL_DISPATCH* in, const OSSL_DISPATCH** out, void** provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start kmppprovider");

    // Calling the ECC init function to initialize the ECC curves - currently relevant only for non-default provider
    KEYISO_EC_init_static();

    return KeyIso_kmpp_prov_init(handle, in, out, provCtx, _kmpp_prov_dispatch_table);
}
