/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>

#include "keyisoclientinternal.h"
#include "keyisoclientprovinternal.h"
#include "keyisocommon.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisotelemetry.h"
#include "p_keyiso.h"
#include "p_keyiso_err.h"

extern KEYISO_CLIENT_CONFIG_ST g_config;
static int isRunning = 0;

static OSSL_FUNC_core_get_libctx_fn *keyIso_core_get_libctx = NULL;
static OSSL_FUNC_core_gettable_params_fn *keyIso_core_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *keyIso_core_get_params = NULL;
static OSSL_FUNC_core_new_error_fn *keyIso_core_new_error = NULL;
static OSSL_FUNC_core_set_error_debug_fn *keyIso_core_set_error_debug = NULL;
static OSSL_FUNC_core_vset_error_fn *keyIso_core_vset_error = NULL;

extern const OSSL_DISPATCH keyIso_prov_rsa_keymgmt_funcs[];
extern const OSSL_DISPATCH keyIso_prov_rsa_store_funcs[];
extern const OSSL_DISPATCH keyIso_prov_rsa_signature_funcs[];
extern const OSSL_DISPATCH keyIso_prov_rsa_cipher_funcs[];


static const OSSL_ALGORITHM keyIso_prov_asym_cipher_algs[] = {
	{ KEYISO_PROV_ASYM_CIPHER_NAME_RSA, KEYISO_PROV_PROPQ, keyIso_prov_rsa_cipher_funcs, "RSA Asym Cipher" },
	{ NULL, NULL, NULL, NULL }
};


static const OSSL_ALGORITHM keyIso_prov_signature_algs[] = {
    { KEYISO_PROV_SIGN_NAME_RSA, KEYISO_PROV_PROPQ, keyIso_prov_rsa_signature_funcs, "RSA Signature" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM keyIso_prov_keymgmt_algs[] = {
    { KEYISO_PROV_KEYMGMT_NAME_RSA, KEYISO_PROV_PROPQ, keyIso_prov_rsa_keymgmt_funcs, "RSA Key management" },
    //{ KEYISO_PROV_KEYMGMT_NAME_EC,  KEYISO_PROV_PROPQ, KeyIso_prov_ecc_keymgmt_functions },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM keyIso_prov_store_algs[] = {
    { KEYISO_PROV_STORE_SCHEME, KEYISO_PROV_PROPQ, keyIso_prov_rsa_store_funcs, "KMPP store"},
    { NULL, NULL, NULL, NULL }
};

#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))

// TLS structure aligned with SCOSSL_TLS_GROUP_INFO
typedef struct KeyIso_prov_tls_group_constants_st KEYISO_PROV_TLS_GROUP_CONSTANTS;
struct KeyIso_prov_tls_group_constants_st {
    unsigned int groupId;    /* Group ID */
    unsigned int secBits;    /* Bits of security */
    int minTls;              /* Minimum TLS version, -1 unsupported */
    int maxTls;              /* Maximum TLS version (or 0 for undefined) */
    int mindTls;             /* Minimum DTLS version, -1 unsupported */
    int maxdTls;             /* Maximum DTLS version (or 0 for undefined) */
};

#define TLS_GROUP_ID_secp192r1 19   // OSSL_TLS_GROUP_ID_secp192r1 in SympCrypt provider       
#define TLS_GROUP_ID_secp224r1 21   // OSSL_TLS_GROUP_ID_secp224r1 in SympCrypt provider   
#define TLS_GROUP_ID_secp256r1 23   // OSSL_TLS_GROUP_ID_secp256r1 in SympCrypt provider   
#define TLS_GROUP_ID_secp384r1 24   // OSSL_TLS_GROUP_ID_secp384r1 in SympCrypt provider   
#define TLS_GROUP_ID_secp521r1 25   // OSSL_TLS_GROUP_ID_secp521r1 in SympCrypt provider   

static const KEYISO_PROV_TLS_GROUP_CONSTANTS tls_group_list[] = {
    { TLS_GROUP_ID_secp192r1, 80, TLS1_VERSION, TLS1_2_VERSION, DTLS1_VERSION, DTLS1_2_VERSION },   // scossl_tls_group_info_p192
    { TLS_GROUP_ID_secp224r1, 112, TLS1_VERSION, TLS1_2_VERSION, DTLS1_VERSION, DTLS1_2_VERSION },  // scossl_tls_group_info_p224 
	{ TLS_GROUP_ID_secp256r1, 128, TLS1_VERSION, 0, DTLS1_VERSION, 0 },                             // scossl_tls_group_info_p256
	{ TLS_GROUP_ID_secp384r1, 192, TLS1_VERSION, 0, DTLS1_VERSION, 0 },     				        // scossl_tls_group_info_p384
    { TLS_GROUP_ID_secp521r1, 256, TLS1_VERSION, 0, DTLS1_VERSION, 0 },                             // scossl_tls_group_info_p521
};

#define TLS_GROUP_ENTRY(tlsName, realName, algorithm, idx) \
    { \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, tlsName, sizeof(tlsName)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, realName, sizeof(realName)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, algorithm, sizeof(algorithm)), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID, (unsigned int *)&tls_group_list[idx].groupId), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, (unsigned int *)&tls_group_list[idx].secBits), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, (int *)&tls_group_list[idx].minTls),     \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, (int *)&tls_group_list[idx].maxTls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, (int *)&tls_group_list[idx].mindTls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, (int *)&tls_group_list[idx].maxdTls), \
        OSSL_PARAM_END \
    }

static const OSSL_PARAM param_tls_group_list[][10] = {
    TLS_GROUP_ENTRY("secp192r1", "prime192v1", "EC", 0),
    TLS_GROUP_ENTRY("P-192", "prime192v1", "EC", 0), /* Alias of previous */
    TLS_GROUP_ENTRY("secp224r1", "secp224r1", "EC", 1),
    TLS_GROUP_ENTRY("P-224", "secp224r1", "EC", 1), /* Alias of previous */
    TLS_GROUP_ENTRY("secp256r1", "prime256v1", "EC", 2),
    TLS_GROUP_ENTRY("P-256", "prime256v1", "EC", 2), /* Alias of previous */
    TLS_GROUP_ENTRY("secp384r1", "secp384r1", "EC", 3),
    TLS_GROUP_ENTRY("P-384", "secp384r1", "EC", 3), /* Alias of previous */
    TLS_GROUP_ENTRY("secp521r1", "secp521r1", "EC", 4),
    TLS_GROUP_ENTRY("P-521", "secp521r1", "EC", 4), /* Alias of above */
};

static int _prov_is_running() 
{ 
    return isRunning; 
}

static const OSSL_ALGORITHM* _query_operation(ossl_unused  void *provCtx, int operation, int *noCache)
{
    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start", "operation: %d", operation);

    *noCache = 0;
    switch (operation) {
    case OSSL_OP_SIGNATURE:
        return keyIso_prov_signature_algs;

    case OSSL_OP_KEYMGMT:
        return keyIso_prov_keymgmt_algs;

    case OSSL_OP_STORE:
        return keyIso_prov_store_algs;

    case OSSL_OP_ASYM_CIPHER:
        return keyIso_prov_asym_cipher_algs;

    /*case OSSL_OP_CIPHER:
        return keyIso_prov_cipher_algs;*/

    }
    return NULL;
}


static int _provider_get_capabilities(ossl_unused void *provCtx, const char *capability, OSSL_CALLBACK *cb, void *arg)
{
    if (OPENSSL_strcasecmp(capability, "TLS-GROUP") == 0) {   
        for (size_t i = 0; i < NELEMS(param_tls_group_list); i++) {
            if (!cb(param_tls_group_list[i], arg))
                return STATUS_FAILED;
        }
        return STATUS_OK;
    }
    return STATUS_FAILED;
}

static const OSSL_PARAM _provider_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *_gettable_params(ossl_unused void *provCtx)
{
	KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
	return _provider_param_types;
}

static int _get_params(ossl_unused void *provCtx, OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, KEYISO_PROV_OPENSSL_NAME)) {
        KMPPerr_para(KeyIsoErrReason_FailedToSetParams, "name :%s", OSSL_PROV_PARAM_NAME);
        return STATUS_FAILED;
    }     
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, KEYISO_PROV_OPENSSL_VERSION_STR)) {
        KMPPerr_para(KeyIsoErrReason_FailedToGetParams, "version :%s", OSSL_PROV_PARAM_VERSION);
		return STATUS_FAILED;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, KEYISO_PROV_OPENSSL_FULL_VERSION_STR)) {
        KMPPerr_para(KeyIsoErrReason_FailedToGetParams, "version str :%s", KEYISO_PROV_OPENSSL_FULL_VERSION_STR);
		return STATUS_FAILED;
    }
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, _prov_is_running())) {
        KMPPerr_para(KeyIsoErrReason_FailedToGetParams, "status :%d", _prov_is_running());
		return STATUS_FAILED;
    }

    return STATUS_OK;
}

static void _provider_teardown(KEYISO_PROV_PROVCTX *provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    
    // Clean up the provider context
    KeyIso_free(provCtx);
    ERR_unload_KMPP_strings();
#ifndef KMPP_TELEMETRY_DISABLED
    KeyIso_check_all_metrics(KeyisoKeyOperation_Max, KeyisoCleanCounters_All);
#endif
}

/* Functions we provide to the core */
static const OSSL_DISPATCH _kmpp_prov_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))_provider_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))_query_operation },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void)) _get_params },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void)) _gettable_params },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))_provider_get_capabilities },
    { 0, NULL }
};

static int _init_core_func_from_dispatch(const OSSL_DISPATCH *fns)
{
    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {

        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            if (keyIso_core_gettable_params == NULL)
                keyIso_core_gettable_params = OSSL_FUNC_core_gettable_params(fns);
            break;

        case OSSL_FUNC_CORE_GET_PARAMS:
            if (keyIso_core_get_params == NULL)
                keyIso_core_get_params = OSSL_FUNC_core_get_params(fns);
            break;

        case OSSL_FUNC_CORE_NEW_ERROR:
            if (keyIso_core_new_error == NULL)
                keyIso_core_new_error = OSSL_FUNC_core_new_error(fns);
            break;

        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            if (keyIso_core_set_error_debug == NULL)
                keyIso_core_set_error_debug = OSSL_FUNC_core_set_error_debug(fns);
            break;

        case OSSL_FUNC_CORE_VSET_ERROR:
            if (keyIso_core_vset_error == NULL)
                keyIso_core_vset_error = OSSL_FUNC_core_vset_error(fns);
            break;
        case OSSL_FUNC_CORE_GET_LIBCTX:
            if (keyIso_core_get_libctx == NULL)
                keyIso_core_get_libctx = OSSL_FUNC_core_get_libctx(fns);
            break;
        }
    }

    return STATUS_OK;
}

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    KEYISO_PROV_PROVCTX *pCtx = NULL;

    // Initialize function pointers 
    _init_core_func_from_dispatch(in);

    // Initialize error strings
    ERR_load_KMPP_strings();
    
    if (keyIso_core_get_libctx == NULL) {
        KMPPerr_log(KeyIsoErrReason_FailedToGetLibCtx, "_init_core_func_from_dispatch");
        KEYISOP_trace_metric_error(NULL, 0, g_config.solutionType, KEYISOP_PROVIDER_TITLE, "Provider Init failed", "");
        return STATUS_FAILED;
    }

    pCtx = KeyIso_zalloc(sizeof(KEYISO_PROV_PROVCTX));
    if (!pCtx) {
        KEYISOP_trace_metric_error(NULL, 0, g_config.solutionType, KEYISOP_PROVIDER_TITLE, "Provider Init failed", "");
        return STATUS_FAILED;
    }
        

    //  Populate KMPP Provider Context 
    pCtx->handle = handle;
    pCtx->libCtx = (OSSL_LIB_CTX*)keyIso_core_get_libctx(handle);
    *provCtx = pCtx;
    *out = _kmpp_prov_dispatch_table;
    isRunning = 1;

#ifndef KMPP_TELEMETRY_DISABLED
    // Setting the counters threshold according to environment variables
    int countTh = 0;
    int timeTh = 0;
    KeyIso_init_counter_th(&countTh, &timeTh, g_config.solutionType);
    KEYISOP_trace_metric_para(NULL, 0, g_config.solutionType, KEYISOP_PROVIDER_TITLE, NULL,"Provider Init - counters and time thresholds: %d, %d", countTh, timeTh);
#endif

    return STATUS_OK;
}