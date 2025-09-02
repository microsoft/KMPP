/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/provider.h>
#include <openssl/params.h>

#include "keyisocommon.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisoclient.h"
#include "keyisoclientinternal.h"
#include "keyisopfxclientinternal.h"
#include "keyisotelemetry.h"
#include "p_keyiso.h"
#include "p_keyiso_err.h"

extern KEYISO_CLIENT_CONFIG_ST g_config;

KEYISO_PROV_PKEY* KeyIso_prov_ecc_keymgmt_new(KEYISO_PROV_PROVCTX *provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    KEYISO_PROV_PKEY* pkey;

    if ((pkey = KeyIso_zalloc(sizeof(KEYISO_PROV_PKEY))) == NULL) {
        return NULL;
    }

    pkey->provCtx = provCtx;
    pkey->keyCtx = NULL;
    pkey->pubKey = NULL;
    pkey->keyType = EVP_PKEY_EC;
    return pkey;
}

void KeyIso_ecc_keymgmt_free(KEYISO_PROV_PKEY *pKey)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    if (pKey == NULL)
        return;

    if (pKey->pubKey) {
        EVP_PKEY_free(pKey->pubKey);
        pKey->pubKey = NULL;
    }

    if (pKey->keyCtx) {
        KeyIso_CLIENT_pfx_close(pKey->keyCtx);
        pKey->keyCtx = NULL;
    }

    KeyIso_clear_free(pKey, sizeof(KEYISO_PROV_PKEY));
}

static int _ecc_keymgmt_get_params(KEYISO_PROV_PKEY *pKey, OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    if (!pKey || !pKey->pubKey) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    if (params == NULL) {
        return STATUS_OK;
    }

    if (EVP_PKEY_get_params(pKey->pubKey, params) <= 0) {
        KMPPerr(KeyIsoErrReason_FailedToGetParams);
        return STATUS_FAILED;
    }

    return STATUS_OK;
}

static const OSSL_PARAM* _ecc_keymgmt_gettable_params(ossl_unused KEYISO_PROV_PROVCTX *provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    static OSSL_PARAM gettable[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_END
    };

    return gettable;
}

static const OSSL_PARAM* _ecc_keymgmt_export_import_types(int selection)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    static const OSSL_PARAM eccPubkeyTypes[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END
    };

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return eccPubkeyTypes;
    
    return NULL;
}

static const char* _ecc_keymgmt_query(int operationId)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    switch (operationId) {
        case OSSL_OP_KEYEXCH:
            return KEYISO_NAME_ECDH;
        case OSSL_OP_SIGNATURE:
            return KEYISO_NAME_ECDSA;
    }

    return NULL;

}

static int _ecc_keymgmt_import(KEYISO_PROV_PKEY *pkey, int selection, const OSSL_PARAM params[])
{
   KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
   return KeyIso_keymgmt_common_import(pkey, KEYISO_NAME_EC, selection, params);
}

static KEYISO_PROV_PKEY* _prov_ecc_keymgmt_new(KEYISO_PROV_PROVCTX *provCtx)
{
    return KeyIso_prov_ecc_keymgmt_new(provCtx);
}

/**************************** 
 ** Generate key functions **
 ***************************/

static void _ecc_keymgmt_gen_cleanup(KEYISO_PROV_ECC_GEN_CTX *genCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    if (genCtx == NULL)
        return;

    KeyIso_clear_free(genCtx, sizeof(KEYISO_PROV_ECC_GEN_CTX));
}

static int _ecc_keymgmt_gen_set_template(ossl_unused KEYISO_PROV_ECC_GEN_CTX *genCtx, ossl_unused const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    return STATUS_OK;
}

 static const OSSL_PARAM* _ecc_keymgmt_gen_settable_params(ossl_unused KEYISO_PROV_ECC_GEN_CTX *genCtx, ossl_unused KEYISO_PROV_PROVCTX *provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_END
    };

    return settable;
}
static int _ecc_keymgmt_gen_set_params(KEYISO_PROV_ECC_GEN_CTX *genCtx, const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");  
    const OSSL_PARAM *p;

    if (params == NULL)
        return STATUS_OK;

    if (genCtx == NULL || genCtx->provCtx == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL) {
        const char *curveName;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &curveName)) {
            KMPPerr(KeyIsoErrReason_FailedToGetParams);
            return STATUS_FAILED;
        }
        /* Convert curve name to NID - first try NIST name, then OpenSSL short name */
        genCtx->curveNid = EC_curve_nist2nid(curveName);
        if (genCtx->curveNid == NID_undef && (genCtx->curveNid = OBJ_sn2nid(curveName)) == NID_undef) {
            KMPPerr(KeyIsoErrReason_InvalidCurve);
            return STATUS_FAILED;
        }
    }

    return STATUS_OK;
}

/* ECC key generation functions – currently implemented only for ephemeral keys used in TLS 1.3 key exchange.
 * These functions delegate to OpenSSL since persistent ECC key generation via KMPP is not yet required.
 * If and when default provider will be required for ECC (similar to RSA), these functions will be updated
 * and fully implemented accordingly.
 */
static KEYISO_PROV_ECC_GEN_CTX* _ecc_keymgmt_gen_init(KEYISO_PROV_PROVCTX* provCtx, int selection, const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    if (!(selection & OSSL_KEYMGMT_SELECT_KEYPAIR)) {
        return NULL;
    }

    KEYISO_PROV_ECC_GEN_CTX *genCtx = KeyIso_zalloc(sizeof(KEYISO_PROV_ECC_GEN_CTX));
    if (genCtx == NULL) {
        KMPPerr(KeyIsoErrReason_AllocFailure);
        return NULL;
    }
    genCtx->provCtx = provCtx;
    genCtx->curveNid = NID_undef;

    if (!_ecc_keymgmt_gen_set_params(genCtx, params)) {
        _ecc_keymgmt_gen_cleanup(genCtx);
        genCtx = NULL;
    }

    return genCtx;
}

static KEYISO_PROV_PKEY* _cleanup_ecc_keymgmt_gen(int ret, KeyIsoErrReason reason, KEYISO_PROV_PKEY *provKey, EVP_PKEY_CTX *paramGenCtx,
     EVP_PKEY_CTX *keyGenCtx, EVP_PKEY *pkey)
{
    if (ret != STATUS_OK) {
        KMPPerr(reason);

        if (pkey)
            EVP_PKEY_free(pkey);
    }

    if(paramGenCtx)
        EVP_PKEY_CTX_free(paramGenCtx);

    if(keyGenCtx)
        EVP_PKEY_CTX_free(keyGenCtx);

    return provKey;
}

#define _CLEANUP_ECC_KEYMGMT_GEN(ret, reason) \
    _cleanup_ecc_keymgmt_gen(ret, reason, provKey, paramGenCtx, keyGenCtx, pkey)

static KEYISO_PROV_PKEY* _ecc_keymgmt_gen(KEYISO_PROV_ECC_GEN_CTX* genCtx, ossl_unused OSSL_CALLBACK* osslcb, ossl_unused void* cbarg)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
 
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *paramGenCtx = NULL;
    EVP_PKEY_CTX *keyGenCtx = NULL;
    EVP_PKEY *params = NULL;
    KEYISO_PROV_PKEY* provKey = NULL;

    if (genCtx == NULL || genCtx->provCtx == NULL) {
        return _CLEANUP_ECC_KEYMGMT_GEN(STATUS_FAILED, KeyIsoErrReason_InvalidParams);
    }

    // Generate ECC parameters for the selected curve
    paramGenCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (paramGenCtx == NULL || EVP_PKEY_paramgen_init(paramGenCtx) <= 0) {
        return _CLEANUP_ECC_KEYMGMT_GEN(STATUS_FAILED, KeyIsoErrReason_FailedToGenerateKey);
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramGenCtx, genCtx->curveNid) <= 0) {
        return _CLEANUP_ECC_KEYMGMT_GEN(STATUS_FAILED, KeyIsoErrReason_InvalidCurve);
    }

    if (EVP_PKEY_paramgen(paramGenCtx, &params) <= 0) {
        return _CLEANUP_ECC_KEYMGMT_GEN(STATUS_FAILED, KeyIsoErrReason_FailedToGenerateKey);
    }

    // Generate ECC key pair
    keyGenCtx = EVP_PKEY_CTX_new(params, NULL);
    EVP_PKEY_free(params);

    if (keyGenCtx == NULL || EVP_PKEY_keygen_init(keyGenCtx) <= 0) {
        return _CLEANUP_ECC_KEYMGMT_GEN(STATUS_FAILED, KeyIsoErrReason_FailedToGenerateKey);
    }

    if (EVP_PKEY_keygen(keyGenCtx, &pkey) <= 0) {
        return _CLEANUP_ECC_KEYMGMT_GEN(STATUS_FAILED, KeyIsoErrReason_FailedToGenerateKey);
    }

    // Store the generated key in the provider key context
    provKey = KeyIso_prov_ecc_keymgmt_new(genCtx->provCtx);
    if (provKey == NULL) {
        return _CLEANUP_ECC_KEYMGMT_GEN(STATUS_FAILED, KeyIsoErrReason_FailedToGetProvKey);
    }
    provKey->pubKey = pkey;

    return _CLEANUP_ECC_KEYMGMT_GEN(STATUS_OK, KeyIsoErrReason_NoError);
}

const OSSL_DISPATCH keyIso_prov_ecc_keymgmt_funcs[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))_prov_ecc_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))KeyIso_ecc_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))KeyIso_keymgmt_load },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))KeyIso_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void(*)(void))KeyIso_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void(*)(void))_ecc_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void(*)(void))_ecc_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))_ecc_keymgmt_query },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))_ecc_keymgmt_export_import_types }, 
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))_ecc_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))_ecc_keymgmt_export_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))KeyIso_keymgmt_common_export },
    /* Gen functions */
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))_ecc_keymgmt_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))_ecc_keymgmt_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))_ecc_keymgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))_ecc_keymgmt_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))_ecc_keymgmt_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))_ecc_keymgmt_gen_settable_params }, 
    { 0, NULL }
};
