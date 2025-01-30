/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include "keyisocommon.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisoclientprovinternal.h"
#include "keyisopfxclientinternal.h"
#include "p_keyiso.h"
#include "p_keyiso_err.h"

static const OSSL_ITEM keyIso_prov_supported_mds[] = {
    { NID_sha1,     OSSL_DIGEST_NAME_SHA1 }, // Default
    { NID_sha256,   OSSL_DIGEST_NAME_SHA2_256 },
    { NID_sha384,   OSSL_DIGEST_NAME_SHA2_384 },
    { NID_sha512,   OSSL_DIGEST_NAME_SHA2_512 },
    { NID_sha3_256, OSSL_DIGEST_NAME_SHA3_256 },
    { NID_sha3_384, OSSL_DIGEST_NAME_SHA3_384 },
    { NID_sha3_512, OSSL_DIGEST_NAME_SHA3_512 } 
};

static int _cleanup_set_md_from_mdname(int ret, KeyIsoErrReason reason, EVP_MD *mdTmp) 
{
    if (ret != STATUS_OK) {
        KMPPerr(reason);

        if (mdTmp)
            EVP_MD_free(mdTmp);
    }

    return ret;
}
#define _CLEANUP_SET_MD_FROM_MDNAME(ret, reason) \
        _cleanup_set_md_from_mdname(ret, reason, mdTmp)

// Common for both RSA and ECC
int KeyIso_prov_set_md_from_mdname(const char *mdName, EVP_MD **md, const OSSL_ITEM **mdInfo)
{
    EVP_MD *mdTmp = NULL;
    const OSSL_ITEM *mdInfoTmp = NULL;

    if (!mdName || !md || !mdInfo)
        return _CLEANUP_SET_MD_FROM_MDNAME(STATUS_FAILED, KeyIsoErrReason_InvalidParams);

    // Fetch MD by Name
    mdTmp = EVP_MD_fetch(NULL, mdName, "");
    if (!mdTmp)
        return _CLEANUP_SET_MD_FROM_MDNAME(STATUS_FAILED, KeyIsoErrReason_InvalidMsgDigest);

    // Find if we support found MD
	for (size_t i = 0; i < sizeof(keyIso_prov_supported_mds) / sizeof(OSSL_ITEM); i++) {
		if (EVP_MD_is_a(mdTmp, keyIso_prov_supported_mds[i].ptr)) {
			mdInfoTmp = &keyIso_prov_supported_mds[i];
			break;
		}
	}

    // If Md was not found by name it's a failure.
    if (mdInfoTmp == NULL)
        return _CLEANUP_SET_MD_FROM_MDNAME(STATUS_FAILED, KeyIsoErrReason_UnsupportedAlgorithm);

    // Cleanup previous MD and update pointers.
    if (*md)
        EVP_MD_free(*md);

    *md = mdTmp;
    *mdInfo = mdInfoTmp;

    return _CLEANUP_SET_MD_FROM_MDNAME(STATUS_OK, KeyIsoErrReason_NoError);
}

void* KeyIso_prov_rsa_keymgmt_new(KEYISO_PROV_PROVCTX *provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    KEYISO_PROV_PKEY* pkey;

    if ((pkey = KeyIso_zalloc(sizeof(KEYISO_PROV_PKEY))) == NULL) {
        return NULL;
    }

    pkey->provCtx = provCtx;
    pkey->keyCtx = NULL;
	pkey->pubKey = NULL;

    return pkey;
}

void KeyIso_rsa_keymgmt_free(KEYISO_PROV_PKEY *pkey)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    if (pkey == NULL)
        return;

    if (pkey->pubKey) {
        EVP_PKEY_free(pkey->pubKey);
    }

    KeyIso_CLIENT_pfx_close(pkey->keyCtx);
    KeyIso_clear_free(pkey, sizeof(KEYISO_PROV_PKEY));
}

// Loads an RSA key management context from a reference
static void *_keymgmt_load(const void *reference, size_t reference_sz)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    KEYISO_PROV_PKEY *pkey = NULL;
 
    if (!reference || reference_sz != sizeof(pkey)) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return NULL;
    }

    // The contents of the reference is the address to our object
    pkey = *(KEYISO_PROV_PKEY**)reference;
    // We grabbed it, so we detach it
    *(KEYISO_PROV_PKEY**)reference = NULL;

    return pkey;
}

static int _cleanup_keymgmt_common_import(int ret, KeyIsoErrReason reason, EVP_PKEY_CTX *ctx) 
{
    if (ret != STATUS_OK) {
        KMPPerr(reason);
    }

    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }   
    
    return ret;
}

#define _CLEANUP_KEYMGMT_COMMON_IMPORT(ret, reason) \
        _cleanup_keymgmt_common_import(ret, reason, ctx)

/***** Common functions for both RSA and ECC ******/

static int _keymgmt_common_import(KEYISO_PROV_PKEY *pkey, const char *algName, int selection, const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *tmpKey = NULL; 

    if (!pkey) {
        return _CLEANUP_KEYMGMT_COMMON_IMPORT(STATUS_FAILED, KeyIsoErrReason_InvalidParams);
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, algName, KEYISO_OSSL_DEFAULT_PROV_PROPQ);
    if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) <= 0) {
        return _CLEANUP_KEYMGMT_COMMON_IMPORT(STATUS_FAILED, KeyIsoErrReason_OperationFailed);
    }

    if(EVP_PKEY_fromdata(ctx, &tmpKey, selection, (OSSL_PARAM*)params) <= 0 || !tmpKey) {
        return _CLEANUP_KEYMGMT_COMMON_IMPORT(STATUS_FAILED, KeyIsoErrReason_ImportFailed);
    }

	pkey->pubKey = tmpKey;
    tmpKey = NULL;
    return _CLEANUP_KEYMGMT_COMMON_IMPORT(STATUS_OK, KeyIsoErrReason_NoError);
}

// Exports parameters from the RSA key management context
static int _keymgmt_common_export(KEYISO_PROV_PKEY *pkey, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
 
    OSSL_PARAM *params = NULL;

    if (!pkey) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    if(!EVP_PKEY_todata(pkey->pubKey, selection, &params)) {
        KMPPerr(KeyIsoErrReason_ExportFailed);
        return STATUS_FAILED;
    }

    return param_cb(params, cbarg);
}

// Gets the parameters of the RSA key management context
static int _keymgmt_get_params(KEYISO_PROV_PKEY *pkey, OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    if (!pkey) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    if (params == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_OK;
    }
    
    if (!EVP_PKEY_get_params(pkey->pubKey, params)) {
        KMPPerr(KeyIsoErrReason_FailedToGetParams);
        return STATUS_FAILED;
    }

    return STATUS_OK;
}

static const OSSL_PARAM* _cleanup_keymgmt_settable_params(int ret, KeyIsoErrReason reason, EVP_PKEY_CTX *ctx,const OSSL_PARAM *params) 
{
    if (ret != STATUS_OK) {
        KMPPerr(reason);
    }

    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    
    return params;
}

#define _CLEANUP_KEYMGMT_SETTABLE_PARAMS(ret, reason) \
        _cleanup_keymgmt_settable_params(ret, reason, ctx, params)

static const OSSL_PARAM* _keymgmt_settable_params(KEYISO_PROV_PROVCTX *provCtx, char *algName)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    const OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    if (!provCtx || !algName) {
        return _CLEANUP_KEYMGMT_SETTABLE_PARAMS(STATUS_FAILED, KeyIsoErrReason_InvalidParams);
    }
 
    ctx = EVP_PKEY_CTX_new_from_name(NULL, algName, KEYISO_OSSL_DEFAULT_PROV_PROPQ);
    if (!ctx) {
        return _CLEANUP_KEYMGMT_SETTABLE_PARAMS(STATUS_FAILED, KeyIsoErrReason_FailedToGetKeyCtx);
    }

    params = EVP_PKEY_fromdata_settable(ctx, OSSL_KEYMGMT_SELECT_PUBLIC_KEY);
    if (!params) {
        return _CLEANUP_KEYMGMT_SETTABLE_PARAMS(STATUS_FAILED, KeyIsoErrReason_OperationFailed);
    }

    return _CLEANUP_KEYMGMT_SETTABLE_PARAMS(STATUS_OK, KeyIsoErrReason_NoError);
}

// Gets the table of parameters that can be set in the RSA key management context
static const OSSL_PARAM* _rsa_keymgmt_settable_params(KEYISO_PROV_PROVCTX *provCtx)
{
   KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

   return _keymgmt_settable_params(provCtx, KEYISO_NAME_RSA);
}

// Sets the parameters of the key management context
static int _keymgmt_set_params(KEYISO_PROV_PKEY *pkey, OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    if (!pkey) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    if (params == NULL)
        return STATUS_OK;

    if (!EVP_PKEY_set_params(pkey->pubKey, params)) {
        KMPPerr(KeyIsoErrReason_FailedToSetParams);
        return STATUS_FAILED;
    }

    return STATUS_OK;
}

// Matches two key management contexts based on the specified selection
static int _keymgmt_match(const KEYISO_PROV_PKEY *pkey1, const KEYISO_PROV_PKEY *pkey2, int selection)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

	if (pkey1 == NULL || pkey2 == NULL) {
		KMPPerr(KeyIsoErrReason_InvalidParams);
		return STATUS_FAILED;
	}

    //  Compare parameters only - relevant for EC key
    if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)
        if (!EVP_PKEY_parameters_eq(pkey1->pubKey, pkey2->pubKey))
            return STATUS_FAILED;

    //  Compare Keys
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) {
        if (!EVP_PKEY_eq(pkey1->pubKey, pkey2->pubKey))
            return STATUS_FAILED;
    }

    return STATUS_OK;
}

// Checks if the key management context has the specified selection
static int _keymgmt_has(const KEYISO_PROV_PKEY *pkey, int selection)
{
    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start", "selection: %d", selection);

    if (pkey == NULL){
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    //  Check if we set the public key 
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        if (!pkey->pubKey)
            return STATUS_FAILED;

    //  Check if we have key ctx
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        if (!pkey->keyCtx)
            return STATUS_FAILED;

    return STATUS_OK;
}

// Queries the operation name for the RSA key management context
static const char* _rsa_keymgmt_query(int operationId)
{
    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start", "operation: %d", operationId);
    return KEYISO_NAME_RSA;
}

// Gets the table of parameters that can be retrieved from the RSA key management context
static const OSSL_PARAM* _rsa_keymgmt_gettable_params(ossl_unused void *provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    static OSSL_PARAM gettable[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
        /* public key */
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END
    };

    return gettable;
}

// Gets the types of parameters that can be exported or imported from the RSA key management context
static const OSSL_PARAM* _rsa_keymgmt_export_import_types(int selection)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    static const OSSL_PARAM rsaPubkeyTypes[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END
    };

    //  The private key cannot be exported
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return rsaPubkeyTypes;
    else
        return NULL;
}

// Imports parameters into the RSA key management context
int _rsa_keymgmt_import(KEYISO_PROV_PKEY *pkey, int selection, const OSSL_PARAM params[])
{
   KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

   return _keymgmt_common_import(pkey, KEYISO_NAME_RSA, selection, params);
}

/*static void* _rsa_gen_init(void* provCtx, int selection, const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    return NULL;
}

static void* _rsa_gen(void* genctx, OSSL_CALLBACK* osslcb, void* cbarg)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    return NULL;
}

static void _rsa_gen_cleanup(void *genctx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
}

static int _keymgmt_generate_set_template(void* genctx, void* template)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    return 1;
}

static int _keymgmt_generate_set_params(void* genctx, const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    return 1;
}

static const OSSL_PARAM* _keymgmt_generate_settable_params(void* genctx, void* provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    static OSSL_PARAM gettable[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
        // public key 
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END
    };

    return gettable;
}*/

const OSSL_DISPATCH keyIso_prov_rsa_keymgmt_funcs[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))KeyIso_prov_rsa_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))KeyIso_rsa_keymgmt_free},
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))_keymgmt_load },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void(*)(void))_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void(*)(void))_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void(*)(void))_rsa_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void(*)(void))_keymgmt_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void(*)(void))_rsa_keymgmt_settable_params },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))_rsa_keymgmt_query },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))_rsa_keymgmt_export_import_types }, 
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))_rsa_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))_rsa_keymgmt_export_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))_keymgmt_common_export },
    
    /* Gen functions */
    /*{OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))_rsa_gen_init},
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))_rsa_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))_rsa_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))_keymgmt_generate_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))_keymgmt_generate_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))_keymgmt_generate_settable_params },
    */
    { 0, NULL }
};