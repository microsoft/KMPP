/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

 #include <stdio.h>
 #include <string.h>
 
 #include <openssl/core_names.h>
 #include <openssl/evp.h>
 #include <openssl/pem.h>
 #include <openssl/provider.h>
 
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

#define KEYISO_PROV_DEFAULT_RSA_PSS_MD_IDX          0 // Index of the default MD (SHA1) similarily to SCOSSL_PROV_RSA_PSS_DEFAULT_MD
#define KEYISO_PROV_DEFAULT_RSA_PSS_DEFAULT_SALTLEN 20 // SCOSSL_PROV_RSA_PSS_DEFAULT_SALTLEN_MIN

static const OSSL_ITEM keyIso_prov_supported_mds[] = {
    { NID_sha1,     OSSL_DIGEST_NAME_SHA1 }, // Default
    { NID_sha256,   OSSL_DIGEST_NAME_SHA2_256 },
    { NID_sha384,   OSSL_DIGEST_NAME_SHA2_384 },
    { NID_sha512,   OSSL_DIGEST_NAME_SHA2_512 },
    { NID_sha3_256, OSSL_DIGEST_NAME_SHA3_256 },
    { NID_sha3_384, OSSL_DIGEST_NAME_SHA3_384 },
    { NID_sha3_512, OSSL_DIGEST_NAME_SHA3_512 } 
};

KEYISO_PROV_PKEY* KeyIso_prov_rsa_keymgmt_new(KEYISO_PROV_PROVCTX *provCtx, unsigned int keyType)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    KEYISO_PROV_PKEY* pkey;

    if ((pkey = KeyIso_zalloc(sizeof(KEYISO_PROV_PKEY))) == NULL) {
        return NULL;
    }

    pkey->provCtx = provCtx;
    pkey->keyCtx = NULL;
	pkey->pubKey = NULL;
    pkey->keyType = keyType;
    pkey->keysInUseCtx = NULL; 
    return pkey;
}

void KeyIso_rsa_keymgmt_free(KEYISO_PROV_PKEY *pKey)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    if (pKey == NULL)
        return;

#ifdef KEYS_IN_USE_AVAILABLE
    // KeysInUse update for unloading the key
    //KeyInUseToDo: p_scossl_keysinuse_unload_key(pKey->keysInUseCtx);     
#endif

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
        return _CLEANUP_KEYMGMT_COMMON_IMPORT(STATUS_FAILED, KeyIsoErrReason_FailedToImport);
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
        KMPPerr(KeyIsoErrReason_FailedToExport);
        return STATUS_FAILED;
    }

    return param_cb(params, cbarg);
}

// Gets the parameters of the RSA key management context
static int _rsa_keymgmt_get_params(KEYISO_PROV_PKEY *pKey, OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    OSSL_PARAM *p;

    if (!pKey || !pKey->pubKey) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    if (params == NULL) {
        return STATUS_OK;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL 
        && !OSSL_PARAM_set_uint32(p, EVP_PKEY_bits(pKey->pubKey))) {
        KMPPerr(KeyIsoErrReason_FailedToGetParams);
        return STATUS_FAILED;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL 
        && !OSSL_PARAM_set_int(p, EVP_PKEY_security_bits(pKey->pubKey))) {
        KMPPerr(KeyIsoErrReason_FailedToGetParams);
        return STATUS_FAILED;
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL 
        && !OSSL_PARAM_set_uint32(p, EVP_PKEY_size(pKey->pubKey))) {
        KMPPerr(KeyIsoErrReason_FailedToGetParams);
        return STATUS_FAILED;
    }

     // The OSSL_PKEY_PARAM_DEFAULT_DIGEST parameter is ignored when restricted PSS keys requirements already exist.
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) != NULL) {
        if (pKey->keyType != EVP_PKEY_RSA_PSS && !OSSL_PARAM_set_utf8_string(p, KEYISO_PROV_DEFAULT_MD)) {
            KMPPerr(KeyIsoErrReason_FailedToGetParams);
            return STATUS_FAILED;
        }
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_N)) != NULL) {
        BIGNUM *n = NULL;
        EVP_PKEY_get_bn_param(pKey->pubKey, OSSL_PKEY_PARAM_RSA_N, &n);
        if (!OSSL_PARAM_set_BN(p, n)) {
            KMPPerr(KeyIsoErrReason_FailedToGetParams);
            BN_free(n);
            return STATUS_FAILED;
        }
        BN_free(n);
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_E)) != NULL) {
        BIGNUM *e = NULL;
        EVP_PKEY_get_bn_param(pKey->pubKey, OSSL_PKEY_PARAM_RSA_E, &e);
        if (!OSSL_PARAM_set_BN(p, e)) {
            KMPPerr(KeyIsoErrReason_FailedToGetParams);
            BN_free(e);
            return STATUS_FAILED;
        }
        BN_free(e);
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
static const OSSL_PARAM* _rsa_keymgmt_gettable_params(ossl_unused KEYISO_PROV_PROVCTX *provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    static OSSL_PARAM gettable[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
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

static KEYISO_PROV_PKEY* _prov_rsa_keymgmt_new(KEYISO_PROV_PROVCTX *provCtx)
{
    return KeyIso_prov_rsa_keymgmt_new(provCtx, EVP_PKEY_RSA);
}

static KEYISO_PROV_PKEY* _prov_rsapss_keymgmt_new(KEYISO_PROV_PROVCTX *provCtx)
{
    return KeyIso_prov_rsa_keymgmt_new(provCtx, EVP_PKEY_RSA_PSS);
}

/**************************** 
 ** Generate key functions **
 ***************************/

static void _rsa_keymgmt_gen_cleanup(KEYISO_PROV_RSA_GEN_CTX *genCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    if (genCtx == NULL)
        return;

    if(genCtx->pssInfo)
        KeyIso_free(genCtx->pssInfo);

    KeyIso_clear_free(genCtx, sizeof(KEYISO_PROV_RSA_GEN_CTX));
}

static void _rsa_pss_info_get_defaults(KEYISO_PROV_RSA_MD_INFO_CTX* pssInfo)
{
    if (pssInfo != NULL) {
        pssInfo->mdInfo = &keyIso_prov_supported_mds[KEYISO_PROV_DEFAULT_RSA_PSS_MD_IDX];
        pssInfo->mgf1MdInfo = &keyIso_prov_supported_mds[KEYISO_PROV_DEFAULT_RSA_PSS_MD_IDX];
        pssInfo->saltLen = KEYISO_PROV_DEFAULT_RSA_PSS_DEFAULT_SALTLEN;

         // Fetch the default MD and MGF1 MD
        pssInfo->md = EVP_MD_fetch(NULL, KEYISO_PROV_DEFAULT_RSA_PSS_MD, KEYISO_OSSL_DEFAULT_PROV_PROPQ);
        pssInfo->mgf1Md = EVP_MD_fetch(NULL, KEYISO_PROV_DEFAULT_RSA_PSS_MD, KEYISO_OSSL_DEFAULT_PROV_PROPQ);

        if (pssInfo->md == NULL || pssInfo->mgf1Md == NULL) {
            // Handle error if fetching the default MD or MGF1 MD fails
            if (pssInfo->md) {
                EVP_MD_free(pssInfo->md);
                pssInfo->md = NULL;
            }
            if (pssInfo->mgf1Md) {
                EVP_MD_free(pssInfo->mgf1Md);
                pssInfo->mgf1Md = NULL;
            }
        }
    }
}

static int _cleanup_rsa_pss_info_from_params(int ret, KeyIsoErrReason reason, KEYISO_PROV_RSA_MD_INFO_CTX *pssInfo, int allocated) 
{
    if (ret != STATUS_OK) {
        KMPPerr(reason);

        if (pssInfo && allocated) {
            KeyIso_free(pssInfo);
        }
    } 

    return ret;
}

#define _CLEANUP_RSA_PSS_INFO_FROM_PARAMS(ret, reason) \
        _cleanup_rsa_pss_info_from_params(ret, reason, tmpPssInfo, allocated)


static int _rsa_pss_info_from_params(OSSL_LIB_CTX *libCtx, const OSSL_PARAM params[], KEYISO_PROV_RSA_MD_INFO_CTX **pssInfo)
{
    const char *mdProps = NULL;
    KEYISO_PROV_RSA_MD_INFO_CTX *tmpPssInfo = NULL;
    int allocated = 0;

    const OSSL_PARAM *saltLen = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN); // OSSL_SIGNATURE_PARAM_PSS_SALTLEN
    const OSSL_PARAM *paramPropq = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_DIGEST_PROPS);
    const OSSL_PARAM *paramMd = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_DIGEST); // OSSL_SIGNATURE_PARAM_DIGEST
    const OSSL_PARAM *paramMgf1md = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_MGF1_DIGEST); // OSSL_SIGNATURE_PARAM_MGF1_DIGEST

    if (saltLen == NULL && paramPropq == NULL && paramMd == NULL && paramMgf1md == NULL) {
        return STATUS_OK;
    }

    if (*pssInfo == NULL) {
        if ((tmpPssInfo = KeyIso_zalloc(sizeof(KEYISO_PROV_RSA_MD_INFO_CTX))) == NULL) {
            return _CLEANUP_RSA_PSS_INFO_FROM_PARAMS(STATUS_FAILED, KeyIsoErrReason_AllocFailure);
        }

        // Set defaults based on RFC 8017, A.2.3, same as SCOSSL and default provider.
        _rsa_pss_info_get_defaults(tmpPssInfo);
        *pssInfo = tmpPssInfo;
		allocated = 1;
    } else {
        tmpPssInfo = *pssInfo;
    }

    if (saltLen != NULL && !OSSL_PARAM_get_int(saltLen, &tmpPssInfo->saltLen)) {
        return _CLEANUP_RSA_PSS_INFO_FROM_PARAMS(STATUS_FAILED, KeyIsoErrReason_UnsupportedSaltLen);
    }

    if (paramPropq != NULL && !OSSL_PARAM_get_utf8_string_ptr(paramPropq, &mdProps)) {
        return _CLEANUP_RSA_PSS_INFO_FROM_PARAMS(STATUS_FAILED, KeyIsoErrReason_FailedToGetParams);
    }

    if (paramMd != NULL && (KeyIso_prov_set_md_from_mdname(libCtx, paramMd, NULL, mdProps, &tmpPssInfo->md, &tmpPssInfo->mdInfo)) == STATUS_FAILED) {
        return _CLEANUP_RSA_PSS_INFO_FROM_PARAMS(STATUS_FAILED, KeyIsoErrReason_InvalidMsgDigest);
    }

    if (paramMgf1md != NULL && (KeyIso_prov_set_md_from_mdname(libCtx, paramMgf1md, NULL, mdProps, &tmpPssInfo->mgf1Md, &tmpPssInfo->mgf1MdInfo)) == STATUS_FAILED) {
        return _CLEANUP_RSA_PSS_INFO_FROM_PARAMS(STATUS_FAILED, KeyIsoErrReason_InvalidMsgDigest);
    }

    return _CLEANUP_RSA_PSS_INFO_FROM_PARAMS(STATUS_OK, KeyIsoErrReason_NoError);
}

static int _rsa_keymgmt_generate_set_params(KEYISO_PROV_RSA_GEN_CTX *genCtx, const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");  
    const OSSL_PARAM *p;

    if (params == NULL)
        return STATUS_OK;

    if (genCtx == NULL || genCtx->provKey == NULL || genCtx->provKey->provCtx == NULL) {
		KMPPerr(KeyIsoErrReason_InvalidParams);
		return STATUS_FAILED;
    }

    // Basic gen info
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS)) != NULL) {
        uint32_t nBitsOfModulus;

        if (!OSSL_PARAM_get_uint32(p, &nBitsOfModulus)) {
            KMPPerr(KeyIsoErrReason_FailedToGetParams);
            return STATUS_FAILED;
        }

        // Provider is expected to validate lower bound here
        if (nBitsOfModulus < KEYISO_SYMCRYPT_RSA_MIN_BITSIZE_MODULUS) {
            KMPPerr(KeyIsoErrReason_InvalidKeySize);
            return STATUS_FAILED;
        }
        genCtx->nBitsOfModulus = nBitsOfModulus;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PRIMES)) != NULL) {
        size_t nPrimes;
        if (!OSSL_PARAM_get_size_t(p, &nPrimes)) {
            KMPPerr(KeyIsoErrReason_FailedToGetParams);
            return STATUS_FAILED;
        }

        if (nPrimes != KEYISO_SYMCRYPT_RSA_SUPPORTED_NUM_OF_PRIMES) {
            KMPPerr(KeyIsoErrReason_UnsupportedNumberOfPrimes);
            return STATUS_FAILED;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E)) != NULL) {
        if (!OSSL_PARAM_get_uint64(p, &genCtx->pubExp64)) {
            KMPPerr(KeyIsoErrReason_FailedToGetParams);
            return STATUS_FAILED;
        }
        genCtx->nPubExp = KEYISO_SYMCRYPT_RSA_PARAMS_N_PUB_EXP;
    }

    // PSS info
    if (genCtx->padding == KMPP_RSA_PKCS1_PSS_PADDING
        && !_rsa_pss_info_from_params(genCtx->provKey->provCtx->libCtx, params, &genCtx->pssInfo)) {
        return STATUS_FAILED;
    }

    return STATUS_OK;
}

static const OSSL_PARAM* _rsa_keymgmt_generate_settable_params(ossl_unused KEYISO_PROV_RSA_GEN_CTX *genCtx,ossl_unused KEYISO_PROV_PROVCTX *provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    static OSSL_PARAM settable[] = {
        OSSL_PARAM_uint32(OSSL_PKEY_PARAM_RSA_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),
        OSSL_PARAM_uint64(OSSL_PKEY_PARAM_RSA_E, NULL),
        OSSL_PARAM_END
    };

    return settable;
}

static const OSSL_PARAM* _rsapss_keymgmt_generate_settable_params(ossl_unused KEYISO_PROV_RSA_GEN_CTX *genctx, ossl_unused KEYISO_PROV_PROVCTX *provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    static OSSL_PARAM settable[] = {
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        // PSS gen info 
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST_PROPS, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MASKGENFUNC, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, NULL),
        OSSL_PARAM_END
    };

    return settable;
}

static KEYISO_PROV_RSA_GEN_CTX* _rsa_keymgmt_gen_init_common(KEYISO_PROV_PROVCTX* provCtx, int selection, const OSSL_PARAM params[], unsigned int padding)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    if (!(selection & OSSL_KEYMGMT_SELECT_KEYPAIR)) {
        return NULL;
    }

    KEYISO_PROV_RSA_GEN_CTX *genCtx = KeyIso_zalloc(sizeof(KEYISO_PROV_RSA_GEN_CTX));
    if (genCtx == NULL) {
        KMPPerr(KeyIsoErrReason_AllocFailure);
        return NULL;
    }

    // Construct KEYISO_PROV_PKEY and set private key handle
    KEYISO_PROV_PKEY *provKey = KeyIso_prov_rsa_keymgmt_new(provCtx, (padding == KMPP_RSA_PKCS1_PADDING)  ? EVP_PKEY_RSA  : EVP_PKEY_RSA_PSS);
    if (!provKey) {
        KMPPerr(KeyIsoErrReason_FailedToGetProvKey);
		KeyIso_free(genCtx);
        return NULL;
    }

    genCtx->nBitsOfModulus = KMPP_RSA_MIN_MODULUS_BITS;
    genCtx->nPubExp = 0;
    genCtx->provKey = provKey;
    genCtx->padding = padding;
    genCtx->pssInfo = NULL;

    if (!_rsa_keymgmt_generate_set_params(genCtx, params)) {
        KeyIso_free(provKey);
        _rsa_keymgmt_gen_cleanup(genCtx);
        genCtx = NULL;
    }

    return genCtx;
}

static KEYISO_PROV_RSA_GEN_CTX *_rsa_keymgmt_gen_init(KEYISO_PROV_PROVCTX* provCtx, int selection, const OSSL_PARAM params[])
{
    return _rsa_keymgmt_gen_init_common(provCtx, selection, params, KMPP_RSA_PKCS1_PADDING);
}

static KEYISO_PROV_RSA_GEN_CTX* _rsapss_keymgmt_gen_init(KEYISO_PROV_PROVCTX* provCtx, int selection, const OSSL_PARAM params[])
{
    return _rsa_keymgmt_gen_init_common(provCtx, selection, params, KMPP_RSA_PKCS1_PSS_PADDING);
}

static void* _cleanup_rsa_keymgmt_gen(int ret, KeyIsoErrReason reason, KEYISO_PROV_PKEY *provKey,X509_SIG *encryptedPkey, char *salt, 
    unsigned char *encryptedPfxBytes,ossl_unused const char* sha256HexHash, X509 *cert, CONF *generatedKeyConf)
{
    if (ret != STATUS_OK) {
        KEYISOP_trace_metric_error_para(NULL, 0, g_config.solutionType, KEYISOP_PROVIDER_TITLE, "", "RSA key pair generation failed.", "sha256:%s", sha256HexHash);
        KMPPerr(reason);
		
        if (encryptedPkey)
            X509_SIG_free(encryptedPkey); // should not be freed at success  
    }

    if (encryptedPfxBytes)
            KeyIso_free(encryptedPfxBytes);
    if (salt)
	    KeyIso_clear_free_string(salt);

    if(cert)
        X509_free(cert);

    if (generatedKeyConf)
        NCONF_free(generatedKeyConf);

    return provKey;
}

#define _CLEANUP_RSA_KEYMGMT_GEN(ret, reason) \
    _cleanup_rsa_keymgmt_gen(ret, reason, genCtx->provKey, encryptedPkey, salt, encryptedPfxBytes, sha256HexHash, cert, generatedKeyConf)

//Steps:
// 1. Generate RSA key pair
// 2. Construct keyId - maybe not necessary
// 3. Load key - Set the public key in the KEYISO_PROV_PKEY like in store
// 4. Return the KEYISO_PROV_PKEY
static KEYISO_PROV_PKEY* _rsa_keymgmt_gen(KEYISO_PROV_RSA_GEN_CTX* genCtx, ossl_unused OSSL_CALLBACK* osslcb, ossl_unused void* cbarg)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
 
    uuid_t correlationId;
    EVP_PKEY *pubKey = NULL;
    X509_SIG *encryptedPkey = NULL;
    char *salt = NULL;
    int encryptedPfxLength = 0;
    unsigned char *encryptedPfxBytes = NULL;  
    KEYISO_KEY_CTX *keyCtx = NULL;     // KeyIso_CLIENT_pfx_close()
    X509* cert = NULL;
    CONF* generatedKeyConf = NULL;
    char sha256HexHash[SHA256_DIGEST_LENGTH * 2 + 1] = "\0";
 
    KeyIso_rand_bytes(correlationId, sizeof(correlationId));
 
     // Validate input parameters
    if (genCtx == NULL || genCtx->provKey == NULL) {
         return _CLEANUP_RSA_KEYMGMT_GEN(STATUS_FAILED, KeyIsoErrReason_InvalidParams);
    }
 
     // Generate RSA key pair with the specified parameters
    int ret = KeyIso_CLIENT_generate_rsa_key_pair(correlationId, genCtx->nBitsOfModulus, 
         KMPP_KEY_USAGE_RSA_SIGN_ECDSA | KMPP_KEY_USAGE_RSA_ENCRYPT_ECDH, 
         genCtx->pubExp64, genCtx->nPubExp, &pubKey, &encryptedPkey, &salt);
         
    if (ret != STATUS_OK) {
         return _CLEANUP_RSA_KEYMGMT_GEN(STATUS_FAILED, KeyIsoErrReason_FailedToGenerateKey);
    }

    if (KeyIso_conf_get(&generatedKeyConf, NULL ,NULL) != STATUS_OK) {
        return _CLEANUP_RSA_KEYMGMT_GEN(STATUS_FAILED, KeyIsoErrReason_FailedToGetConf);
    }

    // Create X509 certificate to format keyId later
    if (KeyIso_CLIENT_create_X509_from_pubkey(correlationId, genCtx->provKey->keyType, pubKey, &cert, generatedKeyConf) != STATUS_OK) {
        return _CLEANUP_RSA_KEYMGMT_GEN(STATUS_FAILED, KeyIsoErrReason_FailedToCreateCert);
    }

    // Construct encryptedPfxBytes in PKCS#12 format
    if (KeyIso_create_encrypted_pfx_bytes(correlationId, encryptedPkey, cert, NULL, &encryptedPfxLength, &encryptedPfxBytes) != STATUS_OK) {
        return _CLEANUP_RSA_KEYMGMT_GEN(STATUS_FAILED, KeyIsoErrReason_FailedToCreatePfx);
    }

    if (KeyIso_CLIENT_private_key_open_from_pfx(correlationId, encryptedPfxLength, encryptedPfxBytes, salt, &keyCtx) != STATUS_OK) {
        return _CLEANUP_RSA_KEYMGMT_GEN(STATUS_FAILED, KeyIsoErrReason_FailedToGetKeyCtx);
    }
 
     genCtx->provKey->pubKey = pubKey;
     genCtx->provKey->keyCtx = keyCtx;
 
     // Telemetry - extract the hash value of the generated key's public part
     KeyIso_pkey_sha256_hex_hash(pubKey, sha256HexHash);
     KEYISOP_trace_metric_para(correlationId, 0, g_config.solutionType, KEYISOP_PROVIDER_TITLE, NULL,
                              "RSA key pair generation succeeded. sha256: %s.", sha256HexHash);
 
     return _CLEANUP_RSA_KEYMGMT_GEN(STATUS_OK, KeyIsoErrReason_NoError);
 }
 
 
 const OSSL_DISPATCH keyIso_prov_rsa_keymgmt_funcs[] = {
     { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))_prov_rsa_keymgmt_new },
     { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))KeyIso_rsa_keymgmt_free},
     { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))_keymgmt_load },
     { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))_keymgmt_has },
     { OSSL_FUNC_KEYMGMT_MATCH, (void(*)(void))_keymgmt_match },
     { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void(*)(void))_rsa_keymgmt_get_params },
     { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void(*)(void))_rsa_keymgmt_gettable_params },
     { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))_rsa_keymgmt_query },
     { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))_rsa_keymgmt_export_import_types }, 
     { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))_rsa_keymgmt_import },
     { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))_rsa_keymgmt_export_import_types },
     { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))_keymgmt_common_export },
     /* Gen functions */
     {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))_rsa_keymgmt_gen_init},
     { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))_rsa_keymgmt_gen },
     { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))_rsa_keymgmt_gen_cleanup },
     { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))_rsa_keymgmt_generate_set_params },
     { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))_rsa_keymgmt_generate_settable_params }, 
     { 0, NULL }
 };
 
 const OSSL_DISPATCH keyIso_prov_rsapss_keymgmt_funcs[] = {
     { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))_prov_rsapss_keymgmt_new },
     { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))KeyIso_rsa_keymgmt_free},
     { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))_keymgmt_load },
     { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))_keymgmt_has },
     { OSSL_FUNC_KEYMGMT_MATCH, (void(*)(void))_keymgmt_match },
     { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void(*)(void))_rsa_keymgmt_get_params },
     { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void(*)(void))_rsa_keymgmt_gettable_params },
     { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))_rsa_keymgmt_query },
     { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))_rsa_keymgmt_export_import_types }, 
     { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))_rsa_keymgmt_import },
     { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))_rsa_keymgmt_export_import_types },
     { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))_keymgmt_common_export },
     /* Gen functions */
     {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))_rsapss_keymgmt_gen_init},
     { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))_rsa_keymgmt_gen },
     { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))_rsa_keymgmt_gen_cleanup },
     { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))_rsa_keymgmt_generate_set_params },
     { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))_rsapss_keymgmt_generate_settable_params },
     { 0, NULL }
 };