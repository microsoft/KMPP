/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/provider.h>

#include "keyisocertinternal.h"
#include "keyisoclient.h"
#include "keyisoclientprov.h"
#include "keyisoclientinternal.h"
#include "keyisoclientprovinternal.h"
#include "keyisocommon.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisopfxclientinternal.h"
#include "p_keyiso.h"
#include "p_keyiso_err.h"


static KEYISO_PROV_STORE_CTX* _store_new_ctx(const char *uri, KEYISO_PROV_PROVCTX *provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    KEYISO_PROV_STORE_CTX *storeCtx = NULL;

    if (!provCtx) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return storeCtx;
    }

    if (!uri) {
        KMPPerr(KeyIsoErrReason_FailedToGetUri);
        return storeCtx;
    }

    if (strncmp(uri, KEYISO_PROV_STORE_SCHEME, sizeof(KEYISO_PROV_STORE_SCHEME) - 1) != 0) {
        // Not our store. Not an Error, just exit.
        KEYISOP_trace_log_error(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_PROVIDER_TITLE, "Not our store", "");
        return storeCtx;
    }

    storeCtx = KeyIso_zalloc(sizeof(*storeCtx));
    if (!storeCtx) {
        return storeCtx;
    }

    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "STORE", "uri: %s", uri);
    storeCtx->keyId = KeyIso_strndup(uri + sizeof(KEYISO_PROV_STORE_SCHEME), KEYISO_MAX_KEY_ID_LEN);
    storeCtx->provCtx = provCtx;
    storeCtx->status = KeyisoProvStoreStatus_unloaded;
 
    return storeCtx;
}

static KEYISO_PROV_STORE_CTX* _rsa_store_open(KEYISO_PROV_PROVCTX *provCtx, const char *uri)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    return _store_new_ctx(uri, provCtx);
}

static const OSSL_PARAM *_rsa_store_settable_ctx_params(ossl_unused void *provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static int _rsa_store_set_ctx_params(ossl_unused KEYISO_PROV_STORE_CTX *ctx, ossl_unused  const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    return STATUS_OK;
}

static int _cleanup_rsa_store_load(int ret, KeyIsoErrReason reason, X509 *pCert, STACK_OF(X509) *ca, 
    KEYISO_PROV_PKEY *provKey, char *salt, unsigned char *pfxBytes) 
{
    if (ret != STATUS_OK) {
        KMPPerr(reason);
        KeyIso_rsa_keymgmt_free(provKey);
    }

    if (pCert)
        X509_free(pCert);

    sk_X509_pop_free(ca, X509_free);
    KeyIso_clear_free_string(salt);
    KeyIso_free(pfxBytes);
    return ret;
}

#define _CLEANUP_RSA_STORE_LOAD(ret, reason) \
        _cleanup_rsa_store_load(ret, reason, pCert, ca, provKey, salt, pfxBytes)

static int _rsa_store_load(KEYISO_PROV_STORE_CTX *storeCtx, OSSL_CALLBACK *object_cb, void *object_cbarg, 
    ossl_unused OSSL_PASSPHRASE_CALLBACK *pw_cb, ossl_unused void* pw_cbarg)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    int ret = 0;
    uuid_t correlationId;
    KEYISO_KEY_CTX *keyCtx = NULL;     // KeyIso_CLIENT_pfx_close()
    int pfxLength = 0;
    unsigned char *pfxBytes = NULL;     // KeyIso_free()
    char *salt = NULL;                  // KeyIso_clear_free_string()
    KEYISO_PROV_PKEY *provKey = NULL;
    EVP_PKEY *pKey = NULL;
    X509 *pCert = NULL;
    STACK_OF(X509) *ca = NULL;

    KeyIso_rand_bytes(correlationId, sizeof(correlationId));

    if (!storeCtx) {
        return _CLEANUP_RSA_STORE_LOAD(STATUS_FAILED, KeyIsoErrReason_InvalidStoreCtx);
    }

    // Status will be changed to success at the end.
    storeCtx->status = KeyisoProvStoreStatus_failed;   

    if (!KeyIso_parse_pfx_provider_key_id(correlationId, storeCtx->keyId, &pfxLength, &pfxBytes, &salt)) {
        return _CLEANUP_RSA_STORE_LOAD(STATUS_FAILED, KeyIsoErrReason_FailedToGetKeyBytes);
    }

    if (!KeyIso_load_pfx_pubkey(correlationId, pfxLength, pfxBytes, &pKey, &pCert, &ca)) {
        return _CLEANUP_RSA_STORE_LOAD(STATUS_FAILED, KeyIsoErrReason_FailedToGetPubkey); 
    }

    if (!KeyIso_CLIENT_private_key_open_from_pfx(correlationId, pfxLength, pfxBytes, salt, &keyCtx)) {
        return _CLEANUP_RSA_STORE_LOAD(STATUS_FAILED, KeyIsoErrReason_FailedToGetKeyCtx); 
    }

    // Construct KEYISO_PROV_PKEY and set private key handle
    provKey = KeyIso_prov_rsa_keymgmt_new(storeCtx->provCtx);
    if (!provKey) {
        return _CLEANUP_RSA_STORE_LOAD(STATUS_FAILED, KeyIsoErrReason_FailedToGetProvKey);
    }
    // Store keyCtx and provCtx in KEYISO_PROV_PKEY 
    provKey->provCtx = storeCtx->provCtx;
    provKey->keyCtx = keyCtx;
	provKey->pubKey = pKey;

    OSSL_PARAM paramsPkey[4];
    int object_type = OSSL_OBJECT_PKEY;
    paramsPkey[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    paramsPkey[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (EVP_PKEY_is_a(pKey, KEYISO_NAME_RSA) || EVP_PKEY_is_a(pKey, KEYISO_NAME_RSA_PSS)) ? KEYISO_NAME_RSA : KEYISO_NAME_EC, 0);
    paramsPkey[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &provKey, sizeof(provKey));
    paramsPkey[3] = OSSL_PARAM_construct_end();
    ret = object_cb(paramsPkey, object_cbarg);
 
    if(ret)
        storeCtx->status = KeyisoProvStoreStatus_success;

    KeyIsoErrReason errReason = (ret) ? KeyIsoErrReason_NoError : KeyIsoErrReason_OperationFailed;
    return _CLEANUP_RSA_STORE_LOAD(ret, errReason); 
}

// Checks if the end of the RSA store context is reached
static int _rsa_store_eof(KEYISO_PROV_STORE_CTX *ctx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    int isEofReached = 1;

    if (!ctx) {
        KMPPerr(KeyIsoErrReason_InvalidStoreCtx);
        return isEofReached;
    }

    // In failure we still may retrieve some data, keep going
    if (ctx->status != KeyisoProvStoreStatus_failed)
        isEofReached = 0;    

    return isEofReached;
}

static int _rsa_store_close(KEYISO_PROV_STORE_CTX *storeCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    if (storeCtx == NULL) {
        return STATUS_OK;
    }
    
    KeyIso_clear_free_string(storeCtx->keyId);
    KeyIso_clear_free(storeCtx, sizeof(KEYISO_PROV_STORE_CTX));

    return STATUS_OK;
}

const OSSL_DISPATCH keyIso_prov_rsa_store_funcs[] = {
    { OSSL_FUNC_STORE_OPEN, (void (*)(void))_rsa_store_open },
    { OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS, (void (*)(void))_rsa_store_settable_ctx_params },
    { OSSL_FUNC_STORE_SET_CTX_PARAMS, (void (*)(void))_rsa_store_set_ctx_params },
    { OSSL_FUNC_STORE_LOAD, (void (*)(void))_rsa_store_load },
    { OSSL_FUNC_STORE_EOF, (void (*)(void))_rsa_store_eof },
    { OSSL_FUNC_STORE_CLOSE, (void (*)(void))_rsa_store_close },
    { 0, NULL }
};

