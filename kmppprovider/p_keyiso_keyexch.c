/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <string.h>

#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "keyisocommon.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisoclientinternal.h"
#include "keyisotelemetry.h"
#include "p_keyiso.h"
#include "p_keyiso_err.h"


typedef struct KeyIso_prov_keyexch_ctx_st KEYISO_PROV_KEYEXCH_CTX;
struct KeyIso_prov_keyexch_ctx_st {
    KEYISO_PROV_PROVCTX *provCtx;
    EVP_PKEY    *pkey;       // Our key. Should include private key.
    EVP_PKEY    *pkeyPeer;   // Peer key. Should include public key.
};

static KEYISO_PROV_KEYEXCH_CTX* _keyexch_newctx(KEYISO_PROV_PROVCTX* provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    
    KEYISO_PROV_KEYEXCH_CTX* ctx = KeyIso_zalloc(sizeof(KEYISO_PROV_KEYEXCH_CTX));
    if (ctx == NULL) {
        KMPPerr(KeyIsoErrReason_AllocFailure);
        return NULL;
    }

    ctx->provCtx = provCtx;
    return ctx;
}

static void _keyexch_freectx(KEYISO_PROV_KEYEXCH_CTX* ctx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    
    if (ctx == NULL)
        return;

    KeyIso_free(ctx);
}

static int _keyexch_init(KEYISO_PROV_KEYEXCH_CTX* ctx, KEYISO_PROV_PKEY* provKey, ossl_unused const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    
    if (ctx == NULL || provKey == NULL || provKey->pubKey == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    ctx->pkey = provKey->pubKey;
    return STATUS_OK;
}

static int _keyexch_set_peer(KEYISO_PROV_KEYEXCH_CTX* ctx, KEYISO_PROV_PKEY* provPeerKey)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    
    if (ctx == NULL || provPeerKey == NULL || provPeerKey->pubKey == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    ctx->pkeyPeer = provPeerKey->pubKey;
    EVP_PKEY_up_ref(ctx->pkeyPeer); // Increase reference count for the peer key

    return STATUS_OK;
}

static int _keyexch_set_ctx_params(ossl_unused KEYISO_PROV_KEYEXCH_CTX* ctx, const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    
    if (params != NULL) {
        KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "KEYEXCH SET_CTX_PARAMS");
    }

    return STATUS_OK;
}

static const OSSL_PARAM* _keyexch_settable_ctx_params(ossl_unused void* ctx, ossl_unused void* provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_END
    };

    return settable;
}

/**
 * _keyexch_derive - Derives a shared secret using the KMPP key exchange context.
 * This function delegates ECDH operations to OpenSSL's default provider to ensure
 * compatibility with KMPP-managed private keys.
 * 
 * Note: If we implement default provider for ECC in the future,
 * this function should be updated to route the operation through the KMPP service
 * instead of delegating to OpenSSL.
 */
static int _cleanup_keyexch_derive(int ret, KeyIsoErrReason reason, EVP_PKEY_CTX* derivationCtx)
{
    if (ret != STATUS_OK) {
        KMPPerr(reason);
    }

    if (derivationCtx != NULL) {
        EVP_PKEY_CTX_free(derivationCtx);
    }

    return ret;
}

#define _CLEANUP_KEYEXCH_DERIVE(ret, reason) \
        _cleanup_keyexch_derive(ret, reason, derivationCtx)

static int _keyexch_derive(KEYISO_PROV_KEYEXCH_CTX* ctx, unsigned char *secret, size_t *secretLen, ossl_unused size_t outLen)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    
    EVP_PKEY_CTX *derivationCtx = NULL;
    
    if (ctx == NULL || ctx->pkey == NULL || ctx->pkeyPeer == NULL || secretLen == NULL) {
        return _CLEANUP_KEYEXCH_DERIVE(STATUS_FAILED, KeyIsoErrReason_InvalidParams);
    }

    if ((derivationCtx = EVP_PKEY_CTX_new_from_pkey(NULL, ctx->pkey, KEYISO_OSSL_DEFAULT_PROV_PROPQ)) == NULL) {
        return _CLEANUP_KEYEXCH_DERIVE(STATUS_FAILED, KeyIsoErrReason_FailedToDeriveInit);
    }

    if (EVP_PKEY_derive_init(derivationCtx) <= 0) {
        return _CLEANUP_KEYEXCH_DERIVE(STATUS_FAILED, KeyIsoErrReason_FailedToDeriveInit);
    }

    if (EVP_PKEY_derive_set_peer(derivationCtx, ctx->pkeyPeer) <= 0) {
        return _CLEANUP_KEYEXCH_DERIVE(STATUS_FAILED, KeyIsoErrReason_FailedToSetDerivedKeyPeer);
    }

    if (EVP_PKEY_derive(derivationCtx, secret, secretLen) <= 0) {
        return _CLEANUP_KEYEXCH_DERIVE(STATUS_FAILED, KeyIsoErrReason_FailedToDeriveKey);
    }

    return _CLEANUP_KEYEXCH_DERIVE(STATUS_OK, KeyIsoErrReason_NoError);
}

const OSSL_DISPATCH keyIso_prov_ecdh_keyexch_funcs[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void(*)(void))_keyexch_newctx },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void(*)(void))_keyexch_freectx },
    { OSSL_FUNC_KEYEXCH_INIT, (void(*)(void))_keyexch_init },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void(*)(void))_keyexch_set_peer },
    { OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void(*)(void))_keyexch_set_ctx_params },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void(*)(void))_keyexch_settable_ctx_params },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void(*)(void))_keyexch_derive },
    { 0, NULL }
};