/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include "keyisoclientinternal.h"
#include "keyisocommon.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "p_keyiso.h"
#include "p_keyiso_err.h"


KEYISO_PROV_RSA_CTX* KeyIso_prov_rsa_newctx(KEYISO_PROV_PKEY *provCtx, ossl_unused const char *propq)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    KEYISO_PROV_RSA_CTX *ctx = NULL;

    if (provCtx == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return NULL;
    }

    ctx = KeyIso_zalloc(sizeof(KEYISO_PROV_RSA_CTX));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->provKey = NULL;
    ctx->mdCtx = NULL;
    ctx->md = NULL;
    ctx->mdInfo = NULL;
    ctx->mgf1Md = NULL;
    ctx->mgf1mMdInfo = NULL;
    ctx->oaepLabel = NULL;

	// Default padding is aligned with Symcrypt and OSSL and will be set if needed
    ctx->padding = KEYISO_PROV_DEFAULT_PADDING;

    return ctx;
}

void KeyIso_prov_rsa_freectx(KEYISO_PROV_RSA_CTX *ctx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    if (ctx == NULL)
        return;

    if (ctx->mdCtx)
        EVP_MD_CTX_free(ctx->mdCtx);

    if (ctx->md)
        EVP_MD_free(ctx->md);

    if (ctx->mgf1Md)
        EVP_MD_free(ctx->mgf1Md);

    if (ctx->oaepLabel)
        KeyIso_free(ctx->oaepLabel);
    
    KeyIso_clear_free(ctx, sizeof(KEYISO_PROV_RSA_CTX));
}


// EVP_MD_CTX_dup is deprectead in OpenSSL 3.1 and higer
static EVP_MD_CTX *_dup_mdctx(const EVP_MD_CTX *in)
{
    EVP_MD_CTX *out = EVP_MD_CTX_new();

    if (out != NULL && !EVP_MD_CTX_copy_ex(out, in)) {
        EVP_MD_CTX_free(out);
        out = NULL;
    }
    return out;
}

KEYISO_PROV_RSA_CTX* KeyIso_prov_rsa_dupctx(KEYISO_PROV_RSA_CTX *ctx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    if (ctx == NULL)
        return NULL;

    KEYISO_PROV_RSA_CTX* dupCtx = KeyIso_zalloc(sizeof(KEYISO_PROV_RSA_CTX));
    if (dupCtx == NULL) {
        return NULL;
    }

    if (ctx->mdCtx) {
        dupCtx->mdCtx = _dup_mdctx(ctx->mdCtx);
    }

    if (ctx->md) {
        EVP_MD_up_ref(ctx->md);
        dupCtx->md = ctx->md;
    }

    if (ctx->mgf1Md) {
        EVP_MD_up_ref(ctx->mgf1Md);
        dupCtx->mgf1Md = ctx->mgf1Md;
    }

    if (ctx->oaepLabel) {
        dupCtx->oaepLabel = (unsigned char *)KeyIso_strndup((const char*)ctx->oaepLabel, ctx->oaepLabelLen);
    }

    dupCtx->provKey = ctx->provKey;
    dupCtx->provKey->pubKey = ctx->provKey->pubKey;
    dupCtx->padding = ctx->padding;
    dupCtx->saltLen = ctx->saltLen;
    dupCtx->operation = ctx->operation; 
    dupCtx->mdInfo = ctx->mdInfo;
    dupCtx->mgf1mMdInfo = ctx->mgf1mMdInfo;
    dupCtx->oaepLabelLen = ctx->oaepLabelLen;

    return dupCtx;
}


size_t KeyIso_get_bn_param_len(KEYISO_PROV_PKEY *provKey, const char *paramType, BIGNUM **outParam)
{
    size_t paramLen = 0;
    BIGNUM* param  = NULL;

    if (!provKey) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return paramLen;
    }

    // Get the BN param from EVP_PKEY
    if (!EVP_PKEY_get_bn_param(provKey->pubKey, paramType, &param)) {
        return paramLen;
    }

    // Get the length of the parameter
    paramLen = BN_num_bytes(param);

	// Return the parameter if requested
    if(outParam != NULL)
        *outParam = param;
    else
		BN_free(param);

    return paramLen;
}