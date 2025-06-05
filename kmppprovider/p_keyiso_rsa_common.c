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


KEYISO_PROV_RSA_CTX* KeyIso_prov_rsa_newctx(KEYISO_PROV_PKEY *provKey, ossl_unused const char *propq)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    KEYISO_PROV_RSA_CTX *ctx = NULL;
    KEYISO_PROV_RSA_MD_INFO_CTX *mdInfoCtx = NULL;

    if (provKey == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return NULL;
    }

    ctx = KeyIso_zalloc(sizeof(KEYISO_PROV_RSA_CTX));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->provKey = provKey;
    ctx->mdCtx = NULL;
    ctx->oaepLabel = NULL;

    mdInfoCtx = KeyIso_zalloc(sizeof(KEYISO_PROV_RSA_MD_INFO_CTX));
    if (mdInfoCtx == NULL) {
		KeyIso_free(ctx);
        return NULL;
    }

    mdInfoCtx->md = NULL;
    mdInfoCtx->mdInfo = NULL;
    mdInfoCtx->mgf1Md = NULL;
    mdInfoCtx->mgf1MdInfo = NULL;
    ctx->mdInfoCtx = mdInfoCtx;

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

    if (ctx->oaepLabel)
        KeyIso_free(ctx->oaepLabel); 

    if (ctx->mdInfoCtx) {
        if (ctx->mdInfoCtx->md)
            EVP_MD_free(ctx->mdInfoCtx->md);

        if (ctx->mdInfoCtx->mgf1Md)
            EVP_MD_free(ctx->mdInfoCtx->mgf1Md);

        KeyIso_free(ctx->mdInfoCtx);
    }
       
    KeyIso_clear_free(ctx, sizeof(KEYISO_PROV_RSA_CTX));
}


// EVP_MD_CTX_dup is deprecated in OpenSSL 3.1 and higher
static EVP_MD_CTX *_dup_mdctx(const EVP_MD_CTX *in)
{
    EVP_MD_CTX *out = EVP_MD_CTX_new();

    if (out != NULL && !EVP_MD_CTX_copy_ex(out, in)) {
        EVP_MD_CTX_free(out);
        out = NULL;
    }
    return out;
}

static KEYISO_PROV_RSA_MD_INFO_CTX *_dup_md_info_ctx(const KEYISO_PROV_RSA_MD_INFO_CTX *in)
{
    KEYISO_PROV_RSA_MD_INFO_CTX *out = KeyIso_zalloc(sizeof(KEYISO_PROV_RSA_MD_INFO_CTX));
    if (out == NULL) { 
        return NULL;
    }

    if (in->md) {
        EVP_MD_up_ref(in->md);
        out->md = in->md;
    }

    if (in->mgf1Md) {
        EVP_MD_up_ref(in->mgf1Md);
        out->mgf1Md = in->mgf1Md;
    }

    out->saltLen = in->saltLen;
    out->mdInfo = in->mdInfo;
    out->mgf1MdInfo = in->mgf1MdInfo;

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

    if (ctx->mdInfoCtx) {
        if ((dupCtx->mdInfoCtx = _dup_md_info_ctx(ctx->mdInfoCtx)) == NULL) {
			KeyIso_free(dupCtx);
            return NULL;
        }    
    }

    if (ctx->oaepLabel) {
        dupCtx->oaepLabel = (unsigned char *)KeyIso_strndup((const char*)ctx->oaepLabel, ctx->oaepLabelLen);
    }

    dupCtx->provKey = ctx->provKey;
	if (ctx->provKey) {
	    dupCtx->provKey->pubKey = ctx->provKey->pubKey;
	}
    dupCtx->padding = ctx->padding;
    dupCtx->operation = ctx->operation; 
    dupCtx->oaepLabelLen = ctx->oaepLabelLen;

    return dupCtx;
}