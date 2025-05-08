/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <string.h>

#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

#include "keyisocommon.h"
#include "keyisoclientinternal.h"
#include "keyisopfxclientinternal.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisotelemetry.h"
#include "p_keyiso.h"
#include "p_keyiso_err.h"


static OSSL_ITEM paddingItem[] = {
    { KMPP_RSA_PKCS1_PADDING,        OSSL_PKEY_RSA_PAD_MODE_PKCSV15 },
    { KMPP_RSA_NO_PADDING,           OSSL_PKEY_RSA_PAD_MODE_NONE },
    { KMPP_RSA_PKCS1_OAEP_PADDING,   OSSL_PKEY_RSA_PAD_MODE_OAEP },
    { 0,                             NULL     }
};

static const OSSL_PARAM* _rsa_cipher_settable_ctx_params(ossl_unused  KEYISO_PROV_RSA_CTX *ctx, ossl_unused KEYISO_PROV_PROVCTX *provCtx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

static int _rsa_cipher_set_ctx_params(KEYISO_PROV_RSA_CTX *ctx, const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    const OSSL_PARAM *p;
	KEYISO_PROV_RSA_MD_INFO_CTX *mdInfoTmp = NULL;

    if (params == NULL)
        return STATUS_OK;

    if (ctx == NULL || ctx->provKey == NULL || ctx->provKey->provCtx == NULL || ctx->mdInfoCtx == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    mdInfoTmp = ctx->mdInfoCtx;

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL) {
        int padMode = 0;
        // Padding mode may be retrieved as integer or string
        switch (p->data_type) {
            case OSSL_PARAM_INTEGER:       
                if (!OSSL_PARAM_get_int(p, &padMode))
                    return STATUS_FAILED;
            break;
            case OSSL_PARAM_UTF8_STRING:    
            {
                if (p->data == NULL)
                    return STATUS_FAILED;

                for (int i = 0; paddingItem[i].id != 0; i++) {
                    if (strcmp(p->data, paddingItem[i].ptr) == 0) {
                        padMode = paddingItem[i].id;
                        break;
                    }
                }
            }
            break;
            default:
                return STATUS_FAILED;
        }

        //  KMPP_RSA_PKCS1_OAEP_PADDING requires MD, set default if ctx->md not populated
        if (padMode == KMPP_RSA_PKCS1_OAEP_PADDING && mdInfoTmp->md == NULL) {
            if (KeyIso_prov_set_md_from_mdname(NULL, NULL, KEYISO_PROV_DEFAULT_OAEP_DIGEST, NULL, &mdInfoTmp->md, &mdInfoTmp->mdInfo) == STATUS_FAILED) {
                KMPPerr(KeyIsoErrReason_InvalidMsgDigest);
                return STATUS_FAILED;
            }
        }
        ctx->padding = padMode;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
    if (p != NULL) {

        if (KeyIso_prov_set_md_from_mdname(NULL, p, NULL, NULL, &mdInfoTmp->md, &mdInfoTmp->mdInfo) == STATUS_FAILED) {
            KMPPerr(KeyIsoErrReason_FailedToSetParams);
            return STATUS_FAILED;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
    if (p != NULL) {
        if (KeyIso_prov_set_md_from_mdname(NULL, p, NULL, NULL, &mdInfoTmp->mgf1Md, &mdInfoTmp->mgf1MdInfo) == STATUS_FAILED) {
            KMPPerr(KeyIsoErrReason_FailedToSetParams);
            return STATUS_FAILED;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
    if (p != NULL) {
        void* tmpLabel = NULL;
        size_t tmpLabellen;

        if (!OSSL_PARAM_get_octet_string(p, &tmpLabel, 0, &tmpLabellen)) {
            KMPPerr(KeyIsoErrReason_FailedToGetParams);
            return STATUS_FAILED;
        }
        KeyIso_free(ctx->oaepLabel);
        ctx->oaepLabel = (unsigned char*)tmpLabel;
        ctx->oaepLabelLen = tmpLabellen;
    }

    return STATUS_OK;
}


static int _rsa_cipher_init(KEYISO_PROV_RSA_CTX *ctx, KEYISO_PROV_PKEY *provKey, const OSSL_PARAM params[], int operation)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    if (!ctx || !provKey || !provKey->keyCtx) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    ctx->provKey = provKey;
    ctx->operation = operation;
    ctx->padding = KMPP_RSA_PKCS1_PADDING;

    return _rsa_cipher_set_ctx_params(ctx, params);
}

static int _rsa_cipher_encrypt_init(KEYISO_PROV_RSA_CTX *ctx, KEYISO_PROV_PKEY *provKey, const OSSL_PARAM params[])
{
	KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

	return _rsa_cipher_init(ctx, provKey, params, EVP_PKEY_OP_ENCRYPT);
}

static int _rsa_cipher_decrypt_init(KEYISO_PROV_RSA_CTX *ctx, KEYISO_PROV_PKEY *provKey, const OSSL_PARAM params[])
{
	KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

	return _rsa_cipher_init(ctx, provKey, params, EVP_PKEY_OP_DECRYPT);
}

static int _rsa_cipher_decrypt(KEYISO_PROV_RSA_CTX *ctx, unsigned char *out, size_t *outLen,
    ossl_unused size_t outSize, const unsigned char *in, size_t inLen)
{
	KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    int resultLen;
    int ret = STATUS_FAILED;
   
    // Start measuring time for metrics
    START_MEASURE_TIME();

    if (!ctx || !ctx->provKey || !ctx->provKey->keyCtx || !ctx->provKey->pubKey) {
		KMPPerr(KeyIsoErrReason_InvalidParams);
		return ret;
    }
       
	// First call with NULL buffer is to determine the required buffer size
    if (out == NULL) {
        *outLen = (int32_t)KeyIso_get_bn_param_len(ctx->provKey->pubKey, OSSL_PKEY_PARAM_RSA_N, NULL);
        return STATUS_OK;
    }

    // Return value is the actual len    
    resultLen = KeyIso_CLIENT_rsa_private_decrypt(ctx->provKey->keyCtx, inLen, in, *outLen, out, ctx->padding);
    ret = resultLen <= INT_MAX;
    *outLen = ret ? (size_t)resultLen : STATUS_FAILED;

	STOP_MEASURE_TIME(KeyisoKeyOperation_RsaPrivDec);

#ifdef KEYS_IN_USE_AVAILABLE    
    //KeyInUseToDo: p_scossl_keysinuse_on_decrypt(ctx->provKey->keysInUseCtx);    
#endif
    
    return ret;
}

const OSSL_DISPATCH keyIso_prov_rsa_cipher_funcs[] = {
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))KeyIso_prov_rsa_newctx },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))KeyIso_prov_rsa_freectx },
    { OSSL_FUNC_ASYM_CIPHER_DUPCTX, (void (*)(void))KeyIso_prov_rsa_dupctx },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, (void (*)(void))_rsa_cipher_encrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))KeyIso_rsa_cipher_encrypt },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void))_rsa_cipher_decrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))_rsa_cipher_decrypt },
    { OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS, (void (*)(void))_rsa_cipher_set_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))_rsa_cipher_settable_ctx_params },
    { 0, NULL }
};
