/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <string.h>

#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/ec.h>

#include "keyisocommon.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisoclientinternal.h"
#include "keyisopfxclientinternal.h"
#include "keyisotelemetry.h"
#include "p_keyiso.h"
#include "p_keyiso_err.h"


static KEYISO_PROV_ECDSA_CTX* _prov_ecdsa_newctx(KEYISO_PROV_PKEY *provKey, ossl_unused const char *propq)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    KEYISO_PROV_ECDSA_CTX *ctx = NULL;

    if ((ctx = KeyIso_zalloc(sizeof(KEYISO_PROV_ECDSA_CTX))) == NULL) {
        return NULL;
    }

    ctx->provKey = provKey;
    return ctx;
}

static void _prov_ecdsa_freectx(KEYISO_PROV_ECDSA_CTX *ctx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    if (ctx == NULL)
        return;

    if (ctx->mdCtx != NULL) {
        EVP_MD_CTX_free(ctx->mdCtx);
        ctx->mdCtx = NULL;
    }

    if (ctx->md != NULL) {
        EVP_MD_free(ctx->md);
        ctx->md = NULL;
    }

    KeyIso_free(ctx);
}

static KEYISO_PROV_ECDSA_CTX* _prov_ecdsa_dupctx(KEYISO_PROV_ECDSA_CTX *ctx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    KEYISO_PROV_ECDSA_CTX *newCtx = NULL;
    if (ctx == NULL) {
        return NULL;
    }

    if ((newCtx = KeyIso_zalloc(sizeof(KEYISO_PROV_ECDSA_CTX))) == NULL) {
        return NULL;
    }

    newCtx->operation = ctx->operation;
    newCtx->provKey = ctx->provKey;
    newCtx->mdSize = ctx->mdSize;

    if (ctx->md != NULL) {
        newCtx->md = ctx->md;
        EVP_MD_up_ref(newCtx->md);
    }
    newCtx->mdInfo = ctx->mdInfo;

    if (ctx->mdCtx != NULL) {
        if ((newCtx->mdCtx = EVP_MD_CTX_new()) == NULL) {
            _prov_ecdsa_freectx(newCtx);
            return NULL;
        }
        if (!EVP_MD_CTX_copy(newCtx->mdCtx, ctx->mdCtx)) {
            _prov_ecdsa_freectx(newCtx);
            return NULL;
        }
    }

    return newCtx;
}

static const OSSL_PARAM *_ecdsa_signature_gettable_ctx_params(ossl_unused KEYISO_PROV_ECDSA_CTX *ctx, ossl_unused void *provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
        OSSL_PARAM_END
    };

    return gettable;
}

static int _get_nid_from_id(int id)
{
    int algNid = NID_undef;
    switch (id) {
        case NID_sha1:
            algNid = NID_ecdsa_with_SHA1;
            break;
        case NID_sha224:
            algNid = NID_ecdsa_with_SHA224;
            break;
        case NID_sha256:
            algNid = NID_ecdsa_with_SHA256;
            break;
        case NID_sha384:
            algNid = NID_ecdsa_with_SHA384;
            break;
        case NID_sha512:
            algNid = NID_ecdsa_with_SHA512;
            break;
        case NID_sha3_224:
            algNid = NID_ecdsa_with_SHA3_224;
            break;
        case NID_sha3_256:
            algNid = NID_ecdsa_with_SHA3_256;
            break;
        case NID_sha3_384:
            algNid = NID_ecdsa_with_SHA3_384;
            break;
        case NID_sha3_512:
            algNid = NID_ecdsa_with_SHA3_512;
            break;
        default:
            KMPPerr(KeyIsoErrReason_UnsupportedAlgorithm);
    }
    return algNid;
}

static int _ecdsa_locate_algorithm_id(OSSL_PARAM *p, const OSSL_ITEM *mdInfo)
{
    int cbAid = -1;
    int algNid = NID_undef;
    int ret = STATUS_OK;

    p->return_size = 0;

    if (p->data_type != OSSL_PARAM_OCTET_STRING) {
        KMPPerr(KeyIsoErrReason_UnsupportedDataType);
        return STATUS_FAILED;
    }

    if (mdInfo == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    X509_ALGOR *x509Alg = X509_ALGOR_new();
    if (x509Alg == NULL) {
        return STATUS_FAILED;
    }

    if ((algNid = _get_nid_from_id(mdInfo->id)) == NID_undef || 
        !X509_ALGOR_set0(x509Alg, OBJ_nid2obj(algNid), V_ASN1_NULL, NULL) ||
        (cbAid = i2d_X509_ALGOR(x509Alg, (unsigned char**)&p->data)) < 0) {
        KMPPerr(KeyIsoErrReason_FailedToSetParams);
        ret = STATUS_FAILED;
    }

    if (ret == STATUS_OK) {
        p->return_size = (size_t)cbAid;
    }
    
    X509_ALGOR_free(x509Alg);

    return ret;
}

static int _ecdsa_signature_get_ctx_params(KEYISO_PROV_ECDSA_CTX *ctx, OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    OSSL_PARAM *p;

    if (ctx == NULL || ctx->provKey == NULL || params == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->mdInfo == NULL ? "" : ctx->mdInfo->ptr)) {
        KMPPerr(KeyIsoErrReason_FailedToGetParams);
        return STATUS_FAILED;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->mdInfo == NULL ? 0 : ctx->mdSize)) {
        KMPPerr(KeyIsoErrReason_FailedToGetParams);
        return STATUS_FAILED;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL && _ecdsa_locate_algorithm_id(p, ctx->mdInfo) != STATUS_OK) {
        KMPPerr(KeyIsoErrReason_FailedToGetParams);
        return STATUS_FAILED;
    }

    return STATUS_OK;
}

static const OSSL_PARAM *_ecdsa_signature_settable_ctx_params(ossl_unused KEYISO_PROV_ECDSA_CTX *ctx, ossl_unused void *provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
        OSSL_PARAM_END
    };

    return settable;
}

static int _ecdsa_signature_set_ctx_params(KEYISO_PROV_ECDSA_CTX *ctx, const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    const OSSL_PARAM *p;

    if (params == NULL)
        return STATUS_OK;

    if (ctx == NULL || ctx->provKey == NULL || ctx->provKey->provCtx == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL) {
            if (KeyIso_prov_set_md_from_mdname(NULL, p, NULL, NULL, &ctx->md, &ctx->mdInfo) == STATUS_FAILED) {
            KMPPerr(KeyIsoErrReason_InvalidMsgDigest);
            return STATUS_FAILED;
        }
        ctx->mdSize = EVP_MD_get_size(ctx->md);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &ctx->mdSize)) {
            KMPPerr(KeyIsoErrReason_FailedToGetParams);
            return STATUS_FAILED;
        }
    }

    return STATUS_OK;
}

static int _ecdsa_signature_signverify_init(KEYISO_PROV_ECDSA_CTX *ctx, KEYISO_PROV_PKEY *provKey, const OSSL_PARAM params[], int operation)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    if (ctx == NULL || provKey == NULL || provKey->provCtx == NULL) {
        return STATUS_FAILED;
    }

    ctx->provKey = provKey;
    ctx->operation = operation;

    // Set default md as openssl
    if (ctx->md == NULL) {
        if (KeyIso_prov_set_md_from_mdname(NULL, NULL, KEYISO_PROV_DEFAULT_MD, NULL, &ctx->md, &ctx->mdInfo) == STATUS_FAILED) {
            KMPPerr(KeyIsoErrReason_InvalidMsgDigest);
            return STATUS_FAILED;
        }
    }

    return _ecdsa_signature_set_ctx_params(ctx, params);
}

static int _ecdsa_signature_sign_init(KEYISO_PROV_ECDSA_CTX *ctx, KEYISO_PROV_PKEY *provKey, const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    return _ecdsa_signature_signverify_init(ctx, provKey, params, EVP_PKEY_OP_SIGN);
}

static int _ecdsa_signature_verify_init(KEYISO_PROV_ECDSA_CTX *ctx, KEYISO_PROV_PKEY *provKey, const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    return _ecdsa_signature_signverify_init(ctx, provKey, params, EVP_PKEY_OP_VERIFY);
}

static int _get_ecdsa_curve_nid_from_pkey(EVP_PKEY *pkey)
{
    char curveName[64] = {0};
    size_t curveNameLen = 0;
    int curveNid = NID_undef;

    if (pkey == NULL) {
        return NID_undef;
    }

    // Get curve name from the public key
    if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, curveName, sizeof(curveName), &curveNameLen)) {
        KMPPerr(KeyIsoErrReason_FailedToGetParams);
        return NID_undef;
    }

    // Convert curve name to NID
    curveNid = EC_curve_nist2nid(curveName);
    if (curveNid == NID_undef) {
        curveNid = OBJ_sn2nid(curveName);
    }
    
    if (curveNid == NID_undef) {
        KMPPerr(KeyIsoErrReason_UnsupportedCurve);
    }

    return curveNid;
}

static size_t _get_ecdsa_size(EVP_PKEY *pkey)
{
    int curveNid = _get_ecdsa_curve_nid_from_pkey(pkey);
    if (curveNid == NID_undef) {
        KEYISOP_trace_log_error_para(NULL, 0, NULL, "KeyIso_get_ec_symcrypt_pkey ERROR", "Unsupported curve", "received curve: %d", curveNid);
        return 0;
	}

    // Get the Symcrypt curve from the NID
	return KeyIso_get_ec_pkey_size(curveNid);
}

static int _ecdsa_signature_sign(KEYISO_PROV_ECDSA_CTX *ctx, unsigned char *sig, size_t *sigLen,
    size_t sigSize, const unsigned char *tbs, size_t tbsLen)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    // Start measuring time for metrics
    START_MEASURE_TIME();

    if (ctx == NULL || ctx->provKey == NULL || ctx->provKey->keyCtx == NULL || ctx->provKey->pubKey == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    size_t ecdsaSize = _get_ecdsa_size(ctx->provKey->pubKey);
    // First call with NULL buffer is to determine the required buffer size
    if (sig == NULL) {
        *sigLen = ecdsaSize;
        return STATUS_OK;
    }

    // We get here only when sig is not NULL
    if (sigSize < ecdsaSize) {
        KMPPerr(KeyIsoErrReason_InvalidSignatureLength);
        return STATUS_FAILED;
    }

    if (ctx->mdSize != 0 && tbsLen != ctx->mdSize) {
        KMPPerr(KeyIsoErrReason_InvalidMsgDigest);
        return STATUS_FAILED;
    }

    if (tbs == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    // Sending to service side
    int ret = KeyIso_CLIENT_ecdsa_sign(ctx->provKey->keyCtx, 0, tbs, tbsLen, sig, (unsigned int)sigSize, (unsigned int *)sigLen);
    if (ret <= 0) {
        KMPPerr(KeyIsoErrReason_OperationFailed);
        return STATUS_FAILED;
    }

    STOP_MEASURE_TIME(KeyisoKeyOperation_EcdsaSign);

    return ret;
}

static int _ecdsa_signature_verify(KEYISO_PROV_ECDSA_CTX *ctx, const unsigned char *sig, size_t sigLen,
    const unsigned char *tbs, size_t tbsLen)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    if (!ctx || !ctx->provKey || !ctx->provKey->pubKey) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    int curveNid = _get_ecdsa_curve_nid_from_pkey(ctx->provKey->pubKey);
    if (curveNid == NID_undef) {
        return STATUS_FAILED; // _get_ecdsa_curve_nid_from_pkey already logs the error
    }

    return KeyIso_ecdsa_signature_verify(ctx, curveNid, sig, sigLen, tbs, tbsLen);
}

static int _ecdsa_signature_digest_signverify_init(KEYISO_PROV_ECDSA_CTX *ctx, const char *mdName,
    KEYISO_PROV_PKEY *provKey, const OSSL_PARAM params[], int operation)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    if (!_ecdsa_signature_signverify_init(ctx, provKey, params, operation)) {
        return STATUS_FAILED;
    }

    // Set MD into context
    if (!mdName || (KeyIso_prov_set_md_from_mdname(NULL, NULL, mdName, NULL, &ctx->md, &ctx->mdInfo) == STATUS_FAILED)) {
        KMPPerr(KeyIsoErrReason_InvalidMsgDigest);
        return STATUS_FAILED;
    }

    // Allocate new MD context
    if (ctx->mdCtx == NULL && ((ctx->mdCtx = EVP_MD_CTX_new()) == NULL)) {
        return STATUS_FAILED;
    }

    if (!EVP_DigestInit_ex2(ctx->mdCtx, ctx->md, params)) {
        EVP_MD_CTX_free(ctx->mdCtx);
        ctx->mdCtx = NULL;
        return STATUS_FAILED;
    }

    return STATUS_OK;
}

static int _ecdsa_signature_digest_sign_init(KEYISO_PROV_ECDSA_CTX *ctx, const char *mdname, KEYISO_PROV_PKEY *provKey, const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    return _ecdsa_signature_digest_signverify_init(ctx, mdname, provKey, params, EVP_PKEY_OP_SIGN);
}

static int _ecdsa_signature_digest_verify_init(KEYISO_PROV_ECDSA_CTX *ctx, const char *mdname, KEYISO_PROV_PKEY *provKey, const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    return _ecdsa_signature_digest_signverify_init(ctx, mdname, provKey, params, EVP_PKEY_OP_VERIFY);
}

static int _ecdsa_signature_digest_signverify_update(KEYISO_PROV_ECDSA_CTX *ctx, const unsigned char *data, size_t dataLen)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    if (ctx == NULL) {
        return STATUS_FAILED;
    }

    if (ctx->mdCtx == NULL) {
        return STATUS_FAILED;
    }

    return EVP_DigestUpdate(ctx->mdCtx, data, dataLen);
}

static int _ecdsa_signature_digest_sign_final(KEYISO_PROV_ECDSA_CTX *ctx, unsigned char *sig, size_t *sigLen, size_t sigSize)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    int ret = STATUS_FAILED;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;

    if (ctx->mdCtx == NULL) {
        return ret;
    }

    // If sig is NULL, this is a size fetch, and the digest does not need to be computed
    if (sig == NULL || EVP_DigestFinal(ctx->mdCtx, digest, &digestLen)) {
        ret = _ecdsa_signature_sign(ctx, sig, sigLen, sigSize, digest, digestLen);
    }

    return ret;
}

static int _ecdsa_signature_digest_verify_final(KEYISO_PROV_ECDSA_CTX *ctx, const unsigned char *sig, size_t sigLen)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;

    if (ctx->mdCtx == NULL) {
        return STATUS_FAILED;
    }

    if (!sig && sigLen <= 0) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    return EVP_DigestFinal(ctx->mdCtx, digest, &digestLen) &&
           _ecdsa_signature_verify(ctx, sig, sigLen, digest, digestLen);
}

static int _ecdsa_signature_digest_sign(KEYISO_PROV_ECDSA_CTX *ctx, unsigned char *sig,
    size_t *sigLen, size_t sigSize, const unsigned char *data, size_t dataLen)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;

    if (ctx == NULL || ctx->mdCtx == NULL || ctx->md == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    // If sig is NULL, this is a size fetch, and the digest does not need to be computed
    if (sig != NULL) {
        if (!EVP_DigestUpdate(ctx->mdCtx, data, dataLen) || !EVP_DigestFinal(ctx->mdCtx, digest, &digestLen)) {
            EVP_MD_CTX_free(ctx->mdCtx);
            ctx->mdCtx = NULL;
            return STATUS_FAILED;
        }
    }

    return _ecdsa_signature_sign(ctx, sig, sigLen, sigSize, digest, digestLen);
}

const OSSL_DISPATCH keyIso_prov_ecdsa_signature_funcs[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))_prov_ecdsa_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))_ecdsa_signature_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))_ecdsa_signature_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))_ecdsa_signature_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))_ecdsa_signature_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))_ecdsa_signature_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))_ecdsa_signature_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))_ecdsa_signature_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))_ecdsa_signature_digest_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))_ecdsa_signature_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))_ecdsa_signature_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))_ecdsa_signature_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))_prov_ecdsa_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))_prov_ecdsa_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))_ecdsa_signature_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))_ecdsa_signature_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))_ecdsa_signature_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))_ecdsa_signature_settable_ctx_params },
    { 0, NULL }
};
