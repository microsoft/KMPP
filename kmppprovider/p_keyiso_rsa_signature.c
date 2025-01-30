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
#include <openssl/rsa.h>

#include "keyisocommon.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisoclientinternal.h"
#include "keyisopfxclientinternal.h"
#include "keyisotelemetry.h"
#include "p_keyiso.h"
#include "p_keyiso_err.h"


static OSSL_ITEM paddingItem[] = {
    {RSA_PKCS1_PADDING, OSSL_PKEY_RSA_PAD_MODE_PKCSV15 },
    {RSA_PKCS1_PSS_PADDING, OSSL_PKEY_RSA_PAD_MODE_PSS },
    {0, NULL} };

static const OSSL_PARAM* _rsa_signature_gettable_ctx_params(ossl_unused KEYISO_PROV_RSA_CTX *ctx, ossl_unused void *provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
        OSSL_PARAM_END };

    return gettable;
}

static int _rsa_locate_pad_mode(OSSL_PARAM *p, unsigned int padding)
{
    int i = 0;

    // Padding mode may be retrieved as legacy NID or string
    switch (p->data_type) {
        case OSSL_PARAM_INTEGER:
            if (!OSSL_PARAM_set_int(p, padding)) {
                KMPPerr(KeyIsoErrReason_FailedToSetParams);
                return STATUS_FAILED;
            }
            break;

        case OSSL_PARAM_UTF8_STRING:
            while (paddingItem[i].id != 0 && padding != paddingItem[i].id) {
                i++;
            }

            if (0 == paddingItem[i].id) {
                KMPPerr(KeyIsoErrReason_UnsupportedPadding);
                return STATUS_FAILED;
            }

            if (!OSSL_PARAM_set_utf8_string(p, paddingItem[i].ptr)) {
                KMPPerr(KeyIsoErrReason_FailedToGetPadding);
                return STATUS_FAILED;
            }
            break;

        default:
            KMPPerr(KeyIsoErrReason_UnsupportedDataType);
            return STATUS_FAILED;
    }
    return STATUS_OK;
}

static int _rsa_locate_pss_salt_len(OSSL_PARAM *p, int saltLen)
{
    const char *saltLenText = NULL;
    int len = 0;

    // Salt mode may be accepted as legacy NID or string
    switch (p->data_type) {
        case OSSL_PARAM_INTEGER:
            if (!OSSL_PARAM_set_int(p, saltLen)) {
                KMPPerr(KeyIsoErrReason_FailedToSetParams);
                return STATUS_FAILED;
            }
            break;

        case OSSL_PARAM_UTF8_STRING:
            switch (saltLen) {
                case RSA_PSS_SALTLEN_DIGEST:
                    saltLenText = OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST;
                    break;
                case RSA_PSS_SALTLEN_AUTO:
                    saltLenText = OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO;
                    break;
                case RSA_PSS_SALTLEN_MAX:
                    saltLenText = OSSL_PKEY_RSA_PSS_SALT_LEN_MAX;
                    break;
                case RSA_PSS_SALTLEN_AUTO_DIGEST_MAX:
                    saltLenText = OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX;
                    break;
                default:
                    len = BIO_snprintf(p->data, p->data_size, "%d", saltLen);
                    if (len <= 0) {
                        KMPPerr(KeyIsoErrReason_UnsupportedSaltLen);
                        return STATUS_FAILED;
                    }
                    p->return_size = len;
            }

            if (!OSSL_PARAM_set_utf8_string(p, saltLenText)) {
                KMPPerr(KeyIsoErrReason_FailedToSetParams);
                return STATUS_FAILED;
            }
            break;
            
        default:
            KMPPerr(KeyIsoErrReason_FailedToGetParams);
            return STATUS_FAILED;
    }
    return STATUS_OK;
}

static int _get_nid_from_id(int id)
{
    int algNid = NID_undef;
    switch (id) {
        case NID_sha1:
            algNid = NID_sha1WithRSAEncryption;
            break;
        case NID_sha224:
            algNid = NID_sha224WithRSAEncryption;
            break;
        case NID_sha256:
            algNid = NID_sha256WithRSAEncryption;
            break;
        case NID_sha384:
            algNid = NID_sha384WithRSAEncryption;
            break;
        case NID_sha512:
            algNid = NID_sha512WithRSAEncryption;
            break;
        case NID_sha512_224:
            algNid = NID_sha512_224WithRSAEncryption;
            break;
        case NID_sha512_256:
            algNid = NID_sha512_256WithRSAEncryption;
            break;
        case NID_sha3_224:
            algNid = NID_RSA_SHA3_224;
            break;
        case NID_sha3_256:
            algNid = NID_RSA_SHA3_256;
            break;
        case NID_sha3_384:
            algNid = NID_RSA_SHA3_384;
            break;
        case NID_sha3_512:
            algNid = NID_RSA_SHA3_512;
            break;
        default:
            KMPPerr(KeyIsoErrReason_UnsupportedAlgorithm);
    }
    return algNid;
}

static int _rsa_locate_algorithm_id(OSSL_PARAM *p, const OSSL_ITEM *mdInfo)
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

    return STATUS_OK;
}

static int _rsa_signature_get_ctx_params(KEYISO_PROV_RSA_CTX *ctx, OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    if (ctx == NULL || ctx->provKey == NULL || params == NULL) {
        return STATUS_FAILED;
    }

    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->mdInfo == NULL ? "" : ctx->mdInfo->ptr)) {
        KMPPerr(KeyIsoErrReason_FailedToGetParams);
        return STATUS_FAILED;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != NULL && _rsa_locate_pad_mode(p, ctx->padding) != STATUS_OK) {
        return STATUS_FAILED;
    }

    // PSS paramaters
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN);
    if (p != NULL && _rsa_locate_pss_salt_len(p, ctx->saltLen) != STATUS_OK) {
        return STATUS_FAILED;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->mgf1mMdInfo == NULL ? "" : ctx->mgf1mMdInfo->ptr)) {
        KMPPerr(KeyIsoErrReason_FailedToGetParams);
        return STATUS_FAILED;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL && _rsa_locate_algorithm_id(p, ctx->mdInfo) != STATUS_OK) {
        return STATUS_FAILED;
    }

    return STATUS_OK;
}

static const OSSL_PARAM* _rsa_signature_settable_ctx_params(ossl_unused KEYISO_PROV_RSA_CTX *ctx, ossl_unused void *provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    // Padding may not be set at the time of querying settable params, so PSS params
    // are always accepted. The provider will check the padding before attempting 
    // to set the PSS parameters
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
        OSSL_PARAM_END };

    return settable;
}

static int _rsa_signature_set_ctx_params(KEYISO_PROV_RSA_CTX *ctx, const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    const OSSL_PARAM *p;

    if (params == NULL)
        return STATUS_OK;

    if (ctx == NULL || ctx->provKey == NULL) {
        return STATUS_FAILED;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL) {
        const char* mdName;

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdName)) {
            KMPPerr(KeyIsoErrReason_InvalidParams);
            return STATUS_FAILED;
        }

        // Similarily to SCOSSL, we do not support distinct MD and MGF1 MD
        if (KeyIso_prov_set_md_from_mdname(mdName, &ctx->md, &ctx->mdInfo) == STATUS_FAILED ||
            ctx->mdInfo == NULL || (ctx->mgf1mMdInfo != NULL && ctx->mdInfo->id != ctx->mgf1mMdInfo->id)) {
            KMPPerr(KeyIsoErrReason_InvalidMsgDigest);
            return STATUS_FAILED;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != NULL) {
        // Padding mode may be passed as legacy NID or string.
        int i = 0;
        unsigned int padding;

        switch (p->data_type) {
            case OSSL_PARAM_INTEGER:
                if (!OSSL_PARAM_get_uint(p, &padding)) {
                    KMPPerr(KeyIsoErrReason_FailedToGetParams);
                    return STATUS_FAILED;
                }
                while (paddingItem[i].id != 0 && padding != paddingItem[i].id) {
                    i++;
                }
                break;
            case OSSL_PARAM_UTF8_STRING:
                while (paddingItem[i].id != 0 && OPENSSL_strcasecmp(p->data, paddingItem[i].ptr) != 0) {
                    i++;
                }
                break;
            default:
                KMPPerr(KeyIsoErrReason_UnsupportedDataType);
                return STATUS_FAILED;
        }

        // Padding value was not found in supported map
        if (paddingItem[i].id == 0) {
            KMPPerr(KeyIsoErrReason_UnsupportedPadding);
            return STATUS_FAILED;
        }
        ctx->padding = paddingItem[i].id;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN);
    if (p != NULL) {
        // PSS padding must be set before setting PSS parameters
        if (ctx->padding != RSA_PKCS1_PSS_PADDING) {
            KMPPerr(KeyIsoErrReason_InvalidParams);
            return STATUS_FAILED;
        }

        int saltLen;
        // Padding mode may be passed as legacy NID or string
        switch (p->data_type) {
            case OSSL_PARAM_INTEGER:
                if (!OSSL_PARAM_get_int(p, &saltLen)) {
                    KMPPerr(KeyIsoErrReason_FailedToGetParams);
                    return STATUS_FAILED;
                }
                break;
            case OSSL_PARAM_UTF8_STRING:
                if (0 == OPENSSL_strcasecmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST))          
                    saltLen = RSA_PSS_SALTLEN_DIGEST;
                else if (0 == OPENSSL_strcasecmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_MAX))              
                    saltLen = RSA_PSS_SALTLEN_MAX;
                else if (0 == OPENSSL_strcasecmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO))             
                    saltLen = RSA_PSS_SALTLEN_AUTO;
                else if (0 == OPENSSL_strcasecmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX))  
                    saltLen = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
                else {
                    saltLen = atoi(p->data);
                }
                break;
            default:
                KMPPerr(KeyIsoErrReason_UnsupportedDataType);
                return STATUS_FAILED;
        }

        if (ctx->operation == EVP_PKEY_OP_VERIFY && (saltLen == RSA_PSS_SALTLEN_AUTO || saltLen == RSA_PSS_SALTLEN_AUTO_DIGEST_MAX)) {
            KMPPerr(KeyIsoErrReason_FailedToSetParams);
            return STATUS_FAILED;
        }
        ctx->saltLen = saltLen;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if (p != NULL) {
        const char* mdName;

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdName)) {
            KMPPerr(KeyIsoErrReason_FailedToGetParams);
            return STATUS_FAILED;
        }

        // Similarily to SCOSSL, we do not support distinct MD and MGF1 MD
        if (KeyIso_prov_set_md_from_mdname(mdName, &ctx->mgf1Md, &ctx->mgf1mMdInfo) == STATUS_FAILED ||
            ctx->mgf1mMdInfo == NULL ||  (ctx->mdInfo != NULL && ctx->mgf1mMdInfo->id != ctx->mdInfo->id)) {
            KMPPerr(KeyIsoErrReason_InvalidMsgDigest);
            return STATUS_FAILED;
        }
    }

    return STATUS_OK;
}


static const OSSL_PARAM* _rsa_signature_gettable_ctx_md_params(KEYISO_PROV_RSA_CTX *ctx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    if (ctx->md == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidMsgDigest);
        return STATUS_FAILED;
    }

    return EVP_MD_gettable_ctx_params(ctx->md);
}

static int _rsa_signature_get_ctx_md_params(KEYISO_PROV_RSA_CTX *ctx, OSSL_PARAM *params)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    if (ctx->mdCtx == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidMsgDigest);
        return STATUS_FAILED;
    }

    return EVP_MD_CTX_get_params(ctx->mdCtx, params);
}

static const OSSL_PARAM* _rsa_signature_settable_ctx_md_params(KEYISO_PROV_RSA_CTX *ctx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    if (ctx->md == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidMsgDigest);
        return STATUS_FAILED;
    }

    return EVP_MD_settable_ctx_params(ctx->md);
}

static int _rsa_signature_set_ctx_md_params(KEYISO_PROV_RSA_CTX *ctx, const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    if (ctx->mdCtx == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidMsgDigest);
        return STATUS_FAILED;
    }

    return EVP_MD_CTX_set_params(ctx->mdCtx, params);
}

static int _rsa_signature_signverify_init(KEYISO_PROV_RSA_CTX *ctx, KEYISO_PROV_PKEY *provKey, const OSSL_PARAM params[], int operation)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start"); 
    if (ctx == NULL || provKey == NULL) {
        return STATUS_FAILED;
    }

    ctx->provKey = provKey;
    ctx->saltLen = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
    ctx->operation = operation;

    return _rsa_signature_set_ctx_params(ctx, params);
}

static int _rsa_signature_sign_init(KEYISO_PROV_RSA_CTX *ctx, KEYISO_PROV_PKEY *provKey, const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    return _rsa_signature_signverify_init(ctx, provKey, params, EVP_PKEY_OP_SIGN);
}

static int _rsa_signature_verify_init(KEYISO_PROV_RSA_CTX *ctx, KEYISO_PROV_PKEY *provKey, const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    return _rsa_signature_signverify_init(ctx, provKey, params, EVP_PKEY_OP_VERIFY);
}


static int _cleanup_rsa_signature_pkcs1_pss_sign(int ret, KeyIsoErrReason reason, unsigned char *from) 
{
    if (ret != STATUS_OK) {
        KMPPerr(reason);
    }

    if (from != NULL) {
        KeyIso_free(from);
        from = NULL;
    }  
    
    return ret;
}

#define _CLEANUP_RSA_SIGNATURE_PKCS1_PSS_SIGN(ret, reason) \
        _cleanup_rsa_signature_pkcs1_pss_sign(ret, reason, from)

static int _rsa_signature_pkcs1_sign(KEYISO_PROV_RSA_CTX *ctx, unsigned char *sig, size_t *sigLen, const unsigned char *tbs, size_t tbsLen) 
{
    int len = -1;
    unsigned int flen = 0;
    unsigned char *from = NULL;
    int mdnid = ctx->mdInfo == NULL ? NID_undef : ctx->mdInfo->id;

    if(tbs == NULL) {
        return _CLEANUP_RSA_SIGNATURE_PKCS1_PSS_SIGN(STATUS_FAILED, KeyIsoErrReason_InvalidParams);
    }

    flen = sizeof(KEYISO_RSA_SIGN) + tbsLen; 
    from = (unsigned char *) KeyIso_zalloc(flen);
    if(from == NULL) {
        return STATUS_FAILED;
    }
     
    // Construct "from" buffer to send to service side
    KeyIso_rsa_sign_serialization(from, mdnid, tbs, tbsLen);

	// Sending to service side
    len = KeyIso_CLIENT_rsa_sign(ctx->provKey->keyCtx, flen, from, *sigLen, sig, 0);              
    if (len <= 0) {
        return _CLEANUP_RSA_SIGNATURE_PKCS1_PSS_SIGN(STATUS_FAILED, KeyIsoErrReason_OperationFailed);
    }
    *sigLen = len;

    return _CLEANUP_RSA_SIGNATURE_PKCS1_PSS_SIGN(STATUS_OK, KeyIsoErrReason_NoError);
}

static int _rsa_signature_pss_sign(KEYISO_PROV_RSA_CTX *ctx, unsigned char *sig, size_t *sigLen, const unsigned char *tbs, size_t tbsLen)
{
    unsigned int flen = 0;
    unsigned char *from = NULL;
    int len = -1;
    int mgf1MdType = (ctx->mgf1Md != NULL) ? EVP_MD_type(ctx->mgf1Md) : 0;
	int mdType = (ctx->md != NULL) ? EVP_MD_type(ctx->md) : 0;

    if(tbs == NULL) {
        return _CLEANUP_RSA_SIGNATURE_PKCS1_PSS_SIGN(STATUS_FAILED, KeyIsoErrReason_InvalidParams);
    }

    // In PSS at least one of these value must be set
    if (ctx->md == NULL && ctx->mgf1Md == NULL) {
		return _CLEANUP_RSA_SIGNATURE_PKCS1_PSS_SIGN(STATUS_FAILED, KeyIsoErrReason_InvalidMsgDigest);
	}

    // mgf1Md and md must be equal unless one of them is NULL as set in _rsa_signature_set_ctx_params  
    if (ctx->mgf1Md == NULL) {
        mgf1MdType = mdType;
    } else if (ctx->md == NULL) {
        mdType = mgf1MdType;
    }

    flen = sizeof(KEYISO_EVP_PKEY_SIGN) + tbsLen; 
    from = (unsigned char *) KeyIso_zalloc(flen);
    if(from == NULL) {
        return STATUS_FAILED;
    }

	// Construct "from" buffer to send to service side
    KeyIso_CLIENT_pkey_rsa_sign_serialization(from, tbs, tbsLen, ctx->saltLen, mdType, mgf1MdType, *sigLen, 0);

	// Sending to service side
    len = KeyIso_CLIENT_pkey_rsa_sign(ctx->provKey->keyCtx, (int)flen, from, *sigLen, sig, ctx->padding);
    if (len <= 0) {
        return _CLEANUP_RSA_SIGNATURE_PKCS1_PSS_SIGN(STATUS_FAILED, KeyIsoErrReason_OperationFailed);
    }
    *sigLen = len;

    return _CLEANUP_RSA_SIGNATURE_PKCS1_PSS_SIGN(STATUS_OK, KeyIsoErrReason_NoError);
}

static int _rsa_signature_sign(KEYISO_PROV_RSA_CTX *ctx, unsigned char *sig, size_t *sigLen,
    size_t sigSize, const unsigned char *tbs, size_t tbsLen)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    int ret = STATUS_FAILED;
    
    // Start measuring time for metrics
    START_MEASURE_TIME();

    if (ctx == NULL || ctx->provKey == NULL || ctx->provKey->keyCtx == NULL) {
        return STATUS_FAILED;
    }

    // First call with NULL buffer is to determine the required buffer size (modulus size)
    size_t modulusSize = KeyIso_get_bn_param_len(ctx->provKey, OSSL_PKEY_PARAM_RSA_N, NULL);;
    if (sig == NULL) {
        *sigLen = modulusSize;
        return STATUS_OK;
    }

    // We get here only when sig is not NULL
    if (sigSize < modulusSize) {
        KMPPerr(KeyIsoErrReason_InvalidSignatureLength);
        return STATUS_FAILED;
    }

    // sign here
    switch (ctx->padding) {
        case KMPP_RSA_PKCS1_PADDING:
            // do the same as kmpppfx_rsa_sign
            ret = _rsa_signature_pkcs1_sign(ctx, sig, sigLen, tbs, tbsLen);
			break;
	    case KMPP_RSA_PKCS1_PSS_PADDING:
            // do the same as kmpppfx_pkey_rsa_sign
            ret = _rsa_signature_pss_sign(ctx, sig, sigLen, tbs, tbsLen);
			break;
        default:
            KMPPerr(KeyIsoErrReason_UnsupportedPadding);
    }


    STOP_MEASURE_TIME(KeyisoKeyOperation_PkeyRsaSign);

    return ret;
}

static int _rsa_signature_verify(KEYISO_PROV_RSA_CTX *ctx, const unsigned char *sig, size_t sigLen, const unsigned char *tbs, size_t tbsLen)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    return KeyIso_rsa_signature_verify(ctx, sig, sigLen, tbs, tbsLen);
}

static int _rsa_signature_digest_signverify_init(KEYISO_PROV_RSA_CTX *ctx, const char *mdName, KEYISO_PROV_PKEY *provKey, const OSSL_PARAM params[], int operation)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");   
    if (!_rsa_signature_signverify_init(ctx, provKey, params, operation)) {
        return STATUS_FAILED;
    }

    // Set MD into context
    if (!mdName || (KeyIso_prov_set_md_from_mdname(mdName, &ctx->md, &ctx->mdInfo) == STATUS_FAILED)) {
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

static int _rsa_signature_digest_sign_init(KEYISO_PROV_RSA_CTX *ctx, const char *mdname, KEYISO_PROV_PKEY *provKey, const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    return _rsa_signature_digest_signverify_init(ctx, mdname, provKey, params, EVP_PKEY_OP_SIGN);
}

static int _rsa_signature_digest_verify_init(KEYISO_PROV_RSA_CTX *ctx, const char *mdname, KEYISO_PROV_PKEY *provKey, const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    return _rsa_signature_digest_signverify_init(ctx, mdname, provKey, params, EVP_PKEY_OP_VERIFY);
}

static int _rsa_signature_digest_signverify_update(KEYISO_PROV_RSA_CTX *ctx, const unsigned char *data, size_t dataLen)
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

static int _rsa_signature_digest_sign_final(KEYISO_PROV_RSA_CTX *ctx, unsigned char *sig, size_t *sigLen, size_t sigSize)
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
        ret = _rsa_signature_sign(ctx, sig, sigLen, sigSize, digest, digestLen);
    }

    return ret;
}


static int _rsa_signature_digest_verify_final(KEYISO_PROV_RSA_CTX *ctx, unsigned char *sig, size_t sigLen)
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

    return EVP_DigestFinal(ctx->mdCtx, digest, &digestLen) && _rsa_signature_verify(ctx, sig, sigLen, digest, digestLen);
}

static int _rsa_signature_digest_sign(KEYISO_PROV_RSA_CTX *ctx, unsigned char *sig, size_t *sigLen, size_t sigSize, const unsigned char *data, size_t dataLen)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;

    if (ctx == NULL || ctx->mdCtx == NULL || ctx->md == NULL){
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

    return _rsa_signature_sign(ctx, sig, sigLen, sigSize, digest, digestLen);
}

const OSSL_DISPATCH keyIso_prov_rsa_signature_funcs[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))KeyIso_prov_rsa_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))_rsa_signature_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))_rsa_signature_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))_rsa_signature_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))_rsa_signature_verify },          
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))_rsa_signature_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,(void (*)(void))_rsa_signature_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))_rsa_signature_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))_rsa_signature_digest_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))_rsa_signature_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))_rsa_signature_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))_rsa_signature_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))KeyIso_prov_rsa_freectx }, 
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))KeyIso_prov_rsa_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))_rsa_signature_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))_rsa_signature_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))_rsa_signature_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))_rsa_signature_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, (void (*)(void))_rsa_signature_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void))_rsa_signature_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, (void (*)(void))_rsa_signature_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void))_rsa_signature_settable_ctx_md_params },
    { 0, NULL }
};





