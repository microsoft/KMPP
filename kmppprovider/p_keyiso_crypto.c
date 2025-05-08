/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>

#include "keyisoclientinternal.h"
#include "keyisocommon.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisosymcryptcommon.h"
#include "keyisotelemetry.h"
#include "p_keyiso.h"
#include "p_keyiso_err.h"


static int _cleanup_rsa_export_pubkey_to_symcrypt(int ret, KeyIsoErrReason reason, unsigned char *modulusBytes, 
    unsigned char *exponentBytes, BIGNUM *modulus,  BIGNUM *exponent, PSYMCRYPT_RSAKEY tmpSymCryptRsaKey) 
{
    if (ret != STATUS_OK) {
        KMPPerr(reason);

        if(tmpSymCryptRsaKey)
            SymCryptRsakeyFree(tmpSymCryptRsaKey);
    }
        
    if(modulusBytes)
        KeyIso_free(modulusBytes);
    if(exponentBytes)
        KeyIso_free(exponentBytes);
    if(modulus)
        BN_free(modulus);
    if(exponent)
        BN_free(exponent);

    return ret;
}
#define _CLEANUP_RSA_EXPORT_PUBKEY_TO_SYMCRYPT(ret, reason) \
        _cleanup_rsa_export_pubkey_to_symcrypt(ret, reason, modulusBytes, exponentBytes, modulus, exponent, tmpSymCryptRsaKey)

// Create SymCrypt key from EVP_PKEY (public key) -
// relevant for public key operations such as "encrypt" and "verify"
int _rsa_export_pubkey_to_symcrypt(const uuid_t correlationId, KEYISO_PROV_PKEY *provKey, PSYMCRYPT_RSAKEY *symcryptRsaKey)
{
	KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    
    uint64_t publicExp;
    unsigned char *modulusBytes = NULL;
    unsigned char *exponentBytes = NULL;
    size_t modulusLen = 0;
    size_t exponentLen = 0;
    PSYMCRYPT_RSAKEY tmpSymCryptRsaKey = NULL;
    SYMCRYPT_RSA_PARAMS symcryptRsaParam;  
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;   
    BIGNUM *modulus = NULL;
    BIGNUM *exponent = NULL;

    if (provKey == NULL || provKey->pubKey == NULL) {
        return STATUS_FAILED;
    }

    if ((modulusLen = KeyIso_get_bn_param_len(provKey->pubKey, OSSL_PKEY_PARAM_RSA_N, &modulus)) == 0) {
        return _CLEANUP_RSA_EXPORT_PUBKEY_TO_SYMCRYPT(STATUS_FAILED, KeyIsoErrReason_FailedToGetParams);
    }

    if ((exponentLen = KeyIso_get_bn_param_len(provKey->pubKey, OSSL_PKEY_PARAM_RSA_E, &exponent)) == 0) {
        return _CLEANUP_RSA_EXPORT_PUBKEY_TO_SYMCRYPT(STATUS_FAILED, KeyIsoErrReason_FailedToGetParams);
    }

    // Allocate memory for the modulus and exponent bytes
    modulusBytes = KeyIso_zalloc(modulusLen);
    if (!modulusBytes) {
        return _CLEANUP_RSA_EXPORT_PUBKEY_TO_SYMCRYPT(STATUS_FAILED, KeyIsoErrReason_AllocFailure);
    }

    exponentBytes = KeyIso_zalloc(exponentLen);
    if (!exponentBytes) {
        return _CLEANUP_RSA_EXPORT_PUBKEY_TO_SYMCRYPT(STATUS_FAILED, KeyIsoErrReason_AllocFailure);
    }
    // Convert the BIGNUMs to byte arrays
    if (BN_bn2bin(modulus, modulusBytes) <= 0 || BN_bn2bin(exponent, exponentBytes) <= 0) {
        return _CLEANUP_RSA_EXPORT_PUBKEY_TO_SYMCRYPT(STATUS_FAILED, KeyIsoErrReason_OperationFailed);
    }

    // Convert the exponent BIGNUM to uint64_t
    if (SymCryptLoadMsbFirstUint64(exponentBytes, exponentLen, &publicExp) != SYMCRYPT_NO_ERROR ) {
		return _CLEANUP_RSA_EXPORT_PUBKEY_TO_SYMCRYPT(STATUS_FAILED, KeyIsoErrReason_OperationFailed);
	}

    symcryptRsaParam.version = KEYISO_SYMCRYPT_RSA_PARAMS_VERSION;
    symcryptRsaParam.nBitsOfModulus = modulusLen * 8;
    symcryptRsaParam.nPrimes = 0;
    symcryptRsaParam.nPubExp = KEYISO_SYMCRYPT_RSA_PARAMS_N_PUB_EXP;
    tmpSymCryptRsaKey = SymCryptRsakeyAllocate(&symcryptRsaParam, 0);

    if (tmpSymCryptRsaKey == NULL) { 
        return _CLEANUP_RSA_EXPORT_PUBKEY_TO_SYMCRYPT(STATUS_FAILED, KeyIsoErrReason_AllocFailure);
    }

    scError = SymCryptRsakeySetValue(modulusBytes, modulusLen, &publicExp, 1, NULL, NULL, 0,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT, tmpSymCryptRsaKey);	
    if (scError != SYMCRYPT_NO_ERROR) {  
        return _CLEANUP_RSA_EXPORT_PUBKEY_TO_SYMCRYPT(STATUS_FAILED, KeyIsoErrReason_FailedToSetParams);
    }

	*symcryptRsaKey = tmpSymCryptRsaKey;

    return _CLEANUP_RSA_EXPORT_PUBKEY_TO_SYMCRYPT(STATUS_OK, KeyIsoErrReason_NoError);
}


/******************************************
************** RSA Encrypt ***************
******************************************/

static int _rsa_encrypt(const uuid_t correlationId, KEYISO_PROV_RSA_CTX *ctx, PSYMCRYPT_RSAKEY pSymCryptRsaKey, 
    const unsigned char *in, size_t inLen, unsigned char *out, int *pToLen)
{
    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    int ret = STATUS_FAILED;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PCSYMCRYPT_HASH symCryptHashAlgo = NULL;
    uint32_t modulusLen = SymCryptRsakeySizeofModulus(pSymCryptRsaKey);
	size_t resultLen = -1;

    *pToLen = -1;

    if (out == NULL) {
        ret = STATUS_OK;
        // An upper estimation for the output length
        *pToLen = (int32_t)modulusLen; 
        return ret;
    }

    switch (ctx->padding) {
        case KMPP_RSA_PKCS1_PADDING:
            if (inLen > modulusLen - KMPP_MIN_PKCS1_PADDING) {
                return ret;
            }
            scError = SymCryptRsaPkcs1Encrypt(pSymCryptRsaKey, in, inLen, 0, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, out, modulusLen, &resultLen);
            if (scError != SYMCRYPT_NO_ERROR) {
                KMPPerr_para(KeyIsoErrReason_OperationFailed, "SymCryptRsaPkcs1Encrypt failed, error: %d, flags:0x%x", scError, ((PCSYMCRYPT_RSAKEY)pSymCryptRsaKey)->fAlgorithmInfo);
                return ret;
            }
            break;
        case KMPP_RSA_PKCS1_OAEP_PADDING:
            if (inLen > modulusLen - KMPP_MIN_OAEP_PADDING) {
                return ret;
            }

            symCryptHashAlgo = KeyIso_get_symcrypt_hash_algorithm(ctx->mdInfoCtx->mdInfo->id);
            if (!symCryptHashAlgo) {
                KMPPerr_para(KeyIsoErrReason_InvalidMsgDigest, "message digest identifier: %d", ctx->mdInfoCtx->mdInfo->id);
                return ret;
            }

            scError = SymCryptRsaOaepEncrypt(pSymCryptRsaKey, in,  inLen, symCryptHashAlgo, ctx->oaepLabel, ctx->oaepLabelLen, 0, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, out, modulusLen, &resultLen);
            if (scError != SYMCRYPT_NO_ERROR) {
                KMPPerr_para(KeyIsoErrReason_OperationFailed, "SymCryptRsaOaepEncrypt failed, error: %d, flags:0x%x", scError, ((PCSYMCRYPT_RSAKEY)pSymCryptRsaKey)->fAlgorithmInfo);
                return ret;
            }
            break;
        case KMPP_RSA_NO_PADDING:
            if (inLen != modulusLen) {
                return ret;
            }
            scError = SymCryptRsaRawEncrypt(pSymCryptRsaKey, in, inLen, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, out, modulusLen);
            resultLen = modulusLen;
            if (scError != SYMCRYPT_NO_ERROR) {
                KMPPerr_para(KeyIsoErrReason_OperationFailed, "SymCryptRsaRawEncrypt failed, error: %d, flags:0x%x", scError, ((PCSYMCRYPT_RSAKEY)pSymCryptRsaKey)->fAlgorithmInfo);
                return ret;
            }
            break;
        default:
            KMPPerr_para(KeyIsoErrReason_UnsupportedPadding, "padding: %d", ctx->padding);
            break;
    }

    ret = resultLen <= INT32_MAX;
    *pToLen = ret ? (int32_t)resultLen : -1;
    return ret;
}

// Symcrypt implementation for RSA encrypt
int KeyIso_rsa_cipher_encrypt(KEYISO_PROV_RSA_CTX *ctx, unsigned char *out, size_t *outLen, ossl_unused size_t outSize, const unsigned char *in, size_t inLen)
{
	KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    // Start measuring time for metrics
    START_MEASURE_TIME();

	PSYMCRYPT_RSAKEY pSymCryptRsaKey = NULL;
	int resultLen = 0;
    int ret = STATUS_FAILED;

    if (!ctx || !ctx->provKey || !ctx->provKey->keyCtx) {
		KMPPerr(KeyIsoErrReason_FailedToGetKeyCtx);
		return ret;
    }

    // Create Symcrypt key our of EVP_PKEY
    ret = _rsa_export_pubkey_to_symcrypt(ctx->provKey->keyCtx->correlationId, ctx->provKey, &pSymCryptRsaKey);
    if(!pSymCryptRsaKey || ret !=  STATUS_OK) {
		KMPPerr_para(KeyIsoErrReason_OperationFailed, "SymCryptRsakeyAllocate failed, ret: %d", ret);
		return ret;
	}

    // Call Symcrypt function
    ret = _rsa_encrypt(ctx->provKey->keyCtx->correlationId, ctx, pSymCryptRsaKey, in, inLen, out, &resultLen);
    *outLen = ret ? (size_t)resultLen : 0;

	// Free Symcrypt key
    if (pSymCryptRsaKey) {
        SymCryptRsakeyFree(pSymCryptRsaKey);
    }
     
    STOP_MEASURE_TIME(KeyisoKeyOperation_RsaPublicEnc);

	return ret;
}

/******************************************
********** Verify RSA signature ***********
******************************************/

static int _rsa_signatur_pkcs1_verify(const uuid_t correlationId, PSYMCRYPT_RSAKEY pSymCryptRsaKey, int mdnid, 
    const unsigned char *hashValue, size_t hashValueLen, const unsigned char *sig, size_t sigLen) 
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    const KMPP_RSA_PKCS1_PARAMS *pkcs1Params = KeyIso_get_rsa_pkcs1_params(mdnid);
    int32_t expectedHash =  KeyIso_get_expected_hash_length(mdnid);

    if (pkcs1Params == NULL) {
        KMPPerr_para(KeyIsoErrReason_InvalidMsgDigest, "mdnid: %d. Size: %d.", mdnid, hashValueLen);
        return STATUS_FAILED;
	}
    
    if (expectedHash < 0 || (uint32_t)expectedHash != hashValueLen) {
        KMPPerr_para(KeyIsoErrReason_InvalidMsgDigest, "hashValueLen: %d, mdnid:%d", hashValueLen, mdnid);
       return STATUS_FAILED;
    }

     // Log warnings for algorithms that aren't FIPS compliant
    if (mdnid == KMPP_NID_md5_sha1 || mdnid == KMPP_NID_md5 ||  mdnid == KMPP_NID_sha1) {
        KEYISOP_trace_log_error_para(correlationId, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_PROVIDER_TITLE, "Compliance warning",
            "Using Mac algorithm which is not FIPS compliant", "Hash algorithm identifier: %d", mdnid);
    }

    scError = SymCryptRsaPkcs1Verify(pSymCryptRsaKey, hashValue, hashValueLen, sig, sigLen,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pkcs1Params->pHashOIDs, pkcs1Params->nOIDCount, 0);

    if (scError != SYMCRYPT_NO_ERROR) {
        KMPPerr_para(KeyIsoErrReason_OperationFailed, "SymCryptRsaPkcs1Verify failed, scError: %d, flags: 0x%x", scError, pSymCryptRsaKey->fAlgorithmInfo);
        return STATUS_FAILED;
    }

   return STATUS_OK;
}

static int _rsa_signature_pss_verify(const uuid_t correlationId, KEYISO_PROV_RSA_MD_INFO_CTX *mdInfoCtx, PSYMCRYPT_RSAKEY pSymCryptRsaKey, int mdnid, 
    const unsigned char *hashValue, size_t hashValueLen, const unsigned char *sig, size_t sigLen)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    uint32_t saltMaxLen = 0;
    PCSYMCRYPT_HASH hashAlgo = KeyIso_get_symcrypt_hash_algorithm(mdnid);
    int32_t expectedHashLength = KeyIso_get_expected_hash_length(mdnid);
    uint32_t flags = 0;

    if (hashAlgo == NULL || expectedHashLength <= 0) {
        KMPPerr_para(KeyIsoErrReason_InvalidMsgDigest, "mdnid: %d. expectedHashLength: %d.", mdnid, expectedHashLength);
        return STATUS_FAILED;
    }
    
    if (hashValueLen > UINT32_MAX || (uint32_t)hashValueLen != (uint32_t)expectedHashLength) {
        KMPPerr_para(KeyIsoErrReason_InvalidMsgDigest, "mdnid: %d, expectedHashLength: %d", hashValueLen, expectedHashLength);
        return STATUS_FAILED;
    }

    saltMaxLen = ((SymCryptRsakeyModulusBits(pSymCryptRsaKey) + 6) / 8) - (uint32_t)hashValueLen - 2; // ceil((ModulusBits - 1) / 8) - digestLen - 2

    // We define saltMaxLen as uint32_t to avoid implicit conversion that might result in a negative value.
    // Therefore, we have to ensure that saltMaxLen does not exceed INT32_MAX, as it will be assigned to an int32_t later.
    if (saltMaxLen > INT32_MAX) {
        KMPPerr_para(KeyIsoErrReason_InvalidMsgDigest, "Invalid salt size. Salt size exceeds the maximum value of signed integer, saltMaxLen: %d", saltMaxLen);
        return STATUS_FAILED;
    }

    switch (mdInfoCtx->saltLen) {
        case KMPP_RSA_PSS_SALTLEN_DIGEST:
            mdInfoCtx->saltLen = expectedHashLength;
            break;
        case KMPP_RSA_PSS_SALTLEN_MAX:
            mdInfoCtx->saltLen = (int32_t)saltMaxLen;
            break;
        case KMPP_RSA_PSS_SALTLEN_AUTO:
        case KMPP_RSA_PSS_SALTLEN_AUTO_DIGEST_MAX:
            mdInfoCtx->saltLen = 0;
            flags = KEYISO_SYMCRYPT_FLAG_RSA_PSS_VERIFY_WITH_MINIMUM_SALT;
            break;
        default:
            KMPPerr_para(KeyIsoErrReason_UnsupportedSaltLen, "saltLen: %d", mdInfoCtx->saltLen);
            return STATUS_FAILED;
    }

    if (mdInfoCtx->saltLen < 0 || (uint32_t)mdInfoCtx->saltLen > saltMaxLen) {
        KMPPerr_para(KeyIsoErrReason_UnsupportedSaltLen, "saltLen: %d, saltMaxLen: %d", mdInfoCtx->saltLen, saltMaxLen);
        return STATUS_FAILED;
    }

    // Log warnings for algorithms that aren't FIPS compliant
    if (mdnid == KMPP_NID_md5_sha1 || mdnid == KMPP_NID_md5 ||  mdnid == KMPP_NID_sha1) {
        KEYISOP_trace_log_error_para(correlationId, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_PROVIDER_TITLE, "Compliance warning",
            "Using Mac algorithm which is not FIPS compliant", "Hash algorithm identifier: %d", mdnid);
    }

    scError = SymCryptRsaPssVerify(pSymCryptRsaKey, hashValue, hashValueLen, sig, sigLen, 
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, hashAlgo, mdInfoCtx->saltLen, flags);

    if (scError != SYMCRYPT_NO_ERROR) {
        KMPPerr_para(KeyIsoErrReason_OperationFailed, "SymCryptRsaPssVerify failed, scError: %d, flags: 0x%x", scError, pSymCryptRsaKey->fAlgorithmInfo);
        return STATUS_FAILED;
    }

	return STATUS_OK;
}

int KeyIso_rsa_signature_verify(KEYISO_PROV_RSA_CTX *ctx, const unsigned char *sig, size_t sigLen, const unsigned char *tbs, size_t tbsLen)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    // Start measuring time for metrics
    START_MEASURE_TIME();

    PSYMCRYPT_RSAKEY pSymCryptRsaKey = NULL;
    int mdnid = (ctx->mdInfoCtx->mdInfo == NULL) ? NID_undef : ctx->mdInfoCtx->mdInfo->id;
	int ret = STATUS_FAILED;

    if (!ctx || !ctx->provKey || !ctx->provKey->keyCtx) {
        KMPPerr(KeyIsoErrReason_FailedToGetKeyCtx);
		return ret;
    }

    if(tbs == NULL || sig == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    // Create Symcrypt key our of EVP_PKEY
    ret = _rsa_export_pubkey_to_symcrypt(ctx->provKey->keyCtx->correlationId, ctx->provKey, (void*)&pSymCryptRsaKey);
    if(!pSymCryptRsaKey || ret !=  STATUS_OK) {
		KMPPerr_para(KeyIsoErrReason_OperationFailed, "SymCryptRsakeyAllocate failed, ret: %d", ret);
		return ret;
	}

    switch (ctx->padding) {
        case RSA_PKCS1_PADDING:
            ret =  _rsa_signatur_pkcs1_verify(ctx->provKey->keyCtx->correlationId, pSymCryptRsaKey, mdnid, tbs, tbsLen, sig, sigLen);
            break;
        case RSA_PKCS1_PSS_PADDING:
            if (mdnid == NID_undef) {
                KMPPerr(KeyIsoErrReason_InvalidMsgDigest);
                return STATUS_FAILED;
            }
            ret = _rsa_signature_pss_verify(ctx->provKey->keyCtx->correlationId, ctx->mdInfoCtx, pSymCryptRsaKey, mdnid, tbs, tbsLen, sig, sigLen);
            break;
        default:
            KMPPerr(KeyIsoErrReason_UnsupportedPadding);
    }

    // Free Symcrypt key
    if (pSymCryptRsaKey) {
        SymCryptRsakeyFree(pSymCryptRsaKey);
    }       

    STOP_MEASURE_TIME(KeyisoKeyOperation_PkeyRsaVerify);
    return ret;
}