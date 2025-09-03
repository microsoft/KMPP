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

// If r and s are both 0, the DER encoding would be 8 bytes
// (0x30 0x06 0x02 0x01 0x00 0x02 0x01 0x00)
// integers must contain at least 1 octet of content in DER
#define KMPP_ECDSA_MIN_DER_SIGNATURE_LEN (8)
// Largest supported curve is P521 => 66 * 2 + 4 (int headers) + 3 (seq header)
#define KMPP_ECDSA_MAX_DER_SIGNATURE_LEN (139)

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

static int _cleanup_ec_export_pubkey_to_symcrypt(int ret, KeyIsoErrReason reason, unsigned char *pubKeyBytes, 
    BIGNUM *coordX, BIGNUM *coordY, PSYMCRYPT_ECKEY pSymCryptEcKey) 
{
    if (ret != STATUS_OK) {
        KMPPerr(reason);
        if(pSymCryptEcKey)
            SymCryptEckeyFree(pSymCryptEcKey);
    }
    
    if(pubKeyBytes)
        KeyIso_free(pubKeyBytes);
    if(coordX)
        BN_free(coordX);
    if(coordY)
        BN_free(coordY);

    return ret;
}

#define _CLEANUP_EC_EXPORT_PUBKEY_TO_SYMCRYPT(ret, reason) \
    _cleanup_ec_export_pubkey_to_symcrypt(ret, reason, pubKeyBytes, coordX, coordY, pSymCryptEcKey)

// Create SymCrypt key from EVP_PKEY (public key) -
// relevant for public key operations such as verify
static int _ec_export_pubkey_to_symcrypt(const uuid_t correlationId, PSYMCRYPT_ECURVE curve, KEYISO_PROV_PKEY *provKey, PSYMCRYPT_ECKEY *symcryptEcKey)
{
    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    
    unsigned char *pubKeyBytes = NULL;
    PSYMCRYPT_ECKEY pSymCryptEcKey = NULL;
    BIGNUM *coordX = NULL;
    BIGNUM *coordY = NULL;
    size_t publicCurveKeyLen = 0;
    size_t publicKeyActualLen = 0;
    size_t coordXLen = 0, coordYLen = 0;

    if (provKey == NULL || provKey->pubKey == NULL || curve == NULL || symcryptEcKey == NULL) {
        return _CLEANUP_EC_EXPORT_PUBKEY_TO_SYMCRYPT(STATUS_FAILED, KeyIsoErrReason_InvalidParams);
    }

    // Create new EC key
    pSymCryptEcKey = SymCryptEckeyAllocate(curve);
    if (pSymCryptEcKey == NULL) {
        return _CLEANUP_EC_EXPORT_PUBKEY_TO_SYMCRYPT(STATUS_FAILED, KeyIsoErrReason_AllocFailure);
    }

    // Get coordinates as BIGNUMs
    if ((coordXLen = KeyIso_get_bn_param_len(provKey->pubKey, OSSL_PKEY_PARAM_EC_PUB_X, &coordX)) == 0 ||
        (coordYLen = KeyIso_get_bn_param_len(provKey->pubKey, OSSL_PKEY_PARAM_EC_PUB_Y, &coordY)) == 0) {
        return _CLEANUP_EC_EXPORT_PUBKEY_TO_SYMCRYPT(STATUS_FAILED, KeyIsoErrReason_FailedToGetParams);
    }
    publicKeyActualLen = coordXLen + coordYLen;

    // Validate against curve's expected size
    publicCurveKeyLen = SymCryptEckeySizeofPublicKey(pSymCryptEcKey, SYMCRYPT_ECPOINT_FORMAT_XY);
    if (publicCurveKeyLen < publicKeyActualLen) {
        return _CLEANUP_EC_EXPORT_PUBKEY_TO_SYMCRYPT(STATUS_FAILED, KeyIsoErrReason_FailedToGetParams);
    }

    // Allocate buffers for X,Y coordinates
    pubKeyBytes = KeyIso_zalloc(publicKeyActualLen);
    if (!pubKeyBytes) {
        return _CLEANUP_EC_EXPORT_PUBKEY_TO_SYMCRYPT(STATUS_FAILED, KeyIsoErrReason_AllocFailure);
    }

    // Convert BIGNUMs to byte arrays and concatenate them
    if (BN_bn2bin(coordX, pubKeyBytes) <= 0 || BN_bn2bin(coordY, pubKeyBytes + coordXLen) <= 0) {
        return _CLEANUP_EC_EXPORT_PUBKEY_TO_SYMCRYPT(STATUS_FAILED, KeyIsoErrReason_OperationFailed);
    }

    // Set key value 
    SYMCRYPT_ERROR scError = SymCryptEckeySetValue(NULL, 0, pubKeyBytes, publicKeyActualLen, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY, SYMCRYPT_FLAG_ECKEY_ECDSA, pSymCryptEcKey);

    if (scError != SYMCRYPT_NO_ERROR) {
        return _CLEANUP_EC_EXPORT_PUBKEY_TO_SYMCRYPT(STATUS_FAILED, KeyIsoErrReason_FailedToSetParams);
    }

    *symcryptEcKey = pSymCryptEcKey;
    return _CLEANUP_EC_EXPORT_PUBKEY_TO_SYMCRYPT(STATUS_OK, KeyIsoErrReason_NoError);
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
                KMPPerr_para(KeyIsoErrReason_OperationFailed, "SymCryptRsaOaepEncrypt failed, error: %d, flags:0x%x", 
                    scError, ((PCSYMCRYPT_RSAKEY)pSymCryptRsaKey)->fAlgorithmInfo);
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
                KMPPerr_para(KeyIsoErrReason_OperationFailed, "SymCryptRsaRawEncrypt failed, error: %d, flags:0x%x",
                     scError, ((PCSYMCRYPT_RSAKEY)pSymCryptRsaKey)->fAlgorithmInfo);
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

/******************************************
************ ECDSA Signature **************
******************************************/

// Return the max length of the DER encoded signature
// 2 * (private key length) + DER encoding header bytes
size_t KeyIso_get_ec_pkey_size(int curveNid)
{
    PSYMCRYPT_ECURVE curve = KeyIso_get_curve_by_nid(NULL, curveNid);
    if (curve == NULL) {

        return 0;
    }
    return 2 * SymCryptEcurveSizeofScalarMultiplier(curve) + KMPP_ECDSA_MIN_DER_SIGNATURE_LEN;
}

// Parse ASN.1 tag and length, return pointer to value, valueLen, totalLen parsed
static int _der_check_tag_and_get_value_and_length(const unsigned char *in, size_t inLen, uint8_t tag, const unsigned char **value, size_t *valueLen)
{
    const unsigned char *content = NULL;
    size_t contentLen = 0;

    // Basic parameter validation
    if (!in || !value || !valueLen || inLen < 2)
        return STATUS_FAILED;

    // Check for tag
    if (in[0] != tag)
        return STATUS_FAILED;

    // Extract content length and pointer to beginning of content
    contentLen = in[1];
    content = in + 2;
    if (contentLen > 0x7f) {
        // Only acceptable length with long form has 1 byte length
        if (contentLen == 0x81) {
            if (in[2] > 0x7f) {
                contentLen = in[2];
                content = in + 3;
            }     return STATUS_FAILED;  // Der element length field is not minimal
        }
        else
            return STATUS_FAILED;  // Unexpected length field encoding
    }

    if (content + contentLen > in + inLen)
        return STATUS_FAILED;

    *value = content;
    *valueLen = contentLen;

    return STATUS_OK;
}	

// Convert DER ECDSA signature to raw SymCrypt format
static int _remove_der_encoding(const uuid_t correlationId, const unsigned char* derSignature, 
    size_t derSignatureLen, unsigned char* symcryptSignature, size_t symcryptSignatureLen)
{

    const unsigned char *pbSeq = NULL, *pbR = NULL, *pbS = NULL;
    size_t cbSeq = 0, cbR = 0, cbS = 0;

    if ((derSignatureLen < KMPP_ECDSA_MIN_DER_SIGNATURE_LEN) ||
        (derSignatureLen > KMPP_ECDSA_MAX_DER_SIGNATURE_LEN) ||
        (symcryptSignatureLen < KMPP_ECDSA_MIN_SYMCRYPT_SIGNATURE_LEN) ||
        (symcryptSignatureLen > KMPP_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN) ||
        (symcryptSignatureLen % 2 == 1)) {
            return STATUS_FAILED;
    }

    // Parse DER encoding
    if (!_der_check_tag_and_get_value_and_length(derSignature, derSignatureLen, 0x30, &pbSeq, &cbSeq))
        return STATUS_FAILED;

    if (pbSeq + cbSeq != derSignature + derSignatureLen) {
        return STATUS_FAILED;  // SEQUENCE must cover entire input
    }

    if (!_der_check_tag_and_get_value_and_length(pbSeq, cbSeq, 0x02, &pbR, &cbR))
        return STATUS_FAILED;

    if (cbR > cbSeq - 3) {
        return STATUS_FAILED;  // R component must fit in SEQUENCE
    }

    if (!_der_check_tag_and_get_value_and_length(pbR + cbR, (pbSeq + cbSeq) - (pbR + cbR), 0x02, &pbS, &cbS))
        return STATUS_FAILED;

    if (pbS + cbS != pbSeq + cbSeq) {
        return STATUS_FAILED;  // S component must fit in SEQUENCE
    }

    // Check R's validity
    if (((pbR[0] & 0x80) == 0x80) ||                                  // R is negative
        ((cbR > 1) && (pbR[0] == 0x00) && ((pbR[1] & 0x80) != 0x80))) {  // R is non-zero, and has a redundant leading 0 byte
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_ECC_SIGN_TITLE, "", "pbR is not strict DER encoded non-negative integer");
        return STATUS_FAILED; 
    }

    // Trim leading 0 from R
    if (pbR[0] == 0) {
        pbR++;
        cbR--;
    }

    // Check S's validity
    if (((pbS[0] & 0x80) == 0x80) ||                                  // S is negative
        ((cbS > 1) && (pbS[0] == 0x00) && ((pbS[1] & 0x80) != 0x80))) { // S is non-zero, and has a redundant leading 0 byte 
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_ECC_SIGN_TITLE, "" ,"pbS is not strict DER encoded non-negative integer");
        return STATUS_FAILED; 
    }

    // Trim leading 0 from S
    if (pbS[0] == 0) {
        pbS++;
        cbS--;
    }

    if ((symcryptSignatureLen < 2 * cbR) || (symcryptSignatureLen < 2 * cbS)) {
        KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_ECC_SIGN_TITLE, "", "", "cbR (%lu) or cbS (%lu) too big for symcryptSignatureLen (%lu)", cbR, cbS, symcryptSignatureLen);
        return STATUS_FAILED; 
    }

    memset(symcryptSignature, 0, symcryptSignatureLen);
    memcpy(symcryptSignature + (symcryptSignatureLen / 2) - cbR, pbR, cbR);
    memcpy(symcryptSignature + symcryptSignatureLen - cbS, pbS, cbS);

    return STATUS_OK;
}


// pbHashValue = tbs, cbHashValue = tbsLen, pbSignature = sig, pcbSignature = sigLen
int KeyIso_ecdsa_signature_verify(KEYISO_PROV_ECDSA_CTX *ctx, int curveNid, const unsigned char *sig, size_t sigLen,
    const unsigned char *tbs, size_t tbsLen)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    // Start measuring time for metrics
    START_MEASURE_TIME();

    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PSYMCRYPT_ECKEY pSymCryptEcKey = NULL;
    PSYMCRYPT_ECURVE curve = NULL;
    unsigned char buf[KMPP_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN] = {0};
    size_t symCryptSigLen = 0;

    if (!ctx || !ctx->provKey || !ctx->provKey->keyCtx || !sig || !tbs) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    // Get the curve from the NID
    curve = KeyIso_get_curve_by_nid(ctx->provKey->keyCtx->correlationId, curveNid);
    if (!curve) {
        KMPPerr(KeyIsoErrReason_UnsupportedCurve);
        return STATUS_FAILED;
    }

    // Calculate expected signature size
    symCryptSigLen = 2 * SymCryptEcurveSizeofScalarMultiplier(curve);
    if (sigLen < symCryptSigLen) {
        KMPPerr(KeyIsoErrReason_InvalidSignatureLength);
        return STATUS_FAILED;
    }

    // Remove DER encoding
    if (_remove_der_encoding(ctx->provKey->keyCtx->correlationId, sig, sigLen, &buf[0], symCryptSigLen) != STATUS_OK) {
        KMPPerr(KeyIsoErrReason_OperationFailed);
        return STATUS_FAILED;
    }

    // Create SymCrypt key from ctx
    int ret = _ec_export_pubkey_to_symcrypt(ctx->provKey->keyCtx->correlationId, curve, ctx->provKey, &pSymCryptEcKey);
    if (!pSymCryptEcKey || ret != STATUS_OK) {
        KMPPerr(KeyIsoErrReason_OperationFailed);
        return STATUS_FAILED;
    }

    scError = SymCryptEcDsaVerify(pSymCryptEcKey, tbs, tbsLen, buf, symCryptSigLen, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0);
    if (scError != SYMCRYPT_NO_ERROR) {
        KMPPerr_para(KeyIsoErrReason_OperationFailed, "SymCryptEcDsaVerify failed, error: %d", scError);
        SymCryptEckeyFree(pSymCryptEcKey);
        return STATUS_FAILED;
    }

    STOP_MEASURE_TIME(KeyisoKeyOperation_EcdsaVerify);

    SymCryptEckeyFree(pSymCryptEcKey);
    return STATUS_OK;
}
