/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include "keyisolog.h"
#include "keyisoservicekeygen.h"
#include "keyisosymcryptcommon.h"
#include "keyisoutils.h"

#define RSAKEY_FIPS_MIN_BITSIZE_MODULUS 1024

/////////////////////////////////////////////////////
///////////// Internal Key Gen methods //////////////
/////////////////////////////////////////////////////

int KeyIso_rsa_key_generate(
    const uuid_t correlationId,
    unsigned int bitSize,
    unsigned int keyUsage,
    PSYMCRYPT_RSAKEY *pGeneratedKey)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PSYMCRYPT_RSAKEY pKey = NULL;
    SYMCRYPT_RSA_PARAMS params;
    
    unsigned int generateFlags = 0;
    unsigned int allowedFlags = 0;

    *pGeneratedKey = NULL;

    if (bitSize < RSAKEY_FIPS_MIN_BITSIZE_MODULUS) {
        // Validation required by FIPS is enabled by default. 
        // This flag enables a caller to opt out of this validation.
        generateFlags |= SYMCRYPT_FLAG_KEY_NO_FIPS;
    }

    params.version = 1;
    params.nBitsOfModulus = bitSize;
    params.nPrimes = 2;    // private key
    params.nPubExp = 1;

    pKey = SymCryptRsakeyAllocate(&params, 0);
    if (!pKey) {
        return STATUS_FAILED;
    }

    // Callers must specify what algorithm(s) a given asymmetric key will be used for.
    // This information will be tracked by SymCrypt, and attempting to use the key in an algorithm it
    // was not generated or imported for will result in failure.
    // If no algorithm is specified then the key generation or import function will fail.

    generateFlags = KMPP_KEY_USAGE_TO_SYMCRYPT_FLAG(keyUsage);
    allowedFlags = SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT;
    if ((generateFlags & allowedFlags) == 0) {
        KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_GEN_KEY_TITLE, "Key usage", "unsupported", "keyUsage: 0x%x", keyUsage);
        SymCryptRsakeyFree(pKey);
        return STATUS_FAILED;
    }

    scError = SymCryptRsakeyGenerate(pKey, NULL, 0, generateFlags); // default exponent 2^16 + 1 is used
    if (scError != SYMCRYPT_NO_ERROR) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_GEN_KEY_TITLE, "SymCryptRsakeyGenerate", "Failed");
        SymCryptRsakeyFree(pKey);
        return STATUS_FAILED;
    }

    *pGeneratedKey = pKey;
    return STATUS_OK;
}

static int _ec_key_generate_failure(PSYMCRYPT_ECKEY pKey)
{
    if (pKey) {
        SymCryptEckeyFree(pKey);
    }
    return STATUS_FAILED;
}

int KeyIso_ec_key_generate(
    const uuid_t correlationId, 
   uint32_t curve_nid,
    unsigned int keyUsage,
    PSYMCRYPT_ECKEY *pGeneratedKey)
{
    unsigned int generateFlags = 0;
    unsigned int allowedFlags = 0;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PSYMCRYPT_ECURVE pCurve = NULL;
    PSYMCRYPT_ECKEY pKey = NULL;

    *pGeneratedKey = NULL;

    pCurve = KeyIso_get_curve_by_nid(correlationId, curve_nid);
    if (!pCurve) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_GEN_KEY_TITLE, "KeyIso_get_curve_by_nid", "Unsupported curve");
        return STATUS_FAILED;
    }

    // Allocate key
    pKey = SymCryptEckeyAllocate(pCurve);
    if (!pKey) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_GEN_KEY_TITLE, "SymCryptEckeyAllocate", "Failed");
        return _ec_key_generate_failure(pKey);
    }

    generateFlags = KMPP_KEY_USAGE_TO_SYMCRYPT_FLAG(keyUsage);
    allowedFlags = SYMCRYPT_FLAG_ECKEY_ECDSA | SYMCRYPT_FLAG_ECKEY_ECDH;
    if ((generateFlags & allowedFlags) == 0) {
        KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_GEN_KEY_TITLE, "Key usage", "unsupported", "keyUsage: 0x%x", keyUsage);
        return _ec_key_generate_failure(pKey);
    }
    
    // Generate key pair
    scError = SymCryptEckeySetRandom(generateFlags, pKey);
    if (scError != SYMCRYPT_NO_ERROR) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_GEN_KEY_TITLE, "SymCryptEckeySetRandom", "Failed");
        return _ec_key_generate_failure(pKey);
    }
    
    *pGeneratedKey = pKey;
    return STATUS_OK;
}

KmppKeyType KeyIso_evp_pkey_id_to_KmppKeyType(const uuid_t correlationId, int evp_pkey_id)
{
    if (evp_pkey_id == KMPP_EVP_PKEY_EC_NID) {
        return KmppKeyType_ec;
    } else if ((evp_pkey_id == KMPP_EVP_PKEY_RSA_NID) || (evp_pkey_id == KMPP_EVP_PKEY_RSA_PSS_NID)) {
        return KmppKeyType_rsa;
    }
    KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_SERVICE_TITLE, "KeyIso_evp_pkey_id_to_KmppKeyType Failed", "The EVP pkey id is not supported", "id: %d", evp_pkey_id); 
    return KmppKeyType_end;
}