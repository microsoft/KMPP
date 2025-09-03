/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stddef.h>
#include <stdio.h>
#include <inttypes.h>

#include "keyisocommon.h"
#include "keyisolog.h"
#include "keyisosymcryptcommon.h"
#include "kmppsymcryptwrapper.h"

PCSYMCRYPT_HASH KeyIso_get_symcrypt_hash_algorithm(uint32_t mdnid)
{
    switch (mdnid) {
        case KMPP_NID_md5:
            return SymCryptMd5Algorithm;
        case KMPP_NID_sha1:
            return SymCryptSha1Algorithm;
        case KMPP_NID_sha256:
            return SymCryptSha256Algorithm;
        case KMPP_NID_sha384:
            return SymCryptSha384Algorithm;
        case KMPP_NID_sha512:
            return SymCryptSha512Algorithm;
        case KMPP_NID_sha3_256:
            return SymCryptSha3_256Algorithm;
        case KMPP_NID_sha3_384:
            return SymCryptSha3_384Algorithm;
        case KMPP_NID_sha3_512:
            return SymCryptSha3_512Algorithm;
        default:
            return NULL;
    }
}

int32_t KeyIso_get_expected_hash_length(int32_t mdnid)
{
    switch (mdnid)
    {
        case KMPP_NID_md5_sha1:
            return KMPP_MD5_SHA1_DIGEST_LENGTH;
        case KMPP_NID_md5:
            return KMPP_MD5_DIGEST_LENGTH;
        case KMPP_NID_sha1:
            return KMPP_SHA1_DIGEST_LENGTH;
        case KMPP_NID_sha256:
        case KMPP_NID_sha3_256:
            return KMPP_SHA256_DIGEST_LENGTH;
        case KMPP_NID_sha384:
        case KMPP_NID_sha3_384:
            return KMPP_SHA384_DIGEST_LENGTH;
        case KMPP_NID_sha512:
        case KMPP_NID_sha3_512:
            return KMPP_SHA512_DIGEST_LENGTH;
        default:
            return -1;
    }
}

static const KMPP_RSA_PKCS1_PARAMS keyiso_rsa_pkcs1_md5sha1_params  = {NULL, 0, SYMCRYPT_FLAG_RSA_PKCS1_NO_ASN1};
static const KMPP_RSA_PKCS1_PARAMS keyiso_rsa_pkcs1_md5_params      = {SymCryptMd5OidList, SYMCRYPT_MD5_OID_COUNT, 0};
static const KMPP_RSA_PKCS1_PARAMS keyiso_rsa_pkcs1_sha1_params     = {SymCryptSha1OidList, SYMCRYPT_SHA1_OID_COUNT, 0};
static const KMPP_RSA_PKCS1_PARAMS keyiso_rsa_pkcs1_sha256_params   = {SymCryptSha256OidList, SYMCRYPT_SHA256_OID_COUNT, 0};
static const KMPP_RSA_PKCS1_PARAMS keyiso_rsa_pkcs1_sha384_params   = {SymCryptSha384OidList, SYMCRYPT_SHA384_OID_COUNT, 0};
static const KMPP_RSA_PKCS1_PARAMS keyiso_rsa_pkcs1_sha512_params   = {SymCryptSha512OidList, SYMCRYPT_SHA512_OID_COUNT, 0};
static const KMPP_RSA_PKCS1_PARAMS keyiso_rsa_pkcs1_sha3_256_params = {SymCryptSha3_256OidList, SYMCRYPT_SHA3_256_OID_COUNT, 0};
static const KMPP_RSA_PKCS1_PARAMS keyiso_rsa_pkcs1_sha3_384_params = {SymCryptSha3_384OidList, SYMCRYPT_SHA3_384_OID_COUNT, 0};
static const KMPP_RSA_PKCS1_PARAMS keyiso_rsa_pkcs1_sha3_512_params = {SymCryptSha3_512OidList, SYMCRYPT_SHA3_512_OID_COUNT, 0};

const KMPP_RSA_PKCS1_PARAMS* KeyIso_get_rsa_pkcs1_params(int32_t mdnid)
{
    switch (mdnid)
    {
        case KMPP_NID_md5_sha1:
            return &keyiso_rsa_pkcs1_md5sha1_params;
        case KMPP_NID_md5:
            return &keyiso_rsa_pkcs1_md5_params;
        case KMPP_NID_sha1:
            return &keyiso_rsa_pkcs1_sha1_params;
        case KMPP_NID_sha256:
            return &keyiso_rsa_pkcs1_sha256_params;
        case KMPP_NID_sha384:
            return &keyiso_rsa_pkcs1_sha384_params;
        case KMPP_NID_sha512:
            return &keyiso_rsa_pkcs1_sha512_params;
        case KMPP_NID_sha3_256:
            return &keyiso_rsa_pkcs1_sha3_256_params;
        case KMPP_NID_sha3_384:
            return &keyiso_rsa_pkcs1_sha3_384_params;
        case KMPP_NID_sha3_512:
            return &keyiso_rsa_pkcs1_sha3_512_params;
        default:
            return NULL;
    }
}

// OpenSSL NID mappings (Only reroute NIST Prime curves to SymCrypt for now)
#define KMPP_ECC_CURVE_NISTP192_NID     409     // NID_X9_62_prime192v1
#define KMPP_ECC_CURVE_NISTP256_NID     415     // NID_X9_62_prime256v1
#define KMPP_ECC_CURVE_NISTP224_NID     713     // NID_secp224r1
#define KMPP_ECC_CURVE_NISTP384_NID     715     // NID_secp384r1
#define KMPP_ECC_CURVE_NISTP521_NID     716     // NID_secp521r1

static PSYMCRYPT_ECURVE _curve_P192 = NULL;
static PSYMCRYPT_ECURVE _curve_P224 = NULL;
static PSYMCRYPT_ECURVE _curve_P256 = NULL;
static PSYMCRYPT_ECURVE _curve_P384 = NULL;
static PSYMCRYPT_ECURVE _curve_P521 = NULL;

int KEYISO_EC_init_static()
{
    if (((_curve_P192 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP192, 0)) == NULL) ||
        ((_curve_P224 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP224, 0)) == NULL) ||
        ((_curve_P256 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP256, 0)) == NULL) ||
        ((_curve_P384 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP384, 0)) == NULL) ||
        ((_curve_P521 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP521, 0)) == NULL))
    {
        return STATUS_FAILED;
    }
    return STATUS_OK;
}

void KEYISO_EC_free_static()
{
    if (_curve_P192) {
        SymCryptEcurveFree(_curve_P192);
        _curve_P192 = NULL;
    }
    if (_curve_P224) {
        SymCryptEcurveFree(_curve_P224);
        _curve_P224 = NULL;
    }
    if (_curve_P256) {
        SymCryptEcurveFree(_curve_P256);
        _curve_P256 = NULL;
    }
    if (_curve_P384) {
        SymCryptEcurveFree(_curve_P384);
        _curve_P384 = NULL;
    }
    if (_curve_P521) {
        SymCryptEcurveFree(_curve_P521);
        _curve_P521 = NULL;
    }
}

// Get nid by symcrypt curve
int32_t KeyIso_get_curve_nid_from_symcrypt_curve(
    const uuid_t correlationId,
    PCSYMCRYPT_ECURVE pCurve)
{
    if (pCurve == NULL) {
        return -1; // Invalid curve
    }

    if (SymCryptEcurveIsSame(pCurve, _curve_P192)) {
        return KMPP_ECC_CURVE_NISTP192_NID;
    } else if (SymCryptEcurveIsSame(pCurve, _curve_P224)) {
        return KMPP_ECC_CURVE_NISTP224_NID;
    } else if (SymCryptEcurveIsSame(pCurve, _curve_P256)) {
        return KMPP_ECC_CURVE_NISTP256_NID;
    } else if (SymCryptEcurveIsSame(pCurve, _curve_P384)) {
        return KMPP_ECC_CURVE_NISTP384_NID;
    } else if (SymCryptEcurveIsSame(pCurve, _curve_P521)) {
        return KMPP_ECC_CURVE_NISTP521_NID;
    }

    KEYISOP_trace_log_error(correlationId, 0, KEYISOP_SERVICE_TITLE, "KeyIso_get_curve_nid_from_symcrypt_curve", "Unsupported curve");
    // Unsupported curve
    return -1;
}

PSYMCRYPT_ECURVE KeyIso_get_curve_by_nid(const uuid_t correlationId, uint32_t groupNid) 
{
    PSYMCRYPT_ECURVE pCurve = NULL;
    
    switch(groupNid)
    {
        case KMPP_ECC_CURVE_NISTP192_NID:
            pCurve = _curve_P192;
            break;
        case KMPP_ECC_CURVE_NISTP256_NID:
            pCurve = _curve_P256;
            break;
        case KMPP_ECC_CURVE_NISTP224_NID:
            pCurve =_curve_P224;
            break;
        case KMPP_ECC_CURVE_NISTP384_NID:
            pCurve = _curve_P384;
            break;
        case KMPP_ECC_CURVE_NISTP521_NID:
            pCurve = _curve_P521;
            break;
        default:
            KEYISOP_trace_log_error_para(correlationId, 0, NULL, "ERROR",  "SymCrypt engine does not yet support this group", "(nid %d)", groupNid);    
    }
    
    return pCurve;
}