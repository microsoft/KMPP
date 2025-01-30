/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stddef.h>
#include <stdio.h>
#include <inttypes.h>

#include "keyisocommon.h"
#include "keyisosymcryptcommon.h"
#include "kmppsymcryptwrapper.h"

PCSYMCRYPT_HASH KeyIso_get_symcrypt_hash_algorithm(uint32_t mdnid)
{
    switch (mdnid)
    {
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