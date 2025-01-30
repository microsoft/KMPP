/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <stdbool.h>
#include <tss2/tss2_mu.h>

#include "keyisocommon.h"
#include "keyisoclientinternal.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisotpmcommon.h"

typedef struct KMPP_TPM_PBEPARAM_st {
    ASN1_INTEGER *parentHandle;  // Parent if was provided a persistent key parent different then the default SRK
    ASN1_OCTET_STRING *pub;
    ASN1_BOOLEAN isAuth;        // Does user authentication password for the key needed
} KMPP_TPM_PBEPARAM;

// The following sequence defines the ASN.1 data structure of KMPP_TPM_PBEPARAM.
// The sequence is packed to an OCTET_STRING that is set to the parameters
// property of the Encryption Algorithm Identifier
ASN1_SEQUENCE(KMPP_TPM_PBEPARAM) = {
    ASN1_SIMPLE(KMPP_TPM_PBEPARAM, parentHandle, ASN1_INTEGER),
    ASN1_SIMPLE(KMPP_TPM_PBEPARAM, pub, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KMPP_TPM_PBEPARAM, isAuth, ASN1_BOOLEAN),
} ASN1_SEQUENCE_END(KMPP_TPM_PBEPARAM)

// New, free, d2i & i2d functions for KMPP_TPM_PBEPARAM 
IMPLEMENT_ASN1_FUNCTIONS(KMPP_TPM_PBEPARAM)

typedef struct {
   TSS2_RC (*marshal_func)(const KEYISO_TPM_KEY_DATA*, uint8_t *, size_t, size_t *);
} MarshalStrategy;


static TSS2_RC _marshal_private(const KEYISO_TPM_KEY_DATA* keyData, uint8_t *buf, size_t bufLen, size_t *outSize) {
    return Tss2_MU_TPM2B_PRIVATE_Marshal(&keyData->priv, buf, bufLen, outSize);
}

static TSS2_RC _marshal_public(const KEYISO_TPM_KEY_DATA* keyData, uint8_t *buf, size_t bufLen, size_t *outSize) {
    return Tss2_MU_TPM2B_PUBLIC_Marshal(&keyData->pub, buf, bufLen, outSize);
}

// Using strategy design pattern to marshal private and public key data as the marshaling done by different APIs that each expect different data types(but all the other code is common)
MarshalStrategy PrivateMarshalStrategy = { _marshal_private };
MarshalStrategy PublicMarshalStrategy = { _marshal_public };

static int _marshal_and_set(const char* title, ASN1_OCTET_STRING *octetStr, 
                            const KEYISO_TPM_KEY_DATA* keyData,
                            size_t marshaledDataLen, MarshalStrategy strategy)
{
    TSS2_RC rc;
    uint8_t* buf = NULL;
    size_t bufLen = 0;

    if (octetStr == NULL || keyData == NULL) {
        KEYISOP_trace_log_error(NULL, 0, title, "marshal and set according to strategy failed", "invalid parameters");
        return STATUS_FAILED;
    }

    buf = (uint8_t *) KeyIso_zalloc(marshaledDataLen);
    if (buf == NULL) {
        KEYISOP_trace_log_error(NULL, 0, title, "marshal and set according to strategy failed", "memory allocation failed");
        return STATUS_FAILED;
    }

    rc = strategy.marshal_func(keyData, &buf[0], marshaledDataLen, &bufLen);
    if (rc != TSS2_RC_SUCCESS) {
        KEYISOP_trace_log_error_para(NULL, 0, title, "marshal and set according to strategy failed", "failed to marshal data", "rc: %d", rc);
        KeyIso_free(buf);
        return STATUS_FAILED;
    }

    if (ASN1_OCTET_STRING_set(octetStr, buf, bufLen) != 1) {
        KEYISOP_trace_log_openssl_error_para(NULL, 0, title, "marshal and set according to strategy failed", "ASN1_OCTET_STRING_set failed");
        
        KeyIso_free(buf);
        return STATUS_FAILED;
    }

    KeyIso_free(buf);
    return STATUS_OK;   
}

static int _cleanup_tpm_pbeparam(int ret, const char *title, const char *msg, KMPP_TPM_PBEPARAM *pbeParam)
{
    if (pbeParam != NULL) {
        if (pbeParam->parentHandle != NULL) {
            ASN1_STRING_free(pbeParam->parentHandle);
            pbeParam->parentHandle = NULL;
        }
        KMPP_TPM_PBEPARAM_free(pbeParam);
        pbeParam = NULL;
    }
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_openssl_error(NULL, 0, title, msg);
    }
    return ret;
}

#define _CLEANUP_TPM_PBEPARAM(ret, title, msg) \
    _cleanup_tpm_pbeparam(ret, title, msg, pbeParam)

static int _pbe_set_algor(
    const char* title,
    X509_ALGOR *algor,
    const KEYISO_TPM_KEY_DATA* keyData)
{
    ASN1_STRING *pbeParamStr = NULL;
    int ret = STATUS_FAILED;
    KMPP_TPM_PBEPARAM *pbeParam = NULL;
    ASN1_OBJECT *kmppTpmObj = NULL;

    if (algor == NULL || keyData == NULL) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_TPM_GEN_KEY_TITLE, "set PBE algorithm", "invalid parameters");
        return _CLEANUP_TPM_PBEPARAM(STATUS_FAILED, title, "invalid parameters");
    }

    ERR_clear_error();

    pbeParam = KMPP_TPM_PBEPARAM_new();
    if (pbeParam == NULL) {
        return _CLEANUP_TPM_PBEPARAM(STATUS_FAILED, title, "KMPP_TPM_PBEPARAM_new failed");
    }
    
    ret = _marshal_and_set(title, pbeParam->pub, keyData, sizeof(keyData->pub), PublicMarshalStrategy);
    if (ret != STATUS_OK) {
        return _CLEANUP_TPM_PBEPARAM(STATUS_FAILED, title, "marshal_and_set failed for public key");
    }
    
    if (ASN1_INTEGER_set(pbeParam->parentHandle, keyData->parentHandle) != 1) {
         return _CLEANUP_TPM_PBEPARAM(STATUS_FAILED, title, "OASN1_INTEGER_set failed");
    }
 
    pbeParam->isAuth = (keyData->auth.size > 0) ? 0xFF : 0x00;

    if (!ASN1_item_pack(pbeParam, ASN1_ITEM_rptr(KMPP_TPM_PBEPARAM), &pbeParamStr)) {
        return _CLEANUP_TPM_PBEPARAM(STATUS_FAILED, title, "ASN1_item_pack failed");
    }

    kmppTpmObj = OBJ_txt2obj(OID_KMPP_ALGO_TPM_ISO, KMPP_OID_NO_NAME);
    if (kmppTpmObj == NULL) {
        return _CLEANUP_TPM_PBEPARAM(STATUS_FAILED, title, "OBJ_txt2obj failed");
    }

    ret = X509_ALGOR_set0(algor, kmppTpmObj, V_ASN1_SEQUENCE, pbeParamStr);
    if (!ret) {
        return _CLEANUP_TPM_PBEPARAM(STATUS_FAILED, title, "X509_ALGOR_set0 failed");
    }

    return _CLEANUP_TPM_PBEPARAM(STATUS_OK, NULL, NULL);
}

static int _cleanup_tpm_create_pkcs8_enckey(int ret, const char* msg, X509_SIG *p8)
{
    const char* title = KEYISOP_TPM_GEN_KEY_TITLE;
    if (ret != STATUS_OK) {
        X509_SIG_free(p8);
        KEYISOP_trace_log_openssl_error(NULL, 0, title, msg);
    }
    return ret;
}

#define CLEANUP_TPM_CREATE_PKCS8_ENCKEY(ret, msg) \
    _cleanup_tpm_create_pkcs8_enckey(ret, msg, p8)


int KeyIso_tpm_create_p8_from_keydata(
    const KEYISO_TPM_KEY_DATA* inEnKeyData,
    X509_SIG **outP8)
{
    const char* title = KEYISOP_TPM_KMPP_PBE_TITLE;
    int ret = STATUS_FAILED;
    X509_SIG *p8 = NULL;
    X509_ALGOR *alg = NULL;
    ASN1_STRING *enckey = NULL;

    if (inEnKeyData == NULL || outP8 == NULL) {
        KEYISOP_trace_log_error(NULL, 0, title, "create enckey from p8", "invalid parameters");
        return STATUS_FAILED;
    }
    
    *outP8 = NULL;
    ERR_clear_error();
    p8 = X509_SIG_new();
    if (!p8) {
        KEYISOP_trace_log_openssl_error(NULL, 0, title, "X509_SIG_new");
        return STATUS_FAILED;
    }

    X509_SIG_getm(p8, &alg, &enckey);

    // Set PBE algorithm, all the parameters that are used to load the tpm key are stored inside x509_algor
    ret = _pbe_set_algor(title, alg, inEnKeyData);
    if (ret != STATUS_OK) {
        return CLEANUP_TPM_CREATE_PKCS8_ENCKEY(ret, "failed to set PBE algorithm");
    }

    // The encrypted TPM key itself is stored inside the ASN1 octet STRING
    ret = _marshal_and_set(title, enckey, inEnKeyData, sizeof(inEnKeyData->priv), PrivateMarshalStrategy);
    if (ret != STATUS_OK) {
        return CLEANUP_TPM_CREATE_PKCS8_ENCKEY(STATUS_FAILED, "marshal_and_set failed for private key");
    }
    
    *outP8 = p8;
    return CLEANUP_TPM_CREATE_PKCS8_ENCKEY(STATUS_OK, NULL); // Used in generate rsa key pair so cant return null and need to return STATUS_OK
}

static int _cleanup_create_enckey_from_p8(int ret, const char* title, const char* msg, KMPP_TPM_PBEPARAM* pbe, KEYISO_TPM_KEY_DATA* keyData)
{
    if (ret != STATUS_OK) {
       KeyIso_free(keyData);
       KEYISOP_trace_log_openssl_error(NULL, 0, title, msg);
    }
    if (pbe != NULL) {
            KMPP_TPM_PBEPARAM_free(pbe);
    }
    return ret;
}

#define _CLEANUP_CREATE_ENCKEY_FROM_P8(ret, msg) \
    _cleanup_create_enckey_from_p8(ret, title, msg, pbe, keyData)

int KeyIso_tpm_create_keydata_from_p8(
    const X509_SIG *inP8,
    KEYISO_TPM_KEY_DATA** pKeyData)
{
    const char* title = KEYISOP_TPM_KMPP_PBE_TITLE;
    const unsigned char *encKeyData = NULL;
    int encKeyLen = 0;
    KMPP_TPM_PBEPARAM* pbe = NULL;
    KEYISO_TPM_KEY_DATA* keyData = NULL;
    const void* param = NULL;
    const X509_ALGOR* alg = NULL;
    const ASN1_OCTET_STRING* osEncKey = NULL;

    if (inP8 == NULL || pKeyData == NULL) {
        _CLEANUP_CREATE_ENCKEY_FROM_P8(STATUS_FAILED, "invalid parameters");
    }

    ERR_clear_error();
    *pKeyData = NULL;

    X509_SIG_get0(inP8, &alg, &osEncKey);
    if (alg == NULL || osEncKey == NULL) {
        _CLEANUP_CREATE_ENCKEY_FROM_P8(STATUS_FAILED, "X509_SIG_get0 failed - failed to retrieve the encrypted key");
    }

    param = KeyIso_pbe_get_algor_param_asn1(title, alg, OID_KMPP_ALGO_TPM_ISO);
    if (!param) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "KeyIso_pbe_get_algor_param_asn1", "Failed");
        return STATUS_FAILED;
    }
    pbe = ASN1_item_unpack(param, ASN1_ITEM_rptr(KMPP_TPM_PBEPARAM));
    if (pbe == NULL) {
        KEYISOP_trace_log_openssl_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "ASN1_item_unpack");
        return STATUS_FAILED;
    }

    keyData = (KEYISO_TPM_KEY_DATA*)KeyIso_zalloc(sizeof(KEYISO_TPM_KEY_DATA));
    if (keyData == NULL) {
        return _CLEANUP_CREATE_ENCKEY_FROM_P8(STATUS_FAILED, "memory allocation failed");
    }

    keyData->parentHandle = ASN1_INTEGER_get(pbe->parentHandle);

    TSS2_RC  rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(pbe->pub->data, pbe->pub->length, NULL, &keyData->pub);
    if (rc != TSS2_RC_SUCCESS) {
        return _CLEANUP_CREATE_ENCKEY_FROM_P8(STATUS_FAILED, "Tss2_MU_TPM2B_PUBLIC_Unmarshal failed");
    }

    if (pbe->isAuth) {
        return _CLEANUP_CREATE_ENCKEY_FROM_P8(STATUS_FAILED, "auth is not supported in this version");
    }

    // Encrypted key bytes
    encKeyLen = ASN1_STRING_length(osEncKey);
    encKeyData = ASN1_STRING_get0_data(osEncKey);
    if (encKeyLen <= 0 || encKeyData == NULL) {
        return _CLEANUP_CREATE_ENCKEY_FROM_P8(STATUS_FAILED, "ASN1_STRING_get0_data failed to get enckey");
    }

    rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(encKeyData, encKeyLen, NULL, &keyData->priv);
    if (rc != TSS2_RC_SUCCESS) {
        return _CLEANUP_CREATE_ENCKEY_FROM_P8(STATUS_FAILED, "Tss2_MU_TPM2B_PRIVATE_Unmarshal failed");
    }
    
    *pKeyData = keyData;
    return _CLEANUP_CREATE_ENCKEY_FROM_P8(STATUS_OK, NULL);
}
