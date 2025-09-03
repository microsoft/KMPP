/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <string.h>

#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include "keyisocommon.h"
#include "keyisomemory.h"
#include "keyisolog.h"
#include "keyisoclientinternal.h"
#include "keyisoservicecommon.h"
#include <stdbool.h>


/* internal functions */

const void* KeyIso_pbe_get_algor_param_asn1(const char* title, const X509_ALGOR *alg, const char* expectedAlgOid)
{
    int paramType = 0;
    const void* param =  NULL;
    const ASN1_OBJECT* oid = NULL;

    if (alg == NULL) {
        KEYISOP_trace_log_error(NULL, 0, title, "get PBE algorithm parameters", "invalid parameters");
        return NULL;
    }
    
    ERR_clear_error();

    X509_ALGOR_get0(&oid, &paramType, &param, alg);
    if (oid == NULL || param == NULL) {
        KEYISOP_trace_log_openssl_error(NULL, 0, title, "get PBE algorithm parameters - failed to get PBE algorithm parameters");
        return NULL;
    }
    
    if (paramType != V_ASN1_SEQUENCE) {
        KEYISOP_trace_log_error(NULL, 0, title, "get PBE algorithm parameters", "invalid parameter type");
        return NULL;
    }

    if(!KeyIso_is_equal_oid(oid, expectedAlgOid)) {
        KEYISOP_trace_log_error(NULL, 0, title, "get PBE algorithm parameters", "invalid oid");
        return NULL;
    }

    return param;
}

bool KeyIso_is_equal_oid(const ASN1_OBJECT *oid, const char* expectedAlgOid)
{
    size_t oid_length = 0;
    size_t oid_txt_length = 0;
    bool isValid = false;

    if (!oid) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "Algorithm identifier", "Failed to get OID");
        return isValid;
    }

    oid_length = OBJ_length(oid);
    if (!oid_length) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "Algorithm identifier", "OID length is zero");
        return isValid;
    }
    
    // Calculating the length for the oid text buffer
    // OBJ_obj2txt returns the length of the string written to buf if buf is not NULL and buf_len is big enough, 
    // otherwise the total string length. Note that this does not count the trailing NUL character.
    oid_txt_length = OBJ_obj2txt(NULL, 0, oid, KMPP_OID_NO_NAME);
    char *oid_txt = (char *) KeyIso_zalloc(oid_txt_length + 1);
    if (!oid_txt) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "Memory allocation", "Failed");
        return isValid;
    }

    if (OBJ_obj2txt(oid_txt, oid_txt_length + 1, oid, KMPP_OID_NO_NAME) != oid_txt_length) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "OBJ_obj2txt", "Failed");
        KeyIso_free(oid_txt);
        return isValid;
    }
    
    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_OPEN_KEY_TITLE, "Algorithm parameters:algorithm identifier", "OID: %s", oid_txt);
    isValid = (strcmp(oid_txt, expectedAlgOid) == 0);
    KeyIso_free(oid_txt);
    return isValid;
}

static int _create_pkcs8_enckey_cleanup(
    int ret,
    const char* msg,
    X509_SIG *p8,
    ASN1_OBJECT *algObj)
{
    if (ret != STATUS_OK) {
        if (msg != NULL) {
            KEYISOP_trace_log_openssl_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, msg);
        }
        if (p8) {
            X509_SIG_free(p8);
        }
        if (algObj) {
            ASN1_OBJECT_free(algObj);
        }
    }
    return ret;
}

int KeyIso_create_pkcs8_enckey(
    unsigned int opaqueEncryptedKeyLen,
    const unsigned char *opaqueEncryptedKey, 
    X509_SIG **outP8)
{   
    X509_SIG *p8 = NULL;
    X509_ALGOR *alg = NULL;
    ASN1_STRING *enckey = NULL;
    ASN1_OBJECT *kmpp_obj = NULL;

    if (opaqueEncryptedKey == NULL || opaqueEncryptedKeyLen == 0) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "input parameter", "opaqueEncryptedKey is NULL");
        return STATUS_FAILED;
    }

    if (outP8 == NULL) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "output parameter", "outP8 is NULL");
        return STATUS_FAILED;
    }

    *outP8 = NULL;
    ERR_clear_error();

    kmpp_obj = OBJ_txt2obj(OID_KMPP_ALGO, KMPP_OID_NO_NAME);
    if (kmpp_obj == NULL) {
        return _create_pkcs8_enckey_cleanup(STATUS_FAILED, "OBJ_txt2obj", p8, kmpp_obj);
    }

    p8 = X509_SIG_new();
    if (p8 == NULL) {
        return _create_pkcs8_enckey_cleanup(STATUS_FAILED, "X509_SIG_new", p8, kmpp_obj);
    }

    X509_SIG_getm(p8, &alg, &enckey);

    // If ptype is V_ASN1_UNDEF, the parameter is omitted and pval is ignored
    if (!X509_ALGOR_set0(alg, kmpp_obj, V_ASN1_UNDEF, NULL)) {
        return _create_pkcs8_enckey_cleanup(STATUS_FAILED, "X509_ALGOR_set0", p8, kmpp_obj);
    }

    // X509_ALGOR_set0() takes ownership of kmpp_obj and will free it when the algorithm object is freed
    kmpp_obj = NULL;


    // Setting encrypted key bytes
    char *opaqueEncryptedKeyStr = (char *)KeyIso_zalloc(opaqueEncryptedKeyLen + 1);
    if (opaqueEncryptedKeyStr == NULL) {
        // allocation failed
        return _create_pkcs8_enckey_cleanup(STATUS_FAILED, NULL, p8, kmpp_obj);
    }
    memcpy(opaqueEncryptedKeyStr, opaqueEncryptedKey, opaqueEncryptedKeyLen);
    opaqueEncryptedKeyStr[opaqueEncryptedKeyLen] = '\0';
    ASN1_STRING_set0(enckey, opaqueEncryptedKeyStr, opaqueEncryptedKeyLen);

    *outP8 = p8;
    return STATUS_OK;
}

int KeyIso_create_enckey_from_p8(
    const X509_SIG *p8,
    unsigned int *opaqueEncryptedKeyLen,
    unsigned char **opaqueEncryptedKey)
{
    if (p8 == NULL || opaqueEncryptedKeyLen == NULL || opaqueEncryptedKey == NULL) {
        // Invalid arguments
        return STATUS_FAILED;
    }
    *opaqueEncryptedKeyLen = 0;
    *opaqueEncryptedKey = NULL;

    const X509_ALGOR *alg = NULL;
    const ASN1_STRING *enckey = NULL;
    const ASN1_OBJECT* oid = NULL;

    unsigned int opaqueKeyLen = 0;
    const unsigned char *opaqueKeyData = NULL;

    ERR_clear_error();

    X509_SIG_get0(p8, &alg, &enckey);
    if (alg == NULL || enckey == NULL) {
        KEYISOP_trace_log_openssl_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "X509_SIG_get0");
        return STATUS_FAILED;
    }

    // Check if the algorithm is KMPP
    X509_ALGOR_get0(&oid, NULL, NULL, alg);
    if (oid == NULL || !KeyIso_is_equal_oid(oid, OID_KMPP_ALGO)) {
        KEYISOP_trace_log_openssl_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "invalid algorithm OID");
        return STATUS_FAILED;
    }

    opaqueKeyLen = ASN1_STRING_length(enckey);
    opaqueKeyData = ASN1_STRING_get0_data(enckey);
    if (opaqueKeyData == NULL || opaqueKeyLen == 0) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "encrypted key data", "can't be NULL");
        return STATUS_FAILED;
    }

    *opaqueEncryptedKey = (unsigned char *)KeyIso_zalloc(opaqueKeyLen);
    if (*opaqueEncryptedKey == NULL) {
        // Memory allocation failed
        return STATUS_FAILED;
    }
    memcpy(*opaqueEncryptedKey, opaqueKeyData, opaqueKeyLen);

    *opaqueEncryptedKeyLen = opaqueKeyLen;
    return STATUS_OK;
}