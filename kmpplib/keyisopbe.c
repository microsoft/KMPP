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
#include <stdbool.h>

/* KMPP password-based encryption parameters structure */

typedef struct KMPP_PBEPARAM_st {
    ASN1_INTEGER *version;
    ASN1_OCTET_STRING *salt;
    ASN1_OCTET_STRING *hmac;
    ASN1_OCTET_STRING *iv;
} KMPP_PBEPARAM;

// The following sequence defines the ASN.1 data structure of KMPP_PBEPARAM.
// The sequence is packed to an OCTET_STRING that is set to the parameters
// property of the Encryption Algorithm Identifier
ASN1_SEQUENCE(KMPP_PBEPARAM) = {
    ASN1_SIMPLE(KMPP_PBEPARAM, version, ASN1_INTEGER),
    ASN1_SIMPLE(KMPP_PBEPARAM, salt, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KMPP_PBEPARAM, iv, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KMPP_PBEPARAM, hmac, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(KMPP_PBEPARAM)

// new, free, d2i & i2d functions for KMPP_PBEPARAM 
IMPLEMENT_ASN1_FUNCTIONS(KMPP_PBEPARAM)

/* internal functions */

static int _get_enc_key_params_failure(
    unsigned char *salt, 
    unsigned char *iv, 
    unsigned char *hmac, 
    unsigned char *encKeyBuf,
    const char *str)
{
    KeyIso_free(salt);
    KeyIso_free(iv);
    KeyIso_free(hmac);
    KeyIso_free(encKeyBuf);
    KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "_get_enc_key_params", str);
    return STATUS_FAILED;
}

int _pbe_set_algor_failure(
    KMPP_PBEPARAM *pbe,
    ASN1_STRING *str)
{
    ASN1_STRING_free(str);
    KMPP_PBEPARAM_free(pbe);
    return STATUS_FAILED;
}

static int _pbe_get_algor_params_failure(
    unsigned char *salt,
    unsigned char *iv,
    KMPP_PBEPARAM *pbe)
{
    KeyIso_free(salt);
    KeyIso_free(iv);
    KMPP_PBEPARAM_free(pbe);
    return STATUS_FAILED;
}

static int _create_pkcs8_enckey_failure(
    unsigned char *salt,
    unsigned char *iv,
    unsigned char *hmac,
    unsigned char *encKeyBuf,
    X509_SIG *p8)
{
    KeyIso_free(salt);
    KeyIso_free(iv);
    KeyIso_free(hmac);
    KeyIso_free(encKeyBuf);
    X509_SIG_free(p8);
    return STATUS_FAILED;
}

static int _create_enckey_from_p8_failure(
    KMPP_PBEPARAM *pbe, 
    const char* loc,
    const char* err)
{
    KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, loc, err);
    KMPP_PBEPARAM_free(pbe);
    return STATUS_FAILED;
}

static int _alloc_and_copy(
    const char *title,
    unsigned char **toBuf, 
    const unsigned char *fromBuf, 
    const unsigned int len)
{
    if (!fromBuf || !toBuf) {
        KEYISOP_trace_log_error(NULL, 0, title, "missing parameter", "NULL");
        return STATUS_FAILED;
    }
        
    if (*toBuf) {
        KeyIso_free(*toBuf);
        *toBuf = NULL;
    }   

    *toBuf = (unsigned char *) KeyIso_zalloc(len);
    if (!*toBuf) {
        KEYISOP_trace_log_error(NULL, 0, title, "Allocation", "Failed");
        return STATUS_FAILED;
    }

    memcpy(*toBuf, fromBuf, len);
    return STATUS_OK;
}

static int _asn1_string_get(
    ASN1_STRING *inStr,
    unsigned int *outBytesLen,
    unsigned char **outBytes)
{
    unsigned int length = 0;
    const unsigned char *data = NULL;

    if (!outBytes) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "output parameter", "outBytes is NULL");
        return STATUS_FAILED;
    }

    if (!outBytesLen) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "output parameter", "outBytesLen is NULL");
        return STATUS_FAILED;
    }

    *outBytesLen = 0;
    *outBytes = NULL;

    ERR_clear_error();

    length = ASN1_STRING_length(inStr);
    data = ASN1_STRING_get0_data(inStr);

    if (!data) {
        KEYISOP_trace_log_openssl_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "ASN1_STRING_get0_data");
        return STATUS_FAILED;
    }

    *outBytes = (unsigned char *) KeyIso_zalloc(length);
    if (!*outBytes) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "Allocation", "Failed");
        return STATUS_FAILED;
    }

    memcpy(*outBytes, data, length);
    *outBytesLen = length;
    
    return STATUS_OK;
}

static int _asn1_string_set(
    ASN1_STRING *str, 
    const unsigned char *inBuf,
    unsigned int inBufLen)
{
    unsigned char *buf = NULL;

    if (!inBuf) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "input parameter", "input buffer is NULL");
        return STATUS_FAILED;
    }

    // Do not free buf by KeyIso_free.
    // The following buf will be set to be the data of the input ASN1_STRING.
    buf = (unsigned char *) KeyIso_zalloc(inBufLen);
    if (!buf) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "Allocation", "Failed");
        return STATUS_FAILED;
    }

    memcpy(buf, inBuf, inBufLen);
    ASN1_STRING_set0(str, buf, inBufLen);

    return STATUS_OK;
}

static int _pbe_set_algor(
    X509_ALGOR *algor,
    unsigned long version,
    const unsigned char *salt, 
    unsigned int saltlen,
    const unsigned char *iv, 
    unsigned int ivlen,
    const unsigned char *hmac, 
    unsigned int hmaclen)
{
    int ret = STATUS_FAILED;

    KMPP_PBEPARAM *pbe = NULL;
    ASN1_STRING *pbe_param_str = NULL;
    ASN1_OBJECT *kmpp_obj = NULL;

    ERR_clear_error();
    
    pbe = KMPP_PBEPARAM_new();
    if (pbe == NULL) {
        KEYISOP_trace_log_openssl_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "KMPP_PBEPARAM_new");
        return STATUS_FAILED;
    }

    ret = ASN1_INTEGER_set_uint64(pbe->version, version); 
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "ASN1_INTEGER_set", "version");
        return _pbe_set_algor_failure(pbe, pbe_param_str);
    }

    ret = _asn1_string_set(pbe->salt, salt, saltlen);
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "_asn1_string_set", "salt");
        return _pbe_set_algor_failure(pbe, pbe_param_str);
    }

    ret = _asn1_string_set(pbe->iv, iv, ivlen);
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "_asn1_string_set", "iv");
        return _pbe_set_algor_failure(pbe, pbe_param_str);
    }

    ret = _asn1_string_set(pbe->hmac, hmac, hmaclen);
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "_asn1_string_set", "hmac");
        return _pbe_set_algor_failure(pbe, pbe_param_str);
    }

    if (!ASN1_item_pack(pbe, ASN1_ITEM_rptr(KMPP_PBEPARAM), &pbe_param_str)) {
        KEYISOP_trace_log_openssl_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "ASN1_item_pack");
        return _pbe_set_algor_failure(pbe, pbe_param_str);
    }

    kmpp_obj = OBJ_txt2obj(OID_KMPP_ALGO, KMPP_OID_NO_NAME);
    if (kmpp_obj == NULL) {
        KEYISOP_trace_log_openssl_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "OBJ_txt2obj");
        return _pbe_set_algor_failure(pbe, pbe_param_str);
    }

    ret = X509_ALGOR_set0(algor, kmpp_obj, V_ASN1_SEQUENCE, pbe_param_str);
    if (!ret) {
        KEYISOP_trace_log_openssl_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "X509_ALGOR_set0");
        return _pbe_set_algor_failure(pbe, pbe_param_str);
    }

    KMPP_PBEPARAM_free(pbe);
    return STATUS_OK;
}

/* KMPP password-based encryption functions */

// returns an initialized KMPP algorithm object on success, 
// or NULL on failure.
X509_ALGOR *KeyIso_pbe_set_algor(
    unsigned long version,
    const unsigned char *salt, 
    unsigned int saltLen,
    const unsigned char *iv, 
    unsigned int ivLen,
    const unsigned char *hmac, 
    unsigned int hmacLen)
{
    X509_ALGOR *ret = NULL;

    ERR_clear_error();

    ret = X509_ALGOR_new();
    if (ret == NULL) {
        KEYISOP_trace_log_openssl_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "X509_ALGOR_new");
        return NULL;
    }
    
    // setting algorithm parameters
    if (_pbe_set_algor(ret, version, salt, saltLen, iv, ivLen, hmac, hmacLen) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "_pbe_set_algor", "Failed");
        X509_ALGOR_free(ret);
        return NULL;
    }
    
    return ret;
}

static KMPP_PBEPARAM* _pbe_get_algor_params(const char *title, const X509_ALGOR * alg)
{
    KMPP_PBEPARAM *pbe = NULL;
    const void* asn1Param = KeyIso_pbe_get_algor_param_asn1(KEYISOP_OPEN_KEY_TITLE, alg, OID_KMPP_ALGO);
    if (!asn1Param) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "KeyIso_pbe_get_algor_param_asn1", "Failed");
        return NULL;
    }
    pbe = ASN1_item_unpack(asn1Param, ASN1_ITEM_rptr(KMPP_PBEPARAM));
    if (pbe == NULL) {
        KEYISOP_trace_log_openssl_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "ASN1_item_unpack");
        return NULL;
    }
    return pbe;
}

// Retrieving algorithm parameters
int KeyIso_pbe_get_algor_params(
    const X509_ALGOR *alg,
    unsigned int *version,
    unsigned char **salt, 
    unsigned int *saltLen,
    unsigned char **iv, 
    unsigned int *ivLen,
    unsigned char **hmac, 
    unsigned int *hmacLen)
{
    int ret = STATUS_FAILED; 
    KMPP_PBEPARAM *pbe = NULL;
    unsigned long algVersion = 0;

    if (!alg) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "Algorithm", "Missing algorithm");
        return STATUS_FAILED;
    }

    if (!version) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "version", "Missing version");
        return STATUS_FAILED;
    }

    pbe = _pbe_get_algor_params(KEYISOP_OPEN_KEY_TITLE, alg);
    if (!pbe) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "_pbe_get_algor_params", "Failed");
        return STATUS_FAILED;
    }            
   
    ret = ASN1_INTEGER_get_uint64(&algVersion, pbe->version);
    if (!ret) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "_pbe_get_algor_params", "Failed to retrieve algorithm version");
        return _pbe_get_algor_params_failure(NULL, NULL, pbe);
    }
    *version = (unsigned int) algVersion;

    ret = _asn1_string_get(pbe->salt, saltLen, salt);
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "_asn1_string_get", "salt");
        return _pbe_get_algor_params_failure(NULL, NULL, pbe);
    }

    ret = _asn1_string_get(pbe->iv, ivLen, iv);
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "_asn1_string_get", "iv");
        return _pbe_get_algor_params_failure(*salt, NULL, pbe);
    }

    ret = _asn1_string_get(pbe->hmac, hmacLen, hmac);
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "_asn1_string_get", "hmac");
        return _pbe_get_algor_params_failure(*salt, *iv, pbe);
    }

    KMPP_PBEPARAM_free(pbe);
    return STATUS_OK;
}

int KeyIso_create_enckey_from_p8(
    const X509_SIG *inP8,
    KEYISO_ENCRYPTED_PRIV_KEY_ST **outEncKey)
{
    int index = 0;
    int saltlen = 0;
    int ivlen = 0;
    int hmaclen = 0;
    int enckeylen = 0;

    size_t structSize = 0;
    size_t dynBufLen = 0;
    
    unsigned long version = 0;

    const unsigned char *salt = NULL;
    const unsigned char *iv = NULL;
    const unsigned char *hmac = NULL;
    const unsigned char *enckeydata = NULL;

    KMPP_PBEPARAM *pbe = NULL;
    const X509_ALGOR *alg = NULL;
    const ASN1_OCTET_STRING *osenckey = NULL;

    if (!inP8)
        return _create_enckey_from_p8_failure(pbe, "input parameter", "inP8 is NULL");

    if (!outEncKey)
        return _create_enckey_from_p8_failure(pbe, "output parameter", "outEncKey is NULL");

    *outEncKey = NULL;

    X509_SIG_get0(inP8, &alg, &osenckey);
    if (!alg || !osenckey)
        return _create_enckey_from_p8_failure(pbe, "X509_SIG_get0", "Failed to get encrypted key");
    
    pbe = _pbe_get_algor_params(KEYISOP_OPEN_KEY_TITLE, alg);
    if (!pbe)
        return _create_enckey_from_p8_failure(pbe, "_pbe_get_algor_params", "Failed");

    // version
    if (!ASN1_INTEGER_get_uint64(&version, pbe->version))
       return _create_enckey_from_p8_failure(pbe, "ASN1_INTEGER", "Failed to get version");

    // salt
    saltlen = ASN1_STRING_length(pbe->salt);
    salt = ASN1_STRING_get0_data(pbe->salt);
    if (saltlen <= 0 || salt == NULL)
        return _create_enckey_from_p8_failure(pbe, "ASN1_STRING", "Failed to get salt");

    // iv
    ivlen = ASN1_STRING_length(pbe->iv);
    iv = ASN1_STRING_get0_data(pbe->iv);
    if (ivlen <= 0 || iv == NULL)
        return _create_enckey_from_p8_failure(pbe, "ASN1_STRING", "Failed to get iv");

    // hmac
    hmaclen = ASN1_STRING_length(pbe->hmac);
    hmac = ASN1_STRING_get0_data(pbe->hmac);
    if (hmaclen <= 0 || hmac == NULL)
        return _create_enckey_from_p8_failure(pbe, "ASN1_STRING", "Failed to get hmac");

    // encrypted key bytes
    enckeylen = ASN1_STRING_length(osenckey);
    enckeydata = ASN1_STRING_get0_data(osenckey);
    if (enckeylen <= 0 || enckeydata == NULL)
        return _create_enckey_from_p8_failure(pbe, "ASN1_STRING", "Failed to get enckey");
    
    dynBufLen = saltlen + ivlen + hmaclen + enckeylen;
    if (!dynBufLen)
        return _create_enckey_from_p8_failure(pbe, "KeyIso_get_enc_key_bytes_len", "total length is zero");

    structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_ENCRYPTED_PRIV_KEY_ST, dynBufLen);
    KEYISO_ENCRYPTED_PRIV_KEY_ST* pEncKeySt = (KEYISO_ENCRYPTED_PRIV_KEY_ST *) KeyIso_zalloc(structSize);
    if (!pEncKeySt)
        return _create_enckey_from_p8_failure(pbe, "KeyIso_zalloc", "memory allocation failed");

    pEncKeySt->algVersion = (unsigned int) version;
    pEncKeySt->saltLen = saltlen;
    pEncKeySt->ivLen = ivlen;
    pEncKeySt->hmacLen = hmaclen;
    pEncKeySt->encKeyLen = enckeylen;

    memcpy(&pEncKeySt->encryptedKeyBytes[index], salt, saltlen);
    index += saltlen;
    memcpy(&pEncKeySt->encryptedKeyBytes[index], iv, ivlen);
    index += ivlen;
    memcpy(&pEncKeySt->encryptedKeyBytes[index], hmac, hmaclen);
    index += hmaclen;
    memcpy(&pEncKeySt->encryptedKeyBytes[index], enckeydata, enckeylen);
    index += enckeylen;

    *outEncKey = pEncKeySt;

    KMPP_PBEPARAM_free(pbe);
    return STATUS_OK;
}

// Retrieving encryption parameters
int KeyIso_get_enc_key_params(
    const KEYISO_ENCRYPTED_PRIV_KEY_ST *inEncKey,
    unsigned long *version,
    unsigned char **salt,
    unsigned int *saltLen,
    unsigned char **iv,
    unsigned int *ivLen,
    unsigned char **hmac,
    unsigned int *hmacLen,
    unsigned char **encKeyBuf,
    unsigned int *encKeyLen)
{
    int ret = STATUS_FAILED;
    int index = 0;

    if (!inEncKey) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "input parameter", "inEncKey is NULL");
        return STATUS_FAILED;
    }

    // version
    if (version) {
        *version = (unsigned long) inEncKey->algVersion;
    }

    // salt
    ret = _alloc_and_copy(KEYISOP_OPEN_KEY_TITLE, salt, &inEncKey->encryptedKeyBytes[index], inEncKey->saltLen);
    if (ret != STATUS_OK)
        return _get_enc_key_params_failure(*salt, *iv, *hmac, *encKeyBuf, "salt");
    if (saltLen)
        *saltLen = inEncKey->saltLen;
    
    // iv
    index += inEncKey->saltLen;
    ret = _alloc_and_copy(KEYISOP_OPEN_KEY_TITLE, iv, &inEncKey->encryptedKeyBytes[index], inEncKey->ivLen);
    if (ret != STATUS_OK)
        return _get_enc_key_params_failure(*salt, *iv, *hmac, *encKeyBuf, "iv");
    if (ivLen)
        *ivLen = inEncKey->ivLen;

    // hmac
    index += inEncKey->ivLen;
    ret = _alloc_and_copy(KEYISOP_OPEN_KEY_TITLE, hmac, &inEncKey->encryptedKeyBytes[index], inEncKey->hmacLen);
    if (ret != STATUS_OK)
        return _get_enc_key_params_failure(*salt, *iv, *hmac, *encKeyBuf, "hmac");
    if (hmacLen)
        *hmacLen = inEncKey->hmacLen;

    // encrypted private key
    index += inEncKey->hmacLen;
    ret = _alloc_and_copy(KEYISOP_OPEN_KEY_TITLE, encKeyBuf, &inEncKey->encryptedKeyBytes[index], inEncKey->encKeyLen);
    if (ret != STATUS_OK)
        return _get_enc_key_params_failure(*salt, *iv, *hmac, *encKeyBuf, "encKey");
    if (encKeyLen)
        *encKeyLen = inEncKey->encKeyLen;
    
    return STATUS_OK;
}

int KeyIso_create_pkcs8_enckey(
    const KEYISO_ENCRYPTED_PRIV_KEY_ST *inEncKey, 
    X509_SIG **outP8)
{
    int ret = STATUS_FAILED;
    
    X509_SIG *p8 = NULL;
    X509_ALGOR *alg = NULL;
    ASN1_STRING *enckey = NULL;

    unsigned int saltlen = 0;
    unsigned int ivlen = 0;
    unsigned int hmaclen = 0;
    unsigned int encKeyBuflen = 0;
    unsigned long version = 0;

    unsigned char *salt = NULL;
    unsigned char *iv = NULL;
    unsigned char *hmac = NULL;
    unsigned char *encKeyBuf = NULL;

    if (!inEncKey) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "input parameter", "inEncKey is NULL");
        return STATUS_FAILED;
    }

    if (!outP8) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "output parameter", "outP8 is NULL");
        return STATUS_FAILED;
    }

    *outP8 = NULL;

    ret = KeyIso_get_enc_key_params(
        inEncKey,
        &version,
        &salt, 
        &saltlen, 
        &iv, 
        &ivlen, 
        &hmac, 
        &hmaclen, 
        &encKeyBuf, 
        &encKeyBuflen);
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "KeyIso_get_enc_key_params", "Failed");
        return ret;
    }
    
    ERR_clear_error();

    p8 = X509_SIG_new();
    if (!p8) {
        KEYISOP_trace_log_openssl_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "X509_SIG_new");
        return _create_pkcs8_enckey_failure(salt, iv, hmac, encKeyBuf, p8);
    }

    X509_SIG_getm(p8, &alg, &enckey);
    
    // Setting algorithm parameters
    ret = _pbe_set_algor(
        alg,
        version,
        salt, 
        saltlen, 
        iv, 
        ivlen, 
        hmac, 
        hmaclen);
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "_pbe_set_algor", "Failed");
        return _create_pkcs8_enckey_failure(salt, iv, hmac, encKeyBuf, p8);
    }

    // Setting encrypted key bytes 
    ASN1_STRING_set0(enckey, encKeyBuf, encKeyBuflen);

    KeyIso_free(salt);
    KeyIso_free(iv);
    KeyIso_free(hmac);

    *outP8 = p8;
    return STATUS_OK;
}

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