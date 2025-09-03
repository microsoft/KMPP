/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <openssl/err.h>
#include <string.h>

#include "keyisoclientinternal.h"
#include "keyisocommon.h"
#include "keyisoipccommands.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisotpmclient.h"
#include "keyisotpmclientmsghandler.h"
#include "keyisotpmcrypto.h"
#include "keyisotpmkeymanagement.h"
#include "keyisotpmsetup.h"

//////////////////////////////////////////////////////////////////////////////////////
//
// Define the TPM implementation of the msg handler functions
//
//////////////////////////////////////////////////////////////////////////////////////
CLIENT_MSG_HANDLER_FUNCTIONS_TABLE_ST TPMMsgHandlerImplementation = {
    .init_key = KeyIso_client_tpm_msg_handler_init_key,
    .free_keyCtx = KeyIso_client_tpm_msg_handler_free_keyCtx,
    .close_key = KeyIso_client_tpm_msg_close_key,
    .rsa_private_encrypt_decrypt = KeyIso_client_tpm_msg_rsa_private_encrypt_decrypt,
    .ecdsa_sign = KeyIso_client_tpm_msg_ecdsa_sign, 
    .import_symmetric_key = KeyIso_client_tpm_msg_import_symmetric_key,
    .symmetric_key_encrypt_decrypt = KeyIso_client_tpm_msg_symmetric_key_encrypt_decrypt,
    .import_private_key = KeyIso_client_tpm_msg_import_private_key,
    .generate_rsa_key_pair = KeyIso_client_tpm_msg_generate_rsa_key_pair,
    .generate_ec_key_pair = KeyIso_client_tpm_msg_generate_ec_key_pair,
    .set_config = KeyIso_client_tpm_set_config
};

static TPMA_OBJECT _get_tpm_object(uint8_t keyUsage) 
{
    TPMA_OBJECT objectAttributes = 0;
    if (keyUsage & KMPP_KEY_USAGE_RSA_SIGN_ECDSA) {
        objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT; // SET (1) The private portion of the key may be used to sign. 
    }
    if (keyUsage & KMPP_KEY_USAGE_RSA_ENCRYPT_ECDH) {
        objectAttributes |= TPMA_OBJECT_DECRYPT; // SET (1) The private portion of the key may be used to encrypt/decrypt.
    }
    return objectAttributes;
}


static int _cleanup_rsa_pub_key_from_data(const uuid_t correlationId, int res, const char* msg, BIGNUM *n, BIGNUM *e, RSA* rsa, EVP_PKEY *pkey)
{
    const char* title = KEYISOP_TPM_GEN_KEY_TITLE;
    if (res != STATUS_OK) {
        KEYISOP_trace_log_openssl_error(correlationId, 0, title, msg);  
        EVP_PKEY_free(pkey);
    }
    BN_free(n);
    BN_free(e);
    RSA_free(rsa); 
    return res;
}
#define _CLEANUP_RSA_PUB_KEY_FROM_DATA(res, msg) \
    _cleanup_rsa_pub_key_from_data(correlationId, res, msg, n, e, rsa, pkey)

static int _get_rsa_public_key_from_key_data(const uuid_t correlationId, const KEYISO_TPM_KEY_DATA* keyData, EVP_PKEY** pubKey)
{
    const char* title = KEYISOP_TPM_GEN_KEY_TITLE;
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    
    if (keyData == NULL || pubKey == NULL) {
        return _CLEANUP_RSA_PUB_KEY_FROM_DATA(STATUS_FAILED, "invalid parameters");
    }
    if (keyData->pub.publicArea.type != TPM2_ALG_RSA) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "get public key from key data", "invalid key type", "type: %d", keyData->pub.publicArea.type);
        return _CLEANUP_RSA_PUB_KEY_FROM_DATA(STATUS_FAILED, "invalid key type");
    }

    TPM2B_PUBLIC_KEY_RSA publicKey = keyData->pub.publicArea.unique.rsa;

    ERR_clear_error();

    rsa = RSA_new();
    if (!rsa) {
       return _CLEANUP_RSA_PUB_KEY_FROM_DATA(STATUS_FAILED, "failed to create RSA");
    }

    n = BN_bin2bn(publicKey.buffer, publicKey.size, NULL);
    if (!n) {
        return _CLEANUP_RSA_PUB_KEY_FROM_DATA(STATUS_FAILED, "failed to create BIGNUM for modulus");
    }

    e = BN_new();
    if (!e) {
        return _CLEANUP_RSA_PUB_KEY_FROM_DATA(STATUS_FAILED, "failed to create BIGNUM for exponent");
    }

    if (BN_set_word(e, keyData->pub.publicArea.parameters.rsaDetail.exponent) != 1) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, 
        "get public key from key data", "BN_set_word failed", 
        "exponent: %d", keyData->pub.publicArea.parameters.rsaDetail.exponent);
        return _CLEANUP_RSA_PUB_KEY_FROM_DATA(STATUS_FAILED, "failed to set exponent");
    }

    if (RSA_set0_key(rsa, n, e, NULL) != 1) {
        return _CLEANUP_RSA_PUB_KEY_FROM_DATA(STATUS_FAILED, "failed to set RSA key");
    }
    
    // RSA_set0_key takes over the ownership of n and e and will free them when rsa is freed
    n = NULL;
    e = NULL;

    pkey = EVP_PKEY_new();
    if (!pkey) {
        return _CLEANUP_RSA_PUB_KEY_FROM_DATA(STATUS_FAILED, "failed to create EVP_PKEY");
    }

    // EVP_PKEY_set1_RSA increments the reference count of rsa
    if (EVP_PKEY_set1_RSA(pkey, rsa) != 1) {
        return _CLEANUP_RSA_PUB_KEY_FROM_DATA(STATUS_FAILED, "failed to set RSA key in EVP_PKEY");
    }

    *pubKey = pkey;
    return _CLEANUP_RSA_PUB_KEY_FROM_DATA(STATUS_OK, NULL);
}

static int _cleanup_generate_rsa_key_pair(const uuid_t correlationId, int res, const char* msg, KEYISO_TPM_KEY_DATA* keyData, EVP_PKEY* pubKey)
{
    const char* title = KEYISOP_TPM_GEN_KEY_TITLE;
    if (res != STATUS_OK) {
        EVP_PKEY_free(pubKey);
        KEYISOP_trace_log_error(correlationId, 0, title, "generate rsa key pair", msg);  
    }
    KeyIso_free(keyData);
    return res;
}

#define _CLEANUP_GENERATE_RSA_KEY_PAIR(res, msg) \
    _cleanup_generate_rsa_key_pair(correlationId, res, msg, keyData, pubKey)

int KeyIso_client_tpm_msg_generate_rsa_key_pair(
    const uuid_t correlationId,
    unsigned int rsaBits,
    uint8_t keyUsage, 
    EVP_PKEY **outPubKey,
    X509_SIG **outEncryptedKeyData,
    KEYISO_CLIENT_METADATA_HEADER_ST *outMetaData)
{
    const char* title = KEYISOP_TPM_GEN_KEY_TITLE;
    KEYISO_TPM_KEY_DATA* keyData = NULL;
    EVP_PKEY* pubKey = NULL;
    X509_SIG* encryptedKeyP8 = NULL;
    char* password = NULL;
    uint32_t exponent = 0;

    if (outPubKey == NULL || outEncryptedKeyData == NULL) {
        return _CLEANUP_GENERATE_RSA_KEY_PAIR(STATUS_FAILED, "invalid parameters");
    }

    if (KeyIso_rsa_generate_tpm_key(correlationId, password, exponent, rsaBits, _get_tpm_object(keyUsage), ESYS_TR_NONE, &keyData) != KEYISO_TPM_RET_SUCCESS) {
        return _CLEANUP_GENERATE_RSA_KEY_PAIR(STATUS_FAILED, "failed to generate rsa key");
    }

    if (_get_rsa_public_key_from_key_data(correlationId, keyData, &pubKey) != STATUS_OK) {        
        return _CLEANUP_GENERATE_RSA_KEY_PAIR(STATUS_FAILED, "failed to get public key from key data");
    }

    // KEYISO_TPM_KEY_DATA to X509_SIG
    if (KeyIso_tpm_create_p8_from_keydata(keyData, &encryptedKeyP8) != STATUS_OK) {
        return _CLEANUP_GENERATE_RSA_KEY_PAIR(STATUS_FAILED, "TPM pkcs8 key creation failed");
    }

    *outPubKey = pubKey;
    *outEncryptedKeyData = encryptedKeyP8;

    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "complete - generate rsa key pair succeeded");
    return _CLEANUP_GENERATE_RSA_KEY_PAIR(STATUS_OK, NULL);
}

static int _cleanup_get_pub_key_from_key_data(const uuid_t correlationId, int res,
                                              const char* loc,  const char* message,
                                              EC_POINT *ecPoint, EC_GROUP* ecGroup, EC_KEY* pubEckey,
                                              BIGNUM* x, BIGNUM* y)
{
    const char* title = KEYISOP_TPM_GEN_KEY_TITLE;
    if (res != STATUS_OK) {
        EC_GROUP_free(ecGroup);
        EC_KEY_free(pubEckey);
        KEYISOP_trace_log_error(correlationId, 0, title, loc, message);
    }
    
    BN_free(x);
    BN_free(y);
    EC_POINT_free(ecPoint);
    return res;
}

#define _CLEANUP_GET_PUB_KEY_FROM_KEY_DATA(res, loc, message) \
    _cleanup_get_pub_key_from_key_data(correlationId, res, loc, message, ecPoint, ecGroup, ecKey, x, y)  

static int _get_ec_public_key_from_key_data(const uuid_t correlationId, KEYISO_TPM_KEY_DATA* keyData, EC_GROUP** outEcGroup, EC_KEY** outPubKEckey)
{
    const char* title = KEYISOP_TPM_GEN_KEY_TITLE;
    EC_GROUP* ecGroup = NULL;
    EC_KEY* ecKey = NULL;
    EC_POINT *ecPoint = NULL;
    BIGNUM* x = NULL;
    BIGNUM* y = NULL;

    if (keyData == NULL || outEcGroup == NULL || outPubKEckey == NULL) {
        return _CLEANUP_GET_PUB_KEY_FROM_KEY_DATA(STATUS_FAILED, "get public key from key data", "invalid parameters");
    }
   
    if (keyData->pub.publicArea.type != TPM2_ALG_ECC) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "get public key from key data", "invalid key type", "type: %d", keyData->pub.publicArea.type);
        return _CLEANUP_GET_PUB_KEY_FROM_KEY_DATA(STATUS_FAILED, "get public key from key data", "invalid key type");
    }

    TPMI_ECC_CURVE tpmCurve = keyData->pub.publicArea.parameters.eccDetail.curveID;
    uint32_t curve = KeyIso_tpm_curve_to_ossl(tpmCurve);
    if (curve == NID_undef) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "get public key from key data", "unsupported curve", "curve: %d", tpmCurve);
        return _CLEANUP_GET_PUB_KEY_FROM_KEY_DATA(STATUS_FAILED, "get public key from key data", "unsupported curve");
    }

    if (KeyIso_get_ec_evp_pub_key(correlationId, curve, 
                                  keyData->pub.publicArea.unique.ecc.x.buffer, keyData->pub.publicArea.unique.ecc.x.size,
                                  keyData->pub.publicArea.unique.ecc.y.buffer, keyData->pub.publicArea.unique.ecc.y.size,  
                                  &ecKey, &ecGroup) != STATUS_OK) {
        
        return _CLEANUP_GET_PUB_KEY_FROM_KEY_DATA(STATUS_FAILED, "get public key from key data", "failed to get EVP_PKEY");
    }

    *outEcGroup = ecGroup;
    *outPubKEckey = ecKey;

    return _CLEANUP_GET_PUB_KEY_FROM_KEY_DATA(STATUS_OK, NULL, NULL);
}

int KeyIso_client_tpm_msg_generate_ec_key_pair(
    const uuid_t correlationId,
    unsigned int curve,
    uint8_t keyUsage,
    EC_GROUP** outGroup,
    EC_KEY** outPubKey,
    X509_SIG** outEncryptedPkeyP8,
    KEYISO_CLIENT_METADATA_HEADER_ST *outMetaData)
{
    const char* title = KEYISOP_TPM_GEN_KEY_TITLE;
    const char* password = NULL;
    KEYISO_TPM_RET res = KEYISO_TPM_RET_FAILURE;
    KEYISO_TPM_KEY_DATA* keyData = NULL;

    (void)outMetaData; // Not used in TPM

    if ( outEncryptedPkeyP8 == NULL || outPubKey == NULL || outGroup == NULL ) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_GEN_KEY_TITLE, "generate ec key pair", "invalid parameters");
        return STATUS_FAILED;
    }

    TPMI_ECC_CURVE  tpmCurve = KeyIso_ossl_curve_to_tpm(curve);
    if (tpmCurve == TPM2_ECC_NONE) {
        KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_GEN_KEY_TITLE, "generate ec key pair", "unsupported curve", "curve: %u", curve);
        return STATUS_FAILED;
    }
    
    if (KeyIso_ecc_generate_tpm_key(correlationId, password, tpmCurve, _get_tpm_object(keyUsage), ESYS_TR_NONE, &keyData) != KEYISO_TPM_RET_SUCCESS) {
        KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_GEN_KEY_TITLE, "generate ec key pair", "failed to generate tpm ec key", "key usage: %d", keyUsage);
        return STATUS_FAILED;
    }

    // KEYISO_TPM_KEY_DATA  to EC_GROUP  and EC_KEY
    res = _get_ec_public_key_from_key_data(correlationId, keyData, outGroup, outPubKey);
    if (res != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_GEN_KEY_TITLE, "generate ec key pair", "failed to get public key from key data");
        KeyIso_free(keyData);
        return STATUS_FAILED;
    }

    // KEYISO_TPM_KEY_DATA to X509_SIG
    if (KeyIso_tpm_create_p8_from_keydata(keyData, outEncryptedPkeyP8) != STATUS_OK) {
        KeyIso_free(keyData);
        EC_KEY_free(*outPubKey);
        EC_GROUP_free(*outGroup);
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_GEN_KEY_TITLE, "generate ec key pair", "TPM pkcs8 key creation failed");
        return STATUS_FAILED;
    }

    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "complete - generate ec key pair succeeded");
    KeyIso_free(keyData);
    return STATUS_OK;
}

static int _cleanup_tpm_key_open(const uuid_t correlationId, int res, const char* message, X509_SIG* p8, KEYISO_TPM_KEY_DATA *keyData)
{
    const char* title = KEYISOP_TPM_OPEN_KEY_TITLE;
    if (res != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, title, "tpm open key failed", message);
        KeyIso_free(keyData);
    } else {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, message);
    }
    X509_SIG_free(p8);
    return res;
}

#define _CLEANUP_TPM_KEY_OPEN(res, message) \
    _cleanup_tpm_key_open(correlationId, res, message, p8, keyData)

static int _tpm_key_open(const uuid_t correlationId, int keyLength, const unsigned char *keyBytes, KEYISO_TPM_KEY_DATA **outKeyData)
{
    X509_SIG* p8 = NULL;
    int ret = STATUS_FAILED;
    KEYISO_TPM_KEY_DATA *keyData = NULL;

    if (keyBytes == NULL || outKeyData == NULL) {
        return _CLEANUP_TPM_KEY_OPEN(STATUS_FAILED, "invalid parameters");
    }
    *outKeyData = NULL;

    // Convert pfxBytes to PKCS12 and parse to X509SIG (p8)
    ret = KeyIso_pkcs12_parse_p8(correlationId, keyLength, keyBytes, &p8, NULL, NULL);
    if (ret != STATUS_OK) {
        return _CLEANUP_TPM_KEY_OPEN(ret, "p8 - Parsing failed");
    }
        
    // Convert to encrypted key structure - KEYISO_TPM_KEY_DATA
    ret = KeyIso_tpm_create_keydata_from_p8(p8, &keyData);
    if (ret != STATUS_OK) {
        return _CLEANUP_TPM_KEY_OPEN(ret, "keyData - Parsing failed");
    }

    *outKeyData = keyData;
    return _CLEANUP_TPM_KEY_OPEN(STATUS_OK, "Complete - open key succeeded");
}


static int _cleanup_init_key(
    const uuid_t correlationId,
    int res,
    const char* message,
    KEYISO_TPM_KEY_DATA* encryptedKeyData,
    KEYISO_TPM_KEY_DETAILS* keyDetails)
{
    const char* title = KEYISOP_TPM_OPEN_KEY_TITLE;
    if ( res != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, title, "failed to init key", message);
        if (keyDetails != NULL) {
            KeyIso_tpm_key_close(correlationId, keyDetails);
            KeyIso_tpm_free_context(&keyDetails->tpmContext);
        }
    } else {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, message);
    }
    KeyIso_free(encryptedKeyData);
    return res;
}

# define _CLEANUP_INIT_KEY(res, message) \
    _cleanup_init_key(keyCtx->correlationId, res, message, encryptedKeyData, tpmKeyDetails)    

int KeyIso_client_tpm_msg_handler_init_key(
    KEYISO_KEY_CTX *keyCtx,
    int keyLength,
    const unsigned char *keyBytes,
    const char *param)
{
    KEYISO_TPM_CONTEXT* tpmContext = NULL;
    KEYISO_TPM_KEY_DATA* encryptedKeyData = NULL;
    KEYISO_TPM_KEY_DETAILS* tpmKeyDetails = NULL;
    
    if (keyCtx == NULL) {
        return STATUS_FAILED;
    }

    // Open key
    if (_tpm_key_open(keyCtx->correlationId, keyLength, keyBytes, &encryptedKeyData) != STATUS_OK) {
        return _CLEANUP_INIT_KEY(STATUS_FAILED, "failed to open key");
    }

    // Creating a TPM context for each key can provide better isolation between keys, 
    // as each key is associated with its own TPM context and provide also parallelism and help to manage TPM resource better
    if (KeyIso_tpm_create_context(keyCtx->correlationId, &tpmContext) != KEYISO_TPM_RET_SUCCESS) {
        return _CLEANUP_INIT_KEY(STATUS_FAILED, "failed to create tpm context");
    }

    // Load key to TPM
    KEYISO_TPM_RET result = KeyIso_load_tpm_key(keyCtx->correlationId, tpmContext, encryptedKeyData, &tpmKeyDetails);  
    if (result != KEYISO_TPM_RET_SUCCESS) {
        KeyIso_tpm_free_context(&tpmContext);
        return _CLEANUP_INIT_KEY(STATUS_FAILED, "failed to load tpm key");
    }

    keyCtx->keyDetails = tpmKeyDetails;
    return _CLEANUP_INIT_KEY(STATUS_OK, "Complete - init key succeeded");
}

static int _get_tpm_details_for_key(
    KEYISO_KEY_CTX *keyCtx,
    KEYISO_TPM_KEY_DETAILS **pTpmKeyDetails)
{
    if (keyCtx == NULL || keyCtx->keyDetails == NULL) {
        return STATUS_FAILED;
    }
    *pTpmKeyDetails = (KEYISO_TPM_KEY_DETAILS *)keyCtx->keyDetails;
    return STATUS_OK;
}

void KeyIso_client_tpm_msg_handler_free_keyCtx(
    KEYISO_KEY_CTX *keyCtx)
{
    if (keyCtx == NULL || keyCtx->keyDetails == NULL) {
        return;
    }

    KeyIso_free(keyCtx->keyDetails);
    keyCtx->keyDetails = NULL;    
}

void KeyIso_client_tpm_msg_close_key(
    KEYISO_KEY_CTX *keyCtx)
{
    const char* title = KEYISOP_KEY_TITLE;
    KEYISO_TPM_KEY_DETAILS *keyDetails = NULL;
    if (_get_tpm_details_for_key(keyCtx, &keyDetails) != STATUS_OK) {
        KEYISOP_trace_log(NULL, 0, title, "close key - failed to get tpm key details");
    }
    
    // Close key
    KeyIso_tpm_key_close(keyCtx->correlationId, keyDetails);
    KeyIso_tpm_free_context(&keyDetails->tpmContext);
    KeyIso_client_tpm_msg_handler_free_keyCtx(keyCtx);
    KEYISOP_trace_log(keyCtx->correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "complete - close key succeeded");
}

static int _client_tpm_rsa_sign(const KEYISO_TPM_KEY_DETAILS *keyDetails, const KEYISO_KEY_CTX *keyCtx, int flen, const unsigned char *from, int tlen, unsigned char *to)
{
    char* title = KEYISOP_TPM_RSA_SIGN_TITLE;
    KEYISO_RSA_SIGN rsaSign;
    int res = -1;

    unsigned int hashOffset = sizeof(rsaSign);
    uint32_t modulusSize = keyDetails->pub.publicArea.unique.rsa.size;
    if (KeyIso_retrieve_rsa_sig_data(keyCtx->correlationId, title, modulusSize, flen, from, tlen, &rsaSign) != STATUS_OK) {
        KEYISOP_trace_log_error_para(keyCtx->correlationId, 0, title, "rsa private encrypt decrypt", "invalid input parameters","flen: %d, hashOffset:%d", flen, hashOffset);
        return res;
    }
    return KeyIso_TPM_rsa_sign(keyCtx->correlationId, keyDetails, rsaSign.type, rsaSign.m_len, from + hashOffset, tlen, to);
}

static int _client_tpm_pkey_rsa_sign(const KEYISO_TPM_KEY_DETAILS *keyDetails, const KEYISO_KEY_CTX *keyCtx, int flen, const unsigned char *from, int tlen, unsigned char *to, int padding)
{
    char* title = KEYISOP_TPM_EPKEY_RSA_SIGN_TITLE;
    uint32_t modulusSize = keyDetails->pub.publicArea.unique.rsa.size;
    int res = -1;
    int siglen = 0;
    KEYISO_EVP_PKEY_SIGN  pkeyRsaSign;
    size_t hashOffset = sizeof(pkeyRsaSign);
    if (KeyIso_retrieve_evp_pkey_sign_data(keyCtx->correlationId, title, modulusSize, flen, from, tlen, &pkeyRsaSign) != STATUS_OK) {
        KEYISOP_trace_log_error_para(keyCtx->correlationId, 0, title, "rsa private encrypt decrypt", "invalid input parameters","flen: %d, hashOffset:%d", flen, hashOffset);
        return res;
    }
    if (pkeyRsaSign.getMaxLen) {
        to = NULL;
    } else {
        // If sig is not NULL then before the call the siglen parameter should contain the length of the sig buffer.
        if (pkeyRsaSign.sigLen > (uint64_t)tlen) {
            KEYISOP_trace_log_error_para(keyCtx->correlationId, 0, title, "rsa private encrypt decrypt", "invalid input parameters","sigLen: %d, tlen:%d", pkeyRsaSign.sigLen, tlen);
            return res;
        }
        siglen = (int)pkeyRsaSign.sigLen;
    } 
    return KeyIso_TPM_pkey_rsa_sign(keyCtx->correlationId, keyDetails, pkeyRsaSign.sigmdType, pkeyRsaSign.tbsLen , from + hashOffset, siglen, to, padding);
}

int KeyIso_client_tpm_msg_rsa_private_encrypt_decrypt(
    KEYISO_KEY_CTX *keyCtx,
    int decrypt,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding,
    int labelLen)
{
    char* title = KEYISOP_TPM_RSA_PRIV_ENC_DEC_TITE;
    int res = -1;
    KEYISO_TPM_KEY_DETAILS *keyDetails = NULL;
    if (_get_tpm_details_for_key(keyCtx, &keyDetails) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, title, "rsa private encrypt decrypt", "invalid input parameters");
        return res;
    }

   switch (decrypt)
   {
        case KEYISO_IPC_RSA_PRIV_ENCRYPT:
        {
            KEYISOP_trace_log_error(keyCtx->correlationId, 0, title, "rsa private encrypt", "private encrypt not supported - low level API should not be invoked directly");
            return res;
        }
        case KEYISO_IPC_RSA_PRIV_DECRYPT:
        {    
            // TPM currently supports OAEP padding but does not support custom OAEP labels (only empty labels are supported)
            return KeyIso_TPM_rsa_private_decrypt(keyCtx->correlationId, keyDetails, flen, from, tlen, to, padding, labelLen);
        }
        case KEYISO_IPC_RSA_SIGN:
        {
            return _client_tpm_rsa_sign(keyDetails, keyCtx, flen, from, tlen, to);
        }
        case KEYISO_IPC_PKEY_SIGN:
        {
            return _client_tpm_pkey_rsa_sign(keyDetails, keyCtx, flen, from, tlen, to, padding);
        }
        default:
        {
            KEYISOP_trace_log_error_para(keyCtx->correlationId, 0, title, "rsa private encrypt decrypt", "invalid decrypt mode","decrypt: %d", decrypt);
            return res;
        }
   }
}

int KeyIso_client_tpm_msg_ecdsa_sign(
    KEYISO_KEY_CTX *keyCtx,
    int type,
    const unsigned char *dgst,
    int dlen,
    unsigned char *sig,
    unsigned int sigLen,
    unsigned int *outLen)
{
    const char* title = KEYISOP_TPM_ECDSA_SIGN_TITLE;
    KEYISO_TPM_KEY_DETAILS *keyDetails = NULL;
    int ret = -1;

    if (_get_tpm_details_for_key(keyCtx, &keyDetails) != STATUS_OK || !outLen) {
        KEYISOP_trace_log_error(NULL, 0, title, "close key", "failed to get tpm key details");
        return ret;
    }

    // Sign
    ret = KeyIso_TPM_ecdsa_sign(keyCtx->correlationId, keyDetails, dgst, dlen, sig, sigLen);
    if (ret < 0) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, title, "ecdsa sign", "failed to sign");
        return ret;
    }

    *outLen = ret;
    KEYISOP_trace_log(keyCtx->correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete - ecdsa sign succeeded");
    return STATUS_OK;
}

int KeyIso_client_tpm_msg_import_private_key(
    const uuid_t correlationId,
    int keyType,
    const unsigned char *inKeyBytes,
    X509_SIG **outEncKey,
    KEYISO_CLIENT_DATA_ST **outClientData)
{
    // No need to cast outClientData since it's now the correct type
    KEYISOP_trace_log_error(correlationId, 0, KEYISOP_TPM_IMPORT_PRIVATE_KEY_TITLE, "import private key", "not supported");
    return STATUS_FAILED;
}


int KeyIso_client_tpm_msg_import_symmetric_key(
    const uuid_t correlationId, 
    int inSymmetricKeyType,
    unsigned int inKeyLength, 
    const unsigned char *inKeyBytes,
    const unsigned char *inImportKeyId,
    unsigned int *outKeyLength, 
    unsigned char **outKeyBytes,
    char **outClientData)
{
    KEYISOP_trace_log_error(correlationId, 0, KEYISOP_TPM_IMPORT_SYMMETRIC_KEY_TITLE, "import symmetric key", "not supported");
    return STATUS_FAILED;
}

int KeyIso_client_tpm_msg_symmetric_key_encrypt_decrypt(
    KEYISO_KEY_CTX *keyCtx,
    int mode, 
    const unsigned char *from,
    const unsigned int fromLen,
    unsigned char *to,
    unsigned int *toLen)
{
    KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_TPM_SYMMETRIC_ENC_DEC_TITLE, "symmetric key encrypt decrypt", "not supported");
    return STATUS_FAILED;
}

void KeyIso_client_tpm_set_config(const KEYISO_CLIENT_CONFIG_ST *clientConfig)
{
    const char* title = KEYISOP_CLIENT_CONFIG;

    if (clientConfig == NULL) {
        KEYISOP_trace_log_error(NULL, 0, title, "set config", "invalid parameters");    
        return;
    }
    KeyIso_tpm_config_set(clientConfig->tpmConfig);
}