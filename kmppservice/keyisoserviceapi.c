/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "keyisocommon.h"
#include "keyisolog.h"
#include "keyisoserviceapi.h"
#include "keyisomemory.h"
#include "keyisoipccommands.h"
#include "keyisoservicecommon.h"
#include "keyisoservicekey.h"
#include "keyisoservicecrypto.h"
#include "keyisoservicekeygen.h"
#include "keyisoservicesymmetrickey.h"

#ifdef KMPP_OPENSSL_SUPPORT
#include "keyisoserviceapiossl.h"
#endif  //KMPP_OPENSSL_SUPPORT

#define KMPP_EC_MIN_HIGH_BIT          33

#define KMPP_KDF_CBC_HMAC_LABEL       "Microsoft KMPP KEK key AES-256-CBC-HMAC-SHA256 32"

// Smallest supported curve is P192 => 24 * 2 byte SymCrypt signatures
#define KMPP_ECDSA_MIN_SYMCRYPT_SIGNATURE_LEN 48
// Largest supported curve is P521 => 66 * 2 byte SymCrypt signatures
#define KMPP_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN 132

/////////////////////////////////////////////////////
///////////////// KeyIso SERVER API /////////////////
/////////////////////////////////////////////////////
static int _is_valid_private_key_header(
    const uuid_t correlationId,
    KmppKeyType type,
    KEYISO_KEY_HEADER_ST header)
    {
        int ret = STATUS_FAILED;
        if(header.keyVersion < KEYISO_PKEY_VERSION) {
            KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "Invalid argument", "Invalid keyVersion", "version = %u", header.keyVersion);
            return ret;
        }

        switch (type) {
        case KmppKeyType_rsa: {
            if (header.magic != KEYISO_RSA_PRIVATE_PKEY_MAGIC) {
                KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "Invalid argument", "Invalid RSA magic");
                break;
            }
            ret = STATUS_OK;
            break;
        }
        case KmppKeyType_ec: {
            if (header.magic != KEYISO_EC_PRIVATE_PKEY_MAGIC) {
                KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "Invalid argument", "Invalid EC magic");
                break;
            }
            ret = STATUS_OK;
            break;
        }
        default:
            KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "Key type", "Unsupported key type");
            break;
        }
        return ret;
    }

static int _is_valid_private_key(
    const uuid_t correlationId,
    KmppKeyType type,
    const void *privatekey)
{
    int ret = STATUS_FAILED;
    void *pSymCryptKey = NULL;

    KEYISO_KEY_HEADER_ST header;
    memcpy(&header, privatekey, sizeof(KEYISO_KEY_HEADER_ST));

    switch (type) {
        case KmppKeyType_rsa: {
            if (!_is_valid_private_key_header(correlationId, type, header)) {
                KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "Invalid argument", "RSA magic was not kept during serialization");
                break;
            }
            pSymCryptKey = (PSYMCRYPT_RSAKEY) KeyIso_get_rsa_symcrypt_pkey(correlationId, (KEYISO_RSA_PKEY_ST *) privatekey);
            if (pSymCryptKey) {
                ret = STATUS_OK;
                SymCryptRsakeyFree(pSymCryptKey);
            }
            break;
        }
        case KmppKeyType_ec: {
            if (!_is_valid_private_key_header(correlationId, type, header)) {
                KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "Invalid argument", "EC magic was not kept during serialization");
                break;
            }
            pSymCryptKey = (PSYMCRYPT_ECKEY) KeyIso_get_ec_symcrypt_pkey(correlationId, (KEYISO_EC_PKEY_ST *) privatekey);
            if (pSymCryptKey) {
                ret = STATUS_OK;
                SymCryptEckeyFree(pSymCryptKey);
            }
            break;
        }
        default:
            KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "Key type", "Unsupported key type");
            break;
    }

    if (STATUS_OK != ret)
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "Private Key", "Failed to get SymCrypt key");

    return ret;
}

static int _cleanup_import_private_key( 
    int ret,
    const char *loc,
    const char *err,
    const uuid_t correlationId,
    unsigned char *secretId,
    unsigned int secretIdLen,
    unsigned char *secretSalt,
    unsigned int secretSaltLen,
    unsigned char *iv,
    unsigned int ivLen,
    unsigned char *hmac,
    unsigned int hmacLen,
    unsigned char *pToEncrypt,
    unsigned int paddedKeyLen,
    unsigned char *pEncrypted,
    KEYISO_ENCRYPTED_PRIV_KEY_ST *pEncKeySt)
{
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, loc, err);
        KeyIso_free(pEncKeySt);
        pEncKeySt = NULL;
    } else {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_IMPORT_KEY_TITLE, loc);
    }

    // Cleanse sensitive data
    KeyIso_cleanse(secretId, secretIdLen);
    KeyIso_cleanse(secretSalt, secretSaltLen);
    KeyIso_cleanse(iv, ivLen);
    KeyIso_cleanse(hmac, hmacLen);
    KeyIso_clear_free(pToEncrypt, paddedKeyLen);
    KeyIso_free(pEncrypted);

    return ret;
}
#define _CLEANUP_IMPORT_PRIVATE_KEY(res, loc, err) \
    _cleanup_import_private_key(res, loc, err, correlationId, secretId, secretIdLen, secretSalt, \
         secretSaltLen, iv, ivLen, hmac, hmacLen, pToEncrypt, paddedKeyLen, pEncrypted, pEncKeySt)

int KeyIso_SERVER_import_private_key( 
    const uuid_t correlationId,
    int keyType,
    const void *inKey,       // KEYISO_RSA_PKEY_ST/KEYISO_EC_PKEY_ST 
    void **outEncKey)        // KEYISO_ENCRYPTED_PRIV_KEY_ST
{
    if (!inKey || !outEncKey) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "Invalid argument", "Null parameter");
        return STATUS_FAILED;
    }
    *outEncKey = NULL;

    int ret = STATUS_FAILED;

    size_t inKeyLen = 0;
    size_t ivLen = 0;
    size_t hmacLen = 0;
    size_t keyLen = 0;
    uint32_t totalDynamicKeyLen = 0;
    size_t structSize = 0;
    unsigned int paddedKeyLen = 0;
    AlgorithmVersion algVersion = AlgorithmVersion_Current;

    unsigned char iv[KMPP_AES_BLOCK_SIZE] = {0};            // KeyIso_cleanse() need to be invoked before exiting the function
    unsigned char hmac[KMPP_HMAC_SHA256_KEY_SIZE] = {0};    // KeyIso_cleanse() need to be invoked before exiting the function
    unsigned char secretSalt[KMPP_SALT_SHA256_SIZE] = {0};  // KeyIso_cleanse() need to be invoked before exiting the function
    unsigned char secretId[KMPP_MAX_SECRET_ID_SIZE] = {0};    // KeyIso_cleanse() need to be invoked before exiting the function


    size_t secretSaltLen = sizeof(secretSalt);
    // The secret Id length will be set differently according to the isolation solution: 
    // sizeof(uuid_t) in process based used as GUId
    // and 32 Bytes in TA, used as extra salt for deriving the machine secret
    uint32_t secretIdLen = 0;
    
    unsigned char *pToEncrypt = NULL; // KeyIso_clear_free() should be used to free
    unsigned char *pEncrypted = NULL;
    
    KmppKeyType type = KmppKeyType_end;
    KEYISO_ENCRYPTED_PRIV_KEY_ST* pEncKeySt = NULL;

    ivLen = sizeof(iv);
    hmacLen = sizeof(hmac);
    type = KeyIso_evp_pkey_id_to_KmppKeyType(correlationId, keyType);

    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_IMPORT_KEY_TITLE, "Start"); 

    // We want to prevent the import of a key whose use is not supported
    if (STATUS_OK != _is_valid_private_key(correlationId, type, inKey))
        return _CLEANUP_IMPORT_PRIVATE_KEY(STATUS_FAILED, "inKey", "Invalid key");

    inKeyLen = KeyIso_get_pkey_bytes_len(type, inKey);
    if (!inKeyLen) {
        return _CLEANUP_IMPORT_PRIVATE_KEY(STATUS_FAILED, "len", "Failed to get key length");
    }
    
    keyLen = sizeof(KmppKeyType) + inKeyLen;  // adding one more byte for key type
    
    // Get PKCS #7 block padding size
    ret = KeyIso_padding_pkcs7_add(
        correlationId,
        NULL, // When sending data as null it will return only the padding size
        keyLen,
        NULL,
        &paddedKeyLen);
    if (ret != STATUS_OK) {
        return _CLEANUP_IMPORT_PRIVATE_KEY(ret, "KeyIso_padding_pkcs7_add", " padding size Failed");
    }

    pToEncrypt = (unsigned char *) KeyIso_zalloc(paddedKeyLen);
    pEncrypted = (unsigned char *) KeyIso_zalloc(paddedKeyLen);
    if (!pToEncrypt || !pEncrypted) {
        return _CLEANUP_IMPORT_PRIVATE_KEY(STATUS_FAILED, "Memory allocation", "Failed");
    }

    // Concatenating key type to the beginning of the private key buffer
    memcpy(pToEncrypt, &type, sizeof(KmppKeyType));
    memcpy(pToEncrypt + sizeof(KmppKeyType), inKey, inKeyLen);

    // PKCS #7 block padding
    ret = KeyIso_padding_pkcs7_add(
        correlationId,
        pToEncrypt,
        keyLen,
        pToEncrypt,
        &paddedKeyLen);
    if (ret != STATUS_OK) {
        return _CLEANUP_IMPORT_PRIVATE_KEY(ret, "KeyIso_padding_pkcs7_add", "Failed");
    }

    // Deriving a 512-bit key from the current machine secret and a random salt using KDF (SP800-108)
    // Encrypting the private key with the the first 256 bits of the derived key using AES-256-CBC
    // and calculating HMAC using the second 256 bits of the derived key.

    ret = KeyIso_symcrypt_kdf_encrypt_hmac(
        correlationId,
        algVersion,
        secretId, 
        &secretIdLen,           
        secretSalt,    
        secretSaltLen,           
        iv,          
        ivLen,     
        pToEncrypt,      
        pEncrypted,  
        paddedKeyLen,      
        hmac,               
        hmacLen);  
    if (ret != STATUS_OK) {
        return _CLEANUP_IMPORT_PRIVATE_KEY(ret, "KeyIso_symcrypt_kdf_encrypt_hmac", "Failed to encrypt private key");
    }

    // Creating encrypted key
    totalDynamicKeyLen = 0;
    ret = KeyIso_get_enc_key_bytes_len_params(correlationId, secretSaltLen, ivLen, hmacLen, paddedKeyLen, secretIdLen, &totalDynamicKeyLen);
    if (ret != STATUS_OK) {
        return _CLEANUP_IMPORT_PRIVATE_KEY(ret, "KeyIso_get_enc_key_bytes_len_params", "Failed to get encrypted key length");
    }

    structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_ENCRYPTED_PRIV_KEY_ST, totalDynamicKeyLen);
    pEncKeySt = (KEYISO_ENCRYPTED_PRIV_KEY_ST *) KeyIso_zalloc(structSize);
    if (!pEncKeySt) {
        return _CLEANUP_IMPORT_PRIVATE_KEY(STATUS_FAILED, "enckey", "Memory allocation failed");
    }

    // Any change (without backward compatibility) in the encryption algorithm above requires to update the version.
    pEncKeySt->algVersion = algVersion;
    pEncKeySt->secretSaltLen = secretSaltLen;
    pEncKeySt->ivLen = ivLen;
    pEncKeySt->hmacLen = hmacLen;
    pEncKeySt->encKeyLen = paddedKeyLen;
    pEncKeySt->secretIdLen = secretIdLen;
    
    uint32_t index = 0;
    memcpy(&pEncKeySt->encryptedKeyBytes[index], secretSalt, secretSaltLen);
    index += secretSaltLen;
    memcpy(&pEncKeySt->encryptedKeyBytes[index], iv, ivLen);
    index += ivLen;
    memcpy(&pEncKeySt->encryptedKeyBytes[index], hmac, hmacLen);
    index += hmacLen;
    memcpy(&pEncKeySt->encryptedKeyBytes[index], secretId, secretIdLen);
    index += secretIdLen;
    memcpy(&pEncKeySt->encryptedKeyBytes[index], pEncrypted, paddedKeyLen);
    index += paddedKeyLen;
    if (index != totalDynamicKeyLen) {
        return _CLEANUP_IMPORT_PRIVATE_KEY(STATUS_FAILED, "Invalid argument", "Encrypted key length mismatch"); 
    }

    *outEncKey = pEncKeySt;

    return _CLEANUP_IMPORT_PRIVATE_KEY(STATUS_OK, "Complete- Success", "");
}

static int _cleanup_generate_rsa_key_pair(
    const uuid_t correlationId, 
    const char *loc, 
    const char *error, 
    int status,
    PSYMCRYPT_RSAKEY pkeyPtr, 
    KEYISO_RSA_PUBLIC_KEY_ST *pubKeyPtr, 
    KEYISO_RSA_PKEY_ST *pPkeySt, // KeyIso_clear_free() should be used to free
    size_t pkeyStSize)
{
    if (pkeyPtr) {
        SymCryptRsakeyFree(pkeyPtr);
    }

    KeyIso_clear_free(pPkeySt, pkeyStSize);
    if (status != STATUS_OK) {
        KeyIso_free(pubKeyPtr);
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_GEN_KEY_TITLE, loc, error);
    } else {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_GEN_KEY_TITLE, loc);
    }
    return status;
}

int KeyIso_SERVER_generate_rsa_key_pair(
    const uuid_t correlationId, 
    unsigned int keyBits,
    unsigned int keyUsage,
    KEYISO_RSA_PUBLIC_KEY_ST **outPubKey,          
    void **outEncryptedPkey)      // KEYISO_ENCRYPTED_PRIV_KEY_ST  
{
    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_GEN_KEY_TITLE, "Start"); 

    if (outPubKey == NULL || outEncryptedPkey == NULL) 
        return _cleanup_generate_rsa_key_pair(correlationId,
                                              "Invalid argument",
                                              "Failed",
                                               STATUS_FAILED,
                                               NULL,
                                               NULL,
                                               NULL,
                                               0);
    
    if (keyBits > KMPP_OPENSSL_RSA_MAX_MODULUS_BITS || keyBits < KMPP_RSA_MIN_MODULUS_BITS) {    
        return _cleanup_generate_rsa_key_pair(correlationId,
                                              "Invalid argument",
                                              "Failed",
                                              STATUS_FAILED,
                                              NULL,
                                              NULL,
                                              NULL,
                                              0); 
    }    
    
    int ret = STATUS_FAILED;
    PSYMCRYPT_RSAKEY rsaKey = NULL;
    KEYISO_RSA_PKEY_ST *pPkeySt = NULL;
    KEYISO_RSA_PUBLIC_KEY_ST *pPubKeySt = NULL;
    void *encryptedPkey = NULL;
    
    *outPubKey = NULL;
    *outEncryptedPkey = NULL;

    // Generating RSA Key 
    ret = KeyIso_rsa_key_generate(correlationId, keyBits, keyUsage, &rsaKey);
    if (ret != STATUS_OK)
        return _cleanup_generate_rsa_key_pair(correlationId,
                                              "KeyIso_rsa_key_generate",
                                              "Failed",
                                               STATUS_FAILED,
                                               rsaKey,
                                               NULL,
                                               NULL,
                                               0);

    pPubKeySt = KeyIso_export_rsa_public_key_from_symcrypt(correlationId, rsaKey);
    if (!pPubKeySt)
        return _cleanup_generate_rsa_key_pair(correlationId,
                                             "KeyIso_export_rsa_public_key_from_symcrypt", 
                                             "Failed",
                                              STATUS_FAILED,
                                              rsaKey,
                                              pPubKeySt,
                                              NULL,
                                              0); 
    size_t keySize = 0;
    pPkeySt = KeyIso_export_rsa_pkey_from_symcrypt(correlationId, rsaKey, &keySize);
    if(!pPkeySt) 
        return _cleanup_generate_rsa_key_pair(correlationId,
                                             "KeyIso_export_rsa_pkey_from_symcrypt", 
                                             "Failed",
                                              STATUS_FAILED,
                                              rsaKey,
                                              pPubKeySt,
                                              pPkeySt,
                                              keySize); 
    // Importing the generated key
    ret = KeyIso_SERVER_import_private_key(correlationId, KMPP_EVP_PKEY_RSA_NID , pPkeySt, &encryptedPkey);
    if (ret != STATUS_OK)
        return _cleanup_generate_rsa_key_pair(correlationId,
                                              "KeyIso_SERVER_import_private_key",
                                              "Failed",
                                               STATUS_FAILED,
                                               rsaKey,
                                               pPubKeySt,
                                               pPkeySt,
                                               keySize);

    // Setting output parameters
    *outPubKey = pPubKeySt;
    *outEncryptedPkey = encryptedPkey;

    return _cleanup_generate_rsa_key_pair(correlationId,
                                          "Complete- Success",
                                          "",
                                          STATUS_OK,
                                          rsaKey,
                                          NULL,
                                          pPkeySt,
                                          keySize);
}

static int _cleanup_generate_ec_key_pair(
    const uuid_t correlationId, 
    const char *loc, 
    const char *err, 
    int status,
    void *pkeyPtr, 
    KEYISO_EC_PUBLIC_KEY_ST *pubKeyPtr, 
    void *encryptedPkey, 
    void *pPkeySt, // KeyIso_clear_free() should be used to free
    size_t pkeyStSize)
{
    if (pkeyPtr) 
        SymCryptEckeyFree(pkeyPtr);

    KeyIso_clear_free(pPkeySt, pkeyStSize);
    if (status != STATUS_OK) {
        KeyIso_free(pubKeyPtr);
        KeyIso_free(encryptedPkey);
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_GEN_KEY_TITLE, loc, err);
    } else {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_GEN_KEY_TITLE, loc);
    }
    return status;
}

int KeyIso_SERVER_generate_ec_key_pair(
    const uuid_t correlationId, 
    uint32_t curve,
    unsigned int keyUsage,
    KEYISO_EC_PUBLIC_KEY_ST **outPubKey, 
    void **outEncryptedPkey)
{
    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_GEN_KEY_TITLE, "Start");
    if (outPubKey == NULL || outEncryptedPkey == NULL) {
        return _cleanup_generate_ec_key_pair(correlationId,
                                          "Invalid argument",
                                           "Failed",
                                            STATUS_FAILED,
                                            NULL,
                                            NULL,
                                            NULL,
                                            NULL,
                                            0);
    }
    int ret = STATUS_FAILED;
    PSYMCRYPT_ECKEY ecKey = NULL;
    KEYISO_EC_PKEY_ST *pPkeySt = NULL;
    KEYISO_EC_PUBLIC_KEY_ST *pPubKeySt = NULL;
    void *encryptedPkey = NULL;

    *outPubKey = NULL;
    *outEncryptedPkey = NULL;

    ret = KeyIso_ec_key_generate(correlationId, curve, keyUsage, &ecKey);
    if (ret != STATUS_OK) {
        return _cleanup_generate_ec_key_pair(correlationId,
                                         "KeyIso_ec_key_generate",
                                          "Failed",
                                          STATUS_FAILED,
                                          ecKey,
                                          NULL,
                                          NULL,
                                          NULL,
                                          0);
    }
    pPubKeySt = KeyIso_export_ec_public_key_from_symcrypt(correlationId, curve, ecKey);
    if (!pPubKeySt) {
        return _cleanup_generate_ec_key_pair(correlationId,
                                          "KeyIso_export_ec_public_key_from_symcrypt",
                                          "Failed",
                                          STATUS_FAILED,
                                          ecKey,
                                          pPubKeySt,
                                          NULL,
                                          NULL,
                                          0);
    }
    size_t keyStSize = 0;
    pPkeySt = KeyIso_export_ec_pkey_from_symcrypt(correlationId, curve, ecKey, &keyStSize); //  KeyIso_clear_free() should be used to free
    if(!pPkeySt) {
        return _cleanup_generate_ec_key_pair(correlationId,
                                          "KeyIso_export_rsa_pkey_from_symcrypt", 
                                          "Failed",
                                           STATUS_FAILED,
                                           ecKey,
                                           pPubKeySt,
                                           NULL,
                                           pPkeySt,
                                           0); 
    }   
    // Importing the generated key
    ret = KeyIso_SERVER_import_private_key(correlationId, KMPP_EVP_PKEY_EC_NID , pPkeySt, &encryptedPkey);
    if (ret != STATUS_OK) {
        return _cleanup_generate_ec_key_pair(correlationId,
                                         "Import key",
                                         "Failed",
                                         STATUS_FAILED,
                                         ecKey,
                                         pPubKeySt,
                                         encryptedPkey,
                                         pPkeySt,
                                         keyStSize);
    }
    // Setting output parameters
    *outPubKey = pPubKeySt;
    *outEncryptedPkey = encryptedPkey;

    return _cleanup_generate_ec_key_pair(correlationId,
                                         "Complete- Success",
                                         "",
                                         STATUS_OK,
                                         ecKey,
                                         NULL,
                                         NULL,
                                         pPkeySt,
                                         keyStSize);
}

static int _cleanup_open_private_key(
    const uuid_t correlationId,
    int ret, 
    const char *loc,
    const char *err,
    void *privatekey,              // KEYISO_RSA_PKEY_ST/KEYISO_EC_PKEY_ST - KeyIso_clear_free() should be used to free
    unsigned int keyLen,
    unsigned char *decryptedKey,   // KeyIso_clear_free() should be used to free
    unsigned int decryptedKeyLen)
{
    KeyIso_clear_free(decryptedKey, decryptedKeyLen);
    KeyIso_clear_free(privatekey, keyLen);

    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_OPEN_KEY_TITLE, loc, err);
    } else {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_OPEN_KEY_TITLE, "Complete- Success");
    }

    return ret;
}

int KeyIso_SERVER_open_private_key( 
    const uuid_t correlationId,
    KEYISO_CLIENT_METADATA_HEADER_ST *metaData,
    KEYISO_ENCRYPTED_PRIV_KEY_ST *pEncKeySt,    // KEYISO_ENCRYPTED_PRIV_KEY_ST
    PKMPP_KEY *outPkey)                         // KMPP_KEY. free by KeyIso_kmpp_key_free
{
    const char* title = KEYISOP_OPEN_KEY_TITLE;
    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Start"); 
    if (!outPkey || !pEncKeySt) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid argument", "inEncryptedPkey or outPkey is null");
        return STATUS_FAILED;
    }
    *outPkey = NULL;
    
    int ret = STATUS_FAILED;
    uint32_t index = 0;
    KmppKeyType type = 0;

    size_t secretSaltLen = 0;
    size_t ivLen = 0;
    size_t hmacLen = 0;
    size_t secretIdLen = 0;
    size_t keyTypeSize = sizeof(KmppKeyType);

    unsigned int keyLen = 0;
    unsigned int decryptedKeyLen = 0;
    unsigned int AlgVersion = 0;

    void *privatekey = NULL;
    void *pSymCryptKey = NULL;

    unsigned char *secretSalt = NULL;
    unsigned char *iv = NULL;
    unsigned char *hmac = NULL;
    unsigned char *encryptedKey = NULL;
    unsigned char *decryptedKey = NULL;
    unsigned char* secretId = NULL;

    AlgVersion = pEncKeySt->algVersion;
    if (AlgVersion <= AlgorithmVersion_Invalid || AlgVersion > AlgorithmVersion_Current) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "Key encryption", "Unsupported encryption algorithm version", "algVersion: %u", AlgVersion);
        return STATUS_FAILED;
    }

    KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Key encryption", "Encryption algorithm version: %u. Current version is: %u", AlgVersion, AlgorithmVersion_Current);

    secretSaltLen = pEncKeySt->secretSaltLen;
    ivLen = pEncKeySt->ivLen;
    hmacLen = pEncKeySt->hmacLen;
    decryptedKeyLen = pEncKeySt->encKeyLen;
    secretIdLen = pEncKeySt->secretIdLen;

    // Check that key size doesn't exceed the maximum
    if (decryptedKeyLen > KMPP_MAX_MESSAGE_SIZE) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, NULL, "Private key is too big", "length: %d", decryptedKeyLen);
        return ret;
    }

    // We don't need to waste time on memory allocation and memory copy.
    // Only copy the IV to pbChainingValue, because pbChainingValue is not a constant and is updated for every block.
    secretSalt = &pEncKeySt->encryptedKeyBytes[index];
    index += secretSaltLen;
    iv = &pEncKeySt->encryptedKeyBytes[index];
    index += ivLen;
    hmac = &pEncKeySt->encryptedKeyBytes[index];
    index += hmacLen;
    secretId = &pEncKeySt->encryptedKeyBytes[index];
    index += secretIdLen;
    encryptedKey = &pEncKeySt->encryptedKeyBytes[index];
    index += decryptedKeyLen;

    uint32_t expectedEncKeyLen = 0;
    if (KeyIso_get_enc_key_bytes_len_params(correlationId, secretSaltLen, ivLen, hmacLen, decryptedKeyLen, secretIdLen, &expectedEncKeyLen) != STATUS_OK) {
        return _cleanup_open_private_key(correlationId,
                                         STATUS_FAILED,
                                         "KeyIso_get_enc_key_bytes_len_params",
                                         "Failed to get encrypted key length",
                                         privatekey,
                                         0,
                                         decryptedKey,
                                         0);
    }
    if (index != expectedEncKeyLen) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "Encrypted key length", "Invalid encrypted key length", "expected: %u, actual: %u", expectedEncKeyLen, index);
        return _cleanup_open_private_key(correlationId,
                                         STATUS_FAILED,
                                         "Encrypted key length",
                                         "Invalid encrypted key length",
                                         privatekey,
                                         0,
                                         decryptedKey,
                                         0);
    }

    if (ivLen != KMPP_AES_BLOCK_SIZE)
        return _cleanup_open_private_key(correlationId,
                                         STATUS_FAILED,
                                         "IV length",
                                         "Incorrect IV length",
                                         privatekey,
                                         0,
                                         decryptedKey,
                                         0);

    decryptedKey = (unsigned char *) KeyIso_zalloc(decryptedKeyLen);
    if (!decryptedKey)
        return _cleanup_open_private_key(correlationId,
                                         STATUS_FAILED,
                                         "decryptedKey",
                                         "Memory allocation failed",
                                         privatekey,
                                         0,
                                         decryptedKey,
                                         0);

    // Decrypting the private key using KDF (SP800-108) and HMAC
    ret = KeyIso_symcrypt_kdf_decrypt_hmac(
        correlationId,
        AlgVersion,
        (const unsigned char *)metaData,
        (metaData) ? sizeof(*metaData) : 0,
        secretId,
        secretIdLen,
        secretSalt,
        secretSaltLen,
        iv,
        ivLen,
        hmac,
        hmacLen,
        encryptedKey,
        decryptedKey,
        decryptedKeyLen);
    if (ret != STATUS_OK)
        return _cleanup_open_private_key(correlationId,
                                         STATUS_FAILED,
                                         "pbe_decrypt_hmac",
                                         "Failed",
                                         privatekey,
                                         0,
                                         decryptedKey,
                                         decryptedKeyLen);

    // PKCS7 removal
    if (KeyIso_padding_pkcs7_remove(
        correlationId,
        decryptedKey,
        decryptedKeyLen,
        &keyLen
        ) != STATUS_OK) {
            return _cleanup_open_private_key(correlationId,
                                            STATUS_FAILED,
                                            "Padding",
                                            "Invalid value",
                                            privatekey,
                                            0,
                                            decryptedKey,
                                            decryptedKeyLen);
    }

    // Subtracting the length of the type from the length of the key
    keyLen -= keyTypeSize;
    privatekey = KeyIso_zalloc(keyLen);
    if (!privatekey)
        return _cleanup_open_private_key(correlationId,
                                         STATUS_FAILED,
                                         "privatekey",
                                         "Memory allocation failed",
                                         privatekey,
                                         0,
                                         decryptedKey,
                                         decryptedKeyLen);

    memcpy(privatekey, decryptedKey + keyTypeSize, keyLen);
    memcpy(&type, decryptedKey, keyTypeSize);

    KEYISO_KEY_HEADER_ST header;
    memcpy(&header, privatekey, sizeof(KEYISO_KEY_HEADER_ST));

    if (!_is_valid_private_key_header(correlationId, type, header)) {
        return _cleanup_open_private_key(correlationId,
                                         STATUS_FAILED,
                                         "header",
                                         "Invalid key header",
                                         privatekey,
                                         keyLen,
                                         decryptedKey,
                                         decryptedKeyLen);
    }

    switch (type) {
        case KmppKeyType_rsa: {
            pSymCryptKey = (PSYMCRYPT_RSAKEY)KeyIso_get_rsa_symcrypt_pkey(correlationId, (KEYISO_RSA_PKEY_ST *) privatekey);
            break;
        }
        case KmppKeyType_ec: {
            //TODO: check if we support the key else open EPKEY here instead of symcrypt key
            // and return this inside the PKMPP_KEY wrapper.
            pSymCryptKey = (PSYMCRYPT_ECKEY) KeyIso_get_ec_symcrypt_pkey(correlationId, (KEYISO_EC_PKEY_ST *) privatekey);
            break;
        }
        default:
            return _cleanup_open_private_key(correlationId,
                                             STATUS_FAILED,
                                             "Type",
                                             "Unsupported key type",
                                             privatekey,
                                             keyLen,
                                             decryptedKey,
                                             decryptedKeyLen);
    }

    *outPkey = KeyIso_kmpp_key_create(correlationId, type, pSymCryptKey);
    if (*outPkey == NULL) {
        if (pSymCryptKey) {
            if (type == KmppKeyType_rsa) {
                SymCryptRsakeyFree(pSymCryptKey);
            }
            else if (type == KmppKeyType_ec) {
                SymCryptEckeyFree(pSymCryptKey);
            }
        }
        return _cleanup_open_private_key(correlationId,
                                         STATUS_FAILED,
                                         "KMPP_KEY",
                                         "Creation failed",
                                         privatekey,
                                         keyLen,
                                         decryptedKey,
                                         decryptedKeyLen);
    }

    return _cleanup_open_private_key(correlationId,
                                     STATUS_OK,
                                     "Complete- Success",
                                     "",
                                     privatekey,
                                     keyLen,
                                     decryptedKey,
                                     decryptedKeyLen);
}

static int _rsa_fallback_to_openssl(
            const uuid_t correlationId,
            const char* message,
            PFN_rsa_operation fallbackFunction,
            PKMPP_KEY kmppPtr,
            int flen, 
            const unsigned char *from, 
            int tlen, 
            unsigned char *to, 
            int padding)
{
    const char *title = KEYISOP_SERVICE_TITLE;
    int res = -1;

#ifdef KMPP_OPENSSL_SUPPORT
    if (!fallbackFunction) {
        KEYISOP_trace_log_error(correlationId,
                                0,
                                title,
                                "Fallback to OpenSSL",
                                "OpenSSL fallback function pointer cant be null");
        return res;
    }
    // Fallback to OpenSSL
    EVP_PKEY* epkey = KeyIso_convert_symcrypt_rsa_to_epkey(correlationId, kmppPtr->key);
    KEYISOP_trace_log_error(correlationId, KEYISOP_TRACELOG_WARNING_FLAG, title, message, "Fallback to OpenSSL");

    res = fallbackFunction(correlationId, epkey, flen, from, tlen, to, padding);
    EVP_PKEY_free(epkey);
    return res;
#else
    // No openssl support hence no fallback
    // In case of no openssl support there are parameters that are not used -  Mark parameters as unused
    (void)fallbackFunction;
    (void)kmppPtr;
    (void)flen;
    (void)from;
    (void)tlen;
    (void)to;
    (void)padding;
    KEYISOP_trace_log_error(correlationId, 0, title,
                            "Not supported",
                            message);
    return res;

#endif // KMPP_OPENSSL_SUPPORT
}

int KeyIso_SERVER_rsa_private_encrypt(
    const uuid_t correlationId, 
    void *pkey,  
    int flen, 
    const unsigned char *from, 
    int tlen, 
    unsigned char *to, 
    int padding)
{
    int res = -1;
    const char *title = KEYISOP_RSA_ENCRYPT_TITLE;
    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Start"); 
    if(from == NULL || to == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title,
                                "Invalid argument",
                                "From and to buffers can't be null");
        return res;
    }

    PKMPP_KEY kmppPtr = (PKMPP_KEY) pkey;
    if (kmppPtr == NULL || kmppPtr->key == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title,
                                "Private encrypt failed",
                                "Key is null or empty");
        return res;
    }

    if (kmppPtr->type != KmppKeyType_rsa) {
         KEYISOP_trace_log_error_para(correlationId, 0, title,
                                "Private encrypt failed",
                                "incompatible key type",
                                "type: %d", kmppPtr->type);
        return res;
    }

    PFN_rsa_operation fallbackFunction = NULL;
#ifdef KMPP_OPENSSL_SUPPORT
    fallbackFunction = KeyIso_SERVER_rsa_private_encrypt_ossl;
#endif //KMPP_OPENSSL_SUPPORT

    res = _rsa_fallback_to_openssl(correlationId,
                               "RSA private encrypt equivalent not FIPS certifiable - Fallback to OpenSSL",
                                fallbackFunction,
                                kmppPtr,
                                flen,
                                from,
                                tlen,
                                to,
                                padding);
    if (res > 0) {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete- Success");
    } else {
        KEYISOP_trace_log_error(correlationId, 0, title, "Private encrypt failed","_rsa_fallback_to_openssl failed");
    
    }
    return res;
} 

int KeyIso_SERVER_rsa_private_decrypt(
    const uuid_t correlationId, 
    void *pkey,  
    int flen, 
    const unsigned char *from, 
    int tlen, 
    unsigned char *to, 
    int padding,
    int labelLen,
    const unsigned char *label)
{
    int res = -1;
    int32_t toLen;
    const char *title = KEYISOP_RSA_DECRYPT_TITLE;
    
    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Start");
    if (from == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title , "Invalid input", "The from ciphertext can't be empty");
        return res;
    }

    PKMPP_KEY kmppPtr = (PKMPP_KEY) pkey;
    if (kmppPtr == NULL || kmppPtr->key == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid input", "Key is null or empty");
        return res;
    }

    if (kmppPtr->type != KmppKeyType_rsa) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "Invalid input", "Incorrect key type", "Key type:%d", kmppPtr->type);
        return res;
    }

    switch (padding)
    {
        case KMPP_RSA_PKCS1_PADDING:
        case KMPP_RSA_NO_PADDING:
        case KMPP_RSA_PKCS1_OAEP_PADDING:
        {
            if (KeyIso_rsa_decrypt(correlationId, kmppPtr, padding, KMPP_NID_sha1, labelLen, label, flen, from, &toLen, to) != STATUS_OK) {
                KEYISOP_trace_log_error(correlationId, 0, title, "Rsa Decrypt Error", "KeyIso_rsa_decrypt failed");
                return res;
            }

            // Success , return the to buffer size    
            KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete- query buffer size");
            return toLen;
        }
        default:
        {
            PFN_rsa_operation fallbackFunction = NULL;

#ifdef KMPP_OPENSSL_SUPPORT
            fallbackFunction = KeyIso_SERVER_rsa_private_decrypt_ossl;
#endif //KMPP_OPENSSL_SUPPORT

            char message[100];
            snprintf(message, sizeof(message), "The padding %d  len:%d is not supported by SymCrypt", padding, flen);
            res =  _rsa_fallback_to_openssl(correlationId,
                                        message,
                                        fallbackFunction,
                                        kmppPtr,
                                        flen,
                                        from,
                                        tlen,
                                        to,
                                        padding);
            if (res > 0) {
                KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete- Success");
            } else {
                KEYISOP_trace_log_error(correlationId, 0, title, "Private decrypt failed", "_rsa_fallback_to_openssl failed");
            }
            return res;
        }
    }
}

int KeyIso_SERVER_rsa_sign(
    const uuid_t correlationId, 
    void *pkey,  
    int flen, 
    const unsigned char *from, 
    int tlen, 
    unsigned char *to, 
    int padding __attribute__((unused))) // This parameter is not used in SymCrypt
{
    int siglen = 0;
    int res = -1;
    KEYISO_RSA_SIGN rsaSign;
    const char *title = KEYISOP_RSA_SIGN_TITLE;

    if (from == NULL || to == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid input", "Both from and to can't be null");
        return res;
    }

    PKMPP_KEY kmppPtr = (PKMPP_KEY) pkey;
    if (kmppPtr == NULL || kmppPtr->key == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid input", "Key is null or empty");
        return res;
    }

    if (kmppPtr->type != KmppKeyType_rsa) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "Invalid input", "Incorrect key type", "Key type: %d", kmppPtr->type);
        return res;
    }
    uint32_t modulusSize = SymCryptRsakeySizeofModulus(kmppPtr->key);

    if (KeyIso_retrieve_rsa_sig_data(correlationId, title, modulusSize, flen, from, tlen, &rsaSign) != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, title, "rsa sign", "failed to retrieve rsa sig data from buff");
        return res;
    }
   
    if (KeyIso_rsa_pkcs1_sign(correlationId, kmppPtr, rsaSign.type, from + sizeof(rsaSign), rsaSign.m_len, to, &siglen) != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, title, "rsa sign", "KeyIso_rsa_pkcs1_sign failed");
        return res;
    }

    // Success , return signature size
    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete- Success");
    return siglen;
}

int KeyIso_SERVER_pkey_rsa_sign(
    const uuid_t correlationId, 
    void *pkey,  
    int flen, 
    const unsigned char *from, 
    int tlen, 
    unsigned char *to, 
    int padding)
{
    const char *title = KEYISOP_PKEY_RSA_SIGN_TITLE;
    PFN_rsa_operation fallbackFunction = NULL;
    int res = -1;
    uint64_t siglen = 0;

    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Start");
    
#ifdef KMPP_OPENSSL_SUPPORT
    fallbackFunction = KeyIso_SERVER_pkey_rsa_sign_ossl;
#endif //KMPP_OPENSSL_SUPPORT
    
    if (from == NULL ) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid input", "from can't be null");
        return res;
    }
    PKMPP_KEY kmppPtr = (PKMPP_KEY) pkey;
    if (kmppPtr == NULL || kmppPtr->key == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid input", "Key is null or empty");
        return res;
    }

    if (kmppPtr->type != KmppKeyType_rsa) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "Invalid input", "Incorrect key type", "Key type: %d", kmppPtr->type);
        return res;
    }

    KEYISO_EVP_PKEY_SIGN  pkeyRsaSign;
    uint32_t modulusSize = SymCryptRsakeySizeofModulus(kmppPtr->key);
    if (KeyIso_retrieve_evp_pkey_sign_data(correlationId, title, modulusSize, flen, from, tlen, &pkeyRsaSign) != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, title, "pkey rsa sign", "failed to retrieve rsa sig data from buff");
        return res;
    }

    if (pkeyRsaSign.sigmdType != pkeyRsaSign.mgfmdType) {
        KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_WARNING_FLAG, title, "pkey rsa sign - Invalid input", "pkeyRsaSign.sigmdType: %d, pkeyRsaSign.mgfmdType: %d", pkeyRsaSign.sigmdType, pkeyRsaSign.mgfmdType); 
        return _rsa_fallback_to_openssl(correlationId,
                                    "Currently Symcrypt library does not support different hash algorithms for signature and MGF1",
                                    fallbackFunction,
                                    kmppPtr,
                                    flen,
                                    from,
                                    tlen,
                                    to,
                                    padding);
    }

    if (pkeyRsaSign.getMaxLen) {
        // We mark by this flag when the initial sig was null and "to" was allocated by our client side code as a dummy buffer
        // In the future, we should probably remove this redundant allocation on the client side by adding a flag indicating the IPC layer that "to" buffer can be null 
        // When sig(to) is null the maximum size of the output buffer should be written to the siglen parameter.
        to = NULL;
    } else {
        // If sig is not NULL then before the call the siglen parameter should 
        // contain the length of the sig buffer.
        if (pkeyRsaSign.sigLen > (uint64_t)tlen) {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "siglen", "Invalid signature length", "sigLen: %d, tlen: %d ", pkeyRsaSign.sigLen, tlen);
            return res;
        } 
        siglen = pkeyRsaSign.sigLen;
    }
    if (padding == KMPP_RSA_PKCS1_PSS_PADDING) {
        if (KeyIso_rsa_pss_sign(correlationId,
                                kmppPtr,
                                pkeyRsaSign.sigmdType,
                                pkeyRsaSign.saltLen,
                                from + sizeof(pkeyRsaSign),
                                pkeyRsaSign.tbsLen,
                                to,
                                &siglen)== STATUS_OK) {
            if (siglen > INTMAX_MAX) {
                KEYISOP_trace_log_error_para(correlationId, 0, title, "Invalid result signature length",
                                     "signature length exceeds the maximum value of signed integer",
                                     "siglen: %d", siglen);
                return res;
            }
            res = (int)siglen;
            KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete- Success");
        } else {
            KEYISOP_trace_log_error(correlationId, 0, title, "rsa sign", "KeyIso_rsa_pss_sign failed");
        }

        return res;
    }
    // Padding is not KMPP_RSA_PKCS1_PSS_PADDING => Fallback to Openssl
    char message[120];
    snprintf(message, sizeof(message), "SymCrypt engine currently supports only KMPP_RSA_PKCS1_PSS_PADDING padding for pkey_rsa_sign. The received padding:%d", padding);
    return _rsa_fallback_to_openssl(correlationId,
                                    message,
                                    fallbackFunction,
                                    kmppPtr,
                                    flen,
                                    from,
                                    tlen,
                                    to,
                                    padding);
}

 //TODO: add fallback for ec keys with curves that are not supported by symcrypt.
#if 0 
//#ifdef KMPP_OPENSSL_SUPPORT
static int _cleanup_ecdsa_fallback_to_openssl(
    const uuid_t correlationId,
    EC_KEY* ecKey,
    EC_GROUP* ecGroup,
    const char* errorMsg,
    int res)
{
    if (res != STATUS_OK) {
        KEYISOP_trace_log_openssl_error(correlationId, 0, KEYISOP_ECC_SIGN_TITLE, errorMsg);
    }

    EC_KEY_free(ecKey);
    EC_GROUP_free(ecGroup);
    return res;
}
//#endif // KMPP_OPENSSL_SUPPORT

static int _ecdsa_fallback_to_openssl(
            const uuid_t correlationId,
            const char* message,
            PKMPP_KEY kmppPtr,
            uint8_t keyUsage,
            uint32_t curve,
            int type, 
            const unsigned char *dgst, 
            int dlen, 
            unsigned char *sig, 
            unsigned int siglen, 
            unsigned int *outlen) 
{
    const char *title = KEYISOP_ECC_SIGN_TITLE;
    int res = -1;

#ifdef KMPP_OPENSSL_SUPPORT

    ERR_clear_error();

    PSYMCRYPT_ECKEY symCryptKey = (PSYMCRYPT_ECKEY)kmppPtr->key;
    if(!symCryptKey) {
        KEYISOP_trace_log_error(correlationId, 0, title,
                                "Invalid key",
                                "Failed to convert to symCrypt ec key");
        return -1;
    }
    // Convert to openssl ec key
    EC_GROUP* ecGroup = EC_GROUP_new_by_curve_name(curve);
    if (!ecGroup) {
        return _cleanup_ecdsa_fallback_to_openssl(correlationId,
                                                  NULL,
                                                  NULL,
                                                  "Fallback to OpenSS - EC_GROUP_new_by_curve_name failed",
                                                  STATUS_FAILED);
    }

    EC_KEY* ecKey = EC_KEY_new_by_curve_name(curve);
    if (!ecKey) {
        return _cleanup_ecdsa_fallback_to_openssl(correlationId,
                                                  NULL,
                                                  NULL,
                                                 "Fallback to OpenSS - EC_KEY_new_by_curve_name failed",
                                                  STATUS_FAILED);
    }

    res = KeyIso_convert_symcrypt_ecc_to_epkey(correlationId,
                                                 curve,
                                                 ecKey,
                                                 ecGroup,                                                
                                                 symCryptKey);

    if (res != STATUS_OK) {
        return _cleanup_ecdsa_fallback_to_openssl(correlationId,
                                                  ecKey,
                                                  ecGroup,
                                                  "Fallback to OpenSSL- KeyIso_convert_symcrypt_ecc_to_epkey failed",
                                                  STATUS_FAILED);
    }

    EVP_PKEY *epkey = EVP_PKEY_new();
    if (!epkey) {
        return _cleanup_ecdsa_fallback_to_openssl(correlationId,
                                                  ecKey,
                                                  ecGroup,
                                                  "Fallback to OpenSSL- EVP_PKEY_new failed",
                                                  STATUS_FAILED);
    }

    if (EVP_PKEY_set1_EC_KEY(epkey, ecKey) != 1) {
         return _cleanup_ecdsa_fallback_to_openssl(correlationId,
                                                  ecKey,
                                                  ecGroup,
                                                  "Fallback to OpenSSL- EVP_PKEY_set1_EC_KEY failed",
                                                  STATUS_FAILED);
    }
    
    KEYISOP_trace_log_error(correlationId, KEYISOP_TRACELOG_WARNING_FLAG, title,
                            "Fallback to OpenSSL", message);

    res = KeyIso_SERVER_ecdsa_sign_ossl(correlationId, epkey,
                                        type, dgst, dlen,
                                        sig, siglen, outlen);

    return _cleanup_ecdsa_fallback_to_openssl(correlationId,
                                              ecKey,
                                              ecGroup,
                                              NULL,
                                              STATUS_OK);
#else
    // No openssl support hence no fallback
    KEYISOP_trace_log_error(correlationId, 0, title,
                            "Not supported",
                            message);
    return res;

#endif // KMPP_OPENSSL_SUPPORT
}
#endif

// This function is taken from SCOSSL
// It generates precisely the DER encodings which we want for ECDSA signatures for the NIST prime curves
// Takes 2 same-size big-endian integers output from SymCrypt and encodes them in the minimally sized(strict) equivalent DER encoding
// The padding is added here to the int in the case that the most significant bit is 1 in which case, in DER encoding, a 0 byte needs to be prepended (as DER integers are always signed)
static int _encode_to_der(
    const uuid_t correlationId, 
    unsigned char* inSymCryptSignaturePtr,
    unsigned int inSymCryptSignatureLen,
    unsigned char* derSigPtr,
    unsigned int derSiglen,
    unsigned int* outDerSiglen)

{
    unsigned char* pbWrite = derSigPtr;
    unsigned int cbSeq = 0;
    unsigned int padSeq = 0;
    unsigned char* pbR = NULL;
    unsigned int cbR = 0;
    unsigned int padR = 0;
    unsigned char* pbS = NULL;
    unsigned int cbS = 0;
    unsigned int padS = 0;
    
    // Check the provided lengths are within reasonable bounds
    if ((inSymCryptSignatureLen < KMPP_ECDSA_MIN_SYMCRYPT_SIGNATURE_LEN) ||
        (inSymCryptSignatureLen > KMPP_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN) ||
        (inSymCryptSignatureLen % 2 == 1)) {

        KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_ECC_SIGN_TITLE,
                               "Incorrect size", "inSymCryptSignatureLen",
                               "inSymCryptSignatureLen %d should be even integer in range [%d, %d]",
                               inSymCryptSignatureLen, KMPP_ECDSA_MIN_SYMCRYPT_SIGNATURE_LEN, KMPP_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN);     
        return STATUS_FAILED;
    }

    pbR = inSymCryptSignaturePtr;
    cbR = inSymCryptSignatureLen/2;
    pbS = inSymCryptSignaturePtr + cbR;
    cbS = inSymCryptSignatureLen/2;

    while ((*pbR == 0) && cbR > 0) {
        pbR++;
        cbR--;
    }
    if ((*pbR & 0x80) == 0x80) {
        padR = 1;
    }

    while ((*pbS == 0) && cbS > 0) {
        pbS++;
        cbS--;
    }
    if ((*pbS & 0x80) == 0x80) {
        padS = 1;
    }

    cbSeq = cbR + padR + cbS + padS + 4;
    if ( cbSeq > 0x7f ) {
        // cbSeq must be encoded in 2 bytes - 0x81 <cbSeq>
        padSeq = 1;
    }
    
    *outDerSiglen = cbSeq + padSeq + 2;
    if (*outDerSiglen > derSiglen) {
        KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_ECC_SIGN_TITLE,
                                     "Incorrect size", "The DER encoded signature size is greater than the provided buffer",
                                     "DER encoded signature len: %d, Provided buffer len: %d", *outDerSiglen, derSiglen);
        return STATUS_FAILED;
    }

    // Write SEQUENCE header
    *pbWrite = 0x30;
    pbWrite++;
    if (padSeq) {
        *pbWrite = 0x81;
        pbWrite++;
    }
    *pbWrite = (uint8_t) cbSeq;
    pbWrite++;

    // Write R
    pbWrite[0] = 0x02;
    pbWrite[1] = (uint8_t) (cbR + padR);
    pbWrite += 2;
    if (padR ) {
        *pbWrite = 0;
        pbWrite++;
    }
    memcpy(pbWrite, pbR, cbR);
    pbWrite += cbR;

    // Write S
    pbWrite[0] = 0x02;
    pbWrite[1] = (uint8_t) (cbS + padS);
    pbWrite += 2;
    if (padS) {
        *pbWrite = 0;
        pbWrite++;
    }
    memcpy(pbWrite, pbS, cbS);
    return STATUS_OK;
}


int KeyIso_SERVER_ecdsa_sign(
    const uuid_t correlationId, 
    void *pkey, 
    int type __attribute__((unused)), // this parameter is not used in SymCrypt but needed for NOT_COMPATIBLE mode
    const unsigned char *dgst, 
    int dlen, 
    unsigned char *sig, 
    unsigned int siglen, 
    unsigned int *outlen)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    const char *title = KEYISOP_ECC_SIGN_TITLE;
    PKMPP_KEY kmppPtr = (PKMPP_KEY) pkey;
    size_t symCryptSigLen = 0;
    int res = -1;

    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Start"); 
    if(dgst == NULL || sig == NULL || outlen == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid input", "NULL");
        return res;
    }
    
    *outlen = 0; 
    
    if (kmppPtr == NULL || kmppPtr->key == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid input", "Key is null or empty");
        return res;
    }

    if (kmppPtr->type != KmppKeyType_ec) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "Invalid input", "Incorrect key type", "Key type: %d", kmppPtr->type);
        return res;
    }
    PSYMCRYPT_ECKEY ecKEy = (PSYMCRYPT_ECKEY)kmppPtr->key;
    // The following should be verified in SymCrypt. However, the ECDSA self test is executed 
    // before this verification and cause to a fatal error if the correct flag was not set.
    if ((ecKEy->fAlgorithmInfo & SYMCRYPT_FLAG_ECKEY_ECDSA) == 0) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Key usage", "This key is not allowed to be used for ECDSA");
        return res;
    }

    symCryptSigLen = 2*SymCryptEcurveSizeofScalarMultiplier(ecKEy->pCurve);
    if (siglen < symCryptSigLen) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "Invalid signature buffer length", "siglen",
                                    "siglen: %d, symCryptSigLen:%d", siglen, symCryptSigLen);
        return res;
    }
    
    BYTE buf[KMPP_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN] = { 0 };
    scError = SymCryptEcDsaSign(ecKEy,
                                dgst,
                                dlen,
                                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                0,
                                buf,
                                symCryptSigLen);

    if (scError != SYMCRYPT_NO_ERROR) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "Sign a message using the ECDSA signature algorithm failed", "SymCryptEcDsaSign", "scError: %d", scError);
        return res;
    }

    int ret = _encode_to_der(correlationId, buf, symCryptSigLen, sig, siglen, outlen);
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, title, "failed to encode symcrypt signature to DER", "_encode_to_der failed");   
        return res;
    }

    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete- Success");
    return STATUS_OK;
}

static int _cleanup_import_symmetric_key(
    const uuid_t correlationId, 
    int status,
    unsigned char* keyToEncrypt,
    unsigned char* hmacKey,
    unsigned char* encryptedKey,
    const char *errStr)
{
    const char *title = KEYISOP_IMPORT_SYMMETRIC_KEY_TITLE;
    if (status == STATUS_FAILED) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, errStr);
    } else {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete- Success");
    }
    
    KeyIso_free(encryptedKey);
    
    if(keyToEncrypt != NULL) {
        KeyIso_cleanse(keyToEncrypt, KMPP_AES_256_KEY_SIZE);
    }

    if(hmacKey != NULL) {
        KeyIso_cleanse(hmacKey, KMPP_AES_256_KEY_SIZE);
    }

    return status;
}

int KeyIso_SERVER_import_symmetric_key(
    const uuid_t correlationId,
    const int inSymmetricKeyType,
    const unsigned int inKeyLength,
    const unsigned char *inKeyBytes,
    const unsigned char *inImportKeyId, // Unique identifier to the imported key
    unsigned int *outKeyLength,
    unsigned char **outKeyBytes)        // KeyIso_free()
{
    unsigned char salt[KMPP_SALT_SHA256_SIZE];
    unsigned char metaData[KMPP_SYMMETRICKEY_META_DATA_LEN];
    unsigned char encryptKey[KMPP_AES_256_KEY_SIZE];
    unsigned char hmacKey[KMPP_HMAC_SHA256_KEY_SIZE];
    unsigned int offset = 0;
    
    *outKeyLength = 0;
    *outKeyBytes = NULL;

    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_IMPORT_SYMMETRIC_KEY_TITLE, "Start"); 
    // Validate key size for CBC encryption block size
    if (inSymmetricKeyType != KEYISO_IPC_SYMMETRIC_KEY_AES_CBC) {
        return _cleanup_import_symmetric_key(correlationId, STATUS_FAILED, NULL, NULL, NULL, "Invalid SymmetricKey type for CBC encryption");    
    }

    // Validate key size for CBC encryption block size
    if (inKeyLength % KMPP_AES_BLOCK_SIZE != 0) {
        return _cleanup_import_symmetric_key(correlationId, STATUS_FAILED, NULL, NULL, NULL, "Invalid key size for CBC encryption key size");    
    }

    if (KeyIso_generate_salt_bytes(
        correlationId,
        salt,
        sizeof(salt)) != STATUS_OK) {       
            return _cleanup_import_symmetric_key(correlationId, STATUS_FAILED, NULL, NULL, NULL, "Generate salt failed");       
    }

    // Derive encrypt key and hmac key from the password
    unsigned char *encryptedKey = KeyIso_zalloc(inKeyLength);
    if (encryptedKey == NULL) {
        return _cleanup_import_symmetric_key(correlationId, STATUS_FAILED, NULL, NULL, NULL, "encryptedKey allocation failed");       
    }

    if (KeyIso_symcrypt_kdf_generate_key_symmetrickey(
        correlationId,
        salt,
        sizeof(salt),
        encryptKey,
        KMPP_AES_256_KEY_SIZE,
        hmacKey,
        KMPP_HMAC_SHA256_KEY_SIZE) != STATUS_OK) {
            return _cleanup_import_symmetric_key(correlationId, STATUS_FAILED, encryptKey, hmacKey, encryptedKey, "Generate keys failed"); 
    }

    // meta data of the import key is the salt + unique identifier to the imported key
    KeyIso_copy_data_dest_offset(metaData, salt, sizeof(salt), &offset);
    KeyIso_copy_data_dest_offset(metaData, inImportKeyId, KMPP_AES_256_KEY_SIZE, &offset);

    //encrypt the key and build the output blob
    if (KeyIso_symmetric_create_encrypted_data(
            correlationId,
            inKeyLength,
            inKeyBytes,
            encryptKey,
            hmacKey,
            sizeof(hmacKey),
            metaData,
            sizeof(metaData),
            outKeyLength,
            outKeyBytes) != STATUS_OK) {
        return _cleanup_import_symmetric_key(correlationId, STATUS_FAILED, encryptKey, hmacKey, encryptedKey, "KeyIso_symmetric_create_encrypted_data failed");
    }

    // Check the output len of the import operation that is the correct size
    unsigned int expectedLen = 0;
    if (KeyIso_symmetric_key_encrypt_decrypt_size(
        KEYISO_AES_ENCRYPT_MODE,
        inKeyLength,
        KMPP_SYMMETRICKEY_META_DATA_LEN,
        &expectedLen) != STATUS_OK) {
            return _cleanup_import_symmetric_key(correlationId, STATUS_FAILED, encryptKey, hmacKey, encryptedKey, "encrypt_decrypt_size error");
    }
    if (expectedLen != *outKeyLength) {
        KeyIso_free(*outKeyBytes);
        *outKeyLength = 0;
        return _cleanup_import_symmetric_key(correlationId, STATUS_FAILED, encryptKey, hmacKey, encryptedKey, "KeyIso_symmetric_key_encrypt returned invalid len");    
    }

    int res = (*outKeyLength != 0) && (*outKeyBytes != NULL);
    return _cleanup_import_symmetric_key(correlationId, res, encryptKey, hmacKey, encryptedKey, NULL);    
}

static int _cleanup_symmetric_key_cipher(
    const uuid_t correlationId, 
    int status,
    unsigned char *keyBytes,
    unsigned int keyBytesLen,
    unsigned char* keyToEncrypt,
    unsigned char* hmacKey,
    unsigned char *outBuf,
    const char *errStr)
{
    const char *title = KEYISOP_SYMMETRIC_ENC_DEC_TITLE;
    if (status == STATUS_FAILED) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, errStr);
    } else {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete- Success");
    }

    KeyIso_cleanse(hmacKey, KMPP_HMAC_SHA256_KEY_SIZE);
    KeyIso_cleanse(keyToEncrypt, KMPP_AES_256_KEY_SIZE);
    KeyIso_clear_free(keyBytes, keyBytesLen);
    KeyIso_free(outBuf);

    return status;
}

int KeyIso_SERVER_symmetric_key_encrypt_decrypt(
    const uuid_t correlationId,
    const int mode,
    int inKeyLength,
    const unsigned char *inKeyBytes,
    const unsigned char *from,
    unsigned int fromLen,
    unsigned char *to,
    unsigned int *toLen)
{
    unsigned int dataLength = 0;
    unsigned char *keyBytes = NULL; // KeyIso_clear_free() 
    unsigned int bufLen = 0;
    unsigned int resDataLen = 0;
    unsigned char *outBuf = NULL;
    unsigned char *kdfEncryptLabel = (unsigned char *) KMPP_KDF_CBC_HMAC_LABEL;
    int kdfEncryptLabelLen = sizeof(KMPP_KDF_CBC_HMAC_LABEL);

    unsigned char encryptKey[KMPP_AES_256_KEY_SIZE]; // KeyIso_cleanse()
    unsigned char hmacKey[KMPP_HMAC_SHA256_KEY_SIZE]; // KeyIso_cleanse()

    *toLen = 0;

    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_SYMMETRIC_ENC_DEC_TITLE, "Start");
    if (from == NULL || to == NULL) {
        return _cleanup_symmetric_key_cipher(correlationId, STATUS_FAILED, keyBytes, 0, encryptKey, hmacKey, outBuf, "Invalid In / Out buffer");
    }

    // Open the encrypted key that will be used for encrypt / decrypt
    if (KeyIso_symmetric_open_encrypted_key(
        correlationId,
        inKeyLength,
        inKeyBytes,
        &dataLength,
        &keyBytes) != STATUS_OK){
            return _cleanup_symmetric_key_cipher(correlationId, STATUS_FAILED, keyBytes, dataLength, encryptKey, hmacKey, outBuf, "Open key error");   
    }

    // Derive two keys from the decrypted key - for encrypt and HMAC
    if (KeyIso_symcrypt_kdf_generate_keys(
        correlationId,
        keyBytes,
        dataLength,
        kdfEncryptLabel,
        kdfEncryptLabelLen,
        NULL,       //for encrypt/decrypt we are not using salt
        0,
        encryptKey,
        KMPP_AES_256_KEY_SIZE,
        hmacKey,
        KMPP_HMAC_SHA256_KEY_SIZE) != STATUS_OK) {
            return _cleanup_symmetric_key_cipher(correlationId, STATUS_FAILED, keyBytes, dataLength, encryptKey, hmacKey, outBuf, "Generate key error");   
    }

    // Encrypt / decrypt the data
    if (mode == KEYISO_AES_ENCRYPT_MODE) {
        if (KeyIso_symmetric_create_encrypted_data (
            correlationId,
            fromLen,
            from,
            encryptKey,
            hmacKey,
            sizeof(hmacKey),
            NULL,   // meta data is not in use for the encryption of the data
            0,
            &bufLen,
            &outBuf) != STATUS_OK) {
                return _cleanup_symmetric_key_cipher(correlationId, STATUS_FAILED, keyBytes, dataLength, encryptKey, hmacKey, outBuf, "Encrypt error");   
        }
        resDataLen = bufLen;
    } else if (mode == KEYISO_AES_DECRYPT_MODE) {  
        if (KeyIso_symmetric_open_encrypted_data(
            correlationId,
            fromLen,
            from,
            encryptKey,
            hmacKey,
            sizeof(hmacKey),
            &bufLen,
            &outBuf) != STATUS_OK) {
                return _cleanup_symmetric_key_cipher(correlationId, STATUS_FAILED, keyBytes, dataLength, encryptKey, hmacKey, outBuf, "Decrypt error");
        }
        resDataLen = KeyIso_get_key_padded_size(bufLen);
    } else {
        return _cleanup_symmetric_key_cipher(correlationId, STATUS_FAILED, keyBytes, dataLength, encryptKey, hmacKey, outBuf, "incorrect mode");
    }

    // Check the output len of the encrypt/decrypt operation that is the correct size
    unsigned int expectedLen = 0;
    if (KeyIso_symmetric_key_encrypt_decrypt_size(
        mode,
        fromLen,
        0,
        &expectedLen) != STATUS_OK) {
            return _cleanup_symmetric_key_cipher(correlationId, STATUS_FAILED, keyBytes, dataLength, encryptKey, hmacKey,outBuf, "encrypt_decrypt_size error");
    }    
    if (resDataLen != expectedLen) {
        return _cleanup_symmetric_key_cipher(correlationId, STATUS_FAILED, keyBytes, dataLength, encryptKey, hmacKey, outBuf, "encrypt/decrypt failed, got incorrect size");
    }
    
    // Copy the buffer to output
    memcpy(to, outBuf, bufLen);
    *toLen = bufLen;
    return _cleanup_symmetric_key_cipher(correlationId, STATUS_OK, keyBytes, dataLength, encryptKey, hmacKey, outBuf, NULL); 
}