/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <string.h>

#include "keyisocommon.h"
#include "keyisolog.h"
#include "keyisoutils.h"
#include "keyisomemory.h"
#include "keyisoipccommands.h"
#include "keyisoservicekey.h"
#include "keyisoservicecrypto.h"
#include "keyisoservicekeygen.h"
#include "keyisoservicesymmetrickey.h"
#include "keyisosymcryptcommon.h"


// Hash digest lengths (same values as defined in OpenSSL)
#define KMPP_MD5_DIGEST_LENGTH      16
#define KMPP_SHA1_DIGEST_LENGTH     20
#define KMPP_MD5_SHA1_DIGEST_LENGTH (KMPP_MD5_DIGEST_LENGTH + KMPP_SHA1_DIGEST_LENGTH) // 36
#define KMPP_SHA256_DIGEST_LENGTH   32
#define KMPP_SHA384_DIGEST_LENGTH   48
#define KMPP_SHA512_DIGEST_LENGTH   64

#define KMPP_ALGO_VERSION_LENGTH_SIZE 1 // 1 byte for the length of the algorithm version

/////////////////////////////////////////////////////
//////////////// Internal KDF methods ///////////////
/////////////////////////////////////////////////////

int KeyIso_symcrypt_pbe_key_derivation(
    const uuid_t correlationId, 
    PCSYMCRYPT_MAC  macAlgorithm,
    uint64_t iterationCnt,
    const unsigned char *password,
    uint32_t passwordLen,
    const unsigned char *salt,  // optional
    uint32_t saltLen,
    unsigned char *kdf2Key,
    uint32_t kdf2KeyLen)
{
    const char *title = KEYISOP_IMPORT_KEY_TITLE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    uint32_t passlen = 0;

    if (passwordLen == UINT32_MAX) { // since that passwordLen is uint32_t, if it assigned with -1 it will be UINT32_MAX
        passlen = strlen((char *)password);
    } else {
        passlen = passwordLen;
    }

    scError = SymCryptPbkdf2(
        macAlgorithm,
        password,   
		passlen,
        salt,                         
		saltLen,                            
        iterationCnt,
        kdf2Key,
        kdf2KeyLen);
    if (scError != SYMCRYPT_NO_ERROR) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, NULL, "SymCryptPbkdf2 Failed", "scError: %d", scError);
        return STATUS_FAILED;
    }
    
    return STATUS_OK;
}

int KeyIso_symcrypt_kdf_key_derivation(
    const uuid_t correlationId, 
    PCSYMCRYPT_MAC  macAlgorithm,
    const unsigned char *key,
    uint32_t keyLen,
    const unsigned char *label,    // optional
    uint32_t labelLen,
    const unsigned char *context,  // salt - optional
    uint32_t contextLen,
    unsigned char *kdf2Key,
    uint32_t kdf2KeyLen)
{
    const char *title = KEYISOP_SYMMETRIC_ENC_DEC_TITLE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    scError = SymCryptSp800_108(
        macAlgorithm,
        key,   
		keyLen,
        label,                         
		labelLen,                            
        context,
        contextLen,
        kdf2Key,
        kdf2KeyLen);
    if (scError != SYMCRYPT_NO_ERROR) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, NULL, "SymCryptSp800_108 failed", "scError: %d", scError);
        return STATUS_FAILED;
    }
    
    return STATUS_OK;
}

/////////////////////////////////////////////////////
//////////////// Internal AES methods ///////////////
/////////////////////////////////////////////////////

int KeyIso_symcrypt_aes_encrypt_decrypt(
    const uuid_t correlationId,
    const int mode,    // KEYISO_AES_ENCRYPT_MODE  / KEYISO_AES_DECRYPT_MODE
    const int padding, // KEYISO_AES_PADDING_PKCS7 / KEYISO_AES_PADDING_NONE
    unsigned char *iv,          // In case of encrypt the iv should be allocated with the ivLen and the iv value will be generated inside the function
    const uint32_t ivLen,    
    const unsigned char *kdf2Key,
    const uint32_t keyLen,   
    const unsigned char *inBuf, 
    const uint32_t bufLen,
    unsigned char *outBuf,
    uint32_t *outBufLen)
{
    const char *title = KEYISOP_IMPORT_KEY_TITLE;
    unsigned char pbChainingValue[KMPP_AES_BLOCK_SIZE];

    SYMCRYPT_AES_EXPANDED_KEY expandedkey;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

    if (keyLen != KMPP_AES_256_KEY_SIZE) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "key length", "incorrect IV length"," Got key len: %d", keyLen);  
        return STATUS_FAILED;
    }

    if (ivLen != KMPP_AES_BLOCK_SIZE) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "iv length", "incorrect IV length"," Got IV len: %d", ivLen);  
        return STATUS_FAILED;
    }

    if (mode == KEYISO_AES_ENCRYPT_MODE) {
        //For encryption - set the iv to random bytes
        if (iv == NULL) {
            KEYISOP_trace_log_error(correlationId, 0, title, NULL, "Got Iv set to NULL, the IV should be initalized first"); 
            return STATUS_FAILED;            
        }
        if (KeyIso_rand_bytes(iv, ivLen) != STATUS_OK) {
            KEYISOP_trace_log_error(correlationId, 0, title, "iv length", "Fail to set IV");
            return STATUS_FAILED;
        } 
    }
    
    //copy the IV to pbChainingValue to not override the original iv, pbChainingValue is in use by SymCryptAesCbcEncrypt and updated for every block
    memcpy(pbChainingValue, iv, ivLen);

    scError = SymCryptAesExpandKey( 
		&expandedkey, 
		kdf2Key, 
		keyLen);
    if (scError != SYMCRYPT_NO_ERROR) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, NULL, "SymCryptAesExpandKey failed", "scError: %d", scError);
        return STATUS_FAILED;
    }

    if (mode == KEYISO_AES_ENCRYPT_MODE) {
        if (padding == KEYISO_AES_PADDING_PKCS7) {
            // Add the PKCS7 padding to the input
            // PKCS7 padding is extremely sensitive to side channels attack
            // in our case since that the data is after successful HMAC verification, we can be sure that the data here has not been tampered
            if (KeyIso_padding_pkcs7_add(
                    correlationId,
                    inBuf,
                    bufLen,
                    outBuf, // outBuf is used as temp buffer for padding
                    outBufLen) != STATUS_OK) {
                KEYISOP_trace_log_error(correlationId, 0, title, NULL, "padding allocation error");
                return STATUS_FAILED;
            }
        } else if (padding == KEYISO_AES_PADDING_NONE) {
            // In case of no padding, the outBufLen should be equal to the bufLen
            memcpy(outBuf, inBuf, bufLen);
            *outBufLen = bufLen;
        } else {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "padding", "Incorrect padding"," Got padding: %d", padding);  
            return STATUS_FAILED;
        }
        
        SymCryptAesCbcEncrypt(
            &expandedkey, 
            pbChainingValue,                        
            outBuf, // outBuf contains the padded data to encrypt                          
            outBuf,                                                  
            *outBufLen);
    } else if (mode == KEYISO_AES_DECRYPT_MODE) {
        SymCryptAesCbcDecrypt(
            &expandedkey, 
            pbChainingValue,                        
            inBuf,                          
            outBuf,                                                  
            bufLen);

        if (padding == KEYISO_AES_PADDING_PKCS7) {
            // Remove the PKCS7 padding from the output
            // PKCS7 padding is extremely sensitive to side channels attack
            // in our case since that the data is after successful HMAC verification, we can be sure that the data here has not been tampered
            if (KeyIso_padding_pkcs7_remove(
                    correlationId,
                    outBuf,
                    bufLen,
                    outBufLen) != STATUS_OK) {
                KEYISOP_trace_log_error(correlationId, 0, title, NULL, "KeyIso_padding_pkcs7_remove Failed");
                return STATUS_FAILED;
            }
        } else if (padding == KEYISO_AES_PADDING_NONE) {
            // In case of no padding, the outBufLen should be equal to the bufLen
            *outBufLen = bufLen;
        } else {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "padding", "Incorrect padding"," Got padding: %d", padding);  
            return STATUS_FAILED;
        }
    } else {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "SymCryptAesExpandKey", "Incorrect mode"," Got mode: %d", mode);  
        return STATUS_FAILED;
    }
    
    return STATUS_OK;
}

/////////////////////////////////////////////////////
/////////////// Internal Padding methods ////////////
/////////////////////////////////////////////////////

// Calculates padding size and adds the padding to the paddedData
// When sending data as null it will return only the padding size
int KeyIso_padding_pkcs7_add(
    const uuid_t correlationId,
    const unsigned char *dataToEncrypt,
    unsigned int dataToEncryptLen,
    unsigned char *paddedData,
    unsigned int *paddedDataLen)
{
    const char *title = KEYISOP_SERVICE_TITLE;

    *paddedDataLen = KeyIso_get_key_padded_size(dataToEncryptLen);

    if (*paddedDataLen < dataToEncryptLen || (*paddedDataLen - dataToEncryptLen) > KMPP_AES_BLOCK_SIZE) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Padding", "Invalid paddedDataLen");
        return STATUS_FAILED;
    }

    if (!dataToEncrypt) {
        // In this case we only compute the paddedDataLen
        return STATUS_OK;
    }

    SIZE_T pcbResult = *paddedDataLen;
    SymCryptPaddingPkcs7Add(
        KMPP_AES_BLOCK_SIZE,
        dataToEncrypt,
        dataToEncryptLen,
        paddedData,
        *paddedDataLen,
        &pcbResult);

    return STATUS_OK;
}

int KeyIso_padding_pkcs7_remove(
    const uuid_t correlationId,
    unsigned char *decryptedData,
    unsigned int decryptedDataLen,
    unsigned int *removedPaddingDataLen)
{
    const char *title = KEYISOP_SERVICE_TITLE;

    SIZE_T pcbResult = 0;    
    SYMCRYPT_ERROR scError = SymCryptPaddingPkcs7Remove(
        KMPP_AES_BLOCK_SIZE,
        decryptedData,
        decryptedDataLen,
        decryptedData, // padding removal reduce the size of decryptedData, hance it's OK to use the buffer that allocated with dataLength
        decryptedDataLen,
        &pcbResult);
    if (scError != SYMCRYPT_NO_ERROR || (pcbResult > (size_t)INT64_MAX)) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Padding", "Invalid paddingValue");
        return STATUS_FAILED;
    }

    *removedPaddingDataLen = pcbResult;
    return STATUS_OK;
}

/////////////////////////////////////////////////////
/////////////// Internal PBE methods ////////////////
/////////////////////////////////////////////////////

static int _pbe_decrypt_hmac_cleanup(
    int ret,
    const uuid_t correlationId,
    const char *title,
    unsigned char *macData,
    unsigned char *derivedKey,
    size_t derivedKeyLen)
{
    if (ret != STATUS_OK)
        KEYISOP_trace_log_error(correlationId, 0, title, KMPP_INTEGRITY_ERR_STR, "Failed");

    if (macData)
        KeyIso_free(macData);
    if (derivedKey)
        KeyIso_clear_free(derivedKey, derivedKeyLen);

    return ret;
}

int KeyIso_symcrypt_pbe_decrypt_hmac(
    const uuid_t correlationId,
    const char *title,
    uint32_t version,
    const unsigned char *password,
    uint32_t passwordLen,
    const unsigned char *salt,
    uint32_t saltLen,
    unsigned char *iv,
    uint32_t ivLen,
    const unsigned char *hmac,
    uint32_t hmacLen,   
    const unsigned char *inBuf, 
    unsigned char *outBuf,
    uint32_t bufLen)
{
    if (!salt || !iv || !hmac || !inBuf) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid input", "NULL input parameters");
        return STATUS_FAILED;
    }

    int ret = STATUS_FAILED;

    unsigned int iterationCnt = KMPP_PKCS5_DEFAULT_ITER;
    unsigned int hmacDataLen = 0;
    unsigned int derivedKeyLen = 0;
    unsigned int index = 0;
    unsigned int versionLenSize = KMPP_ALGO_VERSION_LENGTH_SIZE;

    unsigned char versionLen = sizeof(version);
    unsigned char *macData = NULL;
    unsigned char *derivedKey = NULL;

    unsigned char hmacResult[KMPP_AES_256_KEY_SIZE];

    // Deriving a key
    derivedKeyLen = SymCryptHmacSha512Algorithm->resultSize;
    derivedKey = (unsigned char*)KeyIso_zalloc(derivedKeyLen);
    if (!derivedKey)
        return STATUS_FAILED;

    // The following switch is for backward compatibility
    switch (version)
    {
        case AlgorithmVersion_V1:
            iterationCnt = KMPP_PKCS5_DEFAULT_ITER_V1;   // previous iteration count
            versionLenSize = 0;                          // No versionLen in the mac data
            break;
        case AlgorithmVersion_V2:
            versionLenSize = 0;                          // No versionLen in the mac data
            break;
        case AlgorithmVersion_V3:
            // No changes since V3 is the current version
            break;                  
        default:
            break;
    }

    ret = KeyIso_symcrypt_pbe_key_derivation(
        correlationId,
        SymCryptHmacSha512Algorithm,
        iterationCnt,
        password,
        passwordLen,
        salt,
        saltLen,
        derivedKey,
        derivedKeyLen);
    if (ret != STATUS_OK)
            return _pbe_decrypt_hmac_cleanup(STATUS_FAILED, correlationId, title, NULL, derivedKey, derivedKeyLen);

    // MAC calculation
    // MAC DATA = versionLen | version | salt | iv | cipherText
    hmacDataLen = versionLenSize + versionLen + saltLen + ivLen + bufLen;
    macData = (unsigned char *) KeyIso_zalloc(hmacDataLen);
    if (!macData)
        return _pbe_decrypt_hmac_cleanup(STATUS_FAILED, correlationId, title, NULL, derivedKey, derivedKeyLen);
    // Copy data for mac calculation
    memcpy(macData, &versionLen, versionLenSize);
    index += versionLenSize;
    memcpy(macData, &version, versionLen);
    index += versionLen;
    memcpy(macData + index, salt, saltLen);
    index += saltLen;
    memcpy(macData + index, iv, ivLen);
    index += ivLen;
    memcpy(macData + index, inBuf, bufLen);

    ret = KeyIso_sha256_hmac_calculation(
        correlationId,
        macData,
        hmacDataLen,
        derivedKey + KMPP_HMAC_SHA256_KEY_SIZE,
        KMPP_HMAC_SHA256_KEY_SIZE,
        hmacResult);
    if (ret != STATUS_OK)
        return _pbe_decrypt_hmac_cleanup(STATUS_FAILED, correlationId, title, macData, derivedKey, derivedKeyLen);

    // MAC verification
    if((hmacLen != sizeof(hmacResult)) || (KeyIso_hmac_validation(hmac, hmacResult, KMPP_HMAC_SHA256_KEY_SIZE) != STATUS_OK))
        return _pbe_decrypt_hmac_cleanup(STATUS_FAILED, correlationId, title, macData, derivedKey, derivedKeyLen);

    // Key decryption
    ret = KeyIso_symcrypt_aes_encrypt_decrypt(
        correlationId,
        KEYISO_AES_DECRYPT_MODE,
        KEYISO_AES_PADDING_NONE,
        iv,
        ivLen,
        derivedKey,
        KMPP_AES_256_KEY_SIZE,
        inBuf,
        bufLen,
        outBuf,
        &bufLen);
    return _pbe_decrypt_hmac_cleanup(ret, correlationId, title, macData, derivedKey, derivedKeyLen);
}

int KeyIso_symcrypt_pbe_encrypt_hmac(
    const uuid_t correlationId,
    const char *title,
    uint32_t version,
    const unsigned char *password,
    uint32_t passwordLen,
    const unsigned char *salt,   // optional
    uint32_t saltLen,
    unsigned char *iv,           // ivLen: KMPP_AES_BLOCK_SIZE
    uint32_t ivLen,    
    const unsigned char *inBuf, 
    unsigned char *outBuf,
    uint32_t bufLen,             // multiple of KMPP_AES_BLOCK_SIZE
    unsigned char *hmac,
    uint32_t hmacLen)
{
    if (hmacLen != KMPP_HMAC_SHA256_KEY_SIZE) {
        KEYISOP_trace_log_error(correlationId, 0, title, "hmacLen", "Invalid length");
        return STATUS_FAILED;
    }

    if (!salt || !iv) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid input", "NULL input parameters");
        return STATUS_FAILED;
    }

    int ret = STATUS_FAILED;

    unsigned int index = 0;
    unsigned int hmacDataLen = 0;
    unsigned int derivedKeyLen = 0;
    unsigned int versionLenSize = KMPP_ALGO_VERSION_LENGTH_SIZE;

    unsigned char versionLen = sizeof(version);
    unsigned char *pMacKey = NULL;
    unsigned char *pMacData = NULL;
    unsigned char *pDerivedKey = NULL;
    
    // PKCS #5 password-based encryption
    ret = KeyIso_symcrypt_pbe(
        correlationId,
        title,
        KEYISO_AES_ENCRYPT_MODE,
        password,
        passwordLen,
        salt,
        saltLen,
        iv,
        ivLen,
        inBuf,
        outBuf,
        bufLen,
        &pDerivedKey,
        &derivedKeyLen);
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, title, "KeyIso_symcrypt_pbe", "Failed");
        return STATUS_FAILED;
    }

    if (derivedKeyLen != KMPP_AES_512_KEY_SIZE) {
        KEYISOP_trace_log_error(correlationId, 0, title, "derivedKeyLen", "Invalid length");
        KeyIso_clear_free(pDerivedKey, derivedKeyLen);
        return STATUS_FAILED;
    }

    // MAC DATA = versionLen | version | salt | iv | cipherText
    hmacDataLen = versionLenSize + versionLen + saltLen + ivLen + bufLen;
    pMacData = (unsigned char *) KeyIso_zalloc(hmacDataLen);
    if (!pMacData) {
        KEYISOP_trace_log_error(correlationId, 0, title, "pMacData", "Memory allocation failed");
        KeyIso_clear_free(pDerivedKey, derivedKeyLen);
        return STATUS_FAILED;
    }

    // Copy data for mac calculation
    memcpy(pMacData, &versionLen, versionLenSize);
    index += versionLenSize;
    memcpy(pMacData, &version, versionLen);
    index += versionLen;
    memcpy(pMacData + index, salt, saltLen);
    index += saltLen;
    memcpy(pMacData + index, iv, ivLen);
    index += ivLen;
    memcpy(pMacData + index, outBuf, bufLen);

    // MAC calculation
    pMacKey = pDerivedKey + KMPP_HMAC_SHA256_KEY_SIZE;
    ret = KeyIso_sha256_hmac_calculation(
        correlationId,
        pMacData,
        hmacDataLen,
        pMacKey,
        KMPP_HMAC_SHA256_KEY_SIZE,
        hmac); 
    
    KeyIso_free(pMacData);
    KeyIso_clear_free(pDerivedKey, derivedKeyLen);

    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, title, "KeyIso_sha256_hmac_calculation", "Failed");
        return ret;
    }

    return ret;
}

int KeyIso_symcrypt_pbe(
    const uuid_t correlationId,
    const char *title,
    const int mode,
    const unsigned char *password,
    uint32_t passwordLen,
    const unsigned char *salt,   // optional
    uint32_t saltLen,
    unsigned char *iv,           // ivLen: KMPP_AES_BLOCK_SIZE
    uint32_t ivLen,    
    const unsigned char *inBuf, 
    unsigned char *outBuf,
    uint32_t bufLen,             // multiple of KMPP_AES_BLOCK_SIZE
    unsigned char **derivedKey,
    uint32_t *keySize)
{
    int ret = STATUS_FAILED;
    PCSYMCRYPT_MAC macAlgorithm = SymCryptHmacSha512Algorithm;
    unsigned char *key = NULL;

    *keySize = macAlgorithm->resultSize;
    key = (unsigned char*)KeyIso_zalloc(*keySize);
    if (!key) {
        KEYISOP_trace_log_error(correlationId, 0, title, "key", "allocation error");
        return STATUS_FAILED;
    }

    ret = KeyIso_symcrypt_pbe_key_derivation(
        correlationId,
        macAlgorithm,
        KMPP_PKCS5_DEFAULT_ITER,
        password,
        passwordLen,
        salt,
        saltLen,
        key,
        *keySize);
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, title, "_symcrypt_pbe_key_derivation", "Failed");
        KeyIso_clear_free(key, *keySize);
        return ret;
    } 

    // key: [encKey] [macKey]
    // Example: For HmacSha512, the size of the derived key is 512 bits.
    // The first 256 bits will be used as the encryption key,
    // and the remaining 256 bits will be used as the mac key.
    ret = KeyIso_symcrypt_aes_encrypt_decrypt(
        correlationId,
        mode,
        KEYISO_AES_PADDING_NONE,
        iv,
        ivLen,
        key,
        (*keySize)/2,
        inBuf,
        bufLen,
        outBuf,
        &bufLen);
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, title, "_symcrypt_pbe_encrypt_decrypt", "Failed");
        KeyIso_clear_free(key, *keySize);
        return ret;
    }  

    *derivedKey = key;
    return ret;
}

/////////////////////////////////////////////////////
///////// Internal Asymmetric Keys methods //////////
/////////////////////////////////////////////////////

PKMPP_KEY KeyIso_kmpp_key_create( 
     const uuid_t correlationId,
     KmppKeyType type, 
     void *keyPtr)
{
     if (!keyPtr) {
          KEYISOP_trace_log_error(correlationId,
                                  0,
                                  KEYISOP_KEY_TITLE,
                                  "Invalid input",
                                  "key is null");
          return NULL;
    }

    PKMPP_KEY kmppKey = (PKMPP_KEY)KeyIso_zalloc(sizeof(KMPP_KEY));
    if (!kmppKey) {
          KEYISOP_trace_log_error(correlationId,
                                  0,
                                  KEYISOP_KEY_TITLE,
                                  "Key Create Error",
                                  "Failed to allocate key");
          return NULL;
    }
    kmppKey->type = type;
    kmppKey->key = keyPtr;
    kmppKey->refCounter = (KEYISO_REFERENCE_ST){KeyIso_kmpp_key_free, 1};
    return kmppKey;
}

// KeyIso_free when compiled with openssl uses OPENSSL_free which frees the memory but does not set the key pointer to null
void KeyIso_kmpp_key_free(
    const uuid_t correlationId, 
    const KEYISO_REFERENCE_ST *refcount)
{
    PKMPP_KEY keyPtr = CONTAINER_OF(refcount, KMPP_KEY, refCounter);
    if (!keyPtr) {
         KEYISOP_trace_log_error(correlationId, 0, KEYISOP_KEY_TITLE, "Key Free Error", "Failed get key from refCount");
         return;
    }

    if (keyPtr->key) {
        if (keyPtr->type == KmppKeyType_rsa)  {
            PSYMCRYPT_RSAKEY pSymCryptRsaKey = (PSYMCRYPT_RSAKEY) keyPtr->key;
            if (pSymCryptRsaKey) {
                SymCryptRsakeyFree(pSymCryptRsaKey);            
                keyPtr->key = NULL;
                KeyIso_free(keyPtr);
                return;
            }
        }
    
        if (keyPtr->type == KmppKeyType_ec) {
            PSYMCRYPT_ECKEY pSymCryptKey = (PSYMCRYPT_ECKEY)keyPtr->key;
            if (pSymCryptKey) {
                SymCryptEckeyFree(pSymCryptKey);   
                keyPtr->key = NULL;
                KeyIso_free(keyPtr);
                return;
            }
        }
    
#ifdef KMPP_OPENSSL_SUPPORT
        if (keyPtr->type == KmppKeyType_epkey) {
            EVP_PKEY* epkey = (EVP_PKEY *) keyPtr->key;
            if (epkey) {
                EVP_PKEY_free(epkey);
                keyPtr->key = NULL;
                KeyIso_free(keyPtr);
                return;
            }
        }
#endif //KMPP_OPENSSL_SUPPORT
    }
   
    KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_KEY_TITLE, "Key Free Error", "Failed to free key invalid parameter", "key type: %d", keyPtr->type);
    KeyIso_free(keyPtr);
}

// RSA
static PSYMCRYPT_RSAKEY _cleanup_get_symcrypt_rsa_key(
    const uuid_t correlationId,
    int res, 
    PSYMCRYPT_RSAKEY key, 
    const char *loc)
{
    if (res != STATUS_OK) {
        if (key != NULL) {
            SymCryptRsakeyFree(key);
        }
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_SERVICE_TITLE, loc, "Failed");
        return NULL;
    }
    return key;
}

PSYMCRYPT_RSAKEY KeyIso_get_rsa_symcrypt_pkey( 
    const uuid_t correlationId,
    KEYISO_RSA_PKEY_ST* inRsaPkeySt) 
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PSYMCRYPT_RSAKEY pSymCryptRsaKey = NULL;
    SYMCRYPT_RSA_PARAMS rsaParam;

    if (!inRsaPkeySt) {
        return _cleanup_get_symcrypt_rsa_key(correlationId, STATUS_FAILED, NULL, "Invalid Input");
    }

    if (inRsaPkeySt->rsaModulusLen == 0 ||  inRsaPkeySt->rsaPublicExpLen == 0 ) {
        return _cleanup_get_symcrypt_rsa_key(correlationId, STATUS_FAILED, NULL, "Invalid Input, modulus and public exponent length should be greater than 0");
    }

    if (inRsaPkeySt->rsaPrimes1Len == 0 ||  inRsaPkeySt->rsaPrimes2Len == 0 ) {
        return _cleanup_get_symcrypt_rsa_key(correlationId, STATUS_FAILED, NULL, "Invalid Input, only two-prime RSA supported");
    }

    uint8_t* primes[KEYISO_SYMCRYPT_RSA_SUPPORTED_NUM_OF_PRIMES] = { 0 };
    SIZE_T   primesLen[KEYISO_SYMCRYPT_RSA_SUPPORTED_NUM_OF_PRIMES] = { inRsaPkeySt->rsaPrimes1Len, inRsaPkeySt->rsaPrimes2Len };
    uint64_t publicExp;
    int index = 0; 

    // Currently, in SymCrypt the only acceptable value of nPubExp is 1 or 0 and nPrimes are 2 or 0 (0 only for public key)
    rsaParam.version = KEYISO_SYMCRYPT_RSA_PARAMS_VERSION;
    rsaParam.nBitsOfModulus = inRsaPkeySt->rsaModulusLen * 8;
    rsaParam.nPrimes = KEYISO_SYMCRYPT_RSA_SUPPORTED_NUM_OF_PRIMES;
    rsaParam.nPubExp = KEYISO_SYMCRYPT_RSA_PARAMS_N_PUB_EXP;

    if (rsaParam.nBitsOfModulus > KMPP_OPENSSL_RSA_MAX_MODULUS_BITS || rsaParam.nBitsOfModulus < KMPP_RSA_MIN_MODULUS_BITS) {
        return _cleanup_get_symcrypt_rsa_key(correlationId, STATUS_FAILED, NULL, "Invalid Input, modulus length is out of range");
    }
    
    pSymCryptRsaKey = SymCryptRsakeyAllocate(&rsaParam, 0);
    if (pSymCryptRsaKey == NULL ) {
        return _cleanup_get_symcrypt_rsa_key(correlationId, STATUS_FAILED, NULL, "SymCryptRsakeyAllocate");
    }
    index = inRsaPkeySt->rsaModulusLen;
    if (SymCryptLoadMsbFirstUint64((PBYTE) &inRsaPkeySt->rsaPkeyBytes[index], inRsaPkeySt->rsaPublicExpLen, &publicExp) != SYMCRYPT_NO_ERROR ) {
        return _cleanup_get_symcrypt_rsa_key(correlationId, STATUS_FAILED, pSymCryptRsaKey, "SymCryptLoadMsbFirstUint64");
    }    

    index +=  inRsaPkeySt->rsaPublicExpLen;
    primes[0] = &inRsaPkeySt->rsaPkeyBytes[index];
    index += inRsaPkeySt->rsaPrimes1Len;

    primes[1] = &inRsaPkeySt->rsaPkeyBytes[index];
    index += inRsaPkeySt->rsaPrimes2Len;    

    scError = SymCryptRsakeySetValue(
                   &inRsaPkeySt->rsaPkeyBytes[0],                   // Modulus
                   inRsaPkeySt->rsaModulusLen,                      // cbModulus
                   &publicExp,                                      // pu64PubExp
                   1,
                   (PCBYTE *)primes,                                // ppPrimes
                   (SIZE_T *)primesLen,                             // pcbPrimes
                   KEYISO_SYMCRYPT_RSA_SUPPORTED_NUM_OF_PRIMES,
                   SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,                // numFormat,
                   KMPP_KEY_USAGE_TO_SYMCRYPT_FLAG(inRsaPkeySt->rsaUsage),
                   pSymCryptRsaKey);

    if (scError != SYMCRYPT_NO_ERROR ) {
        KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_SERVICE_TITLE, "ERROR", "Failed to create symcrypt rsa key", "scError: %d, rsaUsage: 0x%x", scError, inRsaPkeySt->rsaUsage);
        return _cleanup_get_symcrypt_rsa_key(correlationId, STATUS_FAILED, pSymCryptRsaKey, "SymCryptRsakeySetValue");
    }
    return  _cleanup_get_symcrypt_rsa_key(correlationId, STATUS_OK, pSymCryptRsaKey, NULL);
}

// Export to struct both the private and public parts of SYMCRYPT_RSAKEY 
static int _export_rsa_pkey(
    const uuid_t correlationId,
    PSYMCRYPT_RSAKEY inRsaKey,
    uint8_t* modulusBytes,
    size_t modulusLen,
    uint8_t* publicExp,
    size_t publicExpLen,
    uint8_t** primes,
    size_t* primesLen) 
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;   
    uint32_t numsOfPrimes = (!primes) ? 0 : KEYISO_SYMCRYPT_RSA_SUPPORTED_NUM_OF_PRIMES ;
    uint64_t pubExp = 0;

    if ( !modulusBytes || !publicExp ) {
        KEYISOP_trace_log_error(correlationId,
                                0,
                                KEYISOP_SERVICE_TITLE,
                                "Invalid input",
                                "modulus and public exponent cant be null");
        return STATUS_FAILED;
    }
  
    scError = SymCryptRsakeyGetValue(
                   inRsaKey,                                    // PCSYMCRYPT_RSAKEY
                   modulusBytes, modulusLen,
                   &pubExp,                                     // Public exponent
                   KEYISO_SYMCRYPT_RSA_PARAMS_N_PUB_EXP,
                   primes, primesLen,                           // Primes (private key) 
                   numsOfPrimes,                                // Number of primes
                   SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                   0);
    if (scError != SYMCRYPT_NO_ERROR )
    {
        KEYISOP_trace_log_error_para(correlationId,
                                     0,
                                     KEYISOP_SERVICE_TITLE,
                                     "_export_rsa_pkey ERROR",
                                     "SymCryptRsakeyGetValue failed",
                                     "scError: %d",
                                     scError);
        return STATUS_FAILED;
    }

    uint64_t rsaPublicExpLen = SymCryptUint64Bytesize( pubExp );
    if (rsaPublicExpLen != publicExpLen) {
        KEYISOP_trace_log_error_para(correlationId, 
                                     0,
                                     KEYISOP_SERVICE_TITLE,
                                     "SymCryptUint64Bytesize ERROR",
                                     "Public key array size is incompatible ",
                                     "public exponent array size: %d, public exp size:%d",
                                     publicExpLen,
                                     rsaPublicExpLen);
        return STATUS_FAILED;
    }
    scError = SymCryptStoreMsbFirstUint64(pubExp,
                                          publicExp,
                                          publicExpLen);
    if (scError != SYMCRYPT_NO_ERROR )
    {
        KEYISOP_trace_log_error_para(correlationId,
                                     0,
                                     KEYISOP_SERVICE_TITLE,
                                     "_export_rsa_pkey ERROR",
                                     "SymCryptStoreMsbFirstUint64 failed",
                                     "scError: %d",
                                     scError);
        return STATUS_FAILED;
    }
    return STATUS_OK;
}

KEYISO_RSA_PUBLIC_KEY_ST* KeyIso_export_rsa_public_key_from_symcrypt(
    const uuid_t correlationId,
    PSYMCRYPT_RSAKEY inPublicRsaKey) 
{ 
    uint32_t modulusArraySize = 0;
    uint32_t publicExponentArraySize = 0;
    uint32_t publicKeyLen = 0;

    if (inPublicRsaKey == NULL) {
        KEYISOP_trace_log_error(correlationId,
                                 0,
                                 KEYISOP_SERVICE_TITLE,
                                 "Invalid argument",
                                 "The received RSA key is null");
        return NULL;
    }

    modulusArraySize = SymCryptRsakeySizeofModulus(inPublicRsaKey);
    //Currently only one exponent supported by SymCrypt, i.e. the only valid index is 0
    publicExponentArraySize = SymCryptRsakeySizeofPublicExponent(inPublicRsaKey, 0);
    publicKeyLen = modulusArraySize + publicExponentArraySize;

    size_t structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_RSA_PUBLIC_KEY_ST, publicKeyLen);
    KEYISO_RSA_PUBLIC_KEY_ST* pRsaPkeySt = (KEYISO_RSA_PUBLIC_KEY_ST*)KeyIso_zalloc(structSize);

    if (!pRsaPkeySt) {
         KEYISOP_trace_log_error(correlationId,
                                 0,
                                 KEYISOP_SERVICE_TITLE,
                                 "pRsaPkeySt is null",
                                 "allocation failed");
        return NULL;
    }

    int res = _export_rsa_pkey(correlationId,
                               inPublicRsaKey,
                               pRsaPkeySt->rsaPubKeyBytes, modulusArraySize,
                               pRsaPkeySt->rsaPubKeyBytes + modulusArraySize, publicExponentArraySize,
                               NULL, 0);
    if (res != STATUS_OK) {
         KEYISOP_trace_log_error(correlationId,
                                 0,
                                 KEYISOP_SERVICE_TITLE,
                                 "_export_rsa_pkey",
                                 "Failed");
        KeyIso_free(pRsaPkeySt);
        return NULL;
    }
    pRsaPkeySt->rsaModulusLen = modulusArraySize;
    pRsaPkeySt->rsaPublicExpLen = publicExponentArraySize;

    KEYISO_KEY_HEADER_ST pKeyHeader;
    pKeyHeader.keyVersion = KEYISO_PKEY_VERSION;
    pKeyHeader.magic = KEYISO_PKEY_MAGIC_UNINITIALIZED;
    pRsaPkeySt->header = pKeyHeader;

    return pRsaPkeySt;
}

static KEYISO_RSA_PKEY_ST* _cleanup_get_symcrypt_rsa_pkey(
    const uuid_t correlationId,
    int status,
    KEYISO_RSA_PKEY_ST* keySt,
    size_t keyStSize,
    uint8_t*  prime1,
    uint8_t*  prime2,
    const char *loc,
    const char *message)
{
    KeyIso_free(prime1);
    KeyIso_free(prime2);

    if (status != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId,
                                 0,
                                 KEYISOP_SERVICE_TITLE,
                                 loc,
                                 message);
        KeyIso_clear_free(keySt, keyStSize);
        return NULL;
    }
    return keySt;
}

// KeyIso_clear_free() should be used to free the memory allocated by this function
KEYISO_RSA_PKEY_ST* KeyIso_export_rsa_pkey_from_symcrypt(
    const uuid_t correlationId,
    PSYMCRYPT_RSAKEY inRsaKey,
    size_t *keyStSize) 
{ 
    KEYISO_RSA_PKEY_ST* pRsaPkeySt = NULL;
    uint64_t offset = 0;
    uint32_t modulusArraySize = 0;
    uint8_t* primes[KEYISO_SYMCRYPT_RSA_SUPPORTED_NUM_OF_PRIMES] = { 0 };
    size_t   primesLen[KEYISO_SYMCRYPT_RSA_SUPPORTED_NUM_OF_PRIMES];
    
    if (inRsaKey == NULL || keyStSize == NULL) {
         KEYISOP_trace_log_error(correlationId,
                                 0,
                                 KEYISOP_SERVICE_TITLE,
                                 "Invalid argument",
                                 "The received key nor key size ptr can't be null");
        return NULL;
    }
    
    *keyStSize = 0;
    modulusArraySize = SymCryptRsakeySizeofModulus(inRsaKey);
    primesLen[0]     = SymCryptRsakeySizeofPrime(inRsaKey, 0);
    primesLen[1]     = SymCryptRsakeySizeofPrime(inRsaKey, 1);

    primes[0] = (uint8_t*)KeyIso_zalloc(primesLen[0]);
    if (!primes[0]) {
        return _cleanup_get_symcrypt_rsa_pkey(correlationId,
                                              STATUS_FAILED,
                                              NULL,
                                              0,
                                              NULL,
                                              NULL,
                                              "allocation failed",
                                              "failed to allocate rsa pkey prime1");
    }

    primes[1] = (uint8_t*)KeyIso_zalloc(primesLen[1]);
    if (!primes[1]) {
        return _cleanup_get_symcrypt_rsa_pkey(correlationId,
                                              STATUS_FAILED,
                                              NULL,
                                              0,
                                              primes[0],
                                              NULL,
                                              "allocation failed",
                                              "failed to allocate rsa pkey prime2");
    }

   // Currently only one exponent supported by SymCrypt, i.e. the only valid index is 0
    uint32_t publicExponentArraySize = SymCryptRsakeySizeofPublicExponent(inRsaKey, 0);
    
    uint32_t pkeyLen = modulusArraySize +
                       publicExponentArraySize + 
                       primesLen[0] +
                       primesLen[1];

    size_t structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_RSA_PKEY_ST, pkeyLen);
    pRsaPkeySt = (KEYISO_RSA_PKEY_ST*)KeyIso_zalloc(structSize);
    if (!pRsaPkeySt) {
        return _cleanup_get_symcrypt_rsa_pkey(correlationId,
                                              STATUS_FAILED,
                                              pRsaPkeySt,
                                              0,
                                              primes[0],
                                              primes[1],
                                              "pRsaPkeySt is null",
                                              "pRsaPkeySt allocation failed");
    }

    int res = _export_rsa_pkey(correlationId,
                                        inRsaKey,
                                        pRsaPkeySt->rsaPkeyBytes, modulusArraySize,
                                        pRsaPkeySt->rsaPkeyBytes + modulusArraySize, publicExponentArraySize,
                                        primes,
                                        primesLen);
    if (res != STATUS_OK) {
        return _cleanup_get_symcrypt_rsa_pkey(correlationId,
                                              STATUS_FAILED,
                                              pRsaPkeySt,
                                              structSize,
                                              primes[0],
                                              primes[1],
                                              "_export_rsa_pkey",
                                              "Failed");
    }
 
    pRsaPkeySt->rsaUsage = KMPP_SYMCRYPT_FLAG_TO_KEY_USAGE(inRsaKey->fAlgorithmInfo);
    pRsaPkeySt->rsaModulusLen = modulusArraySize,
    pRsaPkeySt->rsaPublicExpLen = publicExponentArraySize;
    pRsaPkeySt->rsaPrimes1Len = primesLen[0];
    pRsaPkeySt->rsaPrimes2Len = primesLen[1];

    KEYISO_KEY_HEADER_ST pKeyHeader;
    pKeyHeader.keyVersion = KEYISO_PKEY_VERSION;
    pKeyHeader.magic = KEYISO_RSA_PRIVATE_PKEY_MAGIC;
    pRsaPkeySt->header = pKeyHeader;

    // Copy the p and q bytes
    offset = modulusArraySize + publicExponentArraySize;
    memcpy(&pRsaPkeySt->rsaPkeyBytes[offset], primes[0], primesLen[0]);
    offset += primesLen[0];
    memcpy(&pRsaPkeySt->rsaPkeyBytes[offset], primes[1], primesLen[1]);
    *keyStSize = structSize;
    return _cleanup_get_symcrypt_rsa_pkey(correlationId,
                                          STATUS_OK,
                                          pRsaPkeySt,
                                          structSize,
                                          primes[0],
                                          primes[1],
                                          NULL,
                                          NULL);
}

// EC
static int _export_get_ec_key_from_symcrypt(
    const uuid_t correlationId,
    PSYMCRYPT_ECKEY inEcKey,
    uint8_t* pPublicKey,
    size_t publicKeyLen,
    uint8_t* pPrivateKey,
    size_t privateKeyLen)
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    int res = STATUS_FAILED;
  
    if (!inEcKey) {
        KEYISOP_trace_log_error(correlationId,
                                0,
                                KEYISOP_SERVICE_TITLE,
                                "Invalid input",
                                "ec key is null");
        return res;
    }
  
    if (!pPublicKey || publicKeyLen == 0) {
        KEYISOP_trace_log_error(correlationId,
                                0,
                                KEYISOP_SERVICE_TITLE,
                                "Invalid input",
                                "public key cant be null");
        return res;   
    }

    scError = SymCryptEckeyGetValue(
        inEcKey,
        pPrivateKey, privateKeyLen,
        pPublicKey, publicKeyLen,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        0 );
    
    if (scError != SYMCRYPT_NO_ERROR )
    {
        KEYISOP_trace_log_error_para(correlationId,
                                     0, 
                                     KEYISOP_SERVICE_TITLE,
                                     "_export_get_ec_key_from_symcrypt ERROR",
                                     "SymCryptEckeyGetValue failed",
                                     "scError: %d",
                                     scError);
        return res;   
    }
    return STATUS_OK;
}

KEYISO_EC_PUBLIC_KEY_ST* KeyIso_export_ec_public_key_from_symcrypt(
    const uuid_t correlationId,
    unsigned int curveNid,
    PSYMCRYPT_ECKEY inPublicEcKey) 
{
    SIZE_T publicKeyLen = 0;

    if (!inPublicEcKey) {
        KEYISOP_trace_log_error(correlationId,
                                0,
                                KEYISOP_SERVICE_TITLE,
                                "Invalid input",
                                "ec key is null");
        return NULL;
    }
    
    publicKeyLen = SymCryptEckeySizeofPublicKey(inPublicEcKey, SYMCRYPT_ECPOINT_FORMAT_XY);

    size_t structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_EC_PUBLIC_KEY_ST, publicKeyLen);
    KEYISO_EC_PUBLIC_KEY_ST* pEcPubkeySt = (KEYISO_EC_PUBLIC_KEY_ST*)KeyIso_zalloc(structSize);

    if (!pEcPubkeySt) {
        KEYISOP_trace_log_error(correlationId,
                                0, 
                                KEYISOP_SERVICE_TITLE,
                                "Allocation ERROR",
                                "Failed to allocate KEYISO_EC_PUBLIC_KEY_ST");
        return NULL;   
    }

    pEcPubkeySt->ecCurve = curveNid;
    pEcPubkeySt->ecPubKeyLen = publicKeyLen;

    KEYISO_KEY_HEADER_ST pKeyHeader;
    pKeyHeader.keyVersion = KEYISO_PKEY_VERSION;
    pKeyHeader.magic = KEYISO_PKEY_MAGIC_UNINITIALIZED;
    pEcPubkeySt->header = pKeyHeader;

    int res = _export_get_ec_key_from_symcrypt(correlationId,
                                               inPublicEcKey,
                                               pEcPubkeySt->ecPubKeyBytes, publicKeyLen,
                                               NULL, 0); // No need for the private part of the key
    if (res != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId,
                                0, 
                                KEYISOP_SERVICE_TITLE,
                                "KeyIso_export_ec_public_key_from_symcrypt ERROR",
                                "_export_get_ec_key_from_symcrypt failed");
        KeyIso_free(pEcPubkeySt);
        return NULL;
    }

    return pEcPubkeySt;
}

// KeyIso_clear_free() nedd to be used for the returned pointer
KEYISO_EC_PKEY_ST* KeyIso_export_ec_pkey_from_symcrypt(
    const uuid_t correlationId,
    unsigned int curveNid,
    PSYMCRYPT_ECKEY inEcPkey,
    size_t *keyStSize)
{
    SIZE_T publicKeyLen = 0;
    SIZE_T privateKeyLen = 0;

    if (!inEcPkey || !keyStSize) {
        KEYISOP_trace_log_error(correlationId,
                                0,
                                KEYISOP_SERVICE_TITLE,
                                "Invalid input",
                                "ec key or out key size is null");
        return NULL;
    }

    *keyStSize = 0;
    publicKeyLen = SymCryptEckeySizeofPublicKey(inEcPkey, SYMCRYPT_ECPOINT_FORMAT_XY);
    privateKeyLen = SymCryptEckeySizeofPrivateKey(inEcPkey);

    size_t structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_EC_PKEY_ST, publicKeyLen + privateKeyLen);
    KEYISO_EC_PKEY_ST* pEcPkeySt = (KEYISO_EC_PKEY_ST*)KeyIso_zalloc(structSize); // KeyIso_clear_free()

    if (!pEcPkeySt) {
        KEYISOP_trace_log_error(correlationId,
                                    0,
                                    KEYISOP_SERVICE_TITLE,
                                    "Allocation ERROR",
                                    "Failed to allocate KEYISO_EC_PKEY_ST");
        return NULL;   
    }

    pEcPkeySt->ecUsage = KMPP_SYMCRYPT_FLAG_TO_KEY_USAGE(inEcPkey->fAlgorithmInfo);
    pEcPkeySt->ecCurve = curveNid;
    pEcPkeySt->ecPubXLen = publicKeyLen/2;
    pEcPkeySt->ecPubYLen = pEcPkeySt->ecPubXLen;
    pEcPkeySt->ecPrivKeyLen = privateKeyLen;

    KEYISO_KEY_HEADER_ST pKeyHeader;
    pKeyHeader.keyVersion = KEYISO_PKEY_VERSION;
    pKeyHeader.magic = KEYISO_EC_PRIVATE_PKEY_MAGIC;
    pEcPkeySt->header = pKeyHeader;

    int res = _export_get_ec_key_from_symcrypt(correlationId,
                                           inEcPkey,
                                           pEcPkeySt->ecKeyBytes, publicKeyLen,
                                           pEcPkeySt->ecKeyBytes + publicKeyLen, privateKeyLen);
    if (res == STATUS_FAILED) {
        KEYISOP_trace_log_error(correlationId,
                                0, 
                                KEYISOP_SERVICE_TITLE,
                                "_export_get_ec_key_from_symcrypt",
                                "Failed");
        KeyIso_clear_free(pEcPkeySt, structSize);
        return NULL;
    }
    *keyStSize = structSize;
    return pEcPkeySt;
}

PSYMCRYPT_ECKEY KeyIso_get_ec_symcrypt_pkey(
    const uuid_t correlationId,
    KEYISO_EC_PKEY_ST* inEcPkey)
{
    const char *title = KEYISOP_SERVICE_TITLE;
    if (!inEcPkey) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid input", "ec key is null");
        return NULL;
    }

    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PSYMCRYPT_ECKEY pSymCryptKey = NULL;
    size_t privateCurveKeyLen = 0;
    size_t publicCurveKeyLen = 0;
    size_t publicKeyActualLen = inEcPkey->ecPubXLen + inEcPkey->ecPubYLen;
    size_t privateActualLen = inEcPkey->ecPrivKeyLen;

    PSYMCRYPT_ECURVE curve = KeyIso_get_curve_by_nid(correlationId, inEcPkey->ecCurve);
    if (curve == NULL) {
        KEYISOP_trace_log_error_para(correlationId, 0, title,
                                     "KeyIso_get_ec_symcrypt_pkey ERROR",
                                     "Unsupported curve",
                                     "received curve: %d", inEcPkey->ecCurve);
        return NULL;
    }
    
    pSymCryptKey = SymCryptEckeyAllocate(curve);
    if (pSymCryptKey == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title,
                                "KeyIso_get_ec_symcrypt_pkey ERROR",
                                "SymCryptEckeyAllocate returned NULL");
        return NULL;
    }

    privateCurveKeyLen = SymCryptEckeySizeofPrivateKey(pSymCryptKey);
    if (privateCurveKeyLen < privateActualLen) {
        KEYISOP_trace_log_error_para(correlationId, 0, title,
                                    "ERROR",
                                    "Incompatible private key size",
                                    "curve size: %d, actual size: %d",
                                    privateCurveKeyLen,
                                    inEcPkey->ecPrivKeyLen);

        SymCryptEckeyFree(pSymCryptKey);                        
        return NULL;
    }
    publicCurveKeyLen = SymCryptEckeySizeofPublicKey(pSymCryptKey, SYMCRYPT_ECPOINT_FORMAT_XY);
    if (publicCurveKeyLen < publicKeyActualLen) {
         KEYISOP_trace_log_error_para(correlationId, 0, title,
                                    "ERROR",
                                    "Incompatible public key size",
                                    "curve NID:%d, curve size: %d, x size: %d, y size: %d",
                                    inEcPkey->ecCurve,
                                    publicCurveKeyLen,
                                    inEcPkey->ecPubXLen,
                                    inEcPkey->ecPubYLen);
        SymCryptEckeyFree(pSymCryptKey);                        
        return NULL;
    }
    scError = SymCryptEckeySetValue(
        &inEcPkey->ecKeyBytes[publicKeyActualLen], privateActualLen,
        &inEcPkey->ecKeyBytes[0], publicKeyActualLen,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        KMPP_KEY_USAGE_TO_SYMCRYPT_FLAG(inEcPkey->ecUsage),
        pSymCryptKey);
    if (scError != SYMCRYPT_NO_ERROR )
    {
        KEYISOP_trace_log_error_para(correlationId, 0, title,
                                    "ERROR",
                                    "Failed to create symcrypt ec key",
                                    "scError: %d, ecUsage: 0x%x",
                                    scError,
                                    inEcPkey->ecUsage);
        SymCryptEckeyFree(pSymCryptKey);                        
        return NULL;
    }
    
    return pSymCryptKey;
}

size_t KeyIso_get_pkey_bytes_len(int keyType, const void *privateKey)
{
    size_t keyLen = 0;
    switch (keyType) {
        case KmppKeyType_rsa:
            keyLen = GET_DYNAMIC_STRUCT_SIZE(KEYISO_RSA_PKEY_ST, KeyIso_get_rsa_pkey_bytes_len((KEYISO_RSA_PKEY_ST *) privateKey));
            break;
        case KmppKeyType_ec:
            keyLen = GET_DYNAMIC_STRUCT_SIZE(KEYISO_EC_PKEY_ST, KeyIso_get_ec_pkey_bytes_len((KEYISO_EC_PKEY_ST *) privateKey));
            break;
        default:
            KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "_get_private_key_len", "unsupported key type");
    }
    return keyLen;
}

int KeyIso_rsa_decrypt(
    const uuid_t correlationId, 
    PKMPP_KEY kmppKeyPtr, 
    uint32_t padding,
    uint32_t mdnid,                // Message digest identifier, only used if padding is set to RSA_PKCS1_OAEP_PADDING
    uint32_t labelLen,             // The label length
    const unsigned char* label,    // Label used for OAEP (Will be used in the future KMPP provider)
    uint32_t fromLen,              // A ciphertext size
    const unsigned char* from,     // A pointer to the ciphertext to be decrypted
    int32_t* pToLen,               // A pointer to an integer that will contain the length of the plaintext after decryption
    unsigned char* to)             // A pointer to the buffer where the plaintext will be stored
{
    int ret = STATUS_FAILED;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    PCSYMCRYPT_HASH symCryptHashAlgo = NULL;
    uint32_t modulusLen = SymCryptRsakeySizeofModulus(kmppKeyPtr->key);
    uint64_t err = 0;
    const char *title = KEYISOP_RSA_DECRYPT_TITLE;
    size_t resultLen = -1;

    *pToLen = -1;

    if (fromLen > modulusLen)
    {
        KEYISOP_trace_log_error_para(correlationId, 0, title,
                                     "Invalid input",
                                     "The ciphertext can't be larger then key modulus length",
                                     "fromLen: %d, modulusLen:%d", fromLen, modulusLen);
        return ret;
    }

    if (to == NULL)
    {
        ret = STATUS_OK;
        // An upper estimation for the output length
        *pToLen = (int32_t)modulusLen; 
        return ret;
    }

    switch (padding) //Since minimum RSA key size > maxmium padding size - no risk for underflow.
    {
        case KMPP_RSA_PKCS1_PADDING:
            scError = SymCryptRsaPkcs1Decrypt(
                kmppKeyPtr->key,
                from,
                fromLen,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0, // Must be 0 according to SymCrypt documentation
                to,
                modulusLen - KMPP_MIN_PKCS1_PADDING, // When encrypting, SymCryptRsaPkcs1Ecrypt  applies  padding of 11 bytes 
                &resultLen);

            // Constant-time error processing to avoid Bleichenbacher attack :

            // Set pToLen based on scError and resultLen
            // resultLen > INT_MAX           => err > 0
            err = (uint64_t)resultLen >> 31;

            // scError != SYMCRYPT_NO_ERROR  => err > 0
            err |= (uint32_t)(scError ^ SYMCRYPT_NO_ERROR);
            
            // if( err > 0 ) { pToLen = -1; }
            // else          { pToLen = 0; }
            *pToLen = (0ll - err) >> 32;
            
            // Set pToLen to resultLen if pToLen was set to  0
            *pToLen |= (uint32_t)resultLen;
            
            // if err <= 0  => We return STATUS_OK (1)
            // else         => We return STATUS_FAIL (0)
            ret = err <= 0;
            break;

        case KMPP_RSA_PKCS1_OAEP_PADDING:
            symCryptHashAlgo = KeyIso_get_symcrypt_hash_algorithm(mdnid);
            if (!symCryptHashAlgo)
            {
                KEYISOP_trace_log_error_para(correlationId, 0, title,
                                             "Invalid input",
                                             "Not supported",
                                             "Unknown message digest identifier: %d", mdnid);
                return ret;
            }

            scError = SymCryptRsaOaepDecrypt(
                kmppKeyPtr->key,
                from,
                fromLen,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                symCryptHashAlgo,
                label,       // A pointer to the label value used in the OAEP encoding scheme
                labelLen,    // The length in bytes of the label value
                0,    // A set of flags that control the behavior of the decryption operation (Allowed flags:None)
                to,
                modulusLen - KMPP_MIN_OAEP_PADDING,
                &resultLen);
            if (scError != SYMCRYPT_NO_ERROR)
            {
                KEYISOP_trace_log_error_para(correlationId, 0, title,
                                             "RSA private decrypt failed",
                                             "SymCryptRsaOaepDecrypt failed",
                                             "error: %d, flags:0x%x",
                                             scError, ((PCSYMCRYPT_RSAKEY)kmppKeyPtr->key)->fAlgorithmInfo);
                return ret;
            }
            break;
        case KMPP_RSA_NO_PADDING:
            scError = SymCryptRsaRawDecrypt(
                kmppKeyPtr->key,
                from,
                fromLen,
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                0, // Allowed flags:None
                to,
                modulusLen);

            if (scError != SYMCRYPT_NO_ERROR)
            {
                KEYISOP_trace_log_error_para(correlationId, 0, title,
                                             "RSA private decrypt failed",
                                             "SymCryptRsaRawDecrypt failed",
                                             "error: %d, flags: 0x%x",
                                             scError, ((PCSYMCRYPT_RSAKEY)kmppKeyPtr->key)->fAlgorithmInfo);
                return ret;
            }
            resultLen = modulusLen;
            break;
        default:
            KEYISOP_trace_log_error_para(correlationId, 0, title,
                                         "RSA private decrypt failed",
                                         "Unsupported padding",
                                         "Received padding: %d", padding);
            break;
    }
    // Calculate the len of the plaintext after decryption and the returned value for paddings that are not exposed to timing-based side-channel attack 
    ret = resultLen <= INT32_MAX ;
    *pToLen = ret ? (int32_t)resultLen : -1;
    return ret;
}

int KeyIso_rsa_pkcs1_sign( const uuid_t correlationId, 
                           PKMPP_KEY kmppPtr,
                           int32_t mdnid,                     // Message digest algorithm identifier(the hash algorithm used to compute the message digest)
                           const unsigned char* hashValue,     // A pointer to the computed message digest that will be signed using the RSA private key.
                           uint32_t hashValueLen,              // The length of the message digest
                           unsigned char* sig,                 // A pointer to the buffer where the signature will be stored
                           int *sigLen)                        // The length of the Signature
{
    uint32_t modulusSize = 0;
    const char *title = KEYISOP_SERVICE_TITLE;
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    const KMPP_RSA_PKCS1_PARAMS  *pkcs1Params = NULL;
    size_t resultSigLen = 0;

    if(hashValue == NULL || sig == NULL || sigLen == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_SERVICE_TITLE, 
                               "Invalid input", 
                               "The hashValue, digest signature nor sig length pointer can't pe null");
        return STATUS_FAILED;
    }

    if (kmppPtr == NULL || kmppPtr->key == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, 
                                "Invalid input",
                                "Key is null or empty");
        return STATUS_FAILED;
    }

    if (kmppPtr->type != KmppKeyType_rsa) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, 
                                    "Invalid input", 
                                    "Incorrect key type",
                                    "Key type:%d", kmppPtr->type);
        return STATUS_FAILED;
    }

    modulusSize = SymCryptRsakeySizeofModulus(kmppPtr->key);
    pkcs1Params = KeyIso_get_rsa_pkcs1_params(mdnid);
    if (pkcs1Params == NULL) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, 
                                     "Invalid input", 
                                     "The provided message digest algorithm identifier is not supported",
                                     "mdnid: %d. Size: %d.", mdnid, hashValueLen);
        return STATUS_FAILED;
    }
    
    int32_t expectedHash =  KeyIso_get_expected_hash_length(mdnid);
    if (expectedHash < 0 || (uint32_t)expectedHash != hashValueLen) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, 
                                     "Invalid input", 
                                     "Hash value length is incomputable with the received message digest algorithm identifier",
                                     "hashValueLen: %d, mdnid:%d", hashValueLen, mdnid);

       return STATUS_FAILED;
    }

    // Log warnings for algorithms that aren't FIPS compliant
    if (mdnid == KMPP_NID_md5_sha1 || mdnid == KMPP_NID_md5 ||  mdnid == KMPP_NID_sha1) {
        KEYISOP_trace_log_error_para(correlationId, KEYISOP_TRACELOG_WARNING_FLAG, title, 
                                     "Compliance warning",
                                     "Using Mac algorithm which is not FIPS compliant",
                                     "Hash algorithm identifier: %d", mdnid);
    }

    scError = SymCryptRsaPkcs1Sign(
        kmppPtr->key,
        hashValue,
        hashValueLen,
        pkcs1Params->pHashOIDs,
        pkcs1Params->nOIDCount,
        pkcs1Params->flags,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        sig,
        modulusSize,
        &resultSigLen);

    if (scError != SYMCRYPT_NO_ERROR)
    {
        KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_SERVICE_TITLE,
                        "KeyIso_rsa_pkcs1_sign error",
                        "SymCryptRsaPkcs1Sign failed",
                        "scError: %d, flags: 0x%x",
                        scError, ((PCSYMCRYPT_RSAKEY)kmppPtr->key)->fAlgorithmInfo);
        return STATUS_FAILED;
    }

    if (resultSigLen > INTMAX_MAX) {
        KEYISOP_trace_log_error_para(correlationId, 0, title,
                        "SymCryptRsaPkcs1Sign",
                        "signature length exceeds the maximum value of signed integer",
                        "resultSigLen: %d", resultSigLen);
        return STATUS_FAILED;
    }

    *sigLen = (int)resultSigLen;
    return STATUS_OK;
}

int KeyIso_rsa_pss_sign(
    const uuid_t correlationId, 
    PKMPP_KEY kmppPtr,
    int32_t mdnid,                   // Message digest algorithm identifier
    int32_t saltLen,                 // The length of the salt used in the RSA-PSS signature
    const unsigned char* hashValue,   // A pointer to the computed message digest that will be signed 
    uint64_t hashValueLen,            // The length of the message digest
    unsigned char *sig,               // A pointer to the buffer that will receive the signature
    size_t* pSigLen)                  // A pointer to a variable that will receive the length of the signature
{
    int ret = STATUS_FAILED;
    const char *title = KEYISOP_SERVICE_TITLE;
    if (hashValue == NULL || pSigLen == NULL) {
        KEYISOP_trace_log_error(correlationId,
                                0,
                                title,
                                "Invalid input",
                                "The digest signature and sig length pointer can't be null");
        return ret;
    }

    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    uint32_t saltMaxLen = 0;
    size_t resultLen = 0;
    PCSYMCRYPT_HASH hashAlgo = KeyIso_get_symcrypt_hash_algorithm(mdnid);
    int32_t  expectedHashLength = KeyIso_get_expected_hash_length(mdnid);

    if (hashAlgo == NULL || expectedHashLength <=0) {
        KEYISOP_trace_log_error_para(correlationId, 0, title,
                                     "Unknown type",
                                     "Hash algorithm",
                                     "hashAlgo is null or length is zero, message digest algorithm identifier: %d, expectedHashLength:%d",
                                     mdnid,
                                     expectedHashLength);
        return ret;
    }

    
    if (hashValueLen > UINT32_MAX) {
        KEYISOP_trace_log_error_para(correlationId, 0, title,
                                     "Invalid hash size",
                                     "Hash algorithm",
                                     "Message digest algorithm identifier: %d. Len: %d.",
                                     mdnid,
                                     expectedHashLength);
        return ret;
    }

    if (expectedHashLength < 0 || (uint32_t)hashValueLen != (uint32_t)expectedHashLength) {
        KEYISOP_trace_log_error_para(correlationId, 0, title,
                                     "Invalid hash size",
                                     "Hash algorithm",
                                     "Message digest algorithm identifier: %d. Len: %d.",
                                     mdnid,
                                     expectedHashLength);
        return ret;
    }
    saltMaxLen = ((SymCryptRsakeyModulusBits(kmppPtr->key) + 6) / 8) - (uint32_t)hashValueLen - 2; // ceil((ModulusBits - 1) / 8) - digestLen - 2

    // We define saltMaxLen as uint32_t to avoid implicit conversion that might result in a negative value.
	// Therefore, we have to ensure that saltMaxLen does not exceed INT32_MAX, as it will be assigned to an int32_t later.
    if (saltMaxLen > INT32_MAX) {
        KEYISOP_trace_log_error_para(correlationId, 0, title,
                                     "Invalid salt size",
                                     "Salt size exceeds the maximum value of signed integer",
                                     "saltMaxLen: %d", saltMaxLen);
        return ret;
    }

    switch (saltLen)
    {
    case KMPP_RSA_PSS_SALTLEN_DIGEST:
        saltLen = expectedHashLength;
        break;
    case KMPP_RSA_PSS_SALTLEN_MAX_SIGN:
    case KMPP_RSA_PSS_SALTLEN_MAX:
        saltLen = (int32_t)saltMaxLen;
        break;
    case KMPP_RSA_PSS_SALTLEN_AUTO_DIGEST_MAX:  // Added in OpenSSL 3.1
        saltLen = (int32_t)saltMaxLen < (int)hashValueLen ? (int32_t)saltMaxLen : (int)hashValueLen;
        break;
    default:
        KEYISOP_trace_log_error_para(correlationId, 0, title, NULL, "Invalid saltLen", "saltLen: %d", saltLen);
        return ret;
    }
    
    if (saltLen < 0 || (uint32_t)saltLen > saltMaxLen)  {
        KEYISOP_trace_log_error_para(correlationId, 0, title,
                                    "Invalid input",
                                    "Uncountable salt size",
                                    "saltLen: %d, saltMaxLen: %d",
                                    saltLen,
                                    saltMaxLen);
        return ret;
    }

    resultLen = SymCryptRsakeySizeofModulus(kmppPtr->key);

    if (sig == NULL) {
        *pSigLen = resultLen;
        return STATUS_OK;  // This API can be invoked with null for sig buffer to get the max signature length
    }

    // Log warnings for algorithms that aren't FIPS compliant
     if (mdnid == KMPP_NID_md5 || mdnid == KMPP_NID_sha1 ) {
        KEYISOP_trace_log_error_para(correlationId, KEYISOP_TRACELOG_WARNING_FLAG, title, 
                                     "Compliance warning",
                                     "Using Mac algorithm which is not FIPS compliant",
                                     "Hash algorithm identifier: %d", mdnid);
     }

    scError = SymCryptRsaPssSign(
        kmppPtr->key,
        hashValue,
        hashValueLen,
        hashAlgo,
        (size_t)saltLen,
        0,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        sig,
        resultLen,
        &resultLen);

    if (scError != SYMCRYPT_NO_ERROR) {
        KEYISOP_trace_log_error_para(correlationId, 0, title,
                                    "KeyIso_rsa_pss_sign error",
                                    "SymCryptRsaPssSign failed",
                                    "scError: %d, flags: 0x%x",
                                    scError, ((PCSYMCRYPT_RSAKEY)kmppPtr->key)->fAlgorithmInfo);
        return ret;
    }

    *pSigLen = resultLen;
    return STATUS_OK;
}
/////////////////////////////////////////////////////
///////////// Fallback to OpenSSL methods ///////////
/////////////////////////////////////////////////////

#ifdef KMPP_OPENSSL_SUPPORT
static EVP_PKEY* _cleanup_convert_symcrypt_to_epkey(
    const uuid_t correlationId,
    int res, 
    EVP_PKEY* epkey,
    RSA* rsa,
    const char *loc,
    uint8_t* modulusPtr,
    uint8_t* privateExpPtr,
    uint8_t* prime1Ptr,
    uint8_t* prime2Ptr,
    BIGNUM* rsa_n,
    BIGNUM* rsa_e,
    BIGNUM* rsa_p,
    BIGNUM* rsa_q,
    BIGNUM* rsa_d)
{
    KeyIso_free(modulusPtr);
    KeyIso_free(privateExpPtr);
    KeyIso_free(prime1Ptr);
    KeyIso_free(prime2Ptr);

     if (res != STATUS_OK) {
        RSA_free(rsa);
        EVP_PKEY_free(epkey);
        BN_free(rsa_n);
        BN_free(rsa_e);
        BN_free(rsa_p);
        BN_free(rsa_q);
        BN_free(rsa_d);
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_SERVICE_TITLE, loc, "Failed");
        return NULL;
    }
    return epkey;
}

EVP_PKEY* KeyIso_convert_symcrypt_rsa_to_epkey(
    const uuid_t correlationId,
    PSYMCRYPT_RSAKEY symcryptRsaKey)
{
    SYMCRYPT_ERROR scError;
    uint64_t pu64PubExp    = 0;
    uint8_t* modulusPtr    = NULL;
    uint8_t* privateExpPtr = NULL;
    uint32_t rsa_n_len = 0;
    uint32_t rsa_p_len = 0;
    uint32_t rsa_q_len = 0;
    uint32_t rsa_d_len = 0;
    RSA* rsa               = NULL;
    EVP_PKEY* pkey         = NULL;
    BIGNUM* rsa_n          = NULL;
    BIGNUM* rsa_e          = NULL;
    BIGNUM* rsa_p          = NULL;
    BIGNUM* rsa_q          = NULL;
    BIGNUM* rsa_d          = NULL;
    uint8_t* primes[KEYISO_SYMCRYPT_RSA_SUPPORTED_NUM_OF_PRIMES] = { 0 };
    SIZE_T   primesLen[KEYISO_SYMCRYPT_RSA_SUPPORTED_NUM_OF_PRIMES] ;
    
    if(symcryptRsaKey == NULL) {
        return  _cleanup_convert_symcrypt_to_epkey(correlationId, STATUS_FAILED, NULL, NULL, 
        "Convert RSA SymCrypt key to EVP_PKEY - Invalid argument , key is null", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
   }
    rsa_n_len = SymCryptRsakeySizeofModulus(symcryptRsaKey);
    rsa_p_len = SymCryptRsakeySizeofPrime(symcryptRsaKey, 0);
    primesLen[0] = rsa_p_len;
    rsa_q_len = SymCryptRsakeySizeofPrime(symcryptRsaKey, 1);
    primesLen[1] = rsa_q_len;
    rsa_d_len = rsa_n_len;

    modulusPtr = (uint8_t*)KeyIso_zalloc(rsa_n_len);
    if (!modulusPtr) {
        return  _cleanup_convert_symcrypt_to_epkey(correlationId, STATUS_FAILED, NULL, NULL, 
        "Convert RSA SymCrypt key to EVP_PKEY - failed to allocate modulus buffer", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    }

    privateExpPtr = (uint8_t*)KeyIso_zalloc(rsa_d_len);
    if (!privateExpPtr) {
        return  _cleanup_convert_symcrypt_to_epkey(correlationId, STATUS_FAILED, NULL, NULL, 
        "Convert RSA SymCrypt key to EVP_PKEY - failed to allocate private exponent buffer", modulusPtr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    }

    primes[0] = (uint8_t*)KeyIso_zalloc(rsa_p_len);
    if (!primes[0]) {
        return  _cleanup_convert_symcrypt_to_epkey(correlationId, STATUS_FAILED, NULL, NULL, 
        "Convert RSA SymCrypt key to EVP_PKEY - failed to allocate p buffer", modulusPtr, privateExpPtr, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    }

    primes[1] = (uint8_t*)KeyIso_zalloc(rsa_q_len);
    if (!primes[1]) {
       return  _cleanup_convert_symcrypt_to_epkey(correlationId, STATUS_FAILED, NULL, NULL, 
       "Convert RSA SymCrypt key to EVP_PKEY - failed to allocate q buffer", modulusPtr, privateExpPtr, primes[0] , NULL, NULL, NULL, NULL, NULL, NULL);
    }

    scError = SymCryptRsakeyGetValue(symcryptRsaKey,
                                    modulusPtr,
                                    rsa_n_len,
                                    &pu64PubExp,
                                    KEYISO_SYMCRYPT_RSA_PARAMS_N_PUB_EXP,
                                    primes,
                                    primesLen,
                                    KEYISO_SYMCRYPT_RSA_SUPPORTED_NUM_OF_PRIMES,
                                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                                    0 );

    if (scError != SYMCRYPT_NO_ERROR ) {
        KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_SERVICE_TITLE, "Convert RSA SymCrypt key to EVP_PKEY", "ERROR", "scError: %d", scError);
        return   _cleanup_convert_symcrypt_to_epkey(correlationId, STATUS_FAILED, NULL, NULL, 
        "Convert RSA SymCrypt key to EVP_PKEY - SymCryptRsakeyGetValue failed", modulusPtr, privateExpPtr, primes[0] , primes[1], NULL, NULL, NULL, NULL, NULL);
    }

    scError = SymCryptRsakeyGetCrtValue(
                        symcryptRsaKey,
                        NULL, NULL, 0,
                        NULL, 0,
                        privateExpPtr, rsa_d_len,
                        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                        0);
    if (scError != SYMCRYPT_NO_ERROR)
    {
        KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_SERVICE_TITLE, "Convert RSA SymCrypt key to EVP_PKEY", "Get private exp error", "scError: %d", scError);
        return  _cleanup_convert_symcrypt_to_epkey(correlationId, STATUS_FAILED, NULL, NULL, 
        "Convert RSA SymCrypt key to EVP_PKEY - SymCryptRsakeyGetCrtValue failed", modulusPtr, privateExpPtr, primes[0] , primes[1], NULL, NULL, NULL, NULL, NULL);
    }
    
    rsa = RSA_new();
    if (rsa == NULL) {
        return  _cleanup_convert_symcrypt_to_epkey(correlationId, STATUS_FAILED, NULL, NULL, 
        "Convert RSA SymCrypt key to EVP_PKEY - RSA_new failed", modulusPtr, privateExpPtr, primes[0] , primes[1], NULL, NULL, NULL, NULL, NULL);
    }
    
    if (rsa_n_len > INT_MAX) {
        return  _cleanup_convert_symcrypt_to_epkey(correlationId, STATUS_FAILED, NULL, rsa, 
        "Convert RSA SymCrypt key to EVP_PKEY - RSA_new failed", modulusPtr, privateExpPtr, primes[0] , primes[1], NULL, NULL, NULL, NULL, NULL);
    }
    rsa_n = BN_bin2bn(modulusPtr, (int)rsa_n_len, NULL);
    if (rsa_n == NULL) {
        return  _cleanup_convert_symcrypt_to_epkey(correlationId, STATUS_FAILED, pkey, rsa, 
        "Convert RSA SymCrypt key to EVP_PKEY - BN_bin2bn modulus failed", modulusPtr, privateExpPtr, primes[0] , primes[1], NULL, NULL, NULL, NULL, NULL);
    }
    
    rsa_e = BN_new();
    if(!rsa_e) {
       return  _cleanup_convert_symcrypt_to_epkey(correlationId, STATUS_FAILED, pkey, rsa, 
       "Convert RSA SymCrypt key to EVP_PKEY - BN_bin2bn public exponent failed", modulusPtr, privateExpPtr, primes[0] , primes[1], rsa_n, NULL, NULL, NULL, NULL);
    }
    
    if(!BN_set_word(rsa_e, pu64PubExp)) {
        return  _cleanup_convert_symcrypt_to_epkey(correlationId, STATUS_FAILED, pkey, rsa, 
        "Convert RSA SymCrypt key to EVP_PKEY - BN_set_word public exponent failed", modulusPtr, privateExpPtr, primes[0] , primes[1], rsa_n, rsa_e, NULL, NULL, NULL);
    }

    if (rsa_p_len > INT_MAX ||  rsa_q_len > INT_MAX || rsa_d_len > INT_MAX) {
        return  _cleanup_convert_symcrypt_to_epkey(correlationId, STATUS_FAILED, pkey, rsa, 
        "Convert RSA SymCrypt key to EVP_PKEY p, q or d length is too large", modulusPtr, privateExpPtr, primes[0] , primes[1], rsa_n, rsa_e, NULL, NULL, NULL);
    }
    rsa_p = BN_bin2bn(primes[0], (int)rsa_p_len, NULL);
    if (rsa_n == NULL) {
        return  _cleanup_convert_symcrypt_to_epkey(correlationId, STATUS_FAILED, pkey, rsa, 
        "Convert RSA SymCrypt key to EVP_PKEY - BN_bin2bn prime1 failed", modulusPtr, privateExpPtr, primes[0] , primes[1], rsa_n, rsa_e, NULL, NULL, NULL);
    }

    rsa_q = BN_bin2bn(primes[1], (int)rsa_q_len, NULL);
    if (rsa_q == NULL) {
        return  _cleanup_convert_symcrypt_to_epkey(correlationId, STATUS_FAILED, pkey, rsa, 
        "Convert RSA SymCrypt key to EVP_PKEY - BN_bin2bn prime1 failed", modulusPtr, privateExpPtr, primes[0] , primes[1], rsa_n, rsa_e, rsa_p, NULL, NULL);
    }

    rsa_d = BN_bin2bn(privateExpPtr, (int)rsa_d_len, NULL);
    if (rsa_d == NULL) {
       return  _cleanup_convert_symcrypt_to_epkey(correlationId, STATUS_FAILED, pkey, rsa, 
       "Convert RSA SymCrypt key to EVP_PKEY - BN_bin2bn prime1 failed", modulusPtr, privateExpPtr, primes[0] , primes[1], rsa_n, rsa_e, rsa_p, rsa_q, NULL);
    }
    
    // Set the public modulus and public exponent and private exponent values of the RSA key
    // This function transfers the memory management of the values to the RSA object
    // and therefore the values that have been passed in should not be freed by the caller after this function has been called.
    RSA_set0_key(rsa, rsa_n, rsa_e, rsa_d); 
    RSA_set0_factors(rsa, rsa_p, rsa_q);
    
    pkey = EVP_PKEY_new();
    if (pkey == NULL) {

        return  _cleanup_convert_symcrypt_to_epkey(correlationId, STATUS_FAILED, NULL, rsa, 
        "Convert RSA SymCrypt key to EVP_PKEY - EVP_PKEY_new failed", modulusPtr, privateExpPtr, primes[0] , primes[1], NULL, NULL, NULL, NULL, NULL);
    }
    // Convert the RSA key to an EVP_PKEY key
    if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
        return  _cleanup_convert_symcrypt_to_epkey(correlationId, STATUS_FAILED, pkey, rsa, 
        "Convert RSA SymCrypt key to EVP_PKEY - BN_bin2bn prime1 failed", modulusPtr, privateExpPtr, primes[0] , primes[1], rsa_n, rsa_e, rsa_p, rsa_q, rsa_d);
    }
    return  _cleanup_convert_symcrypt_to_epkey(correlationId, STATUS_OK, pkey, rsa, NULL, modulusPtr, privateExpPtr, primes[0] , primes[1], rsa_n, rsa_e, rsa_p, rsa_q, rsa_d);
}

static EVP_PKEY* _cleanup_convert_symcrypt_ecc_to_epkey(
    const uuid_t correlationId,
    int res,
    EVP_PKEY* evpKey,
    EC_KEY* ecKey,
    EC_GROUP* ecGroup,
    KEYISO_EC_PKEY_ST* ecPkeySt,
    size_t keyStSize,
    const char* loc)
{
    // Always clean up the temporary key structure if it exists
    if (ecPkeySt != NULL) {
        KeyIso_clear_free(ecPkeySt, keyStSize);
    }

    if (res != STATUS_OK) {
        // On failure, free all allocated resources
        if (ecGroup != NULL) {
            EC_GROUP_free(ecGroup);
        }
        if (ecKey != NULL && evpKey == NULL) {
            // Only free ecKey if it's not owned by evpKey
            EC_KEY_free(ecKey);
        }
        if (evpKey != NULL) {
            EVP_PKEY_free(evpKey);
        }
        
        if (loc != NULL) {
            KEYISOP_trace_log_error(correlationId, 0, KEYISOP_SERVICE_TITLE, loc, "KeyIso_convert_symcrypt_ecc_to_epkey Failed");
        }
        return NULL;
    }
    
    // ecKey is now owned by evpKey, but we still need to free ecGroup on success
    if (ecGroup != NULL) {
        EC_GROUP_free(ecGroup);
    }
    
    return evpKey;
}

#define _CLEANUP_CONVERT_SYMCRYPT_ECC_TO_EVPKEY(res, loc) \
        _cleanup_convert_symcrypt_ecc_to_epkey(correlationId, res, evpKey, ecKey, ecGroup, ecPkeySt, keyStSize, loc)

EVP_PKEY* KeyIso_convert_symcrypt_ecc_to_epkey(
    const uuid_t correlationId,
    const PSYMCRYPT_ECKEY inEcPkey) 
{
    int ret = STATUS_FAILED;
    size_t keyStSize = 0;
    EVP_PKEY *evpKey = NULL;
    EC_KEY *ecKey = NULL;
    EC_GROUP *ecGroup = NULL;
    KEYISO_EC_PKEY_ST* ecPkeySt  = NULL;
    
    if (inEcPkey == NULL) {
        return _CLEANUP_CONVERT_SYMCRYPT_ECC_TO_EVPKEY(STATUS_FAILED, "Invalid argument, inEcPkey is null");
    }

    int32_t curveNid = KeyIso_get_curve_nid_from_symcrypt_curve(correlationId, inEcPkey->pCurve);
    if (curveNid == -1) {
        return _CLEANUP_CONVERT_SYMCRYPT_ECC_TO_EVPKEY(STATUS_FAILED, "Invalid argument, curveNid is null");
    }
    
    // Export the SymCrypt EC key to our internal structure
    ecPkeySt = KeyIso_export_ec_pkey_from_symcrypt(
        correlationId, 
        curveNid, 
        inEcPkey, 
        &keyStSize); // KeyIso_clear_free()
    
    if (ecPkeySt == NULL) {
        return _CLEANUP_CONVERT_SYMCRYPT_ECC_TO_EVPKEY(STATUS_FAILED, "KeyIso_export_ec_pkey_from_symcrypt failed");
    }
    
    // Convert to OpenSSL EC_KEY
    ret = KeyIso_get_ec_evp_pkey(correlationId, ecPkeySt, &ecKey, &ecGroup);
    if (ret != STATUS_OK) {
        return _CLEANUP_CONVERT_SYMCRYPT_ECC_TO_EVPKEY(STATUS_FAILED, "KeyIso_get_ec_evp_pkey failed");
    }
    
    // Create a new EVP_PKEY
    evpKey = EVP_PKEY_new();
    if (evpKey == NULL) {
       return _CLEANUP_CONVERT_SYMCRYPT_ECC_TO_EVPKEY(STATUS_FAILED, NULL);
    }
    
    // Assign the EC_KEY to the EVP_PKEY
    if (!EVP_PKEY_assign_EC_KEY(evpKey, ecKey)) {
        return _CLEANUP_CONVERT_SYMCRYPT_ECC_TO_EVPKEY(STATUS_FAILED, "EVP_PKEY_assign_EC_KEY failed");
    }
    
    return _CLEANUP_CONVERT_SYMCRYPT_ECC_TO_EVPKEY(STATUS_OK, NULL);
}
#endif // KMPP_OPENSSL_SUPPORT