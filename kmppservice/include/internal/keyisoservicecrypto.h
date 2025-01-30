/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <kmppsymcryptwrapper.h>
#include <uuid/uuid.h>

#include "keyisocommon.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define KMPP_PKCS5_DEFAULT_ITER                      100000
#define KMPP_PKCS5_DEFAULT_ITER_V1                   2048


// KeyIso key encryption algorithm version
typedef enum {
    AlgorithmVersion_Invalid = 0,
    AlgorithmVersion_V1,
	AlgorithmVersion_V2,
    AlgorithmVersion_V3,
    AlgorithmVersion_Current = AlgorithmVersion_V3
} AlgorithmVersion;

// A generic error message for integrity failures
// Reporting differentiable error messages on integrity failures may result in information disclosure vulnerabilities
#define KMPP_INTEGRITY_ERR_STR "The encrypted data appears to be corrupt and cannot be verified"

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
    uint32_t kdf2KeyLen);

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
    uint32_t kdf2KeyLen);

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
    uint32_t *outBufLen);

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
    unsigned int *paddedDataLen);

int KeyIso_padding_pkcs7_remove(
    const uuid_t correlationId,
    unsigned char *decryptedData,
    unsigned int decryptedDataLen,
    unsigned int *removedPaddingDataLen);

/////////////////////////////////////////////////////
/////////////// Internal PBE methods ////////////////
/////////////////////////////////////////////////////

// PKCS #5 password-based encryption + HMAC calculation
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
    uint32_t hmacLen);
    
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
    uint32_t *keySize);

// PKCS #5 password-based decryption + HMAC verification
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
    uint32_t bufLen);

/////////////////////////////////////////////////////
///////// Internal Asymmetric Keys methods //////////
/////////////////////////////////////////////////////

size_t KeyIso_get_pkey_bytes_len(int keyType, const void *privateKey);

// RSA // 

// Export SymCrypt RSA public key to struct 
 KEYISO_RSA_PUBLIC_KEY_ST* KeyIso_export_rsa_public_key_from_symcrypt(
    const uuid_t correlationId,
    PSYMCRYPT_RSAKEY inPublicRsaKey);

// Export SymCrypt RSA pkey to struct 
// KeyIso_clear_free() should be called on the returned pointer
KEYISO_RSA_PKEY_ST* KeyIso_export_rsa_pkey_from_symcrypt(
    const uuid_t correlationId,
    PSYMCRYPT_RSAKEY inRsaKey,
    size_t *keyStSize) ;

// Create RSA SymCrypt key from received data
PSYMCRYPT_RSAKEY KeyIso_get_rsa_symcrypt_pkey( 
    const uuid_t correlationId,
    KEYISO_RSA_PKEY_ST* pRsaPkeySt);

// EC //
// Export SymCrypt EC public key to struct 
 KEYISO_EC_PUBLIC_KEY_ST* KeyIso_export_ec_public_key_from_symcrypt(
    const uuid_t correlationId,
    unsigned int curveNid,
    PSYMCRYPT_ECKEY inPublicEcKey);

// Export SymCrypt EC pkey to struct 
// KeyIso_clear_free() should be called on the returned pointer
KEYISO_EC_PKEY_ST* KeyIso_export_ec_pkey_from_symcrypt(
    const uuid_t correlationId,
    unsigned int curveNid,
    PSYMCRYPT_ECKEY inEcPkey,
    size_t* outKeyStSize);

// Create EC SymCrypt key from received data
PSYMCRYPT_ECKEY KeyIso_get_ec_symcrypt_pkey(
    const uuid_t correlationId,
    KEYISO_EC_PKEY_ST* inPrivateKey);

int KeyIso_rsa_decrypt(
    const uuid_t correlationId, 
    PKMPP_KEY kmppKeyPtr, 
    uint32_t padding,
    uint32_t mdnid,                    // Message digest identifier, only used if padding is set to RSA_PKCS1_OAEP_PADDING
    uint32_t labelLen,                 // The label length
    const unsigned char* label,        // Label used for OAEP (Will be used in the future KMPP provider)
    uint32_t fromLen,                  // A ciphertext size
    const unsigned char* from,         // A pointer to the ciphertext to be decrypted
    int32_t* pToLen,                   // A pointer to an integer that will contain the length of the plaintext after decryption
    unsigned char* to);                // A pointer to the buffer where the plaintext will be stored

int KeyIso_rsa_pkcs1_sign(
    const uuid_t correlationId, 
    PKMPP_KEY kmppPtr,
    int32_t mdnid,                    // Message digest algorithm identifier
    const unsigned char* hashValue,    // A pointer to the computed message digest that will be signed using the RSA private key
    uint32_t hashValueLen,             // The length of the computed message digest 
    unsigned char* sig,                // A pointer to the buffer where the signature will be stored
    int* pSigLen);                     // A pointer to a variable that will receive the length of the signature

int KeyIso_rsa_pss_sign(
    const uuid_t correlationId, 
    PKMPP_KEY kmppPtr,
    int32_t mdnid,                     // Message digest algorithm identifier
    int32_t saltLen,                   // The length of the salt used in the RSA-PSS signature
    const unsigned char* hashValue,     // A pointer to the computed message digest that will be signed 
    uint64_t hashValueLen,              // The length of the message digest
    unsigned char *sig,                 // A pointer to the buffer that will receive the signature
    size_t* pSigLen);                   // A pointer to a variable that will receive the length of the signature

/////////////////////////////////////////////////////
///////////// Fallback to OpenSSL methods ///////////
/////////////////////////////////////////////////////

#ifdef KMPP_OPENSSL_SUPPORT
EVP_PKEY* KeyIso_convert_symcrypt_to_epkey(
    const uuid_t correlationId,
    PSYMCRYPT_RSAKEY symcryptRsaKey);

int KeyIso_convert_ecdsa_symcrypt_to_epkey(
    const uuid_t correlationId,
    uint32_t curveNid,
    const PSYMCRYPT_ECKEY inEcPkey,
    EC_KEY** outEcKey, 
    EC_GROUP** outEcGroup);

#endif // KMPP_OPENSSL_SUPPORT

#ifdef  __cplusplus
}
#endif