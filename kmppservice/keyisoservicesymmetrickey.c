/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "kmppsymcryptwrapper.h" // TODO: Temporary solution to avoid symcrypt warnings

#include "keyisoservicesymmetrickey.h"
#include "keyisocommon.h"
#include "keyisomemory.h"
#include "keyisolog.h"
#include "keyisoservicekey.h"
#include "keyisoservicecrypto.h"
#include "keyisoserviceapi.h"
#include "keyisoservicecommon.h"

#define SYMMETRIC_KEY_DEFAULT_ITER    100000

extern KeyIso_get_machine_secret_func_ptr KeyIso_get_machine_secret_func;
bool g_isSaltValidationRequired;

/////////////////////////////////////////////////////
///////////// Internal utility methods //////////////
/////////////////////////////////////////////////////

void KeyIso_copy_data_dest_offset(
    unsigned char *dest,
    const unsigned char *src,
    size_t size,
    unsigned int* offset) 
{
    memcpy(dest + *offset, src, size);
    *offset += size;
} 

void KeyIso_copy_data_src_offset(
    unsigned char* dest,
    const unsigned char* src,
    size_t size,
    unsigned int* offset) 
{
    if (dest != NULL && offset != NULL) {
        memcpy(dest, src + *offset, size);
        *offset += size;
    }
}

static int _sha512_hmac_calculation(const uuid_t correlationId,
                            const unsigned char* data,
                            const unsigned int data_len,
                            const unsigned char* key,
                            const unsigned int key_len,
                            unsigned char* hmac_result)
{
    const char *title = KEYISOP_IMPORT_KEY_TITLE;
    SYMCRYPT_HMAC_SHA512_STATE hmac_state;
    SYMCRYPT_HMAC_SHA512_EXPANDED_KEY hmac_key;
    unsigned char hmac_sha_512_result[KMPP_AES_512_KEY_SIZE];

    if (key_len < KMPP_AES_256_KEY_SIZE) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Key", "Invalid length");
        return STATUS_FAILED;
    }

    if (SymCryptHmacSha512ExpandKey(&hmac_key, key, key_len) != SYMCRYPT_NO_ERROR) {
        KEYISOP_trace_log_error(correlationId, 0, title, "SymCryptHmacSha512ExpandKey", "key generation failed");
        return STATUS_FAILED;
    }

    SymCryptHmacSha512Init(&hmac_state, &hmac_key);
    SymCryptHmacSha512Append(&hmac_state, data, data_len);
    SymCryptHmacSha512Result(&hmac_state, hmac_sha_512_result);

    // Clean up the HMAC state
    SymCryptWipe(&hmac_state, sizeof(hmac_state));

    // For smaller storage size we will save only the first KMPP_HMAC_SHA256_KEY_SIZE bytes, as suggested by crypto board
    memcpy(hmac_result, hmac_sha_512_result, KMPP_HMAC_SHA256_KEY_SIZE);

    return STATUS_OK;
}

/////////////////////////////////////////////////////
/////////// Internal Symmetric Key methods //////////
/////////////////////////////////////////////////////

static int _cleanup_hmac_encrypted_symmetric_key(
    const uuid_t correlationId, 
    int status,
    unsigned char* hmacData,
    const char *loc,
    const char *errStr)
{
    const char *title = KEYISOP_IMPORT_KEY_TITLE;
    if (!status) {
        KEYISOP_trace_log_error(correlationId, 0, title, loc, errStr);
    }

    KeyIso_free(hmacData);

    return status;
}

/*
Calculates HMAC for all of the parameters that will be sent to the client:
version + security version + IV + encrypted key
*/
static int _hmac_encrypted_symmetric_key(
    const uuid_t correlationId,
    const unsigned char version,
    const unsigned char securityVersion,
    const unsigned char *metaData,
    const int metaDataLen,
    const unsigned char *encryptedData,
    const int encryptedDataLength,
    const unsigned char *iv,
    const unsigned char *kdf2HmacKey,
    const unsigned int kdf2HmacKeyLen,
    unsigned char *hmacBytes)
{
    unsigned int offset = 0;
    int versionsDataLengthSize = 1; //size of char
    unsigned char* hmacData = NULL;
    unsigned int hmacDataLen = KMPP_SYMMETRICKEY_KEY_LEN + versionsDataLengthSize + metaDataLen + encryptedDataLength;

    hmacData = (unsigned char*)KeyIso_zalloc(hmacDataLen);
    if (!hmacData) {
        return _cleanup_hmac_encrypted_symmetric_key(correlationId, STATUS_FAILED, hmacData, "hmac data", "allocation error");    
    }

    int versionsDataLength = KMPP_SYMMETRICKEY_VERSION_BYTES;

    // Copy the data that will be calculated for HMAC into hmacData
    KeyIso_copy_data_dest_offset(hmacData, (unsigned char *)&versionsDataLength, versionsDataLengthSize, &offset);
    KeyIso_copy_data_dest_offset(hmacData, &version, 1, &offset);
    KeyIso_copy_data_dest_offset(hmacData, &securityVersion, 1, &offset);
    if (metaDataLen > 0) {
        KeyIso_copy_data_dest_offset(hmacData, metaData, metaDataLen, &offset);
    }
    KeyIso_copy_data_dest_offset(hmacData, iv, KMPP_AES_BLOCK_SIZE, &offset);
    KeyIso_copy_data_dest_offset(hmacData, encryptedData, encryptedDataLength, &offset);
    if (offset != hmacDataLen) {
        //offset should now be in the same size as the allocated len, if not - something is wrong
        return _cleanup_hmac_encrypted_symmetric_key(correlationId, STATUS_FAILED, hmacData, "hmac data", "allocation error");    
    }

    if (_sha512_hmac_calculation(
            correlationId,
            hmacData,
            hmacDataLen,
            kdf2HmacKey,
            kdf2HmacKeyLen,
            hmacBytes) != STATUS_OK) {
        return _cleanup_hmac_encrypted_symmetric_key(correlationId, STATUS_FAILED, hmacData, "hmac data", "calculation error");
    }
    
    // Free allocated memory
    return _cleanup_hmac_encrypted_symmetric_key(correlationId, STATUS_OK, hmacData, NULL, NULL);
}

static int _hmac_validate_encrypted_symmetric_key(
    const uuid_t correlationId,
    const unsigned char version,
    const unsigned char securityVersion,
    const unsigned char *metaData,
    const int metaDataLen,
    const unsigned char *encryptedData,
    const int encryptedDataLength,
    const unsigned char *iv,
    const unsigned char *kdf2HmacKey,
    const unsigned int kdf2HmacKeyLen,
    const unsigned char *existingHmacBytes)
{
    unsigned char calculatedHmacBytes[KMPP_HMAC_SHA256_KEY_SIZE];

    if (_hmac_encrypted_symmetric_key(
        correlationId,
        version,
        securityVersion,
        metaData,
        metaDataLen,
        encryptedData,
        encryptedDataLength,
        iv,
        kdf2HmacKey,
        kdf2HmacKeyLen,
        calculatedHmacBytes) != STATUS_OK) {
            return STATUS_FAILED;
    }

    // HMAC validation
    if(KeyIso_hmac_validation(calculatedHmacBytes, existingHmacBytes, KMPP_HMAC_SHA256_KEY_SIZE) != STATUS_OK) {
        return STATUS_FAILED;
    }

    return STATUS_OK;
}

/*
Build the encrypted data that will be sent to the client with all of the node data:
version + security version + HMAC + IV + encrypted data
*/
static int _build_symmetric_key_encrypted_output(
    const uuid_t correlationId,
    const unsigned char *encryptedData,
    const int encryptedDataLen,
    const unsigned char *iv,
    const unsigned char *hmacBytes,
    const unsigned char *metaData,
    const int metaDataLen,
    unsigned char **outBytes, // KeyIso_free()
    unsigned int *outLength)
{
    const char *title = KEYISOP_IMPORT_SYMMETRIC_KEY_TITLE;
    unsigned int offset = 0;
    unsigned char version = KMPP_SYMMETRICKEY_VERSION;
    unsigned char securityVersion = KMPP_SYMMETRICKEY_SECURITY_VERSION;
    unsigned char *dataBytes = NULL;
    unsigned int dataBytesLength = KMPP_SYMMETRICKEY_BLOB_LEN + metaDataLen + encryptedDataLen;

    // Build dataBytes, format - <version><SVN><meta data><HMAC result><IV><aes_256_cbc_ciphertext of the data>
    dataBytes = (unsigned char*)KeyIso_zalloc(dataBytesLength);
    if (!dataBytes) {
        KEYISOP_trace_log_error(correlationId, 0, title, "dataBytes build", "allocation failed");
        return STATUS_FAILED;
    }

    // Copy the data that will be part of the data into dataBytes
    KeyIso_copy_data_dest_offset(dataBytes, &version, 1, &offset);
    KeyIso_copy_data_dest_offset(dataBytes, &securityVersion, 1, &offset);
    KeyIso_copy_data_dest_offset(dataBytes, metaData, metaDataLen, &offset);
    KeyIso_copy_data_dest_offset(dataBytes, hmacBytes, KMPP_HMAC_SHA256_KEY_SIZE, &offset);
    KeyIso_copy_data_dest_offset(dataBytes, iv, KMPP_AES_BLOCK_SIZE, &offset);
    KeyIso_copy_data_dest_offset(dataBytes, encryptedData, encryptedDataLen, &offset);
    if (offset != dataBytesLength) {
        //offset should now be in the same size as the allocated len, if not - something is wrong
        KEYISOP_trace_log_error(correlationId, 0, title, "hmac data", "allocation failed");
        KeyIso_free(dataBytes);
        return STATUS_FAILED;
    }

    *outBytes = dataBytes;
    *outLength = dataBytesLength;

    return STATUS_OK;
}

/*
split the encrypted data to get:
version + security version + HMAC + IV + encrypted data
*/
static int _split_symmetric_key_encrypted_input(
    const uuid_t correlationId,
    const unsigned char* inDataBytes,
    const int inDataBytesLength,
    unsigned char *outVersion,
    unsigned char *outSecurityVersion,
    unsigned char *outMetaData,
    const int metaDataLen,
    unsigned char *outHmacBytes,
    unsigned char *outIv,
    unsigned char **outDataBytes, // KeyIso_free()
    unsigned int* outDataLength)
{
    const char *title = KEYISOP_SYMMETRIC_ENC_DEC_TITLE;
    unsigned int offset = 0;
    unsigned char* dataBytes = NULL;
    unsigned int dataBytesLength = 0;

    // Copy to the output versions HMAC and IVs according to the offset in the key bytes
    // encrypted data byte format - <version><SVN><HMAC result><IV><aes_256_cbc_ciphertext of the key>
    KeyIso_copy_data_src_offset(outVersion, inDataBytes, 1, &offset);
    KeyIso_copy_data_src_offset(outSecurityVersion, inDataBytes, 1, &offset);

    // validate versions
    if (*outVersion != KMPP_SYMMETRICKEY_VERSION || *outSecurityVersion != KMPP_SYMMETRICKEY_SECURITY_VERSION) {
        KEYISOP_trace_log_error(correlationId, 0, title, "dataBytes split", "version incorrect");
        return STATUS_FAILED;
    }

    if (metaDataLen > 0) {
        KeyIso_copy_data_src_offset(outMetaData, inDataBytes, metaDataLen, &offset);
    }
    KeyIso_copy_data_src_offset(outHmacBytes, inDataBytes, KMPP_HMAC_SHA256_KEY_SIZE, &offset);
    KeyIso_copy_data_src_offset(outIv, inDataBytes, KMPP_AES_BLOCK_SIZE, &offset);

    dataBytesLength = inDataBytesLength - offset;
    dataBytes = (unsigned char*)KeyIso_zalloc(dataBytesLength);
    if (!dataBytes) {
        KEYISOP_trace_log_error(correlationId, 0, title, "dataBytes split", "allocation failed");
        return STATUS_FAILED;
    }

    KeyIso_copy_data_src_offset(dataBytes, inDataBytes, dataBytesLength, &offset);

    if (offset != (unsigned int)inDataBytesLength) {
        //offset should now be in the same size as the allocated len, if not - something is wrong
        KEYISOP_trace_log_error(correlationId, 0, title, "dataBytes split", "offset is incorrect");
        KeyIso_free(dataBytes);
        return STATUS_FAILED;
    }

    *outDataBytes = dataBytes;
    *outDataLength = dataBytesLength;

    return STATUS_OK;
}

int KeyIso_symcrypt_kdf_generate_key_symmetrickey(
    const uuid_t correlationId,
    const unsigned char *salt,
    const uint32_t saltLen,
    unsigned char *encryptKey,
    uint32_t encryptKeySize,
    unsigned char *hmacKey,
    uint32_t hmacKeySize)
{
    const char *title = KEYISOP_GEN_KEY_TITLE;
    unsigned char password[KEYISO_SECRET_KEY_LENGTH];
    uint8_t machine_secret[KEYISO_SECRET_FILE_LENGTH] = { };

    if(!KeyIso_get_machine_secret_func){
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, "machine secret retrieval function not set");
        return STATUS_FAILED;
    }

    if (KeyIso_get_machine_secret_func(machine_secret, sizeof(machine_secret)) != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, "Failed to get machine secret");
        return STATUS_FAILED;
    }
    
    memcpy(password, machine_secret + KEYISO_SECRET_SALT_LENGTH, KEYISO_SECRET_KEY_LENGTH);
    
    if (g_isSaltValidationRequired &&
        KeyIso_is_valid_salt_prefix(
            correlationId,
            salt,
            machine_secret) == STATUS_FAILED) {
                KEYISOP_trace_log_error(correlationId, 0, title, NULL, "Invalid salt");
                KeyIso_cleanse(password, KEYISO_SECRET_KEY_LENGTH);  
                KeyIso_cleanse(machine_secret, sizeof(machine_secret));
                return STATUS_FAILED;    
    }

    // Cleanse machine secret after use
    KeyIso_cleanse(machine_secret, sizeof(machine_secret));

    // Derive two keys from the decrypted key - for encrypt and HMAC
    if (KeyIso_symcrypt_kdf_generate_keys(
        correlationId,
        password,
        KEYISO_SECRET_KEY_LENGTH,
        NULL, // No label is needed in key generation with salt
        0,
        salt,
        saltLen,
        encryptKey,
        encryptKeySize,
        hmacKey,
        hmacKeySize) != STATUS_OK) {
            KEYISOP_trace_log_error(correlationId, 0, title, NULL, "Generate password failed");
            KeyIso_cleanse(password, KEYISO_SECRET_KEY_LENGTH);  
            return STATUS_FAILED;    
    }
    
    KeyIso_cleanse(password, KEYISO_SECRET_KEY_LENGTH);  
    return STATUS_OK;
}

int KeyIso_symcrypt_kdf_generate_keys(
    const uuid_t correlationId,
    const unsigned char *key,
    const uint32_t keyLen,
    const unsigned char *label,    // optional
    uint32_t labelLen,
    const unsigned char *context,  // salt - optional
    uint32_t contextLen,
    unsigned char *encryptKey,
    uint32_t encryptKeySize,
    unsigned char *hmacKey,
    uint32_t hmacKeySize)
{
    const char *title = KEYISOP_GEN_KEY_TITLE;
    unsigned char kdfKey[KMPP_AES_512_KEY_SIZE];

    if (encryptKeySize != KMPP_AES_256_KEY_SIZE || hmacKeySize != KMPP_HMAC_SHA256_KEY_SIZE) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, "key sizes are incorrect");
        return STATUS_FAILED;    
    }

    //derive 512 key
    if (!KeyIso_symcrypt_kdf_key_derivation(
        correlationId,
        SymCryptHmacSha256Algorithm,
        key,
        keyLen,
        label,
        labelLen,
        context,
        contextLen,
        kdfKey, 
        KMPP_AES_512_KEY_SIZE)) {
            KEYISOP_trace_log_error(correlationId, 0, title, NULL, "kdf_key_derivation error");
            KeyIso_cleanse(kdfKey, KMPP_AES_512_KEY_SIZE);
            return STATUS_FAILED;
    }

    //divide to encryption key and mac key
    memcpy(encryptKey, &kdfKey, encryptKeySize);
    memcpy(hmacKey, &kdfKey[encryptKeySize], hmacKeySize);
    KeyIso_cleanse(kdfKey, KMPP_AES_512_KEY_SIZE);
    return STATUS_OK;
}

static int _cleanup_open_encrypted_data(
    const uuid_t correlationId, 
    int status,
    unsigned char* decryptedData)
{
    const char *title = KEYISOP_IMPORT_SYMMETRIC_KEY_TITLE;
    if (status == STATUS_FAILED) {
        KEYISOP_trace_log_error(correlationId, 0, title, KMPP_INTEGRITY_ERR_STR, "Failed");
        KeyIso_free(decryptedData);    
    }

    return status;
}

static int _symmetric_key_decrypt(
    const uuid_t correlationId,
    const unsigned char *encryptKey,
    const unsigned char *hmacKey,
    const unsigned int hmacKeyLen,
    const unsigned char version,
    const unsigned char securityVersion,
    const unsigned char *metaData,
    const int metaDataLen,
    const unsigned char *encryptedData,
    const int encryptedDataLength,
    unsigned char *iv,
    const unsigned char *hmacBytes,
    unsigned int *outLength,
    unsigned char **outBytes)  // KeyIso_free()
{
    unsigned char *decryptedData = NULL;

    *outBytes = NULL;

    // HMAC validation - must be done before of the SymCryptPaddingPkcs7Remove
    // The HMAC validation must be constant time, otherwise its a risk of time attack.
    // The data can contain PKCS7 padding that is sensitive to side channels attack, and we assume that this HMAC validation was done here
    if (_hmac_validate_encrypted_symmetric_key(
            correlationId,
            version,
            securityVersion,
            metaData,
            metaDataLen,
            encryptedData,
            encryptedDataLength,
            iv,
            hmacKey,
            hmacKeyLen,
            hmacBytes) != STATUS_OK) {
                return _cleanup_open_encrypted_data(correlationId, STATUS_FAILED, decryptedData);
    }
    
    decryptedData = (unsigned char*)KeyIso_zalloc(encryptedDataLength);
    if (!decryptedData) {
        return _cleanup_open_encrypted_data(correlationId, STATUS_FAILED, decryptedData);
    }

    if (KeyIso_symcrypt_aes_encrypt_decrypt(
            correlationId,
            KEYISO_AES_DECRYPT_MODE,
            KEYISO_AES_PADDING_PKCS7,
            iv,
            KMPP_AES_BLOCK_SIZE,
            encryptKey,
            KMPP_AES_256_KEY_SIZE,
            encryptedData,
            encryptedDataLength,
            decryptedData,
            outLength) != STATUS_OK) {
        return _cleanup_open_encrypted_data(correlationId, STATUS_FAILED, decryptedData);
    }

    *outBytes = decryptedData;

    return _cleanup_open_encrypted_data(correlationId, STATUS_OK, NULL);
}

int KeyIso_symmetric_create_encrypted_data(
    const uuid_t correlationId,
    const int inLength,
    const unsigned char *inBytes,
    const unsigned char *encryptKey,
    const unsigned char *hmacKey,
    const unsigned int hmacKeyLen,
    const unsigned char *metaData,
    const int metaDataLen,
    unsigned int *outLength,
    unsigned char **outBytes)   // KeyIso_free()
{
    const char *title = KEYISOP_IMPORT_SYMMETRIC_KEY_TITLE;
    unsigned char iv[KMPP_AES_BLOCK_SIZE];
    unsigned char hmacBytes[KMPP_HMAC_SHA256_KEY_SIZE];
    unsigned char *dataBytes = NULL;
    unsigned int dataLength = 0;

    if (KeyIso_symmetric_key_encrypt(
            correlationId,
            inLength,
            inBytes,
            encryptKey,
            hmacKey,
            hmacKeyLen,
            metaData,
            metaDataLen,
            hmacBytes,
            iv,
            &dataLength,
            &dataBytes) != STATUS_OK) {
        KeyIso_free(dataBytes);
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, "KeyIso_symmetric_key_encrypt - failed");
        return STATUS_FAILED;
    }

    if (_build_symmetric_key_encrypted_output(
            correlationId,
            dataBytes,
            dataLength,
            iv,
            hmacBytes,
            metaData,
            metaDataLen,
            outBytes,
            outLength) != STATUS_OK) {
        KeyIso_free(dataBytes);
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, "_build_symmetric_key_encrypted_output - failed");
        return STATUS_FAILED;
    }

    KeyIso_free(dataBytes);
    return STATUS_OK;
}

int KeyIso_symmetric_open_encrypted_data(
    const uuid_t correlationId,
    const int inLength,
    const unsigned char *inBytes,
    const unsigned char *encryptKey,
    const unsigned char *hmacKey,
    const unsigned int hmacKeyLen,
    unsigned int *outLength,
    unsigned char **outBytes)  // KeyIso_free()
{
    const char *title = KEYISOP_IMPORT_SYMMETRIC_KEY_TITLE;
    if (inBytes == NULL || inLength < KMPP_SYMMETRICKEY_BLOB_LEN) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, "Invalid input");
        return STATUS_FAILED;
    }

    unsigned char version;
    unsigned char securityVersion;
    unsigned char iv[KMPP_AES_BLOCK_SIZE];
    unsigned char hmacBytes[KMPP_HMAC_SHA256_KEY_SIZE];
    unsigned char *dataBytes = NULL;
    unsigned int dataLength = 0;

    //extract data
    if (_split_symmetric_key_encrypted_input(
            correlationId,
            inBytes,
            inLength,
            &version,
            &securityVersion,
            NULL,
            0, // no metadata for the encrypted data
            hmacBytes,
            iv,
            &dataBytes,
            &dataLength) != STATUS_OK) {
                KeyIso_free(dataBytes);
                KEYISOP_trace_log_error(correlationId, 0, title, "dataBytes split", "split_symmetric_key failed");
                return STATUS_FAILED;
    }

    int status = _symmetric_key_decrypt(
                    correlationId,
                    encryptKey,
                    hmacKey,
                    hmacKeyLen,
                    version,
                    securityVersion, 
                    NULL,
                    0,
                    dataBytes,
                    dataLength,
                    iv,
                    hmacBytes,
                    outLength,
                    outBytes);

    KeyIso_free(dataBytes);
    return status;
}

static int _cleanup_symmetric_open_encrypted_key(
    const uuid_t correlationId, 
    int status,
    unsigned char* keyBytes,
    const char *errStr)
{
    const char *title = KEYISOP_SYMMETRIC_ENC_DEC_TITLE;
    if (status == STATUS_FAILED) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, errStr);
    }
    KeyIso_free(keyBytes);

    return status;
}

int KeyIso_symmetric_open_encrypted_key(
    const uuid_t correlationId,
    const int inKeyLength,
    const unsigned char *inKeyBytes,
    unsigned int *outKeyLength,
    unsigned char **outKeyBytes)
{
    if (inKeyBytes == NULL || inKeyLength < KMPP_SYMMETRICKEY_META_DATA_LEN + KMPP_SYMMETRICKEY_BLOB_LEN) {
        return _cleanup_symmetric_open_encrypted_key(correlationId, STATUS_FAILED, NULL, "Invalid input");
    }

    unsigned char encryptKey[KMPP_AES_256_KEY_SIZE];
    unsigned char hmacKey[KMPP_HMAC_SHA256_KEY_SIZE];
    unsigned char version;
    unsigned char securityVersion;
    unsigned char iv[KMPP_AES_BLOCK_SIZE];
    unsigned char metaData[KMPP_SYMMETRICKEY_META_DATA_LEN];
    unsigned char salt[KMPP_SALT_SHA256_SIZE];
    unsigned char hmacBytes[KMPP_HMAC_SHA256_KEY_SIZE];
    unsigned char *keyBytes = NULL;
    unsigned int keyBytesLength = 0;

    *outKeyLength = 0;
    *outKeyBytes = NULL;

    // Split the key in order to have the needed data for KDF
    if (_split_symmetric_key_encrypted_input(
        correlationId,
        inKeyBytes,
        inKeyLength,
        &version,
        &securityVersion,
        metaData,
        KMPP_SYMMETRICKEY_META_DATA_LEN,
        hmacBytes,
        iv,
        &keyBytes,
        &keyBytesLength) != STATUS_OK) {
            return _cleanup_symmetric_open_encrypted_key(correlationId, STATUS_FAILED, keyBytes, "split_symmetric_key failed");
    }

    //copy the salt from the meta data
    memcpy(salt, metaData, sizeof(salt));
    
    // Based on the splitted key handle - generate the KDF keys
    if (KeyIso_symcrypt_kdf_generate_key_symmetrickey(
        correlationId,
        salt,
        sizeof(salt),
        encryptKey,
        sizeof(encryptKey),
        hmacKey,
        sizeof(hmacKey)) != STATUS_OK) {
            return _cleanup_symmetric_open_encrypted_key(correlationId, STATUS_FAILED, keyBytes, "Generate key failed");
    }

    int status = _symmetric_key_decrypt(correlationId,
            encryptKey,
            hmacKey,
            sizeof(hmacKey),
            version,
            securityVersion,
            metaData,
            KMPP_SYMMETRICKEY_META_DATA_LEN,
            keyBytes,
            keyBytesLength,
            iv,
            hmacBytes,
            outKeyLength,
            outKeyBytes);
    
    return _cleanup_symmetric_open_encrypted_key(correlationId, status, keyBytes, "KeyIso_symmetric_key_decrypt failed");
}

int KeyIso_symmetric_key_encrypt(
    const uuid_t correlationId,
    const int inLength,
    const unsigned char *inBytes,
    const unsigned char *encryptKey,
    const unsigned char *hmacKey,
    const unsigned int hmacKeyLen,
    const unsigned char *metaData,
    const int metaDataLen,
    unsigned char *hmacBytes,
    unsigned char *iv,
    unsigned int *outLength,
    unsigned char **outBytes)   // KeyIso_free()
{
    const char *title = KEYISOP_SYMMETRIC_ENC_DEC_TITLE;
    *outBytes = NULL;
    
    unsigned char *encryptedBuf = NULL;
    encryptedBuf = (unsigned char*)KeyIso_zalloc(inLength + KMPP_AES_BLOCK_SIZE); // Maximal size of the encrypted data
    if (!encryptedBuf) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, "allocation error");
        return STATUS_FAILED;
    }

    // Encrypt the data
    if (KeyIso_symcrypt_aes_encrypt_decrypt(
            correlationId,
            KEYISO_AES_ENCRYPT_MODE,
            KEYISO_AES_PADDING_PKCS7,
            iv,
            KMPP_AES_BLOCK_SIZE,
            encryptKey,
            KMPP_AES_256_KEY_SIZE,
            inBytes,
            inLength,
            encryptedBuf,
            outLength) != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, "encrypt error");
        KeyIso_clear_free(encryptedBuf, inLength + KMPP_AES_BLOCK_SIZE);
        return STATUS_FAILED;
    }

    // HMAC encrypted data
    if (_hmac_encrypted_symmetric_key(
            correlationId,
            KMPP_SYMMETRICKEY_VERSION,
            KMPP_SYMMETRICKEY_SECURITY_VERSION,
            metaData,
            metaDataLen,
            encryptedBuf,
            *outLength,
            iv,
            hmacKey,
            hmacKeyLen,
            hmacBytes) != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, "HMAC error");
        KeyIso_clear_free(encryptedBuf, inLength + KMPP_AES_BLOCK_SIZE);
        return STATUS_FAILED;
    }

    *outBytes = encryptedBuf;
  
    return STATUS_OK;   
}
