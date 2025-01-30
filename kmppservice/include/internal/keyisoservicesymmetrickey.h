/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <uuid/uuid.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define KMPP_SYMMETRICKEY_VERSION           0x01
#define KMPP_SYMMETRICKEY_SECURITY_VERSION  0x01

/////////////////////////////////////////////////////
///////////// Internal utility methods //////////////
/////////////////////////////////////////////////////

void KeyIso_copy_data_dest_offset(
    unsigned char* dest,
    const unsigned char* src,
    size_t size,
    unsigned int* offset);

void KeyIso_copy_data_src_offset(
    unsigned char* dest,
    const unsigned char* src,
    size_t size,
    unsigned int* offset);

/////////////////////////////////////////////////////
/////////// Internal Symmetric Key methods //////////
/////////////////////////////////////////////////////

int KeyIso_symcrypt_kdf_generate_key_symmetrickey(
    const uuid_t correlationId,
    const unsigned char *salt,
    const uint32_t saltLen,
    unsigned char *encryptKey,
    uint32_t encryptKeySize,
    unsigned char *hmacKey,
    uint32_t hmacKeySize);

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
    uint32_t hmacKeySize);

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
    unsigned char **outBytes);   // KeyIso_free()
    
int KeyIso_symmetric_open_encrypted_data(
    const uuid_t correlationId,
    const int inLength,
    const unsigned char *inBytes,
    const unsigned char *encryptKey,
    const unsigned char *hmacKey,
    const unsigned int hmacKeyLen,
    unsigned int *outLength,
    unsigned char **outBytes);      // KeyIso_free()

int KeyIso_symmetric_open_encrypted_key(
    const uuid_t correlationId,
    const int inKeyLength,
    const unsigned char *inKeyBytes,
    unsigned int *outKeyLength,
    unsigned char **outKeyBytes);

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
    unsigned char **outBytes);   // KeyIso_free()
    
#ifdef  __cplusplus
}
#endif