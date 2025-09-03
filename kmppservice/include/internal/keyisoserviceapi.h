/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <kmppsymcryptwrapper.h>
#include <keyisoservicekey.h>

#include "keyisoservicecommon.h"


#ifdef  __cplusplus
extern "C" {
#endif

int KeyIso_SERVER_open_private_key( 
    const uuid_t correlationId,
    KEYISO_CLIENT_METADATA_HEADER_ST *metaData,
    KEYISO_ENCRYPTED_PRIV_KEY_ST *pEncKeySt,  
    PKMPP_KEY* outPkey);   //KMPP_KEY. free by KeyIso_kmpp_key_free
    
int KeyIso_SERVER_import_private_key( 
    const uuid_t correlationId,
    int keyType,
    const void *inKey,            // KEYISO_RSA_PKEY_ST/KEYISO_EC_PKEY_ST
    void **outEncKey);             // KEYISO_ENCRYPTED_PRIV_KEY_ST
    
int KeyIso_SERVER_generate_rsa_key_pair(
    const uuid_t correlationId, 
    unsigned int keyBits,
    unsigned int keyUsage,
    KEYISO_RSA_PUBLIC_KEY_ST **outPubKey,            
    void **outEncryptedPkey);      // KEYISO_ENCRYPTED_PRIV_KEY_ST

int KeyIso_SERVER_generate_ec_key_pair(
    const uuid_t correlationId, 
    unsigned int curve,
    unsigned int keyUsage,
    KEYISO_EC_PUBLIC_KEY_ST **outPubKey,
    void **outEncryptedPkey);      // KEYISO_ENCRYPTED_PRIV_KEY_ST

int KeyIso_SERVER_rsa_private_encrypt(
    const uuid_t correlationId, 
    void *pkey,  
    int flen, 
    const unsigned char *from, 
    int tlen, 
    unsigned char *to, 
    int padding);

int KeyIso_SERVER_rsa_private_decrypt(
    const uuid_t correlationId, 
    void *pkey,  
    int flen, 
    const unsigned char *from, 
    int tlen, 
    unsigned char *to, 
    int padding,
    int labelLen,
    const unsigned char *label);

int KeyIso_SERVER_rsa_sign(
    const uuid_t correlationId, 
    void *pkey,  
    int flen, 
    const unsigned char *from, 
    int tlen, 
    unsigned char *to, 
    int padding);

int KeyIso_SERVER_pkey_rsa_sign(
    const uuid_t correlationId, 
    void *pkey,  
    int flen, 
    const unsigned char *from, 
    int tlen, 
    unsigned char *to, 
    int padding);

int KeyIso_SERVER_ecdsa_sign(
    const uuid_t correlationId, 
    void *pkey,
    int type, 
    const unsigned char *dgst, 
    int dlen, 
    unsigned char *sig, 
    unsigned int siglen, 
    unsigned int *outlen); 

int KeyIso_SERVER_import_symmetric_key(
    const uuid_t correlationId,
    const int inSymmetricKeyType,
    const unsigned int inKeyLength,
    const unsigned char *inKeyBytes,
    const unsigned char *inImportKeyId, // Unique identifier to the imported key
    unsigned int *outKeyLength,
    unsigned char **outKeyBytes);       // KeyIso_free()

int KeyIso_SERVER_symmetric_key_encrypt_decrypt(
    const uuid_t correlationId,
    const int mode,
    int inKeyLength,
    const unsigned char *inKeyBytes,
    const unsigned char *from,
    unsigned int fromLen,
    unsigned char *to,
    unsigned int *toLen);


#ifdef  __cplusplus
}
#endif