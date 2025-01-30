/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once 

#include <stdbool.h>

#ifdef  __cplusplus
extern "C" {
#endif


//////////////////////////////////////////////////////////////////////////////////////////////////
//                             Message Handler generic structures                               //
//////////////////////////////////////////////////////////////////////////////////////////////////

typedef int (*PFN_msg_deserialize) (const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);
typedef uint8_t* (*PFN_msg_serialize) (const void *stToEncode, size_t *encodedLen);
typedef size_t (*PFN_msg_length) (const uint8_t *encodedSt, size_t encodedLen);

typedef struct keyiso_message_handler_table_st KEYISO_MSG_HANDLER_TABLE_ST;
struct keyiso_message_handler_table_st {
    PFN_msg_serialize inSerializeFunc;
    PFN_msg_deserialize inDeserializeFunc;
    PFN_msg_length inMsgLengthFunc;
    PFN_msg_serialize outSerializeFunc;
    PFN_msg_deserialize outDeserializeFunc;
    PFN_msg_length outMsgLengthFunc;
};

//////////////////////////////////////////////////////////////////////////////////////////////////
//                             Message Handler generic functions                                //
//////////////////////////////////////////////////////////////////////////////////////////////////

// IpcCommand_OpenPrivateKey
unsigned char* KeyIso_handle_msg_open_private_key(
    const char *senderName, 
    const uint8_t *inSt, 
    size_t inLen, 
    size_t *outLen);
    
// IpcCommand_CloseKey
unsigned char* KeyIso_handle_msg_close_key(
    const char *senderName, 
    const uint8_t *inSt, 
    size_t inLen, 
    size_t *outLen);

// IpcCommand_EcdsaSign
unsigned char* KeyIso_handle_msg_ecdsa_sign(
    const char *senderName, 
    const uint8_t *inSt, 
    size_t inLen, 
    size_t *outLen);

// IpcCommand_RsaPrivateEncryptDecrypt
unsigned char* KeyIso_handle_msg_rsa_private_enc_dec(
    const char *senderName,  
    const uint8_t *inSt, 
    size_t inLen, 
    size_t *outLen);

// IpcCommand_GenerateRsaKeyPair
unsigned char* KeyIso_handle_msg_rsa_key_generate(
    const uint8_t *inSt, 
    size_t inLen, 
    size_t *outLen) ;
    
// IpcCommand_GenerateEcKeyPair
unsigned char* KeyIso_handle_msg_ec_key_generate(
    const uint8_t *inSt, 
    size_t inLen, 
    size_t *outLen);

// IpcCommand_ImportRsaPrivateKey
unsigned char* KeyIso_handle_msg_rsa_import_private_key(
    const uint8_t *inSt, 
    size_t inLen, 
    size_t *outLen);

// IpcCommand_ImportEcPrivateKey
unsigned char* KeyIso_handle_msg_ec_import_private_key(
    const uint8_t *inSt, 
    size_t inLen, 
    size_t *outLen);

// IpcCommand_ImportSymmetricKey
unsigned char* KeyIso_handle_msg_import_symmetric_key(
    const uint8_t *inSt, 
    size_t inLen, 
    size_t *outLen);

// IpcCommand_SymmetricKeyEncryptDecrypt
unsigned char* KeyIso_handle_msg_symmetric_key_enc_dec(
    const uint8_t *inSt, 
    size_t inLen, 
    size_t *outLen);

// IpcCommand_EcdsaSignWithAttachedKey
unsigned char*  KeyIso_handle_msg_ecdsa_sign_with_attached_key(
    const char *sender,
    const uint8_t *inSt, 
    size_t inLen, 
    size_t *outLen);

// IpcCommand_RsaPrivateEncryptDecryptWithAttachedKey
unsigned char* KeyIso_handle_msg_rsa_private_enc_dec_with_attached_key(
    const char *sender,
    const uint8_t *inSt, 
    size_t inLen, 
    size_t *outLen);
    
#ifdef  __cplusplus
}
#endif