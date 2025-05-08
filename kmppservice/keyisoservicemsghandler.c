/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */


#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "keyisoservicecommon.h"
#include "keyisoipccommands.h"
#include "keyisoservicekeylist.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisoserviceapi.h"
#include "keyisoservicecommon.h"
#include "keyisoipcserviceadapter.h"
#include "keyisoservicemsghandler.h"

#define MAX_SYMMETRIC_KEY_LEN 256

/////////////////////////////////
/*     RSA Private enc dec     */
/////////////////////////////////

static const PFN_ecc_operation KEYISO_SERVER_ecc_operation = KeyIso_SERVER_ecdsa_sign;

// Function to initialize RSA encrypt/decrypt response based on the command
static uint8_t* _allocate_and_initialize_rsa_enc_dec_response(uint64_t keyId, uint32_t command, uint32_t  status, int bytesLen, const unsigned char *toBytes, size_t *outLen)
 {
    size_t structSize = 0;
    uint8_t* res = NULL;
    if (command == IpcCommand_RsaPrivateEncryptDecrypt) {
        structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_RSA_PRIVATE_ENC_DEC_OUT_ST, bytesLen);
        KEYISO_RSA_PRIVATE_ENC_DEC_OUT_ST* out = (KEYISO_RSA_PRIVATE_ENC_DEC_OUT_ST*) KeyIso_zalloc(structSize);
        out->headerSt.command = command;
        out->headerSt.result = status;
        out->bytesLen = bytesLen;
        if (bytesLen > 0) {
            memcpy(out->toBytes, toBytes, bytesLen);
        }
        res = (uint8_t*)out;
    } else if (command == IpcCommand_RsaPrivateEncryptDecryptWithAttachedKey) {
        structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_OUT_ST, bytesLen);
        KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_OUT_ST* out = (KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_OUT_ST*) KeyIso_zalloc(structSize);
        out->headerSt.command = command;
        out->headerSt.result = status;
        out->keyId = keyId;
        out->bytesLen = bytesLen;
        if (bytesLen > 0) {
            memcpy(out->toBytes, toBytes, bytesLen);
        }
       res = (uint8_t*)out;
    }
    
    *outLen = structSize;
    return res;
}


// Main function to create the response
static unsigned char* _create_response_rsa_private_enc_dec(uint64_t keyId, uint32_t status, uint32_t command, int bytesLen, const unsigned char *toBytes, size_t *outLen) 
{
    if (outLen == NULL) {
        KEYISOP_trace_log_error(0, 0, KEYISOP_RSA_ENCRYPT_TITLE, "create_response_rsa_private_enc_dec", "Invalid outLen");
        return NULL;
    }

    uint8_t *outSt = _allocate_and_initialize_rsa_enc_dec_response(keyId, command, status, bytesLen, toBytes, outLen);
    if (outSt == NULL) {
        *outLen = 0;
        return NULL;
    }
    uint8_t *outBuf = KeyIso_service_adapter_generic_msg_postprocessing(command, outSt, outLen);
    KeyIso_service_adapter_generic_msg_cleanup(outSt, 0, false);
    return outBuf;
}

static unsigned char* _rsa_private_enc_dec_failure(const uint8_t *correlationId, uint64_t  keyId, size_t *outLen, const char *loc, const char *errorStr, uint32_t status, uint32_t command)
{
    KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_SERVICE_TITLE, loc, errorStr, "command: %d, status: %d", command, status);
    return _create_response_rsa_private_enc_dec(keyId, status, command, 0, NULL, outLen);
}

static int _activate_server_rsa_operation(const uint8_t *correlationId, KEYISO_RSA_PRIVATE_ENC_DEC_IN_PARAMS_ST *rsaPrivEncDecInParams, PKMPP_KEY pkeyPtr, unsigned char *toBytes)
{
    int rsa_operation_result = -1;

    switch (rsaPrivEncDecInParams->decrypt)
    {
        case 0:
        {
            rsa_operation_result = KeyIso_SERVER_rsa_private_encrypt(correlationId, pkeyPtr,
                rsaPrivEncDecInParams->fromBytesLen, rsaPrivEncDecInParams->bytes, rsaPrivEncDecInParams->tlen, toBytes, rsaPrivEncDecInParams->padding);
            break;
        }

        case 1:
        {
            unsigned char* label = NULL;
            if (rsaPrivEncDecInParams->labelLen > 0) {
                label = rsaPrivEncDecInParams->bytes + rsaPrivEncDecInParams->fromBytesLen;
            }
            rsa_operation_result = KeyIso_SERVER_rsa_private_decrypt(correlationId, pkeyPtr,
                rsaPrivEncDecInParams->fromBytesLen, rsaPrivEncDecInParams->bytes,
                rsaPrivEncDecInParams->tlen, toBytes, rsaPrivEncDecInParams->padding, rsaPrivEncDecInParams->labelLen, label);
            break;
        }

        case 2:
        {
            rsa_operation_result = KeyIso_SERVER_rsa_sign(correlationId, pkeyPtr,
                rsaPrivEncDecInParams->fromBytesLen, rsaPrivEncDecInParams->bytes, rsaPrivEncDecInParams->tlen, toBytes, rsaPrivEncDecInParams->padding);
            break;
        }

        case 3:
        {
            rsa_operation_result = KeyIso_SERVER_pkey_rsa_sign(correlationId, pkeyPtr,
                rsaPrivEncDecInParams->fromBytesLen, rsaPrivEncDecInParams->bytes, rsaPrivEncDecInParams->tlen, toBytes, rsaPrivEncDecInParams->padding);
            break;
        }

        default:
        {
            KEYISOP_trace_log_error(correlationId, 0, KEYISOP_SERVICE_TITLE, "KEYISO_SERVER_rsa_operations", "Invalid decrypt value");
            break;
        }
    }

    return rsa_operation_result;
}

static unsigned  char* _handle_rsa_encrypt_dec(const uint8_t *correlationId, uint64_t keyId, PKMPP_KEY pkeyPtr, KEYISO_RSA_PRIVATE_ENC_DEC_IN_PARAMS_ST *rsaPrivEncDecInParams, size_t *outLen, uint32_t command)
{   
    if(pkeyPtr == NULL || pkeyPtr->key == NULL || rsaPrivEncDecInParams == NULL || rsaPrivEncDecInParams->tlen <= 0) {
        return _rsa_private_enc_dec_failure(correlationId, keyId, outLen, "_handle_rsa_encrypt_dec", "failed", STATUS_FAILED, command);
    }

    // Since the key parameters are been checked during import / generate operations, we can assume at this point that the key is valid
    uint32_t modulusSize = SymCryptRsakeySizeofModulus(pkeyPtr->key);
 
    if ((uint32_t)rsaPrivEncDecInParams->tlen < modulusSize) {
        return _rsa_private_enc_dec_failure(correlationId, keyId, outLen, "_handle_rsa_encrypt_dec", "invalid tlen", STATUS_FAILED, command);
    }
    
    unsigned char *toBytes = (unsigned char*) KeyIso_zalloc(rsaPrivEncDecInParams->tlen);
    if (toBytes == NULL) {
        // Close key handle (is increased in KeyIso_get_key_in_list)
        return _rsa_private_enc_dec_failure(correlationId, keyId, outLen, "toBytes", "allocation failed", STATUS_FAILED, command);
    }
    
    int bytesLen = _activate_server_rsa_operation(correlationId, rsaPrivEncDecInParams, pkeyPtr, toBytes);
    if (bytesLen <= 0 || bytesLen > rsaPrivEncDecInParams->tlen) {
        KeyIso_free(toBytes);
        return _rsa_private_enc_dec_failure(correlationId, keyId, outLen, "KEYISO_SERVER_rsa_operations", "invalid result", STATUS_FAILED, command);
    }    
    // Create response
    uint8_t *msgBuf = _create_response_rsa_private_enc_dec(keyId, STATUS_OK, command, bytesLen, toBytes, outLen);
    KeyIso_free(toBytes);
    return msgBuf;
}

unsigned char* KeyIso_handle_msg_rsa_private_enc_dec(const char *sender, const uint8_t *inSt, size_t inLen, size_t *outLen)
{       
    uint8_t *res = NULL;
    void *rsaPrivEncDecInSt_v = NULL;
    uint32_t command = IpcCommand_RsaPrivateEncryptDecrypt;
    KEYISO_RSA_PRIVATE_ENC_DEC_IN_ST *rsaPrivEncDecInSt = NULL;
    int status = KeyIso_service_adapter_generic_msg_preprocessing(command, inSt, inLen, &rsaPrivEncDecInSt_v);
    
    if (status != STATUS_OK) {
        res = _rsa_private_enc_dec_failure(NULL, 0, outLen, "KeyIso_service_adapter_generic_msg_preprocessing", "failed", STATUS_FAILED, command);
        KeyIso_service_adapter_generic_msg_cleanup(rsaPrivEncDecInSt, 0, true);
        return res;
    }  

    rsaPrivEncDecInSt = (KEYISO_RSA_PRIVATE_ENC_DEC_IN_ST *)rsaPrivEncDecInSt_v;

    // Get key from list
    PKMPP_KEY pkeyPtr = NULL;
    pkeyPtr = KeyIso_get_key_in_list(rsaPrivEncDecInSt->headerSt.correlationId, sender, rsaPrivEncDecInSt->keyId);
    if (pkeyPtr == NULL) {
        res = _create_response_rsa_private_enc_dec(rsaPrivEncDecInSt->keyId, STATUS_NOT_FOUND, command, 0, NULL, outLen);
        KeyIso_service_adapter_generic_msg_cleanup(rsaPrivEncDecInSt, 0, true);
        return res;
    }

    // Pass to the service API for the actual handling
    res = _handle_rsa_encrypt_dec(rsaPrivEncDecInSt->headerSt.correlationId, rsaPrivEncDecInSt->keyId, pkeyPtr, &rsaPrivEncDecInSt->params, outLen, command);
    // Decrease the ref count that was increased in get key in list API
    KeyIso_SERVER_free_key(rsaPrivEncDecInSt->headerSt.correlationId, pkeyPtr);
    KeyIso_service_adapter_generic_msg_cleanup(rsaPrivEncDecInSt, 0, true);
    return res;
}

static uint64_t _open_encrypted_key( const uuid_t correlationId, const char * secretSalt, KEYISO_ENCRYPTED_PRIV_KEY_ST* encKeySt, const char* sender,  PKMPP_KEY* outPkey)
{
    if (encKeySt == NULL || outPkey == NULL) {
        return 0;
    }
    //Pass to service API for the actual handling
    int ret = KeyIso_SERVER_open_private_key(correlationId, secretSalt, encKeySt, outPkey);
 
   if (ret != STATUS_OK) {
        return 0;
    }  
    
    //Get the keyId from the list , this API increases the reference counter of the key
    uint64_t keyId = KeyIso_add_key_to_list(correlationId, sender, *outPkey);
    if (keyId == 0) {
        // The key was not added to the list, hence we need to free the key
        KeyIso_SERVER_free_key(correlationId, *outPkey);
    }
    return keyId;
}

static KEYISO_ENCRYPTED_PRIV_KEY_ST* _get_encrypted_key(const uuid_t correlationId, uint32_t algVersion, uint32_t saltLen, uint32_t ivLen, uint32_t hmacLen, uint32_t encKeyLen, const unsigned char *encryptedKeyBytes, size_t *dynamicLen)
{
    *dynamicLen = 0;
    size_t dynamicEncKeySize = KeyIso_get_enc_key_bytes_len(correlationId,saltLen, ivLen, hmacLen, encKeyLen);
     if (dynamicEncKeySize == 0) {
        KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_SERVICE_TITLE, "Invalid input", "Invalid dynamic length", "dynamicLen = %ld", dynamicEncKeySize);
        return NULL;
    }
    
    size_t totalSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_ENCRYPTED_PRIV_KEY_ST, dynamicEncKeySize);
    KEYISO_ENCRYPTED_PRIV_KEY_ST* enKeySt = (KEYISO_ENCRYPTED_PRIV_KEY_ST*) KeyIso_zalloc(totalSize);
    if (enKeySt == NULL) {
        return NULL;
    }
    
    // Fill the structure with the data from the incoming
    enKeySt->algVersion = algVersion;
    enKeySt->saltLen = saltLen;
    enKeySt->ivLen = ivLen;
    enKeySt->hmacLen = hmacLen;
    enKeySt->encKeyLen = encKeyLen;
    memcpy(enKeySt->encryptedKeyBytes, encryptedKeyBytes, dynamicEncKeySize);
    *dynamicLen = dynamicEncKeySize;
    return enKeySt;
}

unsigned char* KeyIso_handle_msg_rsa_private_enc_dec_with_attached_key(const char *sender, const uint8_t *inSt,  size_t inLen, size_t *outLen)
{
    uint64_t keyId = 0; 
    unsigned char* res  = NULL;
    void *rsaPrivEncDecInSt_v = NULL;
    uint32_t command = IpcCommand_RsaPrivateEncryptDecryptWithAttachedKey;
    KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_IN_ST *rsaPrivEncDecInSt = NULL;

    if (inLen > KMPP_MAX_MESSAGE_SIZE) {
        res = _rsa_private_enc_dec_failure(NULL, keyId, outLen, "Incoming buffer of encrypted key is too big", "failed", STATUS_FAILED, command);
        KeyIso_service_adapter_generic_msg_cleanup(rsaPrivEncDecInSt, 0, true);
        return res;
    }
    int status = KeyIso_service_adapter_generic_msg_preprocessing(command, inSt, inLen, &rsaPrivEncDecInSt_v);
    if (status != STATUS_OK) {
        res =  _rsa_private_enc_dec_failure(NULL, keyId, outLen, "KeyIso_service_adapter_generic_msg_preprocessing", "failed", STATUS_FAILED, command);
        KeyIso_service_adapter_generic_msg_cleanup(rsaPrivEncDecInSt, 0, true);
        return res;
    }
    rsaPrivEncDecInSt = (KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_IN_ST*)rsaPrivEncDecInSt_v;
    PKMPP_KEY pkeyPtr = NULL;
    size_t encKeyDynamicSize = 0;
    KEYISO_ENCRYPTED_PRIV_KEY_ST* enKeySt = _get_encrypted_key(rsaPrivEncDecInSt->headerSt.correlationId, rsaPrivEncDecInSt->algVersion, rsaPrivEncDecInSt->saltLen, rsaPrivEncDecInSt->ivLen, rsaPrivEncDecInSt->hmacLen, rsaPrivEncDecInSt->encKeyLen, rsaPrivEncDecInSt->bytes, &encKeyDynamicSize);
    if (enKeySt == NULL) {
        res =  _rsa_private_enc_dec_failure(rsaPrivEncDecInSt->headerSt.correlationId, keyId, outLen, "enKeySt", "allocation failed", STATUS_FAILED, command);
        KeyIso_service_adapter_generic_msg_cleanup(rsaPrivEncDecInSt, 0, true);
        return NULL;
    }

    keyId = _open_encrypted_key(rsaPrivEncDecInSt->headerSt.correlationId, (char*)rsaPrivEncDecInSt->secretSalt, enKeySt, sender, &pkeyPtr);
    KeyIso_free(enKeySt);
    enKeySt = NULL;

    KEYISOP_trace_log_para(rsaPrivEncDecInSt->headerSt.correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_SERVICE_TITLE, "Open after evict - RSA", "sender: %s, keyId: 0x%016llx", sender, keyId);

    if (keyId == 0) {
        res =  _rsa_private_enc_dec_failure(rsaPrivEncDecInSt->headerSt.correlationId, keyId, outLen, "_open_encrypted_key", "failed", STATUS_FAILED, command);
        KeyIso_SERVER_free_key(rsaPrivEncDecInSt->headerSt.correlationId, pkeyPtr);
        KeyIso_service_adapter_generic_msg_cleanup(rsaPrivEncDecInSt, 0, true);
        return res;
    }
    
    KEYISOP_trace_log_para(rsaPrivEncDecInSt->headerSt.correlationId, 0, KEYISOP_SERVICE_TITLE, "Open private key general info", "sender: %s, keyId: 0x%016llx", sender, keyId);
    size_t dynamicSize = KeyIso_get_rsa_enc_dec_params_dynamic_len(rsaPrivEncDecInSt->fromBytesLen, rsaPrivEncDecInSt->labelLen);
    size_t paramStSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_RSA_PRIVATE_ENC_DEC_IN_PARAMS_ST, dynamicSize);
    KEYISO_RSA_PRIVATE_ENC_DEC_IN_PARAMS_ST* rsaPrivEncDecInParams = (KEYISO_RSA_PRIVATE_ENC_DEC_IN_PARAMS_ST*) KeyIso_zalloc(paramStSize);
    if (rsaPrivEncDecInParams == NULL) {
        res =  _rsa_private_enc_dec_failure(rsaPrivEncDecInSt->headerSt.correlationId, keyId, outLen, "rsaPrivEncDecInParams", "allocation failed", STATUS_FAILED, command);
        KeyIso_SERVER_free_key(rsaPrivEncDecInSt->headerSt.correlationId, pkeyPtr);
        KeyIso_service_adapter_generic_msg_cleanup(rsaPrivEncDecInSt, 0, true);
        return res;
    }

    KeyIso_fill_rsa_enc_dec_param(rsaPrivEncDecInParams, rsaPrivEncDecInSt->decrypt, rsaPrivEncDecInSt->padding, rsaPrivEncDecInSt->tlen, rsaPrivEncDecInSt->fromBytesLen, rsaPrivEncDecInSt->labelLen, rsaPrivEncDecInSt->bytes + encKeyDynamicSize);
    res = _handle_rsa_encrypt_dec(rsaPrivEncDecInSt->headerSt.correlationId, keyId, pkeyPtr, rsaPrivEncDecInParams, outLen, command);
    KeyIso_SERVER_free_key(rsaPrivEncDecInSt->headerSt.correlationId, pkeyPtr);
    KeyIso_free(rsaPrivEncDecInParams);

    //Cleanup
    KeyIso_service_adapter_generic_msg_cleanup(rsaPrivEncDecInSt, 0, true);
    return res;
}

//////////////////////////
/*  ECDSA Sign         */
//////////////////////////
// Function to allocate and initialize ECDSA response
static void* _allocate_and_initialize_ecdsa_response(uint64_t keyId, uint32_t command, uint32_t status, int bytesLen, const unsigned char *signatureBytes, size_t *outLen) {
    size_t structSize = 0;
    uint8_t* res = NULL;
    if (command == IpcCommand_EcdsaSign) {
        structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_ECDSA_SIGN_OUT_ST, bytesLen);
        KEYISO_ECDSA_SIGN_OUT_ST* out = (KEYISO_ECDSA_SIGN_OUT_ST*) KeyIso_zalloc(structSize);
        out->headerSt.command = command;
        out->headerSt.result = status;
        out->bytesLen = bytesLen;
        if (bytesLen > 0) {
            memcpy(out->signatureBytes, signatureBytes, bytesLen);
        }
        res = (uint8_t*)out;
    } else if (command == IpcCommand_EcdsaSignWithAttachedKey) {
        structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_OUT_ST, bytesLen);
        KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_OUT_ST* out = (KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_OUT_ST*) KeyIso_zalloc(structSize);
        out->headerSt.command = command;
        out->headerSt.result = status;
        out->keyId = keyId;
        out->bytesLen = bytesLen;
        if (bytesLen > 0) {
            memcpy(out->signatureBytes, signatureBytes, bytesLen);
        }
       res = (uint8_t*)out;
    }
    *outLen = structSize;
    return res;
}
// Function to create and serialize ECDSA sign response
static unsigned char* _create_response_ecdsa_sign(size_t *outLen, uint64_t keyId, int bytesLen, const unsigned char *signatureBytes, uint32_t status, uint32_t command) {
    if (outLen == NULL) {
        KEYISOP_trace_log_error(0, 0, KEYISOP_SERVICE_TITLE, "_create_response_ecdsa_sign", "Invalid outLen");
        return NULL;
    }
    
    void *outSt = _allocate_and_initialize_ecdsa_response(keyId, command, status, bytesLen, signatureBytes, outLen);
    if (outSt == NULL) {
        *outLen = 0;
        return NULL;
    }

    uint8_t *outBuf = KeyIso_service_adapter_generic_msg_postprocessing(command, outSt, outLen);
    KeyIso_service_adapter_generic_msg_cleanup(outSt, 0, false);
    return outBuf;
}


static unsigned char* _ecdsa_sign_failure(const uint8_t *correlationId, uint64_t keyId , size_t *encodedOutLen, const char *loc, const char *errorStr, uint32_t status, uint32_t command)
{
    KEYISOP_trace_log_error(correlationId, 0, KEYISOP_SERVICE_TITLE, loc, errorStr);
    return _create_response_ecdsa_sign(encodedOutLen, keyId, 0, NULL, status, command);
}

static unsigned char* _handle_ecdsa_sign(const unsigned char *correlationId, uint64_t keyId, KEYISO_ECDSA_SIGN_IN_PARAMS_ST *params, PKMPP_KEY pkeyPtr, size_t *outLen, uint32_t command)
{
    //Send to the service for the actual handling
    unsigned char *signatureBytes = NULL;
    if (params->sigLen != 0 && params->sigLen < 0x10000) {
        signatureBytes = (unsigned char*) KeyIso_zalloc(params->sigLen);
    }

    if (signatureBytes == NULL) {
        return _ecdsa_sign_failure(correlationId, keyId, outLen, "signatureBytes", "allocation failed", STATUS_FAILED, command);
    }

    unsigned int actualLen = 0;
    int success = KEYISO_SERVER_ecc_operation(correlationId, pkeyPtr, params->type, params->digestBytes, params->digestLen, signatureBytes, params->sigLen, &actualLen);
    
    if (success < 0 || actualLen == 0 || actualLen > params->sigLen) {
        KeyIso_free(signatureBytes);
        return _ecdsa_sign_failure(correlationId, keyId, outLen, "KeyIso_SERVER_ecdsa_sign_ossl", "invalid result", STATUS_FAILED, command);
    }
                       
    //Create response
    uint8_t *outBuf = _create_response_ecdsa_sign(outLen, keyId, actualLen, signatureBytes, STATUS_OK, command);
    KeyIso_free(signatureBytes);
    return outBuf;
}

unsigned char* KeyIso_handle_msg_ecdsa_sign(const char *sender, const uint8_t *inSt, size_t inLen, size_t *outLen)
{   
    //Performing pre-processing
    uint8_t *res = NULL;
    uint64_t keyId = 0;
    void *ecSignInSt_v = NULL;
    uint32_t command = IpcCommand_EcdsaSign;
    KEYISO_ECDSA_SIGN_IN_ST *ecSignInSt = NULL;
    int status = KeyIso_service_adapter_generic_msg_preprocessing(command, inSt, inLen, &ecSignInSt_v); 
    if (status != STATUS_OK) {
        res = _ecdsa_sign_failure(NULL, keyId, outLen, "KeyIso_service_adapter_generic_msg_preprocessing", "failed", STATUS_FAILED, command);
        KeyIso_service_adapter_generic_msg_cleanup(ecSignInSt, 0, true);  
        return res;
    }

    ecSignInSt = (KEYISO_ECDSA_SIGN_IN_ST *)ecSignInSt_v;

    //2. Check if the message can be handled
    PKMPP_KEY pkeyPtr = NULL; 
    pkeyPtr = KeyIso_get_key_in_list(ecSignInSt->headerSt.correlationId, sender, ecSignInSt->keyId);
    if (pkeyPtr == NULL || pkeyPtr->key == NULL) {
        res = _ecdsa_sign_failure(ecSignInSt->headerSt.correlationId, keyId, outLen, "KeyIso_get_key_in_list", "key not found", STATUS_NOT_FOUND, command);
        KeyIso_service_adapter_generic_msg_cleanup(ecSignInSt, 0, true);  
        return res;
    }

    if (pkeyPtr->type != KmppKeyType_ec) {
        res = _ecdsa_sign_failure(ecSignInSt->headerSt.correlationId, keyId, outLen, "KeyIso_get_key_in_list", "invalid key type", STATUS_FAILED, command);
        KeyIso_SERVER_free_key(ecSignInSt->headerSt.correlationId, pkeyPtr);
        KeyIso_service_adapter_generic_msg_cleanup(ecSignInSt, 0, true);  
        return res;
    }
      
    res = _handle_ecdsa_sign(ecSignInSt->headerSt.correlationId, keyId, &ecSignInSt->params, pkeyPtr, outLen, command);
    KeyIso_SERVER_free_key(ecSignInSt->headerSt.correlationId, pkeyPtr);
    KeyIso_service_adapter_generic_msg_cleanup(ecSignInSt, 0, true);  
    return res;
}

unsigned char*  KeyIso_handle_msg_ecdsa_sign_with_attached_key(
    const char *sender,
    const uint8_t *inSt, 
    size_t inLen, 
    size_t *outLen)
{
    // Performing pre-processing
    unsigned char* res  = NULL;
    uint64_t keyId = 0;
    void *ecSignInSt_v = NULL;
    uint32_t command = IpcCommand_EcdsaSignWithAttachedKey;
    KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_IN_ST *ecSignInSt = NULL;

    if (inLen > KMPP_MAX_MESSAGE_SIZE) {
        res = _ecdsa_sign_failure(NULL, keyId, outLen, "Incoming buffer of encrypted key is too big", "failed", STATUS_FAILED, command);
        KeyIso_service_adapter_generic_msg_cleanup(ecSignInSt, 0, true);
        return res;
    }

    int status = KeyIso_service_adapter_generic_msg_preprocessing(command, inSt, inLen, &ecSignInSt_v);
    if (status != STATUS_OK) {
        res = _ecdsa_sign_failure(NULL, keyId, outLen, "KeyIso_service_adapter_generic_msg_preprocessing", "failed", STATUS_FAILED, command);
        KeyIso_service_adapter_generic_msg_cleanup(ecSignInSt, 0, true);
        return res;
    }

    ecSignInSt = (KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_IN_ST *)ecSignInSt_v;

    PKMPP_KEY pkeyPtr = NULL;
    size_t dynamicEncKeySize = 0;
    KEYISO_ENCRYPTED_PRIV_KEY_ST *enKeySt = _get_encrypted_key(ecSignInSt->headerSt.correlationId, ecSignInSt->algVersion, ecSignInSt->saltLen, ecSignInSt->ivLen, ecSignInSt->hmacLen, ecSignInSt->encKeyLen, ecSignInSt->bytes, &dynamicEncKeySize);
    if (enKeySt == NULL) {
        res = _ecdsa_sign_failure(ecSignInSt->headerSt.correlationId, keyId, outLen, "_get_encrypted_key", "failed", STATUS_FAILED, command);
        KeyIso_service_adapter_generic_msg_cleanup(ecSignInSt, 0, true);
        return res;
    }
    keyId = _open_encrypted_key(ecSignInSt->headerSt.correlationId, (char*)ecSignInSt->secretSalt, enKeySt, sender, &pkeyPtr);
    if (keyId == 0) {
        res = _ecdsa_sign_failure(ecSignInSt->headerSt.correlationId, keyId, outLen, "_open_encrypted_key", "failed", STATUS_FAILED, command);
        KeyIso_service_adapter_generic_msg_cleanup(ecSignInSt, 0, true);
        KeyIso_free(enKeySt);
        return res;
    }
    KeyIso_free(enKeySt);
    enKeySt = NULL;

    KEYISOP_trace_log_para(ecSignInSt->headerSt.correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_SERVICE_TITLE, "Open after evict - ECC", "sender: %s, keyId: 0x%016llx", sender, keyId);
    
    size_t dynamicSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_ECDSA_SIGN_IN_PARAMS_ST, ecSignInSt->digestLen);
    KEYISO_ECDSA_SIGN_IN_PARAMS_ST* ecSignInParams = (KEYISO_ECDSA_SIGN_IN_PARAMS_ST*) KeyIso_zalloc(dynamicSize);
    if (ecSignInParams == NULL) {
        res = _ecdsa_sign_failure(ecSignInSt->headerSt.correlationId, keyId, outLen, "_open_encrypted_key", "failed", STATUS_FAILED, command);
        KeyIso_SERVER_free_key(ecSignInSt->headerSt.correlationId, pkeyPtr);
        KeyIso_service_adapter_generic_msg_cleanup(ecSignInSt, 0, true);
        return res;
    }
    ecSignInParams->type = ecSignInSt->type;
    ecSignInParams->sigLen = ecSignInSt->sigLen;
    ecSignInParams->digestLen = ecSignInSt->digestLen;
    memcpy(ecSignInParams->digestBytes, (ecSignInSt->bytes + dynamicEncKeySize), ecSignInSt->digestLen);

    res = _handle_ecdsa_sign(ecSignInSt->headerSt.correlationId, keyId, ecSignInParams, pkeyPtr, outLen, command);
    KeyIso_SERVER_free_key(ecSignInSt->headerSt.correlationId, pkeyPtr);
    KeyIso_free(ecSignInParams);
    KeyIso_service_adapter_generic_msg_cleanup(ecSignInSt, 0, true);
    return res;
}

//////////////////////////
/*      Close Key       */
//////////////////////////

static unsigned char* _create_response_close_key(size_t *outLen, int result)
{    
    if (outLen == NULL) {
        KEYISOP_trace_log_error(0, 0, KEYISOP_CLOSE_PFX_TITLE, "_create_response_close_key", "Invalid outLen");
        return NULL;
    }
    
    KEYISOP_trace_log_para(NULL, 0, NULL, "Complete", "result: %d", result);

    KEYISO_CLOSE_KEY_OUT_ST* outSt = (KEYISO_CLOSE_KEY_OUT_ST *)KeyIso_zalloc(sizeof(KEYISO_CLOSE_KEY_OUT_ST));
    if (outSt == NULL) {
        *outLen = 0;
        return NULL;
    }

    outSt->headerSt.command = IpcCommand_CloseKey;
    outSt->headerSt.result = result;

    *outLen = sizeof(KEYISO_CLOSE_KEY_OUT_ST); // initialize the outLen to the struct size for the case of no encoding (inproc)
    uint8_t *outBuf = KeyIso_service_adapter_generic_msg_postprocessing(IpcCommand_CloseKey, outSt, outLen); 
    
    KeyIso_service_adapter_generic_msg_cleanup(outSt, 0, false);
    
    return outBuf;
}


static unsigned char* _close_key_failure(KEYISO_CLOSE_KEY_IN_ST *inSt, size_t *outLen, const char *loc, const char *errorStr)
{
    const uint8_t *correlationId = inSt ? inSt->headerSt.correlationId : NULL;
    KEYISOP_trace_log_error(correlationId, 0, KEYISOP_SERVICE_TITLE, loc, errorStr);    
    KeyIso_service_adapter_generic_msg_cleanup(inSt, 0, true);
    return _create_response_close_key(outLen, STATUS_FAILED);
}


unsigned char* KeyIso_handle_msg_close_key(const char *sender, const uint8_t *inSt, size_t inLen, size_t *outLen)
{      
    //1. Performing pre-processing
    void *closeKeyInSt_v = NULL;
    KEYISO_CLOSE_KEY_IN_ST *closeKeyInSt = NULL;
    int status = KeyIso_service_adapter_generic_msg_preprocessing(IpcCommand_CloseKey, inSt, inLen, &closeKeyInSt_v);
    if (status != STATUS_OK) {
        return _close_key_failure(closeKeyInSt, outLen, "KeyIso_service_adapter_generic_msg_preprocessing", "failed");
    }

    closeKeyInSt = (KEYISO_CLOSE_KEY_IN_ST *)closeKeyInSt_v;
    
    //2. Handle message
    KeyIso_remove_key_from_list(closeKeyInSt->headerSt.correlationId, sender, closeKeyInSt->keyId);
        
    //3. Cleanup
    KeyIso_service_adapter_generic_msg_cleanup(closeKeyInSt, 0, true);
   
    //4. Create response
    return _create_response_close_key(outLen, STATUS_OK);
}


////////////////////////////////////////
/*      Symmetric key: Import         */
////////////////////////////////////////

static unsigned char* _create_response_import_symmetric_key(size_t *outLen, int encryptedKeyLen, const unsigned char *encryptedKeyBytes)
{    
    if (!outLen)
        return NULL;
    *outLen = 0;

    size_t structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_IMPORT_SYMMETRIC_KEY_OUT_ST, encryptedKeyLen);
    KEYISO_IMPORT_SYMMETRIC_KEY_OUT_ST* outSt = (KEYISO_IMPORT_SYMMETRIC_KEY_OUT_ST *)KeyIso_zalloc(structSize);
    if (outSt == NULL)
        return NULL;
    
    outSt->headerSt.command = IpcCommand_ImportSymmetricKey;
    outSt->headerSt.result = encryptedKeyLen ? STATUS_OK : STATUS_FAILED;
    outSt->encryptedKeyLen = encryptedKeyLen;
    if (encryptedKeyLen) {
        memcpy(outSt->encryptedKeyBytes, encryptedKeyBytes, encryptedKeyLen);
    }
    
    *outLen = structSize; // initialize the outLen to the struct size for the case of no encoding (inproc)
    uint8_t *outBuf = KeyIso_service_adapter_generic_msg_postprocessing(IpcCommand_ImportSymmetricKey, outSt, outLen);
    
    KeyIso_service_adapter_generic_msg_cleanup(outSt, 0, false);
    
    return outBuf;
}


static unsigned char* _import_symmetric_key_failure(KEYISO_IMPORT_SYMMETRIC_KEY_IN_ST *inSt, size_t *outLen, const char *loc, const char *errorStr)
{
    const uint8_t *correlationId = inSt ? inSt->headerSt.correlationId : NULL;
    KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_SYMMETRIC_KEY_TITLE, loc, errorStr);
    KeyIso_service_adapter_generic_msg_cleanup(inSt, 0, true); 
    return _create_response_import_symmetric_key(outLen, 0, NULL);
}


unsigned char* KeyIso_handle_msg_import_symmetric_key(const uint8_t *inSt, size_t inLen, size_t *outLen)
{   
    //1. Performing pre-processing
    void *importSymmetricKeyinSt_v = NULL;
    KEYISO_IMPORT_SYMMETRIC_KEY_IN_ST *importSymmetricKeyinSt = NULL;
    int status = KeyIso_service_adapter_generic_msg_preprocessing(IpcCommand_ImportSymmetricKey, inSt, inLen, &importSymmetricKeyinSt_v);
    if (status != STATUS_OK) {
        return _import_symmetric_key_failure(importSymmetricKeyinSt, outLen, "KeyIso_service_adapter_generic_msg_preprocessing", "failed");
    }        

    importSymmetricKeyinSt = (KEYISO_IMPORT_SYMMETRIC_KEY_IN_ST *)importSymmetricKeyinSt_v;

    if (importSymmetricKeyinSt->keyLen == 0 ||  importSymmetricKeyinSt->keyLen > MAX_SYMMETRIC_KEY_LEN)
        return _import_symmetric_key_failure(importSymmetricKeyinSt, outLen, "invalid keyLen length", "failed");
    
    //2. Send to the service for the actual handling
    unsigned char *outKeyBytes = NULL; // KeyIso_clear_free()
    unsigned int outKeyLen = 0; 

    status = KeyIso_SERVER_import_symmetric_key(importSymmetricKeyinSt->headerSt.correlationId, importSymmetricKeyinSt->symmetricKeyType, 
                importSymmetricKeyinSt->keyLen, importSymmetricKeyinSt->keyBytes, importSymmetricKeyinSt->importKeyId, &outKeyLen, &outKeyBytes);
          
    if (status == STATUS_FAILED) {
        KeyIso_free(outKeyBytes);
        return _import_symmetric_key_failure(importSymmetricKeyinSt, outLen, "KeyIso_SERVER_import_symmetric_key", "invalid result");
    }

    //3. Cleanup
    KeyIso_service_adapter_generic_msg_cleanup(importSymmetricKeyinSt, 0, true);                          

    //4. Create response
    uint8_t *outBuf = _create_response_import_symmetric_key(outLen, outKeyLen, outKeyBytes);
    KeyIso_clear_free(outKeyBytes, outKeyLen);
    return outBuf;
}

////////////////////////////////////////
/*   Symmetric key: Encode - Decode   */
////////////////////////////////////////

static unsigned char* _create_response_symmetric_key_enc_dec(size_t *outLen, int bytesLen, const unsigned char *toBytes)
{    
    if (!outLen)
        return NULL;
    *outLen = 0;

    size_t structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_OUT_ST, bytesLen);
    KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_OUT_ST* outSt = (KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_OUT_ST *)KeyIso_zalloc(structSize);
    if (outSt == NULL)
        return NULL;
    
    outSt->headerSt.command = IpcCommand_SymmetricKeyEncryptDecrypt;
    outSt->headerSt.result = bytesLen ? STATUS_OK : STATUS_FAILED;
    outSt->bytesLen = bytesLen;
    if (bytesLen) {
        memcpy(outSt->toBytes, toBytes, bytesLen);
    }
    
    *outLen = structSize; // initialize the outLen to the struct size for the case of no encoding (inproc)
    uint8_t *outBuf = KeyIso_service_adapter_generic_msg_postprocessing(IpcCommand_SymmetricKeyEncryptDecrypt, outSt, outLen);
    
    KeyIso_service_adapter_generic_msg_cleanup(outSt, 0, false);
    
    return outBuf;
}


static unsigned char* _symmetric_key_enc_dec_failure(KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST *inSt, size_t *outLen, const char *loc, const char *errorStr)
{
    const uint8_t *correlationId = inSt ? inSt->headerSt.correlationId : NULL;
    KEYISOP_trace_log_error(correlationId, 0, KEYISOP_SERVICE_TITLE, loc, errorStr);
    KeyIso_service_adapter_generic_msg_cleanup(inSt, 0, true);
    return _create_response_symmetric_key_enc_dec(outLen, 0, NULL);
}


unsigned char* KeyIso_handle_msg_symmetric_key_enc_dec(const uint8_t *inSt, size_t inLen, size_t *outLen)
{   
    //1. Performing pre-processing
    void *symmetricEncDecInSt_v = NULL;
    KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST *symmetricEncDecInSt = NULL;
    int status = KeyIso_service_adapter_generic_msg_preprocessing(IpcCommand_SymmetricKeyEncryptDecrypt, inSt, inLen, &symmetricEncDecInSt_v);
    if (status != STATUS_OK) {
        return _symmetric_key_enc_dec_failure(symmetricEncDecInSt, outLen, "KeyIso_deserialize_ecdsa_sign_in", "failed");
    }

    symmetricEncDecInSt = (KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST *)symmetricEncDecInSt_v;

    if (symmetricEncDecInSt->encryptedKeyLen == 0 || symmetricEncDecInSt->fromBytesLen == 0 ||
        symmetricEncDecInSt->encryptedKeyLen > 0x10000 || symmetricEncDecInSt->fromBytesLen > 0x10000) { 
        return _symmetric_key_enc_dec_failure(symmetricEncDecInSt, outLen, "invalid dynamic length", "failed");
    }
    
    unsigned char* encryptedKey = (unsigned char*) KeyIso_zalloc(symmetricEncDecInSt->encryptedKeyLen);
    if (encryptedKey == NULL) {
        return _symmetric_key_enc_dec_failure(symmetricEncDecInSt, outLen, "encryptedKey", "allocation failed");
    }

    unsigned char* from = (unsigned char*) KeyIso_zalloc(symmetricEncDecInSt->fromBytesLen);
    if (from == NULL) {
        KeyIso_free(encryptedKey);
        return _symmetric_key_enc_dec_failure(symmetricEncDecInSt, outLen, "from", "allocation failed");
    }

    int index = 0;
    memcpy(encryptedKey, &symmetricEncDecInSt->encDecBytes[index], symmetricEncDecInSt->encryptedKeyLen);
    index += symmetricEncDecInSt->encryptedKeyLen;
    memcpy(from, &symmetricEncDecInSt->encDecBytes[index], symmetricEncDecInSt->fromBytesLen);
 
    //2. Send to the service for the actual handling
    unsigned int lenToAlloc = 0;
    if (KeyIso_symmetric_key_encrypt_decrypt_size(
        symmetricEncDecInSt->decrypt,
        symmetricEncDecInSt->fromBytesLen,
        0,
        &lenToAlloc) != STATUS_OK) {
            KeyIso_free(encryptedKey);
            KeyIso_free(from);
            return _symmetric_key_enc_dec_failure(symmetricEncDecInSt, outLen, "KeyIso_symmetric_key_encrypt_decrypt_size", "failed");
    }
    unsigned char* toBytes = (unsigned char*) KeyIso_zalloc(lenToAlloc); 
    unsigned int toLen = 0;
    status = KeyIso_SERVER_symmetric_key_encrypt_decrypt(symmetricEncDecInSt->headerSt.correlationId, symmetricEncDecInSt->decrypt,
            symmetricEncDecInSt->encryptedKeyLen, encryptedKey, from, symmetricEncDecInSt->fromBytesLen, toBytes, &toLen);
    
    KeyIso_free(encryptedKey);
    KeyIso_free(from);

    if (status == STATUS_FAILED) {
        KeyIso_free(toBytes);
        return _symmetric_key_enc_dec_failure(symmetricEncDecInSt, outLen, "KeyIso_SERVER_symmetric_key_encrypt_decrypt", "invalid result");
    }

    //3. Cleanup
    KeyIso_service_adapter_generic_msg_cleanup(symmetricEncDecInSt, 0, true);                               

    //4. Create response
    uint8_t *outBuf = _create_response_symmetric_key_enc_dec(outLen, toLen, toBytes);
    KeyIso_free(toBytes);
    return outBuf;
}

//////////////////////////
/*  Import private Key  */
//////////////////////////

static unsigned char* _cleanup_response_import_private_key(int ret, const char *loc, const char *err, uint8_t *encodedBuf,
    KEYISO_ENCRYPTED_PRIV_KEY_ST *encKeySt, char *saltStr, KEYISO_IMPORT_PRIV_KEY_OUT_ST* outSt)
{
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(0, 0, KEYISOP_IMPORT_KEY_TITLE, loc, err);
    }
    KeyIso_clear_free_string(saltStr);
    KeyIso_free(encKeySt);
    KeyIso_service_adapter_generic_msg_cleanup(outSt, 0, false);
    return encodedBuf;
}

static unsigned char* _create_response_import_private_key(IpcCommand command, size_t *outLen, int ret, KEYISO_ENCRYPTED_PRIV_KEY_ST *encKeySt, char *saltStr)
{   
    *outLen = 0;     
    size_t dynamicLen = ((encKeySt != NULL) ? encKeySt->saltLen + encKeySt->ivLen + encKeySt->hmacLen + encKeySt->encKeyLen : 0);
    size_t structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_IMPORT_PRIV_KEY_OUT_ST, dynamicLen);
    KEYISO_IMPORT_PRIV_KEY_OUT_ST* outSt = (KEYISO_IMPORT_PRIV_KEY_OUT_ST *)KeyIso_zalloc(structSize);
    if (outSt == NULL)
        return _cleanup_response_import_private_key(STATUS_FAILED, "KeyIso_zalloc", "Invalid allocation", NULL, encKeySt, saltStr, NULL);
    
    outSt->headerSt.result = ret;
    outSt->headerSt.command = command;
    if (saltStr) {
        size_t secretSaltLen = strlen(saltStr);
        if (secretSaltLen >= KEYISO_SECRET_SALT_STR_BASE64_LEN) {
            return _cleanup_response_import_private_key(STATUS_FAILED, "secretSalt", "Invalid secret salt length", NULL, encKeySt, saltStr, outSt);
        }
        memcpy(outSt->secretSalt, saltStr, secretSaltLen);
        outSt->secretSalt[KEYISO_SECRET_SALT_STR_BASE64_LEN - 1] = '\0';
    }
    if (encKeySt) {
        outSt->encKeySt.algVersion = encKeySt->algVersion;
        outSt->encKeySt.saltLen = encKeySt->saltLen;
        outSt->encKeySt.ivLen = encKeySt->ivLen;
        outSt->encKeySt.hmacLen = encKeySt->hmacLen; 
        outSt->encKeySt.encKeyLen = encKeySt->encKeyLen;
        memcpy(outSt->encKeySt.encryptedKeyBytes, encKeySt->encryptedKeyBytes, dynamicLen);
    } 
    
    *outLen = structSize; // initialize the outLen to the struct size for the case of no encoding (inproc)
    uint8_t *outBuf = KeyIso_service_adapter_generic_msg_postprocessing(command, outSt, outLen);

    return _cleanup_response_import_private_key(STATUS_OK, "", "", outBuf, encKeySt, saltStr, outSt);    
}

// RSA functions
static unsigned char* _rsa_import_key_failure(KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST *inSt, size_t inLen, size_t *encodedOutLen, const char *loc, const char *errorStr)
{
    const uint8_t *correlationId = inSt ? inSt->headerSt.correlationId : NULL;
    KEYISOP_trace_log_error(correlationId, 0, KEYISOP_SERVICE_TITLE, loc, errorStr);
    KeyIso_service_adapter_generic_msg_cleanup(inSt, inLen, true);
    return _create_response_import_private_key(IpcCommand_ImportRsaPrivateKey, encodedOutLen, STATUS_FAILED, NULL, NULL);
}

unsigned char* KeyIso_handle_msg_rsa_import_private_key(const uint8_t *inSt, size_t inLen, size_t *outLen)
{
    //1. Performing pre-processing
    void *importRsaKeyInSt_v = NULL;
    KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST *importRsaKeyInSt = NULL;

    // Check that pfx size doesn't exceed the maximum
    if (inLen > KMPP_MAX_MESSAGE_SIZE) {
        return _rsa_import_key_failure(importRsaKeyInSt, 0, outLen, "Incoming buffer of import key is too big", "failed");
    }

    size_t structSize = KeyIso_service_adapter_generic_msg_in_get_len(IpcCommand_ImportRsaPrivateKey, inSt, inLen);
    int status = KeyIso_service_adapter_generic_msg_preprocessing(IpcCommand_ImportRsaPrivateKey, inSt, inLen, &importRsaKeyInSt_v);
    if (status != STATUS_OK) {
        return _rsa_import_key_failure(importRsaKeyInSt, structSize, outLen, "KeyIso_service_adapter_generic_msg_preprocessing", "failed");
    }

    importRsaKeyInSt = (KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST *)importRsaKeyInSt_v; 

    //2. Send to the service for the actual handling
    void* outEncKey = NULL;
    char* outSalt = NULL;

    status = KeyIso_SERVER_import_private_key(importRsaKeyInSt->headerSt.correlationId, KMPP_EVP_PKEY_RSA_NID, (void *)&importRsaKeyInSt->pkeySt, &outEncKey, &outSalt);
    if (status != STATUS_OK)
        return _rsa_import_key_failure(importRsaKeyInSt, structSize, outLen, "KeyIso_SERVER_import_private_key", "failed");

    //3. Cleanup                          
    KeyIso_service_adapter_generic_msg_cleanup(importRsaKeyInSt, structSize, true);

    //4. Create response
    return _create_response_import_private_key(IpcCommand_ImportRsaPrivateKey, outLen, STATUS_OK, (KEYISO_ENCRYPTED_PRIV_KEY_ST *)outEncKey, outSalt);
}

// EC functions
static unsigned char* _ec_import_key_failure(KEYISO_IMPORT_EC_PRIV_KEY_IN_ST *inSt, size_t inLen, size_t *encodedOutLen, const char *loc, const char *errorStr)
{
    const uint8_t *correlationId = inSt ? inSt->headerSt.correlationId : NULL;
    KEYISOP_trace_log_error(correlationId, 0, KEYISOP_SERVICE_TITLE, loc, errorStr);
    KeyIso_service_adapter_generic_msg_cleanup(inSt, inLen, true);
    return _create_response_import_private_key(IpcCommand_ImportEcPrivateKey, encodedOutLen, STATUS_FAILED, NULL, NULL);
}

unsigned char* KeyIso_handle_msg_ec_import_private_key(const uint8_t *inSt, size_t inLen, size_t *outLen) 
{
    //1. Performing pre-processing
    void *importEcKeyInSt_v = NULL;
    KEYISO_IMPORT_EC_PRIV_KEY_IN_ST *importEcKeyInSt = NULL;

    // Check that pfx size doesn't exceed the maximum
    if (inLen > KMPP_MAX_MESSAGE_SIZE) {
        return _ec_import_key_failure(importEcKeyInSt, 0, outLen, "Incoming buffer of import key is too big", "failed");
    }

    size_t structSize = KeyIso_service_adapter_generic_msg_in_get_len(IpcCommand_ImportEcPrivateKey, inSt, inLen);
    int status = KeyIso_service_adapter_generic_msg_preprocessing(IpcCommand_ImportEcPrivateKey, inSt, inLen, &importEcKeyInSt_v);
    if (status != STATUS_OK) {
        return _ec_import_key_failure(importEcKeyInSt, structSize, outLen, "KeyIso_service_adapter_generic_msg_preprocessing", "failed");
    }

    importEcKeyInSt = (KEYISO_IMPORT_EC_PRIV_KEY_IN_ST *)importEcKeyInSt_v;

    //2. Send to the service for the actual handling
    void* outEncKey = NULL;
    char* outSalt = NULL;

    status = KeyIso_SERVER_import_private_key(importEcKeyInSt->headerSt.correlationId, KMPP_EVP_PKEY_EC_NID, (void *)&importEcKeyInSt->pkeySt, &outEncKey, &outSalt);
    if (status != STATUS_OK) {
        return _ec_import_key_failure(importEcKeyInSt, structSize, outLen, "KeyIso_SERVER_import_private_key", "failed");
    }

    //3. Cleanup                         
    KeyIso_service_adapter_generic_msg_cleanup(importEcKeyInSt, structSize, true);

    //4. Create response
    return _create_response_import_private_key(IpcCommand_ImportEcPrivateKey, outLen, STATUS_OK, (KEYISO_ENCRYPTED_PRIV_KEY_ST *)outEncKey, outSalt);
}

//////////////////////////
/*  Generate key pair  */
////////////////////////// 

// RSA functions

static unsigned char* _cleanup_response_key_generate(int ret, const char *loc, const char *err, uint8_t *msgBuf, 
    void *pubKey, KEYISO_ENCRYPTED_PRIV_KEY_ST *encKeySt, char *saltStr, void* outSt)
{
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(0, 0, KEYISOP_GEN_KEY_TITLE, loc, err);
    }
    KeyIso_clear_free_string(saltStr);
    KeyIso_free(encKeySt);
    KeyIso_free(pubKey);
    KeyIso_service_adapter_generic_msg_cleanup(outSt, 0, false);

    return msgBuf;
}

static unsigned char* _create_response_rsa_key_generate(IpcCommand command, size_t *outLen, int ret, KEYISO_RSA_PUBLIC_KEY_ST *pubKey, KEYISO_ENCRYPTED_PRIV_KEY_ST *encKeySt, char *saltStr)
{
    if (!outLen)
        return NULL;
    *outLen = 0;     
    
    size_t encKeyLen = 0;
    size_t pubKeyLen = 0;    

    if (ret == STATUS_OK) {
        encKeyLen = ((encKeySt != NULL) ? encKeySt->saltLen + encKeySt->ivLen + encKeySt->hmacLen + encKeySt->encKeyLen : 0);
        pubKeyLen = pubKey ? (pubKey->rsaModulusLen + pubKey->rsaPublicExpLen) : 0;
    }

    size_t structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_GEN_RSA_KEY_PAIR_OUT_ST, encKeyLen + pubKeyLen);    
    KEYISO_GEN_RSA_KEY_PAIR_OUT_ST* outSt = (KEYISO_GEN_RSA_KEY_PAIR_OUT_ST *)KeyIso_zalloc(structSize);
    if (outSt == NULL) {
        return _cleanup_response_key_generate(STATUS_FAILED, "KeyIso_zalloc", "Invalid allocation", NULL, pubKey, encKeySt, saltStr, NULL);
    }   
    outSt->headerSt.result = ret;
    outSt->headerSt.command = command;

    if (ret == STATUS_OK) {
        size_t secretSaltLen = strlen(saltStr);
        if (secretSaltLen >= KEYISO_SECRET_SALT_STR_BASE64_LEN) {
            return _cleanup_response_key_generate(STATUS_FAILED, "secretSalt", "Invalid secret salt length", NULL, pubKey, encKeySt, saltStr, outSt);
        }
        memcpy(outSt->secretSalt, saltStr, secretSaltLen);
        outSt->secretSalt[KEYISO_SECRET_SALT_STR_BASE64_LEN - 1] = '\0';
        outSt->algVersion = encKeySt->algVersion;
        outSt->saltLen = encKeySt->saltLen;
        outSt->ivLen = encKeySt->ivLen;
        outSt->hmacLen = encKeySt->hmacLen; 
        outSt->encKeyLen = encKeySt->encKeyLen;
        memcpy(outSt->generateRsaKeyBytes, encKeySt->encryptedKeyBytes, encKeyLen);

        outSt->rsaModulusLen = pubKey->rsaModulusLen;
        outSt->rsaPublicExpLen = pubKey->rsaPublicExpLen;
        memcpy(outSt->generateRsaKeyBytes + encKeyLen, pubKey->rsaPubKeyBytes, pubKeyLen);    
    }
    
    *outLen = structSize; // initialize the outLen to the struct size for the case of no encoding (inproc)
    uint8_t *outBuf = KeyIso_service_adapter_generic_msg_postprocessing(IpcCommand_GenerateRsaKeyPair, outSt, outLen); 

    return _cleanup_response_key_generate(STATUS_OK, "", "", outBuf, pubKey, encKeySt, saltStr, outSt);
}

static unsigned char* _rsa_key_generate_failure(KEYISO_GEN_RSA_KEY_PAIR_IN_ST *inSt, size_t *encodedOutLen, const char *loc, const char *errorStr)
{
    const uint8_t *correlationId = inSt ? inSt->headerSt.correlationId : NULL;
    KEYISOP_trace_log_error(correlationId, 0, KEYISOP_SERVICE_TITLE, loc, errorStr);
    KeyIso_service_adapter_generic_msg_cleanup(inSt, 0, true);
    return _create_response_rsa_key_generate(IpcCommand_GenerateRsaKeyPair, encodedOutLen, STATUS_FAILED, NULL, NULL, NULL);
}

unsigned char* KeyIso_handle_msg_rsa_key_generate(const uint8_t *inSt, size_t inLen, size_t *outLen) 
{
    //1. Performing pre-processing
    void *genRsaKeyPairInSt_v = NULL;
    KEYISO_GEN_RSA_KEY_PAIR_IN_ST *genRsaKeyPairInSt = NULL;    
    
    int status = KeyIso_service_adapter_generic_msg_preprocessing(IpcCommand_GenerateRsaKeyPair, inSt, inLen, &genRsaKeyPairInSt_v);
    if (status != STATUS_OK) {
        return _rsa_key_generate_failure(genRsaKeyPairInSt, outLen, "KeyIso_service_adapter_generic_msg_preprocessing", "failed");
    }

    genRsaKeyPairInSt = (KEYISO_GEN_RSA_KEY_PAIR_IN_ST *)genRsaKeyPairInSt_v;

    //2. Send to the service for the actual handling
    void* outEncryptedPkey = NULL;
    KEYISO_RSA_PUBLIC_KEY_ST* outPubKey = NULL;
    char* outSalt = NULL;
 
    status = KeyIso_SERVER_generate_rsa_key_pair(genRsaKeyPairInSt->headerSt.correlationId, genRsaKeyPairInSt->bits, genRsaKeyPairInSt->keyUsage, &outPubKey, &outEncryptedPkey, &outSalt);
    if (status != STATUS_OK)
        return _rsa_key_generate_failure(genRsaKeyPairInSt, outLen, "KeyIso_SERVER_generate_key_pair", "failed");

    //3. Cleanup
    KeyIso_service_adapter_generic_msg_cleanup(genRsaKeyPairInSt, 0, true);

    //4. Create response
    return _create_response_rsa_key_generate(IpcCommand_GenerateRsaKeyPair, outLen, STATUS_OK, (KEYISO_RSA_PUBLIC_KEY_ST*) outPubKey, (KEYISO_ENCRYPTED_PRIV_KEY_ST *)outEncryptedPkey, outSalt);
}


// EC functions 
static unsigned char* _create_response_ec_key_generate(IpcCommand command, size_t *outLen, int ret, KEYISO_EC_PUBLIC_KEY_ST *pubKey, KEYISO_ENCRYPTED_PRIV_KEY_ST *encKeySt, char *saltStr)
{
    if (!outLen)
        return NULL;
    *outLen = 0; 

    size_t encKeyLen = 0;
    size_t pubKeyLen = 0;    

    if (ret == STATUS_OK) {
        encKeyLen = ((encKeySt != NULL) ? encKeySt->saltLen + encKeySt->ivLen + encKeySt->hmacLen + encKeySt->encKeyLen : 0);
        pubKeyLen = pubKey->ecPubKeyLen;
    }

    size_t structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_GEN_EC_KEY_PAIR_OUT_ST, encKeyLen + pubKeyLen);
    KEYISO_GEN_EC_KEY_PAIR_OUT_ST* outSt = (KEYISO_GEN_EC_KEY_PAIR_OUT_ST *)KeyIso_zalloc(structSize);
    if (outSt == NULL)
        return _cleanup_response_key_generate(STATUS_FAILED, "KeyIso_zalloc", "Invalid allocation", NULL, pubKey, encKeySt, saltStr, NULL);
      
    outSt->headerSt.result = ret;
    outSt->headerSt.command = command;

    if (ret == STATUS_OK) {
        size_t secretSaltLen = strlen(saltStr);
        if (secretSaltLen >= KEYISO_SECRET_SALT_STR_BASE64_LEN) {
            return _cleanup_response_key_generate(STATUS_FAILED, "secretSalt", "Invalid secret salt length", NULL, pubKey, encKeySt, saltStr, outSt);
        }
        memcpy(outSt->secretSalt, saltStr, secretSaltLen);
        outSt->secretSalt[KEYISO_SECRET_SALT_STR_BASE64_LEN - 1] = '\0';
        outSt->algVersion = encKeySt->algVersion;
        outSt->saltLen = encKeySt->saltLen;
        outSt->ivLen = encKeySt->ivLen;
        outSt->hmacLen = encKeySt->hmacLen; 
        outSt->encKeyLen = encKeySt->encKeyLen;
        memcpy(outSt->generateEcKeyBytes, encKeySt->encryptedKeyBytes, encKeyLen);
        outSt->ecCurve = pubKey->ecCurve;
        outSt->ecPubKeyLen = pubKey->ecPubKeyLen;

        memcpy(outSt->generateEcKeyBytes + encKeyLen, pubKey->ecPubKeyBytes, pubKeyLen);
    } 
    
    *outLen = structSize; // initialize the outLen to the struct size for the case of no encoding (inproc)
    uint8_t *outBuf = KeyIso_service_adapter_generic_msg_postprocessing(IpcCommand_GenerateEcKeyPair, outSt, outLen); 
    
    return _cleanup_response_key_generate(STATUS_OK, "", "", outBuf, pubKey, encKeySt, saltStr, outSt);
}

static unsigned char* _ec_key_generate_failure(KEYISO_GEN_EC_KEY_PAIR_IN_ST *inSt, size_t *outLen, const char *loc, const char *errorStr)
{
    const uint8_t *correlationId = inSt ? inSt->headerSt.correlationId : NULL;
    KEYISOP_trace_log_error(correlationId, 0, KEYISOP_SERVICE_TITLE, loc, errorStr);
    KeyIso_service_adapter_generic_msg_cleanup(inSt, 0, true);
    return _create_response_ec_key_generate(IpcCommand_GenerateEcKeyPair, outLen, STATUS_FAILED, NULL, NULL, NULL);
}

unsigned char* KeyIso_handle_msg_ec_key_generate(const uint8_t *inSt, size_t inLen, size_t *outLen) 
{
    //1. Performing pre-processing
    void *genEcKeyPairInSt_v = NULL;
    KEYISO_GEN_EC_KEY_PAIR_IN_ST *genEcKeyPairInSt = NULL;

    int status = KeyIso_service_adapter_generic_msg_preprocessing(IpcCommand_GenerateEcKeyPair, inSt, inLen, &genEcKeyPairInSt_v);
    if (status != STATUS_OK) {
        return _ec_key_generate_failure(genEcKeyPairInSt, outLen, "KeyIso_service_adapter_generic_msg_preprocessing", "failed");
    }

    genEcKeyPairInSt = (KEYISO_GEN_EC_KEY_PAIR_IN_ST *)genEcKeyPairInSt_v;

    //2. Send to the service for the actual handling
    void* outEncryptedPkey = NULL;
    KEYISO_EC_PUBLIC_KEY_ST* outPubKey = NULL;
    char* outSalt = NULL;
 
   status = KeyIso_SERVER_generate_ec_key_pair(genEcKeyPairInSt->headerSt.correlationId, genEcKeyPairInSt->curve, genEcKeyPairInSt->keyUsage, &outPubKey, &outEncryptedPkey, &outSalt);
    if (status != STATUS_OK)
        return _ec_key_generate_failure(genEcKeyPairInSt, outLen, "KeyIso_SERVER_generate_key_pair", "failed");

    //3. Cleanup
    KeyIso_service_adapter_generic_msg_cleanup(genEcKeyPairInSt, 0, true);

    //4. Create response
    return _create_response_ec_key_generate(IpcCommand_GenerateEcKeyPair, outLen, STATUS_OK, outPubKey, (KEYISO_ENCRYPTED_PRIV_KEY_ST *)outEncryptedPkey, outSalt);
}

//////////////////////////
/*     Open key         */
//////////////////////////

static unsigned char* _create_response_open_private_key(IpcCommand command, size_t *outLen, int ret, uint64_t keyId)
{
    if (outLen == NULL) {
        KEYISOP_trace_log_error(0, 0, KEYISOP_OPEN_KEY_TITLE, "_create_response_open_private_key", "Invalid outLen");
        return NULL;
    } 
    
    *outLen = 0; 
    KEYISO_OPEN_PRIV_KEY_OUT_ST* outSt = (KEYISO_OPEN_PRIV_KEY_OUT_ST *)KeyIso_zalloc(sizeof(KEYISO_OPEN_PRIV_KEY_OUT_ST));
    if (outSt == NULL) {        
        return NULL;
    }
    outSt->headerSt.result = ret;
    outSt->headerSt.command = command;
    outSt->keyId = keyId;
    
    *outLen = sizeof(KEYISO_OPEN_PRIV_KEY_OUT_ST); // initialize the outLen to the struct size for the case of no encoding (inproc)
    uint8_t *outBuf = KeyIso_service_adapter_generic_msg_postprocessing(command, outSt, outLen);
    
    KeyIso_service_adapter_generic_msg_cleanup(outSt, 0, false);
    
    return outBuf;
}

static unsigned char* _open_key_failure(KEYISO_OPEN_PRIV_KEY_IN_ST *inSt, size_t *outLen, const char *loc, const char *errorStr)
{
    const uint8_t *correlationId = inSt ? inSt->headerSt.correlationId : NULL;
    KEYISOP_trace_log_error(correlationId, 0, KEYISOP_SERVICE_TITLE, loc, errorStr);
    KeyIso_service_adapter_generic_msg_cleanup(inSt, 0, true);
    return _create_response_open_private_key(IpcCommand_OpenPrivateKey, outLen, STATUS_FAILED, 0);
}

unsigned char* KeyIso_handle_msg_open_private_key(const char *sender, const uint8_t *inSt, size_t inLen, size_t *outLen) 
{
    //Performing pre-processing    
    void *openKeyInSt_v = NULL;
    KEYISO_OPEN_PRIV_KEY_IN_ST *openKeyInSt = NULL;

    // Check that pfx size doesn't exceed the maximum
    if (inLen > KMPP_MAX_MESSAGE_SIZE) {
        return _open_key_failure(openKeyInSt, outLen, "Incoming buffer of encrypted key is too big", "failed");
    }

    int status = KeyIso_service_adapter_generic_msg_preprocessing(IpcCommand_OpenPrivateKey, inSt, inLen, &openKeyInSt_v);
    if (status != STATUS_OK) {
        return _open_key_failure(openKeyInSt, outLen, "KeyIso_service_adapter_generic_msg_preprocessing", "failed");
    }

    openKeyInSt = (KEYISO_OPEN_PRIV_KEY_IN_ST *)openKeyInSt_v;
    PKMPP_KEY outPkey = NULL;  
    uint64_t keyId = _open_encrypted_key(openKeyInSt->headerSt.correlationId, (char*)openKeyInSt->secretSalt, &openKeyInSt->encKeySt, sender, &outPkey);
    if (keyId == 0)
        return _open_key_failure(openKeyInSt, outLen, "_open_encrypted_key", "keyId is 0");

    // General information printing    
    KEYISOP_trace_log_para(openKeyInSt->headerSt.correlationId, 0, KEYISOP_SERVICE_TITLE, "Open private key general info", "sender: %s, keyId: 0x%016llx", sender, keyId);

    //Cleanup
    KeyIso_SERVER_free_key(openKeyInSt->headerSt.correlationId, outPkey);
    KeyIso_service_adapter_generic_msg_cleanup(openKeyInSt, 0, true);    
    
    //Create response
    return  _create_response_open_private_key(IpcCommand_OpenPrivateKey, outLen, STATUS_OK, keyId);   
}