/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <string.h>

#include "keyisoclientmsghandler.h"
#include "keyisoipcclientadapter.h"
#include "keyisoipccommands.h"
#include "keyisoipcserializeapi.h"
#include "keyisoclientinternal.h"

#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisoutils.h"

#include "keyisoserviceinprocmsghandler.h"  // in-proc


#include "kmppopteeutils.h"

int verboseFlag = KEY_VERBOSITY_FLAG ? KEYISOP_TRACELOG_VERBOSE_FLAG : 0;

//////////////////////////////////////////////////////////////////////////////////////
//
// Define the process-based implementation of the msg handler functions
//
//////////////////////////////////////////////////////////////////////////////////////
CLIENT_MSG_HANDLER_FUNCTIONS_TABLE_ST keyIsoMsgHandlerImplementation = {
    .init_key = KeyIso_client_msg_handler_init_key,
    .free_keyCtx = KeyIso_client_msg_handler_free_keyCtx,
    .close_key = KeyIso_client_msg_close_key,
    .rsa_private_encrypt_decrypt = KeyIso_client_msg_rsa_private_encrypt_decrypt,
    .ecdsa_sign = KeyIso_client_msg_ecdsa_sign, 
    .import_symmetric_key = KeyIso_client_msg_import_symmetric_key,
    .symmetric_key_encrypt_decrypt = KeyIso_client_msg_symmetric_key_encrypt_decrypt,
    .import_private_key = KeyIso_client_msg_import_private_key,
    .generate_rsa_key_pair = KeyIso_client_msg_generate_rsa_key_pair,
    .generate_ec_key_pair = KeyIso_client_msg_generate_ec_key_pair,
    .set_config = KeyIso_client_set_config
};

//////////////////////////
/*  IN-PROC functions   */
//////////////////////////
IPC_REPLY_ST* KeyIso_send_ipc(KEYISO_KEY_CTX *keyCtx, IPC_SEND_RECEIVE_ST *ipcSt, int *result, bool isPermanentSessionRequired)
{
    size_t outLen = 0;
    const char* sender = "inProcSender";
    unsigned char *response = KeyIso_inproc_handle_client_message(ipcSt->command, sender, ipcSt->inSt, ipcSt->inLen, &outLen);
    if ((response == NULL) || (outLen == 0)) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_IPC_CLIENT_TITLE, "Complete", "KeyIso_gdbus_handle_client_message");
        return NULL;
    }

    // The following log allow us validate the estimated length for each structure
    size_t estimateOutLen = KeyIso_get_estimate_out_len(ipcSt->command, ipcSt);
    KEYISOP_trace_log_para(keyCtx->correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_IPC_CLIENT_TITLE, "in-proc", "outLen: %d. estimateOutLen: %d", outLen, estimateOutLen);
    if (outLen != estimateOutLen) {
        // The outLen does not match the estimateOutLen, most of the times this is an error while running the in-proc handler.
        // However, in some cases, the estimated length is larger than the actual out length.
        // For example, in ECDSA sign, the calculation of the dynamic length may not match the actual length since the calculation takes
        // the maximum possible value using ECDSA_size().
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_IPC_CLIENT_TITLE, "in-proc", "outLen does not match estimateOutLen");
        if (outLen > estimateOutLen) {
            // The estimateOutLen is smaller than the outLen, this is an error.
            KEYISOP_trace_log_error_para(keyCtx->correlationId, 0, KEYISOP_IPC_CLIENT_TITLE, "in-proc", "outLen is smaller than estimateOutLen", "outLen: %d, estimateOutLen: %d", outLen, estimateOutLen);
            *result = IPC_FAILURE;
            KeyIso_free(response);
            return NULL;
        }
    }

    IPC_REPLY_ST *reply = (IPC_REPLY_ST *)KeyIso_zalloc(sizeof(IPC_REPLY_ST) + outLen);
    if (reply == NULL) {
        *result = IPC_FAILURE;        
    } else {
        reply->command = ipcSt->command;
        reply->outLen = outLen;
        reply->outSt = (uint8_t *)KeyIso_zalloc(reply->outLen);
        memcpy(reply->outSt, response, reply->outLen);           
    }

    KeyIso_free(response);
    return reply;
}
//////////////////////////
/*  Internal functions  */
//////////////////////////

// Some of the IPC commands do not require a permanent session.
static bool _is_key_session_required(IpcCommand command) 
{
    if (command == IpcCommand_ImportRsaPrivateKey ||
        command == IpcCommand_ImportEcPrivateKey ||
        command == IpcCommand_GenerateRsaKeyPair || 
        command == IpcCommand_GenerateEcKeyPair ||
        command == IpcCommand_ImportSymmetricKey)
        return false;
  
    return true;
}

static IPC_REPLY_ST* _create_and_send_generic_msg(KEYISO_KEY_CTX *keyCtx, int32_t command, uint32_t msgLen, uint8_t *msgBuf, int *result)
{
    IPC_SEND_RECEIVE_ST *ipcSt = (IPC_SEND_RECEIVE_ST *)KeyIso_zalloc(sizeof(IPC_SEND_RECEIVE_ST));
    if (ipcSt == NULL)
        return NULL;

    ipcSt->command = command;
    ipcSt->inLen = msgLen;
    ipcSt->inSt = msgBuf;
  
    *result = STATUS_OK;
    bool isPermanentSessionRequired =  _is_key_session_required(ipcSt->command);
    IPC_REPLY_ST *reply = (command == IpcCommand_OpenPrivateKey) ? KeyIso_client_adapter_send_open_ipc_and_key(keyCtx, ipcSt, result) :
                                                                   KeyIso_client_adapter_send_ipc(keyCtx, ipcSt, result, isPermanentSessionRequired);
    if (KeyIso_client_adapter_is_service_compatiblity_error(keyCtx, *result)) {
        // The key version determine the path of new or old API as old API do not support new key
        // If we are here, it means that the key is not compatible with the service
        // The key is new and the service does not support the new messages
        // The service was probably downgraded, there is a need to upgrade the service or re-import the key
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_GDBUS_CLIENT_TITLE, 
            "An attempt to send a new version message with an incompatible key",
            "The service was probably downgraded, please upgrade the service or re-import the key");
    }   
    KeyIso_free(ipcSt);
    return reply;
};

static IPC_REPLY_ST* _create_temp_key_ctx_and_send_msg(const uuid_t correlationId, int32_t command, int32_t msgLen, uint8_t *msgBuf, int *result)
{
    // Create dummy keyCtx
    KEYISO_KEY_CTX *keyCtx = (KEYISO_KEY_CTX *)KeyIso_zalloc(sizeof(KEYISO_KEY_CTX));
    if (keyCtx == NULL)
        return NULL;

    memcpy(keyCtx->correlationId, correlationId, CORRELATION_ID_LEN);
    IPC_REPLY_ST *reply = _create_and_send_generic_msg(keyCtx, command, msgLen, msgBuf, result);
    KeyIso_free(keyCtx);
    return reply; 
}

static bool _is_calc_len_equal_to_received_len(const uuid_t correlationId, uint32_t receivedLen, size_t outStLenCalculation, const char *title)
{   
    bool lensMatch = true;
    // Checking if the calculated length is equal to the received length
    if (outStLenCalculation != receivedLen) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "Invalid input", "calculated length is not equal to received length", "outStLenCalculation = %ld, receivedLen = %u", outStLenCalculation, receivedLen);        
        lensMatch = false;
    }
    return lensMatch;
}

// The following function will calculate the size to alloc for the serialized / encoded out struct (in case of GDBUS)
size_t KeyIso_safely_calc_encoded_out_st_alloc_size(const uuid_t correlationId, const uint8_t *encodedSt, size_t encodedLen,
                                         size_t (*serializeStructGetLenFunc)(const uint8_t *encodedSt, size_t encodedLen))
{       
    size_t sizeToAlloc = serializeStructGetLenFunc(encodedSt, encodedLen);

    // Checking for integer overflow or invalid input in the sizeToAlloc calculation
    if (sizeToAlloc == 0) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IPC_CLIENT_TITLE, "sizeToAlloc = 0", "reason: integer overflow or invalid input");        
    } else if(sizeToAlloc >= encodedLen) {     // The sizeToAlloc ("real" size) should be smaller than the size of the outSt (because outSt in this phase is the serialized struct)           
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IPC_CLIENT_TITLE, "sizeToAlloc = 0", "reason: sizeToAlloc >= encodedLen");                
        sizeToAlloc = 0; // Set the sizeToAlloc to 0 to indicate that the size is invalid.
    }

    return sizeToAlloc;
}

static void _fill_header(KEYISO_INPUT_HEADER_ST *header, IpcCommand command, const uuid_t correlationId)
{
    header->version = HEADER_VERSION;
    header->command = command;
    memcpy(header->correlationId, correlationId, CORRELATION_ID_LEN);
}

static void _fill_client_data(KEYISO_CLIENT_METADATA_HEADER_ST *header, KEYISO_CLIENT_DATA_ST *clientData)
{
    // Fill the data about the key 
    header->version = clientData->keyIdHeader.keyServiceVersion;
    header->isolationSolution = clientData->keyIdHeader.isolationSolution;
}

/////////////////////////////
/*   Encrypted key        */
////////////////////////////
static int _cleanup_encrypted_key_from_key_bytes(
    int ret,
    const char *loc,
    const char *err,
    const uuid_t correlationId,
    X509_SIG *p8)
{
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_OPEN_KEY_TITLE, loc, err);
    }
    X509_SIG_free(p8);
    
    return ret;
}

static int _get_opaque_key_from_key_ctx(const KEYISO_KEY_CTX *keyCtx, unsigned char **opaqueEncKey, uint32_t *opaqueEncKeyLen)
{
    // Convert pfxBytes to PKCS12 and parse to X509SIG (p8)
    X509_SIG* p8 = NULL;
    int ret = STATUS_FAILED;
    KEYISO_KEY_DETAILS* keyDetails = NULL;

    if (!opaqueEncKey || !opaqueEncKeyLen)
        return STATUS_FAILED;
    *opaqueEncKey = NULL;
    *opaqueEncKeyLen = 0;

    if (!keyCtx)
        return _cleanup_encrypted_key_from_key_bytes(ret, "keyCtx", "Invalid key context", NULL, p8);
    
    keyDetails = (KEYISO_KEY_DETAILS*)keyCtx->keyDetails;
    if (!keyDetails)
        return _cleanup_encrypted_key_from_key_bytes(ret, "keyDetails", "Invalid key details", keyCtx->correlationId, p8);

    ret = KeyIso_pkcs12_parse_p8(keyCtx->correlationId, keyDetails->keyLength, keyDetails->keyBytes, &p8, NULL, NULL);
    if (ret != STATUS_OK)
        return _cleanup_encrypted_key_from_key_bytes(ret, "p8", "PFX parsing failed", keyCtx->correlationId, p8);   
        
    // Convert to encrypted opaque key
    ret = KeyIso_create_enckey_from_p8((const X509_SIG *)p8, opaqueEncKeyLen, opaqueEncKey);
    if (ret != STATUS_OK)
        return _cleanup_encrypted_key_from_key_bytes(ret, "enckey", "Creation failed", keyCtx->correlationId, p8);

    return _cleanup_encrypted_key_from_key_bytes(ret, "", "", keyCtx->correlationId, p8);
}

//////////////////////////
/*  RSA Encrypt Decrypt */
//////////////////////////
static const char* _get_rsa_enc_dec_title(int value) {
    static const char* titles[] = {
        KEYISOP_RSA_ENCRYPT_TITLE,
        KEYISOP_RSA_DECRYPT_TITLE,
        KEYISOP_RSA_SIGN_TITLE,
        KEYISOP_PKEY_RSA_SIGN_TITLE
    };

    const int numTitles = sizeof(titles) / sizeof(titles[0]);
    return (value >= 0 && value < numTitles) ? titles[value] : KEYISOP_ENGINE_TITLE;    
}

static KEYISO_RSA_PRIVATE_ENC_DEC_IN_ST* _create_rsa_private_encrypt_decrypt_message(const KEYISO_KEY_CTX *keyCtx,
    int decrypt, int flen, const unsigned char *from, int tlen, int padding, int labelLen, size_t *structSize) 
{
    if (!structSize || !keyCtx || !from)
        return NULL;
    
    KEYISO_KEY_DETAILS* keyDetails = (KEYISO_KEY_DETAILS*)keyCtx->keyDetails;
    if (!keyDetails) {
        return NULL;
    }
    
    uint32_t dynamicLen = 0;
    if (KeyIso_get_rsa_enc_dec_params_dynamic_len(flen, labelLen, &dynamicLen) != STATUS_OK) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, _get_rsa_enc_dec_title(decrypt), "KeyIso_get_rsa_enc_dec_params_dynamic_len", "Failed to get dynamic length");
        return NULL;
    }
    *structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_RSA_PRIVATE_ENC_DEC_IN_ST, dynamicLen); 
    KEYISO_RSA_PRIVATE_ENC_DEC_IN_ST* inSt = (KEYISO_RSA_PRIVATE_ENC_DEC_IN_ST *)KeyIso_zalloc(*structSize);
    if (inSt == NULL)
        return NULL;    

    _fill_header(&inSt->headerSt, IpcCommand_RsaPrivateEncryptDecrypt, keyCtx->correlationId);
    
    inSt->keyId = keyDetails->keyId;
    KeyIso_fill_rsa_enc_dec_param(&inSt->params, decrypt, padding, tlen, flen, labelLen, from); 
    return inSt;
}

static uint8_t* _create_and_serialize_rsa_private_encrypt_decrypt_message(const KEYISO_KEY_CTX *keyCtx, int decrypt, 
    int flen, const unsigned char *from, int tlen, int padding, int labelLen, size_t *msgLen) 
{        
    if (!msgLen)
        return NULL;
    *msgLen = 0;

    //1. Create struct
    size_t structSize = 0;
    KEYISO_RSA_PRIVATE_ENC_DEC_IN_ST* inSt = _create_rsa_private_encrypt_decrypt_message(keyCtx, decrypt, flen, from, tlen, padding, labelLen, &structSize);
    if (inSt == NULL)
        return NULL;
         
    //2. Check if encoding is required by the IPC
    bool isEncodingRequired = KeyIso_client_adapter_is_encoding();
    if (!isEncodingRequired) {
        *msgLen = structSize;
        return (uint8_t*) inSt;
    }  
    
    //3. serialize struct
    uint8_t *msgBuf = KeyIso_serialize_rsa_enc_dec_in(inSt, msgLen);
    
    //4. Free origin struct
    KeyIso_free(inSt);
    return msgBuf;
}

// Checking if the non serialized rsa_private_enc_dec out structure is valid (this will be activated when encoding is not needed)
bool KeyIso_is_valid_rsa_private_enc_dec_out_structure(const uuid_t correlationId, const KEYISO_RSA_PRIVATE_ENC_DEC_OUT_ST *outSt, uint32_t receivedLen) 
{
    // Checking if bytesLen value is negative 
    if (outSt->bytesLen < 0) {
        KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_RSA_ENCRYPT_TITLE, "Invalid input", "outSt->bytesLen < 0", "outSt->bytesLen = %d", outSt->bytesLen);
        return false;
    }

    // Calculating the size of the out structure, when the dynamic array size equals to outSt->bytesLen
    size_t outStLenCalculation = GET_DYNAMIC_STRUCT_SIZE(KEYISO_RSA_PRIVATE_ENC_DEC_OUT_ST, outSt->bytesLen);

    // Checking if the calculated length is equal to the received length
    if (!_is_calc_len_equal_to_received_len(correlationId, receivedLen, outStLenCalculation, KEYISOP_RSA_ENCRYPT_TITLE)) {        
        return false;
    }

    return true;
}

bool KeyIso_is_valid_rsa_private_enc_dec_with_attached_key_out_structure(const uuid_t correlationId, const KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_OUT_ST *outSt, uint32_t receivedLen) 
{
    // Checking if bytesLen value is negative 
    if (outSt->bytesLen < 0) {
        KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_RSA_ENCRYPT_TITLE, "Invalid input", "outSt->bytesLen < 0", "outSt->bytesLen = %d", outSt->bytesLen);
        return false;
    }

    // Calculating the size of the out structure, when the dynamic array size equals to outSt->bytesLen
    size_t outStLenCalculation = GET_DYNAMIC_STRUCT_SIZE(KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_OUT_ST, outSt->bytesLen);
    // Checking if the calculated length is equal to the received length
    if (!_is_calc_len_equal_to_received_len(correlationId, receivedLen, outStLenCalculation, KEYISOP_RSA_ENCRYPT_TITLE)) {        
        return false;
    }
    
    return true;
}

static int _cp_if_valid(const uuid_t correlationId, uint8_t* toBytes, int32_t  bytesLen, unsigned char *to, int tlen)
{
    if (to && (bytesLen > 0) && (tlen >= bytesLen)) {
        memcpy(to, toBytes, bytesLen);
        return STATUS_OK;
    }
    KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_RSA_ENCRYPT_TITLE, "Invalid input", "result buff larger then expected", "output bytes len = %d, tlen = %d", bytesLen, tlen);
    return STATUS_FAILED;
}


// RSA Encrypt Decrypt with Encrypted Key
static KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_IN_ST* _cleanup_rsa_private_encrypt_decrypt_with_attached_key(
                                                                    unsigned char* opaqueEncKey,
                                                                    KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_IN_ST* inSt) {
    KeyIso_free(opaqueEncKey);
    return inSt;
}

#define _CLEANUP_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY(inSt) \
    _cleanup_rsa_private_encrypt_decrypt_with_attached_key(opaqueEncKey, inSt)

static KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_IN_ST* _create_rsa_private_encrypt_decrypt_with_attached_key_message(const KEYISO_KEY_CTX *keyCtx,
    int decrypt, int flen, const unsigned char *from, int tlen, int padding, int labelLen, size_t *totalStSize) 
{
    if (!totalStSize || !keyCtx || !from) {
        return NULL;
    }
    
    *totalStSize = 0;
    KEYISO_KEY_DETAILS* keyDetails = (KEYISO_KEY_DETAILS*)keyCtx->keyDetails;
    if (!keyDetails) {
        return NULL;
    }

    KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_IN_ST* inSt = NULL;
    unsigned char* opaqueEncKey = NULL;
    uint32_t opaqueEncKeyLen = 0;

    // Get the encrypted key bytes
    int result = _get_opaque_key_from_key_ctx(keyCtx, &opaqueEncKey, &opaqueEncKeyLen);
    if (result != STATUS_OK) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_RSA_ENCRYPT_TITLE, "_get_opaque_key_from_key_ctx failed", "Failed to get encrypted key from key bytes");
        return _CLEANUP_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY(NULL);
    }
    
    KEYISO_CLIENT_DATA_ST* clientData = (KEYISO_CLIENT_DATA_ST *)keyDetails->clientData;
    if (!clientData) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_RSA_ENCRYPT_TITLE, "Invalid client data", "");
        return _CLEANUP_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY(NULL);
    }

    uint32_t dynamicLen = 0;
    if (KeyIso_get_rsa_enc_dec_with_attached_key_in_dynamic_bytes_len(keyCtx->correlationId, clientData->pubKeyLen, opaqueEncKeyLen, flen, labelLen, &dynamicLen) != STATUS_OK) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_RSA_ENCRYPT_TITLE, "KeyIso_get_rsa_enc_dec_with_attached_key_in_dynamic_bytes_len failed", "Failed to get dynamic length");
        return _CLEANUP_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY(NULL);
    }

    size_t totalSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_IN_ST, dynamicLen);
    if (totalSize == 0) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_RSA_ENCRYPT_TITLE, "Invalid input", "Failed to calculate struct size");
        return _CLEANUP_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY(NULL);
    }
    inSt = (KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_IN_ST *)KeyIso_zalloc(totalSize);
    if (inSt == NULL) {
        // Memory allocation failed
        return _CLEANUP_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY(NULL);
    } 
    
    // Headers
    _fill_header(&inSt->headerSt, IpcCommand_RsaPrivateEncryptDecryptWithAttachedKey, keyCtx->correlationId);
    _fill_client_data(&inSt->clientDataHeader, clientData);

    // Fill the key details
    inSt->publicKeyLen = clientData->pubKeyLen;
    inSt->opaqueEncryptedKeyLen = opaqueEncKeyLen;

    // Fill crypto operation details
    inSt->decrypt = decrypt;
    inSt->padding = padding;
    inSt->tlen = tlen;
    inSt->fromBytesLen = flen;
    inSt->labelLen = labelLen;

    // Copy the encrypted key and the data to be decrypted
    uint32_t offset = 0;
    if (clientData->pubKeyLen > 0) {
        memcpy(inSt->data + offset, clientData->pubKeyBytes, clientData->pubKeyLen);
        offset += clientData->pubKeyLen;
    }
    if (opaqueEncKeyLen > 0) {
        memcpy(inSt->data + offset, opaqueEncKey, opaqueEncKeyLen);
        offset += opaqueEncKeyLen;
    }
    if (flen > 0) {
        memcpy(inSt->data + offset, from, flen);
        offset += flen;
    }
    if (labelLen > 0) {
        memcpy(inSt->data + offset, from, labelLen);
    }
    
    *totalStSize = totalSize;
    return _CLEANUP_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY(inSt);
}

static uint8_t* _create_and_serialize_rsa_private_encrypt_decrypt_with_attached_key_message(const KEYISO_KEY_CTX *keyCtx,
    int decrypt, int flen, const unsigned char *from, int tlen, int padding, int labelLen, size_t *msgLen) 
{        
    if (!msgLen)
        return NULL;
    *msgLen = 0;

    //1. Create struct
    size_t structSize = 0;
    KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_IN_ST* inSt = _create_rsa_private_encrypt_decrypt_with_attached_key_message(keyCtx, decrypt, flen, from, tlen, padding, labelLen, &structSize);
    if (inSt == NULL)
        return NULL;
 
    //2. Check if encoding is required by the IPC
    bool isEncodingRequired = KeyIso_client_adapter_is_encoding();
    if (!isEncodingRequired) {
        *msgLen = structSize;
        return (uint8_t*) inSt;
    }  
    
    //3. serialize struct
    uint8_t *msgBuf = KeyIso_serialize_rsa_enc_dec_with_attached_key_in(inSt, msgLen);
    
    //4. Free origin struct
    KeyIso_free(inSt);
    return msgBuf;
}

static int _handle_rsa_private_encrypt_decrypt_message_with_attached_key(KEYISO_KEY_CTX *keyCtx, int decrypt, 
    int flen, const unsigned char *from, int tlen, unsigned char *to, int padding, int labelLen)
{
    //1. Create the structure and encode it
    size_t msgLen = 0;
    uint32_t command = IpcCommand_RsaPrivateEncryptDecryptWithAttachedKey;
    uint8_t *msgBuf = _create_and_serialize_rsa_private_encrypt_decrypt_with_attached_key_message(keyCtx, decrypt, flen, from, tlen, padding, labelLen, &msgLen);
             
    //2. Send to the server as a generic message
    int result;
    IPC_REPLY_ST *reply = _create_and_send_generic_msg(keyCtx, command, msgLen, msgBuf, &result);    
    KeyIso_clear_free(msgBuf, msgLen);

    int actualLen = 0;
    KEYISO_KEY_DETAILS *keyDetails = (KEYISO_KEY_DETAILS*)keyCtx->keyDetails;
    if (!keyDetails) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_RSA_ENCRYPT_TITLE, "keyDetails", "Invalid key details");
        return actualLen;
    }

    //3. Deserialize response (if needed) and return relevant fields
    if (reply) {
        if (result == STATUS_OK) {
            KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_OUT_ST *outSt = NULL;
            bool isEncodingRequired = KeyIso_client_adapter_is_encoding();        
            if (!isEncodingRequired) {
                outSt = (KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_OUT_ST*)reply->outSt;
                if (outSt && outSt->headerSt.result == STATUS_OK && KeyIso_is_valid_rsa_private_enc_dec_with_attached_key_out_structure(keyCtx->correlationId, outSt, reply->outLen)) {
                    if (_cp_if_valid(keyCtx->correlationId, outSt->toBytes, outSt->bytesLen, to, tlen) == STATUS_OK) {
                        actualLen = outSt->bytesLen;
                    }
                }
             } else {
                size_t sizeToAlloc = KeyIso_safely_calc_encoded_out_st_alloc_size(keyCtx->correlationId, reply->outSt, reply->outLen, KeyIso_get_len_rsa_enc_dec_with_attached_key_out);            
                // Checking if the sizeToAlloc is valid. sizeToAlloc == 0 means that the size is invalid.
                if (sizeToAlloc > 0) {
                    outSt = (KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_OUT_ST *)KeyIso_zalloc(sizeToAlloc);
                    if (outSt != NULL) {
                        result = KeyIso_deserialize_rsa_enc_dec_with_attached_key_out(reply->outSt, reply->outLen, outSt);
                        if (result == STATUS_OK) {
                            keyDetails->keyId = outSt->keyId;
                            if (_cp_if_valid(keyCtx->correlationId, outSt->toBytes, outSt->bytesLen, to, tlen) == STATUS_OK) {
                                actualLen = outSt->bytesLen;
                            }
                        }
                        KeyIso_free(outSt);
                    }
                }
            }       
            KeyIso_free(reply->outSt);
        }
        KeyIso_free(reply);
    }
    return actualLen;
}


static int _handle_rsa_private_encrypt_decrypt_message(KEYISO_KEY_CTX *keyCtx, int decrypt, int flen,
    const unsigned char *from, int tlen, unsigned char *to, int padding, int labelLen)
{   
    //1. Create the structure and encode it
    size_t msgLen = 0;
    const uint32_t command = IpcCommand_RsaPrivateEncryptDecrypt;
    uint8_t *msgBuf = _create_and_serialize_rsa_private_encrypt_decrypt_message(keyCtx, decrypt, flen, from, tlen, padding, labelLen, &msgLen);
   
    //2. Send to the server as a generic message
    int result;
    IPC_REPLY_ST *reply = _create_and_send_generic_msg(keyCtx, command, msgLen, msgBuf, &result);    
    KeyIso_clear_free(msgBuf, msgLen);       
    
    
    //3. Deserialize response (if needed) and return relevant fields
    int actualLen = 0;
    if (reply && result == STATUS_OK) {
        KEYISO_RSA_PRIVATE_ENC_DEC_OUT_ST *outSt = NULL;
        bool isEncodingRequired = KeyIso_client_adapter_is_encoding();        
        if (!isEncodingRequired) {
            outSt = (KEYISO_RSA_PRIVATE_ENC_DEC_OUT_ST*)reply->outSt;
            if (outSt && (outSt->headerSt.result == STATUS_OK) && KeyIso_is_valid_rsa_private_enc_dec_out_structure(keyCtx->correlationId, outSt, reply->outLen)) {
                if (_cp_if_valid(keyCtx->correlationId, outSt->toBytes, outSt->bytesLen, to, tlen) == STATUS_OK) {
                    actualLen = outSt->bytesLen;
                }
            }  
        } else {            
            size_t sizeToAlloc = KeyIso_safely_calc_encoded_out_st_alloc_size(keyCtx->correlationId, reply->outSt, reply->outLen, KeyIso_get_len_rsa_enc_dec_out);            
            // Checking if the sizeToAlloc is valid. sizeToAlloc == 0 means that the size is invalid.
            if (sizeToAlloc > 0) {
                outSt = (KEYISO_RSA_PRIVATE_ENC_DEC_OUT_ST *)KeyIso_zalloc(sizeToAlloc);
                if (outSt != NULL) {
                    result = KeyIso_deserialize_rsa_enc_dec_out(reply->outSt, reply->outLen, outSt);
                    if (result == STATUS_OK) {
                        if (outSt->headerSt.result == STATUS_NOT_FOUND) {
                            // Print log
                            KEYISOP_trace_log(keyCtx->correlationId, 0, KEYISOP_RSA_ENCRYPT_TITLE, "STATUS_NOT_FOUND - key was not found, probably evicted. Resending crypto operation with attached key");
                            KeyIso_free(outSt);
                            KeyIso_free(reply->outSt);
                            KeyIso_free(reply);
                            return _handle_rsa_private_encrypt_decrypt_message_with_attached_key(keyCtx, decrypt, flen, from, tlen, to, padding, labelLen);

                        } else if (_cp_if_valid(keyCtx->correlationId, outSt->toBytes, outSt->bytesLen, to, tlen) == STATUS_OK) {                            
                            actualLen = outSt->bytesLen;
                        }
                    }
                    KeyIso_free(outSt);
                }
            }            
        }
        KeyIso_free(reply->outSt);
        KeyIso_free(reply);
    }

    return actualLen;
}


//////////////////////////
/*  ECDSA Sign         */
//////////////////////////
static KEYISO_ECDSA_SIGN_IN_ST* _create_ecdsa_sign_message(const KEYISO_KEY_CTX *keyCtx, int type, const unsigned char *dgst, int dlen, unsigned int sigLen, size_t *structSize)
{   
    if (!structSize || !keyCtx)
        return NULL;
    
    KEYISO_KEY_DETAILS* keyDetails = (KEYISO_KEY_DETAILS*)keyCtx->keyDetails;
    if (!keyDetails) {
        return NULL;
    }
    
    // calculate the struct size
    *structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_ECDSA_SIGN_IN_ST, dlen);
    KEYISO_ECDSA_SIGN_IN_ST* inSt = (KEYISO_ECDSA_SIGN_IN_ST *)KeyIso_zalloc(*structSize);
    if (inSt == NULL) {
        *structSize = 0;
        return NULL;
    }

    _fill_header(&inSt->headerSt, IpcCommand_EcdsaSign, keyCtx->correlationId);

    inSt->keyId = keyDetails->keyId;
    inSt->params.type = type;
    inSt->params.sigLen = sigLen;
    inSt->params.digestLen = dlen;
    memcpy(inSt->params.digestBytes, dgst, dlen);
  
    return inSt;
}

static KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_IN_ST* _cleanup_ecdsa_sign_with_attached_key(
    unsigned char* opaqueEncKey,
    KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_IN_ST* inSt)
{
    KeyIso_free(opaqueEncKey);
    return inSt;
}

#define _CLEANUP_ECDSA_SIGN_WITH_ATTACHED_KEY(inSt) \
    _cleanup_ecdsa_sign_with_attached_key(opaqueEncKey, inSt)

static KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_IN_ST* _create_ecdsa_sign_with_attached_key_message(const KEYISO_KEY_CTX *keyCtx,
    int type, const unsigned char *dgst, int dlen, unsigned int sigLen, size_t *structSize)
{   
    if (!structSize || !keyCtx)
        return NULL;
    
    KEYISO_KEY_DETAILS* keyDetails = (KEYISO_KEY_DETAILS*)keyCtx->keyDetails;
    if (!keyDetails) {
        return NULL;
    }
    
    const char* title = KEYISOP_ECC_SIGN_TITLE;
    unsigned char *opaqueEncKey = NULL;
    KEYISO_CLIENT_DATA_ST* clientData = NULL;
    KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_IN_ST* inSt = NULL;
    
    // Get the encrypted key from the key bytes
    uint32_t opaqueEncKeyLen = 0;
    int result = _get_opaque_key_from_key_ctx(keyCtx, &opaqueEncKey, &opaqueEncKeyLen);
    if (result != STATUS_OK) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, title, "_get_opaque_key_from_key_ctx failed", "Failed to get encrypted key from key bytes");
        return _CLEANUP_ECDSA_SIGN_WITH_ATTACHED_KEY(NULL);
    } 

    clientData = (KEYISO_CLIENT_DATA_ST *)keyDetails->clientData;
    if (!clientData) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_RSA_ENCRYPT_TITLE, "Invalid client data", "");
        return _CLEANUP_ECDSA_SIGN_WITH_ATTACHED_KEY(NULL); 
    }

    // Calculate the struct size
    uint32_t dynamicLen = 0;
    if (KeyIso_get_ecdsa_sign_with_attached_key_in_dynamic_bytes_len(keyCtx->correlationId, clientData->pubKeyLen, opaqueEncKeyLen, dlen, &dynamicLen) != STATUS_OK) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, title, "KeyIso_get_ecdsa_sign_with_attached_key_in_dynamic_bytes_len failed", "Failed to get dynamic length");
        return _CLEANUP_ECDSA_SIGN_WITH_ATTACHED_KEY(NULL);
    }

    size_t totalSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_IN_ST, dynamicLen);
    *structSize = totalSize;
    if (totalSize == 0) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, title, "Invalid input", "Failed to calculate struct size");
        return _CLEANUP_ECDSA_SIGN_WITH_ATTACHED_KEY(NULL);
    }
    
    inSt = (KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_IN_ST *)KeyIso_zalloc(*structSize);
    if (inSt == NULL) {
        *structSize = 0;
        return _CLEANUP_ECDSA_SIGN_WITH_ATTACHED_KEY(NULL);
    }

    // Fill the headers
    _fill_header(&inSt->headerSt, IpcCommand_EcdsaSignWithAttachedKey, keyCtx->correlationId);
    _fill_client_data(&inSt->clientDataHeader, clientData);

    // Fill the key details
    inSt->publicKeyLen = clientData->pubKeyLen;
    inSt->opaqueEncryptedKeyLen = opaqueEncKeyLen;

    // Fill crypto operation details
    inSt->type = type;
    inSt->sigLen = sigLen;
    inSt->digestLen = dlen;
    
    // Copy components in order: pubkey, enckey, digest
    uint32_t offset = 0;
    if (clientData->pubKeyLen > 0) {
        memcpy(inSt->data + offset, clientData->pubKeyBytes, clientData->pubKeyLen);
        offset += clientData->pubKeyLen;
    }
    
    if (opaqueEncKeyLen > 0) {
        memcpy(inSt->data + offset, opaqueEncKey, opaqueEncKeyLen);
        offset += opaqueEncKeyLen;
    }
    
    if (dlen > 0) {
        memcpy(inSt->data + offset, dgst, dlen);
        offset += dlen;
    }
    
    return _CLEANUP_ECDSA_SIGN_WITH_ATTACHED_KEY(inSt);
}

static uint8_t* _create_and_serialize_ecdsa_sign_message(const KEYISO_KEY_CTX *keyCtx,
    int type, const unsigned char *dgst, int dlen, unsigned int sigLen, size_t *msgLen)
{   
    if (!msgLen)
        return NULL;
    *msgLen = 0; 

    //1. Create struct
    size_t structSize = 0;
    KEYISO_ECDSA_SIGN_IN_ST* inSt = _create_ecdsa_sign_message(keyCtx, type, dgst, dlen, sigLen, &structSize);
    if (inSt == NULL)
        return NULL;

    //2. Check if encoding is required by the IPC
    bool isEncodingRequired = KeyIso_client_adapter_is_encoding(); 
    if (!isEncodingRequired) {
        *msgLen = structSize;
        return (uint8_t*) inSt;
    }

    //3. Encode struct
    uint8_t *msgBuf = KeyIso_serialize_ecdsa_sign_in(inSt, msgLen);
  
    //4. Free origin struct
    KeyIso_free(inSt);
    return msgBuf;
}

static uint8_t* _create_and_serialize_ecdsa_sign_with_attached_key_message(const KEYISO_KEY_CTX *keyCtx,
    int type, const unsigned char *dgst, int dlen, unsigned int sigLen, size_t *msgLen)
{   
    if (!msgLen)
        return NULL;
    *msgLen = 0; 

    //1. Create struct
    size_t structSize = 0;
    KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_IN_ST* inSt = _create_ecdsa_sign_with_attached_key_message(keyCtx, type, dgst, dlen, sigLen, &structSize);
    if (inSt == NULL)
        return NULL;

    //2. Check if encoding is required by the IPC
    bool isEncodingRequired = KeyIso_client_adapter_is_encoding(); 
    if (!isEncodingRequired) {
        *msgLen = structSize;
        return (uint8_t*) inSt;
    }

    //3. Encode struct
    uint8_t *msgBuf = KeyIso_serialize_ecdsa_sign_with_attached_key_in(inSt, msgLen);
  
    //4. Free origin struct
    KeyIso_free(inSt);
    return msgBuf;
}

// Checking if the non serialized ecdsa_sign out structure is valid (this will be activated when encoding is not needed)
bool KeyIso_is_valid_ecdsa_sign_out_structure(const uuid_t correlationId, const KEYISO_ECDSA_SIGN_OUT_ST *outSt, uint32_t receivedLen, uint32_t command) 
{
    // Checking if bytesLen value is negative 
    if (outSt->bytesLen < 0) {
        KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_ECC_SIGN_TITLE, "Invalid input", "outSt->bytesLen < 0", "outSt->bytesLen = %d", outSt->bytesLen);
        return false;
    }
    
    // Calculating the size of the out structure, when the dynamic array size equals to outSt->bytesLen
    size_t outStLenCalculation = GET_DYNAMIC_STRUCT_SIZE(KEYISO_ECDSA_SIGN_OUT_ST, outSt->bytesLen);
    
    // Checking if the calculated length is equal to the received length
    if (!_is_calc_len_equal_to_received_len(correlationId, receivedLen, outStLenCalculation, KEYISOP_ECC_SIGN_TITLE)) {        
        return false;
    }

    return true;
}

bool KeyIso_is_valid_ecdsa_sign_with_attached_key_out_structure(const uuid_t correlationId, const KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_OUT_ST *outSt, uint32_t receivedLen) 
{

    // Checking if bytesLen value is negative 
    if (outSt->bytesLen < 0) {
        KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_ECC_SIGN_TITLE, "Invalid input", "outSt->bytesLen < 0", "outSt->bytesLen = %d", outSt->bytesLen);
        return false;
    }
    
    // Calculating the size of the out structure, when the dynamic array size equals to outSt->bytesLen
    size_t outStLenCalculation = GET_DYNAMIC_STRUCT_SIZE(KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_OUT_ST, outSt->bytesLen);
    
    // Checking if the calculated length is equal to the received length
    if (!_is_calc_len_equal_to_received_len(correlationId, receivedLen, outStLenCalculation, KEYISOP_ECC_SIGN_TITLE)) {        
        return false;
    }

    return true;
}

static int _handle_ecdsa_sign_with_attached_key(KEYISO_KEY_CTX *keyCtx, int type, const unsigned char *dgst, int dlen, unsigned char *sig, unsigned int sigLen, unsigned int *outlen)
{
    if (!outlen)
        return STATUS_FAILED;
    *outlen = 0;

    //1. Create the structure and encode it (if needed)
    size_t msgLen = 0;
    uint8_t *msgBuf = _create_and_serialize_ecdsa_sign_with_attached_key_message(keyCtx, type, dgst, dlen, sigLen, &msgLen);

    //2. Send to the server as a generic message
    int result = STATUS_FAILED;
    uint32_t command = IpcCommand_EcdsaSignWithAttachedKey;
    IPC_REPLY_ST *reply = _create_and_send_generic_msg(keyCtx, command, msgLen, msgBuf, &result);    
    KeyIso_free(msgBuf);
    
    //3. Deserialize response (if needed) and return relevant fields
    if (reply && (result == STATUS_OK)) {
        KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_OUT_ST *outSt = NULL;
        bool isEncodingRequired = KeyIso_client_adapter_is_encoding();
        if (!isEncodingRequired) {
            outSt = (KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_OUT_ST*)reply->outSt;
            if (outSt && outSt->headerSt.result == STATUS_OK && KeyIso_is_valid_ecdsa_sign_with_attached_key_out_structure(keyCtx->correlationId, outSt, reply->outLen)) {
                memcpy(sig, outSt->signatureBytes, outSt->bytesLen);
                *outlen = outSt->bytesLen;
            } else {
                result = STATUS_FAILED;
            }
        } else {
            size_t sizeToAlloc = KeyIso_safely_calc_encoded_out_st_alloc_size(keyCtx->correlationId, reply->outSt, reply->outLen, KeyIso_get_len_ecdsa_sign_with_attached_key_out);            
            // Checking if the sizeToAlloc is valid. sizeToAlloc == 0 means that the size is invalid.
            if (sizeToAlloc > 0) {
                outSt = (KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_OUT_ST*)KeyIso_zalloc(sizeToAlloc);
                if (outSt != NULL) {
                    result = KeyIso_deserialize_ecdsa_sign_with_attached_key_out(reply->outSt, reply->outLen, outSt);
                    if (result == STATUS_OK) {
                        memcpy(sig, outSt->signatureBytes, outSt->bytesLen);
                        *outlen = outSt->bytesLen;
                    }
                    result &= outSt->headerSt.result;
                    KeyIso_free(outSt);
                } else {
                    result = STATUS_FAILED;
                }
            } else {
                result = STATUS_FAILED;
            }
        }
        KeyIso_free(reply->outSt);
        KeyIso_free(reply);
    }
    return result;
}

static int _handle_ecdsa_sign_message(KEYISO_KEY_CTX *keyCtx, int type, const unsigned char *dgst, int dlen, unsigned char *sig, unsigned int sigLen, unsigned int *outlen)
{   
    if (!outlen)
        return STATUS_FAILED;
    *outlen = 0;

    //1. Create the structure and encode it (if needed)
    size_t msgLen = 0;
    uint8_t *msgBuf = _create_and_serialize_ecdsa_sign_message(keyCtx, type, dgst, dlen, sigLen, &msgLen);

    //2. Send to the server as a generic message
    int result = STATUS_FAILED;
    uint32_t command = IpcCommand_EcdsaSignWithAttachedKey;

    IPC_REPLY_ST *reply = _create_and_send_generic_msg(keyCtx, IpcCommand_EcdsaSign, msgLen, msgBuf, &result);    
    KeyIso_free(msgBuf);

    //3. Deserialize response (if needed) and return relevant fields
    if (reply && (result == STATUS_OK)) {
        KEYISO_ECDSA_SIGN_OUT_ST *outSt = NULL;
        bool isEncodingRequired = KeyIso_client_adapter_is_encoding();
        if (!isEncodingRequired) {
            outSt = (KEYISO_ECDSA_SIGN_OUT_ST*)reply->outSt;
            if (outSt && outSt->headerSt.result == STATUS_OK && KeyIso_is_valid_ecdsa_sign_out_structure(keyCtx->correlationId, outSt, reply->outLen, command)) {
                memcpy(sig, outSt->signatureBytes, outSt->bytesLen);
                *outlen = outSt->bytesLen;
            } else {
                result = STATUS_FAILED;
            }
        } else {
            size_t sizeToAlloc = KeyIso_safely_calc_encoded_out_st_alloc_size(keyCtx->correlationId, reply->outSt, reply->outLen, KeyIso_get_len_ecdsa_sign_out);            
            // Checking if the sizeToAlloc is valid. sizeToAlloc == 0 means that the size is invalid.
            if (sizeToAlloc > 0) {
                outSt = (KEYISO_ECDSA_SIGN_OUT_ST*)KeyIso_zalloc(sizeToAlloc);
                if (outSt != NULL) {
                    result = KeyIso_deserialize_ecdsa_sign_out(reply->outSt, reply->outLen, outSt);
                    if (result == STATUS_OK) {
                         if (outSt->headerSt.result == STATUS_NOT_FOUND) {
                            // Print log
                            KEYISOP_trace_log(keyCtx->correlationId, 0, KEYISOP_RSA_ENCRYPT_TITLE, "STATUS_NOT_FOUND - key was not found, probably evicted. Resending ecdsa sign operation with attached key");
                            KeyIso_free(outSt);
                            KeyIso_free(reply->outSt);
                            KeyIso_free(reply);
                            return _handle_ecdsa_sign_with_attached_key(keyCtx, type, dgst, dlen, sig, sigLen, outlen);
                        } else if (sig && (outSt->bytesLen > 0) && (sigLen >= outSt->bytesLen)) {
                            memcpy(sig, outSt->signatureBytes, outSt->bytesLen);
                            *outlen = outSt->bytesLen;
                        }
                        result &= outSt->headerSt.result;
                    } else {
                        result = STATUS_FAILED;
                    }
                    KeyIso_free(outSt);
                } else {
                    result = STATUS_FAILED;
                }
            }
        }
        KeyIso_free(reply->outSt);
        KeyIso_free(reply);
    }
    return result;
}

//////////////////////////
/*    Close key         */
//////////////////////////

static KEYISO_CLOSE_KEY_IN_ST* _create_close_key_message(const KEYISO_KEY_CTX *keyCtx, size_t *structSize)
{  
    if (!keyCtx || !structSize)
        return NULL;

    KEYISO_KEY_DETAILS* keyDetails = (KEYISO_KEY_DETAILS*)keyCtx->keyDetails;
    if (!keyDetails) {
        return NULL;
    }

    *structSize = sizeof(KEYISO_CLOSE_KEY_IN_ST);
    KEYISO_CLOSE_KEY_IN_ST* inSt = (KEYISO_CLOSE_KEY_IN_ST *)KeyIso_zalloc(*structSize);
    if (inSt == NULL) {
        *structSize = 0;
        return NULL;
    }

    _fill_header(&inSt->headerSt, IpcCommand_CloseKey, keyCtx->correlationId);
    
    inSt->keyId = keyDetails->keyId;
    return inSt;
}

static uint8_t* _create_and_serialize_close_key_message(const KEYISO_KEY_CTX *keyCtx, size_t *msgLen)
{   
    if (!msgLen)
        return NULL;
    *msgLen = 0;
    
    //1. Create struct
    size_t structSize = 0;
    KEYISO_CLOSE_KEY_IN_ST* inSt = _create_close_key_message(keyCtx, &structSize);
    if (inSt == NULL)
        return NULL;

    //2. Check if encoding is required by the IPC
    bool isEncodingRequired = KeyIso_client_adapter_is_encoding(); 
    if (!isEncodingRequired) {
        *msgLen = structSize;
        return (uint8_t*) inSt;
    }

    //3. Encode struct
    uint8_t *msgBuf = KeyIso_serialize_close_key_in(inSt, msgLen);

    //4. Free origin struct
    KeyIso_free(inSt);
    return msgBuf;
}

static size_t _get_len_close_key_out(const uint8_t *encodedSt, size_t encodedLen)
{
    return sizeof(KEYISO_CLOSE_KEY_OUT_ST);
}

static void _handle_close_key_message(KEYISO_KEY_CTX *keyCtx)
{
    // We first check if the connection was established with the service before sending the close message
    // When loading a key, we only open it on the client side and initialize the data 
    // The connection with the service is being established on the first crypto operation  
    if (KeyIso_client_adapter_is_connection(keyCtx) || KEYISOP_inProc) {
        //1. Create the structure and encode it (if needed)
        size_t msgLen = 0;
        uint8_t *msgBuf = _create_and_serialize_close_key_message(keyCtx, &msgLen);
        
        //2. Send to the server as a generic message
        int result;
        IPC_REPLY_ST *reply = _create_and_send_generic_msg(keyCtx, IpcCommand_CloseKey, msgLen, msgBuf, &result);    
        KeyIso_free(msgBuf);

        //3. Deserialize response (if needed) and return relevant fields
        if (reply && (result == STATUS_OK)) {
            bool isEncodingRequired = KeyIso_client_adapter_is_encoding();
            if (isEncodingRequired) {
                size_t sizeToAlloc = KeyIso_safely_calc_encoded_out_st_alloc_size(keyCtx->correlationId, reply->outSt, reply->outLen, _get_len_close_key_out);
                // Checking if the sizeToAlloc is valid. sizeToAlloc == 0 means that the size is invalid.
                if (sizeToAlloc > 0) {
                    KEYISO_CLOSE_KEY_OUT_ST *outSt = (KEYISO_CLOSE_KEY_OUT_ST *)KeyIso_zalloc(sizeToAlloc);
                    if (outSt != NULL) {
                        KeyIso_deserialize_close_key_out(reply->outSt, reply->outLen, outSt);   
                        KeyIso_free(outSt);        
                    }  
                }
            }
            KeyIso_free(reply->outSt);
            KeyIso_free(reply);
        }
    } else {
        KEYISOP_trace_log(keyCtx->correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_CLOSE_PFX_TITLE, "Close key command received, but connection with the service was not established; no operation needed");
    }

    //4. Close ipc
    KeyIso_client_adapter_free_keyCtx(keyCtx);

    KEYISOP_trace_log(keyCtx->correlationId, verboseFlag, KEYISOP_CLOSE_PFX_TITLE, "Close key command received");
}


//////////////////////////
/*  Import private key  */
//////////////////////////
#define _CLEANUP_COPY_ENCRYPTED_KEY_AND_CLIENT_DATA(ret, loc, message) \
    _cleanup_copy_encrypted_key_and_client_data(correlationId, ret, loc, message, pEncKeySt, clientData)

// RSA functions
static KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST* _create_rsa_import_key_message(const uuid_t correlationId, KEYISO_RSA_PKEY_ST *rsaPrivateKey, size_t *structSize)
{
    uint32_t keyLen = 0;
    if (KeyIso_get_rsa_pkey_bytes_len(rsaPrivateKey, &keyLen) != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "Invalid input", "Failed to get rsa pkey bytes length");
        return NULL;
    }
    
    if (!structSize)
        return NULL;
    *structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST, keyLen);
    
    KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST* inSt = (KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST*)KeyIso_zalloc(*structSize); // KeyIso_clear_free()
    if (inSt == NULL) {
        *structSize = 0;
        return NULL;
    }
    
    _fill_header(&inSt->headerSt, IpcCommand_ImportRsaPrivateKey, correlationId);
    
    inSt->pkeySt.rsaUsage = rsaPrivateKey->rsaUsage;
    inSt->pkeySt.rsaModulusLen = rsaPrivateKey->rsaModulusLen;
    inSt->pkeySt.rsaPublicExpLen = rsaPrivateKey->rsaPublicExpLen;
    inSt->pkeySt.rsaPrimes1Len = rsaPrivateKey->rsaPrimes1Len;
    inSt->pkeySt.rsaPrimes2Len = rsaPrivateKey->rsaPrimes2Len;
    inSt->pkeySt.header = rsaPrivateKey->header;
    memcpy(& inSt->pkeySt.rsaPkeyBytes, rsaPrivateKey->rsaPkeyBytes, keyLen);

    return inSt;
}

static uint8_t* _create_and_serialize_rsa_import_key_message(const uuid_t correlationId, KEYISO_RSA_PKEY_ST *rsaPrivateKey, size_t *msgLen)
{    
    if (!msgLen)
        return NULL;
    *msgLen = 0;

    //1. Create struct
    size_t structSize = 0;
    KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST* inSt = _create_rsa_import_key_message(correlationId, rsaPrivateKey, &structSize);
    if (inSt == NULL)
        return NULL;

    //2. Check if encoding is required by the IPC
    bool isEncodingRequired = KeyIso_client_adapter_is_encoding(); 
    if (!isEncodingRequired) {
        *msgLen = structSize;
        return (uint8_t*) inSt;
    }

    //3. Encode struct
    uint8_t *msgBuf = KeyIso_serialize_import_rsa_priv_key_in(inSt, msgLen); 
    KeyIso_clear_free(inSt, structSize);  // Free origin struct
    return msgBuf;
}

// Checking if the non serialized import out structure is valid (this will be activated when encoding is not needed)
bool KeyIso_is_valid_import_priv_key_out_structure(const uuid_t correlationId, const KEYISO_IMPORT_PRIV_KEY_OUT_ST* outSt, uint32_t receivedLen)
{
    // Checking for integer overflow in the out structure dynamic array
    uint32_t dynamicArrayLen = outSt->opaqueEncryptedKeyLen + outSt->publicKeyLen;
    if(dynamicArrayLen > 0 && dynamicArrayLen <= KMPP_MAX_MESSAGE_SIZE) {
        // Calculating the size of the out structure, where the dynamic array is already calculated in the above step
        size_t outStLenCalculation = GET_DYNAMIC_STRUCT_SIZE(KEYISO_IMPORT_PRIV_KEY_OUT_ST, dynamicArrayLen);

        // Checking if the calculated length is equal to the received length
        if (!_is_calc_len_equal_to_received_len(correlationId, receivedLen, outStLenCalculation, KEYISOP_IMPORT_KEY_TITLE)) {
            return false;
        }
    } else {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "Invalid input", "dynamicArrayLen is invalid");
        return false;
    }

    return true;
}

static int _copy_data(KEYISO_IMPORT_PRIV_KEY_OUT_ST *outSt, unsigned char **opaqueEncryptedKey, unsigned int *opaqueEncryptedKeyLen, KEYISO_CLIENT_DATA_ST** outClientData)
{
    if (outSt == NULL || opaqueEncryptedKey == NULL || opaqueEncryptedKeyLen == NULL || outClientData == NULL) {
        return STATUS_FAILED;
    }
    *outClientData = NULL;
    *opaqueEncryptedKey = NULL;
    *opaqueEncryptedKeyLen = 0;


    // Copy the client data
    uint8_t *pubkeyBytes = (outSt->publicKeyLen > 0) ? outSt->data : NULL;
    int ret = KeyIso_copy_client_data(NULL, outSt->headerSt.version, outSt->headerSt.isolationSolution, outSt->publicKeyLen, pubkeyBytes, outClientData);
    if (ret != STATUS_OK) {
        KeyIso_free(*opaqueEncryptedKey);
        *opaqueEncryptedKey = NULL;
        *opaqueEncryptedKeyLen = 0;
    }

    // Copy the opaque encrypted key
    if (outSt->opaqueEncryptedKeyLen > 0) {
        *opaqueEncryptedKeyLen = outSt->opaqueEncryptedKeyLen;
        *opaqueEncryptedKey = (unsigned char *)KeyIso_zalloc(*opaqueEncryptedKeyLen);
        if (*opaqueEncryptedKey == NULL) {
            *opaqueEncryptedKeyLen = 0;
            return STATUS_FAILED;
        }
        memcpy(*opaqueEncryptedKey, outSt->data + outSt->publicKeyLen, *opaqueEncryptedKeyLen);
    }

    return ret;
}

static int _handle_rsa_import_private_key_message(const uuid_t correlationId, KEYISO_RSA_PKEY_ST *rsaPrivateKey, KEYISO_CLIENT_DATA_ST **outClientData, unsigned int *opaqueEncryptedKeyLen, unsigned char **opaqueEncryptedKey) 
{
    //1. Create the structure and encode it (if needed)
    size_t msgLen = 0;
    uint8_t *msgBuf = _create_and_serialize_rsa_import_key_message(correlationId, rsaPrivateKey, &msgLen);

    //2. Send to the server as a generic message
    int result = STATUS_FAILED;
    IPC_REPLY_ST *reply = _create_temp_key_ctx_and_send_msg(correlationId, IpcCommand_ImportRsaPrivateKey, msgLen, msgBuf, &result);
    KeyIso_clear_free(msgBuf, msgLen);

    //3. Deserialize response and return relevant fields
    *outClientData = NULL;
    *opaqueEncryptedKey = NULL;
    *opaqueEncryptedKeyLen = 0;

    if (reply && (result == STATUS_OK)) {
        KEYISO_IMPORT_PRIV_KEY_OUT_ST* outSt = NULL;
        bool isEncodingRequired = KeyIso_client_adapter_is_encoding(); 
        if (!isEncodingRequired) {
            outSt = (KEYISO_IMPORT_PRIV_KEY_OUT_ST*)reply->outSt;
            if (outSt && (outSt->headerSt.result == STATUS_OK) && KeyIso_is_valid_import_priv_key_out_structure(correlationId, outSt, reply->outLen))
                result = _copy_data(outSt, opaqueEncryptedKey, opaqueEncryptedKeyLen, outClientData);
            else
                result = STATUS_FAILED;
        } else {
            size_t sizeToAlloc = KeyIso_safely_calc_encoded_out_st_alloc_size(correlationId, reply->outSt, reply->outLen, KeyIso_get_len_import_priv_key_out);            
            // Checking if the sizeToAlloc is valid. sizeToAlloc == 0 means that the size is invalid.
            if (sizeToAlloc > 0) {
                outSt = (KEYISO_IMPORT_PRIV_KEY_OUT_ST*)KeyIso_zalloc(sizeToAlloc); // KeyIso_clear_free()
                if (outSt != NULL) {
                    result = KeyIso_deserialize_import_rsa_priv_key_out(reply->outSt, reply->outLen, outSt);
                    if (result == STATUS_OK && outSt->headerSt.result == STATUS_OK)
                        result = _copy_data(outSt, opaqueEncryptedKey, opaqueEncryptedKeyLen, outClientData);
                    else
                        result = STATUS_FAILED;
                    KeyIso_clear_free(outSt, sizeToAlloc);
                } else {
                    result = STATUS_FAILED;
                }
            } else {
                result = STATUS_FAILED;
            }            
        }

        KeyIso_clear_free(reply->outSt, reply->outLen);
        KeyIso_free(reply);
    }

    return result;
}


// EC functions
static KEYISO_IMPORT_EC_PRIV_KEY_IN_ST* _create_ec_import_key_message(const uuid_t correlationId, KEYISO_EC_PKEY_ST *ecPrivateKey, size_t *structSize) 
{
    uint32_t keyLen = 0;
    if (KeyIso_get_ec_pkey_bytes_len(ecPrivateKey, &keyLen) != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "Invalid input", "Failed to get ec pkey bytes length");
        return NULL;
    }
    
    if (!structSize)
        return NULL;
    *structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_IMPORT_EC_PRIV_KEY_IN_ST, keyLen);

    KEYISO_IMPORT_EC_PRIV_KEY_IN_ST* inSt = (KEYISO_IMPORT_EC_PRIV_KEY_IN_ST*)KeyIso_zalloc(*structSize); // KeyIso_clear_free()
    if (inSt == NULL) {
        *structSize = 0;
        return NULL;
    }

    _fill_header(&inSt->headerSt, IpcCommand_ImportEcPrivateKey, correlationId);
    inSt->pkeySt.ecUsage = ecPrivateKey->ecUsage;
    inSt->pkeySt.ecCurve = ecPrivateKey->ecCurve;
    inSt->pkeySt.ecPubXLen = ecPrivateKey->ecPubXLen;
    inSt->pkeySt.ecPubYLen = ecPrivateKey->ecPubYLen;
    inSt->pkeySt.ecPrivKeyLen = ecPrivateKey->ecPrivKeyLen;
    inSt->pkeySt.header = ecPrivateKey->header;
    memcpy(& inSt->pkeySt.ecKeyBytes, ecPrivateKey->ecKeyBytes, keyLen);

    return inSt;
}

static uint8_t* _create_and_serialize_ec_import_key_message(const uuid_t correlationId, KEYISO_EC_PKEY_ST *ecPrivateKey, size_t *msgLen) 
{  
    if (!msgLen)
        return NULL;
    *msgLen = 0;

    //1. Create struct
    size_t structSize = 0;
    KEYISO_IMPORT_EC_PRIV_KEY_IN_ST* inSt = _create_ec_import_key_message(correlationId, ecPrivateKey, &structSize);
    if (inSt == NULL)
        return NULL;

    //2. Check if encoding is required by the IPC
    bool isEncodingRequired = KeyIso_client_adapter_is_encoding(); 
    if (!isEncodingRequired) {
        *msgLen = structSize;
        return (uint8_t*) inSt;
    }

    //3. Encode struct
    uint8_t *msgBuf = KeyIso_serialize_import_ec_priv_key_in(inSt, msgLen); 
    KeyIso_clear_free(inSt, structSize);  // Free origin struct
    return msgBuf;
}

static int _handle_ec_import_private_key_message(const uuid_t correlationId, KEYISO_EC_PKEY_ST *ecPrivateKey, KEYISO_CLIENT_DATA_ST **outClientData, unsigned int *opaqueEncryptedKeyLen, unsigned char **opaqueEncryptedKey)
    
{
    //1. Create the structure and encode it (if needed)
    size_t msgLen = 0;
    uint8_t *msgBuf = _create_and_serialize_ec_import_key_message(correlationId, ecPrivateKey, &msgLen); //KeyIso_clear_free

    //2. Send to the server as a generic message
    int result = STATUS_FAILED;
    IPC_REPLY_ST *reply = _create_temp_key_ctx_and_send_msg(correlationId, IpcCommand_ImportEcPrivateKey, msgLen, msgBuf, &result);
    KeyIso_clear_free(msgBuf, msgLen);

    //3. Deserialize response (if needed) and return relevant fields
    *outClientData = NULL;
    *opaqueEncryptedKey = NULL;
    *opaqueEncryptedKeyLen = 0;

    if (reply && (result == STATUS_OK)) {
        KEYISO_IMPORT_PRIV_KEY_OUT_ST *outSt = NULL;
        bool isEncodingRequired = KeyIso_client_adapter_is_encoding();
        if (!isEncodingRequired) {
            outSt = (KEYISO_IMPORT_PRIV_KEY_OUT_ST*)reply->outSt;
            if (outSt && (outSt->headerSt.result == STATUS_OK) && KeyIso_is_valid_import_priv_key_out_structure(correlationId, outSt, reply->outLen))
                result = _copy_data(outSt, opaqueEncryptedKey, opaqueEncryptedKeyLen, outClientData);
            else
                result = STATUS_FAILED;
        } else {
            size_t sizeToAlloc = KeyIso_safely_calc_encoded_out_st_alloc_size(correlationId, reply->outSt, reply->outLen, KeyIso_get_len_import_priv_key_out);            
            // Checking if the sizeToAlloc is valid. sizeToAlloc == 0 means that the size is invalid.
            if (sizeToAlloc > 0) {
                outSt = (KEYISO_IMPORT_PRIV_KEY_OUT_ST*)KeyIso_zalloc(sizeToAlloc); // KeyIso_clear_free()
                if (outSt != NULL) {
                    result = KeyIso_deserialize_import_ec_priv_key_out(reply->outSt, reply->outLen, outSt);
                    if (result == STATUS_OK && outSt->headerSt.result == STATUS_OK)
                        result = _copy_data(outSt, opaqueEncryptedKey, opaqueEncryptedKeyLen, outClientData);
                    else
                        result = STATUS_FAILED;
                    KeyIso_clear_free(outSt, sizeToAlloc);
                } else {
                    result = STATUS_FAILED;
                }
            } else {
                result = STATUS_FAILED;
            }
        }

        KeyIso_clear_free(reply->outSt, reply->outLen);
        KeyIso_free(reply);
    }
    return result;
}

//////////////////////////
/*  Generate key pair   */
////////////////////////// 

// RSA functions
static int _copy_rsa_key_generate_values(
	const uuid_t correlationId,
    const KEYISO_GEN_RSA_KEY_PAIR_OUT_ST *decodedOutSt,
    EVP_PKEY **outPubKey,
    X509_SIG **outEncKey,
    KEYISO_CLIENT_METADATA_HEADER_ST *outMetaData)
{
    if (!decodedOutSt || !outPubKey || !outEncKey || !outMetaData) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_GEN_KEY_TITLE, "Invalid input", "NULL parameter");
        return STATUS_FAILED;
    }
    *outPubKey = NULL;
    *outEncKey = NULL;

    EVP_PKEY *pkey = NULL;
    int ret = STATUS_FAILED;

    // Get modulus and public exponent from output struct
    const uint8_t *n = decodedOutSt->data;  // modulus is first
    const uint8_t *e = n + decodedOutSt->rsaModulusLen; // public exponent follows

    if ((pkey = KeyIso_get_rsa_evp_pub_key(correlationId, n, decodedOutSt->rsaModulusLen, e, decodedOutSt->rsaPublicExpLen)) == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_GEN_KEY_TITLE, "Failed to create RSA public key", "Invalid modulus or public exponent");
        return STATUS_FAILED;
    }
   
    // Update client meta data
    outMetaData->version = decodedOutSt->headerSt.version;
    outMetaData->isolationSolution = decodedOutSt->headerSt.isolationSolution;

    // Copy opaque key data
    uint32_t opaqueKeyOffset = 0;
    if (decodedOutSt->opaqueEncryptedKeyLen > 0 && !KEYISO_ADD_OVERFLOW(decodedOutSt->rsaModulusLen, decodedOutSt->rsaPublicExpLen, &opaqueKeyOffset)) {
        ret = KeyIso_create_pkcs8_enckey(decodedOutSt->opaqueEncryptedKeyLen, (const unsigned char *)decodedOutSt->data + opaqueKeyOffset, outEncKey);
    }

    if (ret != STATUS_OK) {
        EVP_PKEY_free(pkey);
        *outPubKey = NULL;
    } else {
        // Assign the output public key
        *outPubKey = pkey;
    }

    return ret;
}

static KEYISO_GEN_RSA_KEY_PAIR_IN_ST* _create_rsa_generate_key_message(const uuid_t correlationId, unsigned int rsaBits, uint8_t keyUsage, size_t *structSize)
{
    if (!structSize)
        return NULL;
    
    *structSize = sizeof(KEYISO_GEN_RSA_KEY_PAIR_IN_ST);
    KEYISO_GEN_RSA_KEY_PAIR_IN_ST* inSt = (KEYISO_GEN_RSA_KEY_PAIR_IN_ST*)KeyIso_zalloc(*structSize);
    if (inSt == NULL) {
        *structSize = 0;
        return NULL;
    }

    _fill_header(&inSt->headerSt, IpcCommand_GenerateRsaKeyPair, correlationId);

    inSt->bits = rsaBits;
    inSt->keyUsage = keyUsage;
    return inSt;
}

static uint8_t* _create_and_serialize_rsa_generate_key_message(const uuid_t correlationId, unsigned int rsaBits, uint8_t keyUsage, size_t *msgLen)
{
    if (!msgLen)
        return NULL;
    *msgLen = 0;

    //1. Create struct
    size_t structSize = 0;
    KEYISO_GEN_RSA_KEY_PAIR_IN_ST* inSt = _create_rsa_generate_key_message(correlationId, rsaBits, keyUsage, &structSize);
    if (inSt == NULL)
        return NULL;

    //2. Check if encoding is required by the IPC
    bool isEncodingRequired = KeyIso_client_adapter_is_encoding(); 
    if (!isEncodingRequired) {
        *msgLen = structSize;
        return (uint8_t*) inSt;
    }

    //3. Encode struct (if needed)
    uint8_t *msgBuf = KeyIso_serialize_gen_rsa_key_pair_in(inSt, msgLen);
  
    //4. Free origin struct
    KeyIso_free(inSt);
    return msgBuf;
}

// Checking if the non serialized gen_rsa_key_pair out structure is valid (this will be activated when encoding is not needed)
bool KeyIso_is_valid_gen_rsa_key_pair_out_structure(const uuid_t correlationId, const KEYISO_GEN_RSA_KEY_PAIR_OUT_ST* outSt, uint32_t receivedLen)
{    
    // Checking for integer overflow in the out structure dynamic array
    uint32_t dynamicArrayLen = 0;
    if(!KEYISO_ADD_OVERFLOW(outSt->rsaModulusLen, outSt->rsaPublicExpLen, &dynamicArrayLen) &&
       !KEYISO_ADD_OVERFLOW(dynamicArrayLen, outSt->opaqueEncryptedKeyLen, &dynamicArrayLen)) {

        // Calculating the size of the out structure, where the dynamic array is already calculated in the above step
        size_t outStLenCalculation = GET_DYNAMIC_STRUCT_SIZE(KEYISO_GEN_RSA_KEY_PAIR_OUT_ST, dynamicArrayLen);

        // Checking if the calculated length is equal to the received length
        if (!_is_calc_len_equal_to_received_len(correlationId, receivedLen, outStLenCalculation, KEYISOP_GEN_KEY_TITLE)) {
            return false;
        }
    } else {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_GEN_KEY_TITLE, "KEYISO_ADD_OVERFLOW", "Integer overflow");
        return false;
    }

    return true;
}

static int _handle_rsa_generate_key_pair_message(const uuid_t correlationId,unsigned int rsaBits, uint8_t keyUsage, 
                                                EVP_PKEY** outPubKey, X509_SIG** outEncryptedPkey, KEYISO_CLIENT_METADATA_HEADER_ST *outMetaData)
{
    //1. Create the structure and encode it (if needed)
    size_t msgLen = 0;
    uint8_t *msgBuf = _create_and_serialize_rsa_generate_key_message(correlationId, rsaBits, keyUsage, &msgLen);

    //2. Send to the server as a generic message
    int result = STATUS_FAILED;
    IPC_REPLY_ST *reply = _create_temp_key_ctx_and_send_msg(correlationId, IpcCommand_GenerateRsaKeyPair, msgLen, msgBuf, &result);
    KeyIso_free(msgBuf);

    //3. Deserialize response (if needed) and return relevant fields
    *outPubKey = NULL;
    *outEncryptedPkey = NULL;

    if (reply && (result == STATUS_OK)) {
        KEYISO_GEN_RSA_KEY_PAIR_OUT_ST *outSt = NULL;
        bool isEncodingRequired = KeyIso_client_adapter_is_encoding();
        if (!isEncodingRequired) {
            outSt = (KEYISO_GEN_RSA_KEY_PAIR_OUT_ST*)reply->outSt;
            if (outSt && outSt->headerSt.result == STATUS_OK && KeyIso_is_valid_gen_rsa_key_pair_out_structure(correlationId, outSt, reply->outLen))
                result = _copy_rsa_key_generate_values(correlationId, outSt, outPubKey, outEncryptedPkey, outMetaData);
            else
                result = STATUS_FAILED;
        } else {
            size_t sizeToAlloc = KeyIso_safely_calc_encoded_out_st_alloc_size(correlationId, reply->outSt, reply->outLen, KeyIso_get_len_gen_rsa_key_pair_out);
            // Checking if the sizeToAlloc is valid. sizeToAlloc == 0 means that the size is invalid.
            if (sizeToAlloc > 0) {
                outSt = (KEYISO_GEN_RSA_KEY_PAIR_OUT_ST*)KeyIso_zalloc(sizeToAlloc);
                if (outSt != NULL) {
                    result = KeyIso_deserialize_gen_rsa_key_pair_out(reply->outSt, reply->outLen, outSt);
                    if (result == STATUS_OK && outSt->headerSt.result == STATUS_OK)
                        result = _copy_rsa_key_generate_values(correlationId, outSt, outPubKey, outEncryptedPkey, outMetaData);
                    else
                        result = STATUS_FAILED;
                    KeyIso_free(outSt);
                } else {
                    result = STATUS_FAILED;
                }
            } else {
                result = STATUS_FAILED;
            }
        }       
        KeyIso_free(reply->outSt);
        KeyIso_free(reply);
    }
    return result;
}

// static int _cleanup_copy_ec_key_generate_values(const uuid_t correlationId, int result,
//                                                 const char* message, const char* loc,
//                                                 KEYISO_ENCRYPTED_PRIV_KEY_ST* encKey,
//                                                 char* salt, 
//                                                 X509_SIG* encKeyP8)
// {
//     if (result != STATUS_OK) {
//         KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, message, loc); 
//         KeyIso_clear_free_string(salt);
//         X509_SIG_free(encKeyP8);
//     }
//     KeyIso_free(encKey);
//     return result;
// }

/* #define _CLEANUP_COPY_EC_KEY_GENERATE_VALUES(result, message, loc) \
     _cleanup_copy_ec_key_generate_values(correlationId, result, message, loc, pEncKeySt, secretSalt, encKeyP8)*/

// EC functions
static int _copy_ec_key_generate_values(
    const uuid_t correlationId,
    const KEYISO_GEN_EC_KEY_PAIR_OUT_ST *outSt,
    EC_GROUP **outEcGroup,
    EC_KEY **outEcPubKey,
    X509_SIG **outEncKeyP8,
    KEYISO_CLIENT_METADATA_HEADER_ST *outMetaData)
{
    int ret = STATUS_FAILED;
    EC_KEY *ecKey = NULL;
    EC_GROUP *ecGroup = NULL;

    // Validate input
    if (!outSt || !outEcGroup || !outEcPubKey || !outEncKeyP8 || !outMetaData) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_GEN_KEY_TITLE, "Invalid input", "NULL parameter");
        return STATUS_FAILED;
    }
    *outEcGroup = NULL;
    *outEcPubKey = NULL;
    *outEncKeyP8 = NULL;

    // CB-CHANGES: Replace deprecated EC key handling in KeyIso_get_ec_evp_key by constructing EVP_PKEY directly from EC public key components.
    // Use KeyIso_create_ec_evp_pub_key instead, which is already implemented but currently disabled.

    // Getting outEcGroup and outEcPubKey using KeyIso_get_ec_evp_pub_key 
    if (KeyIso_get_ec_evp_key(correlationId, outSt->ecCurve, outSt->ecPubKeyLen, outSt->data, 0, NULL, &ecKey, &ecGroup) != STATUS_OK) {
        return STATUS_FAILED;
    }
    *outEcGroup = ecGroup;
    *outEcPubKey = ecKey;

    // Update client meta data
    outMetaData->version = outSt->headerSt.version;
    outMetaData->isolationSolution = outSt->headerSt.isolationSolution;

    // Copy opaque key data
    uint32_t opaqueKeyOffset = outSt->ecPubKeyLen;
    if (outSt->opaqueEncryptedKeyLen > 0) {
        ret = KeyIso_create_pkcs8_enckey(outSt->opaqueEncryptedKeyLen, (const unsigned char *)outSt->data + opaqueKeyOffset, outEncKeyP8);
    }

    if (ret != STATUS_OK) {
        // free allocated resources ?
        EC_KEY_free(*outEcPubKey);
        *outEcGroup = NULL;
        *outEcPubKey = NULL;
        *outEncKeyP8 = NULL;
    }

    return ret;
}

static KEYISO_GEN_EC_KEY_PAIR_IN_ST* _create_ec_generate_key_message(const uuid_t correlationId, unsigned int curve, uint8_t keyUsage, size_t *structSize)
{
    if (!structSize)
        return NULL;
    
    *structSize = sizeof(KEYISO_GEN_EC_KEY_PAIR_IN_ST);
    KEYISO_GEN_EC_KEY_PAIR_IN_ST* inSt = (KEYISO_GEN_EC_KEY_PAIR_IN_ST*)KeyIso_zalloc(*structSize);
    if (inSt == NULL) {
        *structSize = 0;
        return NULL;
    }

    _fill_header(&inSt->headerSt, IpcCommand_GenerateEcKeyPair, correlationId);
    
    inSt->curve = curve;
    inSt->keyUsage = keyUsage;

    return inSt;
}

static uint8_t* _create_and_serialize_ec_generate_key_message(const uuid_t correlationId, unsigned int curve, uint8_t keyUsage, size_t *msgLen)
{
    if (!msgLen)
        return NULL;
    *msgLen = 0;

    //1. Create struct
    size_t structSize = 0;
    KEYISO_GEN_EC_KEY_PAIR_IN_ST* inSt = _create_ec_generate_key_message(correlationId, curve, keyUsage, &structSize);
    if (inSt == NULL)
        return NULL;

    //2. Check if encoding is required by the IPC
    bool isEncodingRequired = KeyIso_client_adapter_is_encoding(); 
    if (!isEncodingRequired) {
        *msgLen = structSize;
        return (uint8_t*) inSt;
    }

    //3. Encode struct (if needed)
    uint8_t *msgBuf = KeyIso_serialize_gen_ec_key_pair_in(inSt, msgLen);

    //4. Free origin struct
    KeyIso_free(inSt);
    return msgBuf;
}

// Checking if the non serialized gen_ec_key_pair out structure is valid (this will be activated when encoding is not needed)
bool KeyIso_is_valid_gen_ec_key_pair_out_structure(const uuid_t correlationId, const KEYISO_GEN_EC_KEY_PAIR_OUT_ST* outSt, uint32_t receivedLen)
{    
    // Checking for integer overflow in the out structure dynamic array
    uint32_t dynamicArrayLen = 0;
    if(!KEYISO_ADD_OVERFLOW(outSt->ecPubKeyLen, outSt->opaqueEncryptedKeyLen, &dynamicArrayLen)) {
        
        // Calculating the size of the out structure, where the dynamic array is already calculated in the above step
        size_t outStLenCalculation = GET_DYNAMIC_STRUCT_SIZE(KEYISO_GEN_EC_KEY_PAIR_OUT_ST, dynamicArrayLen);

        // Checking if the calculated length is equal to the received length
        if (!_is_calc_len_equal_to_received_len(correlationId, receivedLen, outStLenCalculation, KEYISOP_GEN_KEY_TITLE)) {
            return false;
        }
    } else {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_GEN_KEY_TITLE, "KEYISO_ADD_OVERFLOW", "Integer overflow");
        return false;
    }

    return true;
}

static int _handle_ec_generate_key_pair_message(
    const uuid_t correlationId,
    unsigned int curve,
    uint8_t keyUsage, 
    EC_GROUP** outEcGroup,
    EC_KEY** outPubKey,
    X509_SIG** outEncryptedPkeyP8,
    KEYISO_CLIENT_METADATA_HEADER_ST *outMetaData)
{
    //1. Create the structure and encode it (if needed)
    size_t msgLen = 0;
    uint8_t *msgBuf = _create_and_serialize_ec_generate_key_message(correlationId, curve, keyUsage, &msgLen);    

    //2. Send to the server as a generic message
    int result = STATUS_FAILED;
    IPC_REPLY_ST *reply = _create_temp_key_ctx_and_send_msg(correlationId, IpcCommand_GenerateEcKeyPair, msgLen, msgBuf, &result);
    KeyIso_free(msgBuf);
    
    //3. Deserialize response (if needed) and return relevant fields
    *outPubKey = NULL;
    *outEncryptedPkeyP8 = NULL;

    if (reply && (result == STATUS_OK)) {
        KEYISO_GEN_EC_KEY_PAIR_OUT_ST* outSt = NULL;
        bool isEncodingRequired = KeyIso_client_adapter_is_encoding();
        if (!isEncodingRequired) {
            outSt = (KEYISO_GEN_EC_KEY_PAIR_OUT_ST*)reply->outSt;
            if (outSt && outSt->headerSt.result == STATUS_OK && KeyIso_is_valid_gen_ec_key_pair_out_structure(correlationId, outSt, reply->outLen)) {
                result = _copy_ec_key_generate_values(correlationId, outSt, outEcGroup, outPubKey, outEncryptedPkeyP8, outMetaData);                
            }                
            else
                result = STATUS_FAILED;
        } else {                        
            size_t sizeToAlloc = KeyIso_safely_calc_encoded_out_st_alloc_size(correlationId, reply->outSt, reply->outLen, KeyIso_get_len_gen_ec_key_pair_out);            
            // Checking if the sizeToAlloc is valid. sizeToAlloc == 0 means that the size is invalid.
            if (sizeToAlloc > 0) {
                outSt = (KEYISO_GEN_EC_KEY_PAIR_OUT_ST*)KeyIso_zalloc(sizeToAlloc);
                if (outSt != NULL) {
                    result = KeyIso_deserialize_gen_ec_key_pair_out(reply->outSt, reply->outLen, outSt);
                    if (result == STATUS_OK && outSt->headerSt.result == STATUS_OK)
                        result = _copy_ec_key_generate_values(correlationId, outSt, outEcGroup, outPubKey, outEncryptedPkeyP8, outMetaData);
                    else
                        result = STATUS_FAILED;
                    KeyIso_free(outSt);
                } else {
                    result = STATUS_FAILED;
                }
            } else {
                result = STATUS_FAILED;    
            }            
        }
        KeyIso_free(reply->outSt);
        KeyIso_free(reply);
    }
    return result;
}

//////////////////////////
/*     Open key         */
//////////////////////////

static KEYISO_OPEN_PRIV_KEY_IN_ST* _cleanup_open_priv_key_message(
    int ret,
    const char *loc,
    const char *err,
    const uuid_t correlationId,
    KEYISO_OPEN_PRIV_KEY_IN_ST* inSt,
    unsigned char* opaqueEncKey,
    uint32_t opaqueEncKeyLen)
{
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_OPEN_KEY_TITLE, loc, err);
        KeyIso_free(inSt);
    }

    KeyIso_free(opaqueEncKey);
    return inSt;
}
 
#define _CLEANUP_OPEN_PRIV_KEY(ret, loc, err) \
    _cleanup_open_priv_key_message(ret, loc, err, keyCtx->correlationId, inSt, opaqueEncKey, opaqueEncKeyLen)
 
static KEYISO_OPEN_PRIV_KEY_IN_ST* _create_open_priv_key_message(
    const KEYISO_KEY_CTX *keyCtx,
    size_t *structSize)
{
    if (!keyCtx || !structSize) {
        return NULL;
    }
 
    unsigned char* opaqueEncKey = NULL;
    uint32_t opaqueEncKeyLen = 0;
    KEYISO_OPEN_PRIV_KEY_IN_ST* inSt = NULL;
   
    int result = _get_opaque_key_from_key_ctx(keyCtx, &opaqueEncKey, &opaqueEncKeyLen);
    if (result != STATUS_OK) {
        return _CLEANUP_OPEN_PRIV_KEY(result, "_get_opaque_key_from_key_ctx", "Failed to get encrypted key from key bytes");
    }
   
    KEYISO_KEY_DETAILS* keyDetails = (KEYISO_KEY_DETAILS*)keyCtx->keyDetails;
    if (!keyDetails) {
        return _CLEANUP_OPEN_PRIV_KEY(STATUS_FAILED, "keyDetails", "Invalid key details");
    }
 
    KEYISO_CLIENT_DATA_ST* clientData = (KEYISO_CLIENT_DATA_ST *)keyDetails->clientData;
    if (!clientData) {
        return _CLEANUP_OPEN_PRIV_KEY(STATUS_FAILED, "clientData", "Invalid client data");
    }
 
    uint32_t dynamicLen = clientData->pubKeyLen + opaqueEncKeyLen;
    *structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_OPEN_PRIV_KEY_IN_ST, dynamicLen);
   
    inSt = (KEYISO_OPEN_PRIV_KEY_IN_ST*)KeyIso_zalloc(*structSize);
    if (inSt == NULL) {
        *structSize = 0;
        return _CLEANUP_OPEN_PRIV_KEY(STATUS_FAILED, "KeyIso_zalloc", "Failed to allocate memory for open private key message");
    }
 
    // Fill the headers
    _fill_header(&inSt->headerSt, IpcCommand_OpenPrivateKey, keyCtx->correlationId);
    _fill_client_data(&inSt->clientDataHeader, clientData);
 
    // Fill the key data
    inSt->publicKeyLen = clientData->pubKeyLen;
    inSt->opaqueEncryptedKeyLen = opaqueEncKeyLen;
 
    // Copy the key data
    if (clientData->pubKeyLen > 0) {
        memcpy(inSt->data, clientData->pubKeyBytes, clientData->pubKeyLen);
    }
    if (opaqueEncKeyLen > 0) {
        memcpy(inSt->data + clientData->pubKeyLen, opaqueEncKey, opaqueEncKeyLen);
    }
 
    KeyIso_free(opaqueEncKey);
    return inSt;
}
 
static uint8_t* _cleanup_open_priv_key_serialized_message(
    int ret,
    const char *loc,
    const char *err,
    const uuid_t correlationId,
    uint8_t *msgBuf,
    KEYISO_OPEN_PRIV_KEY_IN_ST *inSt)
{
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_OPEN_KEY_TITLE, loc, err);
    }
    KeyIso_free(inSt);
    return msgBuf;
}
 
#define _CLEANUP_OPEN_PRIV_KEY_SERIALIZED(ret, loc, err) \
    _cleanup_open_priv_key_serialized_message(ret, loc, err, keyCtx->correlationId, msgBuf, inSt)
 
static uint8_t* _create_and_serialize_open_priv_key_message(const KEYISO_KEY_CTX *keyCtx, size_t *msgLen)
{      
    if (!msgLen || !keyCtx) {
        return NULL;
    }
   
    *msgLen = 0;
   
    // Create the structure using our helper function
    size_t structSize = 0;
    KEYISO_OPEN_PRIV_KEY_IN_ST *inSt = _create_open_priv_key_message(keyCtx, &structSize);
    if (inSt == NULL) {
        // Memory allocation failed
        return NULL;
    }
   
    // Check if encoding is required by the IPC
    uint8_t *msgBuf = NULL;
    bool isEncodingRequired = KeyIso_client_adapter_is_encoding();
    if (!isEncodingRequired) {
        *msgLen = structSize;
        return (uint8_t*)inSt;
    }    
 
    // Encode struct
    msgBuf = KeyIso_serialize_open_priv_key_in(inSt, msgLen);
    if (msgBuf == NULL) {
        return _CLEANUP_OPEN_PRIV_KEY_SERIALIZED(STATUS_FAILED, "KeyIso_serialize_open_priv_key_in failed", "Failed to serialize open private key message");
    }
   
    KeyIso_free(inSt);
    return msgBuf;
}

static size_t _get_len_open_priv_key_out(const uint8_t *encodedSt, size_t encodedLen)
{
    return sizeof(KEYISO_OPEN_PRIV_KEY_OUT_ST);
}

// Checking if the non serialized open_priv_key out structure is valid (this will be activated when encoding is not needed)
bool KeyIso_is_valid_open_priv_key_out_structure(const uuid_t correlationId, const KEYISO_OPEN_PRIV_KEY_OUT_ST *outSt, uint32_t receivedLen) 
{
    // Calculating the size of the out structure
    size_t outStLenCalculation = _get_len_open_priv_key_out((uint8_t*)outSt, receivedLen);

    // Checking if the calculated length is equal to the received length
    if (!_is_calc_len_equal_to_received_len(correlationId, receivedLen, outStLenCalculation, KEYISOP_OPEN_KEY_TITLE)) {        
        return false;
    }

    return true;
}

static int _handle_open_priv_key_message(KEYISO_KEY_CTX *keyCtx)
{
    if(!keyCtx)
        return STATUS_FAILED;
    
    KEYISO_KEY_DETAILS* keyDetails = (KEYISO_KEY_DETAILS*)keyCtx->keyDetails;
    if(!keyDetails)
        return STATUS_FAILED;      
    //1. Create the structure and encode it (if needed)
    size_t msgLen = 0;
    uint8_t *msgBuf = _create_and_serialize_open_priv_key_message(keyCtx, &msgLen);

    //2. Send to the server as a generic message
    int result = STATUS_FAILED;    
    IPC_REPLY_ST *reply = _create_and_send_generic_msg(keyCtx, IpcCommand_OpenPrivateKey, msgLen, msgBuf, &result);
    KeyIso_clear_free(msgBuf, msgLen);

    //3.Check if there is no need for open
    if (KeyIso_client_adapter_is_key_already_opened(reply, result)) {
        KeyIso_client_adapter_key_open_completed(keyCtx);
        return STATUS_OK;
    }
    
    //4. Deserialize response (if needed) and return relevant fields
    if (reply && (result == STATUS_OK)) { 
        KEYISO_OPEN_PRIV_KEY_OUT_ST *outSt = NULL;
        bool isEncodingRequired = KeyIso_client_adapter_is_encoding();        
        if (!isEncodingRequired) {            
            outSt = (KEYISO_OPEN_PRIV_KEY_OUT_ST*)reply->outSt;
            if (outSt && (outSt->headerSt.result == STATUS_OK) && KeyIso_is_valid_open_priv_key_out_structure(keyCtx->correlationId, outSt, reply->outLen))
                keyDetails->keyId = outSt->keyId;
            else
                result = STATUS_FAILED;
        } else {  
            size_t sizeToAlloc = KeyIso_safely_calc_encoded_out_st_alloc_size(keyCtx->correlationId, reply->outSt, reply->outLen, _get_len_open_priv_key_out);
            // Checking if the sizeToAlloc is valid. sizeToAlloc == 0 means that the size is invalid.
            if (sizeToAlloc > 0) {
                outSt = (KEYISO_OPEN_PRIV_KEY_OUT_ST *)KeyIso_zalloc(sizeToAlloc);            
                if (outSt != NULL) {
                    result = KeyIso_deserialize_open_priv_key_out(reply->outSt, reply->outLen, outSt);
                    if (result == STATUS_OK && outSt->headerSt.result == STATUS_OK)
                        keyDetails->keyId = outSt->keyId;
                    else  
                        result = STATUS_FAILED;     
                    KeyIso_free(outSt);

                } else {
                    result = STATUS_FAILED;
                } 
            } else {
                result = STATUS_FAILED;
            } 
        }

        KeyIso_free(reply->outSt);
        KeyIso_free(reply);   
    }
    KeyIso_client_adapter_key_open_completed(keyCtx);

    if (result == STATUS_OK)
        KEYISOP_trace_log(keyCtx->correlationId, verboseFlag, KEYISOP_OPEN_PFX_TITLE, "Open Private key command received and completed");
    else
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_OPEN_PFX_TITLE, "Open Private key command received", "operation failed");
    return result;
}


/////////////////////////////////////
/*  import symmetric key           */
/////////////////////////////////////

static KEYISO_IMPORT_SYMMETRIC_KEY_IN_ST* _create_import_symmetric_key_message(const uuid_t correlationId, int inSymmetricKeyType, int inKeyLength, 
                    const unsigned char *inKeyBytes, const unsigned char *inImportKeyId, size_t *structSize)
{   
    if (!structSize)
        return NULL;
    
    *structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_IMPORT_SYMMETRIC_KEY_IN_ST, inKeyLength);
    KEYISO_IMPORT_SYMMETRIC_KEY_IN_ST* inSt = (KEYISO_IMPORT_SYMMETRIC_KEY_IN_ST *)KeyIso_zalloc(*structSize); // KeyIso_clear_free()
    if (inSt == NULL) {
        *structSize = 0;
        return NULL;
    }

    _fill_header(&inSt->headerSt, IpcCommand_ImportSymmetricKey, correlationId);
    
    inSt->symmetricKeyType = inSymmetricKeyType;
    memcpy(inSt->importKeyId, inImportKeyId, KMPP_AES_256_KEY_SIZE);
    inSt->keyLen = inKeyLength;
    memcpy(inSt->keyBytes, inKeyBytes, inKeyLength);

    return inSt;
}

static uint8_t* _create_and_serialize_import_symmetric_key_message(const uuid_t correlationId, int inSymmetricKeyType, int inKeyLength, 
                    const unsigned char *inKeyBytes, const unsigned char *inImportKeyId, size_t *outLen)
{   
    if (!outLen)
        return NULL;
    *outLen = 0; 

    //1. Create struct
    size_t structSize = 0;
    KEYISO_IMPORT_SYMMETRIC_KEY_IN_ST* inSt = _create_import_symmetric_key_message(correlationId, inSymmetricKeyType, inKeyLength, inKeyBytes, inImportKeyId, &structSize);
    if (inSt == NULL)
        return NULL;

    //2. Check if encoding is required by the IPC
    bool isEncodingRequired = KeyIso_client_adapter_is_encoding();
    if (!isEncodingRequired) {
        *outLen = structSize;
        return (uint8_t*) inSt;
    }

    //3. Encode struct (if needed)
    uint8_t *outBuf = KeyIso_serialize_import_symmetric_key_in(inSt, outLen);
  
    //3. Free origin struct
    KeyIso_clear_free(inSt, structSize);
    return outBuf;
}

static int _create_base64_client_keyid_metadata(const uuid_t correlationId, KmppKeyIdType  keyType, uint8_t clientVersion, uint8_t serviceVersion, uint32_t isolationSolution, char **outClientData)
{
    if (!outClientData) {
        return STATUS_FAILED;
    }
    KEYISO_CLIENT_KEYID_HEADER_ST clientKeyIdMetadataSt =  {
        .clientVersion = clientVersion,
        .keyType = keyType,
        .keyServiceVersion = serviceVersion,
        .isolationSolution = isolationSolution
    };

    *outClientData = NULL;
    unsigned char* clientKeyIdBuff = (unsigned char *)KeyIso_zalloc(sizeof(clientKeyIdMetadataSt));
    if (clientKeyIdBuff == NULL) {
        return STATUS_FAILED;
    }
    
    memcpy(clientKeyIdBuff, &clientKeyIdMetadataSt, sizeof(KEYISO_CLIENT_KEYID_HEADER_ST));

    char *clientDataBase64 = NULL;
    int len = KeyIso_base64_encode(correlationId, clientKeyIdBuff, sizeof(clientKeyIdMetadataSt), &clientDataBase64);
    if (len <= 0 || clientDataBase64 == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "KeyIso_base64_encode failed", "Failed to encode client header");
        KeyIso_free(clientKeyIdBuff);
        return STATUS_FAILED;
    }

    *outClientData = clientDataBase64;
    KeyIso_free(clientKeyIdBuff);
    return STATUS_OK;
}

int _get_import_symmetric_key_result(const unsigned char *correlationId, const KEYISO_IMPORT_SYMMETRIC_KEY_OUT_ST *outSt, unsigned int *outKeyLength, unsigned char **outKeyBytes, char **outClientData)
{
    if ((outSt->headerSt.result == STATUS_OK) && (outSt->encryptedKeyLen > 0)) {
        *outKeyBytes = (unsigned char *)KeyIso_zalloc(outSt->encryptedKeyLen);
        if (*outKeyBytes != NULL) {
            memcpy(*outKeyBytes, outSt->encryptedKeyBytes, outSt->encryptedKeyLen);
            *outKeyLength = outSt->encryptedKeyLen; 
        }
    }
    uint8_t clientVersion = KEYISOP_CURRENT_VERSION; // The version of the client that formats the keyid
    KmppKeyIdType keyType = KmppKeyIdType_symmetric; // The type of the key that is being imported
    uint8_t serviceVersion = outSt->headerSt.version;
    uint16_t isolationSolution = outSt->headerSt.isolationSolution;
    if (serviceVersion == KEYISOP_INVALID_VERSION && isolationSolution == KeyIsoSolutionType_invalid ) { 
        // Previous Version Service 
        serviceVersion = KEYISOP_VERSION_3;
        // There is no other isolation solution for version 3, so we set PB
        isolationSolution = KeyIsoSolutionType_process;
    }

    int result = _create_base64_client_keyid_metadata(correlationId, keyType, clientVersion, serviceVersion, isolationSolution, outClientData);
    if (result != STATUS_OK) {
        return result;
    }

    return outSt->headerSt.result;
}

// Checking if the non serialized import_symmetric out structure is valid (this will be activated when encoding is not needed)
bool KeyIso_is_valid_import_symmetric_key_out_structure(const uuid_t correlationId, const KEYISO_IMPORT_SYMMETRIC_KEY_OUT_ST *outSt, uint32_t receivedLen)
{
    // Calculating the size of the out structure, when the dynamic array size equals to outSt->encryptedKeyLen
    size_t outStLenCalculation = GET_DYNAMIC_STRUCT_SIZE(KEYISO_IMPORT_SYMMETRIC_KEY_OUT_ST, outSt->encryptedKeyLen);

    // Checking if the calculated length is equal to the received length
    if (!_is_calc_len_equal_to_received_len(correlationId, receivedLen, outStLenCalculation, KEYISOP_IMPORT_SYMMETRIC_KEY_TITLE)) {        
        return false;
    }

    return true;
}

int _handle_import_symmetric_message(const uuid_t correlationId, int inSymmetricKeyType, int inKeyLength, 
                    const unsigned char *inKeyBytes, const unsigned char *inImportKeyId, unsigned int *outKeyLength, unsigned char **outKeyBytes, char **outClientData)
{
    *outKeyLength = 0;
    *outKeyBytes = NULL;

    //1. Create the structure and encode it (if needed)
    size_t msgLen = 0;
    uint8_t *msgBuf = _create_and_serialize_import_symmetric_key_message(correlationId, inSymmetricKeyType, inKeyLength, inKeyBytes, inImportKeyId, &msgLen); // KeyIso_clear_free()

    //2. Send to the server as a generic message
    int result = STATUS_FAILED;
    IPC_REPLY_ST *reply = _create_temp_key_ctx_and_send_msg(correlationId, IpcCommand_ImportSymmetricKey, msgLen, msgBuf, &result);    
    KeyIso_clear_free(msgBuf, msgLen);

    //3. Deserialize response (if needed) and return relevant fields
    if (reply && (result == STATUS_OK)) {
        KEYISO_IMPORT_SYMMETRIC_KEY_OUT_ST *outSt = NULL;
        bool isEncodingRequired = KeyIso_client_adapter_is_encoding();
        if (!isEncodingRequired) {
            outSt = (KEYISO_IMPORT_SYMMETRIC_KEY_OUT_ST*)reply->outSt;
            if (outSt && outSt->headerSt.result == STATUS_OK && KeyIso_is_valid_import_symmetric_key_out_structure(correlationId, outSt, reply->outLen)) {
                result = _get_import_symmetric_key_result(correlationId, outSt, outKeyLength, outKeyBytes, outClientData);
            } else {
                result = STATUS_FAILED;
            }
        } else {
            size_t sizeToAlloc = KeyIso_safely_calc_encoded_out_st_alloc_size(correlationId, reply->outSt, reply->outLen, KeyIso_get_len_import_symmetric_key_out);            
            // Checking if the sizeToAlloc is valid. sizeToAlloc == 0 means that the size is invalid.
            if (sizeToAlloc > 0) {
                outSt = (KEYISO_IMPORT_SYMMETRIC_KEY_OUT_ST *)KeyIso_zalloc(sizeToAlloc);
                if (outSt != NULL) {
                    result = KeyIso_deserialize_import_symmetric_key_out(reply->outSt, reply->outLen, outSt);
                    if (result == STATUS_OK) {
                        result = _get_import_symmetric_key_result(correlationId, outSt, outKeyLength, outKeyBytes, outClientData);
                    }
                    KeyIso_free(outSt);
                } else {
                    result = STATUS_FAILED;
                }
            } else {
                result = STATUS_FAILED;
            }            
        }
        KeyIso_clear_free(reply->outSt, reply->outLen);
        KeyIso_free(reply);
    }

    if (result != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, NULL, "Import symmetric key failed");
    }

    return result;
}


/////////////////////////////////////
/*  symmetric key encrypt decrypt  */
/////////////////////////////////////
static KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST* _create_symmetric_key_encrypt_decrypt_message(const KEYISO_KEY_CTX *keyCtx, int mode, 
                            const unsigned char *from, uint32_t fromLen, size_t *structSize)
{   
    if (!structSize || !keyCtx)
        return NULL;
    
    KEYISO_KEY_DETAILS* keyDetails = (KEYISO_KEY_DETAILS*)keyCtx->keyDetails;
    if (!keyDetails) {
        return NULL;
    }

    int dynamicLen = fromLen + keyDetails->keyLength;
    *structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST, dynamicLen);
    KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST* inSt = (KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST *)KeyIso_zalloc(*structSize);
    if (inSt == NULL) {
        *structSize = 0;
        return NULL;
    }

    _fill_header(&inSt->headerSt, IpcCommand_SymmetricKeyEncryptDecrypt, keyCtx->correlationId);
      
    inSt->decrypt = mode;
    inSt->encryptedKeyLen = keyDetails->keyLength;
    inSt->fromBytesLen = fromLen; 

    int index = 0;
    memcpy(&inSt->encDecBytes[index], keyDetails->keyBytes, keyDetails->keyLength);
    index += inSt->encryptedKeyLen;
    memcpy(&inSt->encDecBytes[index], from, inSt->fromBytesLen);

    return inSt;
}


static uint8_t* _create_and_serialize_symmetric_key_encrypt_decrypt_message(const KEYISO_KEY_CTX *keyCtx, int mode, 
                            const unsigned char *from, uint32_t fromLen, size_t *outLen)
{   
    if (!outLen)
        return NULL;
    *outLen = 0; 

    //1. Create struct
    size_t structSize = 0;
    KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST* inSt = _create_symmetric_key_encrypt_decrypt_message(keyCtx, mode, from, fromLen, &structSize);
    if (inSt == NULL)
        return NULL;

    //2. Check if encoding is required by the IPC
    bool isEncodingRequired = KeyIso_client_adapter_is_encoding();
    if (!isEncodingRequired) {
        *outLen = structSize;
        return (uint8_t*) inSt;
    }

    //3. Encode struct (if needed)
    uint8_t *outBuf = KeyIso_serialize_enc_dec_symmetric_key_in(inSt, outLen);
  
    //4. Free origin struct
    KeyIso_free(inSt);
    return outBuf;
}


int _get_symmetric_key_encrypt_decrypt_result(const KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_OUT_ST *outSt, unsigned char *to, unsigned int *toLen)
{
    if (outSt->headerSt.result == STATUS_OK) {
        memcpy(to, outSt->toBytes, outSt->bytesLen);
        *toLen = outSt->bytesLen;
    }
    return outSt->headerSt.result;
}

// Checking if the non serialized symmetric_key_enc_dec out structure is valid (this will be activated when encoding is not needed)
bool KeyIso_is_valid_symmetric_key_enc_dec_out_structure(const uuid_t correlationId, const KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_OUT_ST *outSt, uint32_t receivedLen)
{
    // Calculating the size of the out structure, when the dynamic array size equals to outSt->bytesLen
    size_t outStLenCalculation = GET_DYNAMIC_STRUCT_SIZE(KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_OUT_ST, outSt->bytesLen);

    // Checking if the calculated length is equal to the received length
    if (!_is_calc_len_equal_to_received_len(correlationId, receivedLen, outStLenCalculation, KEYISOP_SYMMETRIC_ENC_DEC_TITLE)) {        
        return false;
    }

    return true;
}
  
int _handle_symmetric_key_encrypt_decrypt_message(KEYISO_KEY_CTX *keyCtx, int mode, 
                        const unsigned char *from, const unsigned int fromLen, unsigned char *to, unsigned int *toLen)
{   
    if (!from || !to || !toLen)
        return STATUS_FAILED;

    *toLen = 0;
    //1. Create the structure and encode it
    size_t msgLen = 0;
    uint8_t *msgBuf = _create_and_serialize_symmetric_key_encrypt_decrypt_message(keyCtx, mode, from, fromLen, &msgLen);

    //2. Send to the server as a generic message
    int result = STATUS_FAILED;
    IPC_REPLY_ST *reply = _create_and_send_generic_msg(keyCtx, IpcCommand_SymmetricKeyEncryptDecrypt, msgLen, msgBuf, &result);    
    KeyIso_free(msgBuf);

    //3. Deserialize response (if needed) and return relevant fields
    if (reply && (result == STATUS_OK)) {
        KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_OUT_ST *outSt = NULL;
        bool isEncodingRequired = KeyIso_client_adapter_is_encoding();
        if (!isEncodingRequired) {
            outSt = (KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_OUT_ST*)reply->outSt;
            if (outSt && outSt->headerSt.result == STATUS_OK && KeyIso_is_valid_symmetric_key_enc_dec_out_structure(keyCtx->correlationId, outSt, reply->outLen)) {
                result = _get_symmetric_key_encrypt_decrypt_result(outSt, to, toLen);
            } else {
                result = STATUS_FAILED;
            }
        } else {
            size_t sizeToAlloc = KeyIso_safely_calc_encoded_out_st_alloc_size(keyCtx->correlationId, reply->outSt, reply->outLen, KeyIso_get_len_enc_dec_symmetric_key_out);            
            // Checking if the sizeToAlloc is valid. sizeToAlloc == 0 means that the size is invalid.
            if (sizeToAlloc > 0) {
                outSt = (KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_OUT_ST *)KeyIso_zalloc(sizeToAlloc);
                if (outSt != NULL) {
                    result = KeyIso_deserialize_enc_dec_symmetric_key_out(reply->outSt, reply->outLen, outSt);
                    if (result == STATUS_OK) {
                        result = _get_symmetric_key_encrypt_decrypt_result(outSt, to, toLen);
                    }
                    KeyIso_free(outSt);
                }
                else {
                    result = STATUS_FAILED;
                }
            } else {
                result = STATUS_FAILED;
            }            
        }
        KeyIso_free(reply->outSt);
        KeyIso_free(reply);
    }

    if (result != STATUS_OK) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_SYMMETRIC_ENC_DEC_TITLE, NULL, "Symmetric key encrypt/decrypt failed");
    }

    return result;
}

//////////////////////////
/*  External functions  */
//////////////////////////

int KeyIso_client_msg_handler_init_key(KEYISO_KEY_CTX *keyCtx, int keyLength, const unsigned char *keyBytes, const char *clientData)
{
    return KeyIso_client_adapter_init_keyCtx(keyCtx, keyLength, keyBytes, clientData);
}

void KeyIso_client_msg_handler_free_keyCtx(KEYISO_KEY_CTX *keyCtx)
{
    KEYISOP_trace_log(keyCtx->correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_GDBUS_CLIENT_TITLE, "KeyIso_client_adapter_free_keyCtx");
    KeyIso_client_adapter_free_keyCtx(keyCtx);
}

void KeyIso_client_msg_close_key(KEYISO_KEY_CTX *keyCtx)
{
    if (keyCtx == NULL) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_CLOSE_PFX_TITLE, "keyCtx", "Invalid argument"); 
        return;
    }

    _handle_close_key_message(keyCtx);    
}

int KeyIso_client_msg_ecdsa_sign(KEYISO_KEY_CTX *keyCtx,
                int type, const unsigned char *dgst, int dlen, unsigned char *sig, unsigned int sigLen, unsigned int *outLen)
{
    const char *title = KEYISOP_ECC_SIGN_TITLE;
    if (keyCtx == NULL) {
        KEYISOP_trace_log_error(NULL, 0, title, "keyCtx", "Invalid argument");
        return -1;
    }
      
    bool validConnection = KeyIso_client_adapter_is_connection(keyCtx); 
    if (!validConnection) {
        int result = _handle_open_priv_key_message(keyCtx);
        if (result != STATUS_OK) {
            KEYISOP_trace_log_error(keyCtx->correlationId, 0, title, "open ipc", "open failed");     
            return -1;          
        }
    }

    return _handle_ecdsa_sign_message(keyCtx, type, dgst, dlen, sig, sigLen, outLen);
}

int KeyIso_client_msg_rsa_private_encrypt_decrypt(KEYISO_KEY_CTX *keyCtx, int decrypt, int flen, 
    const unsigned char *from, int tlen, unsigned char *to, int padding, int labelLen)
{
    const char *title = _get_rsa_enc_dec_title(decrypt);
    if (keyCtx == NULL) {
        KEYISOP_trace_log_error(NULL, 0, title, "keyCtx", "Invalid argument");
        return -1;
    }

    bool validConnection = KeyIso_client_adapter_is_connection(keyCtx); 
    if (!validConnection) {
        int result = _handle_open_priv_key_message(keyCtx);
        if (result != STATUS_OK) {
            KEYISOP_trace_log_error(keyCtx->correlationId, 0, title, "open ipc", "open failed");     
            return -1;          
        }
    }
    
    return _handle_rsa_private_encrypt_decrypt_message(keyCtx, decrypt, flen, from, tlen, to, padding, labelLen);
}

int KeyIso_client_msg_import_symmetric_key(const uuid_t correlationId, int inSymmetricKeyType, unsigned int inKeyLength, 
                const unsigned char *inKeyBytes, const unsigned char *inImportKeyId, unsigned int *outKeyLength, unsigned char **outKeyBytes, char **outClientData)
{
    return _handle_import_symmetric_message(correlationId, inSymmetricKeyType, inKeyLength, inKeyBytes, inImportKeyId, outKeyLength, outKeyBytes, outClientData);
}

int KeyIso_client_msg_symmetric_key_encrypt_decrypt(KEYISO_KEY_CTX *keyCtx, int mode, 
                            const unsigned char *from, const unsigned int fromLen, unsigned char *to, unsigned int *toLen)
{
    if (keyCtx == NULL) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_SYMMETRIC_ENC_DEC_TITLE, "keyCtx", "Invalid argument");
        return STATUS_FAILED;
    }

    bool validConnection = KeyIso_client_adapter_is_connection(keyCtx); 
    if (!validConnection) {
        int result = KeyIso_client_adapter_open_ipc(keyCtx);
        if (result != STATUS_OK) {
            KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_SYMMETRIC_ENC_DEC_TITLE, "open ipc", "open failed");     
            return STATUS_FAILED;
        }
    }    
    return _handle_symmetric_key_encrypt_decrypt_message(keyCtx, mode, from, fromLen, to, toLen);
}

static int _cleanup_client_msg_import_private_key(const uuid_t correlationId, int ret , const char* message, unsigned char *opaqueKey, KEYISO_CLIENT_DATA_ST *clientData)
{
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "Import private key failed", message);
        KeyIso_free(clientData);
    }
    KeyIso_free(opaqueKey);
    return ret;
}

#define _CLEANUP_IMPORT_PRIVATE_KEY(ret, message) \
     _cleanup_client_msg_import_private_key(correlationId, ret, message, opaqueKey, clientData)

int KeyIso_client_msg_import_private_key(const uuid_t correlationId, int keyType,
    const unsigned char *inKeyBytes, X509_SIG **outEncKey, KEYISO_CLIENT_DATA_ST **outClientData) {

    int ret = STATUS_FAILED; 
    KEYISO_CLIENT_DATA_ST *clientData = NULL;
    X509_SIG* encKey = NULL;
    unsigned int opaqueKeyLen = 0;
    unsigned char *opaqueKey = NULL;
    
    if (inKeyBytes == NULL || outEncKey == NULL || outClientData == NULL) {
        return _CLEANUP_IMPORT_PRIVATE_KEY(STATUS_FAILED, "Invalid arguments");
    }

    //keyType is either ECC or RSA else the calling function failed.
    if (keyType == EVP_PKEY_EC) {
        ret = _handle_ec_import_private_key_message(correlationId, (KEYISO_EC_PKEY_ST*) inKeyBytes, &clientData, &opaqueKeyLen, &opaqueKey);
    }
    else { // EVP_PKEY_RSA or EVP_PKEY_RSA_PSS
        ret = _handle_rsa_import_private_key_message(correlationId, (KEYISO_RSA_PKEY_ST*) inKeyBytes, &clientData, &opaqueKeyLen, &opaqueKey);
    }

    if (ret != STATUS_OK) {
       return _CLEANUP_IMPORT_PRIVATE_KEY(ret, "Import private key failed");
    }

    ret = KeyIso_create_pkcs8_enckey(opaqueKeyLen, (const unsigned char *)opaqueKey, &encKey);
    if (ret != STATUS_OK) {
        return _CLEANUP_IMPORT_PRIVATE_KEY(ret, "Create pkcs8 enckey failed");
    }

    *outClientData = clientData;
    *outEncKey = encKey;
    return _CLEANUP_IMPORT_PRIVATE_KEY(STATUS_OK, NULL);
}

int KeyIso_client_msg_generate_rsa_key_pair(const uuid_t correlationId, unsigned int rsaBits, uint8_t keyUsage,
    EVP_PKEY** outPubKey,  X509_SIG **outEncryptedPkey, KEYISO_CLIENT_METADATA_HEADER_ST *outMetaData)
{        
    return _handle_rsa_generate_key_pair_message(correlationId, rsaBits, keyUsage, outPubKey, outEncryptedPkey, outMetaData);
}

int KeyIso_client_msg_generate_ec_key_pair(const uuid_t correlationId, unsigned int curve, uint8_t keyUsage,
    EC_GROUP** outEcGroup, EC_KEY** outPubKey, X509_SIG **outEncryptedPkeyP8, KEYISO_CLIENT_METADATA_HEADER_ST *outMetaData)
{
    return  _handle_ec_generate_key_pair_message(correlationId, curve, keyUsage, outEcGroup, outPubKey, outEncryptedPkeyP8, outMetaData);
}

void KeyIso_client_set_config(const KEYISO_CLIENT_CONFIG_ST *config)
{
    return KeyIso_client_set_ipcImp(config->solutionType);
}

int KeyIso_client_open_priv_key_message(KEYISO_KEY_CTX *keyCtx)
{
    return _handle_open_priv_key_message(keyCtx);
}
