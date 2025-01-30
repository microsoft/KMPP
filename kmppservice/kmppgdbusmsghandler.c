/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisoipccommands.h"
#include "keyisoservicemsghandler.h"
#include "keyisoipcserviceadapter.h"
#include "kmppgdbusmsghandler.h"

//////////////////////////////////////////////////////////////////////////////////////
//                                                                                  //
//            Define the GDBUS implementation of the IPC service functions          //
//                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////

const IPC_SERVICE_FUNCTIONS_TABLE_ST GDBusServiceImplementation = {   
    .msgPreprocessing = KeyIso_gdbus_msg_preprocessing,
    .msgPostprocessing = KeyIso_gdbus_msg_postprocessing,
    .msgInLength = KeyIso_gdbus_msg_in_length,
    .msgOutLength = KeyIso_gdbus_msg_out_length,
    .msgCleanup = KeyIso_gdbus_msg_cleanup,
};
const IPC_SERVICE_FUNCTIONS_TABLE_ST ipcSrvImp = GDBusServiceImplementation;


// This table is used to map the incoming IPC command to the appropriate encode/decode function.
static const KEYISO_MSG_HANDLER_TABLE_ST KeyIso_gdbus_msg_handler_table[] = 
{   
    // IpcCommand_OpenPrivateKey
    {KeyIso_serialize_open_priv_key_in,                     // inSerializeFunc  
     KeyIso_deserialize_open_priv_key_in,                   // inDeserializeFunc   
     KeyIso_get_len_open_priv_key_in,                       // inMsgLengthFunc  
     KeyIso_serialize_open_priv_key_out,                    // outSerializeFunc
     KeyIso_deserialize_open_priv_key_out,                  // outDeserializeFunc
     NULL},                                                 // outMsgLengthFunc

    // IpcCommand_CloseKey
    {KeyIso_serialize_close_key_in,                         // inSerializeFunc
     KeyIso_deserialize_close_key_in,                       // inDeserializeFunc
     KeyIso_get_len_close_key_in,                           // inMsgLengthFunc
     KeyIso_serialize_close_key_out,                        // outSerializeFunc
     KeyIso_deserialize_close_key_out,                      // outDeserializeFunc
     NULL},                                                 // outMsgLengthFunc
    
    // IpcCommand_EcdsaSign
    {KeyIso_serialize_ecdsa_sign_in,                        // inSerializeFunc     
     KeyIso_deserialize_ecdsa_sign_in,                      // inDeserializeFunc
     KeyIso_get_len_ecdsa_sign_in,                          // inMsgLengthFunc   
     KeyIso_serialize_ecdsa_sign_out,                       // outSerializeFunc
     KeyIso_deserialize_ecdsa_sign_out,                     // outDeserializeFunc
     KeyIso_get_len_ecdsa_sign_out},                        // outMsgLengthFunc
    
    // IpcCommand_RsaPrivateEncryptDecrypt
    {KeyIso_serialize_rsa_enc_dec_in,                       // inSerializeFunc
     KeyIso_deserialize_rsa_enc_dec_in,                     // inDeserializeFunc
     KeyIso_get_len_rsa_enc_dec_in,                         // inMsgLengthFunc
     KeyIso_serialize_rsa_enc_dec_out,                      // outSerializeFunc
     KeyIso_deserialize_rsa_enc_dec_out,                    // outDeserializeFunc
     KeyIso_get_len_rsa_enc_dec_out},                       // outMsgLengthFunc           
    
    // IpcCommand_GenerateRsaKeyPair
    {KeyIso_serialize_gen_rsa_key_pair_in,                  // inSerializeFunc  
     KeyIso_deserialize_gen_rsa_key_pair_in,                // inDeserializeFunc
     KeyIso_get_len_gen_rsa_key_pair_in,                    // inMsgLengthFunc
     KeyIso_serialize_gen_rsa_key_pair_out,                 // outSerializeFunc
     KeyIso_deserialize_gen_rsa_key_pair_out,               // outDeserializeFunc
     KeyIso_get_len_gen_rsa_key_pair_out},                  // outMsgLengthFunc  
    
    // IpcCommand_GenerateEcKeyPair
    {KeyIso_serialize_gen_ec_key_pair_in,                   // inSerializeFunc
     KeyIso_deserialize_gen_ec_key_pair_in,                 // inDeserializeFunc
     KeyIso_get_len_gen_ec_key_pair_in,                     // inMsgLengthFunc
     KeyIso_serialize_gen_ec_key_pair_out,                  // outSerializeFunc
     KeyIso_deserialize_gen_ec_key_pair_out,                // outDeserializeFunc
     KeyIso_get_len_gen_ec_key_pair_out},                   // outMsgLengthFunc
    
    // IpcCommand_ImportRsaPrivateKey
    {KeyIso_serialize_import_rsa_priv_key_in,               // inSerializeFunc
     KeyIso_deserialize_import_rsa_priv_key_in,             // inDeserializeFunc
     KeyIso_get_len_import_rsa_priv_key_in,                 // inMsgLengthFunc
     KeyIso_serialize_import_priv_key_out,                  // outSerializeFunc
     KeyIso_deserialize_import_rsa_priv_key_out,            // outDeserializeFunc
     KeyIso_get_len_import_priv_key_out},                   // outMsgLengthFunc
    
    // IpcCommand_ImportEcPrivateKey
    {KeyIso_serialize_import_ec_priv_key_in,                // inSerializeFunc
     KeyIso_deserialize_import_ec_priv_key_in,              // inDeserializeFunc
     KeyIso_get_len_import_ec_priv_key_in,                  // inMsgLengthFunc
     KeyIso_serialize_import_priv_key_out,                  // outSerializeFunc
     KeyIso_deserialize_import_ec_priv_key_out,             // outDeserializeFunc
     KeyIso_get_len_import_priv_key_out},                   // outMsgLengthFunc
    
    // IpcCommand_ImportSymmetricKey
    {KeyIso_serialize_import_symmetric_key_in,              // inSerializeFunc
     KeyIso_deserialize_import_symmetric_key_in,            // inDeserializeFunc
     KeyIso_get_len_import_symmetric_key_in,                // inMsgLengthFunc
     KeyIso_serialize_import_symmetric_key_out,             // outSerializeFunc
     KeyIso_deserialize_import_symmetric_key_out,           // outDeserializeFunc
     KeyIso_get_len_import_symmetric_key_out},              // outMsgLengthFunc
    
    // IpcCommand_SymmetricKeyEncryptDecrypt
    {KeyIso_serialize_enc_dec_symmetric_key_in,             // inSerializeFunc
     KeyIso_deserialize_enc_dec_symmetric_key_in,           // inDeserializeFunc
     KeyIso_get_len_enc_dec_symmetric_key_in,               // inMsgLengthFunc
     KeyIso_serialize_enc_dec_symmetric_key_out,            // outSerializeFunc
     KeyIso_deserialize_enc_dec_symmetric_key_out,          // outDeserializeFunc
     KeyIso_get_len_enc_dec_symmetric_key_out},             // outMsgLengthFunc

    // IpcCommand_RsaPrivateEncryptDecryptWithAttachedKey
    {KeyIso_serialize_rsa_enc_dec_with_attached_key_in,     // inSerializeFunc            
     KeyIso_deserialize_rsa_enc_dec_with_attached_key_in,   // inDeserializeFunc
     KeyIso_get_len_rsa_enc_dec_with_attached_key_in,       // inMsgLengthFunc
     KeyIso_serialize_rsa_enc_dec_with_attached_key_out,    // outSerializeFunc
     KeyIso_deserialize_rsa_enc_dec_with_attached_key_out,  // outDeserializeFunc
     KeyIso_get_len_rsa_enc_dec_with_attached_key_out},     // outMsgLengthFunc
     
    // IpcCommand_EcdsaSignWithAttachedKey
    {KeyIso_serialize_ecdsa_sign_with_attached_key_in,      // inSerializeFunc
     KeyIso_deserialize_ecdsa_sign_with_attached_key_in,    // inDeserializeFunc
     KeyIso_get_len_ecdsa_sign_with_attached_key_in,        // inMsgLengthFunc
     KeyIso_serialize_ecdsa_sign_with_attached_key_out,     // outSerializeFunc
     KeyIso_deserialize_ecdsa_sign_with_attached_key_out,   // outDeserializeFunc
     KeyIso_get_len_ecdsa_sign_with_attached_key_out},      // outMsgLengthFunc
    };

static int _validate_ipc_command(IpcCommand command)
{
    if (command < 0 || command >= IpcCommand_Max) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_SERVICE_TITLE, "IpcCommand", "invalid command");
        return STATUS_FAILED;
    }
    return STATUS_OK;
}

size_t KeyIso_safely_calc_encoded_in_st_alloc_size(IpcCommand command, const uint8_t *inSt, size_t inLen)
{    
    //get the size of the structure to be allocated
    size_t sizeToAlloc = KeyIso_gdbus_msg_in_length(command, inSt, inLen);

    // Checking for integer overflow in the sizeToAlloc calculation or invalid input
    if (sizeToAlloc == 0) {                
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_SERVICE_TITLE, "KeyIso_gdbus_msg_in_length", "sizeToAlloc is 0 probably due to integer overflow or invalid input.", "command: %d ", command);
    } else if(sizeToAlloc >= inLen) {    // The sizeToAlloc ("real" size) should be smaller than the size of the inSt (because inSt in this phase is the serialized struct)                       
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_SERVICE_TITLE, "KeyIso_gdbus_msg_in_length", "sizeToAlloc >= inLen", "command: %d ", command);
        sizeToAlloc = 0;  // Set the sizeToAlloc to 0 to indicate that the size is invalid.
    }

    return sizeToAlloc;
}

// Mapping the incoming IPC command to the appropriate in message decoding function.
int KeyIso_gdbus_msg_preprocessing(IpcCommand command, const uint8_t *inSt, size_t inLen, void **decodedInSt)
{
    if (!_validate_ipc_command(command)) {
        return STATUS_FAILED;
    }

    if (!decodedInSt) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_SERVICE_TITLE, "KeyIso_gdbus_msg_preprocessing", "decodedInSt is NULL");
        return STATUS_FAILED;
    }
    *decodedInSt = NULL;

    size_t sizeToAlloc = KeyIso_safely_calc_encoded_in_st_alloc_size(command, inSt, inLen);    
    
    if (sizeToAlloc == 0) {   // The sizeToAlloc is invalid (error indication)      
        return STATUS_FAILED;
    }

    // Allocate the structure to be decoded.
    *decodedInSt = KeyIso_zalloc(sizeToAlloc);
    if (*decodedInSt == NULL) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_SERVICE_TITLE, "KeyIso_zalloc", "failed to allocate memory");
        return STATUS_FAILED;
    }

    // Decode the structure.
    return KeyIso_gdbus_msg_handler_table[command].inDeserializeFunc(inSt, inLen, *decodedInSt);
}

// Mapping the incoming IPC command to the appropriate out message encoding function.
uint8_t* KeyIso_gdbus_msg_postprocessing(IpcCommand command, void *outSt, size_t *outLen)
{
    if (!_validate_ipc_command(command))
        return NULL;
    return KeyIso_gdbus_msg_handler_table[command].outSerializeFunc(outSt, outLen);
}

// Getting the the length of the in message structure.
size_t KeyIso_gdbus_msg_in_length(IpcCommand command, const uint8_t *encodedSt, size_t encodedLen)
{
    if (!_validate_ipc_command(command))
        return STATUS_FAILED;
    return KeyIso_gdbus_msg_handler_table[command].inMsgLengthFunc(encodedSt, encodedLen);
}

// Getting the the length of the out message structure.
size_t KeyIso_gdbus_msg_out_length(IpcCommand command, const uint8_t *encodedSt, size_t encodedLen)
{
    if (!_validate_ipc_command(command))
        return STATUS_FAILED;
    return KeyIso_gdbus_msg_handler_table[command].outMsgLengthFunc(encodedSt, encodedLen);
}

// Freeing the memory allocated for the in message structure.
void KeyIso_gdbus_msg_cleanup(void *mem, size_t num, bool shouldFreeMem)
{
    if (num > 0) {
        KeyIso_clear_free(mem, num);
    } else {
        KeyIso_free(mem);
    }
}

// Handling the incoming IPC command.
unsigned char* KeyIso_gdbus_handle_client_message(unsigned int command, const char *senderName, const uint8_t *encodedInSt, size_t encodedInLen, size_t *encodedOutLen, GDBusConnection *connection)
{
    unsigned char *encodedResponse = NULL;
    *encodedOutLen = 0;

    switch (command)
    {
        case IpcCommand_CloseKey:
           encodedResponse = KeyIso_handle_msg_close_key(senderName, encodedInSt, encodedInLen, encodedOutLen);
           break;
        case IpcCommand_RsaPrivateEncryptDecrypt:
           encodedResponse = KeyIso_handle_msg_rsa_private_enc_dec(senderName, encodedInSt, encodedInLen, encodedOutLen);
           break;
        case IpcCommand_EcdsaSign:
           encodedResponse = KeyIso_handle_msg_ecdsa_sign(senderName, encodedInSt, encodedInLen, encodedOutLen);
           break;
        case IpcCommand_ImportSymmetricKey:
           encodedResponse = KeyIso_handle_msg_import_symmetric_key(encodedInSt, encodedInLen, encodedOutLen);
           break;    
        case IpcCommand_SymmetricKeyEncryptDecrypt:
           encodedResponse = KeyIso_handle_msg_symmetric_key_enc_dec(encodedInSt, encodedInLen, encodedOutLen);
           break;
        case IpcCommand_ImportRsaPrivateKey:
            encodedResponse = KeyIso_handle_msg_rsa_import_private_key(encodedInSt, encodedInLen, encodedOutLen);
            break;
        case IpcCommand_ImportEcPrivateKey:
            encodedResponse = KeyIso_handle_msg_ec_import_private_key(encodedInSt, encodedInLen, encodedOutLen);
            break;
        case IpcCommand_OpenPrivateKey:
            encodedResponse = KeyIso_handle_msg_open_private_key(senderName, encodedInSt, encodedInLen, encodedOutLen);                        
            KeyIso_add_gdbus_sender_to_list(connection, senderName);
            break;
        case IpcCommand_GenerateRsaKeyPair:
            encodedResponse = KeyIso_handle_msg_rsa_key_generate(encodedInSt, encodedInLen, encodedOutLen);
            break;
        case IpcCommand_GenerateEcKeyPair:
            encodedResponse = KeyIso_handle_msg_ec_key_generate(encodedInSt, encodedInLen, encodedOutLen);
            break;
        case IpcCommand_RsaPrivateEncryptDecryptWithAttachedKey:
            encodedResponse = KeyIso_handle_msg_rsa_private_enc_dec_with_attached_key(senderName, encodedInSt, encodedInLen, encodedOutLen);
            break;
        case IpcCommand_EcdsaSignWithAttachedKey:
            encodedResponse = KeyIso_handle_msg_ecdsa_sign_with_attached_key(senderName, encodedInSt, encodedInLen, encodedOutLen);
            break;

        default:
           KEYISOP_trace_log_error(NULL, 0, KEYISOP_SERVICE_TITLE, "unrecognized command", "not handled");
           break;   
    }

    return encodedResponse;
}