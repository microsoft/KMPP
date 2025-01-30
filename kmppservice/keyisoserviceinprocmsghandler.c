/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <string.h>

#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisoipccommands.h"
#include "keyisoservicecommon.h"
#include "keyisoipcserviceadapter.h"
#include "keyisoservicemsghandler.h"
#include "keyisoserviceinprocmsghandler.h"

////////////////////////////////////////////////////////////////////////////////////////////
//                        IN-PROC Message Handler Implementation.                         //
////////////////////////////////////////////////////////////////////////////////////////////

// When running in-proc, it is not required to use tiny cbor for message encoding/decoding.
// The in/out bytes are copied to/from message structures.


//////////////////////////////////////////////////////////////////////////////////////
//                                                                                  //
//          Define the IN-PROC implementation of the IPC service functions          //
//                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////

const IPC_SERVICE_FUNCTIONS_TABLE_ST InProcServiceImplementation = {
    .msgPreprocessing = KeyIso_inproc_msg_preprocessing,
    .msgPostprocessing = KeyIso_inproc_msg_postprocessing, 
    .msgInLength = KeyIso_inproc_msg_in_length,
    .msgOutLength = KeyIso_inproc_msg_out_length,
    .msgCleanup = KeyIso_inproc_msg_cleanup,
};
const IPC_SERVICE_FUNCTIONS_TABLE_ST ipcInProcSrvImp = InProcServiceImplementation;

int KeyIso_inproc_msg_preprocessing(IpcCommand command, const uint8_t *inSt, size_t inLen, void **decodedInSt)
{    
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_SERVICE_TITLE, "performing inproc msg preprocessing - no action required");
    
    if (!decodedInSt || !inSt)
        return STATUS_FAILED;

    if (KeyIso_inproc_msg_in_length(command, inSt, inLen) != inLen)
        return STATUS_FAILED;

    *decodedInSt = (void *)inSt;
    return STATUS_OK;
}

uint8_t* KeyIso_inproc_msg_postprocessing(IpcCommand command, void *outSt, size_t *outLen)
{    
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_SERVICE_TITLE, "performing inproc msg postprocessing - no action required");
    return (uint8_t *)outSt;
}

size_t KeyIso_inproc_msg_in_length(IpcCommand command, const uint8_t *encodedSt, size_t encodedLen)
{
    return KeyIso_msg_in_length((int)command, encodedSt, encodedLen, memmove);
}

size_t KeyIso_inproc_msg_out_length(IpcCommand command, const uint8_t *encodedSt, size_t encodedLen)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_SERVICE_TITLE, "performing inproc msg length - no action required");
    return encodedLen;
}

void KeyIso_inproc_msg_cleanup(void *mem, size_t num, bool shouldFreeMem)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_SERVICE_TITLE, "performing inproc msg cleanup - no action required");
    return;
}

// Handling the incoming IPC command.
unsigned char* KeyIso_inproc_handle_client_message(unsigned int command, const char *sender, const uint8_t *inSt, size_t inLen, size_t *outLen)
{
    unsigned char *response = NULL;
    *outLen = 0;

    switch (command)
    {
        case IpcCommand_CloseKey:
           response = KeyIso_handle_msg_close_key(sender, inSt, inLen, outLen);
           break;
        case IpcCommand_RsaPrivateEncryptDecrypt:
           response = KeyIso_handle_msg_rsa_private_enc_dec(sender, inSt, inLen, outLen);
           break;
        case IpcCommand_EcdsaSign:
           response = KeyIso_handle_msg_ecdsa_sign(sender, inSt, inLen, outLen);
           break;
        case IpcCommand_ImportSymmetricKey:
           response = KeyIso_handle_msg_import_symmetric_key(inSt, inLen, outLen);
           break;    
        case IpcCommand_SymmetricKeyEncryptDecrypt:
           response = KeyIso_handle_msg_symmetric_key_enc_dec(inSt, inLen, outLen);
           break;
        case IpcCommand_ImportRsaPrivateKey:
            response = KeyIso_handle_msg_rsa_import_private_key(inSt, inLen, outLen);
            break;
        case IpcCommand_ImportEcPrivateKey:
            response = KeyIso_handle_msg_ec_import_private_key(inSt, inLen, outLen);
            break;
        case IpcCommand_OpenPrivateKey:
            response = KeyIso_handle_msg_open_private_key(sender, inSt, inLen, outLen);                                    
            break;
        case IpcCommand_GenerateRsaKeyPair:
            response = KeyIso_handle_msg_rsa_key_generate(inSt, inLen, outLen);
            break;
        case IpcCommand_GenerateEcKeyPair:
            response = KeyIso_handle_msg_ec_key_generate(inSt, inLen, outLen);
            break;
        case IpcCommand_EcdsaSignWithAttachedKey:
            response = KeyIso_handle_msg_ecdsa_sign_with_attached_key(sender, inSt, inLen, outLen);
            break;
        case IpcCommand_RsaPrivateEncryptDecryptWithAttachedKey:
            response = KeyIso_handle_msg_rsa_private_enc_dec_with_attached_key(sender, inSt, inLen, outLen);
            break;
        default:
           KEYISOP_trace_log_error(NULL, 0, KEYISOP_SERVICE_TITLE, "unrecognized command", "not handled");
           break;   
    }

    return response;
}