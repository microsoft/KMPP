/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <string_ext.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "keyisocommon.h"
#include "keyisolog.h"
#include "keyisoservicecommon.h"
#include "kmpptamsghandler.h"
#include "keyisoipcserviceadapter.h"


//////////////////////////////////////////////////////////////////////////////////////
//                                                                                  //
//            Define the TA implementation of the IPC service functions             //
//                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////

const IPC_SERVICE_FUNCTIONS_TABLE_ST ipcSrvImp = {
    .msgPreprocessing = KeyIso_ta_msg_preprocessing,
    .msgPostprocessing = KeyIso_ta_msg_postprocessing,
    .msgInLength = KeyIso_ta_msg_in_length,
    .msgOutLength = NULL,
    .msgCleanup = KeyIso_ta_msg_cleanup,
};

// Wrapper function to match the expected type
static void *_ta_mem_move(void *dest, const void *src, size_t n) {
    return TEE_MemMove(dest, src, (uint32_t)n);
}

static bool _get_and_check_ta_msg_in_structure_size_to_alloc(IpcCommand command, const uint8_t *inSt, size_t inLen)   
{   
    bool isSizeToAllocValid = true;

    // Calculate the size of the structure to be allocated
    size_t sizeToAlloc = KeyIso_ta_msg_in_length(command, inSt, inLen);

    // Checking for integer overflow in the sizeToAlloc calculation or invalid input
    if (sizeToAlloc == 0) {
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_SERVICE_TITLE, "", "sizeToAlloc is 0 probably due to integer overflow or invalid input.",
        "command: %d ", command);
        isSizeToAllocValid = false;

    } else if(sizeToAlloc != inLen) {   // The sizeToAlloc ("real" size) should be equal to the size of the inSt (because inSt in this phase is the serialized struct)
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_SERVICE_TITLE, "", "sizeToAlloc != inLen", "command: %d ", command);
        isSizeToAllocValid = false;
    }

    return isSizeToAllocValid;
}

int KeyIso_ta_msg_preprocessing(IpcCommand command, const uint8_t *inSt, size_t inLen, void **localTAInSt)
{   
    if (inLen == 0) {
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_SERVICE_TITLE, "", "InLen is 0", "command: %d ", command);
        return STATUS_FAILED;
    }

    if (!inSt) {
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_SERVICE_TITLE, "", "InSt is NULL", "command: %d ", command);
        return STATUS_FAILED;
    }

    if (!localTAInSt) {
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_SERVICE_TITLE, "", "LocalTAInSt is NULL", "command: %d ", command);
        return STATUS_FAILED;
    }
    *localTAInSt = NULL;    
    
    // Get the size of the structure to be allocated AND CHECK if it is valid
    if (!_get_and_check_ta_msg_in_structure_size_to_alloc(command, inSt, inLen)) {
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_SERVICE_TITLE, "", "IsSizeToAllocValid is false", "command: %d ", command);
        return STATUS_FAILED;
    }

    // Allocate the local TA memory to be in used from this point.    
    *localTAInSt = TEE_Malloc(inLen, TEE_MALLOC_FILL_ZERO);
    if (*localTAInSt == NULL) {
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_SERVICE_TITLE, "", "*localTAInSt == NULL", "command: %d ", command);
        return STATUS_FAILED;
    }

    // Copying the given data to the local allocated TA memory
    TEE_MemMove(*localTAInSt, inSt, inLen);     

    // Performing the size check again as a concern to race condition due to the fact we are working on shared memory.    
    if (!_get_and_check_ta_msg_in_structure_size_to_alloc(command, *localTAInSt, inLen)) {
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_SERVICE_TITLE, "", "Size check failure after TEE_MemMove", "command: %d ", command);
        return STATUS_FAILED;
    }

    return STATUS_OK;
}

uint8_t* KeyIso_ta_msg_postprocessing(IpcCommand __maybe_unused command, void *outSt, size_t __maybe_unused *outLen)
{    
    return (uint8_t*) outSt;    
}

// Getting the the length of the in message structure.
size_t KeyIso_ta_msg_in_length(IpcCommand command, const uint8_t *inSt, size_t inLen)
{   
    return KeyIso_msg_in_length((int)command, inSt, inLen, _ta_mem_move);
}

// Freeing the allocated memory
void KeyIso_ta_msg_cleanup(void *mem, size_t num, bool shouldFreeMem)
{
    if (mem == NULL) {
        return;
    }
    // This function should free only the input allocated memory (the output will be free in another place)
    if (shouldFreeMem) {
        if (num > 0) {
            memzero_explicit(mem, num);
        }
        TEE_Free(mem);
    }     
}