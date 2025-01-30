/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once 

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "keyisoipccommands.h"


// Define the IPC service function table
typedef struct ipc_service_functions_table_st IPC_SERVICE_FUNCTIONS_TABLE_ST;
struct ipc_service_functions_table_st {
    int (*msgPreprocessing)(IpcCommand command, const uint8_t *inSt, size_t inLen, void **decodedInSt);
    uint8_t* (*msgPostprocessing)(IpcCommand command, void *outSt, size_t *outLen);
    size_t (*msgInLength)(IpcCommand command, const uint8_t *encodedSt, size_t encodedLen);
    size_t (*msgOutLength)(IpcCommand command, const uint8_t *encodedSt, size_t encodedLen);
    void (*msgCleanup)(void *mem, size_t num, bool inputMemScenario);
};

int KeyIso_service_adapter_generic_msg_preprocessing(
    IpcCommand command, 
    const uint8_t *inSt, 
    size_t inLen, 
    void **decodedInSt);

uint8_t* KeyIso_service_adapter_generic_msg_postprocessing(
    IpcCommand command, 
    void *inSt, 
    size_t *outLen);

size_t KeyIso_service_adapter_generic_msg_in_get_len(
    IpcCommand command, 
    const uint8_t *encodedSt, 
    size_t encodedLen);

size_t KeyIso_service_adapter_generic_msg_out_get_len(
    IpcCommand command, 
    const uint8_t *encodedSt, 
    size_t encodedLen);

void KeyIso_service_adapter_generic_msg_cleanup( 
    void *mem, 
    size_t num,
    bool shouldFreeMem);