/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once 

#include <stdbool.h>
#include "keyisoipccommands.h"

//////////////////////////////////////////////////////////////////////////
//                     IN-PROC Message Handler                          //
//////////////////////////////////////////////////////////////////////////

// The following functions are used in the service message adapter.

int KeyIso_inproc_msg_preprocessing(
    IpcCommand command, 
    const uint8_t *inSt, 
    size_t inLen, 
    void **decodedInSt);

uint8_t* KeyIso_inproc_msg_postprocessing(
    IpcCommand command, 
    void *inSt, 
    size_t *outLen);

size_t KeyIso_inproc_msg_in_length(
    IpcCommand command, 
    const uint8_t *encodedSt, 
    size_t encodedLen);

size_t KeyIso_inproc_msg_out_length(
    IpcCommand command, 
    const uint8_t *encodedSt, 
    size_t encodedLen);

void KeyIso_inproc_msg_cleanup(
    void *mem, 
    size_t num,
    bool shouldFreeMem);

// Inproc message handler
unsigned char* KeyIso_inproc_handle_client_message(
    unsigned int command, 
    const char *sender, 
    const uint8_t *inSt, 
    size_t inLen, 
    size_t *outLen);