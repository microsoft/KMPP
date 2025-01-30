/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <gio/gio.h>
#include <stdbool.h>
#include "keyisoipcserializeapi.h"
#include "keyisoservicekeylistgdbus.h"


/////////////////////////////////////////////////////////////////////////////////////////////////
/*                                 GDBUS Message Handler                                       */
/////////////////////////////////////////////////////////////////////////////////////////////////

int KeyIso_gdbus_msg_preprocessing(
    IpcCommand command, 
    const uint8_t *inSt, 
    size_t inLen, 
    void **decodedInSt);

void KeyIso_gdbus_msg_cleanup(
    void *mem, 
    size_t num,
    bool shouldFreeMem);

uint8_t* KeyIso_gdbus_msg_postprocessing(
    IpcCommand command, 
    void *outSt, 
    size_t *outLen);

size_t KeyIso_gdbus_msg_in_length(
    IpcCommand command, 
    const uint8_t *encodedSt, 
    size_t encodedLen);

size_t KeyIso_gdbus_msg_out_length(
    IpcCommand command, 
    const uint8_t *encodedSt, 
    size_t encodedLen);

// GDBus message handler
unsigned char* KeyIso_gdbus_handle_client_message(
    unsigned int command, 
    const char *senderName, 
    const uint8_t *encodedInSt, 
    size_t encodedInLen, 
    size_t *encodedlOutLen, 
    GDBusConnection *connection);