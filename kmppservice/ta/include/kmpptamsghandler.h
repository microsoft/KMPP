/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#ifndef TA_MSG_HANDLER_H
#define TA_MSG_HANDLER_H

#include <stddef.h>
#include <stdbool.h>
#include "keyisoipccommands.h"


/////////////////////////////////////////////////////////////////////////////////////////////////
/*                                 TA Message Handler                                          */
/////////////////////////////////////////////////////////////////////////////////////////////////

int KeyIso_ta_msg_preprocessing(
    IpcCommand command, 
    const uint8_t *inSt, 
    size_t inLen, 
    void **decodedInSt);

 uint8_t* KeyIso_ta_msg_postprocessing(
    IpcCommand command, 
    void *outSt, 
    size_t *outLen);

size_t KeyIso_ta_msg_in_length(
    IpcCommand command, 
    const uint8_t *encodedSt, 
    size_t encodedLen);

void KeyIso_ta_msg_cleanup(
    void *mem, 
    size_t num,
    bool shouldFreeMem);

#endif /*TA_MSG_HANDLER_H*/