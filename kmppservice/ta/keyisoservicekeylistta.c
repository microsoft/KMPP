/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>

#include "keyisoservicekeylist.h"
#include "keyisoservicekeylistta.h"


//////////////////////////////////////////////////////////////////////////////////////
//
// Define the TA implementation of the key list assist functions
//
//////////////////////////////////////////////////////////////////////////////////////
const KEY_LIST_ASSIST_FUNCTIONS_TABLE_ST TAKeyListFnctImp = {    
    .readLock = NULL,
    .writeLock = NULL,
    .readUnlock = NULL,
    .writeUnlock = NULL,
    .initLocks = NULL,
    .clearLocks = NULL,
    .compareSender = KeyIso_ta_compare_sender,
};

const KEY_LIST_ASSIST_FUNCTIONS_TABLE_ST keyListFunctionTable = TAKeyListFnctImp;

int KeyIso_ta_compare_sender(
    const char* str1,
    const char* str2)
{
    return str1 == str2;
}