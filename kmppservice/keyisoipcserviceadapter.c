/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include "keyisoipcserviceadapter.h"

//////////////////////////////////////////////////////////////////////////////////////
//                                                                                  //
//                          KeyIso Message Adapter functions                        //
//                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////

extern const IPC_SERVICE_FUNCTIONS_TABLE_ST ipcSrvImp; 
extern const IPC_SERVICE_FUNCTIONS_TABLE_ST ipcInProcSrvImp;



int KeyIso_service_adapter_generic_msg_preprocessing(IpcCommand command, const uint8_t *inSt, size_t inLen, void **decodedInSt)
{
#ifndef KMPP_TA_COMPILATION
    if (KEYISOP_inProc) {
        return ipcInProcSrvImp.msgPreprocessing(command, inSt, inLen, decodedInSt);
    }
#endif
    return ipcSrvImp.msgPreprocessing(command, inSt, inLen, decodedInSt);
}

uint8_t* KeyIso_service_adapter_generic_msg_postprocessing(IpcCommand command, void *outSt, size_t *outLen)
{
#ifndef KMPP_TA_COMPILATION
    if (KEYISOP_inProc) {
        return ipcInProcSrvImp.msgPostprocessing(command, outSt, outLen);
    }  
#endif
    return ipcSrvImp.msgPostprocessing(command, outSt, outLen);
}

size_t KeyIso_service_adapter_generic_msg_in_get_len(IpcCommand command, const uint8_t *encodedSt, size_t encodedLen)
{
#ifndef KMPP_TA_COMPILATION
    if (KEYISOP_inProc) {
        return ipcInProcSrvImp.msgInLength(command, encodedSt, encodedLen);
    }
#endif
    return ipcSrvImp.msgInLength(command, encodedSt, encodedLen);
}

size_t KeyIso_service_adapter_generic_msg_out_get_len(IpcCommand command, const uint8_t *encodedSt, size_t encodedLen)
{
#ifndef KMPP_TA_COMPILATION
    if (KEYISOP_inProc) {
        return ipcInProcSrvImp.msgOutLength(command, encodedSt, encodedLen);
    }
#endif
    return ipcSrvImp.msgOutLength(command, encodedSt, encodedLen);
}

void KeyIso_service_adapter_generic_msg_cleanup(void *mem, size_t num, bool shouldFreeMem)
{
#ifndef KMPP_TA_COMPILATION
    if (KEYISOP_inProc) {
        return ipcInProcSrvImp.msgCleanup(mem, num, shouldFreeMem);
    }
#endif
    return ipcSrvImp.msgCleanup(mem, num, shouldFreeMem);
}