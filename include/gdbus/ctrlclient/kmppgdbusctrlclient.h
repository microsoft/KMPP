/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <gio/gio.h>

#ifdef  __cplusplus
extern "C" {
#endif

int KMPP_GDBUS_open_shared_mem(
    KEYISO_SHARED_MEM *sharedMem);

void KMPP_GDBUS_close_shared_mem(
    KEYISO_SHARED_MEM *sharedMem);

int KMPP_GDBUS_CLIENT_cert_ctrl(
    const uuid_t correlationId,
    KEYISO_SHARED_MEM *sharedMem,
    int ctrl,
    int location,
    int format,
    int length,
    const unsigned char *bytes);

#ifdef  __cplusplus
}
#endif
