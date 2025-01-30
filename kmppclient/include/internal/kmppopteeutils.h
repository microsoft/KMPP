/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <stddef.h>

#include "keyisoipcgenericmessage.h"

size_t KeyIso_get_estimate_out_len(int command, IPC_SEND_RECEIVE_ST *ipcSt);