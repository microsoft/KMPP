/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include "keyisotpmcommon.h"

#ifdef  __cplusplus
extern "C" {
#endif
// Inline function to convert between the TSS2_RC to KEYISO_TPM_RET
KEYISO_TPM_RET KeyIso_convert_ret_val(TSS2_RC rc);

// Get the parent handle if was initalized, otherwise retrieve it from the NVRAM
TSS2_RC KeyIso_tpm_acquire_parent(
    const uuid_t correlationId,
    KEYISO_TPM_CONTEXT* ctx,
    const TPM2_HANDLE parentHandle,
    ESYS_TR* outParent);


#ifdef  __cplusplus
}
#endif
