/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once
#include <uuid/uuid.h>
#include <tss2/tss2_esys.h>
#include "keyisotpmcommon.h"

#ifdef  __cplusplus
extern "C" {
#endif

TSS2_RC KeyIso_tpm_create_context(
    const uuid_t correlationId,
    KEYISO_TPM_CONTEXT** ppCtx);

void KeyIso_tpm_free_context(
    KEYISO_TPM_CONTEXT** pCtx);

TSS2_RC KeyIso_tpm_create_session(
    const uuid_t correlationId,
    KEYISO_TPM_CONTEXT* tpmCont,      // The context to create the session in
    ESYS_TR tpmKey,                   // The key to bind the session to, can provide an additional layer of security when you want to make sure that the session is only used with a specific key
    TPM2B_AUTH const* authValue,      // The authentication value(password) for the session
    KEYISO_TPM_SESSION** outSession); // Should be freed by the caller(KeyIso_tpm_session_free)

void KeyIso_tpm_session_free(
    const uuid_t correlationId,
    KEYISO_TPM_SESSION* pSession);

void KeyIso_tpm_config_set(
    const KEYISO_TPM_CONFIG_ST newConfig);
#ifdef  __cplusplus
}
#endif