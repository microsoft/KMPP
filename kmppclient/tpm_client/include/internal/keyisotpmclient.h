/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */
#pragma once

#include <openssl/x509.h>
#include "keyisotpmcommon.h"

int KeyIso_tpm_create_p8_from_keydata(
    const KEYISO_TPM_KEY_DATA* inEnKeyData,
    X509_SIG** outP8);

int KeyIso_tpm_create_keydata_from_p8(
    const X509_SIG* inP8,
    KEYISO_TPM_KEY_DATA** keyData);

KEYISO_TPM_CONFIG_ST KeyIso_load_tpm_config(
    const CONF *conf);

void KeyIso_validate_user_privileges(
    KeyIsoSolutionType solutionType);