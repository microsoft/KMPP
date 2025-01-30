/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once
#include <tss2/tss2_tpm2_types.h>
#include <uuid/uuid.h>
#include "keyisotpmcommon.h"

#ifdef  __cplusplus
extern "C" {
#endif 

KEYISO_TPM_RET KeyIso_rsa_generate_tpm_key(
    const uuid_t correlationId,
    const char* password,        // Currently the password is stored in the returned outKeyData, it is the API user responsibility to be save it securely
    uint32_t exponent,            // The exponent of the RSA key (defaults to 65537 if passed 0).
    unsigned int rsaBits,         // The length of the RSA key (defaults to 2048 if passed 0).
    TPMA_OBJECT objectAttributes, // Sets TPM object's security properties and usage capabilities.
    TPM2_HANDLE parentHandle,
    KEYISO_TPM_KEY_DATA** outKeyData);

KEYISO_TPM_RET KeyIso_ecc_generate_tpm_key(
    const uuid_t correlationId,
    const char* password,
    TPMI_ECC_CURVE curve,
    TPMA_OBJECT objectAttributes,       // Sets TPM object's security properties and usage capabilities.
    TPM2_HANDLE parentHandle,
    KEYISO_TPM_KEY_DATA** outKeyData); // The generated key data. The output buffer must be freed by the caller

void KeyIso_tpm_key_close(
    const uuid_t correlationId,
    KEYISO_TPM_KEY_DETAILS* details);

KEYISO_TPM_RET KeyIso_load_tpm_key(
    const uuid_t correlationId,
    KEYISO_TPM_CONTEXT* tpmContext,
    KEYISO_TPM_KEY_DATA* encryptedKeyData,
    KEYISO_TPM_KEY_DETAILS** outTpmKeyDetails); // The loaded key details. The output buffer must be freed by the caller

KEYISO_TPM_RET KeyIso_import_key_to_tpm(
    const uuid_t correlationId,
    TPM2B_PUBLIC* parentPub,
    TPM2B_ENCRYPTED_SECRET* encryptedSeed,
    const char* objectAuthValue,
    const char* inputKeyFile,
    const char* passwordIn,
    KEYISO_TPM_KEY_DATA** outKeyData); // The imported key data. The output buffer must be freed by the caller

// Convert TPM curve to OpenSSL curve.
uint32_t KeyIso_tpm_curve_to_ossl(TPMI_ECC_CURVE curve);

// Convert OpenSSL curve to TPM curve.
TPMI_ECC_CURVE KeyIso_ossl_curve_to_tpm(uint32_t curve);

#ifdef  __cplusplus
}
#endif