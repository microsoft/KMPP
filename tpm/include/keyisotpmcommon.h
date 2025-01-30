/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once 
#include <linux/limits.h>
#include <tss2/tss2_esys.h>

typedef uint32_t KEYISO_TPM_RET;

#define KEYISO_TPM_RET_SUCCESS ((KEYISO_TPM_RET) 0)
#define KEYISO_TPM_RET_FAILURE ((KEYISO_TPM_RET) 1)
#define KEYISO_TPM_RET_BAD_PARAM ((KEYISO_TPM_RET) 2)
#define KEYISO_TPM_RET_MEMORY ((KEYISO_TPM_RET) 3)

#define DEFAULT_TCTI_CONFIG "device:/dev/tpmrm0"
#define DEFAULT_NV_INDEX 0x1500020

typedef enum {
    KmppTpmKeyType_Asymmetric,
    KmppTpmKeyType_Symmetric,
    KmppTpmKeyType_Max
} KmppTpmKeyType;

typedef struct KeyIso_tpm_context_st KEYISO_TPM_CONTEXT;
struct KeyIso_tpm_context_st {
    ESYS_CONTEXT* ectx;
};

typedef struct KeyIso_tpm_session_st KEYISO_TPM_SESSION;
struct KeyIso_tpm_session_st {
    ESYS_TR sessionHandle;
    TPM2B_AUTH auth;
    struct {
        TPMT_SYM_DEF symmetric;
        ESYS_TR tpmKey;
        ESYS_TR bind;
        TPM2_SE sessionType;
        TPMI_ALG_HASH authHash;
        TPMA_SESSION attrs;
        TPMA_SESSION mask;
    } params;
    KEYISO_TPM_CONTEXT* tpmContext;
};

typedef struct KeyIso_tpm_key_data_st KEYISO_TPM_KEY_DATA;
struct KeyIso_tpm_key_data_st
{
    TPM2_HANDLE          parentHandle; // Parent if was provided a persistent key parent different then the default SRK
    TPM2B_PUBLIC         pub;
    TPM2B_PRIVATE        priv;   
    TPM2B_DIGEST         auth;        // User authentication password for the key(if needed)
};

typedef struct KeyIso_tpm_key_details_st KEYISO_TPM_KEY_DETAILS;
struct KeyIso_tpm_key_details_st
{
    KEYISO_TPM_CONTEXT* tpmContext;
    ESYS_TR  keyHandle;
    TPM2B_PUBLIC pub;
};

typedef struct KeyIso_tmp_config_st KEYISO_TPM_CONFIG_ST;
struct KeyIso_tmp_config_st {
    TPM2_HANDLE nvIndex;
    char tctiNameConf[PATH_MAX];
};
