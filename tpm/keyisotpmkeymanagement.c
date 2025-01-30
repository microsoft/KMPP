/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <string.h>
#include <openssl/obj_mac.h>
#include <tss2/tss2_tpm2_types.h>

#include "keyisotpmkeymanagement.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisotpmcommon.h"
#include "keyisotpmutils.h"
#include "keyisotpmsetup.h"

#define KMPP_DEFAULT_EXPONENT 65537
#define KMPP_DEFAULT_RSA_BITS 2048

static TPM2B_PUBLIC tpmRsaPublickeyTemplate = {
    .publicArea = {
        .type = TPM2_ALG_RSA,
        .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |          // The object can be used by providing the  correct user authorization(password or a HMAC session)
                             TPMA_OBJECT_FIXEDTPM |             // The object is permanently associated with the TPM.
                             TPMA_OBJECT_FIXEDPARENT |          // The parent of the object is fixed and cannot be changed.
                             TPMA_OBJECT_SENSITIVEDATAORIGIN |  // The sensitive data of the object was created by the TPM.
                             TPMA_OBJECT_NODA),                 // The object is not subject to dictionary attack protections
        .authPolicy.size = 0,
        .parameters.rsaDetail = {
             .symmetric = {
                 .algorithm = TPM2_ALG_NULL,
                 .keyBits.aes = 0,
                 .mode.aes = 0,
              },
             .scheme = {
                .scheme = TPM2_ALG_NULL,
                .details = {}
             },
             .keyBits = KMPP_DEFAULT_RSA_BITS,
             .exponent = KMPP_DEFAULT_EXPONENT,
         },
        .unique.rsa.size = 0
     }
};

static TPM2B_PUBLIC tpmEcPublickeyTemplate = {
    .publicArea = {
        .type = TPM2_ALG_ECC,
        .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                             TPMA_OBJECT_FIXEDTPM |
                             TPMA_OBJECT_FIXEDPARENT |
                             TPMA_OBJECT_SENSITIVEDATAORIGIN |
                             TPMA_OBJECT_NODA),
        .parameters.eccDetail = {
             .curveID = 0,
             .symmetric = {
                 .algorithm = TPM2_ALG_NULL,
                 .keyBits.aes = 0,
                 .mode.aes = 0,
              },
             .scheme = {
                .scheme = TPM2_ALG_NULL,
                .details = {}
             },
             .kdf = {
                .scheme = TPM2_ALG_NULL,
                .details = {}
             },
         },
        .unique.ecc = { .x.size = 0, .y.size = 0 }
     }
};

static KEYISO_TPM_RET _cleanup_generate_tpm_key(
    KEYISO_TPM_RET ret,
    const TPM2_HANDLE parentHandle,
    ESYS_TR parent,
    KEYISO_TPM_CONTEXT* tpmContext,
    KEYISO_TPM_KEY_DATA* keyData)
{

    if (ret != KEYISO_TPM_RET_SUCCESS)
    {
        KeyIso_free(keyData);
    }

    KeyIso_tpm_free_context(&tpmContext);
    return ret;
}

#define _CLEANUP_GENERATE_TPM_KEY(ret) \
     _cleanup_generate_tpm_key(ret, parentHandle, parent, tpmContext, keyData)

// Common function to generate key
static KEYISO_TPM_RET _generate_tpm_key(
    const uuid_t correlationId,
    const char* password,
    const TPM2B_PUBLIC* inPublic,
    const TPM2_HANDLE parentHandle,
    KEYISO_TPM_KEY_DATA** outKeyData)
{
    const char* title = KEYISOP_TPM_KEY_TITLE;
    TSS2_RC rc;
    ESYS_TR parent = ESYS_TR_NONE;
    TPM2B_PUBLIC* keyPublic = NULL;
    TPM2B_PRIVATE* keyPrivate = NULL;
    KEYISO_TPM_CONTEXT* tpmContext = NULL;
    TPM2B_DATA outsideInfo = {.size = 0,};
    TPML_PCR_SELECTION creationPCR = {.count = 0,};
    
    // Defines the sensetive part of the key
    TPM2B_SENSITIVE_CREATE inSensitive = {
        .sensitive = {
            .userAuth = {
                 .size = 0,
             },
            .data = {
                 .size = 0,
             }
        }
    };

    if(outKeyData == NULL || inPublic == NULL)
    {
        KEYISOP_trace_log_error(correlationId, 0, title, "can't generate key", "Invalid parameter - cant be NULL");
        return KEYISO_TPM_RET_BAD_PARAM;
    }
    
    *outKeyData = NULL;
    uint16_t alg = inPublic->publicArea.type;

    KEYISO_TPM_KEY_DATA* keyData = (KEYISO_TPM_KEY_DATA*)KeyIso_zalloc(sizeof(*keyData));
    if (keyData == NULL) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "can't generate key", "Memory allocation failed", "alg: %d", alg);
        return KEYISO_TPM_RET_MEMORY;
    }
    keyData->parentHandle = parentHandle;
    keyData->auth.size = 0;

    if (password) {
        size_t passwordLength = strlen(password);
        if (passwordLength > sizeof(keyData->auth.buffer) - 1) {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "can't generate key", "Invalid parameter - password is too long", "password length: %lu, alg:%d", passwordLength, alg);
            return _CLEANUP_GENERATE_TPM_KEY(KEYISO_TPM_RET_BAD_PARAM);
        }

        inSensitive.sensitive.userAuth.size = passwordLength;
        memcpy(&inSensitive.sensitive.userAuth.buffer, password, passwordLength);

        // Copy also to the key data so it will be saved and retrievd upon key usage
        keyData->auth.size = passwordLength;
        memcpy(&keyData->auth.buffer, password, keyData->auth.size);
    }
    
    rc = KeyIso_tpm_create_context(correlationId, &tpmContext);
    if ( rc != TSS2_RC_SUCCESS) {

        KEYISOP_trace_log_error_para(correlationId, 0, title, "can't generate key", "KeyIso_tpm_create_context failed", "error: %d, alg:%d", rc, alg);
        return _CLEANUP_GENERATE_TPM_KEY(KeyIso_convert_ret_val(rc));
    }

   rc = KeyIso_tpm_acquire_parent(correlationId, tpmContext, parentHandle, &parent);
    if ( rc != TSS2_RC_SUCCESS) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "can't generate key", "KeyIso_tpm_acquire_parent failed", "error: %d, alg:%d", rc, alg);
        return _CLEANUP_GENERATE_TPM_KEY(KeyIso_convert_ret_val(rc));
    }

    rc = Esys_Create(tpmContext->ectx, 
                    parent,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                    &inSensitive, inPublic, &outsideInfo, &creationPCR,
                    &keyPrivate, &keyPublic,
                    NULL, NULL, NULL);

    if (rc != TSS2_RC_SUCCESS) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "can't generate key", "Esys_Create failed", "error: %d, alg:%d", rc, alg);
        return _CLEANUP_GENERATE_TPM_KEY(KeyIso_convert_ret_val(rc));
    }

    keyData->parentHandle = parentHandle;
    keyData->priv = *keyPrivate;
    keyData->pub = *keyPublic;
    *outKeyData = keyData;

    // Free the memory allocated by Esys_Create
    Esys_Free(keyPrivate);
    Esys_Free(keyPublic);

    KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete key generated", "alg:%d", alg);
    return _CLEANUP_GENERATE_TPM_KEY(KEYISO_TPM_RET_SUCCESS);
}

// RSA key generation function
KEYISO_TPM_RET KeyIso_rsa_generate_tpm_key(
    const uuid_t correlationId,
    const char* password,
    uint32_t exponent,
    unsigned int rsaBits, 
    TPMA_OBJECT objectAttributes, // Attributes of the TPM object(Can be used to set the key usage)
    TPM2_HANDLE parentHandle,
    KEYISO_TPM_KEY_DATA** outKeyData)
{
    // Defines the public part of the key
    TPM2B_PUBLIC inPublic = tpmRsaPublickeyTemplate;
    inPublic.publicArea.objectAttributes |= objectAttributes;

    if (rsaBits > 0)
        inPublic.publicArea.parameters.rsaDetail.keyBits = rsaBits;

    if (exponent > 0)
        inPublic.publicArea.parameters.rsaDetail.exponent = exponent;

    return _generate_tpm_key(correlationId, password, &inPublic, parentHandle, outKeyData);
}

// ECC key generation function
KEYISO_TPM_RET KeyIso_ecc_generate_tpm_key(
    const uuid_t correlationId,
    const char* password,
    TPMI_ECC_CURVE curve,
    TPMA_OBJECT objectAttributes,
    TPM2_HANDLE parentHandle,
    KEYISO_TPM_KEY_DATA** outKeyData)
{
    TPM2B_PUBLIC inPublic = tpmEcPublickeyTemplate;
    
    inPublic.publicArea.objectAttributes |= objectAttributes;
    inPublic.publicArea.parameters.eccDetail.curveID = curve;
    return _generate_tpm_key(correlationId, password, &inPublic, parentHandle, outKeyData);
}

static KEYISO_TPM_RET _clear_load_tpm_key(
    TSS2_RC rc,
    KEYISO_TPM_KEY_DETAILS* tpmKeyDetails)
{
    if (rc != TSS2_RC_SUCCESS) {
     KeyIso_free(tpmKeyDetails);
    }
    
    return KeyIso_convert_ret_val(rc);
}

KEYISO_TPM_RET KeyIso_load_tpm_key(
    const uuid_t correlationId,
    KEYISO_TPM_CONTEXT* tpmContext,
    KEYISO_TPM_KEY_DATA* encryptedKeyData,
    KEYISO_TPM_KEY_DETAILS** outTpmKeyDetails) // The loaded key details, need to be freed by the caller (KeyIso_free)
{
    TSS2_RC rc;
    ESYS_TR parent = ESYS_TR_NONE;
    const char* title = KEYISOP_TPM_KEY_TITLE;

    if (outTpmKeyDetails == NULL || tpmContext == NULL || encryptedKeyData == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "can't load key", "Invalid parameter - can't be NULL");
        return KEYISO_TPM_RET_BAD_PARAM;
    }

    *outTpmKeyDetails = NULL;
    KEYISO_TPM_KEY_DETAILS *tpmKeyDetails = (KEYISO_TPM_KEY_DETAILS*)KeyIso_zalloc(sizeof(*tpmKeyDetails));


    if (encryptedKeyData->parentHandle != ESYS_TR_NONE && encryptedKeyData->parentHandle != TPM2_RH_OWNER) {
        // We received a handle to a persistent parent key to load the key under
        rc = Esys_TR_FromTPMPublic(tpmContext->ectx, encryptedKeyData->parentHandle,
                                   ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &parent);

        if (rc != TSS2_RC_SUCCESS) {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "can't load key", "Esys_TR_FromTPMPublic failed", "error: %d", rc);
            return _clear_load_tpm_key(rc, tpmKeyDetails);
        }
    } else {
        // Get the default SRK and then use it to load the keys
        rc = KeyIso_tpm_acquire_parent(correlationId, tpmContext, ESYS_TR_NONE, &parent);
        if (rc != TSS2_RC_SUCCESS) {
            KEYISOP_trace_log_error_para(correlationId, 0, title,"can't load key", "KeyIso_tpm_acquire_parent failed", "error: %d", rc);
            return _clear_load_tpm_key(rc, tpmKeyDetails);
        }
    }

    tpmKeyDetails->tpmContext = tpmContext;

    // Load the key
    // We do not need to create an authorization session here, we use the ESYS_TR_PASSWORD as the authorization with the parent key in our case is password(which is assumed to be empty in the first phase)
    // In the future, when we will support more complex form of authorization (like a policy) or use a complex feature like the "Command and response parameter encryption is a feature", we will need to create a session and use it here and use it instead of ESYS_TR_PASSWORD
    rc = Esys_Load(tpmContext->ectx, parent, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &encryptedKeyData->priv, &encryptedKeyData->pub, &tpmKeyDetails->keyHandle);
    if (rc != TSS2_RC_SUCCESS) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "can't load key", "Esys_Load failed", "error: %d", rc);
        return _clear_load_tpm_key(rc, tpmKeyDetails);
    }
    
    rc = Esys_TR_SetAuth(tpmContext->ectx, tpmKeyDetails->keyHandle, &encryptedKeyData->auth);
    if (rc != TSS2_RC_SUCCESS) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "can't load key", "Esys_TR_SetAuth failed", "error: %d", rc);
        return _clear_load_tpm_key(rc, tpmKeyDetails);
    }
        
    tpmKeyDetails->pub = encryptedKeyData->pub;
    *outTpmKeyDetails = tpmKeyDetails;

    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete: key was successfully loaded");
    return _clear_load_tpm_key( TSS2_RC_SUCCESS, tpmKeyDetails);
}

void KeyIso_tpm_key_close(const uuid_t correlationId, 
                          KEYISO_TPM_KEY_DETAILS* tpmKeyDetails)
{
    if (!tpmKeyDetails || !tpmKeyDetails->tpmContext)
    {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_TPM_KEY_TITLE, "failed to close key", "Invalid parameter - can't be NULL");
        return;
    }
    
    TSS2_RC rc = Esys_FlushContext(tpmKeyDetails->tpmContext->ectx, tpmKeyDetails->keyHandle);
    if (rc != TSS2_RC_SUCCESS) {
        KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_TPM_KEY_TITLE, "failed to close key", "Esys_FlushContext failed", "error: %d", rc);
    }
    
}

KEYISO_TPM_RET KeyIso_import_key_to_tpm(
    const uuid_t correlationId,
    TPM2B_PUBLIC* parentPub,
    TPM2B_ENCRYPTED_SECRET* encryptedSeed,
    const char* objectAuthValue,
    const char* inputKeyFile,
    const char* passwordIn,
    KEYISO_TPM_KEY_DATA** outKeyData)
{
    //  Temporary ignore the unused parameter warning on this file
    (void)correlationId; 
    (void)parentPub; 
    (void)encryptedSeed; 
    (void)objectAuthValue; 
    (void)inputKeyFile; 
    (void)passwordIn;
    (void)outKeyData;

    KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_TPM_KEY_TITLE, "can't import key", "Not implemented", "error: %d", 0);
    return KEYISO_TPM_RET_FAILURE;
}

uint32_t KeyIso_tpm_curve_to_ossl(TPMI_ECC_CURVE curve)
{
    switch (curve) {
        case TPM2_ECC_NIST_P192:
            return (uint32_t)NID_X9_62_prime192v1;
        case TPM2_ECC_NIST_P224:
            return (uint32_t)NID_secp224r1;
        case TPM2_ECC_NIST_P256:
            return (uint32_t)NID_X9_62_prime256v1;
        case TPM2_ECC_NIST_P384:
            return (uint32_t)NID_secp384r1;
        case TPM2_ECC_NIST_P521:
            return (uint32_t)NID_secp521r1;
        default:
            return (uint32_t)NID_undef;
    }
}

TPMI_ECC_CURVE KeyIso_ossl_curve_to_tpm(uint32_t curve)
{
    switch (curve) {
        case NID_X9_62_prime192v1:
            return (uint32_t)TPM2_ECC_NIST_P192;
        case NID_secp224r1:
            return (uint32_t)TPM2_ECC_NIST_P224;
        case NID_X9_62_prime256v1:
            return (uint32_t)TPM2_ECC_NIST_P256;
        case NID_secp384r1:
            return (uint32_t)TPM2_ECC_NIST_P384;
        case NID_secp521r1:
            return (uint32_t)TPM2_ECC_NIST_P521;
        default:
            return (uint32_t)TPM2_ECC_NONE;
    }
}