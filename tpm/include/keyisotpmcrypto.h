/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <uuid/uuid.h>
#include "keyisotpmcommon.h"

#ifdef  __cplusplus
extern "C" {
#endif

//***********************************
//             RSA                 **
//***********************************

int KeyIso_TPM_rsa_private_decrypt(
    const uuid_t correlationId,
    const KEYISO_TPM_KEY_DETAILS *details,
    unsigned int flen,
    const unsigned char *from,
    unsigned int tlen,
    unsigned char *to, 
    int padding);

// Signs data using the RSA private key (RSA-PKCS1)
int KeyIso_TPM_rsa_sign(
    const uuid_t correlationId,
    const KEYISO_TPM_KEY_DETAILS *details,
    uint32_t mdnid, // Message digest algorithm
    unsigned int mLength,
    const unsigned char *m,
    unsigned int siglen,
    unsigned char* sig);

// RSA-PSS (Probabilistic Signature Scheme) sign
int KeyIso_TPM_pkey_rsa_sign(
    const uuid_t correlationId,
    const KEYISO_TPM_KEY_DETAILS *details,
    uint32_t mdnid,
    unsigned int mLength,
    const unsigned char *m,
    unsigned int siglen,
    unsigned char* sig,
    int padding);

//***********************************
//             ECC                 **
//***********************************
int KeyIso_TPM_ecdsa_sign(
    const uuid_t correlationId,
    const KEYISO_TPM_KEY_DETAILS *details,
    const unsigned char *m,
    unsigned int mLength,
    unsigned char *sig,
    unsigned int siglen);
      
#ifdef  __cplusplus
}
#endif