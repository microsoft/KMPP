/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <kmppsymcryptwrapper.h>

#ifdef  __cplusplus
extern "C" {
#endif


// Smallest supported curve is P192 => 24 * 2 byte SymCrypt signatures
#define KMPP_ECDSA_MIN_SYMCRYPT_SIGNATURE_LEN 48
// Largest supported curve is P521 => 66 * 2 byte SymCrypt signatures
#define KMPP_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN 132


/*
*    Structures
*/

typedef struct
{
    PCSYMCRYPT_OID pHashOIDs;
    size_t         nOIDCount;
    uint32_t       flags;
} KMPP_RSA_PKCS1_PARAMS;


/*
*    Functions
*/
PCSYMCRYPT_HASH KeyIso_get_symcrypt_hash_algorithm(
    uint32_t mdnid);

const KMPP_RSA_PKCS1_PARAMS* KeyIso_get_rsa_pkcs1_params(
    int32_t mdnid);

int32_t KeyIso_get_expected_hash_length(
    int32_t mdnid);

    
int32_t KeyIso_get_curve_nid_from_symcrypt_curve(
    const uuid_t correlationId,
    PCSYMCRYPT_ECURVE pCurve);

// Initializes static variables
int KEYISO_EC_init_static(void);
void KEYISO_EC_free_static(void);

PSYMCRYPT_ECURVE KeyIso_get_curve_by_nid(
    const uuid_t correlationId,
    uint32_t groupNid);

#ifdef  __cplusplus
}
#endif
