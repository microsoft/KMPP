/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <kmppsymcryptwrapper.h>

#ifdef  __cplusplus
extern "C" {
#endif 

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

#ifdef  __cplusplus
}
#endif