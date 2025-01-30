/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <stdio.h>
#include "kmppsymcryptwrapper.h"
#include <uuid/uuid.h>

#include "keyisoservicecommon.h"
#include "keyisoservicekey.h"

/* KMPP key usage parameter is a 4-bit value while SymCrypt key usage is a 32-bit value
   This macro converts the KMPP key usage to a SymCrypt key usage flag
   The KMPP key usage is shifted 12 bits to the left to match the SymCrypt key usage flag

    The following are the key usage flags as defined in Symcrypt:
    #define SYMCRYPT_FLAG_ECKEY_ECDSA        (0x1000)
    #define SYMCRYPT_FLAG_ECKEY_ECDH         (0x2000)

    #define SYMCRYPT_FLAG_RSAKEY_SIGN        (0x1000)
    #define SYMCRYPT_FLAG_RSAKEY_ENCRYPT     (0x2000)

    The following are the key usage flags as defined in KMPP:
    #define KMPP_KEY_USAGE_RSA_SIGN_ECDSA    (0x01)   // RSA Sign or ECDSA
    #define KMPP_KEY_USAGE_RSA_ENCRYPT_ECDH  (0x02)   // RSA Encrypt or ECDH
*/
#define KMPP_SHIFT_KEY_USAGE_TO_SYMCRYPT_FLAG     12
#define KMPP_KEY_USAGE_TO_SYMCRYPT_FLAG(usage)   (usage << KMPP_SHIFT_KEY_USAGE_TO_SYMCRYPT_FLAG)
#define KMPP_SYMCRYPT_FLAG_TO_KEY_USAGE(flag)    (flag >> KMPP_SHIFT_KEY_USAGE_TO_SYMCRYPT_FLAG) & 0xFF

#ifdef  __cplusplus
extern "C" {
#endif

/////////////////////////////////////////////////////
///////////// Internal Key Gen methods //////////////
/////////////////////////////////////////////////////

// Initializes static variables
int KEYISO_EC_init_static(void);
void KEYISO_EC_free_static(void);

int KeyIso_rsa_key_generate(
    const uuid_t correlationId,
    unsigned int bitSize,
    unsigned int keyUsage,
    PSYMCRYPT_RSAKEY *pGeneratedKey);

PSYMCRYPT_ECURVE KeyIso_get_curve_by_nid(
    const uuid_t correlationId,
    uint32_t groupNid);

int KeyIso_ec_key_generate(
    const uuid_t correlationId, 
    uint32_t curve_nid,
    unsigned int keyUsage,
    PSYMCRYPT_ECKEY *pGeneratedKey);

KmppKeyType KeyIso_evp_pkey_id_to_KmppKeyType(const uuid_t correlationId, int evp_pkey_id);

#ifdef  __cplusplus
}
#endif