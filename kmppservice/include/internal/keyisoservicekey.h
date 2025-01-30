/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once
#include "keyisocommon.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*
*     Enums
*/
typedef enum {
    KmppKeyType_epkey = 0, // EVP_PKEY used for backward compatibility, only when key isolation service can use OpenSSL
    KmppKeyType_rsa, 
    KmppKeyType_ec, 
    KmppKeyType_end
} KmppKeyType;

// Cast to void* to solve GCC false positive warning for container_of macro as described in https://mail.openvswitch.org/pipermail/ovs-dev/2010-May/245717.html
#define CONTAINER_OF(ptr, type, member) \
    ((type *)(void *)((char *)(ptr) - offsetof(type, member)))

typedef struct keyiso_reference_st KEYISO_REFERENCE_ST;
struct keyiso_reference_st {
    void (*free)(const uuid_t correlationId, const  KEYISO_REFERENCE_ST*);
    int count;
};

static inline void KeyIso_reference_up(const KEYISO_REFERENCE_ST* ref)
{
    if (ref) {
        __sync_add_and_fetch((int *)&ref->count, 1);
    }
}

static inline void KeyIso_reference_free(
    const uuid_t correlationId, 
    const KEYISO_REFERENCE_ST *ref)
{
    if (ref && __sync_sub_and_fetch((int *)&ref->count, 1) == 0) {
        ref->free(correlationId, ref);
    }
}

/* Key list */
typedef struct KMPP_KEY_st {
    KmppKeyType type;
    void *key;
    KEYISO_REFERENCE_ST refCounter;
} KMPP_KEY, *PKMPP_KEY;

PKMPP_KEY KeyIso_kmpp_key_create( 
     const uuid_t correlationId,
     KmppKeyType type, void *keyPtr);

void KeyIso_kmpp_key_free(
    const uuid_t correlationId, 
    const KEYISO_REFERENCE_ST *refcount);

/* 
   The key parameters in the reference count APIs are const because in some cases users
   that uses these API's have a const pointer to the key and we do not wand such user to be forced
   to cast away the const each time up ref or down ref is needed.
   In such way the const cast away is done inside the reference counter functions which saves the API user
   the need of doing dangers casts .
*/

static inline void KeyIso_SERVER_key_up_ref(const PKMPP_KEY pkey) 
{
    if(pkey) {
        KeyIso_reference_up(&pkey->refCounter);
    }
}

static inline void KeyIso_SERVER_free_key(
    const uuid_t correlationId, 
    const PKMPP_KEY pkey)
{
    if(pkey) {
        KeyIso_reference_free(correlationId, &pkey->refCounter);
    }
}

#ifdef  __cplusplus
}
#endif