/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>

#include "keyisocommon.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisoclient.h"
#include "keyisoclientinternal.h"
#include "p_keyiso.h"
#include "p_keyiso_err.h"


void* KeyIso_keymgmt_load(const void *reference, size_t reference_sz)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    KEYISO_PROV_PKEY *pkey = NULL;
 
    if (!reference || reference_sz != sizeof(pkey)) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return NULL;
    }

    // The contents of the reference is the address to our object
    pkey = *(KEYISO_PROV_PKEY**)reference;
    // We grabbed it, so we detach it
    *(KEYISO_PROV_PKEY**)reference = NULL;

    return pkey;
}

static int _cleanup_keymgmt_common_import(int ret, KeyIsoErrReason reason, EVP_PKEY_CTX *ctx) 
{
    if (ret != STATUS_OK) {
        KMPPerr(reason);
    }

    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }   
    
    return ret;
}

#define _CLEANUP_KEYMGMT_COMMON_IMPORT(ret, reason) \
        _cleanup_keymgmt_common_import(ret, reason, ctx)

int KeyIso_keymgmt_common_import(KEYISO_PROV_PKEY *pkey, const char *algName, int selection, const OSSL_PARAM params[])
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *tmpKey = NULL; 

    if (!pkey) {
        return _CLEANUP_KEYMGMT_COMMON_IMPORT(STATUS_FAILED, KeyIsoErrReason_InvalidParams);
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, algName, KEYISO_OSSL_DEFAULT_PROV_PROPQ);
    if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) <= 0) {
        return _CLEANUP_KEYMGMT_COMMON_IMPORT(STATUS_FAILED, KeyIsoErrReason_OperationFailed);
    }

    if(EVP_PKEY_fromdata(ctx, &tmpKey, selection, (OSSL_PARAM*)params) <= 0 || !tmpKey) {
        return _CLEANUP_KEYMGMT_COMMON_IMPORT(STATUS_FAILED, KeyIsoErrReason_FailedToImport);
    }

    pkey->pubKey = tmpKey;
    tmpKey = NULL;
    return _CLEANUP_KEYMGMT_COMMON_IMPORT(STATUS_OK, KeyIsoErrReason_NoError);
}

int KeyIso_keymgmt_common_export(KEYISO_PROV_PKEY *pkey, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
 
    OSSL_PARAM *params = NULL;

    if (!pkey) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    if(!EVP_PKEY_todata(pkey->pubKey, selection, &params)) {
        KMPPerr(KeyIsoErrReason_FailedToExport);
        return STATUS_FAILED;
    }

    return param_cb(params, cbarg);
}

int KeyIso_keymgmt_match(const KEYISO_PROV_PKEY *pkey1, const KEYISO_PROV_PKEY *pkey2, int selection)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    if (pkey1 == NULL || pkey2 == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    //  Compare parameters only - relevant for EC key
    if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)
        if (!EVP_PKEY_parameters_eq(pkey1->pubKey, pkey2->pubKey))
            return STATUS_FAILED;

    //  Compare Keys
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) {
        if (!EVP_PKEY_eq(pkey1->pubKey, pkey2->pubKey))
            return STATUS_FAILED;
    }

    return STATUS_OK;
}

int KeyIso_keymgmt_has(const KEYISO_PROV_PKEY *pkey, int selection)
{
    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start", "selection: %d", selection);

    if (pkey == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    //  Check if we set the public key 
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (!pkey->pubKey)
            return STATUS_FAILED;
    }

    //  Check if we have key ctx
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (!pkey->keyCtx)
            return STATUS_FAILED;
    }

    return STATUS_OK;
}
