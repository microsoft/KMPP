/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <openssl/err.h>

#include "p_keyiso_err.h"
#include "keyisolog.h"


static ERR_STRING_DATA KMPP_ERR_library_string[] = {
    {0, "kmppprovider"},  // library name
    {0, NULL}
};

static ERR_STRING_DATA KMPP_str_reasons[] = {
    {ERR_PACK(0, 0, KeyIsoErrReason_AllocFailure), "allocation failure"},
    {ERR_PACK(0, 0, KeyIsoErrReason_OperationFailed), "operation failed"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToImport), "failed to import key"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToExport), "failed to export"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToInitProvider), "failed to initialize the provider"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToGetBio), "failed to get bio core ctx"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToGetLibCtx), "failed to get lib ctx"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToGetParams), "failed to get parameters"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToGetPadding), "failed to get padding"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToGetKeyBytes), "failed to get key bytes"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToGetPubKey), "failed to get public key"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToGetKeyType), "failed to get key type"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToGetKeyCtx), "failed to get key context"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToGetProvKey), "failed to get provider key"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToLoadProvKey), "failed to load provider"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToGetUri), "failed to get URI"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToSetParams), "failed to set parameters"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToGenerateKey), "failed to generate key pair"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToCreatePfx), "failed to create encrypted PFX"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToCreateCert), "failed to create X509 Cert with public key"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToEncodePem), "failed to encode PEM file"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToDecodePem), "failed to decode PEM file"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToFormatKeyId), "failed to format keyId"},
    {ERR_PACK(0, 0, KeyIsoErrReason_UnsupportedType), "unsupported type"},
    {ERR_PACK(0, 0, KeyIsoErrReason_UnsupportedSelection), "unsupported selection"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToSetKeyAttributes), "failed to set key attributes"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToGetConf), "failed to get configuration"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToEditAltNamesSection), "failed to edit alt names section"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToDeriveInit), "failed to initialize key derivation"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToSetDerivedKeyPeer), "failed to set peer key for derivation"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToDeriveKey), "failed to derive shared secret"},
    {ERR_PACK(0, 0, KeyIsoErrReason_UnsupportedScheme), "unsupported scheme"},
    {ERR_PACK(0, 0, KeyIsoErrReason_UnsupportedPadding), "unsupported padding"},
    {ERR_PACK(0, 0, KeyIsoErrReason_UnsupportedDataType), "unsupported data type"},
    {ERR_PACK(0, 0, KeyIsoErrReason_UnsupportedSaltLen), "unsupported salt length"},
    {ERR_PACK(0, 0, KeyIsoErrReason_UnsupportedAlgorithm), "unsupported algorithm"},
    {ERR_PACK(0, 0, KeyIsoErrReason_UnsupportedNumberOfPrimes), "unsupported number of primes"},
    {ERR_PACK(0, 0, KeyIsoErrReason_UnsupportedFormat), "unsupported format"},
    {ERR_PACK(0, 0, KeyIsoErrReason_UnsupportedKeyType), "unsupported key type"},
    {ERR_PACK(0, 0, KeyIsoErrReason_UnsupportedCurve), "unsupported curve"},
    {ERR_PACK(0, 0, KeyIsoErrReason_InvalidStoreCtx), "invalid store context"},
    {ERR_PACK(0, 0, KeyIsoErrReason_InvalidMsgDigest), "invalid message digest"},
    {ERR_PACK(0, 0, KeyIsoErrReason_InvalidParams), "invalid parameters"},
    {ERR_PACK(0, 0, KeyIsoErrReason_InvalidKeySize), "invalid key size"},
    {ERR_PACK(0, 0, KeyIsoErrReason_InvalidKeyId), "invalid key type"},
    {ERR_PACK(0, 0, KeyIsoErrReason_InvalidLength), "invalid length"},
    {ERR_PACK(0, 0, KeyIsoErrReason_InvalidCurve), "invalid curve"},
    {ERR_PACK(0, 0, KeyIsoErrReason_HeaderNotFound), "header not found"},
    {ERR_PACK(0, 0, KeyIsoErrReason_InvalidSignatureLength), "invalid signature length"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedEncodingPublicKey), "failed to encode public key"},
    {ERR_PACK(0, 0, KeyIsoErrReason_FailedToLoadKeyForKeysInUse), "failed to load key for keys in use"},
    {0, NULL}
};

static int lib_code = 0;
static int error_loaded = 0;

int ERR_load_KMPP_strings(void)
{
    if (lib_code == 0) {
        lib_code = ERR_get_next_error_library();
    }

    if (!error_loaded) {
        // Binding the library name "kmppprovider" to the library code
        KMPP_ERR_library_string[0].error = ERR_PACK(lib_code, 0, 0);
        ERR_load_strings(lib_code, KMPP_ERR_library_string);
        // Binding the error reasons to the library code
        ERR_load_strings(lib_code, KMPP_str_reasons);
        error_loaded = 1;
    }
    return 1;
}

void ERR_unload_KMPP_strings(void)
{
    if (error_loaded) {
        ERR_unload_strings(lib_code, KMPP_str_reasons);
        error_loaded = 0;
    }
}

void ERR_KMPP_error(int reason)
{
    if (lib_code == 0) {
        lib_code = ERR_get_next_error_library();
    }

    if (reason != KeyIsoErrReason_NoError) {
        ERR_raise(lib_code, reason);
    }
}

void ERR_KMPP_error_para(int reason, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    char paraBuf[KEYISOP_TRACELOG_PARA_LENGTH];
    if (vsnprintf(paraBuf, sizeof(paraBuf), fmt, args) < 0) {
        *paraBuf = '\0';
    }

    // Raising the error
    ERR_KMPP_error(reason);
    // Adding the error details as error data
    ERR_add_error_data(1, paraBuf);  
    
    va_end(args);
}

const char *ERR_KMPP_get_string(int reason)
{
    if (reason < KeyIsoErrReason_AllocFailure || 
        reason >= KeyIsoErrReason_MaxError) {
        return NULL;
    }

    // Calculating the index
    int i = reason - KeyIsoErrReason_AllocFailure;

    // return the corresponding string
    return KMPP_str_reasons[i].string;
}

