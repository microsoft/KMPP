/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <openssl/buffer.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "p_keyiso.h"
#include "p_keyiso_err.h"

#include "keyisolog.h"
#include "keyisocommon.h"
#include "keyisomemory.h"
#include "keyisoclientinternal.h"
#include "keyisopfxclientinternal.h"


typedef struct KeyIso_prov_decoder_ctx_st KEYISO_PROV_DECODER_CTX;
struct KeyIso_prov_decoder_ctx_st {
    KEYISO_PROV_PROVCTX *provCtx;
};

// Checks if the given bytes represent a keyid
// The keyid format is expected to be "n<base64_extra_data>:<encrypted_pfx>" or "0.<base64_salt>:<encrypted_pfx>"
static int _is_keyid(unsigned char *inBytes, unsigned int inLength) 
{
    if (inBytes == NULL || inLength == 0) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    size_t maxLimit = 0;
    size_t maxLengthToSearch = 0;

    // Check if the first character is 'n'
    // Note: The decoder supports decoding keyids that were encoded using the kmpp encoder,
    // which is why we check only for 'n' as the first character, and not support the legacy '0' format.
    if (inBytes[0] == VERSION_CHAR) {
        maxLimit = MAX_EXTRA_DATA_BASE64_LENGTH + 1;
    } else {
        // Invalid version
        KMPPerr(KeyIsoErrReason_InvalidKeyId);
        return STATUS_FAILED;
    }

    // Check if the length of the keyid is valid
    maxLengthToSearch = (maxLimit > inLength) ? inLength : maxLimit;

    // Check if ':' is present in the buffer
    if (memchr(inBytes, EXTRA_DATA_DELIMITER, maxLengthToSearch) == NULL) {
        KMPPerr(KeyIsoErrReason_UnsupportedFormat);
        return STATUS_FAILED;
    }

    return STATUS_OK;
}

// loads the keyid into the KMPP provider
static int _load_keyid(unsigned char *inBytes, unsigned int inLength, KEYISO_PROV_DECODER_CTX *ctx, 
    OSSL_CALLBACK *objectCb, void *objectCbArg, OSSL_PASSPHRASE_CALLBACK *pwCb, void *pwCbArg)
{    
    if (inBytes == NULL || inLength == 0 || ctx == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    KEYISO_PROV_STORE_CTX *storeCtx = NULL;
    char *uri = NULL;

    // Create a new URI string for the keyid
    uri = KeyIso_zalloc(inLength + 1);
    if (uri == NULL) {
        // Allocation failed
        return STATUS_FAILED;
    }
    memcpy(uri, inBytes, inLength);
    uri[inLength] = '\0';

    // Create a temporary store context
    storeCtx = KeyIso_store_new_ctx(uri, ctx->provCtx);
    KeyIso_free(uri); // a duplicate of uri is used in the store context
    if (storeCtx == NULL) {
        // Allocation failed
        return STATUS_FAILED;
    }

    int ret = KeyIso_rsa_store_load(storeCtx, objectCb, objectCbArg, pwCb, pwCbArg);
    if (ret != STATUS_OK) {
        KMPPerr(KeyIsoErrReason_OperationFailed);
    }

    // Clean up the store context
    KeyIso_rsa_store_close(storeCtx);

    return ret;
}

static int _cleanup_import_decoded_key(int ret, KeyIsoErrReason reason, char *salt, unsigned char *pfxBytes, KEYISO_KEY_CTX *keyCtx)
{
    if (ret != STATUS_OK) {
        KMPPerr(reason);
        if (keyCtx) {
            KeyIso_CLIENT_pfx_close(keyCtx);
        }
    }

    if (salt) {
        KeyIso_clear_free_string(salt);
    }

    if (pfxBytes) {
        KeyIso_free(pfxBytes);
    }

    return ret;
}

static int _import_decoded_private_key(EVP_PKEY *pkey, OSSL_LIB_CTX *libCtx, KEYISO_PROV_DECODER_CTX *ctx, OSSL_CALLBACK *objectCb, void *objectCbArg, OSSL_PASSPHRASE_CALLBACK *pwCb, void *pwCbArg)
{    
    if (pkey == NULL || ctx == NULL || libCtx == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    uuid_t correlationId = {0};
    int pfxLength = 0;
    char *salt = NULL;
    unsigned char *pfxBytes = NULL;
    X509_SIG *encryptedPkey = NULL;
    KEYISO_KEY_CTX *keyCtx = NULL;
    EVP_PKEY *pubKey = NULL;

    // Set the key usage
    uint8_t usage = KMPP_KEY_USAGE_RSA_SIGN_ECDSA | KMPP_KEY_USAGE_RSA_ENCRYPT_ECDH;
    unsigned char data = (unsigned char)usage;
    EVP_PKEY_add1_attr_by_NID(pkey, NID_key_usage, V_ASN1_BIT_STRING, &data, 1);

    // Import the private key and create the X509_SIG (encrypted private key)
    KeyIso_rand_bytes(correlationId, sizeof(correlationId));
    if (KeyIso_CLIENT_import_private_key(correlationId, 0, pkey, &encryptedPkey, &salt) != STATUS_OK) {
        return _cleanup_import_decoded_key(STATUS_FAILED, KeyIsoErrReason_FailedToImport, salt, pfxBytes, keyCtx);
    }

    // Create a new PFX structure
    if (KeyIso_create_encrypted_pfx_bytes(correlationId, encryptedPkey, NULL, NULL, &pfxLength, &pfxBytes) != STATUS_OK) {
        if (encryptedPkey) {
            X509_SIG_free(encryptedPkey);
        }
        return _cleanup_import_decoded_key(STATUS_FAILED, KeyIsoErrReason_FailedToCreatePfx, salt, pfxBytes, keyCtx);
    }

    // Create a new key context from the PFX bytes
    if (KeyIso_CLIENT_private_key_open_from_pfx(correlationId, pfxLength, pfxBytes, salt, &keyCtx) != STATUS_OK) {
        return _cleanup_import_decoded_key(STATUS_FAILED, KeyIsoErrReason_FailedToGetKeyCtx, salt, pfxBytes, keyCtx);
    }

    // Create a new public key from the private key
    pubKey = KeyIso_new_pubKey_from_privKey(libCtx, pkey);
    if (pubKey == NULL) {
        return _cleanup_import_decoded_key(STATUS_FAILED, KeyIsoErrReason_FailedToGetPubKey, salt, pfxBytes, keyCtx);
    }

    // Create a new key object
    KeyIsoErrReason reason = KeyIsoErrReason_NoError;
    int ret = KeyIso_create_key_object(correlationId, ctx->provCtx, keyCtx, pubKey, objectCb, objectCbArg, pwCb, pwCbArg, false); // encoder self-generated cert should not be monitored as KIU
    if (ret != STATUS_OK) {
        reason = KeyIsoErrReason_OperationFailed;
    }

    return _cleanup_import_decoded_key(ret, reason, salt, pfxBytes, keyCtx);
}

static int _cleanup_decode_private_key(int ret, KeyIsoErrReason reason, EVP_PKEY *pkey, OSSL_DECODER_CTX *dctx, OSSL_PROVIDER *osslProv, OSSL_LIB_CTX *libCtx)
{
    if (ret != STATUS_OK) {
        KMPPerr(reason);
    }

    if (dctx) {
        OSSL_DECODER_CTX_free(dctx);
    }

    if (osslProv) {
        OSSL_PROVIDER_unload(osslProv);
    }

    if (libCtx) {
        OSSL_LIB_CTX_free(libCtx);
    }

    if (pkey) {
        EVP_PKEY_free(pkey);
    }

    return ret;
}

static int _decode_private_key(KEYISO_PROV_DECODER_CTX *ctx, BIO *in,
    OSSL_CALLBACK *objectCb, void *objectCbArg, OSSL_PASSPHRASE_CALLBACK *pwCb, void *pwCbArg)
{
    // We want to notify the user that we are decoding a plain private key
    KEYISOP_trace_log_error(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_PROVIDER_TITLE, "", "Decoding a plain private key");

    if (ctx == NULL || in == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    OSSL_LIB_CTX *libCtx = NULL;
    OSSL_PROVIDER *osslProv = NULL;
    
    // Load the default OpenSSL provider
    libCtx = OSSL_LIB_CTX_new();
    if (libCtx == NULL) {
        // allocation failure
        return STATUS_FAILED;
    }
    
    osslProv = OSSL_PROVIDER_load(libCtx, KEYISO_OSSL_DEFAULT_PROV_NAME);
    if (osslProv == NULL) {
        return _cleanup_decode_private_key(STATUS_FAILED, KeyIsoErrReason_FailedToLoadProvKey, pkey, dctx, osslProv, libCtx);
    }

    // Decoding the private key using the OpenSSL pem2key decoder
    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, KEYISO_NAME_PEM, NULL, NULL, EVP_PKEY_KEYPAIR, libCtx, KEYISO_OSSL_DEFAULT_PROV_PROPQ);
    if (OSSL_DECODER_CTX_get_num_decoders(dctx) == 0) {
        return _cleanup_decode_private_key(STATUS_FAILED, KeyIsoErrReason_OperationFailed, pkey, dctx, osslProv, libCtx);
    }

    if (pwCb != NULL) {
        OSSL_DECODER_CTX_set_passphrase_cb(dctx, pwCb, pwCbArg);
    }

    if (OSSL_DECODER_from_bio(dctx, in) == 0) {
        return _cleanup_decode_private_key(STATUS_FAILED, KeyIsoErrReason_FailedToDecodePem, pkey, dctx, osslProv, libCtx);
    }
    
    // Import the decoded key into the KMPP
    int ret = _import_decoded_private_key(pkey, libCtx, ctx, objectCb, objectCbArg, pwCb, pwCbArg);
    KeyIsoErrReason reason = KeyIsoErrReason_NoError;
    if (ret != STATUS_OK) {
        reason = KeyIsoErrReason_FailedToImport;
    }

    return _cleanup_decode_private_key(ret, reason, pkey, dctx, osslProv, libCtx);
}

static int _decode_encrypted_private_key(BIO *in, KEYISO_PROV_DECODER_CTX *ctx, char *bioMemBuf, unsigned int bioMemBufLength,
    OSSL_CALLBACK *objectCb, void *objectCbArg, OSSL_PASSPHRASE_CALLBACK *pwCb, void *pwCbArg)
{
    if (in == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    int ret = STATUS_FAILED;
    unsigned char *keyIdBytes = NULL;
    long keyIdLength = 0;

    keyIdLength = KeyIso_read_content_between_headers(in, bioMemBuf, bioMemBufLength, KEYISO_PEM_HEADER_BEGINE_PKCS8, KEYISO_PEM_HEADER_END_PKCS8, &keyIdBytes);
    if (keyIdBytes == NULL || keyIdLength <= 0 || keyIdLength > UINT_MAX) {
        KMPPerr(KeyIsoErrReason_FailedToGetKeyBytes);
        return STATUS_FAILED;
    }

    // Decode the encrypted private key
    if (_is_keyid(keyIdBytes, keyIdLength)) {
        // Case 1: A private key that is encrypted using KMPP, therefore the keyid is in the inBytes
        ret = _load_keyid(keyIdBytes, keyIdLength, ctx, objectCb, objectCbArg, pwCb, pwCbArg);
    } else {
        // Case 2: A private key that is encrypted using a password (not by KMPP)
        ret = _decode_private_key(ctx, in, objectCb, objectCbArg, pwCb, pwCbArg);
    }

    KeyIso_free(keyIdBytes);
    return ret;
}

static int _decode_pem_from_core_bio(OSSL_CORE_BIO *cin, KEYISO_PROV_DECODER_CTX *ctx,
    OSSL_CALLBACK *objectCb, void *objectCbArg, OSSL_PASSPHRASE_CALLBACK *pwCb, void *pwCbArg)
{
    if (cin == NULL || ctx == NULL || ctx->provCtx == NULL || ctx->provCtx->libCtx == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }
    
    char *bioContent = NULL;
    long bioLength = 0;
    int ret = STATUS_FAILED;
    PemType type = PemType_NotSupported;
    BIO *in = NULL;

    // Create a new BIO from the core BIO
    in = BIO_new_from_core_bio(ctx->provCtx->libCtx, cin);
    if (in == NULL) {
        // Failed to create BIO
        return STATUS_FAILED;
    }

    // Get the type from the BIO
    type = KeyIso_get_type_from_bio_buff(in, &bioContent, &bioLength);
    /*
     * Note: bioContent is only populated for memory BIOs, NULL for file BIOs.
     * _decode_encrypted_private_key handles both cases by checking bioMemBuf
     * parameter - when NULL, it reads directly from the BIO object instead.
     * No additional validation needed as the function handles NULL inputs safely.
     */
    switch (type) {
        case PemType_EncryptedPrivateKeyInfo:
            // PKCS #8 Encrypted Private Key Info
            ret = _decode_encrypted_private_key(in, ctx, bioContent, bioLength, objectCb, objectCbArg, pwCb, pwCbArg);
            break;
        case PemType_PrivateKeyInfo:
            // PKCS #8 Private Key Info
            ret = _decode_private_key(ctx, in, objectCb, objectCbArg, pwCb, pwCbArg);
            break;
        default:
            KMPPerr(KeyIsoErrReason_UnsupportedDataType);
            ret = STATUS_FAILED;
    }

    // Free the BIO content
    if (in != NULL) {
        BIO_free(in);
    }

    return ret;
}

static int _decoder_decode(KEYISO_PROV_DECODER_CTX *ctx, OSSL_CORE_BIO *cin, int selection,
    OSSL_CALLBACK *objectCb, void *objectCbArg, OSSL_PASSPHRASE_CALLBACK *pwCb, void *pwCbArg)
{
    KEYISOP_trace_log(NULL, 0, KEYISOP_PROVIDER_TITLE, "Start");

    if (ctx == NULL || cin == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return STATUS_FAILED;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0) {
        KMPPerr(KeyIsoErrReason_UnsupportedSelection);
        return STATUS_FAILED;
    }

    if (_decode_pem_from_core_bio(cin, ctx, objectCb, objectCbArg, pwCb, pwCbArg) != STATUS_OK) {
        ERR_KMPP_error(KeyIsoErrReason_FailedToDecodePem);
        return STATUS_FAILED;
    }

    return STATUS_OK;
}

static KEYISO_PROV_DECODER_CTX *_decoder_newctx(KEYISO_PROV_PROVCTX *provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    if (provCtx == NULL) {
        return NULL;
    }

    KEYISO_PROV_DECODER_CTX *ctx = (KEYISO_PROV_DECODER_CTX *)KeyIso_zalloc(sizeof(KEYISO_PROV_DECODER_CTX));
    if (ctx != NULL) {
        ctx->provCtx = provCtx;
    }

    return ctx;
}

static void _decoder_freectx(KEYISO_PROV_DECODER_CTX *ctx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    if (ctx != NULL) {
        KeyIso_free(ctx);
    }
}

const OSSL_DISPATCH keyIso_prov_decoder_pem_funcs[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))_decoder_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))_decoder_freectx },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))_decoder_decode },
    { 0, NULL }
};