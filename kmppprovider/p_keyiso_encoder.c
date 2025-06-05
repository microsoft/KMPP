/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>

#include "keyisocommon.h"
#include "keyisoclient.h"
#include "keyisoclientinternal.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "p_keyiso.h"
#include "p_keyiso_err.h"


typedef struct KeyIso_prov_encoder_ctx_st KEYISO_PROV_ENCODER_CTX_ST;
struct KeyIso_prov_encoder_ctx_st {
    KEYISO_PROV_PROVCTX *provCtx;
};

static KEYISO_PROV_ENCODER_CTX_ST* _encoder_newctx(KEYISO_PROV_PROVCTX *provCtx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    KEYISO_PROV_ENCODER_CTX_ST* ctx = NULL;

    if (provCtx == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return NULL;
    }

    if ((ctx = KeyIso_zalloc(sizeof(KEYISO_PROV_ENCODER_CTX_ST))) == NULL) {
        return NULL;
    }

    ctx->provCtx = provCtx;
    return ctx;
}

static void _encoder_freectx(KEYISO_PROV_ENCODER_CTX_ST *ctx)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");
    KeyIso_free(ctx);
}

static int _cleanup_import_private_key(int ret, KeyIsoErrReason reason, char *salt, unsigned char *encryptedPfxBytes,
    X509 *cert, X509_SIG *encryptedPkey, EVP_PKEY *pubKey, CONF* generatedKeyConfEncoder) 
{
    if (ret != STATUS_OK) {
        KMPPerr(reason);
        if (encryptedPkey) {
            X509_SIG_free(encryptedPkey);
        }
        
        // Free pubKey only on error path
        if (pubKey) {
            EVP_PKEY_free(pubKey);
        }
    }

    if (encryptedPfxBytes) {
        KeyIso_free(encryptedPfxBytes);
    }

    if (cert) {
        X509_free(cert);
    }

    if (salt) {
        KeyIso_clear_free_string(salt);
    }

	if (generatedKeyConfEncoder) {
		NCONF_free(generatedKeyConfEncoder);
	}

    return ret;
}

#define _CLEANUP_IMPORT_PRIVATE_KEY(ret, reason) \
    _cleanup_import_private_key(ret, reason, salt, encryptedPfxBytes, cert, encryptedPkey, (ret != STATUS_OK) ? pubKey : NULL, generatedKeyConfEncoder)

static int _import_private_key_encoder(uuid_t correlationId, KEYISO_PROV_PKEY *provKey)
{
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start");

    EVP_PKEY *pKey = provKey->pubKey; // In this scenario, the public key is actually plain text key
    X509_SIG *encryptedPkey = NULL;
    char* salt = NULL;
    EVP_PKEY *pubKey = NULL;
    KEYISO_KEY_CTX *keyCtx = NULL;
    int encryptedPfxLength = 0; 
    unsigned char *encryptedPfxBytes = NULL;
    X509* cert = NULL;
    CONF *generatedKeyConfEncoder = NULL;

    if (pKey == NULL) {
        return _CLEANUP_IMPORT_PRIVATE_KEY(STATUS_FAILED, KeyIsoErrReason_InvalidParams);
    }

    // Check the type of the key - currently only RSA & RSA-PSS are supported
    int keyType = EVP_PKEY_get_id(pKey);
    if (keyType != EVP_PKEY_RSA && keyType != EVP_PKEY_RSA_PSS) {
        return _CLEANUP_IMPORT_PRIVATE_KEY(STATUS_FAILED, KeyIsoErrReason_UnsupportedKeyType);
    }    

    uint8_t usage = KMPP_KEY_USAGE_RSA_SIGN_ECDSA | KMPP_KEY_USAGE_RSA_ENCRYPT_ECDH;
    unsigned char usVal = (unsigned char)usage;

    if (!EVP_PKEY_add1_attr_by_NID(pKey, NID_key_usage, V_ASN1_BIT_STRING, &usVal, 1)) {
        return _CLEANUP_IMPORT_PRIVATE_KEY(STATUS_FAILED, KeyIsoErrReason_FailedToSetKeyAttributes);
    }
 
    // This step transforms a plaintext key into a protected format with encrypted private key data
    // and salt for key derivation functions
    if (KeyIso_CLIENT_import_private_key(correlationId, 0, pKey, &encryptedPkey, &salt) != STATUS_OK) {
        return _CLEANUP_IMPORT_PRIVATE_KEY(STATUS_FAILED, KeyIsoErrReason_FailedToImport);
    }
    
    // Create a new public key from the private key
    pubKey = KeyIso_new_pubKey_from_privKey(NULL, pKey);
    if (pubKey == NULL) {
        return _CLEANUP_IMPORT_PRIVATE_KEY(STATUS_FAILED, KeyIsoErrReason_FailedToGetPubKey);
    }

    if (KeyIso_conf_get(&generatedKeyConfEncoder, KEYISO_ENCODER_CERT_DNS_NAME, KEYISO_ENCODER_CERT_DNS_NAME) != STATUS_OK) {
        return _CLEANUP_IMPORT_PRIVATE_KEY(STATUS_FAILED, KeyIsoErrReason_FailedToGetConf);
    }

    // Create X509 certificate to format keyId later - use keyType (int) instead of provKey->keyType
    if (KeyIso_CLIENT_create_X509_from_pubkey(correlationId, keyType, pubKey, &cert, generatedKeyConfEncoder) != STATUS_OK) {
        return _CLEANUP_IMPORT_PRIVATE_KEY(STATUS_FAILED, KeyIsoErrReason_FailedToCreateCert);
    }

    // Construct encryptedPfxBytes in PKCS#12 format
    if (KeyIso_create_encrypted_pfx_bytes(correlationId, encryptedPkey, cert, NULL, &encryptedPfxLength, &encryptedPfxBytes) != STATUS_OK) {
        return _CLEANUP_IMPORT_PRIVATE_KEY(STATUS_FAILED, KeyIsoErrReason_FailedToCreatePfx);
    }
   
    if (KeyIso_CLIENT_private_key_open_from_pfx(correlationId, encryptedPfxLength, encryptedPfxBytes, salt, &keyCtx) != STATUS_OK) {
        return _CLEANUP_IMPORT_PRIVATE_KEY(STATUS_FAILED, KeyIsoErrReason_FailedToGetKeyCtx);
    }

    // Replace the plain text key with the public key in the provider key
    if (provKey->pubKey != NULL) {
        EVP_PKEY_free(provKey->pubKey);
    }

    provKey->pubKey = pubKey; // We're transferring ownership of pubKey here
    provKey->keyCtx = keyCtx;
    
    // Don't free pubKey on success path since ownership is transferred to pKeyProv
    return _CLEANUP_IMPORT_PRIVATE_KEY(STATUS_OK, KeyIsoErrReason_NoError);
}

static int _cleanup_encoder_encode(int ret, KeyIsoErrReason reason, char *keyId, BIO *bio)
{
    if (ret != STATUS_OK) {
        KMPPerr(reason);
    }

    if (keyId)
        KeyIso_clear_free_string(keyId);
    if (bio)
        BIO_free(bio);

    return ret;
}

#define _CLEANUP_ENCODER_ENCODE(ret, reason) \
    _cleanup_encoder_encode(ret, reason, keyId, bio)

static int _encoder_encode(KEYISO_PROV_ENCODER_CTX_ST* ctx, OSSL_CORE_BIO* coreBio, const KEYISO_PROV_PKEY* pKey,
    ossl_unused const OSSL_PARAM params[], int selection, ossl_unused OSSL_PASSPHRASE_CALLBACK* cb, ossl_unused void* cbarg)
{
    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_PROVIDER_TITLE, "Start", "selection: %d", selection);
    uuid_t correlationId;
    char* keyId = NULL;
    BIO* bio = NULL;

    KeyIso_rand_bytes(correlationId, sizeof(correlationId));

    if (ctx == NULL || ctx->provCtx == NULL || pKey == NULL || pKey->pubKey == NULL || ctx->provCtx->libCtx == NULL) {
        return _CLEANUP_ENCODER_ENCODE(STATUS_FAILED, KeyIsoErrReason_InvalidParams);
    }

    // if the keyCtx is not set, import the private key
    if (pKey->keyCtx == NULL) {
        // if the private key does not exist or import failed, return error
        if ((KeyIso_get_bn_param_len(pKey->pubKey, OSSL_PKEY_PARAM_RSA_D, NULL) < 1) || 
            (_import_private_key_encoder(correlationId, (KEYISO_PROV_PKEY *)pKey) != STATUS_OK)) { // Convert to non-const to remove the original open key.
            return _CLEANUP_ENCODER_ENCODE(STATUS_FAILED, KeyIsoErrReason_FailedToGetKeyBytes);
        }
    }

    KEYISO_KEY_DETAILS* keyDetails = (KEYISO_KEY_DETAILS*)pKey->keyCtx->keyDetails;
    if (keyDetails == NULL) {
        return _CLEANUP_ENCODER_ENCODE(STATUS_FAILED, KeyIsoErrReason_InvalidParams);
    }

    // Construct keyId out of the new encryptedBytes and salt stored in the keyCtx
    if (KeyIso_format_pfx_engine_key_id(correlationId, keyDetails->keyLength, keyDetails->keyBytes, keyDetails->salt, &keyId) != STATUS_OK) {
        return _CLEANUP_ENCODER_ENCODE(STATUS_FAILED, KeyIsoErrReason_FailedToFormatKeyId);
    }

    // Write the encrypted key to PEM format
    bio = BIO_new_from_core_bio(ctx->provCtx->libCtx, coreBio);
    if (bio == NULL) {
        return _CLEANUP_ENCODER_ENCODE(STATUS_FAILED, KeyIsoErrReason_FailedToGetBio);
    }

    // Write the encryptedKeyId to the BIO with header and footer using OpenSSL standard macros
    if (BIO_printf(bio, "%s\n%s\n%s\n", KEYISO_PEM_HEADER_BEGINE_PKCS8, keyId, KEYISO_PEM_HEADER_END_PKCS8) <= 0) {
        return _CLEANUP_ENCODER_ENCODE(STATUS_FAILED, KeyIsoErrReason_FailedToEncodePem);
    }

    return _CLEANUP_ENCODER_ENCODE(STATUS_OK, KeyIsoErrReason_NoError);
}

const OSSL_DISPATCH keyIso_prov_encoder_funcs[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void)) _encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void)) _encoder_freectx },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void)) _encoder_encode },
    { 0, NULL }
};