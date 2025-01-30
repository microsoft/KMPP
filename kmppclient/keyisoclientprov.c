/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/err.h>

#include "keyisoclientinternal.h"
#include "keyisoclientprovinternal.h"
#include "keyisomemory.h"
#include "keyisolog.h"
#include "keyisocommon.h"
#include "keyisoclient.h"

DEFINE_STACK_OF(OSSL_PROVIDER)
#define MAX_PROVIDER_NAME_LEN 128 // Reasonable maximum length for provider names

//
// Support functions for provider and key id defined in keyisoclient.h
//

static void _cleanup_load_prov(
    OSSL_PROVIDER* kmppProv,
    OSSL_STORE_CTX *storeCtx, 
    OSSL_STORE_INFO *storeInfo, 
    char *keyId) 
{
    if (storeInfo) {
        OSSL_STORE_INFO_free(storeInfo);
        storeInfo = NULL;
    }
        
    if (storeCtx) {
        OSSL_STORE_close(storeCtx);
        storeCtx = NULL;
    }
        
    if (kmppProv) {
        OSSL_PROVIDER_unload(kmppProv);
        kmppProv = NULL;
    }

    if (keyId) {
        KeyIso_clear_free_string(keyId);
        keyId = NULL;
    }
}

#define _CLEANUP_LOAD() \
    _cleanup_load_prov(kmppProv, storeCtx, storeInfo, keyId)

EVP_PKEY *KeyIso_load_provider_private_key(
    OSSL_LIB_CTX *libCtx,
    const char *providerKeyId)
{
    OSSL_PROVIDER* kmppProv = NULL;
    OSSL_STORE_CTX* storeCtx = NULL;
    OSSL_STORE_INFO* storeInfo = NULL;
    EVP_PKEY* pkey = NULL;
    char *keyId = NULL;

    if (providerKeyId == NULL) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_PROVIDER_TITLE, "keyId", "NULL");
        return NULL;
    }

    // Concatenating KMPP scheme to the keyId
    size_t providerKeyIdLen = strnlen(providerKeyId, KEYISO_MAX_KEY_ID_LEN);
    size_t prefixLen = sizeof(KEYISO_PROV_STORE_SCHEME_PREFIX);
    keyId = (char *)KeyIso_zalloc(providerKeyIdLen + prefixLen);
    if (keyId == NULL) {
        return NULL;
    }

    strncpy(keyId, KEYISO_PROV_STORE_SCHEME_PREFIX, prefixLen);
    strncat(keyId, providerKeyId, providerKeyIdLen);

    ERR_clear_error();

    // load the kmpp provider
    kmppProv = OSSL_PROVIDER_load(libCtx, KEYISO_PROV_NAME);
    if (kmppProv == NULL) {
        KEYISOP_trace_log_openssl_error(NULL, 0, KEYISOP_PROVIDER_TITLE, "load provider");
        _cleanup_load_prov(kmppProv, storeCtx, storeInfo, keyId);
        return NULL;
    }

    // open the store context
    storeCtx = OSSL_STORE_open_ex(keyId, libCtx, KEYISO_PROV_PROPQ, NULL, NULL, NULL, NULL, NULL);
    if (storeCtx == NULL) {
        KEYISOP_trace_log_openssl_error_para(NULL, 0, KEYISOP_PROVIDER_TITLE, "open store", "key id: %s", keyId);
        _cleanup_load_prov(kmppProv, storeCtx, storeInfo, keyId);
        return NULL;
    }

    // load the key
    storeInfo = OSSL_STORE_load(storeCtx);
    if (storeInfo == NULL) {
        KEYISOP_trace_log_openssl_error(NULL, 0, KEYISOP_PROVIDER_TITLE, "load key");
        _cleanup_load_prov(kmppProv, storeCtx, storeInfo, keyId);
        return NULL;
    }

    // get the evp key
    if (OSSL_STORE_INFO_get_type(storeInfo) == OSSL_STORE_INFO_PKEY) {
        pkey = OSSL_STORE_INFO_get1_PKEY(storeInfo);
        if (pkey == NULL) {
            KEYISOP_trace_log_openssl_error(NULL, 0, KEYISOP_PROVIDER_TITLE, "get pkey");
        }
    }

    _cleanup_load_prov(kmppProv, storeCtx, storeInfo, keyId);
    return pkey;
}

/* Currently, self - signing using the engine is invoked even
 if we are working with OpenSSL 3.x and the KMPP provider is available,
 until we implement ECC in the provider as well.
 Once ECC is implemented, these functions will be re-enabled. */
#if 0
static int KeyIso_conf_sign_prov(
    const uuid_t correlationId,
    OSSL_LIB_CTX *libctx,
    CONF *conf,
    X509 *cert,
    EVP_PKEY *pkey)
{
    const char *title = KEYISOP_CREATE_SELF_SIGN_TITLE;
    const char *loc = "";
    int ret = 0;
    const char *signDigest = NULL;  // don't free
    const char *keyType = NULL;     // don't free
    const EVP_MD *digest = NULL;    // don't free
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;      // don't free

    signDigest = KeyIso_conf_get_string(correlationId, conf, "sign_digest");
    if (signDigest == NULL) {
        goto end;
    }

    digest = EVP_get_digestbyname(signDigest);
    if (digest == NULL) {
        loc = "EVP_get_digestbyname";
        KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, loc,
            "sign_digest: %s", signDigest);
        goto end;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        goto openSslErr;
    }

    if (!EVP_DigestSignInit_ex(ctx, &pctx, signDigest, libctx, KEYISO_PROV_PROPQ, pkey, NULL)) {
        loc = "EVP_DigestSignInit";
        goto openSslErr;
    }

    keyType = KeyIso_conf_get_string(correlationId, conf, "key_type");
    if (keyType != NULL && strcmp(keyType, "rsa") == 0) {
        long rsaPadding = 0;

        // Padding values:
        //  # define RSA_PKCS1_PADDING       1
        //  # define RSA_PKCS1_PSS_PADDING   6

        if (!KeyIso_conf_get_number(correlationId, conf, "rsa_padding", &rsaPadding) || rsaPadding <= 0) {
            goto end;
        }

        if (EVP_PKEY_CTX_set_rsa_padding(pctx, (int) rsaPadding) <= 0) {
            loc = "EVP_PKEY_CTX_set_rsa_padding";
            goto openSslErr;
        }
    }

    if (X509_sign_ctx(cert, ctx) <= 0) {
        loc = "X509_sign_ctx";
        goto openSslErr;
    }

    ret = 1;
end:
    EVP_MD_CTX_free(ctx);       // also frees pctx

    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

// Self signing the cert utilizing the provider
int KeyIso_cert_sign(
    const uuid_t correlationId, 
    CONF *conf, 
    X509 *cert, 
    const char *encryptedKeyId)
{
    EVP_PKEY *encryptedKeyPkey = NULL;
    OSSL_LIB_CTX *libCtx = NULL;
    int ret = STATUS_FAILED;

    libCtx = OSSL_LIB_CTX_new();
    encryptedKeyPkey = KeyIso_load_provider_private_key(libCtx, encryptedKeyId);
    if (encryptedKeyPkey == NULL) {
        OSSL_LIB_CTX_free(libCtx);
        return STATUS_FAILED;
    }

    ret = KeyIso_conf_sign_prov(correlationId, libCtx, conf, cert, encryptedKeyPkey);

    EVP_PKEY_free(encryptedKeyPkey);
    OSSL_LIB_CTX_free(libCtx);
    return ret;
}
#endif

int KeyIso_parse_pfx_provider_key_id(
    const uuid_t correlationId,
    const char *keyId,
    int *pfxLength,
    unsigned char **pfxBytes,         // KeyIso_clear_free()
    char **salt)                      // Optional, KeyIso_clear_free_string()
{
    return KeyIso_parse_pfx_engine_key_id(correlationId, keyId, pfxLength, pfxBytes, salt);
}

int KeyIso_format_pfx_provider_key_id(
    const uuid_t correlationId,
    int pfxLength,
    const unsigned char *pfxBytes,
    const char *salt,
    char **keyId)                     // KeyIso_clear_free_string()
{
    return KeyIso_format_pfx_engine_key_id(correlationId, pfxLength, pfxBytes, salt, keyId);
}

static int _provider_cmp(const OSSL_PROVIDER * const *a, const OSSL_PROVIDER * const *b)
{
    return strncmp(OSSL_PROVIDER_get0_name(*a), OSSL_PROVIDER_get0_name(*b), MAX_PROVIDER_NAME_LEN);
}

static int _collect_providers(OSSL_PROVIDER *provider, void *stack)
{
    STACK_OF(OSSL_PROVIDER) *provider_stack = stack;
    return sk_OSSL_PROVIDER_push(provider_stack, provider) > 0 ? 1 : 0;
}

bool _is_symcrypt_provider_available()
{    
    STACK_OF(OSSL_PROVIDER) *providers = sk_OSSL_PROVIDER_new(_provider_cmp);
    if (providers == NULL) {
        return false;
    }

    if (OSSL_PROVIDER_do_all(NULL, &_collect_providers, providers) != 1) {
        sk_OSSL_PROVIDER_free(providers);
        return false;
    }

    for (int i = 0; i < sk_OSSL_PROVIDER_num(providers); i++) {
        const OSSL_PROVIDER* prov = sk_OSSL_PROVIDER_value(providers, i);
        const char* provName = OSSL_PROVIDER_get0_name(prov);
        if (strncmp(provName, KEYISO_SYMCRYPT_PROV_NAME, sizeof(KEYISO_SYMCRYPT_PROV_NAME) - 1) == 0) {
            printf("SymCrypt provider is available.\n");
            sk_OSSL_PROVIDER_free(providers);
            return true;
        }
    }

    sk_OSSL_PROVIDER_free(providers);
    return false;
}

bool KeyIso_check_default(const char* name)
{
	// currently only smcrypt provider can be defualt provider that affects us
    if (strncmp(name, KEYISO_SYMCRYPT_NAME, sizeof(KEYISO_SYMCRYPT_NAME) - 1) == 0) {
        return _is_symcrypt_provider_available();
    }


	return false;
}