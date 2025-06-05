/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <openssl/core_names.h>
#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/err.h>

#include "keyisoclientinternal.h"
#include "keyisomemory.h"
#include "keyisolog.h"
#include "keyisocommon.h"
#include "keyisoclient.h"
#include "p_keyiso.h"

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
    if (providerKeyIdLen == KEYISO_MAX_KEY_ID_LEN) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_PROVIDER_TITLE, "keyId", "too long");
        return NULL;
    }
    
    size_t prefixLen = sizeof(KEYISO_PROV_STORE_SCHEME_PREFIX);
    keyId = (char *)KeyIso_zalloc(providerKeyIdLen + prefixLen);
    if (keyId == NULL) {
        return NULL;
    }

    memcpy(keyId, KEYISO_PROV_STORE_SCHEME_PREFIX, prefixLen - 1);
    memcpy(keyId + prefixLen - 1, providerKeyId, providerKeyIdLen);
    keyId[providerKeyIdLen + prefixLen - 1] = '\0';

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

static int _cleanup_conf_sign_prov(
    int ret,
    const char *loc,
    const uuid_t correlationId,
    EVP_MD_CTX *mdCtx)
{
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_openssl_error(correlationId, 0, KEYISOP_CREATE_SELF_SIGN_TITLE, loc);     
    }
    
	if (mdCtx) {
		EVP_MD_CTX_free(mdCtx); // also frees pCtx 
	}

    return ret;
}

#define _CLEANUP_CONF_SIGN_PROV(ret, loc) \
    _cleanup_conf_sign_prov(ret, loc, correlationId, mdCtx)

/*
* Similar to "KeyIso_cert_sign", once ECC support is added to the providers and
* to ensure consistency between the engine and provider, the function name will be changed
* to KeyIso_conf_sign with the additional arguments.
*/
int KeyIso_conf_cert_sign_prov(
    const uuid_t correlationId,
    const CONF *conf,
    X509 *cert,
    EVP_PKEY *pkey,
    void *ctx,
    const char* propq)
{
    const char *signDigest = NULL;  // don't free
    const char *keyType = NULL;     // don't free
    const EVP_MD *digest = NULL;    // don't free
    EVP_MD_CTX *mdCtx = NULL;
    EVP_PKEY_CTX *pCtx = NULL;      // don't free
    OSSL_LIB_CTX *libCtx = (OSSL_LIB_CTX *)ctx;

	if (pkey == NULL) {
		return _CLEANUP_CONF_SIGN_PROV(STATUS_FAILED, "pkey is NULL");
	}

    signDigest = KeyIso_conf_get_string(correlationId, conf, "sign_digest");
    if (signDigest == NULL) {
        return _CLEANUP_CONF_SIGN_PROV(STATUS_FAILED, "sign_digest not found");
    }

    digest = EVP_get_digestbyname(signDigest);
    if (digest == NULL) {
        return _CLEANUP_CONF_SIGN_PROV(STATUS_FAILED, "EVP_get_digestbyname");
    }

    mdCtx = EVP_MD_CTX_new();
    if (mdCtx == NULL) {
        return _CLEANUP_CONF_SIGN_PROV(STATUS_FAILED, "EVP_MD_CTX_new");
    }

    if (EVP_DigestSignInit_ex(mdCtx, &pCtx, signDigest, libCtx, propq, pkey, NULL) <= 0) {
        return _CLEANUP_CONF_SIGN_PROV(STATUS_FAILED, "EVP_DigestSignInit");
    }

    keyType = KeyIso_conf_get_string(correlationId, conf, "key_type");
    if (keyType != NULL && strncmp(keyType, KMPP_KEY_TYPE_STR_RSA, sizeof(KMPP_KEY_TYPE_STR_RSA)) == 0) {
        long rsaPadding = 0;
        // Padding values:
        //  # define RSA_PKCS1_PADDING       1
        //  # define RSA_PKCS1_PSS_PADDING   6
        if (KeyIso_conf_get_number(correlationId, conf, "rsa_padding", &rsaPadding) != STATUS_OK || rsaPadding <= 0) {
            return _CLEANUP_CONF_SIGN_PROV(STATUS_FAILED, "Invalid rsa_padding");
        }

        if (EVP_PKEY_CTX_set_rsa_padding(pCtx, (int) rsaPadding) <= 0) {
            return _CLEANUP_CONF_SIGN_PROV(STATUS_FAILED, "EVP_PKEY_CTX_set_rsa_padding");
        }
    }

    if (X509_sign_ctx(cert, mdCtx) <= 0) {
        return _CLEANUP_CONF_SIGN_PROV(STATUS_FAILED, "X509_sign_ctx");
    }

    return _CLEANUP_CONF_SIGN_PROV(STATUS_OK, NULL);
}

/* Currently, self - signing using the engine is invoked even
 if we are working with OpenSSL 3.x and the KMPP provider is available,
 until we implement ECC in the provider as well.
 Once ECC is implemented, these functions will be re-enabled. */
#if 0
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

    ret = KeyIso_conf_cert_sign_prov(correlationId, conf, cert, encryptedKeyPkey, libCtx, KEYISO_PROV_PROPQ);

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
            KEYISOP_trace_log(NULL, 0, KEYISOP_SUPPORT_TITLE, "SymCrypt provider is available");
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

size_t KeyIso_get_bn_param_len(const EVP_PKEY *pkey, const char *paramType, BIGNUM **outParam)
{
    size_t paramLen = 0;
    BIGNUM* param  = NULL;

    // Get the BN param from EVP_PKEY
    if (!EVP_PKEY_get_bn_param(pkey, paramType, &param)) {
        return paramLen;
    }

    // Get the length of the parameter
    paramLen = BN_num_bytes(param);

	// Return the parameter if requested
    if(outParam != NULL)
        *outParam = param;
    else
        BN_free(param);

    return paramLen;
}

int KeyIso_get_rsa_params(
    const EVP_PKEY *pkey, 
    BIGNUM **rsa_n,  // Modulus (public)
    BIGNUM **rsa_e,  // Exponent (public)
    BIGNUM **rsa_p,  // Prime1 (private)
    BIGNUM **rsa_q)  // Prime2 (private)
{
    if (pkey == NULL) {
        return STATUS_FAILED;
    }

    // Public parameters are mandatory
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, rsa_n) ||
        !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, rsa_e)) {
        return STATUS_FAILED;
    }

    // Private parameters are optional
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, rsa_p);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, rsa_q);

    return STATUS_OK;
}