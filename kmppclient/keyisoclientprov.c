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
    unsigned char **pfxBytes,     // KeyIso_clear_free()
    char **clientData)            // Salt for legacy/ Client data for kmpp key, KeyIso_clear_free_string()
{
    return KeyIso_parse_pfx_engine_key_id(correlationId, keyId, pfxLength, pfxBytes, clientData);
}

int KeyIso_format_pfx_provider_key_id(
    const uuid_t correlationId,
    int pfxLength,
    const unsigned char *pfxBytes,
    const char *clientData,
    char **keyId)                 // KeyIso_clear_free_string()
{
    return KeyIso_format_pfx_engine_key_id(correlationId, pfxLength, pfxBytes, clientData, keyId);
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

////////////
//  RSA  //
//////////

int KeyIso_get_rsa_params(
    const EVP_PKEY *pkey, 
    BIGNUM **rsaN,  // Modulus (public)
    BIGNUM **rsaE,  // Exponent (public)
    BIGNUM **rsaP,  // Prime1 (private)
    BIGNUM **rsaQ)  // Prime2 (private)
{
    if (pkey == NULL || rsaN == NULL || rsaE == NULL) {
        return STATUS_FAILED;
    }

    // Public parameters are mandatory
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, rsaN) ||
        !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, rsaE)) {
        return STATUS_FAILED;
    }

    // Private parameters are 
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, rsaP);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, rsaQ);

    return STATUS_OK;
}


#if 0
//Creates an EVP_PKEY containing an RSA public from the provided modulus and exponent
int KeyIso_get_rsa_evp_pub_key(
    const uint8_t *modulus,
    size_t modulusLen,                            
    const uint8_t *exponent,
    size_t exponentLen,
    EVP_PKEY **outPkey)
{
    if (modulus == NULL || modulusLen == 0 || exponent == NULL || exponentLen == 0 || outPkey == NULL) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Invalid input", "NULL parameter or zero length");
        return STATUS_FAILED;
    }
    *outPkey = NULL;

    // Create parameter context for RSA
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", KMPP_OSSL_PROVIDER_DEFAULT);
    if (ctx == NULL) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Failed to create EVP_PKEY_CTX", "EVP_PKEY_CTX_new_from_name failed");
        return STATUS_FAILED;
    }

    // Set up public key parameters from data buffer
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, (unsigned char*)modulus, modulusLen),
        OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, (unsigned char*)exponent, exponentLen),
        OSSL_PARAM_construct_end()
    };

    // Create EVP_PKEY with parameters
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Failed to initialize fromdata operation", "EVP_PKEY_fromdata_init failed");
        EVP_PKEY_CTX_free(ctx);
        return STATUS_FAILED;
    }

    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Failed to create EVP_PKEY from data", "EVP_PKEY_fromdata failed");
        EVP_PKEY_CTX_free(ctx);
        return STATUS_FAILED;
    }

    *outPkey = pkey;
    EVP_PKEY_CTX_free(ctx);

    return STATUS_OK;
}
#endif
 
////////////
//  ECC  //
//////////

// TODO: Once ECC support is added to the providers the following functions will be enabled.

#if 0 
// Get the public components from an ECC private key
int KeyIso_get_ecc_params(
    const EVP_PKEY *privKey,
    unsigned char **pubKey,      // KeyIso_clear_free()
    size_t *pubKeyLen,
    char **groupName)           // KeyIso_clear_free() if requested, NULL if not needed
{
    if (!privKey || !pubKey || !pubKeyLen || !groupName) {
        return STATUS_FAILED;
    }

    size_t nameLen = 0;
    size_t keyLen = 0;

    *pubKey = NULL;
    *pubKeyLen = 0;
    *groupName = NULL;

    // Get required sizes
    if (!EVP_PKEY_get_octet_string_param(privKey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &keyLen)) {
        return STATUS_FAILED;
    }

    if (!EVP_PKEY_get_utf8_string_param(privKey, OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0, &nameLen)) {
        return STATUS_FAILED;
    }

    // Allocate buffers for the key and group name
    unsigned char *keyBuf = KeyIso_zalloc(keyLen);
    if (!keyBuf) {
        return STATUS_FAILED;
    }

    char *nameBuf = KeyIso_zalloc(nameLen);
    if (!nameBuf) {
        KeyIso_free(keyBuf);
        return STATUS_FAILED;
    }

    //  Extract values into allocated buffers
    if (!EVP_PKEY_get_utf8_string_param(privKey, OSSL_PKEY_PARAM_GROUP_NAME, nameBuf, nameLen, NULL)) {
        KeyIso_free(nameBuf);
        KeyIso_free(keyBuf);
        return STATUS_FAILED;
    }

    if (!EVP_PKEY_get_octet_string_param(privKey, OSSL_PKEY_PARAM_PUB_KEY, keyBuf, keyLen , NULL)) {
        KeyIso_free(nameBuf);
        KeyIso_free(keyBuf);
        return STATUS_FAILED;
    }

    // Assign output values
    *pubKey = keyBuf;
    *pubKeyLen = keyLen;
    *groupName = nameBuf;

    return STATUS_OK;
}

//Creates an EVP_PKEY containing an ECC public from the provided public components
int KeyIso_create_ec_evp_pub_key(
    uint32_t curveNid,
    const uint8_t *pubKey,
    size_t pubKeyLen,
    EVP_PKEY **outPkey)
{
    if (pubKey == NULL || pubKeyLen == 0 || outPkey == NULL) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Invalid input", "NULL parameter or zero length");
        return STATUS_FAILED;
    }
    *outPkey = NULL;

    // Create parameter context for EC
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", KMPP_OSSL_PROVIDER_DEFAULT);
    if (ctx == NULL) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Failed to create EVP_PKEY_CTX", "EVP_PKEY_CTX_new_from_name failed");
        return STATUS_FAILED;
    }

    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Failed to initialize fromdata operation", "EVP_PKEY_fromdata_init failed");
        EVP_PKEY_CTX_free(ctx);
        return STATUS_FAILED;
    }

    // Get the group name from the curve NID
    const char *groupName = OBJ_nid2sn(curveNid);
    if (groupName == NULL) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Failed to get group name", "OBJ_nid2sn failed");
        EVP_PKEY_CTX_free(ctx);
        return STATUS_FAILED;
    }
    // print the group name for debug
    KEYISOP_trace_log_para(NULL, 0, KEYISOP_GEN_KEY_TITLE, "", "######### curveNid:%d Group name: %s", curveNid, groupName); // DEBUG!!!


    // Allocate buffer and copy pubKey data explicitly
    unsigned char *pubKeyCopy = KeyIso_zalloc(pubKeyLen);
    if (!pubKeyCopy) {
        EVP_PKEY_CTX_free(ctx);
        return STATUS_FAILED;
    }
    memcpy(pubKeyCopy, pubKey, pubKeyLen);


    // Set up public key parameters from data buffer
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)groupName, 0),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pubKeyCopy, pubKeyLen),
        OSSL_PARAM_construct_end()
    };

    // Create EVP_PKEY with parameters
    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Failed to create EVP_PKEY from data", "EVP_PKEY_fromdata failed");
        KeyIso_free(pubKeyCopy);
        EVP_PKEY_CTX_free(ctx);
        return STATUS_FAILED;
    }

    *outPkey = pkey;
    KeyIso_free(pubKeyCopy);
    EVP_PKEY_CTX_free(ctx);

    return STATUS_OK;
}

// Extracts the public key component from an ECC private key
EVP_PKEY* KeyIso_get_ec_public_key(
    const uuid_t correlationId,
    const EVP_PKEY *privKey) 
{
    unsigned char *pubKeyBytes = NULL;
    size_t pubKeyLen = 0;
    char *groupName = NULL;
    EVP_PKEY* pubKey = NULL;

    if (privKey == NULL) {
        return NULL;
    }

    // Get ECC public parameters
    if (KeyIso_get_ecc_params(privKey, &pubKeyBytes, &pubKeyLen, &groupName) != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_GEN_KEY_TITLE, "Failed to get ECC parameters", NULL);
        return NULL;
    }

    // Get curveNid out of the groupName
    int curveNid = OBJ_sn2nid(groupName);
    if (curveNid == 0) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_GEN_KEY_TITLE, "Failed to get curveNid", NULL);
        KeyIso_free(pubKeyBytes);
        KeyIso_free(groupName);
        return NULL;
    }

    // Create public key from components
    if (KeyIso_create_ec_evp_pub_key(curveNid, pubKeyBytes, pubKeyLen, &pubKey) != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_GEN_KEY_TITLE, "Failed to create public key", NULL);
        pubKey = NULL;
    }

    KeyIso_free(pubKeyBytes);
    KeyIso_free(groupName);
    
    return pubKey;
}
#endif