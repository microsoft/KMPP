/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/pkcs12.h>

#include "keyisoclient.h"
#include "keyisoclientinternal.h"
#include "keyisocommon.h"
#include "keyisopfxclientinternal.h"
#include "keyisolog.h"
#include "keyisocert.h"
#include "keyisoutils.h"
#include "keyisomemory.h"
#include "keyisotelemetry.h"
#include "keyisocertinternal.h"
#include "keyisoclientmsghandler.h"

#include "kmppgdbuspfxclient.h"

// Temporary: for testing / In-proc
#include <symcrypt.h>
#include <openssl/ossl_typ.h>
#include "keyisoserviceapi.h"
#include "keyisoservicekey.h"
#include "keyisoserviceapiossl.h"
 
extern CLIENT_MSG_HANDLER_FUNCTIONS_TABLE_ST g_msgHandlerImplementation;
extern KEYISO_CLIENT_CONFIG_ST g_config; 

static int _client_common_open(
    const uuid_t correlationId,
    const char* title,
    int pfxLength,
    const unsigned char* pfxBytes,
    const char* salt,
    KEYISO_KEY_CTX** keyCtx)
{
    int ret = STATUS_FAILED;
    KEYISO_KEY_CTX *ctx = NULL;
    ERR_clear_error();

    // Check that pfx size doesn't exceed the maximum
    if (pfxLength > KMPP_MAX_MESSAGE_SIZE) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, NULL, "Encrypted Pfx file is too big", "length: %d", pfxLength);
        return ret;
    }

    ctx = (KEYISO_KEY_CTX *) KeyIso_zalloc(sizeof(KEYISO_KEY_CTX));
    if (ctx == NULL) {
        return ret;
    }

    if (correlationId == NULL) {
        KeyIso_rand_bytes(ctx->correlationId, sizeof(ctx->correlationId));
    } else {
        memcpy(ctx->correlationId, correlationId, sizeof(ctx->correlationId));
    }

    KEYISOP_trace_log(ctx->correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Start");

    ret = g_msgHandlerImplementation.init_key(ctx, pfxLength, pfxBytes, salt);
    if (!ret) {
        KEYISOP_trace_log_error(ctx->correlationId, 0, title, "Complete", "Open failed");
        KeyIso_CLIENT_pfx_close(ctx);
        ctx = NULL;
        return ret;
    } else {
        KEYISOP_trace_log(ctx->correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete");
    }
    ctx->isP8Key = true;
    *keyCtx = ctx;
    return ret;
}

static int _get_type_by_name(
    const uuid_t correlationId,
    const CONF *conf)    
{
    const char *keyType = KeyIso_conf_get_string(correlationId, conf, "key_type");

    if (keyType != NULL) {
        if (strcmp(keyType, KMPP_KEY_TYPE_STR_EC) == 0) {
            return EVP_PKEY_EC;
        } else if (strcmp(keyType, KMPP_KEY_TYPE_STR_RSA) == 0) {
            return EVP_PKEY_RSA;
        }
    }

    return NID_undef;
}

static uint8_t _get_usage_from_string(
    const uuid_t correlationId,
    const char *title,
    const char *keyUsage)
{
    if (keyUsage == NULL)
        return KMPP_KEY_USAGE_INVALID;
    uint8_t usage = KMPP_KEY_USAGE_INVALID;

    if (strstr(keyUsage, KMPP_KEY_USAGE_SIGN_STR) != NULL)
        usage |= KMPP_KEY_USAGE_RSA_SIGN_ECDSA;
        
    if (strstr(keyUsage, KMPP_KEY_USAGE_ENCRYPT_STR) != NULL)
        usage |= KMPP_KEY_USAGE_RSA_ENCRYPT_ECDH;
    
    if (strstr(keyUsage, KMPP_KEY_USAGE_KEY_ENCIPHERMENT_STR) != NULL)
        usage |= KMPP_KEY_USAGE_RSA_ENCRYPT_ECDH;
    
    if (strstr(keyUsage, KMPP_KEY_USAGE_KEY_AGREEMENT_STR) != NULL)
        usage |= KMPP_KEY_USAGE_RSA_ENCRYPT_ECDH;

    if (usage == KMPP_KEY_USAGE_INVALID) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "keyUsage", "Supported key usage string was not found",
            "keyUsage: %s", keyUsage);
    }
    
    return usage;
}

static uint8_t _get_usage_from_keyiso_flags(
    const uuid_t correlationId,
    const char *title,
    const int keyisoFlags)
{
    uint8_t keyUsage = KMPP_KEY_USAGE_INVALID;

    if (keyisoFlags & KEYISO_KEY_USAGE_SIGN_FLAG)
        keyUsage |= KMPP_KEY_USAGE_RSA_SIGN_ECDSA;

    if (keyisoFlags & KEYISO_KEY_USAGE_ENCRYPT_FLAG)
        keyUsage |= KMPP_KEY_USAGE_RSA_ENCRYPT_ECDH;

    if (keyisoFlags & KEYISO_KEY_USAGE_KEY_AGREEMENT_FLAG)
        keyUsage |= KMPP_KEY_USAGE_RSA_ENCRYPT_ECDH;

    return keyUsage;
}

static void _get_usage_string_from_keyiso_flags(int keyisoFlags, char* usageStr, size_t len)
{
    if (usageStr == NULL || len == 0) {
        return;
    }
    usageStr[0] = '\0';  // Initialize the string

    int isUsageFlags = keyisoFlags & (KEYISO_KEY_USAGE_SIGN_FLAG | KEYISO_KEY_USAGE_ENCRYPT_FLAG | KEYISO_KEY_USAGE_KEY_AGREEMENT_FLAG);
    if (isUsageFlags == 0) {
        strncat(usageStr, KMPP_KEY_USAGE_SIGN_STR, len - strlen(usageStr) - 1);
        strncat(usageStr, " ", len - strlen(usageStr) - 1);
        strncat(usageStr, KMPP_KEY_USAGE_ENCRYPT_STR, len - strlen(usageStr) - 1);
    } else {
        if (isUsageFlags & KEYISO_KEY_USAGE_SIGN_FLAG) {
            strncat(usageStr, KMPP_KEY_USAGE_SIGN_STR, len - strlen(usageStr) - 1);
            strncat(usageStr, " ", len - strlen(usageStr) - 1);
        }
            
        if (isUsageFlags & KEYISO_KEY_USAGE_ENCRYPT_FLAG) {
            strncat(usageStr, KMPP_KEY_USAGE_ENCRYPT_STR, len - strlen(usageStr) - 1);
            strncat(usageStr, " ", len - strlen(usageStr) - 1);
        }
        
        if (isUsageFlags & KEYISO_KEY_USAGE_KEY_AGREEMENT_FLAG) {
            strncat(usageStr, KMPP_KEY_USAGE_KEY_AGREEMENT_STR, len - strlen(usageStr) - 1);
        }
    }

    // Remove trailing space
    if (strlen(usageStr) > 0) {
        usageStr[strlen(usageStr) - 1] = '\0';
    }
}

static int _get_key_usage(
    const uuid_t correlationId,
    const char *title,
    int keyisoFlags,
    const CONF *conf,
    uint8_t *keyUsage)
{
    if (keyUsage == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "keyUsage", "keyUsage is NULL");
        return STATUS_FAILED;
    }
    *keyUsage = KMPP_KEY_USAGE_INVALID;

    // Get key usage from conf
    if (conf != NULL) {
        const char *keyUsageStr = KeyIso_conf_get_string(correlationId, conf, KMPP_KEY_USAGE_STR);
        if (keyUsageStr != NULL) {
            *keyUsage |= _get_usage_from_string(correlationId, title, keyUsageStr);
            if (*keyUsage == KMPP_KEY_USAGE_INVALID)
                return STATUS_FAILED;   // key_use was found in conf but it is not supported
        } else {
            KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "key usage property was not found in Conf");
        }
    }
        
    // Get key usage from keyisoFlags
    *keyUsage |= _get_usage_from_keyiso_flags(correlationId, title, keyisoFlags);
    if (*keyUsage == KMPP_KEY_USAGE_INVALID)
        KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "keyUsage", "Supported key usage flag was not found. keyisoFlags: 0x%x", keyisoFlags);

    // If keyUsage is still invalid, set it to default value
    if (*keyUsage == KMPP_KEY_USAGE_INVALID) {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "key usage was not provided. Using default value");
        *keyUsage = KMPP_KEY_USAGE_RSA_ENCRYPT_ECDH | KMPP_KEY_USAGE_RSA_SIGN_ECDSA;
    }

    return STATUS_OK;
}

static int _get_rsa_param(
    const uuid_t correlationId,
    const CONF *conf, 
    unsigned int *rsaBits)
{
    long bits = 0;

    if (!KeyIso_conf_get_number(correlationId, conf, KMPP_KEY_PARAM_BITS_STR, &bits)) {
        return STATUS_FAILED;
    }

    if (bits > KMPP_OPENSSL_RSA_MAX_MODULUS_BITS || bits < KMPP_RSA_MIN_MODULUS_BITS) {
        KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_GEN_KEY_TITLE, KMPP_KEY_PARAM_BITS_STR, "Invalid key length",
            "rsa_bits: %ld", bits);
        return STATUS_FAILED;
    }      

    if (rsaBits)
        *rsaBits = (unsigned int) bits;  // The value of bits is in the range between 2048 and 16384

    return STATUS_OK;
}

static int _create_encrypted_pfx_bytes(
    const uuid_t correlationId,
    X509_SIG *inP8,
    X509 *inCert,
    STACK_OF(X509) *inCa,
    int *outPfxLength,
    unsigned char **outPfxBytes)
{
    int outLength = 0;
    unsigned char *outBytes = NULL;         // don't free

    BIO *pfxBio = NULL;
    PKCS12 *p12 = NULL;

    *outPfxLength = 0;
    *outPfxBytes = NULL;

    // Creating new PKCS #12
    p12 = KeyIso_pkcs12_create_p8(inP8, inCert, inCa);
    if (!p12) {
        KEYISOP_trace_log(correlationId, 0, KEYISOP_CREATE_PFX_TITLE, "creating PFX failed");
        return STATUS_FAILED;
    }

    // Writing PFX bytes
    pfxBio = KeyIsoP_create_pfx_bio(
        correlationId,
        p12,
        &outLength,
        &outBytes);
    if (pfxBio == NULL) {
        KEYISOP_trace_log(correlationId, 0, KEYISOP_CREATE_PFX_TITLE, "creating PFX BIO failed");
        PKCS12_free(p12);
        return STATUS_FAILED;
    }

    *outPfxBytes = (unsigned char *)KeyIso_zalloc(outLength);
    if (*outPfxBytes == NULL) {
        KEYISOP_trace_log(correlationId, 0, KEYISOP_CREATE_PFX_TITLE, "Allocation failed");
        PKCS12_free(p12);
        BIO_free(pfxBio);
        return STATUS_FAILED;
    }

    memcpy(*outPfxBytes, outBytes, outLength);
    *outPfxLength = outLength;

    PKCS12_free(p12);
    BIO_free(pfxBio);

    return STATUS_OK;
}

////////////////////////////////////////////////
///////   KeyIso_CLIENT_* P8 interface   ///////
////////////////////////////////////////////////

int KeyIso_CLIENT_private_key_open_from_pfx(
    const uuid_t correlationId,
    int pfxLength,
    const unsigned char* pfxBytes,
    const char* salt,
    KEYISO_KEY_CTX** keyCtx)
{
    uuid_t randId;
    if (correlationId == NULL) {
        KeyIso_rand_bytes(randId, sizeof(randId));
        correlationId = randId;
    }

    KEYISOP_trace_log(correlationId, 0, KEYISOP_OPEN_KEY_TITLE, "start");

    int ret = _client_common_open(correlationId, KEYISOP_OPEN_KEY_TITLE, pfxLength, pfxBytes, salt, keyCtx);
    if (ret != STATUS_OK) {
        return ret;
    }

    KEYISOP_trace_log((*keyCtx)->correlationId, 0, KEYISOP_OPEN_KEY_TITLE, "Complete");
    return STATUS_OK;
}

static int _cleanup_import_private_key(
    int ret,
    const uuid_t correlationId, 
    const char *loc,
    const char *err,
    void *privateKey,
    size_t privateKeySize,
    X509_SIG *encKey,
    char *salt)
{
    KeyIso_clear_free(privateKey, privateKeySize);
    if(ret != STATUS_OK) {
        KeyIso_clear_free_string(salt);
        X509_SIG_free(encKey);
        encKey = NULL;
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, loc, err);
    }

    return ret;
}

int KeyIso_CLIENT_import_private_key( 
    const uuid_t correlationId,
    int keyisoFlags,
    const EVP_PKEY *inPkey,      // PKCS #8 ANS.1 encoded Private Key  
    X509_SIG **outEncryptedPkey, // X509_SIG_free()
    char **outSalt)              // KeyIso_clear_free_string()
{
    int ret = STATUS_FAILED;

    char *salt = NULL;
    void *privateKey = NULL; // KeyIso_clear_free()
    X509_SIG *encKey = NULL;
    int keyType = NID_undef;
    size_t privateKeySize = 0;

   
   if (!outEncryptedPkey || !outSalt) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "outEncryptedPkey or outSalt", "output parameter is NULL");
        return STATUS_FAILED;
    }
    if (!inPkey) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "inPkey", "input parameter is NULL");
        return STATUS_FAILED;
    }

    keyType = EVP_PKEY_id(inPkey);
    switch (keyType) {
        case EVP_PKEY_RSA:
        case EVP_PKEY_RSA_PSS:
            privateKey = (void *) KeyIso_export_rsa_epkey(correlationId, inPkey, &privateKeySize);  
            break;
        case EVP_PKEY_EC:
            privateKey = (void *) KeyIso_export_ec_private_key(correlationId, inPkey, &privateKeySize);
            break;
        default:
            KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "inPkey", "unsupported key type");
    }

    if (!privateKey) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "privateKey", "parameter is NULL");
        return STATUS_FAILED;
    }

    ret = g_msgHandlerImplementation.import_private_key(correlationId, keyType, (unsigned char *) privateKey, &encKey, &salt);     

    if (ret != STATUS_OK)
        return _cleanup_import_private_key(ret, correlationId, "Complete", "Import failed", privateKey, privateKeySize, encKey, salt);
    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_IMPORT_KEY_TITLE, "Complete");
    *outEncryptedPkey = encKey;
    *outSalt = salt;
    
    return _cleanup_import_private_key(STATUS_OK, correlationId, KEYISOP_IMPORT_KEY_TITLE, "Complete", privateKey, privateKeySize, encKey, salt);
}


static int _cleanup_generate_rsa_key_pair(
    int ret,
    const uuid_t correlationId,
    const char *loc,
    const char *message,
    char *salt,
    EVP_PKEY *pubKmppKey,
    X509_SIG *encryptedPkey)
{
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_GEN_KEY_TITLE, loc, message);
        KeyIso_clear_free_string(salt);
        X509_SIG_free(encryptedPkey);
        EVP_PKEY_free(pubKmppKey);
    }
    return ret;
}

#define _CLEANUP_GENERATE_RSA_KEY_PAIR(ret, loc, message) \
    _cleanup_generate_rsa_key_pair(ret, correlationId, loc, message, salt, pubEpkey, encryptedPkey)

int KeyIso_CLIENT_generate_rsa_key_pair( 
    const uuid_t correlationId,
    int keyisoFlags, 
    const CONF *conf,
    EVP_PKEY **outPubKey, 
    X509_SIG **outEncryptedPkeyP8,
    char **outSalt)
{
    uuid_t randId;
    char *salt = NULL;  
    uint8_t keyUsage = KMPP_KEY_USAGE_INVALID;
    EVP_PKEY* pubEpkey = NULL;
    X509_SIG *encryptedPkey = NULL;
    int ret = STATUS_FAILED;
    unsigned int rsaBits;

    if (correlationId == NULL) {
        KeyIso_rand_bytes(randId, sizeof(randId));
        correlationId = randId;
    }

    KEYISOP_trace_log_para(correlationId, 0, KEYISOP_GEN_KEY_TITLE, "Start",
        "flags: 0x%x", keyisoFlags);

    if(conf == NULL || outPubKey == NULL || outEncryptedPkeyP8 == NULL || outSalt == NULL)
        return _CLEANUP_GENERATE_RSA_KEY_PAIR(STATUS_FAILED, "Rsa key generation", "invalid argument");
    *outPubKey = NULL;
    *outEncryptedPkeyP8 = NULL;
    *outSalt = NULL;

    ret =_get_rsa_param(correlationId, conf, &rsaBits);
    if (ret != STATUS_OK) {
        return _CLEANUP_GENERATE_RSA_KEY_PAIR(STATUS_FAILED, "_get_rsa_param", "Failed");
    }

    ret = _get_key_usage(correlationId, KEYISOP_GEN_KEY_TITLE, keyisoFlags, conf, &keyUsage);
    if (ret != STATUS_OK) {
        return _CLEANUP_GENERATE_RSA_KEY_PAIR(STATUS_FAILED, "keyUsage", "Failed");
    }
    
    ret = g_msgHandlerImplementation.generate_rsa_key_pair(correlationId, rsaBits, keyUsage, &pubEpkey, &encryptedPkey, &salt);
          
    if (ret != STATUS_OK) {
        return _CLEANUP_GENERATE_RSA_KEY_PAIR(STATUS_FAILED, "Generate key pair", "Failed");
    }

    *outPubKey = pubEpkey;
    *outEncryptedPkeyP8 = encryptedPkey;
    *outSalt = salt;
    KEYISOP_trace_log(correlationId, 0, KEYISOP_GEN_KEY_TITLE, "Complete");
    return _CLEANUP_GENERATE_RSA_KEY_PAIR(STATUS_OK, NULL, NULL);
}

int _cleanup_generate_ec_key_pair(
     int ret,
     const uuid_t correlationId,
     const char *message,
     char *salt,
     X509_SIG *encKey,
     EC_GROUP *ecGroup,
     EC_KEY *ecKey)
{
    if (ret != STATUS_OK) {
        EC_KEY_free(ecKey);
        EC_GROUP_free(ecGroup);
        X509_SIG_free(encKey);
        KeyIso_clear_free_string(salt);
        KEYISOP_trace_log_openssl_error(correlationId, 0, KEYISOP_GEN_KEY_TITLE, message);
    } else {
        KEYISOP_trace_log(correlationId, 0, KEYISOP_GEN_KEY_TITLE, message);
    }
    return ret;
}

#define _CLEANUP_GENERATE_EC_KEY_PAIR(ret, message) \
    _cleanup_generate_ec_key_pair(ret, correlationId, message, salt, encryptedKey, ecGroup, pubEckey)

int KeyIso_CLIENT_generate_ec_key_pair( 
    const uuid_t correlationId,
    int keyisoFlags, 
    const CONF *conf,
    EC_GROUP **outEcGroup,
    EC_KEY **outPubKey, 
    X509_SIG **outEncryptedPkey,
    char **outSalt)
{
    char *salt = NULL;  
    uint8_t keyUsage = KMPP_KEY_USAGE_INVALID;
    uuid_t randId;
    EC_GROUP *ecGroup = NULL;
    EC_KEY *pubEckey = NULL;
    X509_SIG *encryptedKey = NULL;
    int ret = STATUS_FAILED;
    unsigned int curve;
    
    if (correlationId == NULL) {
        KeyIso_rand_bytes(randId, sizeof(randId));
        correlationId = randId;
    }

    KEYISOP_trace_log_para(correlationId, 0, KEYISOP_GEN_KEY_TITLE, "Start",
        "flags: 0x%x", keyisoFlags);
    
    if(conf == NULL || outPubKey == NULL || outEncryptedPkey == NULL || outSalt == NULL || outEcGroup == NULL) {
        return _CLEANUP_GENERATE_EC_KEY_PAIR(ret, "Invalid argument");
    }

    *outPubKey = NULL;
    *outEncryptedPkey = NULL;
    *outSalt = NULL;
    *outPubKey = NULL;
    *outEcGroup = NULL;

    ret = KeyIso_conf_get_curve_nid(correlationId, conf, &curve);
    if (ret != STATUS_OK) {
        return _CLEANUP_GENERATE_EC_KEY_PAIR(STATUS_FAILED, "KeyIso_conf_get_curve_nid failed");
    }

    ret = _get_key_usage(correlationId, KEYISOP_GEN_KEY_TITLE, keyisoFlags, conf, &keyUsage);
    if (ret != STATUS_OK) {
        return _CLEANUP_GENERATE_EC_KEY_PAIR(STATUS_FAILED, "_get_key_usage failed");
    }
    
    ret = g_msgHandlerImplementation.generate_ec_key_pair(correlationId, curve, keyUsage, &ecGroup, &pubEckey, &encryptedKey, &salt);
           
    if (ret != STATUS_OK) {
        return _CLEANUP_GENERATE_EC_KEY_PAIR(STATUS_FAILED, "Generate key pair");
    }

    *outPubKey = pubEckey;
    *outEcGroup = ecGroup;
    *outEncryptedPkey = encryptedKey;
    *outSalt = salt;
    return _CLEANUP_GENERATE_EC_KEY_PAIR(STATUS_OK, "Complete");
}

static int _cleanup_import_pfx_private_key(
    int ret,
    const char *loc,
    const char *err,
    const char* sha256HexHash,
    EVP_PKEY *pkey,
    X509 *cert,
    STACK_OF(X509) *inCa,
    STACK_OF(X509) *outCa,
    X509_SIG *p8)
{
    if (!ret) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_PFX_TITLE, loc, err);
        KEYISOP_trace_metric_error_para(NULL, 0, g_config.solutionType, KEYISOP_IMPORT_PFX_TITLE, loc, "Import failed.", "sha256:%s", sha256HexHash);
        X509_SIG_free(p8);   // should not be freed at success 
    }
    EVP_PKEY_free(pkey);
    X509_free(cert);
    sk_X509_pop_free(inCa, X509_free);
    sk_X509_pop_free(outCa, X509_free);
    return ret;
}

int KeyIso_CLIENT_import_private_key_from_pfx(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *inPassword,                     // Optional
    int *outVerifyChainError,
    int *outPfxLength,
    unsigned char **outPfxBytes,                // KeyIso_free()
    char **outPfxSalt)                          // KeyIso_free()
{
    const char *title = KEYISOP_IMPORT_PFX_TITLE;
    int ret = STATUS_FAILED;

    int buildPfxCaRet = 0;
    uuid_t randId;
    char *salt = NULL;
    X509_SIG *p8 = NULL;
    EVP_PKEY *inPfxPkey = NULL;
    X509 *inPfxCert = NULL;
    STACK_OF(X509) *inPfxCa = NULL;
    STACK_OF(X509) *outPfxCa = NULL;

    if (!outVerifyChainError || !outPfxLength || !outPfxBytes || !outPfxSalt) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_PFX_TITLE, "Failed", "Missing output parameters");
        return STATUS_FAILED;
    }

    *outVerifyChainError = 0;
    *outPfxLength = 0;
    *outPfxBytes = NULL;
    *outPfxSalt = NULL;

    char sha256HexHash[SHA256_DIGEST_LENGTH * 2 + 1];

    if (correlationId == NULL) {
        KeyIso_rand_bytes(randId, sizeof(randId));
        correlationId = randId;
    }

    KEYISOP_trace_log_para(correlationId, 0, title, "Start", "flags: 0x%x, solutionType: %d, isDefaultConfig: %d", keyisoFlags, g_config.solutionType, g_config.isDefault);

    ERR_clear_error();

    // PKCS #12 parsing
    ret = KeyIso_pkcs12_parse(correlationId, inPfxLength, inPfxBytes, inPassword, &inPfxPkey, &inPfxCert, &inPfxCa);

    if (inPfxCert != NULL) {
        // Extract sha256 string out of the public key of the cert.
        KeyIsoP_X509_pubkey_sha256_hex_hash(inPfxCert, sha256HexHash);
    } else {
        const char* errCert = "NoCert";
        snprintf(sha256HexHash, sizeof(errCert), "%s", errCert);
    }

    if (inPfxPkey) {
        uint8_t usage = KMPP_KEY_USAGE_INVALID;
        ret = _get_key_usage(correlationId, KEYISOP_IMPORT_PFX_TITLE, keyisoFlags, NULL, &usage);
        if (ret != STATUS_OK)
            return _cleanup_import_pfx_private_key(ret, "_get_key_usage", "Failed", sha256HexHash, inPfxPkey, inPfxCert, inPfxCa, outPfxCa, p8);
        unsigned char us_val = (unsigned char)usage;
        EVP_PKEY_add1_attr_by_NID(inPfxPkey, NID_key_usage, V_ASN1_BIT_STRING, &us_val, 1);
    }

    if (ret != STATUS_OK)
        return _cleanup_import_pfx_private_key(ret, "KeyIso_pkcs12_parse", "Failed", sha256HexHash, inPfxPkey, inPfxCert, inPfxCa, outPfxCa, p8);

    // certificate validation
    if ((keyisoFlags & KEYISO_SKIP_VALIDATE_CERT) == 0) {
        ret = KeyIso_validate_certificate(
            correlationId,
            KEYISO_EXCLUDE_END_FLAG |
                KEYISO_IGNORE_DEPTH_ZERO_SELF_SIGNED_ERROR_FLAG |
                (keyisoFlags & KEYISO_EXCLUDE_EXTRA_CA_FLAG),
            inPfxCert,
            inPfxCa,
            outVerifyChainError,
            &outPfxCa);
        buildPfxCaRet = ret;
        if (ret == STATUS_FAILED) {
            return _cleanup_import_pfx_private_key(ret, "verify_cert2", "unable to build chain", sha256HexHash, inPfxPkey, inPfxCert, inPfxCa, outPfxCa, p8);
        }
    }
    else {
        buildPfxCaRet = 1;
    }
  
    ret = KeyIso_CLIENT_import_private_key( 
        correlationId,
        keyisoFlags, 
        inPfxPkey,
        &p8,
        &salt);
    if (ret != STATUS_OK)
        return _cleanup_import_pfx_private_key(ret, "KeyIso_CLIENT_import_private_key", "Failed", sha256HexHash, inPfxPkey, inPfxCert, inPfxCa, outPfxCa, p8);

    // creating encrypted pfx
    ret = _create_encrypted_pfx_bytes(correlationId, p8, inPfxCert, inPfxCa, outPfxLength, outPfxBytes);
    if (ret != STATUS_OK)
        return _cleanup_import_pfx_private_key(ret, "_create_encrypted_pfx_bytes", "Failed", sha256HexHash, inPfxPkey, inPfxCert, inPfxCa, outPfxCa, p8);

    // Print metric of the imported key.
    char usageStr[64];
    _get_usage_string_from_keyiso_flags(keyisoFlags, usageStr, sizeof(usageStr));
    KEYISOP_trace_metric_para(correlationId, 0, g_config.solutionType, title, NULL,"Key import succeeded. sha256: %s. Usage: <%s>", sha256HexHash, usageStr);
    *outPfxSalt = salt;
    
    ret = buildPfxCaRet;
    if (ret < 0) {
        KEYISOP_trace_log_openssl_verify_cert_error(correlationId, 0, title, "X509_verify_cert", *outVerifyChainError);
        return _cleanup_import_pfx_private_key(ret, "Complete", "Import succeeded with certificate errors", sha256HexHash, inPfxPkey, inPfxCert, inPfxCa, outPfxCa, p8);
    }

    return _cleanup_import_pfx_private_key(ret, "Complete", "", sha256HexHash, inPfxPkey, inPfxCert, inPfxCa, outPfxCa, p8);
}

static int _cleanup_self_sign_key_generation(
    const uuid_t correlationId, 
    int status,
    const char *errStr,
    EVP_PKEY *generatedPubKey,
    EC_GROUP *generatedEccGroup,
    EC_KEY *generatedEccPubKey)
{
    const char *title = KEYISOP_CREATE_SELF_SIGN_TITLE;
    if (errStr != NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, errStr);
    }

    EVP_PKEY_free(generatedPubKey);
    EC_GROUP_free(generatedEccGroup);
    EC_KEY_free(generatedEccPubKey);

    return status;
}

int _create_self_sign_key_generation(
    const uuid_t correlationId,
    const int keyType,
    const int keyisoFlags,
    char **pfxSalt,
    const CONF* conf,
    X509 *cert,
    X509_SIG **generatedEncryptedPkey)
{
    const char *title = KEYISOP_CREATE_SELF_SIGN_TITLE;
    EVP_PKEY *generatedPubKey = NULL;
    EC_GROUP *generatedEccGroup = NULL;
    EC_KEY *generatedEccPubKey = NULL;

    if (keyType == EVP_PKEY_RSA) {
        if (KeyIso_CLIENT_generate_rsa_key_pair(correlationId, keyisoFlags, conf, &generatedPubKey, generatedEncryptedPkey, pfxSalt) != STATUS_OK) {
            return _cleanup_self_sign_key_generation(correlationId, STATUS_FAILED, "Failed to generate rsa key pair", generatedPubKey, generatedEccGroup, generatedEccPubKey);
        }

    } else if (keyType == EVP_PKEY_EC) {
        if (KeyIso_CLIENT_generate_ec_key_pair(correlationId, keyisoFlags, conf, &generatedEccGroup, &generatedEccPubKey, generatedEncryptedPkey, pfxSalt) != STATUS_OK) {
            return _cleanup_self_sign_key_generation(correlationId, STATUS_FAILED, "Failed to generate ecc key pair", generatedPubKey, generatedEccGroup, generatedEccPubKey);
        }
        // Create the public key from the EC_KEY
        generatedPubKey = EVP_PKEY_new();
        if (generatedPubKey == NULL) {
            return _cleanup_self_sign_key_generation(correlationId, STATUS_FAILED, "Failed to allocate EVP_PKEY", generatedPubKey, generatedEccGroup, generatedEccPubKey);
        }
        // Set the EC_KEY as the public key for the EVP_PKEY
        if (EVP_PKEY_set1_EC_KEY(generatedPubKey, generatedEccPubKey) != 1) {
            return _cleanup_self_sign_key_generation(correlationId, STATUS_FAILED, "Failed to generate public key from EC_KEY", generatedPubKey, generatedEccGroup, generatedEccPubKey);
        }
    } else {
        return _cleanup_self_sign_key_generation(correlationId, STATUS_FAILED, "Unsupported key type", generatedPubKey, generatedEccGroup, generatedEccPubKey);
    }

    // Cert creation - for generating the cert that will be signed
    if (!X509_set_pubkey(cert, generatedPubKey)) {
        KEYISOP_trace_log_openssl_error(correlationId, 0, title, "X509_set_pubkey");
        return _cleanup_self_sign_key_generation(correlationId, STATUS_FAILED, NULL, generatedPubKey, generatedEccGroup, generatedEccPubKey);
    }

    return _cleanup_self_sign_key_generation(correlationId, STATUS_OK, NULL, generatedPubKey, generatedEccGroup, generatedEccPubKey);
}

int _create_self_sign_cert_configuration(
    const uuid_t correlationId,
    CONF* conf,
    X509 *cert)
{
    const char *title = KEYISOP_CREATE_SELF_SIGN_TITLE;

    if (!KeyIso_conf_get_name(correlationId, conf, cert)) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, "KeyIso_conf_get_name failed");
        return STATUS_FAILED;
    }

    if (!KeyIso_conf_get_time(correlationId, conf, cert)) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, "KeyIso_conf_get_time failed");
        return STATUS_FAILED;
    }

    if (!KeyIso_conf_get_extensions(correlationId, conf, cert)) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, "KeyIso_conf_get_extensions failed");
        return STATUS_FAILED;
    }

    return STATUS_OK;
}

int _create_self_sign_dummy_sign(
    const uuid_t correlationId,
    const int keyType,
    const CONF* conf,
    X509 *cert)
{
    const char *title = KEYISOP_CREATE_SELF_SIGN_TITLE;
    EVP_PKEY *dummyPkey = NULL;
    int status = STATUS_FAILED;

    if (keyType == EVP_PKEY_RSA) {
        dummyPkey = KeyIso_conf_generate_rsa(correlationId, conf);
    } else if (keyType == EVP_PKEY_EC) {
        dummyPkey = KeyIso_conf_generate_ecc(correlationId, conf);
    }

    if (dummyPkey == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, "Failed to generate dummy key");
        return STATUS_FAILED;
    }

    if (X509_sign(cert, dummyPkey, EVP_sha256()) <= 0) {
        KEYISOP_trace_log_openssl_error(correlationId, 0, title, "X509_sign");
    } else {
        status = STATUS_OK;
    }

    EVP_PKEY_free(dummyPkey);
    return status;
}

int _create_self_sign_key_handle(
    const uuid_t correlationId,
    X509_SIG *generatedEncryptedPkey,
    X509 *cert,
    const char *pfxSalt,
    char **encryptedKeyId)
{
    const char *title = KEYISOP_CREATE_SELF_SIGN_TITLE;
    int encryptedPfxLength = 0;
    unsigned char *encryptedPfxBytes = NULL;

    if (_create_encrypted_pfx_bytes(correlationId, generatedEncryptedPkey, cert, NULL, &encryptedPfxLength, &encryptedPfxBytes) != STATUS_OK) {
        KeyIso_free(encryptedPfxBytes);
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, "creating encrypted PFX failed");
        return STATUS_FAILED;
    }
    if (!KeyIso_format_pfx_engine_key_id(correlationId, encryptedPfxLength, encryptedPfxBytes, pfxSalt, encryptedKeyId)) {
        KeyIso_free(encryptedPfxBytes);
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, "KeyIso_format_pfx_engine_key_id_ex failed");
        return STATUS_FAILED;
    }

    KeyIso_free(encryptedPfxBytes);
    return STATUS_OK;
}

static int _cleanup_create_self_sign_pfx_p8(
    const uuid_t correlationId,
    int status,
    const char *errStr,
    X509 *cert,
    char *encryptedKeyId,
    CONF *conf)
{
    const char *title = KEYISOP_CREATE_SELF_SIGN_TITLE;
    if (status != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, errStr);
    }

    X509_free(cert);
    KeyIso_clear_free_string(encryptedKeyId);
    NCONF_free(conf);

    return status;
}
/* Note:
 Currently, self - signing using the engine is invoked even
 if we are working with OpenSSL 3.x and the KMPP provider is available,
 until we implement ECC in the provider as well.
 Once ECC is implemented, this function will be removed and the implementations in
 keyisoclienteng.c and keyisoclientprov.c will be re-enabled.
*/
int KeyIso_cert_sign(
    const uuid_t correlationId, 
    CONF *conf, 
    X509 *cert, 
    const char *encryptedKeyId)
{
    EVP_PKEY *encryptedKeyPkey = NULL;
    int ret = STATUS_FAILED;

    encryptedKeyPkey = KeyIso_load_engine_private_key(correlationId, KMPP_ENGINE_ID, encryptedKeyId);
    if (encryptedKeyPkey == NULL) {
        return STATUS_FAILED;
    }

    ret = KeyIso_conf_sign(correlationId, conf, cert, encryptedKeyPkey);

    EVP_PKEY_free(encryptedKeyPkey);
    return ret;
}

int KeyIso_CLIENT_create_self_sign_pfx_p8(
    const uuid_t correlationId,
    const int keyisoFlags,
    const char *confStr,
    int *pfxLength,
    unsigned char **pfxBytes,
    char **pfxSalt)
{
    const char *title = KEYISOP_CREATE_SELF_SIGN_TITLE;
    CONF *conf = NULL;
    int keyType = 0;
    X509_SIG *generatedEncryptedPkey = NULL;
    X509_SIG *pkcs8Signature = NULL;
    X509 *cert = NULL;
    char *encryptedKeyId = NULL;

    *pfxLength = 0;
    *pfxBytes = NULL;
    *pfxSalt = NULL;
    char sha256HexHash[SHA256_DIGEST_LENGTH * 2 + 1] = "\0";

    KEYISOP_trace_log_para(correlationId, 0, title, "Start", "flags: 0x%x, solutionType: %d, isDefaultConfig: %d", keyisoFlags, g_config.solutionType, g_config.isDefault);

    ERR_clear_error();

    // confStr parsing
    if (KeyIso_conf_load(correlationId, confStr, &conf) != STATUS_OK) {
        return _cleanup_create_self_sign_pfx_p8(correlationId, STATUS_FAILED, "Failed to load configuration", cert, encryptedKeyId, conf);
    }

    // get key type and validate
    keyType = _get_type_by_name(correlationId, conf);
    if (keyType != EVP_PKEY_RSA && keyType != EVP_PKEY_EC) {
        return _cleanup_create_self_sign_pfx_p8(correlationId, STATUS_FAILED, "Invalid key_type", cert, encryptedKeyId, conf);
    }

    // key generation
    cert = X509_new();
    if (_create_self_sign_key_generation(correlationId, keyType, keyisoFlags, pfxSalt, conf, cert, &generatedEncryptedPkey) != STATUS_OK) {
        return _cleanup_create_self_sign_pfx_p8(correlationId, STATUS_FAILED, "Failed to generate key", cert, encryptedKeyId, conf);
    }

    // Extract sha256 string out of the public key of the cert.
    KeyIsoP_X509_pubkey_sha256_hex_hash(cert, sha256HexHash);

    // cert configuration
    if (_create_self_sign_cert_configuration(correlationId, conf, cert) != STATUS_OK) {
        return _cleanup_create_self_sign_pfx_p8(correlationId, STATUS_FAILED, "Failed to configure cert", cert, encryptedKeyId, conf);
    }

    // Duplicate the encrypted key, to be used for signing
    pkcs8Signature = X509_SIG_new();
    if (KeyIso_x509_sig_dup(generatedEncryptedPkey, pkcs8Signature) != STATUS_OK) {
        return _cleanup_create_self_sign_pfx_p8(correlationId, STATUS_FAILED, "X509_SIG_dup failed", cert, encryptedKeyId, conf);
    }

    // Dummy key sign - for signing the cert temporary, this will allow to load the pfx to the engine
    if (_create_self_sign_dummy_sign(correlationId, keyType, conf, cert) != STATUS_OK) {
        return _cleanup_create_self_sign_pfx_p8(correlationId, STATUS_FAILED, "KeyIso_create_self_sign_dummy_sign failed", cert, encryptedKeyId, conf);
    }

    // create key handle from the encrypted key
    if (_create_self_sign_key_handle(correlationId, generatedEncryptedPkey, cert, *pfxSalt, &encryptedKeyId) != STATUS_OK) {
        return _cleanup_create_self_sign_pfx_p8(correlationId, STATUS_FAILED, "KeyIso_create_key_handle_from_encrypted_key failed", cert, encryptedKeyId, conf);
    }

    if (KeyIso_cert_sign(correlationId, conf, cert, encryptedKeyId) != STATUS_OK) {
        return _cleanup_create_self_sign_pfx_p8(correlationId, STATUS_FAILED, "KeyIso_cert_sign_engine failed", cert, encryptedKeyId, conf);
    }

    // Create the final pfx with the signed cert
    if (_create_encrypted_pfx_bytes(correlationId, pkcs8Signature, cert, NULL, pfxLength, pfxBytes) != STATUS_OK) {
        return _cleanup_create_self_sign_pfx_p8(correlationId, STATUS_FAILED, "creating encrypted PFX failed", cert, encryptedKeyId, conf);
    }

    char usageStr[64];
    _get_usage_string_from_keyiso_flags(keyisoFlags, usageStr, sizeof(usageStr));
    KEYISOP_trace_metric_para(correlationId, 0, g_config.solutionType, title, NULL,"create_self_sign_pfx succeeded. sha256: %s. Usage: <%s>", sha256HexHash, usageStr);

    KEYISOP_trace_log(correlationId, 0, title, "Complete");
    return _cleanup_create_self_sign_pfx_p8(correlationId, STATUS_OK, NULL, cert, encryptedKeyId, conf);
}

static int _cleanup_replace_pfx_certs_p8(
    int ret,
    EVP_PKEY *pkey1,
    EVP_PKEY *pkey2,  
    X509 *cert,
    STACK_OF(X509) *ca,
    X509_SIG *p8)
{
    EVP_PKEY_free(pkey1);
    EVP_PKEY_free(pkey2);
    X509_free(cert);
    sk_X509_pop_free(ca, X509_free);
    if (ret != STATUS_OK)
        X509_SIG_free(p8);
    return ret;
}

int KeyIso_replace_pfx_certs_p8(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    int pemCertLength,
    const unsigned char *pemCertBytes,
    int *outPfxLength,
    unsigned char **outPfxBytes)
{
    const char *title = KEYISOP_CREATE_SELF_SIGN_TITLE;
    int ret = STATUS_FAILED;

    int match = 0;

    X509_SIG *p8 = NULL; 
    X509 *pemCert = NULL;
    EVP_PKEY *pfxPubKey = NULL;
    EVP_PKEY *pemPubKey = NULL;
    STACK_OF(X509) *pemCa = NULL;

    *outPfxLength = 0;
    *outPfxBytes = NULL;

    ERR_clear_error();

    // Loading pfx cert's public key
    ret = KeyIso_load_pfx_pubkey(correlationId, inPfxLength, inPfxBytes, &pfxPubKey, NULL, NULL);
    if (ret != STATUS_OK) {
        KEYISOP_trace_log(correlationId, 0, title, "loading public key from PFX failed");
        return _cleanup_replace_pfx_certs_p8(ret, pfxPubKey, pemPubKey, pemCert, pemCa, p8);
    }

    // Loading pem cert's public key
    ret = KeyIso_load_pem_pubkey(correlationId, pemCertLength, pemCertBytes, &pemPubKey, &pemCert, &pemCa);
    if (ret != STATUS_OK) {
        KEYISOP_trace_log(correlationId, 0, title, "loading public key from PEM failed");
        return _cleanup_replace_pfx_certs_p8(ret, pfxPubKey, pemPubKey, pemCert, pemCa, p8);
    }

    // Public key matching
    match = EVP_PKEY_cmp(pfxPubKey, pemPubKey);
    if (match != STATUS_OK) {
        KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, "EVP_PKEY_cmp", "match: %d", match);
        return _cleanup_replace_pfx_certs_p8(STATUS_FAILED, pfxPubKey, pemPubKey, pemCert, pemCa, p8);
    }
    
    // Extracting encrypted PKCS #8 from PFX
    ret = KeyIso_pkcs12_parse_p8(correlationId, inPfxLength, inPfxBytes, &p8, NULL, NULL);
    if (ret != STATUS_OK) {
        KEYISOP_trace_log(correlationId, 0, title, "extracting encrypted key from PFX failed");
        return _cleanup_replace_pfx_certs_p8(ret, pfxPubKey, pemPubKey, pemCert, pemCa, p8);
    }

    // creating encrypted pfx
    ret = _create_encrypted_pfx_bytes(correlationId, p8, pemCert, pemCa, outPfxLength, outPfxBytes);
    if (ret != STATUS_OK) {
        KEYISOP_trace_log(correlationId, 0, title, "creating encrypted PFX failed");
        return _cleanup_replace_pfx_certs_p8(ret, pfxPubKey, pemPubKey, pemCert, pemCa, p8);
    }

    return _cleanup_replace_pfx_certs_p8(STATUS_OK, pfxPubKey, pemPubKey, pemCert, pemCa, p8);
}

static void _client_validate_keyid_cleanup(
    const uuid_t correlationId,
    unsigned char *pfxBytes, 
    char *salt,
    const char *errorReason)
{
    if (pfxBytes != NULL) {
        KeyIso_free(pfxBytes);
    }
    if (salt != NULL) {
        KeyIso_clear_free_string(salt);
    }
    if (errorReason != NULL) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_VALIDATE_KEY_TITLE, errorReason, "Failed");
    }
}

int KeyIso_validate_keyid(
    const uuid_t correlationId,
    const char *keyId) 
{
    int ret = STATUS_FAILED;
    KEYISO_KEY_CTX *keyCtx = NULL;     // KeyIso_CLIENT_pfx_close()
    int pfxLength = 0;
    unsigned char *pfxBytes = NULL;     // KeyIso_free()
    char *salt = NULL;
    uuid_t randId;

    if (keyId == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_VALIDATE_KEY_TITLE, "keyId", "input parameter is NULL");
        return STATUS_FAILED;
    }

    if (correlationId == NULL) {
        KeyIso_rand_bytes(randId, sizeof(randId));
        correlationId = randId;
    }
    
    KEYISOP_trace_log(correlationId, 0, KEYISOP_VALIDATE_KEY_TITLE, "Start");

    ret = KeyIso_parse_pfx_engine_key_id(correlationId, keyId, &pfxLength, &pfxBytes, &salt);
    if (ret != STATUS_OK) {
        KeyIso_CLIENT_pfx_close(keyCtx);
        _client_validate_keyid_cleanup(correlationId, pfxBytes, salt, "KeyIso_parse_pfx_engine_key_id");
        return ret;
    }

    ret = _client_common_open(correlationId, KEYISOP_VALIDATE_KEY_TITLE, pfxLength, pfxBytes, salt, &keyCtx);
    if (ret != STATUS_OK) {
        KeyIso_CLIENT_pfx_close(keyCtx);
        _client_validate_keyid_cleanup(correlationId, pfxBytes, salt, "_client_common_open");
        return ret;
    }

    ret = KeyIso_client_open_priv_key_message(keyCtx);
    if (ret != STATUS_OK) {
        KeyIso_CLIENT_pfx_close(keyCtx);
        _client_validate_keyid_cleanup(correlationId, pfxBytes, salt, "KeyIso_client_open_priv_key_message");
        return ret;
    }

    KEYISOP_trace_log(keyCtx->correlationId, 0, KEYISOP_VALIDATE_KEY_TITLE, "Complete");
    KeyIso_CLIENT_pfx_close(keyCtx);
    _client_validate_keyid_cleanup(correlationId, pfxBytes, salt, NULL);
    return STATUS_OK;
}