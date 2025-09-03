/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include "keyisocommon.h"
#include "keyisoipccommands.h"

#include <linux/limits.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define KMPP_KEY_PARAM_BITS_STR     "rsa_bits"
#define KMPP_KEY_PARAM_EXP_STR      "rsa_exp"
#define KMPP_KEY_PARAM_PAD_STR      "rsa_padding"
#define KMPP_KEY_PARAM_CURVE_STR    "ecc_curve"

#define KMPP_KEY_TYPE_STR           "key_type"
#define KMPP_KEY_TYPE_STR_RSA       "rsa"
#define KMPP_KEY_TYPE_STR_EC        "ecc"

#define KMPP_KEY_USAGE_SIGN_STR             "digitalSignature"
#define KMPP_KEY_USAGE_ENCRYPT_STR          "dataEncipherment"
#define KMPP_KEY_USAGE_KEY_ENCIPHERMENT_STR "keyEncipherment"
#define KMPP_KEY_USAGE_KEY_AGREEMENT_STR    "keyAgreement"

#define KMPP_KEY_USAGE_INVALID           (0x00)

#define KMPP_KEY_USAGE_RSA_SIGN_ECDSA    (0x01)   // RSA Sign or ECDSA
#define KMPP_KEY_USAGE_RSA_ENCRYPT_ECDH  (0x02)   // RSA Encrypt or ECDH

// KMPP Algorithm Identifier
#define KMPP_OID_SUBTREE        "1.3.6.1.4.1.311.130"     // Official KMPP's Microsoft OID subtree - defined in /ds/security/cryptoapi/oids/oid.txt
#define OID_KMPP_ALGO           KMPP_OID_SUBTREE ".1"   // 1.3.6.1.4.1.311.130.1
#define OID_KMPP_ALGO_TPM_ISO   KMPP_OID_SUBTREE ".2"   // 1.3.6.1.4.1.311.130.2
#define OID_PBE2                "1.2.840.113549.1.5.13" // Standard PBE algorithm PBES2 

#define KEYISO_SYMCRYPT_NAME "symcrypt"

// KMPP_OID_NO_NAME is used to set the 'no_name' parameter to 1 in OBJ_obj2txt/OBJ_txt2obj, 
// so the numerical form of the KMPP OID will be used.
// In this way we avoid the need of adding KMPP object to the OpenSSL internal table.
#define KMPP_OID_NO_NAME    1

// KMPP_OSSL_PROVIDER_DEFAULT is used to load explicitly openssl default provider in OpenSSL 3.x
#define KMPP_OSSL_PROVIDER_DEFAULT "provider=default"

// KeyIso engine name
#ifndef KMPP_MSCRYPT_ENGINE
#define KMPP_ENGINE_ID "kmpppfx"
#define KMPP_ENGINE_NAME "KMPP PFX ENGINE"
#else
#define KMPP_ENGINE_ID "mscryptpfx"
#define KMPP_ENGINE_NAME "MSCRYPT PFX ENGINE"
#endif // KMPP_MSCRYPT_ENGINE

#ifdef KMPP_GENERAL_PURPOSE_TARGET
#include "keyisotpmclient.h"
#endif // KMPP_GENERAL_PURPOSE_TARGET


typedef struct keyiso_client_config_st KEYISO_CLIENT_CONFIG_ST;
struct keyiso_client_config_st {
    KeyIsoSolutionType solutionType;
    bool isDefaultSolutionType;
    bool isKmppEnabledByDefault;
    bool isLegacyMode;
#ifdef KMPP_GENERAL_PURPOSE_TARGET
    KEYISO_TPM_CONFIG_ST tpmConfig;
#endif  // KMPP_GENERAL_PURPOSE_TARGET
};

// Define the msg handler functions table
typedef struct client_msg_handler_functions_table_st CLIENT_MSG_HANDLER_FUNCTIONS_TABLE_ST;
struct client_msg_handler_functions_table_st {
    int (*init_key)(KEYISO_KEY_CTX *keyCtx, int keyLength, const unsigned char *keyBytes, const char *clientData);
    void (*free_keyCtx)(KEYISO_KEY_CTX *keyCtx);
    void (*close_key)(KEYISO_KEY_CTX *keyCtx);
    int (*rsa_private_encrypt_decrypt)(KEYISO_KEY_CTX *keyCtx, int decrypt, int flen, const unsigned char *from, int tlen, unsigned char *to, int padding, int labelLen);
    int (*ecdsa_sign)(KEYISO_KEY_CTX *keyCtx, int type, const unsigned char *dgst, int dlen, unsigned char *sig, unsigned int sigLen, unsigned int *outLen);
    int (*import_symmetric_key)(const uuid_t correlationId, int inSymmetricKeyType, unsigned int inKeyLength, const unsigned char *inKeyBytes, const unsigned char *inImportKeyId, unsigned int *outKeyLength, unsigned char **outKeyBytes, char **outClientData);
    int (*symmetric_key_encrypt_decrypt)(KEYISO_KEY_CTX *keyCtx, int mode, const unsigned char *from, const unsigned int fromLen, unsigned char *to, unsigned int *toLen);
    int (*import_private_key)(const uuid_t correlationId, int keyType, const unsigned char *inKeyBytes, X509_SIG **outEncKey, KEYISO_CLIENT_DATA_ST **outClientData);
    int (*generate_rsa_key_pair)(const uuid_t correlationId, unsigned int rsaBits, uint8_t keyUsage, EVP_PKEY** outPubKey, X509_SIG **outEncryptedPkey, KEYISO_CLIENT_METADATA_HEADER_ST *outMetaData);
    int (*generate_ec_key_pair)(const uuid_t correlationId, unsigned int curve, uint8_t keyUsage, EC_GROUP** outEcGroup, EC_KEY** outPubKey, X509_SIG **outEncryptedPkey, KEYISO_CLIENT_METADATA_HEADER_ST *outMetaData);    
    void (*set_config)(const KEYISO_CLIENT_CONFIG_ST *config);
};

// Function pointer types for KeysInUse functions
typedef void* (*keysinuse_load_key_func_ptr)(const unsigned char *encodedPubKey, int encodedPubKeyLength);
typedef void (*keysinuse_on_use_func_ptr)(void *keysInUseCtx, int operationEnumValue);
typedef void (*keysinuse_unload_key_func_ptr)(void *keysInUseCtx);
typedef unsigned int (*keysinuse_get_key_identifier_func_ptr)(void *keysInUseCtx, char *pbKeyIdentifier, unsigned long cbKeyIdentifier);
// Structure to hold KeysInUse library state and function pointers
typedef struct keyiso_keysinuse_st KEYISO_KEYSINUSE_ST;
struct keyiso_keysinuse_st {
    void *handle;
    bool isLibraryLoaded;
    keysinuse_load_key_func_ptr load_key_func;
    keysinuse_on_use_func_ptr on_use_func;
    keysinuse_unload_key_func_ptr unload_key_func;
    keysinuse_get_key_identifier_func_ptr get_key_identifier_func;
};

bool KeyIso_load_keysInUse_library();

/*///////////////////////////////////////////// 
    Backward-Compatibility helper functions
/////////////////////////////////////////////*/

unsigned int KeyIso_CLIENT_get_version(const uuid_t correlationId);
    
int KeyIso_validate_current_service_compatibility_mode(
    const uuid_t correlationId,
    KeyisoCompatibilityMode mode);

unsigned int KeyIso_get_min_compatible_version(
    const uuid_t correlationId,
    KeyisoCompatibilityMode mode);

/*///////////////////////////////// 
    KeyIso_CLIENT_* interface
/////////////////////////////////*/

// NOTE:
// The following interface is based on the PKCS #8.
// This interface is supported starting KEYISOP_VERSION_3.

int KeyIso_CLIENT_import_private_key_from_pfx(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *inPassword,                     // Optional
    int *outVerifyChainError,
    int *outPfxLength,
    unsigned char **outPfxBytes,                // KeyIso_free()
    char  **outClientData);                     // Base64 encoded string

int KeyIso_CLIENT_private_key_open_from_pfx(
    const uuid_t correlationId,
    int pfxLength,
    const unsigned char* pfxBytes,
    const char *clientData,    // Base64 encoded string          
    KEYISO_KEY_CTX** keyCtx);          

int KeyIso_CLIENT_import_private_key( 
    const uuid_t correlationId,
    int keyisoFlags, 
    const EVP_PKEY *inPkey,
    X509_SIG **outEncryptedPkey,
    char  **outClientData);          // Base64 encoded string

int KeyIso_CLIENT_generate_rsa_key_pair_conf( 
    const uuid_t correlationId,
    int keyisoFlags, 
    const CONF *conf,
    EVP_PKEY **outPubKey, 
    X509_SIG **outEncryptedPkey,
    char  **outClientData);                     // Base64 encoded string

int KeyIso_CLIENT_generate_rsa_key_pair(
    const uuid_t correlationId,
    unsigned int rsaBits,
    uint8_t keyUsage,
    uint64_t pubExp64,
    uint32_t nPubExp,
    EVP_PKEY** pubEpkey,
    X509_SIG** encryptedPkey,
    char  **outClientData);               // Base64 encoded string

int KeyIso_CLIENT_generate_ec_key_pair( 
    const uuid_t correlationId,
    int keyisoFlags, 
    const CONF *conf,
    EC_GROUP** outEcGroup,
    EC_KEY **outPubKey, 
    X509_SIG **outEncryptedPkey,
    char  **outClientData);               // Base64 encoded string

int KeyIso_CLIENT_init_key_ctx(
    KEYISO_KEY_CTX *keyCtx, 
    int keyLength, 
    const unsigned char *keyBytes, 
    const char  *clientData);            // Base64 encoded string

void KeyIso_CLIENT_free_key_ctx(
    KEYISO_KEY_CTX *keyCtx);
    
/*///////////////////////////////// 
      Internal functionality
/////////////////////////////////*/

int KeyIso_CLIENT_create_self_sign_pfx_p8(
    const uuid_t correlationId,
    int keyisoFlags,
    const char *confStr,
    int *pfxLength,
    unsigned char **pfxBytes,
    char  **outClientData);               // Base64 encoded string

int KeyIso_CLIENT_create_X509_from_pubkey(
    const uuid_t correlationId,
    int keyType,
    EVP_PKEY *pubKey,
    X509 **cert,
    CONF *conf);

int KeyIso_replace_pfx_certs_p8(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    int pemCertLength,
    const unsigned char *pemCertBytes,
    int *outPfxLength,
    unsigned char **outPfxBytes);

int KeyIso_create_encrypted_pfx_bytes(
    const uuid_t correlationId,
    X509_SIG* inP8,
    X509* inCert,
    STACK_OF(X509)* inCa,
    int* outPfxLength,
    unsigned char** outPfxBytes);

PKCS12 *KeyIso_pkcs12_create_p8(
    X509_SIG *p8, 
    X509 *cert, 
    STACK_OF(X509) *ca);

bool KeyIso_is_oid_pbe2(
    const uuid_t correlationId, 
    const unsigned char *keyBytes, 
    int keyLen);

int KeyIso_create_pkcs8_enckey(
    unsigned int opaqueEncryptedKeyLen,
    const unsigned char *opaqueEncryptedKey, 
    X509_SIG **outP8);

int KeyIso_x509_sig_dup(
    const X509_SIG *in,
    X509_SIG *out);

int KeyIso_cert_sign(
    const uuid_t correlationId, 
    CONF *conf, 
    X509 *cert, 
    const char *encryptedKeyId);

bool KeyIso_check_default(
    const char* name);

size_t KeyIso_get_bn_param_len(
    const EVP_PKEY *pkey, 
    const char *paramType, 
    BIGNUM **outParam);

int KeyIso_conf_cert_sign_prov(
    const uuid_t correlationId,
    const CONF* conf,
    X509* cert,
    EVP_PKEY* pkey,
    void* libCtx,
    const char *propq);

int KeyIso_open_key_by_compatibility(
    uuid_t correlationId, 
    KEYISO_KEY_CTX **keyCtx,
    unsigned char *pfxBytes, 
    int pfxLength, 
    char *clientData,
    bool isKeyP8Compatible, 
    bool isServiceP8Compatible);

int KeyIso_load_public_key_by_compatibility(
    const uuid_t correlationId,
    KEYISO_KEY_CTX *keyCtx, 
    int isKeyP8Compatible,
    int pfxLength,
    unsigned char *pfxBytes,
    EVP_PKEY **outPKey,
    X509 **outPCert,
    STACK_OF(X509) **outCa); 

int KeyIso_encode_public_key_asn1(
    EVP_PKEY* pkey,
    unsigned char** outBytes,
    uint32_t* outLen);

int KeyIso_decode_public_key_asn1(
    unsigned char *inBytes,
    uint32_t intLen,
    EVP_PKEY **outPkey);

int KeyIso_copy_client_data(
    const uuid_t correlationId,
    uint8_t version,
    uint16_t isolationSolution,
    uint32_t pubKeyLen,
    const uint8_t* pubKeyBytes,
    KEYISO_CLIENT_DATA_ST** outClientData);

void KeyIso_add_key_to_keys_in_use(
    uuid_t correlationId,
    KEYISO_KEY_CTX *keyCtx,
    EVP_PKEY *pKey);

/////////////
//  RSA   //
///////////

// Export EVP_PKEY to struct 
// Should be freed by the caller KeyIso_clear_free()
KEYISO_RSA_PKEY_ST* KeyIso_export_rsa_epkey(
    const uuid_t correlationId,
    const void* inPkey,
    size_t* pkeySize);

// Converting received public key params to EVP_PKEY
EVP_PKEY* KeyIso_get_rsa_evp_pub_key(
    const uuid_t correlationId,
    const uint8_t *rsaModulusBytes,
    size_t rsaModulusLen,                            
    const uint8_t *rsaPublicExpBytes,
    size_t rsaPublicExpLen);

int KeyIso_get_rsa_params(
    const EVP_PKEY *pkey, 
    BIGNUM **rsaN,  // Modulus (public)
    BIGNUM **rsaE,  // Exponent (public)
    BIGNUM **rsaP,  // Prime1 (private)
    BIGNUM **rsaQ);  // Prime2 (private)

EVP_PKEY* KeyIso_get_rsa_public_key(
    const uuid_t correlationId, 
    const EVP_PKEY *privKey);

/////////////
//  EC    //
///////////

// Export EVP_PKEY to struct 
// Should be freed by the caller KeyIso_clear_free()
KEYISO_EC_PKEY_ST* KeyIso_export_ec_private_key(
    const uuid_t correlationId,
    const void* inPkey,
    size_t* outKeySize);

int KeyIso_get_ec_evp_key(
    const uuid_t correlationId,
    uint32_t curve,
    uint32_t ecPubKeyLen,
    const uint8_t *ecPubKeyBytes,
    uint32_t ecPrivateKeyLen,
    const uint8_t *ecPrivateKeyBytes,
    EC_KEY **outEcKey,
    EC_GROUP **outEcGroup);


EVP_PKEY* KeyIso_get_ec_public_key(
    const uuid_t correlationId,
    const EVP_PKEY *privKey);

#ifdef  __cplusplus
}
#endif