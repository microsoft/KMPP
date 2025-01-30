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

typedef enum {
    KeyIsoKeyType_pfx = 0,
    KeyIsoKeyType_symmetric,
    KeyIsoKeyType_max
} KeyIsoKeyType;

typedef struct keyiso_client_config_st KEYISO_CLIENT_CONFIG_ST;
struct keyiso_client_config_st {
    KeyIsoSolutionType solutionType;
    bool isDefault;
#ifdef KMPP_GENERAL_PURPOSE_TARGET
    KEYISO_TPM_CONFIG_ST tpmConfig;
#endif  // KMPP_GENERAL_PURPOSE_TARGET
};

// Define the msg handler functions table
typedef struct client_msg_handler_functions_table_st CLIENT_MSG_HANDLER_FUNCTIONS_TABLE_ST;
struct client_msg_handler_functions_table_st {
    int (*init_key)(KEYISO_KEY_CTX *keyCtx, int keyLength, const unsigned char *keyBytes, const char *salt);
    void (*free_keyCtx)(KEYISO_KEY_CTX *keyCtx);
    void (*close_key)(KEYISO_KEY_CTX *keyCtx);
    int (*rsa_private_encrypt_decrypt)(KEYISO_KEY_CTX *keyCtx, int decrypt, int flen, const unsigned char *from, int tlen, unsigned char *to, int padding);
    int (*ecdsa_sign)(KEYISO_KEY_CTX *keyCtx, int type, const unsigned char *dgst, int dlen, unsigned char *sig, unsigned int sigLen, unsigned int *outLen);
    int (*import_symmetric_key)(const uuid_t correlationId, int inSymmetricKeyType, unsigned int inKeyLength, const unsigned char *inKeyBytes, const unsigned char *inImportKeyId, unsigned int *outKeyLength, unsigned char **outKeyBytes);
    int (*symmetric_key_encrypt_decrypt)(KEYISO_KEY_CTX *keyCtx, int mode, const unsigned char *from, const unsigned int fromLen, unsigned char *to, unsigned int *toLen);
    int (*import_private_key)(const uuid_t correlationId, int keyType, const unsigned char *inKeyBytes, X509_SIG **outEncKey, char **outSalt);
    int (*generate_rsa_key_pair)(const uuid_t correlationId, unsigned int rsaBits, uint8_t keyUsage, EVP_PKEY** outPubKey, X509_SIG **outEncryptedPkey, char **outSalt);
    int (*generate_ec_key_pair)(const uuid_t correlationId, unsigned int curve, uint8_t keyUsage, EC_GROUP** outEcGroup, EC_KEY** outPubKey, X509_SIG **outEncryptedPkey, char **outSalt);    
    void (*set_config)(const KEYISO_CLIENT_CONFIG_ST *config);
};

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
    char **outPfxSalt);                         // KeyIso_free()

int KeyIso_CLIENT_private_key_open_from_pfx(
    const uuid_t correlationId,
    int pfxLength,
    const unsigned char* pfxBytes,
    const char* salt,           
    KEYISO_KEY_CTX** keyCtx);          

int KeyIso_CLIENT_import_private_key( 
    const uuid_t correlationId,
    int keyisoFlags, 
    const EVP_PKEY *inPkey,
    X509_SIG **outEncryptedPkey,
    char **outSalt);

int KeyIso_CLIENT_generate_rsa_key_pair( 
    const uuid_t correlationId,
    int keyisoFlags, 
    const CONF *conf,
    EVP_PKEY **outPubKey, 
    X509_SIG **outEncryptedPkey,
    char **outSalt);

int KeyIso_CLIENT_generate_ec_key_pair( 
    const uuid_t correlationId,
    int keyisoFlags, 
    const CONF *conf,
    EC_GROUP** outEcGroup,
    EC_KEY **outPubKey, 
    X509_SIG **outEncryptedPkey,
    char **outSalt);

int KeyIso_CLIENT_init_key_ctx(
    KEYISO_KEY_CTX *keyCtx, 
    int keyLength, 
    const unsigned char *keyBytes, 
    const char *salt);

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
    char **pfxSalt);

int KeyIso_replace_pfx_certs_p8(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    int pemCertLength,
    const unsigned char *pemCertBytes,
    int *outPfxLength,
    unsigned char **outPfxBytes);

int KeyIso_pkcs12_parse_p8(
    const uuid_t correlationId,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    X509_SIG **outP8,
    X509 **outCert,
    STACK_OF(X509) **outCa);

PKCS12 *KeyIso_pkcs12_create_p8(
    X509_SIG *p8, 
    X509 *cert, 
    STACK_OF(X509) *ca);

X509_ALGOR *KeyIso_pbe_set_algor(
    unsigned long version,
    const unsigned char *salt, 
    unsigned int saltLen,
    const unsigned char *iv, 
    unsigned int ivLen,
    const unsigned char *hmac, 
    unsigned int hmacLen);

int KeyIso_pbe_get_algor_params(
    const X509_ALGOR *alg,
    unsigned int *version,
    unsigned char **salt, 
    unsigned int *saltLen,
    unsigned char **iv, 
    unsigned int *ivLen,
    unsigned char **hmac, 
    unsigned int *hmacLen);

bool KeyIso_is_equal_oid(const ASN1_OBJECT *oid, const char* expectedAlgOid);

const void* KeyIso_pbe_get_algor_param_asn1(
    const char* title,
    const X509_ALGOR *algor,
    const char* expectedAlgOid);

bool KeyIso_is_oid_pbe2(const uuid_t correlationId, const unsigned char *keyBytes, int keyLen);

int KeyIso_get_enc_key_params(
    const KEYISO_ENCRYPTED_PRIV_KEY_ST *inEncKey,
    unsigned long *version,
    unsigned char **salt,
    unsigned int *saltLen,
    unsigned char **iv,
    unsigned int *ivLen,
    unsigned char **hmac,
    unsigned int *hmacLen,
    unsigned char **encKeyBuf,
    unsigned int *encKeyLen);

int KeyIso_create_pkcs8_enckey(
    const KEYISO_ENCRYPTED_PRIV_KEY_ST *inEncKey, 
    X509_SIG **outP8);

int KeyIso_create_enckey_from_p8(
    const X509_SIG *inP8,
    KEYISO_ENCRYPTED_PRIV_KEY_ST **outEncKey);

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

/*//////////
    RSA
//////////*/

// Export EVP_PKEY to struct 
// Should be freed by the caller KeyIso_clear_free()
KEYISO_RSA_PKEY_ST* KeyIso_export_rsa_epkey(
    const uuid_t correlationId,
    const void* inPkey,
    size_t* pkeySize);

// Converting received public key to EVP_PKEY
EVP_PKEY* KeyIso_get_rsa_evp_pub_key(
    const uuid_t correlationId,
    const KEYISO_RSA_PUBLIC_KEY_ST* inPubKey);

/*//////////
    EC
//////////*/

// Export EVP_PKEY to struct 
// Should be freed by the caller KeyIso_clear_free()
KEYISO_EC_PKEY_ST* KeyIso_export_ec_private_key(
    const uuid_t correlationId,
    const void* inPkey,
    size_t* outKeySize);

#ifdef  __cplusplus
}
#endif