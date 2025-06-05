/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#ifdef  __cplusplus
extern "C" {
#endif 

#include <openssl/provider.h>
#include "keyisocommon.h"

/** KeyIso Provider public details **/
#define KEYISO_PROV_NAME                       "kmppprovider"
#define KEYISO_PROV_DEFAULT_NAME               "kmppprovider_dflt"
#define KEYISO_PROV_PROPQ 			           "provider=" KEYISO_PROV_NAME
#define KEYISO_PROV_PROPQ_QUE_MARK             "?provider=" KEYISO_PROV_NAME
#define KEYISO_PROV_OPENSSL_NAME               "OpenSSL KMPP Provider"
#define	KEYISO_PROV_STORE_SCHEME               "KMPPStore"
#define	KEYISO_PROV_STORE_SCHEME_PREFIX        KEYISO_PROV_STORE_SCHEME ":"

#define KEYISO_OSSL_DEFAULT_PROV_NAME          "default"
#define KEYISO_OSSL_DEFAULT_PROV_PROPQ 	       "provider=" KEYISO_OSSL_DEFAULT_PROV_NAME
#define KEYISO_PROV_OPENSSL_VERSION_STR        PKG_VERSION

#define KEYISO_SYMCRYPT_PROV_NAME			   "symcryptprovider"
/** Names **/
#define KEYISO_PROV_KEYMGMT_NAME_RSA	       "RSA:rsaEncryption"
#define KEYISO_PROV_KEYMGMT_NAME_RSA_PSS	   "RSA-PSS:RSASSA-PSS"
#define KEYISO_PROV_SIGN_NAME_RSA		       "RSA:rsaSignature"
#define KEYISO_PROV_ASYM_CIPHER_NAME_RSA       "RSA:rsaEncryption"

#define KEYISO_NAME_RSA						   "RSA"
#define KEYISO_NAME_RSA_PSS					   "RSA-PSS"
#define KEYISO_NAME_EC					       "EC"
#define KEYISO_NAME_DSA					       "DSA"
#define KEYISO_NAME_ECDSA					   "ECDSA"

/** PEM Support **/
#define KEYISO_NAME_PEM                        "PEM"

#define KEYISO_PEM_HEADER_BEGIN                "-----BEGIN "
#define KEYISO_PEM_HEADER_END                  "-----END "
#define KEYISO_PEM_HEADER_PKCS8                "ENCRYPTED PRIVATE KEY-----"
#define KEYISO_PEM_HEADER_PKCS8_INFO           "PRIVATE KEY-----"
#define KEYISO_PEM_HEADER_BEGINE_PKCS8         KEYISO_PEM_HEADER_BEGIN KEYISO_PEM_HEADER_PKCS8
#define KEYISO_PEM_HEADER_BEGINE_PKCS8_INFO    KEYISO_PEM_HEADER_BEGIN KEYISO_PEM_HEADER_PKCS8_INFO
#define KEYISO_PEM_HEADER_END_PKCS8            KEYISO_PEM_HEADER_END KEYISO_PEM_HEADER_PKCS8
#define KEYISO_PEM_HEADER_END_PKCS8_INFO       KEYISO_PEM_HEADER_END KEYISO_PEM_HEADER_PKCS8_INFO

typedef enum {
    PemType_PrivateKeyInfo = 0,
    PemType_EncryptedPrivateKeyInfo,
    PemType_NotSupported,
    PemType_Max
} PemType;

/** Default values **/
#define KEYISO_PROV_DEFAULT_PADDING         KMPP_RSA_PKCS1_PADDING
#define KEYISO_PROV_DEFAULT_MD              "SHA256"                //RSA_DEFAULT_MD
#define KEYISO_PROV_DEFAULT_RSA_PSS_MD      OSSL_DIGEST_NAME_SHA1 
#define KEYISO_PROV_DEFAULT_OAEP_DIGEST     OSSL_DIGEST_NAME_SHA1

#define KEYISO_SYMCRYPT_FLAG_RSA_PSS_VERIFY_WITH_MINIMUM_SALT 4 // based on SYMCRYPT_FLAG_RSA_PSS_VERIFY_WITH_MINIMUM_SALT

/** Macros from openssl 3.1 **/
#ifndef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
    #define RSA_PSS_SALTLEN_AUTO_DIGEST_MAX -4 // Maximum salt length for the digest, relevant from OpenSSL 3.1
#endif
#ifndef OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX
    #define OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX "auto-digestmax"
#endif

#define KEYISO_ENCODER_CERT_DNS_NAME "rsa.cert.kmpp.microsoft.com"

typedef struct KeyIso_prov_provctx_st KEYISO_PROV_PROVCTX;
struct KeyIso_prov_provctx_st {
    OSSL_LIB_CTX *libCtx;
    const OSSL_CORE_HANDLE *handle;
    int p8SrvCompatible;
};

typedef struct KeyIso_prov_pkey_st KEYISO_PROV_PKEY;
struct KeyIso_prov_pkey_st {
    KEYISO_PROV_PROVCTX *provCtx;
    KEYISO_KEY_CTX *keyCtx;
    EVP_PKEY *pubKey;

    /*
    *  Specify the keyType at the provider level. 
    *  (Necessary because we don't differentiate between
    *  RSA and RSA-PSS key types during key generation)
    */
    unsigned int keyType;
    void *keysInUseCtx; //An opaque handle for the keys in use context
};

typedef struct KeyIso_prov_rsa_md_info_st KEYISO_PROV_RSA_MD_INFO_CTX;
struct KeyIso_prov_rsa_md_info_st {
    EVP_MD              *md;			    // Message digest
    const OSSL_ITEM     *mdInfo; 	    	// Informational, must match md if set
    EVP_MD              *mgf1Md;		    // Message digest for MGF1
    const OSSL_ITEM     *mgf1MdInfo;      	// Informational, must match md if set 
    int                 saltLen;	    	// RSA PSS salt length
};


typedef struct KeyIso_prov_rsa_ctx_st KEYISO_PROV_RSA_CTX;
struct KeyIso_prov_rsa_ctx_st {
    KEYISO_PROV_PKEY             *provKey;	
    unsigned int                 padding;
    unsigned int                 operation;	
    EVP_MD_CTX                   *mdCtx;		// For digest sign digest verify operations
    KEYISO_PROV_RSA_MD_INFO_CTX  *mdInfoCtx;    // can be pss info or oaep info
    unsigned char                *oaepLabel;
    size_t                       oaepLabelLen;
};

typedef struct KeyIso_prov_rsa_gen_ctx_st KEYISO_PROV_RSA_GEN_CTX;
struct KeyIso_prov_rsa_gen_ctx_st {
    KEYISO_PROV_PKEY              *provKey;
    uint32_t                      nBitsOfModulus;
    uint64_t                      pubExp64;
    uint32_t                      nPubExp;
    unsigned int                  padding;	
	KEYISO_PROV_RSA_MD_INFO_CTX  *pssInfo;
};

typedef enum {
    KeyisoProvStoreStatus_unloaded = 0,
    KeyisoProvStoreStatus_failed,
    KeyisoProvStoreStatus_success,
}KeyisoProvStoreStatus;


typedef struct keyiso_prov_store_ctx_st KEYISO_PROV_STORE_CTX;
struct keyiso_prov_store_ctx_st {
    KEYISO_PROV_PROVCTX*        provCtx;        //Provider Context created by OSSL_provider_init function
    char*                       keyId;          //KeyId Null Terminated String
    KeyisoProvStoreStatus       status;
};

/** Common declarations **/
extern const OSSL_ITEM g_keyIsoPovSupportedMds[];

int KeyIso_conf_get(
    CONF **conf,
    const char *dns1,
    const char *dns2);

int KeyIso_edit_alt_names_section(
    const uuid_t correlationId,
    CONF *conf,
    const char *dns1,
    const char *dns2);

/** Public key operation APIs **/
int KeyIso_rsa_cipher_encrypt(
    KEYISO_PROV_RSA_CTX *ctx, 
    unsigned char *out, 
    size_t *outLen, 
    ossl_unused size_t outSize, 
    const unsigned char *in, 
    size_t inLen);

int KeyIso_rsa_signature_verify(
    KEYISO_PROV_RSA_CTX* ctx, 
    const unsigned char* sig, 
    size_t sigLen, 
    const unsigned char* tbs, 
    size_t tbsLen);

/** Common RSA Functions **/
int KeyIso_create_key_object(
    const uuid_t correlationId,
    KEYISO_PROV_PROVCTX *provCtx, 
    KEYISO_KEY_CTX *keyCtx, EVP_PKEY *pubKey, 
    OSSL_CALLBACK *objectCb, 
    void *objectCbArg, 
    ossl_unused OSSL_PASSPHRASE_CALLBACK *pwCb, 
    ossl_unused void* pwCbArg,
    bool monitoredByKIU);

int KeyIso_rsa_store_load(
    KEYISO_PROV_STORE_CTX *storeCtx, 
    OSSL_CALLBACK *objectCb, 
    void *objectCbArg,
    ossl_unused OSSL_PASSPHRASE_CALLBACK *pwCb, 
    ossl_unused void* pwCbArg);

KEYISO_PROV_STORE_CTX* KeyIso_store_new_ctx(
    const char *uri, 
    KEYISO_PROV_PROVCTX *provCtx);

int KeyIso_rsa_store_close(
    KEYISO_PROV_STORE_CTX *storeCtx);

KEYISO_PROV_PKEY* KeyIso_prov_rsa_keymgmt_new(
    KEYISO_PROV_PROVCTX* provCtx, 
    unsigned int keyType);

void KeyIso_rsa_keymgmt_free(
    KEYISO_PROV_PKEY *pkey);

/** Common function for both RSA and ECC **/
int KeyIso_prov_set_md_from_mdname(
    OSSL_LIB_CTX *libCtx, 
    const OSSL_PARAM *p, 
    const char* mdName, 
    const char *propq, 
    EVP_MD **md, 
    const OSSL_ITEM **mdInfo);

EVP_PKEY *KeyIso_new_pubKey_from_privKey(
    OSSL_LIB_CTX *libCtx, 
    EVP_PKEY *pkey);

/** Common RSA functions for both Signature and Asym cipher APIs **/
KEYISO_PROV_RSA_CTX* KeyIso_prov_rsa_newctx(
    KEYISO_PROV_PKEY *provCtx,
    ossl_unused const char *propq);

void KeyIso_prov_rsa_freectx(
    KEYISO_PROV_RSA_CTX *ctx);

KEYISO_PROV_RSA_CTX* KeyIso_prov_rsa_dupctx(
    KEYISO_PROV_RSA_CTX *ctx);

/** Common utility functions **/
PemType KeyIso_get_type_from_bio_buff(
    BIO *bio, 
    char **data, 
    long *len);

long KeyIso_read_content_between_headers(
    BIO *bio, 
    char *buff, 
    long buffLength, 
    const char *headerBegin, 
    const char *headerEnd, 
    unsigned char **data);

#ifdef  __cplusplus
}
#endif