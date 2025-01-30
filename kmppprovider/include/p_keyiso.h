/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#ifdef  __cplusplus
extern "C" {
#endif 

#include <openssl/provider.h>


OSSL_provider_init_fn OSSL_provider_init;

/** Names **/
#define KEYISO_PROV_KEYMGMT_NAME_RSA	    "RSA:rsaEncryption"
#define KEYISO_PROV_SIGN_NAME_RSA		    "RSA:rsaSignature"
#define KEYISO_PROV_ASYM_CIPHER_NAME_RSA    "RSA:rsaEncryption"

#define KEYISO_NAME_RSA						"RSA"
#define KEYISO_NAME_RSA_PSS					"RSA-PSS"
#define KEYISO_NAME_EC					    "EC"
#define KEYISO_NAME_DSA					    "DSA"
#define KEYISO_NAME_ECDSA					"ECDSA"

#define	KEYISO_PROV_STORE_GET_PARAM		    "KMPPStore_GetParam"
#define	KEYISO_PROV_STORE_GET_PARAM_CERT	"KMPPStore_GetParamCert"
#define	KEYISO_PROV_STORE_GET_PARAM_KEY	    "KMPPStore_GetParamKey"

/** Default values **/
#define KEYISO_PROV_DEFAULT_PADDING         KMPP_RSA_PKCS1_PADDING
//#define KEYISO_PROV_DEFAULT_MD            RSA_DEFAULT_MD //"SHA256"
//#define KEYISO_PROV_DEFAULT_RSA_PSS_MD    OSSL_DIGEST_NAME_SHA1
#define KEYISO_PROV_DEFAULT_OAEP_DIGEST     OSSL_DIGEST_NAME_SHA1

#define KEYISO_SYMCRYPT_FLAG_RSA_PSS_VERIFY_WITH_MINIMUM_SALT 4 // based on SYMCRYPT_FLAG_RSA_PSS_VERIFY_WITH_MINIMUM_SALT

/** Macros from openssl 3.1 **/
#ifndef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
    #define RSA_PSS_SALTLEN_AUTO_DIGEST_MAX -4 // Maximum salt length for the digest, relevant from OpenSSL 3.1
#endif
#ifndef OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX
    #define OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX "auto-digestmax"
#endif

typedef struct KeyIso_prov_provctx_st KEYISO_PROV_PROVCTX;
struct KeyIso_prov_provctx_st {
    OSSL_LIB_CTX *libCtx;
    const OSSL_CORE_HANDLE *handle;
};

typedef struct KeyIso_prov_pkey_st KEYISO_PROV_PKEY;
struct KeyIso_prov_pkey_st {
    KEYISO_PROV_PROVCTX *provCtx;
    KEYISO_KEY_CTX *keyCtx;
    EVP_PKEY *pubKey;
};

typedef struct KeyIso_prov_rsa_ctx_st KEYISO_PROV_RSA_CTX;
struct KeyIso_prov_rsa_ctx_st {
    KEYISO_PROV_PKEY   *provKey;	
    unsigned int        padding;
    unsigned int        operation;	
    EVP_MD_CTX          *mdCtx;		        // For digest sign digest verify operations
    EVP_MD              *md;			    // Message digest
    const OSSL_ITEM     *mdInfo; 	    	// Informational, must match md if set
    EVP_MD              *mgf1Md;		    // Message digest for MGF1
    const OSSL_ITEM     *mgf1mMdInfo;      	// Informational, must match md if set 
    int                 saltLen;	    	// RSA PSS salt length
    unsigned char       *oaepLabel;
    size_t              oaepLabelLen;
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


/** OSSL_DISPATCH **/
extern const OSSL_DISPATCH keyIso_prov_rsa_keymgmt_funcs[];
extern const OSSL_DISPATCH keyIso_prov_rsa_signature_funcs[];
extern const OSSL_DISPATCH keyIso_prov_rsa_store_funcs[];
extern const OSSL_DISPATCH keyIso_prov_rsa_cipher_funcs[];



/** Public key operation APIs **/
int KeyIso_rsa_cipher_encrypt(KEYISO_PROV_RSA_CTX *ctx, unsigned char *out, size_t *outLen, ossl_unused size_t outSize, const unsigned char *in, size_t inLen);
int KeyIso_rsa_signature_verify(KEYISO_PROV_RSA_CTX* ctx, const unsigned char* sig, size_t sigLen, const unsigned char* tbs, size_t tbsLen);

/** Common Functions **/
void* KeyIso_prov_rsa_keymgmt_new(KEYISO_PROV_PROVCTX* provCtx);
void KeyIso_rsa_keymgmt_free(KEYISO_PROV_PKEY *pkey);

/** Common function for both RSA and ECC **/
int KeyIso_prov_set_md_from_mdname(const char *mdName, EVP_MD **md, const OSSL_ITEM **mdInfo);

/** Common RSA functions for both Signature and Asym cipher APIs **/
KEYISO_PROV_RSA_CTX* KeyIso_prov_rsa_newctx(KEYISO_PROV_PKEY *provCtx,ossl_unused const char *propq);
void KeyIso_prov_rsa_freectx(KEYISO_PROV_RSA_CTX *ctx);
KEYISO_PROV_RSA_CTX* KeyIso_prov_rsa_dupctx(KEYISO_PROV_RSA_CTX *ctx);
size_t KeyIso_get_bn_param_len(KEYISO_PROV_PKEY *provKey, const char *paramType, BIGNUM **outParam);


#ifdef  __cplusplus
}
#endif