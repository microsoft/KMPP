/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <string.h>

#include <openssl/x509.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

#include "keyisoclient.h"
#include "keyisolog.h"
#include "keyisocommon.h"
#include "keyisoclientinternal.h"

/* Currently, self - signing using the engine is invoked even
 if we are working with OpenSSL 3.x and the KMPP provider is available,
 until we implement ECC in the provider as well.
 Once ECC is implemented, this function will be re-enabled. */
#if 0
// Self signing the cert utilizing the engine
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
#endif

bool _is_symcrypt_engine_available()
{
    bool ret = false;
    ENGINE *defaultEng = NULL;
    ENGINE *symcryptEng = NULL;

    defaultEng = ENGINE_get_default_RSA();
    if (defaultEng == NULL) {
        ret = false;
    } else {
        // There might be several default engines, we need to check that symcrypt is one of them
        symcryptEng = ENGINE_by_id(KEYISO_SYMCRYPT_NAME);
        if (symcryptEng != NULL) { // with symcrypt
            ret = true;
        } else {
            ret = false;
        }
    }

    if (symcryptEng)
        ENGINE_free(symcryptEng);
    if (defaultEng)
        ENGINE_free(defaultEng);

    return ret;
}

bool KeyIso_check_default(const char* name)
{   
// currently only smcrypt provider can be defualt provider that affects us
    if (strncmp(name, KEYISO_SYMCRYPT_NAME, sizeof(KEYISO_SYMCRYPT_NAME) - 1) == 0) {
        return _is_symcrypt_engine_available();
    }

return false;
}

////////////
//  RSA  //
//////////

// In order to be aligned with openssl 3.0 implementation, get the RSA parameters 
// from an EVP_PKEY while allocating new BIGNUMs for them.
static int _cleanup_rsa_params(
    int ret,
    BIGNUM *dupN,
    BIGNUM *dupE,
    BIGNUM *dupP,
    BIGNUM *dupQ)
{
    if (ret != STATUS_OK) {
        if (dupN) {
            BN_free(dupN);
        }
        if (dupE) {
            BN_free(dupE);
        }
        if (dupP) {
            BN_free(dupP);
        }
        if (dupQ) {
            BN_free(dupQ);
        }
    }
    return ret;
}
#define _CLEANUP_RSA_PARAMS(ret) \
    _cleanup_rsa_params(ret, dupN, dupE, dupP, dupQ)

int KeyIso_get_rsa_params(
    const EVP_PKEY *pkey, 
    BIGNUM **rsaN,  // Modulus (public)
    BIGNUM **rsaE,  // Exponent (public)
    BIGNUM **rsaP,  // Prime1 (private)
    BIGNUM **rsaQ)  // Prime2 (private)
{
    const BIGNUM *n = NULL, *e = NULL, *p = NULL, *q = NULL;
    BIGNUM *dupN = NULL, *dupE = NULL, *dupP = NULL, *dupQ = NULL;

    if (!pkey || !rsaN || !rsaE) {
        return STATUS_FAILED;
    }

    const RSA *rsa = EVP_PKEY_get0_RSA((EVP_PKEY *)pkey);
    if (!rsa) {
        return STATUS_FAILED;
    }

    RSA_get0_key(rsa, &n, &e, NULL);
    if (!n || !e) {
        return STATUS_FAILED;
    }

    dupN = BN_dup(n);
    dupE = BN_dup(e);
    if (!dupN || !dupE) {
        return _CLEANUP_RSA_PARAMS(STATUS_FAILED);
    }

    // Handle optional private parameters
    if (rsaP && rsaQ) {
        RSA_get0_factors(rsa, &p, &q);
        if (!p || !q) {
            return _CLEANUP_RSA_PARAMS(STATUS_FAILED);
        }

        dupP = BN_dup(p);
        dupQ = BN_dup(q);
        if (!dupP || !dupQ) {
            return _CLEANUP_RSA_PARAMS(STATUS_FAILED);
        }
    }

    // Assign local variables to output parameters
    *rsaN = dupN;
    *rsaE = dupE;
    if (rsaP) 
       *rsaP = dupP;
    if (rsaQ)
        *rsaQ = dupQ;

    return STATUS_OK;
}    

////////////
//  ECC  //
//////////

// CB-CHANGES: Create EVP_PKEY from EC public key components instead of deprecated structures as in KeyIso_get_ec_evp_key
#if 0
static int _cleanup_create_ec_pub_key(
    int ret,
    const char *loc,
    const char *message,
    EC_KEY *ecKey,
    EVP_PKEY *pkey, 
   EC_POINT *point)
{
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, loc, message);
        
        if (ecKey) {
            EC_KEY_free(ecKey);
        }
        if (pkey) {
            EVP_PKEY_free(pkey);
        }
    }
    
    if (point) {
        EC_POINT_free(point);
    }
    return ret;
}

#define _CLEANUP_CREATE_EC_PUB_KEY(ret, loc, message) \
    _cleanup_create_ec_pub_key(ret, loc, message, ecKey, pkey, point)

int KeyIso_create_ec_evp_pub_key(
    uint32_t curveNid,
    const uint8_t *pubKey,
    size_t pubKeyLen,
    EVP_PKEY **outPkey)
{
    EC_KEY *ecKey = NULL;
    EVP_PKEY *pkey = NULL;
    EC_POINT *point = NULL;
    const EC_GROUP *group = NULL;

    if (!pubKey || !pubKeyLen || !outPkey) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Invalid input", "NULL parameter or zero length");
        return STATUS_FAILED;
    }
    *outPkey = NULL;

    // Create EC_KEY and set the group
    ecKey = EC_KEY_new_by_curve_name(curveNid);
    if (!ecKey) {
        return _CLEANUP_CREATE_EC_PUB_KEY(STATUS_FAILED, "EC_KEY_new_by_curve_name", "Failed to create EC_KEY");
    }

    group = EC_KEY_get0_group(ecKey);
    if (!group) {
        return _CLEANUP_CREATE_EC_PUB_KEY(STATUS_FAILED, "EC_KEY_get0_group", "Failed to get EC group");
    }

     // Convert bytes into EC_POINT
    point = EC_POINT_new(group);
    if (!point) {
        return _CLEANUP_CREATE_EC_PUB_KEY(STATUS_FAILED, "EC_POINT_new", "Failed to allocate EC_POINT");
    }

    if (!EC_POINT_oct2point(group, point, pubKey, pubKeyLen, NULL)) {
        return _CLEANUP_CREATE_EC_PUB_KEY(STATUS_FAILED, "EC_POINT_oct2point", "Invalid public key encoding");
    }

    // Set public key
   if (!EC_KEY_set_public_key(ecKey, point)) {
        return _CLEANUP_CREATE_EC_PUB_KEY(STATUS_FAILED, "EC_KEY_set_public_key", "Failed to set public key");
    }
   
    // Create EVP_PKEY and assign EC_KEY
    pkey = EVP_PKEY_new();
    if (!pkey || !EVP_PKEY_assign_EC_KEY(pkey, ecKey)) {
        return _CLEANUP_CREATE_EC_PUB_KEY(STATUS_FAILED, "EVP_PKEY_assign_EC_KEY", "Failed to assign EC_KEY to EVP_PKEY");
    }

    *outPkey = pkey;
    return _CLEANUP_CREATE_EC_PUB_KEY(STATUS_OK, "", "");;
}
#endif