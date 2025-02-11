/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <string.h>

#include <openssl/x509.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

#include "keyisoclient.h"
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
