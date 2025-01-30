/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stddef.h>
#include <string.h>
#include <openssl/engine.h>

#include "e_keyisopfx_err.h"
#include "keyisoclientinternal.h"
#include "keyisocommon.h"
#include "keyisoclient.h"
#include "keyisolog.h"
#include "keyisotelemetry.h"
#include "keyisoutils.h"
#include "keyisomemory.h"
#include "keyisosymmetrickeyclientinternal.h"

#ifdef KEYISO_TEST_WINDOWS
typedef unsigned char uuid_t[16];
#else
#include <uuid/uuid.h>
# endif

#define AES_CBC_HMAC_FLAGS   (EVP_CIPH_FLAG_DEFAULT_ASN1|EVP_CIPH_CBC_MODE|EVP_CIPH_CUSTOM_COPY \
                        |EVP_CIPH_CUSTOM_IV|EVP_CIPH_FLAG_CUSTOM_CIPHER \
                        |EVP_CIPH_ALWAYS_CALL_INIT|EVP_CIPH_CTRL_INIT \
                        |EVP_CIPH_FLAG_FIPS)


static EVP_CIPHER* _hidden_aes_256_cbc_hmac_sha256 = NULL;
static int _kmpp_cipher_nids[] = {
    NID_aes_256_cbc_hmac_sha256,
 };


// Initializes ctx with the provided key and iv, along with enc/dec mode.
// Returns engine_SUCCESS on success, or engine_FAILURE on error.
// In Symcrypt the IV is generated randomly during encryption,
// the client IV is not relevant and will not be set
static int _kmpp_aes_256_cbc_hmac_sha256_init_key(EVP_CIPHER_CTX* ctx, const unsigned char* key,
   const unsigned char* iv, int enc)
{
    const char *title = KEYISOP_SYMMETRIC_ENC_DEC_TITLE;
    KEYISO_KEY_CTX* keyCtx = (KEYISO_KEY_CTX*)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (!keyCtx) {
        KMPPPFXerr(KMPPPFX_F_INIT_SYMMETRIC_KEY, KMPPPFX_R_CTX_NULL);
        KEYISOP_trace_log_error(NULL, 0, title, NULL, "Error getting key ctx");
        return STATUS_FAILED;
    }

    if (key) {
        KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "kmpp_aes_256_cbc_hmac_sha256_init_key - set key");
        KeyIso_rand_bytes(keyCtx->correlationId, sizeof(keyCtx->correlationId));
        int keyLength;
        unsigned char *keyBytes;
       
        if (!KeyIso_parse_pfx_engine_key_id(
                keyCtx->correlationId,
                (char *)key,
                &keyLength,
                &keyBytes,
                NULL)) {
            KMPPPFXerr(KMPPPFX_F_INIT_SYMMETRIC_KEY, KMPPPFX_R_PARSE_PFX_KEY_ID_ERROR);
            KEYISOP_trace_log_error(NULL, 0, title, NULL, "KeyIso_parse_pfx_engine_key_id FAILED");
            return STATUS_FAILED;
        }   

        int status = KeyIso_CLIENT_init_key_ctx(keyCtx, keyLength, keyBytes, NULL);

        KeyIso_free(keyBytes);
        return status;
    }
    return STATUS_OK;
}

// This is a EVP_CIPH_FLAG_CUSTOM_CIPHER do cipher method
// return negative value on failure, and number of unsigned chars written to out on success (may be 0)
//In EVP_aes_256_cbc_hmac_sha256 algorithm, the value that the cipher function returns, is the value that will be set in the inl parameter of EVP_Encrypt functions
static int _kmpp_aes_256_cbc_hmac_sha256_cipher(EVP_CIPHER_CTX* ctx, unsigned char* out,
    const unsigned char* in, size_t inLen)
{
    const char *title = KEYISOP_SYMMETRIC_ENC_DEC_TITLE;

    unsigned int outLen = 0;
    int mode = 0;
    int status = 0;

    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "kmpp_aes_256_cbc_hmac_sha256_cipher");
    if (inLen == 0) {
        //assuming that this is EVP_EncryptFinal_ex that dosn't need here - we are calling only once
        return outLen;
    }

    KEYISO_KEY_CTX* keyCtx = (KEYISO_KEY_CTX*)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (!keyCtx) {
        KMPPPFXerr(KMPPPFX_F_SYMMETRIC_CIPHER, KMPPPFX_R_CTX_NULL);
        KEYISOP_trace_log_error(NULL, 0, title, NULL, "kmpp_aes_256_cbc_hmac_sha256_cipher - ctx null");
        return -1;
    }

    // Start measuring time for metrics
    START_MEASURE_TIME();

    if (EVP_CIPHER_CTX_encrypting(ctx)) {
        KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "kmpp_aes_256_cbc_hmac_sha256_cipher - encrypt");
        mode = KEYISO_AES_ENCRYPT_MODE;
    }
    else {
        KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "kmpp_aes_256_cbc_hmac_sha256_cipher - decrypt");
        mode = KEYISO_AES_DECRYPT_MODE;
    }

    if (inLen > (size_t)UINT_MAX) {
        KMPPPFXerr(KMPPPFX_F_SYMMETRIC_CIPHER, KMPPPFX_R_DATA_TOO_LARGE);
        KEYISOP_trace_log_error(NULL, 0, title, NULL, "The length of the data must be lower then UINT_MAX");
        status = -1;
    }

    if (status != -1) {
        if (KeyIso_CLIENT_symmetric_key_encrypt_decrypt(
            keyCtx,
            mode,
            in,
            (unsigned int)inLen,
            out,
            &outLen) != STATUS_OK) {
                KMPPPFXerr(KMPPPFX_F_SYMMETRIC_CIPHER, KMPPPFX_R_ENCRYPT_DECRYPT_FAILED);
                KEYISOP_trace_log_error(NULL, 0, title, NULL, "KeyIso_CLIENT_symmetric_key_encrypt_decrypt failed");
                status = -1;
            }
    }

    KeyisoKeyOperation operation = (mode == KEYISO_AES_ENCRYPT_MODE) ? KeyisoKeyOperation_SymmetricKeyEncrypt : KeyisoKeyOperation_SymmetricKeyDecrypt;
    int ret = (status >= 0) ? STATUS_OK : STATUS_FAILED;
    STOP_MEASURE_TIME(operation);

    return ((status != -1) ? outLen : status);
}

// Allows various cipher specific parameters to be determined and set.
// Returns engine_SUCCESS on success, engine_FAILURE on error, or taglen on successful query of
// EVP_CTRL_AEAD_TLS1_AAD.
static int _kmpp_aes_256_cbc_hmac_sha256_ctrl(EVP_CIPHER_CTX* ctx, int type, int arg,
    void* ptr)
{
    const char *title = KEYISOP_SYMMETRIC_ENC_DEC_TITLE;

    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, NULL, "kmpp_aes_256_cbc_hmac_sha256_ctrl - 0x%x", type);
    KEYISO_KEY_CTX* keyCtx = (KEYISO_KEY_CTX*)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (!keyCtx) {
        KMPPPFXerr(KMPPPFX_F_SYMMETRIC_CTRL, KMPPPFX_R_CTX_NULL);
        KEYISOP_trace_log_error(NULL, 0, title, NULL, "kmpp_aes_256_cbc_hmac_sha256_ctrl - ctx null");
        return 0;
    }
    
    return 1;
}

static int _kmpp_aes_256_cbc_hmac_sha256_cleanup(EVP_CIPHER_CTX* ctx)
{
    const char *title = KEYISOP_SYMMETRIC_ENC_DEC_TITLE;

    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "_kmpp_aes_256_cbc_hmac_sha256_cleanup");
    KEYISO_KEY_CTX* keyCtx = (KEYISO_KEY_CTX*)EVP_CIPHER_CTX_get_cipher_data(ctx);
    KeyIso_CLIENT_free_key_ctx(keyCtx);
    return 1;
}

/* AES256-CBC - HMAC SHA256 */
static const EVP_CIPHER* _kmpp_aes_256_cbc_hmac_sha256(void)
{
    const char *title = KEYISOP_SYMMETRIC_ENC_DEC_TITLE;

    if (!(_hidden_aes_256_cbc_hmac_sha256 = EVP_CIPHER_meth_new(NID_aes_256_cbc_hmac_sha256, 1, KMPP_AES_256_KEY_SIZE))
            || !EVP_CIPHER_meth_set_flags(_hidden_aes_256_cbc_hmac_sha256, AES_CBC_HMAC_FLAGS)
            || !EVP_CIPHER_meth_set_init(_hidden_aes_256_cbc_hmac_sha256, _kmpp_aes_256_cbc_hmac_sha256_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_cbc_hmac_sha256, _kmpp_aes_256_cbc_hmac_sha256_cipher)
            || !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_cbc_hmac_sha256, _kmpp_aes_256_cbc_hmac_sha256_ctrl)
            || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_cbc_hmac_sha256,(sizeof(KEYISO_KEY_CTX)))
            || !EVP_CIPHER_meth_set_cleanup(_hidden_aes_256_cbc_hmac_sha256, _kmpp_aes_256_cbc_hmac_sha256_cleanup)) {
        KMPPPFXerr(KMPPPFX_F_INIT_SYMMETRIC, KMPPPFX_R_BIND_FAILURE);
        KEYISOP_trace_log_error(NULL, 0, title, NULL, "kmpp_aes_256_cbc_hmac_sha256 - Error!");
        _hidden_aes_256_cbc_hmac_sha256 = NULL;
    }
    return _hidden_aes_256_cbc_hmac_sha256;
}


static int _kmpp_ciphers_init_static()
{
    if (!_kmpp_aes_256_cbc_hmac_sha256()) {
        return 0;
    }
    return 1;
}

int kmpp_ciphers(ENGINE* e, const EVP_CIPHER** cipher,
    const int** nids, int nid)
{
    int ok = 1;
    if (!cipher) {
        /* We are returning a list of supported nids */
        *nids = _kmpp_cipher_nids;
        return (sizeof(_kmpp_cipher_nids))
             / sizeof(_kmpp_cipher_nids[0]);
    }

    /* We are being asked for a specific cipher */
    switch (nid) {
        case NID_aes_256_cbc_hmac_sha256:
            *cipher = _hidden_aes_256_cbc_hmac_sha256;
            break;
        default:
            ok = 0;
            *cipher = NULL;
            break;
    }
    return ok;
}

int kmpp_symmetric_destroy(ENGINE* e)
{
#ifdef KMPP_SYMMETRIC_KEY_SUPPORT
    EVP_CIPHER_meth_free(_hidden_aes_256_cbc_hmac_sha256);
#endif
    return STATUS_OK;
}


int kmpp_symmetric_bind_engine(ENGINE* e)
{
    const char *title = KEYISOP_SYMMETRIC_ENC_DEC_TITLE;
    
    // Symmetric key support is working only when using compile flag
    // KMPP_SYMMETRIC_KEY_SUPPORT
#ifndef KMPP_SYMMETRIC_KEY_SUPPORT
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "kmpp_symmetric_init not running since that KMPP_SYMMETRIC_KEY_SUPPORT is not set");
    return STATUS_OK;
#endif

    // Explicitly load all ciphers in order to remove registered stitched algorithms which we want to avoid
    // This means that applications using EVP_get_cipherbyname will not find stitched algorithms, and will instead use the unstitched versions that engine supports
    if (!OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, NULL)) {
        KMPPPFXerr(KMPPPFX_F_INIT_SYMMETRIC_KEY, KMPPPFX_R_OPENSSL_INIT_CRYPTO_FAILED);
        KEYISOP_trace_log_error(NULL, 0, title, NULL, "kmpp_symmetric_init - fail in OPENSSL_init_crypto");
        return STATUS_FAILED;
    }

    // Engine initialization
    if (!ENGINE_set_ciphers(e, kmpp_ciphers)) {
        KMPPPFXerr(KMPPPFX_F_INIT_SYMMETRIC_KEY, KMPPPFX_R_ENGINE_SET_CIPHERS_FAILED);
        KEYISOP_trace_log_error(NULL, 0, title, NULL, "kmpp_symmetric_init - fail in ENGINE_set_ciphers");
        return STATUS_FAILED;
    }

    // Initialize hidden static variables once at Engine load time
    if (!_kmpp_ciphers_init_static()) {
        KMPPPFXerr(KMPPPFX_F_INIT_SYMMETRIC_KEY, KMPPPFX_R_CIPHERS_INIT_STATIC_FAILED);
        KEYISOP_trace_log_error(NULL, 0, title, NULL, "kmpp_symmetric_init - fail in kmpp_ciphers_init_static");        
        kmpp_symmetric_destroy(e);
        return STATUS_FAILED;
    }
 
    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "kmpp_symmetric_init - finished");

    return STATUS_OK;
 
}
