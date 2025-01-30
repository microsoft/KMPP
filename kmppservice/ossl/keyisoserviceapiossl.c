/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>  
#include <dirent.h>

#include <openssl/pkcs12.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

#include "keyisoserviceapiossl.h"
#include "keyisocommon.h"
#include "keyisolog.h"
#include "keyisotelemetry.h"
#include "keyisomemory.h"
#include "keyisoservicecommon.h"

#include "keyisocert.h"
#include "keyisoutils.h"

#ifdef KMPP_GENERAL_PURPOSE_TARGET
#ifdef  __cplusplus
extern "C" {
#endif 
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>
#define TCTI_NAME_DEFAULT "device:/dev/tpmrm0"
#define TPM_DEVICE_PREFIX "tpm"
#define TPM_DEVICE_DIR "/dev"
#ifdef  __cplusplus
}
#endif
#endif //KMPP_GENERAL_PURPOSE_TARGET

static unsigned char KEYISO_pfxSecret[KEYISO_SECRET_FILE_LENGTH];

// In this service the KEYISO_pfxSecret is read when the service starts.
static int _get_machine_secret(    
    uint8_t *key, 
    uint16_t keySize)
{
    memcpy(key, KEYISO_pfxSecret, keySize);
    return STATUS_OK;
}

static int _create_salted_pfx(
    const uuid_t correlationId,
    EVP_PKEY *key,
    X509 *cert,
    STACK_OF(X509) *ca,               // Optional
    int *outPfxLength,
    unsigned char **outPfxBytes,      // KeyIso_free()
    char **outPfxSalt)                // KeyIso_free()
{
    const char *title = KEYISOP_PFX_SECRET_TITLE;
    const char *loc = "";
    int ret = 0;
    BIO *bioOutPfx = NULL;
    char *outSalt = NULL;
    char *password = NULL;
    int outLength = 0;
    unsigned char *outBytes = NULL;         // don't free

    *outPfxLength = 0;
    *outPfxBytes = NULL;
    *outPfxSalt = NULL;

    if (!KeyIso_generate_salt(correlationId, &outSalt)) {
        goto end;
    }

    if (!KeyIso_generate_password_from_salt(correlationId, outSalt, &password)) {
        goto end;
    }

    bioOutPfx = KeyIsoP_create_pfx(
        correlationId,
        key,
        cert,
        ca,
        password,
        &outLength,
        &outBytes);           // Don't free
    if (bioOutPfx == NULL) {
        goto end;
    }

    *outPfxBytes = (unsigned char *) KeyIso_zalloc(outLength);
    if (*outPfxBytes == NULL) {
        goto openSslErr;
    }

    memcpy(*outPfxBytes, outBytes, outLength);
    *outPfxLength = outLength;

    *outPfxSalt = outSalt;
    outSalt = NULL;

    ret = 1;

end:
    KeyIso_clear_free_string(outSalt);
    KeyIso_clear_free_string(password);
    BIO_free(bioOutPfx);

    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}


// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *outVerifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to import PFX.
int KeyIso_SERVER_import_pfx(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *inPassword,             // optional
    int *verifyChainError,
    int *outPfxLength,
    unsigned char **outPfxBytes,        // KeyIso_free()
    char **outPfxSalt)                  // KeyIso_free()
{
    const char *title = KEYISOP_IMPORT_PFX_TITLE;
    int ret = 0;
    int buildPfxCaRet = 0;
    EVP_PKEY *inPfxPkey = NULL;
    X509 *inPfxCert = NULL;
    STACK_OF(X509) *inPfxCa = NULL;
    STACK_OF(X509) *outPfxCa = NULL;

    *verifyChainError = 0;
    *outPfxLength = 0;
    *outPfxBytes = NULL;
    *outPfxSalt = NULL;

#ifndef KMPP_TELEMETRY_DISABLED
    char sha256HexHash[SHA256_DIGEST_LENGTH * 2 + 1];
#endif

    ERR_clear_error();

    // Check that pfx size doesn't exceed the maximum
    if (inPfxLength > KMPP_MAX_MESSAGE_SIZE) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, NULL, "Pfx file is too big", "length: %d", inPfxLength);
        return ret;
    }

    if (!KeyIso_pkcs12_parse(correlationId, inPfxLength, inPfxBytes, inPassword, &inPfxPkey, &inPfxCert, &inPfxCa)) {
        KEYISOP_trace_log_error(correlationId, 0, title, "pkcs12 parse", "Failed");
        goto end;
    }

    buildPfxCaRet = KeyIso_validate_certificate(
            correlationId,
            KEYISO_EXCLUDE_END_FLAG |
                KEYISO_IGNORE_DEPTH_ZERO_SELF_SIGNED_ERROR_FLAG |
                (keyisoFlags & KEYISO_EXCLUDE_EXTRA_CA_FLAG),
            inPfxCert,
            inPfxCa,
            verifyChainError,
            &outPfxCa);
    if (buildPfxCaRet == 0) {
        KEYISOP_trace_log_error(correlationId, 0, title, "verify cert", "Failed");
        goto end;
    }

    if (!_create_salted_pfx(
            correlationId,
            inPfxPkey,
            inPfxCert,
            outPfxCa,
            outPfxLength,
            outPfxBytes,        // KeyIso_free()
            outPfxSalt)) {      // KeyIso_free()
        goto end;
    }

    ret = buildPfxCaRet;

end:

#ifndef KMPP_TELEMETRY_DISABLED
    // Extract sha256 string out of the public key of the cert.
    KeyIsoP_X509_pubkey_sha256_hex_hash(inPfxCert, sha256HexHash);
    if (ret != 0)
        KEYISOP_trace_metric_para(correlationId, 0, KeyIsoSolutionType_process, title, NULL, "PFX import succeeded. sha256: %s", sha256HexHash);
    else
        KEYISOP_trace_metric_error_para(correlationId, 0, KeyIsoSolutionType_process, title, NULL, "PFX import failed.", "sha256:%s", sha256HexHash);
#endif

    EVP_PKEY_free(inPfxPkey);
    X509_free(inPfxCert);
    sk_X509_pop_free(inPfxCa, X509_free);
    sk_X509_pop_free(outPfxCa, X509_free);

    return ret;
}

int KeyIso_SERVER_pfx_open(
    const uuid_t correlationId,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *salt,
    void **pkey)
{
    const char *title = KEYISOP_OPEN_PFX_TITLE;
    const char *loc = "";
    int ret = 0;
    char *password = NULL;    // KeyIso_clear_free_string()
    BIO *bioPfx = NULL;
    PKCS12 *p12 = NULL;
    X509 *parse_cert = NULL;

    *pkey = NULL;

    ERR_clear_error();

    // Check that pfx size doesn't exceed the maximum
    if (inPfxLength > KMPP_MAX_MESSAGE_SIZE) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, NULL, "Pfx file is too big", "length: %d", inPfxLength);
        return ret;
    }

    if (!KeyIso_generate_password_from_salt(correlationId, salt, &password)) {
        goto end;
    }

    bioPfx = BIO_new_mem_buf(inPfxBytes, inPfxLength);
    if (bioPfx == NULL) {
        goto openSslErr;
    }

    p12 = d2i_PKCS12_bio(bioPfx, NULL);
    if (p12 == NULL) {
        loc = "d2i_PKCS12_bio";
        goto openSslErr;
    }

    if (!PKCS12_parse(p12, password, (EVP_PKEY **) pkey, &parse_cert, NULL)) {
        loc = "PKCS12_parse";
        goto openSslErr;
    }

    ret = 1;

end:
    KeyIso_clear_free_string(password);
    BIO_free(bioPfx);
    PKCS12_free(p12);
    X509_free(parse_cert);

    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

void KeyIso_SERVER_pfx_free(
    void *pkey)
{
    EVP_PKEY_free((EVP_PKEY *) pkey);
}

void KeyIso_SERVER_pfx_up_ref(
    void *pkey)
{
    EVP_PKEY_up_ref((EVP_PKEY *) pkey);
}


int KeyIso_SERVER_rsa_private_encrypt_ossl(
    const uuid_t correlationId,
    void *pkey,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding)
{
    const char *title = KEYISOP_RSA_ENCRYPT_TITLE;
    int ret = -1;
    EVP_PKEY *evp_pkey = (EVP_PKEY *) pkey;

    ERR_clear_error();

    if (evp_pkey && EVP_PKEY_id(evp_pkey) == EVP_PKEY_RSA) {
        RSA *rsa = (RSA *)EVP_PKEY_get0_RSA(evp_pkey);        // get0 doesn't up_ref

        if (rsa == NULL) {
            KEYISOP_trace_log_error(correlationId, 0, title, "get0_RSA", "Not RSA");
        } else {
            int sigLen = RSA_size(rsa);
            if (tlen < sigLen) {
                KEYISOP_trace_log_error_para(correlationId, 0, title, "SigLength", "Invalid length",
                    "Length: %d Expected: %d", tlen, sigLen);
            } else {
                ret = RSA_private_encrypt(flen, from, to, rsa, padding);
                if (ret <= 0) {
                    KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, "RSA_private_encrypt", "padding: %d", padding);
                }
            }
        }
    } else {
        KEYISOP_trace_log_error(correlationId, 0, title, "KeyType", "Not RSA");
    }

    return ret;
}


int KeyIso_SERVER_rsa_private_decrypt_ossl(
    const uuid_t correlationId,
    void *pkey,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding)
{
    const char *title = KEYISOP_RSA_DECRYPT_TITLE;
    int ret = -1;
    EVP_PKEY *evp_pkey = (EVP_PKEY *) pkey;

    ERR_clear_error();

    if (evp_pkey && EVP_PKEY_id(evp_pkey) == EVP_PKEY_RSA) {
        RSA *rsa = (RSA *)EVP_PKEY_get0_RSA(evp_pkey);        // get0 doesn't up_ref

        if (rsa == NULL) {
            KEYISOP_trace_log_error(correlationId, 0, title, "get0_RSA", "Not RSA");
        } else {
            int decryptLen = RSA_size(rsa);
            if (tlen < decryptLen) {
                KEYISOP_trace_log_error_para(correlationId, 0, title, "DecryptLength", "Invalid length",
                    "Length: %d Expected: %d", tlen, decryptLen);
            } else {
                ret = RSA_private_decrypt(flen, from, to, rsa, padding);
                if (ret <= 0) {
                    KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, "RSA_private_decrypt", "padding: %d", padding);
                }
            }
        }
    } else {
        KEYISOP_trace_log_error(correlationId, 0, title, "KeyType", "Not RSA");
    }

    return ret;
}


int KeyIso_SERVER_rsa_sign_ossl(
    const uuid_t correlationId,
    void *pkey,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding)
{
    unsigned int siglen;
    unsigned int m_offset;

    KEYISO_RSA_SIGN rsaSign;
    EVP_PKEY *evp_pkey = (EVP_PKEY *) pkey;

    const char *title = KEYISOP_RSA_SIGN_TITLE;
    int ret = -1;

    ERR_clear_error();

    if (evp_pkey && EVP_PKEY_id(evp_pkey) == EVP_PKEY_RSA) {
        RSA *rsa = (RSA *)EVP_PKEY_get0_RSA(evp_pkey);        // get0 doesn't up_ref

        if (rsa == NULL) {
            KEYISOP_trace_log_error(correlationId, 0, title, "get0_RSA", "Not RSA");
        } else {
            if (tlen < RSA_size(rsa)) {
                KEYISOP_trace_log_error_para(correlationId, 0, title, "SignatureLength", "Invalid length",
                    "Length: %d Expected: %d", tlen, RSA_size(rsa));
            } else {
                m_offset = sizeof(KEYISO_RSA_SIGN);
                if ((unsigned int)flen < m_offset) {
                    KEYISOP_trace_log_error(correlationId, 0, title, "flen", "Invalid buffer Length");
                    return ret;
                }
                memcpy(&rsaSign, from, m_offset);
                if (rsaSign.m_len != flen - m_offset) {
                    KEYISOP_trace_log_error(correlationId, 0, title, "m_len", "Invalid message Length");
                    return ret;
                }
                ret = RSA_sign(rsaSign.type, from + m_offset, rsaSign.m_len, to, &siglen, rsa);

                if (ret <= 0) {
                    KEYISOP_trace_log_openssl_error(correlationId, 0, title, "RSA_sign");
                } else {
                    ret = siglen;
                }
            }
        }
    } else {
        KEYISOP_trace_log_error(correlationId, 0, title, "KeyType", "Not RSA");
    }

    return ret;
}


int KeyIso_SERVER_pkey_rsa_sign_ossl(
    const uuid_t correlationId,
    void *pkey,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding)
{
    unsigned int tbs_offset;
    int outlength;
    KEYISO_EVP_PKEY_SIGN pkeyRsaSign;
    size_t siglen = 0;

    const char *title = KEYISOP_PKEY_RSA_SIGN_TITLE;
    int ret = -1;

    EVP_PKEY_CTX *ctx   = NULL;
    EVP_PKEY *evp_pkey  = (EVP_PKEY *) pkey;
    int pkeyId          = (evp_pkey) ? EVP_PKEY_id(evp_pkey) : EVP_PKEY_NONE;
    
    ERR_clear_error();

    if (pkeyId == EVP_PKEY_RSA || pkeyId == EVP_PKEY_RSA_PSS) {
        const RSA *rsa = EVP_PKEY_get0_RSA(evp_pkey);        // get0 doesn't up_ref
        if (rsa == NULL) {
            KEYISOP_trace_log_error(correlationId, 0, title, "get0_RSA", "Not RSA");
        } else {
            outlength  = RSA_size(rsa);
            if (tlen < outlength) {
                KEYISOP_trace_log_error_para(correlationId, 0, title, "RSA_size", "Invalid length",
                    "Length: %d Expected: %d", tlen, outlength);

            } else {
                const EVP_MD *sigmd;
                const EVP_MD *mgfmd;

                ctx = EVP_PKEY_CTX_new((EVP_PKEY *)pkey, NULL);
                if (ctx == NULL) {
                    KEYISOP_trace_log_error(correlationId, 0, title, "EVP_PKEY_CTX_new", "Failed to allocate public key algorithm context");
                    goto end;
                }
                if (EVP_PKEY_sign_init(ctx) <= 0) { 
                    KEYISOP_trace_log_error(correlationId, 0, title, "EVP_PKEY_sign_init", "Failed to initialize a public key algorithm context");
                    goto end;
                }

                tbs_offset = sizeof(KEYISO_EVP_PKEY_SIGN);
                if ((unsigned int)flen < tbs_offset) {
                    KEYISOP_trace_log_error(correlationId, 0, title, "flen", "Invalid buffer length");
                    goto end;
                }

                memcpy(&pkeyRsaSign, from, tbs_offset);
                if (pkeyRsaSign.tbsLen != flen - tbs_offset) {
                    KEYISOP_trace_log_error(correlationId, 0, title, "tbsLen", "Invalid tbs length");
                    goto end;
                }

                sigmd = EVP_get_digestbynid(pkeyRsaSign.sigmdType);
                if(sigmd == NULL) { 
                    KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, "get_digestbynid - Failed to get the message digest type", "sigmdType: %d", pkeyRsaSign.sigmdType);
                    goto end;
                }

                // Sets properties to the public key algorithm context //

                if (EVP_PKEY_CTX_set_signature_md(ctx, sigmd) <= 0) { 
                    KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, "set_signature_md - Failed to set the message digest type", "sigmd: %d", sigmd);
                    goto end;
                }

                if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) { 
                    KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, "set_rsa_padding - Failed to set the rsa padding mode", "padding: %d", padding);
                    goto end;
                }

                // Sets properties unique to PSS padding //

                if (padding == RSA_PKCS1_PSS_PADDING)
                {
                    mgfmd = EVP_get_digestbynid(pkeyRsaSign.mgfmdType);
                    if (mgfmd == NULL) { 
                        KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, "get_digestbynid - Failed to get the message digest type", "mgfmdType:%d", pkeyRsaSign.mgfmdType);
                        goto end;
                    }
                    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgfmd) <= 0) { 
                        KEYISOP_trace_log_openssl_error(correlationId, 0, title, "set_rsa_mgf1_md - Failed to set MGF1 digest");
                        goto end;
                    }
                    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, pkeyRsaSign.saltLen) <= 0) { 
                        KEYISOP_trace_log_openssl_error(correlationId, 0, title, "set_rsa_pss_saltlen - Failed to set salt length");
                        goto end;
                    }
                }

                if (pkeyRsaSign.getMaxLen){
                    // This flag is not equal to zero when sig is NULL, so the maximum size of the output buffer 
                    // should be written to the siglen parameter.
                    
                    to = NULL;
                    
                } else {
                    // If sig is not NULL then before the call the siglen parameter should 
                    // contain the length of the sig buffer.
                    if (pkeyRsaSign.sigLen > (unsigned int)tlen) {
                        KEYISOP_trace_log_openssl_error(correlationId, 0, title, "siglen - Invalid signature length");
                        goto end;
                    } 
                    siglen = (size_t)pkeyRsaSign.sigLen;
                }

                ret = EVP_PKEY_sign(ctx, to, &siglen, from + tbs_offset, (size_t)pkeyRsaSign.tbsLen);
                if (ret <= 0) { 
                    KEYISOP_trace_log_openssl_error(correlationId, 0, title, "EVP_PKEY_sign");
                    goto end;
                } 

                ret = (int) siglen;
            }
        }
    } else {
        KEYISOP_trace_log_error(correlationId, 0, title, "KeyType", "Not RSA");
    }
end:
    EVP_PKEY_CTX_free(ctx);   // If ctx is NULL, nothing is done.

    return ret;
}

int KeyIso_SERVER_ecdsa_sign_ossl(
    const uuid_t correlationId,
    void *pkey,
    int type,
    const unsigned char *dgst,
    int dlen,
    unsigned char *sig,
    unsigned int siglen,
    unsigned int *outlen)
{
    const char *title = KEYISOP_ECC_SIGN_TITLE;
    int ret = 0;
    EVP_PKEY *evp_pkey = (EVP_PKEY *) pkey;

    *outlen = 0;
    ERR_clear_error();

    if (pkey && EVP_PKEY_id(evp_pkey) == EVP_PKEY_EC) {
        EC_KEY *eckey = (EC_KEY *)EVP_PKEY_get0_EC_KEY(evp_pkey);   // get0 doesn't up_ref
        if (eckey == NULL) {
            KEYISOP_trace_log_error(correlationId, 0, title, "get0_EC_KEY", "Not ECC");
        } else {
            int ecdsaSigLen = ECDSA_size(eckey);
            if ((int) siglen < ecdsaSigLen) {
                KEYISOP_trace_log_error_para(correlationId, 0, title, "SigLength", "Invalid length",
                    "Length: %d Expected: %d", siglen, ecdsaSigLen);
            } else {
                ret = ECDSA_sign(type, dgst, dlen, sig, outlen, eckey);
                if (!ret) {
                    KEYISOP_trace_log_openssl_error(correlationId, 0, title, "ECDSA_sign");
                }
            }
        }
    } else {
        KEYISOP_trace_log_error(correlationId, 0, title, "KeyType", "Not ECC");
    }

    return ret;
}

// The pemCert consists of the end certificate followed by
// 1 or more CA certificates
int KeyIso_SERVER_replace_pfx_certs(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *inSalt,
    int pemCertLength,
    const unsigned char *pemCertBytes,
    int *outPfxLength,
    unsigned char **outPfxBytes,    // KeyIso_free()
    char **outSalt)                 // KeyIso_free()
{
    int ret = 0;
    void *pkey = NULL;            // KeyIso_SERVER_pfx_free()
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;

    *outPfxLength = 0;
    *outPfxBytes = NULL;
    *outSalt = NULL;

    if (!KeyIso_SERVER_pfx_open(
            correlationId,
            inPfxLength,
            inPfxBytes,
            inSalt,
            &pkey)) {
        goto end;
    }

    if (!KeyIso_load_pem_cert(
            correlationId,
            pemCertLength,
            pemCertBytes,
            NULL,     // pkey
            &cert,
            &ca)) {
        goto end;
    }

    if (!_create_salted_pfx(
            correlationId,
            (EVP_PKEY *)pkey,
            cert,
            ca,
            outPfxLength,
            outPfxBytes,
            outSalt)) {
        goto end;
    }

    ret = 1;

end:
    KeyIso_SERVER_pfx_free(pkey);
    X509_free(cert);
    sk_X509_pop_free(ca, X509_free);

    return ret;
}

static int _conf_get_key(
    const uuid_t correlationId,
    CONF *conf,
    X509 *cert,
    EVP_PKEY **pkey)
{
    const char *title = KEYISOP_CREATE_SELF_SIGN_TITLE;
    const char *keyType = NULL; // don't free
    int ret = 0;

    *pkey = NULL;

    keyType = KeyIso_conf_get_string(correlationId, conf, "key_type");
    if (keyType == NULL) {
        goto end;
    }

    if (strcmp(keyType, "rsa") == 0) {
        *pkey = KeyIso_conf_generate_rsa(correlationId, conf);
    } else if (strcmp(keyType, "ecc") == 0) {
        *pkey = KeyIso_conf_generate_ecc(correlationId, conf);
    } else {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "key_type", "Invalid",
            "Expected: rsa or ecc");
        goto end;
    }

    if (*pkey == NULL) {
        goto end;
    }

    ERR_clear_error();

    if (!X509_set_pubkey(cert, *pkey)) {
        KEYISOP_trace_log_openssl_error(correlationId, 0, title, "X509_set_pubkey");
        goto end;
    }

    ret = 1;

end:
    if (!ret) {
        EVP_PKEY_free(*pkey);
        *pkey = NULL;
    }

    return ret;
}

int KeyIso_SERVER_create_self_sign_pfx(
    const uuid_t correlationId,
    int keyisoFlags,
    const char *confStr,
    int *outPfxLength,
    unsigned char **outPfxBytes,        // KeyIso_free()
    char **outPfxSalt)                  // KeyIso_free()
{
    const char *title = KEYISOP_CREATE_SELF_SIGN_TITLE;
    const char *loc = "";
    int ret = 0;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    ASN1_INTEGER *serial = NULL;
    int64_t randSerial;
    CONF *conf = NULL;

    *outPfxLength = 0;
    *outPfxBytes = NULL;
    *outPfxSalt = NULL;

    ERR_clear_error();

    cert = X509_new();
    if (cert == NULL) {
        goto openSslErr;
    }

    // V3 version
    if (!X509_set_version(cert, 2)) {
        loc = "X509_set_version";
        goto openSslErr;
    }

    // Random 8 byte serial number
    serial = ASN1_INTEGER_new();
    if (serial == NULL) {
        goto openSslErr;
    }
    if (KeyIso_rand_bytes((unsigned char *) &randSerial, sizeof(randSerial)) != STATUS_OK) {
        loc = "RAND_bytes";
         goto openSslErr;
    }
    if (!ASN1_INTEGER_set_int64(serial, randSerial)) {
        loc = "ASN1_INTEGER_set_int64";
        goto openSslErr;
    }
    if (!X509_set_serialNumber(cert, serial)) {
        loc = "X509_set_serialNumber";
        goto openSslErr;
    }

    if (!KeyIso_conf_load(correlationId, confStr, &conf)) {
        goto end;
    }

    if (!_conf_get_key(correlationId, conf, cert, &pkey)) {
        goto end;
    }

    if (!KeyIso_conf_get_name(correlationId, conf, cert)) {
        goto end;
    }

    if (!KeyIso_conf_get_time(correlationId, conf, cert)) {
        goto end;
    }

    if (!KeyIso_conf_get_extensions(correlationId, conf, cert)) {
        goto end;
    }

    if (!KeyIso_conf_sign(correlationId, conf, cert, pkey)) {
        goto end;
    }

    if (!_create_salted_pfx(
            correlationId,
            pkey,
            cert,
            NULL,                       // STACK_OF(X509) *ca
            outPfxLength,
            outPfxBytes,
            outPfxSalt)) {
        goto end;
    }

    ret = 1;

end:
    X509_free(cert);
    EVP_PKEY_free(pkey);
    NCONF_free(conf);
    ASN1_INTEGER_free(serial);
    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

static int _write_pfx_secret_file(
    const uuid_t correlationId,
    const char *filename)
{
    const char *title = KEYISOP_PFX_SECRET_TITLE;
    const char *loc = "";
    int ret = 0;
    BIO *out = NULL;
    unsigned char randBytes[KEYISO_SECRET_FILE_LENGTH];
    mode_t prevMask = 0;

    ERR_clear_error();

    if (KeyIso_rand_bytes(randBytes, sizeof(randBytes)) != STATUS_OK) {
        loc = "RAND_bytes";
        goto openSslErr;
    }

    if (randBytes[0] == 0) {
        randBytes[0] = 1;
    }

#ifndef KEYISO_TEST_WINDOWS
    prevMask = umask(077);      // Remove permissions for group/other
#endif

    out = BIO_new_file(filename, "wb");

#ifndef KEYISO_TEST_WINDOWS
    umask(prevMask);
#endif

    if (out == NULL) {
        loc = "BIO_new_file";
        goto openSslErr;
    }

    if (BIO_write(out, randBytes, sizeof(randBytes)) != sizeof(randBytes)) {
        loc = "BIO_write";
        goto openSslErr;
    }
    BIO_flush(out);

    ret = 1;

end:
    BIO_free(out);
    KeyIso_cleanse(randBytes, sizeof(randBytes));
    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, loc,
        "filename: %s", filename);
    goto end;
}

#define KEYISO_PFX_SECRET_SUB_PATH "private/pfx.0"

// OPENSSLDIR "/" "private/pfx.0"
// KeyIso_free() returned filename
// TODO: Remove dendency on openssl from this function.
char *KeyIso_get_pfx_secret_filename()
{
    const char *dir = KeyIsoP_get_default_private_area();
    size_t dirLength = strlen(dir);
    const char *subPath = KEYISO_PFX_SECRET_SUB_PATH;
    size_t subPathLength = strlen(subPath);
    size_t filenameLength = dirLength + 1 + subPathLength + 1;
    char *filename = (char *) KeyIso_zalloc(filenameLength);

    if (filename != NULL) {
        snprintf(filename, filenameLength, "%s/%s",
            dir, subPath);
    }

    return filename;
}

static int _read_pfx_secret_file(
    const uuid_t correlationId,
    const char *filename)
{
    const char *title = KEYISOP_PFX_SECRET_TITLE;
    const char *loc = "";
    int ret = 0;
    BIO *in = NULL;

    ERR_clear_error();

    in = BIO_new_file(filename, "rb");
    if (in == NULL) {
        if (ERR_GET_REASON(ERR_peek_last_error()) != BIO_R_NO_SUCH_FILE) {
            loc = "BIO_new_file";
            goto openSslErr;
        }
        goto end;
    }
    
    if (BIO_read(in, KEYISO_pfxSecret, sizeof(KEYISO_pfxSecret)) != sizeof(KEYISO_pfxSecret)) {
        loc = "BIO_read";
        goto openSslErr;
    }
    
    if (KEYISO_pfxSecret[0] == 0) {
        loc = "Invalid Content";
        goto openSslErr;
    }

    ret = 1;

end:
    if (!ret) {
        KEYISO_pfxSecret[0] = 0;
    }
    BIO_free(in);
    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, loc,
        "filename: %s", filename);
    goto end;
}


int _create_pfx_secret(
    const uuid_t correlationId, 
    char *filename)
{
    const char *title = KEYISOP_PFX_SECRET_TITLE;
    int ret = 0;

    if (_read_pfx_secret_file(correlationId, filename)) {
        KEYISOP_trace_log_para(correlationId, 0, title, "Using previously generated PFX secret",
            "secret: %s", filename);
        goto success;
    }

    if (_write_pfx_secret_file(correlationId, filename) &&
            _read_pfx_secret_file(correlationId, filename)) {
        KEYISOP_trace_log_para(correlationId, 0, title, "Generated PFX secret",
            "secret: %s", filename);
        goto success;
    }
    KEYISOP_trace_log_error_para(correlationId, 0, title, "Create PFX secret", "Failed", "secret: %s", filename);
    goto end;

success:
    ret = 1;

end:
    return ret;
}

//////////////////////
// TPM functions
/////////////////////
#ifdef KMPP_GENERAL_PURPOSE_TARGET
static void _print_tpm_error(
    const uuid_t correlationId,
    TSS2_RC ret,
    const char *errStr,
    const char *loc) {

    const char *title = KEYISOP_TPM_SECRET_TITLE;
    const char* tpmErr; 
    tpmErr = Tss2_RC_Decode(ret); 
    KEYISOP_trace_log_error_para(correlationId, 0, title, loc, errStr, "0x%x, TPM Error String: %s", ret, tpmErr); 
}


static TSS2_RC _cleanup_create_secret_tpm(
    const uuid_t correlationId,
    TSS2_RC ret,
    const char *loc,
    const char *message,
    TSS2_TCTI_CONTEXT *pTctiCtx,
    ESYS_CONTEXT *ctx,
    ESYS_TR primaryHandle) 
{
    
    if (ret != TSS2_RC_SUCCESS)
        _print_tpm_error(correlationId, ret, loc, message);

    if (ctx != NULL) {
        Esys_FlushContext(ctx, primaryHandle);
        Esys_Finalize(&ctx);
    }

    if (pTctiCtx != NULL) {
        Tss2_TctiLdr_Finalize(&pTctiCtx);
    }

    return ret;
}

#define _CLEANUP_CREATE_SECRET_TPM(ret, loc, message) \
        _cleanup_create_secret_tpm(correlationId, ret, loc, message, pTctiCtx, ctx, primaryHandle)


static int _create_primary_key_tpm(
    ESYS_CONTEXT *ctx,
    ESYS_TR *primaryHandle)
{
    TSS2_RC ret;
    TPM2B_SENSITIVE_CREATE inSensitivePrim = { .size = 0 };
    TPML_PCR_SELECTION creationPCR = { .count = 0 };
    TPM2B_DATA outsideInfo = { .size = 0 };
    TPM2B_PUBLIC inPublicPrim = {
            .size = sizeof(TPMT_PUBLIC),
            .publicArea = {
                    .type = TPM2_ALG_RSA,
                    .nameAlg = TPM2_ALG_SHA256,
                    .objectAttributes = TPMA_OBJECT_RESTRICTED |
                                        TPMA_OBJECT_DECRYPT |
                                        TPMA_OBJECT_FIXEDTPM |
                                        TPMA_OBJECT_FIXEDPARENT |
                                        TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                        TPMA_OBJECT_USERWITHAUTH,
                    .authPolicy = {

                    },
                    .parameters = {
                            .rsaDetail = {
                                    .symmetric = {
                                                    .algorithm = TPM2_ALG_AES,
                                                    .keyBits = { .sym = 128 },
                                                    .mode = { .sym = TPM2_ALG_CFB }
                                    },
                                    .scheme = { .scheme = TPM2_ALG_NULL },
                                    .keyBits = 2048
                            }
                    },
                    .unique = {
                            .rsa = {
                                        .size = 256
                            }
                    }
            }
    };

    if ((ret = Esys_CreatePrimary(
	        ctx,
	        ESYS_TR_RH_OWNER,
            ESYS_TR_PASSWORD,
	        ESYS_TR_NONE,
	        ESYS_TR_NONE,
	        &inSensitivePrim,
	        &inPublicPrim,
            &outsideInfo,
	        &creationPCR,
	        primaryHandle,
	        NULL,
	        NULL,
            NULL,
	        NULL)) != TSS2_RC_SUCCESS) {
        return ret;  
    }

    return TSS2_RC_SUCCESS;
}


static TSS2_RC _cleanup_create_and_load_key_tpm(
    const uuid_t correlationId,
    TSS2_RC ret,
    const char *loc,
    const char *message,
    TPM2B_PUBLIC *outPublic,
    TPM2B_PRIVATE *outPrivate) 
{
    if(outPrivate)
        Esys_Free(outPrivate);
    if(outPublic)
        Esys_Free(outPublic);

    return ret;
}

#define _CLEANUP_CREATE_AND_LOAD_SECRET_TPM(ret, loc, message) \
        _cleanup_create_and_load_key_tpm(correlationId, ret, loc, message, outPublic, outPrivate)

static TSS2_RC _create_and_load_key_tpm(
    const uuid_t correlationId,
    ESYS_CONTEXT *ctx,
    ESYS_TR primaryHandle,
    ESYS_TR *objectHandleOut,
    const unsigned char *secret)
{
    TSS2_RC ret;
    TPM2B_PUBLIC *outPublic;
    TPM2B_PRIVATE *outPrivate;
    TPML_PCR_SELECTION creationPCR = { .count = 0 };
    TPM2B_DATA outsideInfo = { .size = 0 };

    TPM2B_PUBLIC inPublic = {
        .size = sizeof(TPMT_PUBLIC),
        .publicArea = {
            .type = TPM2_ALG_KEYEDHASH,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = TPMA_OBJECT_FIXEDTPM |
                                TPMA_OBJECT_FIXEDPARENT |
                                TPMA_OBJECT_USERWITHAUTH,
            .parameters = {
                .keyedHashDetail = {
                .scheme = { TPM2_ALG_NULL }
                }
            },
            .unique = {
                .keyedHash = {
                    .size = 32
                }
            }
        }
    };
    TPM2B_SENSITIVE_CREATE inSensitive = { 
	.size = sizeof(TPM2B_SENSITIVE_CREATE), 
	.sensitive = {
		.data = {
			.size = sizeof(secret)
			}
		}
	};
	memcpy(inSensitive.sensitive.data.buffer, secret, inSensitive.sensitive.data.size);

    if ((ret = Esys_Create(
                ctx,
                primaryHandle,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
			    &inSensitive,
                &inPublic,
                &outsideInfo,
                &creationPCR,
                &outPrivate,
                &outPublic,
                NULL,
                NULL,
                NULL)) != TSS2_RC_SUCCESS) {
        return _CLEANUP_CREATE_AND_LOAD_SECRET_TPM(ret, "Esys_Create", "");
    }

    // Loading sealing key;
    if ((ret = Esys_Load(
            ctx,
            primaryHandle,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            outPrivate,
            outPublic,
            objectHandleOut)) != TSS2_RC_SUCCESS) {
        return _CLEANUP_CREATE_AND_LOAD_SECRET_TPM(ret, "Esys_Load", "");
    }
    
    return _CLEANUP_CREATE_AND_LOAD_SECRET_TPM(TSS2_RC_SUCCESS, "", "");
}

static TSS2_RC _evict_control_tpm(
    const uuid_t correlationId,
    ESYS_CONTEXT* ctx,
    ESYS_TR primaryHandle,
    ESYS_TR inObjectHandle,
    TPMI_DH_PERSISTENT *persistHandle)
{
    TSS2_RC ret = TSS2_TCTI_RC_GENERAL_FAILURE;
    ESYS_TR evictObjectHandleOut;
    const char *title = KEYISOP_TPM_SECRET_TITLE;
    TPMI_DH_PERSISTENT currentHandle = *persistHandle;

    while (currentHandle <= TPM2_PERSISTENT_LAST) {
        // Evict control sealing key
        ret = Esys_EvictControl(
                ctx,
                ESYS_TR_RH_OWNER,
                inObjectHandle,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                currentHandle,
                &evictObjectHandleOut);

        if (ret == TSS2_RC_SUCCESS) {
            return TSS2_RC_SUCCESS;
        } else if (ret != TPM2_RC_NV_DEFINED) {
            break;
        }

        // Increment the persistent handle and try again
        currentHandle++;
        *persistHandle = currentHandle;
    }

    if (currentHandle >= TPM2_PERSISTENT_LAST) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, "No available persistent handles");
    } 

    return ret;
}

static TSS2_RC _tpm_init_resources(
    TSS2_TCTI_CONTEXT **pTctiCtx,
    ESYS_CONTEXT **pCtx,
    ESYS_TR *primaryHandle, 
    const char** loc,
    const char** errStr)
{
    TSS2_RC ret = TSS2_RC_SUCCESS;
    TSS2_TCTI_CONTEXT* tctiCtx = NULL;
    ESYS_CONTEXT* ctx = NULL ;

    // Initialize the TCTI context
    // This initialization is required in old versions (below 2.4.0) of the TSS2 stack to avoid errors in the ESAPI initialization.
    if ((ret = Tss2_TctiLdr_Initialize(TCTI_NAME_DEFAULT, &tctiCtx)) != TSS2_RC_SUCCESS) {
        *loc = "Tss2_TctiLdr_Initialize";
        *errStr = "Error initializing TCTI ctx:";
        return ret;
    }

    // Initialize the ESAPI context
    if ((ret = Esys_Initialize(&ctx, tctiCtx, NULL)) != TSS2_RC_SUCCESS) {
        *loc = "Esys_Initialize";
        *errStr = "Error initializing ESAPI:";
        Tss2_TctiLdr_Finalize(&tctiCtx);
        return ret;
    }
 
    // Create primary key
    if ((ret = _create_primary_key_tpm(ctx, primaryHandle)) != TSS2_RC_SUCCESS) {
        *loc = "_create_primary_key_tpm";
        *errStr = "Error creating primary key:";
        Tss2_TctiLdr_Finalize(&tctiCtx);
        Esys_Finalize(&ctx);
        return ret;
    }

    *pTctiCtx = tctiCtx;
    *pCtx = ctx;
    return ret;
}

static TSS2_RC _create_secret_in_tpm(
    const uuid_t correlationId,
    const unsigned char *randBytesSecret,
    TPMI_DH_PERSISTENT *persistHandle)
{
    TSS2_TCTI_CONTEXT *pTctiCtx = NULL;
    ESYS_CONTEXT *ctx = NULL;
    ESYS_TR primaryHandle = ESYS_TR_NONE;
    ESYS_TR objectHandleOut = ESYS_TR_NONE;
    TSS2_RC ret;
    const char *loc = "";
    const char *errStr = "";
    
    // Init TPM resources
    if ((ret = _tpm_init_resources(&pTctiCtx, &ctx, &primaryHandle, &loc, &errStr)) != TSS2_RC_SUCCESS) {
        return _CLEANUP_CREATE_SECRET_TPM(ret, loc, errStr);
    }
   
    // Create and load sealing key
    if ((ret = _create_and_load_key_tpm(correlationId, ctx, primaryHandle, &objectHandleOut, randBytesSecret)) != TSS2_RC_SUCCESS) {
        return _CLEANUP_CREATE_SECRET_TPM(ret, "_create_and_load_key_tpm", "Error loading or sealing the key");
    }
   
    // Storing the object within a persistent handle
    if ((ret = _evict_control_tpm(correlationId, ctx, primaryHandle, objectHandleOut, persistHandle)) != TSS2_RC_SUCCESS) {
        return _CLEANUP_CREATE_SECRET_TPM(ret, "_evict_control_tpm", "Error unsealing data:");
    }

    return _CLEANUP_CREATE_SECRET_TPM(TSS2_RC_SUCCESS, NULL, NULL);
}


static TSS2_RC _cleanup_load_tpm_secret(
    const uuid_t correlationId,
    TSS2_RC ret,
    const char *loc,
    const char *message,
    TSS2_TCTI_CONTEXT *pTctiCtx,
    ESYS_CONTEXT *ctx,
    ESYS_TR primaryHandle,
    ESYS_TR evictObjectHandleOut,
    TPM2B_SENSITIVE_DATA *outData) 
{
    if (ret != TSS2_RC_SUCCESS)
        _print_tpm_error(correlationId, ret, loc, message);

    if (ctx != NULL) {
        Esys_FlushContext(ctx, primaryHandle);
        Esys_Finalize(&ctx);
    }

    if (pTctiCtx != NULL) {
        Tss2_TctiLdr_Finalize(&pTctiCtx);
    }
    Esys_Free(outData);

    return ret;
}

#define _CLEANUP_LOAD_TPM_SECRET(ret, loc, message) \
        _cleanup_load_tpm_secret(correlationId, ret, loc, message, pTctiCtx, ctx, primaryHandle, evictObjectHandleOut, outData)

static TSS2_RC _load_secret_from_tpm(
    const uuid_t correlationId,
    TPMI_DH_PERSISTENT persistHandle)
{
    TSS2_RC ret;
    ESYS_CONTEXT *ctx = NULL;
    ESYS_TR primaryHandle = ESYS_TR_NONE;
    ESYS_TR evictObjectHandleOut = ESYS_TR_NONE;
    TPM2B_SENSITIVE_DATA *outData = NULL;
    TSS2_TCTI_CONTEXT *pTctiCtx = NULL;

    const char *loc = "";
    const char *errStr = "";
    
    // Init TPM resources
    if ((ret = _tpm_init_resources(&pTctiCtx, &ctx, &primaryHandle, &loc, &errStr)) != TSS2_RC_SUCCESS) {
        return _CLEANUP_LOAD_TPM_SECRET(ret, loc, errStr);
    }

    //  Getting the objet handle out of the persistent area
    if ((ret = Esys_TR_FromTPMPublic(
                ctx,
                persistHandle,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &evictObjectHandleOut)) != TSS2_RC_SUCCESS) {
        return _CLEANUP_LOAD_TPM_SECRET(ret, "Esys_TR_FromTPMPublic", "Error getting handle from public:");
    }

    // Unseal data using the sealing key
    if ((ret = Esys_Unseal(
                ctx,
                evictObjectHandleOut,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &outData)) != TSS2_RC_SUCCESS) {
        return _CLEANUP_LOAD_TPM_SECRET(ret, "Esys_Unseal", "Error unsealing data");
    }

    // Copy the unsealed data to the KEYISO_pfxSecret 
    if (outData->size <= sizeof(KEYISO_pfxSecret)) {
        memcpy(KEYISO_pfxSecret, outData->buffer, outData->size);
    }
    else {
        return _CLEANUP_LOAD_TPM_SECRET(TSS2_TCTI_RC_INSUFFICIENT_BUFFER, "_load_pfx_secret_from_tpm", "Unsealed data is too large:");
    }

    return _CLEANUP_LOAD_TPM_SECRET(TSS2_RC_SUCCESS, NULL, NULL); 
}

static int _read_tpm_secret_file(
    const uuid_t correlationId,
    const char* filename)
{
    const char *title = KEYISOP_TPM_SECRET_TITLE;
    FILE *in = NULL;
    int ret = STATUS_FAILED;
    TPMI_DH_PERSISTENT persistHandle;

    in = fopen(filename, "rb");
    if (in  == NULL) {
        if (errno != ENOENT) {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "fopen", "Failed to open file", "filename: %s errno:%d", filename, errno);
        }
        return ret;
    }
    
    // Loading the mater key from TPM   
    if (fread(&persistHandle, sizeof(TPMI_DH_PERSISTENT), 1, in)) {
        if (_load_secret_from_tpm(correlationId, persistHandle) == TSS2_RC_SUCCESS) {
            ret = STATUS_OK;
        }
    }
    else {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "fread", "filename: %s", filename);
    }

    if (ret == STATUS_FAILED) {
        KEYISO_pfxSecret[0] = 0;
    }
    fclose(in);
    return ret;
}

static int _write_tpm_secret_file(
    const uuid_t correlationId,
    const char* filename)
{
    const char* title = KEYISOP_TPM_SECRET_TITLE;
    FILE *out = NULL;
    int ret = STATUS_FAILED;
    TPMI_DH_PERSISTENT persistHandle = TPM2_PERSISTENT_FIRST;
    unsigned char randBytes[KEYISO_SECRET_FILE_LENGTH];
    mode_t prevMask = 0;

    if (KeyIso_rand_bytes(randBytes, sizeof(randBytes)) != STATUS_OK) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "KeyIso_rand_bytes", "filename: %s", filename);
        return ret;
    }

    // The machine secret should never start with "0" so in case that the random value start with  it we set it.
    if (randBytes[0] == 0) {
        randBytes[0] = 1;
    }

    prevMask = umask(077); // Remove permissions for group/other

    out = fopen(filename, "wb");
    if (out == NULL) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "fopen", "Failed to open file", "filename: %s", filename);
        return ret;
    }

    umask(prevMask);

    // Encrypting and storing the machine secret in TPM
    if(_create_secret_in_tpm(correlationId, randBytes, &persistHandle) == TSS2_RC_SUCCESS) {
        // Write the TPMI_DH_PERSISTENT value to the file
        if (fwrite(&persistHandle, sizeof(TPMI_DH_PERSISTENT), 1, out)) {
            ret = STATUS_OK;
        }
        else {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "fwrite", "filename: %s", filename);
        }         
    }

    fflush(out);
    fclose(out);
    return ret;
}

static int _create_tpm_secret(
    const uuid_t correlationId,
    const char *filename) {

    const char *title = KEYISOP_TPM_SECRET_TITLE;
    int ret = STATUS_FAILED;

    if ((ret = _read_tpm_secret_file(correlationId, filename)) == STATUS_OK) {
        KEYISOP_trace_log_para(correlationId, 0, title, "Using previously generated TPM secret", "secret: %s", filename);
        //ret = STATUS_OK;
    }
    else {
        if ((ret = _write_tpm_secret_file(correlationId, filename) == STATUS_OK) &&
            (ret = _read_tpm_secret_file(correlationId, filename) == STATUS_OK)) {
            KEYISOP_trace_log_para(correlationId, 0, title, "Generated TPM secret", "secret: %s", filename);
            //ret = STATUS_OK;
        }
        else {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "Create TPM secret", "Failed", "secret: %s", filename);
        }
    }

    return ret;
}

static int _check_tpm_device() 
{
    DIR *d;
    struct dirent *dir;
    int tpmExists = 0;

    d = opendir(TPM_DEVICE_DIR);
    if (d) {
        while ((dir = readdir(d)) != NULL) {
        // Check if the directory entry name starts with "tpm"
            if (strncmp(dir->d_name, TPM_DEVICE_PREFIX, sizeof(TPM_DEVICE_PREFIX)-1) == 0) {
                closedir(d);
                return 1;
            }
        }
        closedir(d);
    }
    return tpmExists;
}
#endif //KMPP_GENERAL_PURPOSE_TARGET

// TODO: In this function KeyIso_get_pfx_secret_filename and KeyIso_free remains with their dependency on openssl.
//       This is the only reason for the dependency between TPM code and openssl. 
//       As we currently do not know how we are going to be working with secret files on OP-TEE this code is still left here 
//       we will move this code to keyisoserviceapi.c once we address the secret handling in OP-TEE
int KeyIsoP_create_pfx_secret(
    const uuid_t correlationId) {

   char *filename = NULL;      // KeyIso_free()
   int ret = STATUS_FAILED;

   // Retrieve the secret
   filename = KeyIso_get_pfx_secret_filename();
   if (filename == NULL) {
        return ret;
   }
   // Additional check to ensure 'filename' contains a valid file path that ends with null terminator
   if (strnlen(filename, PATH_MAX + 1) > PATH_MAX || strchr(filename, '%') != NULL) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_PFX_SECRET_TITLE, "Invalid filename", "Invalid filename");
        KeyIso_free(filename);
        return ret;
    }

#ifdef KMPP_GENERAL_PURPOSE_TARGET
   // Checking if TPM exists in the system
   if (1 == _check_tpm_device()) {
       KEYISOP_trace_log(correlationId, 0, KEYISOP_TPM_SECRET_TITLE, "TPM exists");
       ret = _create_tpm_secret(correlationId, filename);
    }    
    else
       ret = _create_pfx_secret(correlationId, filename);
#else
    ret = _create_pfx_secret(correlationId, filename);
#endif

    // Set the default function for getting the machine secret
    KeyIso_set_machine_secret_method(correlationId, _get_machine_secret);    
    
    KeyIso_free(filename);
    return ret;
}