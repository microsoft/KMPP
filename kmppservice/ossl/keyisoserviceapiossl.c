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
        KEYISOP_trace_metric_para(correlationId, 0, KeyIsoSolutionType_process, 0, title, NULL, "PFX import succeeded. sha256: %s", sha256HexHash);
    else
        KEYISOP_trace_metric_error_para(correlationId, 0, KeyIsoSolutionType_process, 0, title, NULL, "PFX import failed.", "sha256:%s", sha256HexHash);
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
        loc = "KeyIso_rand_bytes";
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
