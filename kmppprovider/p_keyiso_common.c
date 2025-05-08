/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include "keyisoclientinternal.h"
#include "keyisocommon.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "p_keyiso.h"
#include "p_keyiso_err.h"

#define INVALID_VALUE -1

static const char* certConfStr =
    "[self_sign]\n"
    "sign_digest = sha256\n"
    "key_type = rsa\n"
    "rsa_bits = 2048\n"
    "rsa_exp = 0x10001          # also 0x3\n"
    "rsa_padding = 6            # 1 - RSA_PKCS1_PADDING 6 - RSA_PKCS1_PSS_PADDING\n"
    "key_usage = digitalSignature,keyEncipherment\n"
    "days = 365\n"
    "distinguished_name = dn\n"
    "x509_extensions = v3_ext\n"
    "\n"
    "[dn]\n"
    "C = US\n"
    "ST = Washington\n"
    "L = Redmond\n"
    "O = \"Microsoft Corporation\"\n"
    "1.CN = \"KMPP Generated Cert\"\n"
    "2.CN = \"KMPP Generated Cert For Encoder\"\n"
    "\n"
    "[v3_ext]\n"
    "basicConstraints = critical,CA:FALSE\n"
    "extendedKeyUsage = critical,serverAuth,clientAuth\n"
    "subjectKeyIdentifier = hash\n"
    "authorityKeyIdentifier = keyid\n"
    "subjectAltName = @alt_names\n"
    "\n"
    "[alt_names]\n"
    "DNS.1 = pubkey.cert.kmpp.microsoft.com\n"
    "DNS.2 = pubkey.cert.kmpp.microsoft.com\n"
    "\n"
    "[cert]\n"
    "default_startdate = 20230101000000Z\n"
    "default_enddate = 20240101000000Z\n"
    "";

const OSSL_ITEM g_keyIsoPovSupportedMds[] = {
    { NID_sha1,     OSSL_DIGEST_NAME_SHA1 }, // Default
    { NID_sha256,   OSSL_DIGEST_NAME_SHA2_256 },
    { NID_sha384,   OSSL_DIGEST_NAME_SHA2_384 },
    { NID_sha512,   OSSL_DIGEST_NAME_SHA2_512 },
    { NID_sha3_256, OSSL_DIGEST_NAME_SHA3_256 },
    { NID_sha3_384, OSSL_DIGEST_NAME_SHA3_384 },
    { NID_sha3_512, OSSL_DIGEST_NAME_SHA3_512 } 
};

static int _cleanup_set_md_from_mdname(int ret, KeyIsoErrReason reason, EVP_MD *mdTmp) 
{
    if (ret != STATUS_OK) {
        KMPPerr(reason);

        if (mdTmp)
            EVP_MD_free(mdTmp);
    }

    return ret;
}
#define _CLEANUP_SET_MD_FROM_MDNAME(ret, reason) \
        _cleanup_set_md_from_mdname(ret, reason, mdTmp)

// Common for both RSA and ECC
int KeyIso_prov_set_md_from_mdname(OSSL_LIB_CTX *libCtx, const OSSL_PARAM *p, 
                                 const char* mdName, const char *propq, 
                                 EVP_MD **md, const OSSL_ITEM **mdInfo)
{
    EVP_MD *mdTmp = NULL;
    const OSSL_ITEM *mdInfoTmp = NULL;
    size_t supportedMdsCount = sizeof(g_keyIsoPovSupportedMds) / sizeof(OSSL_ITEM);

    if (!md || !mdInfo) {
        return _CLEANUP_SET_MD_FROM_MDNAME(STATUS_FAILED, KeyIsoErrReason_InvalidParams);
    }

    if (mdName == NULL) {
        if (p == NULL || !OSSL_PARAM_get_utf8_string_ptr(p, &mdName)) {
            KMPPerr(KeyIsoErrReason_FailedToGetParams);
            return STATUS_FAILED;
        }
    }

    // Fetch MD by Name
    mdTmp = EVP_MD_fetch(libCtx, mdName, propq);
    if (!mdTmp) {
        return _CLEANUP_SET_MD_FROM_MDNAME(STATUS_FAILED, KeyIsoErrReason_InvalidMsgDigest);
    }

    // Find if we support found MD
    for (size_t i = 0; i < supportedMdsCount; i++) {
        if (EVP_MD_is_a(mdTmp, g_keyIsoPovSupportedMds[i].ptr)) {
            mdInfoTmp = &g_keyIsoPovSupportedMds[i];
            break;
        }
    }

    // If Md was not found by name it's a failure.
    if (mdInfoTmp == NULL) {
        return _CLEANUP_SET_MD_FROM_MDNAME(STATUS_FAILED, KeyIsoErrReason_UnsupportedAlgorithm);
    }

    // Cleanup previous MD and update pointers.
    if (*md) {
        EVP_MD_free(*md);
    }

    *md = mdTmp;
    *mdInfo = mdInfoTmp;

    return _CLEANUP_SET_MD_FROM_MDNAME(STATUS_OK, KeyIsoErrReason_NoError);
}

// returns the PEM type based on the content of the buffer
static PemType _get_pem_type_from_buff(char *bioContent, unsigned int bioLength)
{
    if (bioContent == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return PemType_NotSupported;
    }

    unsigned int privateKeyHeaderLength = sizeof(KEYISO_PEM_HEADER_BEGINE_PKCS8_INFO) - 1;
    unsigned int encryptedPrivateKeyHeaderLength = sizeof(KEYISO_PEM_HEADER_BEGINE_PKCS8) - 1;

    if (bioLength >= privateKeyHeaderLength) {
        if (memcmp(bioContent, KEYISO_PEM_HEADER_BEGINE_PKCS8_INFO, privateKeyHeaderLength) == 0) {
            return PemType_PrivateKeyInfo;
        }
    }

    if (bioLength >= encryptedPrivateKeyHeaderLength) {
        if (memcmp(bioContent, KEYISO_PEM_HEADER_BEGINE_PKCS8, encryptedPrivateKeyHeaderLength) == 0) {
            return PemType_EncryptedPrivateKeyInfo;
        }
    }

    return PemType_NotSupported;
}

// Calculates the offset of a given header in a PEM file
static long _find_header_offset_bio(BIO *bio, const char *header) 
{
    char buffer[1024];
    long offset = 0;
    int bytesRead = 0;

    if (bio == NULL || header == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return INVALID_VALUE;
    }

    while ((bytesRead = BIO_gets(bio, buffer, sizeof(buffer))) > 0) {
        char *headerPos = strstr(buffer, header);
        if (headerPos != NULL) {
            // Calculate the exact position of the header within the buffer
            long headerOffset = headerPos - buffer;
            offset += headerOffset;
            // Reset the file pointer to the start of the file
            if (BIO_reset(bio) < 0) {
                KMPPerr(KeyIsoErrReason_OperationFailed);
            }
            return offset;
        }
        offset += bytesRead;
    }

    // Rewinds the file pointer to the start of the file
    if (BIO_reset(bio) < 0) {
        KMPPerr(KeyIsoErrReason_OperationFailed);
    }

    // Header not found
    KMPPerr(KeyIsoErrReason_OperationFailed);
    return INVALID_VALUE;
}

// Reads the PEM header and determines the type of PEM file
static PemType _get_type_from_header_file(BIO *in)
{
    if (in == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return PemType_NotSupported;
    }

    long pos = _find_header_offset_bio(in, KEYISO_PEM_HEADER_BEGIN);
    if (pos <= INVALID_VALUE) {
        // Not PEM format
        KMPPerr(KeyIsoErrReason_UnsupportedFormat);
        return PemType_NotSupported;
    }

    // If the header is found, check for the specific PEM type
    BIO_seek(in, pos);
    if (_find_header_offset_bio(in, KEYISO_PEM_HEADER_BEGINE_PKCS8) >= 0) {
        return PemType_EncryptedPrivateKeyInfo;
    }

    if (_find_header_offset_bio(in, KEYISO_PEM_HEADER_BEGINE_PKCS8_INFO) >= 0) {
        return PemType_PrivateKeyInfo;
    }

    // rewinds the file pointer to the start of the file
    if (BIO_reset(in) < 0) {
        KMPPerr(KeyIsoErrReason_OperationFailed);
    }

    // If no header is found, return UnsupportedFormat
    KMPPerr(KeyIsoErrReason_UnsupportedType);
    return PemType_NotSupported;
}

static long _find_header_offset_buff(char *buffer, const char *header) 
{
    if (buffer == NULL || header == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return INVALID_VALUE;
    }

    char *headerPos = strstr(buffer, header);
    return (headerPos != NULL) ? (headerPos - buffer) : INVALID_VALUE;
}

// Reads the content between two headers in a PEM file
static long _read_content_between_headers_bio_file(BIO *bio, const char *headerBegin, const char *headerEnd, unsigned char **data) 
{   
    if (bio == NULL || headerBegin == NULL || headerEnd == NULL || data == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return INVALID_VALUE;
    }
    *data = NULL;

    long offsetBegin = 0;
    long offsetEnd = 0;
    long offsetContent = 0;
    long contentLength = 0;
    unsigned char *content = NULL;

    // Find the offsets of the begin and end headers
    offsetBegin = _find_header_offset_bio(bio, headerBegin);
    if (offsetBegin < 0) {
        KMPPerr_para(KeyIsoErrReason_HeaderNotFound, "Header: %s", headerBegin);
        return INVALID_VALUE;
    }
    offsetEnd = _find_header_offset_bio(bio, headerEnd);
    if (offsetEnd < 0) {
        KMPPerr_para(KeyIsoErrReason_HeaderNotFound, "Header: %s", headerEnd);
        return INVALID_VALUE;
    }
    offsetContent = offsetBegin + strlen(headerBegin) + 1;
    
    // Calculate the length of the content between the headers
    contentLength = offsetEnd - offsetContent - 1;
    if (contentLength <= 0) {
        KMPPerr(KeyIsoErrReason_InvalidLength);
        return INVALID_VALUE;
    }

    // Allocate buffer to read the content
    content = (unsigned char *)KeyIso_zalloc(contentLength);
    if (content == NULL) {
        // Allocation failed
        return INVALID_VALUE;
    }

    // Seek to the content position and read the content
    BIO_seek(bio, offsetContent);
    int bytesRead = BIO_read(bio, content, contentLength);
    if (bytesRead <= 0) {
        KMPPerr(KeyIsoErrReason_OperationFailed);
        KeyIso_free(content);
        return INVALID_VALUE;
    }

    *data = content;
    return bytesRead;
}

static long _read_content_between_headers_bio_mem(char *buff, unsigned int buffLength, 
    const char *headerBegin, const char *headerEnd, unsigned char **data) 
{
    if (buff == NULL || headerBegin == NULL || headerEnd == NULL || data == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return INVALID_VALUE; 
    }
    *data = NULL;

    long offsetBegin = 0;
    long offsetEnd = 0;
    long offsetContent = 0;
    long contentLength = 0;
    unsigned char *content = NULL;

    // Find the offsets of the begin and end headers
    if (buffLength < strlen(headerBegin) + strlen(headerEnd)) {
        // Buffer is too small to contain both headers
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return INVALID_VALUE;
    }

    offsetBegin = _find_header_offset_buff(buff, headerBegin);
    if (offsetBegin < 0) {
        KMPPerr_para(KeyIsoErrReason_HeaderNotFound, "Header: %s", headerBegin);
        return INVALID_VALUE;
    }
    offsetEnd = _find_header_offset_buff(buff, headerEnd);
    if (offsetEnd < 0) {
        KMPPerr_para(KeyIsoErrReason_HeaderNotFound, "Header: %s", headerEnd);
        return INVALID_VALUE;
    }
    offsetContent = offsetBegin + strlen(headerBegin) + 1;
    
    // Calculate the length of the content between the headers
    contentLength = offsetEnd - offsetContent - 1;
    if (contentLength <= 0 || contentLength > buffLength) {
        KMPPerr(KeyIsoErrReason_InvalidLength);
        return INVALID_VALUE;
    }

    // Allocate buffer to read the content
    content = (unsigned char *)KeyIso_zalloc(contentLength);
    if (content == NULL) {
        // Allocation failed
        return INVALID_VALUE;
    }
    
    memcpy(content, buff + offsetContent, contentLength);
    *data = content;

    return contentLength;
}

// Reads the content between two headers in a PEM file, either from a BIO or a buffer
long KeyIso_read_content_between_headers(BIO *bio, char *buff, long buffLength, 
    const char *headerBegin, const char *headerEnd, unsigned char **data) 
{
    long length = INVALID_VALUE;
    if (buff != NULL && buffLength > 0) {
        // If the buffer is not NULL, read from the buffer, assuming it's a memory BIO
        length = _read_content_between_headers_bio_mem(buff, (unsigned int)buffLength, headerBegin, headerEnd, data);
    } else if (bio != NULL) {
        // If the BIO is not NULL, read from the BIO file
        length = _read_content_between_headers_bio_file(bio, headerBegin, headerEnd, data);
        // reset BIO to the start of the file
        if (BIO_reset(bio) < 0) {
            KMPPerr(KeyIsoErrReason_OperationFailed);
        }
    } else {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return INVALID_VALUE;
    }
    return length;
}

// Returns the PEM type based on the content of the BIO
PemType KeyIso_get_type_from_bio_buff(BIO *bio, char **data, long *len)
{
    if (bio == NULL || data == NULL || len == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return PemType_NotSupported;
    }
    *data = NULL;
    *len = 0;
    
    PemType type = PemType_NotSupported;
    *len = BIO_get_mem_data(bio, data);

    if (*data != NULL && *len > 0) {
        // Read the content from the memory buffer
        type = _get_pem_type_from_buff(*data, (unsigned int)*len);
    } else {
        // Read the content from the file BIO
        type = _get_type_from_header_file(bio);
    }
    
    return type;
}

// creates a new EVP_PKEY containing the public params only
EVP_PKEY *KeyIso_new_pubKey_from_privKey(OSSL_LIB_CTX *libCtx, EVP_PKEY *pkey)
{
    if (pkey == NULL) {
        KMPPerr(KeyIsoErrReason_InvalidParams);
        return NULL;
    }

    const char *keyTypeName = NULL;
    OSSL_PARAM *publicParams = NULL;
    EVP_PKEY *pubKey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    // Validate the type of the key
    keyTypeName = EVP_PKEY_get0_type_name(pkey);    // get0 doesn't up_ref
    if (keyTypeName == NULL) {
        KMPPerr(KeyIsoErrReason_FailedToGetKeyType);
        return NULL;
    }

    if (strncmp(keyTypeName, KEYISO_NAME_RSA, strlen(KEYISO_NAME_RSA)) != 0 && 
        strncmp(keyTypeName, KEYISO_NAME_RSA_PSS, strlen(KEYISO_NAME_RSA_PSS)) != 0) {
        KMPPerr_para(KeyIsoErrReason_UnsupportedType, "key type: %s", keyTypeName);
        return NULL;
    }

    if (EVP_PKEY_todata(pkey, EVP_PKEY_PUBLIC_KEY, &publicParams) <= 0) {
        KMPPerr(KeyIsoErrReason_FailedToGetParams);
        return NULL;
    }

    ctx = EVP_PKEY_CTX_new_from_name(libCtx, keyTypeName, KEYISO_OSSL_DEFAULT_PROV_PROPQ);
    if (ctx == NULL || publicParams == NULL ||
        EVP_PKEY_fromdata_init(ctx) <= 0 || 
        EVP_PKEY_fromdata(ctx, &pubKey, EVP_PKEY_PUBLIC_KEY, publicParams) <= 0) {
            KMPPerr(KeyIsoErrReason_FailedToGetPubKey);
    }

    OSSL_PARAM_free(publicParams);
    EVP_PKEY_CTX_free(ctx);

    return pubKey;
}

int KeyIso_conf_get(CONF **conf, const char *dns1, const char *dns2)
{
    if (*conf == NULL) {
        if (!KeyIso_conf_load(NULL, certConfStr, conf)) { 
            KEYISOP_trace_log_openssl_error(NULL, 0, KEYISOP_CREATE_SELF_SIGN_TITLE, "KeyIso_conf_get");
            return STATUS_FAILED;
        }
    }
    
    if ((dns1 != NULL || dns2 != NULL) && 
        !KeyIso_edit_alt_names_section(NULL, *conf, 
                                      dns1 ? dns1 : KEYISO_ENCODER_CERT_DNS_NAME, 
                                      dns2 ? dns2 : KEYISO_ENCODER_CERT_DNS_NAME)) {
        KEYISOP_trace_log_openssl_error(NULL, 0, KEYISOP_CREATE_SELF_SIGN_TITLE, "KeyIso_edit_alt_names_section");
        return STATUS_FAILED;
    }
    
    return STATUS_OK;
}
