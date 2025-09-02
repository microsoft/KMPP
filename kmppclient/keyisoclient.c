/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <string.h>
#include <stdbool.h>

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/engine.h>
#include <openssl/buffer.h>

#include "keyisoclientinternal.h"
#include "keyisoclientmsghandler.h"
#include "keyisoipccommands.h"
#include "keyisopfxclientinternal.h"
#include "keyisosymmetrickeyclientinternal.h"
#include "keyisocertinternal.h"
#include "keyisolog.h"
#include "keyisotelemetry.h"
#include "keyisoctrl.h"
#include "keyisoipccommands.h"

#include "keyiso.h"
#include "keyisoutils.h"

#include "keyisoserviceapiossl.h" // For inproc
#include "keyisoserviceapi.h"     // For inproc

#include "kmppgdbuspfxclient.h"

#define FIRST_BYTE 1
#define KEYSISO_KEYSINUSE_SIGN_OPERATION 0
#define KEYSISO_KEYSINUSE_DECRYPT_OPERATION 1

#ifdef KMPP_GENERAL_PURPOSE_TARGET
#define KMPP_MIN_SERVICE_VERSION KEYISOP_VERSION_3
#else
#define KMPP_MIN_SERVICE_VERSION KEYISOP_VERSION_1
#endif

extern CLIENT_MSG_HANDLER_FUNCTIONS_TABLE_ST g_msgHandlerImplementation;
extern KEYISO_CLIENT_CONFIG_ST g_config;
extern KEYISO_KEYSINUSE_ST g_keysinuse;

// Format legacy key ID: <Salt> ":" <Base64 PFX>
static int _format_legacy_engine_key_id(
    const uuid_t correlationId,
    int keyLength,
    const unsigned char *keyBytes,
    const char *salt,
    char **keyId) // KeyIso_free()
{
    const char *title = KEYISOP_HELPER_PFX_TITLE;
    int ret = STATUS_FAILED;
    unsigned int base64Length = KEYISOP_BASE64_ENCODE_LENGTH(keyLength); // includes NULL terminator

    // Validate salt
    if (salt == NULL || *salt == '\0') {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid parameter", "salt is required for legacy format");
        return ret;
    }
    size_t saltLength = strnlen(salt, KEYISO_SECRET_SALT_STR_BASE64_LEGACY_LEN);
    if (saltLength != KEYISO_SECRET_SALT_STR_BASE64_LEGACY_LEN - 1) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "Invalid parameter", "salt is invalid", "size:%zu, expected:%d",
                                    saltLength, KEYISO_SECRET_SALT_STR_BASE64_LEGACY_LEN-1);
        return ret;
    }

    size_t idLength = saltLength + 1 + base64Length; // salt + ':' + base64PFX + null terminator
    unsigned int encodeLength;

    char *id = (char*)KeyIso_zalloc(idLength);
    if (id == NULL) {
        return ret;    
    }

    // Copy salt
    memcpy(id, salt, saltLength);
    
    // Add delimiter
    id[saltLength] = CLIENT_DATA_DELIMITER;
    
    // Encode keyBytes to base64 and append
    encodeLength = EVP_EncodeBlock((unsigned char*)(id + saltLength + 1), keyBytes, keyLength);
    if (encodeLength != base64Length - 1) {
        KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, "EVP_EncodeBlock",
                                             "length: %d expected: %d", encodeLength, base64Length - 1);

        KeyIso_clear_free(id, idLength);
        return ret;    
    }

    *keyId = id;
    ret = STATUS_OK;
    return ret;    
}

// Format:         'n' <Base64 ExtraDataBuffer> ':' <Base64 PFX>
// Legacy Format:  <Salt> ":" <Base64 PFX> , salt first byte is '0' or 't'
static int _format_engine_key_id(
    const uuid_t correlationId,
    int keyLength,
    const unsigned char *keyBytes,
    const char *clientData,  // Base64 encoded string
    char **keyId)           // KeyIso_free()
{
    const char *title = KEYISOP_HELPER_PFX_TITLE;
    int ret = STATUS_FAILED;

    if (keyBytes == NULL || keyId == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid parameter", "cant be null or empty");
        return ret;
    }

    if (keyLength <= 0) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "Invalid parameter", "keyLength is invalid", "size:%d", keyLength);
        return ret;
    }


    size_t idLength = 0;
    unsigned int encodeLength;
    uint32_t clientDataBuffLength = 0;
    char *id = NULL; // KeyIso_free()
    unsigned int base64Length = KEYISOP_BASE64_ENCODE_LENGTH(keyLength); // includes NULL terminator
    ERR_clear_error();

    // Format as legacy when legacyMode is true in global config
    if (g_config.isLegacyMode) {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "PKCS12 backward-compatibility");        
        return _format_legacy_engine_key_id(correlationId, keyLength, keyBytes, clientData, keyId);
    }

    if (clientData != NULL) {
        int maxClientDataLength = MAX_CLIENT_DATA_BASE64_LENGTH + 1;
        clientDataBuffLength = strnlen(clientData, maxClientDataLength);
        if (clientDataBuffLength == 0 || clientDataBuffLength == maxClientDataLength) {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "Invalid parameter", "clientData is invalid", "maxLength:%d , length:%d", maxClientDataLength, clientDataBuffLength);
            return ret;
        }
    }

    // Calculate the length of the keyid
    // The new version keyid is:   n<base64ExtraDataBuff>:<base64Pfx>
    // We add 2 to clientDataBuffLength, one for the version char and one for the ':' delimiter
    idLength = clientDataBuffLength + base64Length + 2;
  
    // Allocate memory for id
    id = (char*)KeyIso_zalloc(idLength);
    if (id == NULL) {
        // Allocation failed
        return ret;
    }

    // Format id
    id[0] = VERSION_CHAR; // First byte is 'n' for new versions 0 for legacy code , 't' for legacy testing 
                          // The first byte of the salt will still be 0 or 't' in new version , it will just be inside the extra data struct
    unsigned int offset = 1;
    memcpy((id + offset), clientData, clientDataBuffLength);
    offset += clientDataBuffLength; 
    id[offset] = CLIENT_DATA_DELIMITER;
    offset += 1;

    // Encode keyBytes to base64 and append to id
    encodeLength = EVP_EncodeBlock((unsigned char*)(id + offset), keyBytes, keyLength);
    if (encodeLength != base64Length - 1) {
        KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, "EVP_EncodeBlock", "length: %d expected: %d", encodeLength, base64Length - 1);
        KeyIso_clear_free(id, idLength);
        return ret;
    }

    // Set output parameter and return success
    *keyId = id;
    return STATUS_OK;
}

static bool _is_service_supporting_p8_keys(const uuid_t correlationId)
{
    // This function is used to check if the service supports PKCS8 keys, it retrieves the current service version to do so
    int p8Compatible = KeyIso_validate_current_service_compatibility_mode(correlationId, KeyisoCompatibilityMode_pkcs8);
    return p8Compatible == PKCS8_COMPATIBLE;
}

static bool _should_use_legacy_API(const uuid_t correlationId)
{
    bool shouldUseLegacyAPI = (g_config.isLegacyMode || !_is_service_supporting_p8_keys(correlationId));
    return shouldUseLegacyAPI;
}

// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to import PFX.
int KeyIso_import_pfx(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *password,             // Optional
    int *verifyChainError,
    int *pfxLength,
    unsigned char **pfxBytes,         // KeyIso_free()
    char **outClientData)            // Base64 encoded string
{
    int ret = 0;
    const char *title = KEYISOP_IMPORT_PFX_TITLE;

    // Check that pfx size doesn't exceed the maximum
    if (inPfxLength > KMPP_MAX_MESSAGE_SIZE) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, NULL, "Pfx file is too big", "length: %d", inPfxLength);
        return ret;
    }
    
    // None p8Compatible - this is a backward compatibility code
    if (_should_use_legacy_API(correlationId)) {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "PKCS12 backward-compatibility");
        ret = KeyIso_CLIENT_import_pfx(
            correlationId,
            keyisoFlags,
            inPfxLength,
            inPfxBytes,
            password,
            verifyChainError,
            pfxLength,
            pfxBytes,
            outClientData);
        return ret;
    } 

    ret = KeyIso_CLIENT_import_private_key_from_pfx(
        correlationId,
        keyisoFlags,
        inPfxLength,
        inPfxBytes,
        password,
        verifyChainError,
        pfxLength,
        pfxBytes,               
        outClientData);
    
    // Added metric to get an average size of PFXs before and after their provisioning to make "KMPP_MAX_MESSAGE_SIZE" more accurate 
    KEYISOP_trace_metric_para(correlationId, 0, g_config.solutionType, (int)g_keysinuse.isLibraryLoaded, title, NULL, "PFX size %d, encrypted key size: %d", inPfxLength, *pfxLength);

    return ret;
}

// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to import PFX.
int KeyIso_import_pfx_to_key_id(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *password,             // Optional
    int *verifyChainError,
    char **keyId)                    // KeyIso_clear_free_string()
{
    int ret = 0;
    int outPfxLength = 0;
    unsigned char *outPfxBytes = NULL;  // KeyIso_free()
    char *clientData = NULL;            // Base64 encoded string
    *keyId = NULL;

    ret = KeyIso_import_pfx(
        correlationId,
        keyisoFlags,
        inPfxLength,
        inPfxBytes,
        password,
        verifyChainError,
        &outPfxLength,
        &outPfxBytes,
        &clientData);
    if (ret != 0) {
        if (!KeyIso_format_pfx_engine_key_id(
                correlationId,
                outPfxLength,
                outPfxBytes,
                clientData,
                keyId)) {
            ret = 0;
        }
    }

    KeyIso_free(outPfxBytes);
    KeyIso_clear_free_string(clientData);
    return ret;
}

// Return:
//  STATUS_OK - Success
//  STATUS_FAILED - Error, unable to import symmetric key.
int KeyIso_import_symmetric_key_to_key_id(
    const uuid_t correlationId,
    const int inKeyLength,
    const unsigned char *inKeyBytes,
    const unsigned char *inImportKeyId, // Unique identifier to the imported key
    unsigned char **keyId)              // KeyIso_free()
{
    int status = STATUS_OK;
    unsigned int outKeyLength = 0;
    unsigned char *outKeyBytes = NULL;  // KeyIso_free()
    char *clientData = NULL;            // Base64 encoded string

    *keyId = NULL;
 
    unsigned char internalImportKeyId[KMPP_AES_256_KEY_SIZE] = {0};
 
    if (inImportKeyId == NULL || memcmp(inImportKeyId, "", FIRST_BYTE) == 0) {
        KeyIso_rand_bytes(internalImportKeyId, KMPP_AES_256_KEY_SIZE);
    } else {
        memcpy(internalImportKeyId, inImportKeyId, KMPP_AES_256_KEY_SIZE);
    }

    status = KeyIso_CLIENT_import_symmetric_key_new(
            correlationId,
            inKeyLength,
            inKeyBytes,
            internalImportKeyId,
            &outKeyLength,
            &outKeyBytes,
            &clientData);
    if (status != STATUS_FAILED) {
        status = _format_engine_key_id(
                    correlationId,
                    outKeyLength,
                    outKeyBytes,
                    clientData,
                    (char **)keyId);
    }

    KeyIso_free(outKeyBytes);
    KeyIso_clear_free_string(clientData);
    clientData = NULL;
    return status;
}

// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to import PFX.
int KeyIso_build_cert_chain_from_pfx(
    const uuid_t correlationId,
    int keyisoFlags,
    int pfxLength,
    const unsigned char *pfxBytes,
    int *verifyChainError,
    int *pemCertLength,              // Excludes NULL terminator
    char **pemCert)                  // KeyIso_free()                   
{
    int ret = 0;
    int chainRet = 0;
    uuid_t randId;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    STACK_OF(X509) *chain = NULL;
    KEYISO_VERIFY_CERT_CTX *ctx = NULL;    // KeyIso_free_verify_cert_ctx()

    *verifyChainError = 0;
    *pemCertLength = 0;
    *pemCert = NULL;

    if (correlationId == NULL) {
        KeyIso_rand_bytes(randId, sizeof(randId));
        correlationId = randId;
    }

    ERR_clear_error();

    if (!KeyIsoP_load_pfx_certs(
            correlationId,
            pfxLength,
            pfxBytes,
            &cert,
            &ca)) {
        goto end;
    }

    ctx = KeyIso_create_verify_cert_ctx(correlationId);
    if (ctx == NULL) {
        goto end;
    }

    chainRet = KeyIso_verify_cert2(
        ctx,
        keyisoFlags | KEYISO_IGNORE_DEPTH_ZERO_SELF_SIGNED_ERROR_FLAG,
        cert,
        ca,
        verifyChainError,
        &chain);
    if (chainRet == 0) {
        goto end;
    }

    if (!KeyIsoP_pem_from_certs(
            correlationId,
            NULL,                   // X509 *cert
            chain,
            pemCertLength,
            pemCert)) {
        goto end;
    }

    ret = chainRet;

end:
    X509_free(cert);
    sk_X509_pop_free(ca, X509_free);
    sk_X509_pop_free(chain, X509_free);
    KeyIso_free_verify_cert_ctx(ctx);
    return ret;
}

// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to import PFX.
int KeyIso_build_cert_chain_from_key_id(
    const uuid_t correlationId,
    int keyisoFlags,
    const char *keyId,
    int *verifyChainError,
    int *pemCertLength,              // Excludes NULL terminator
    char **pemCert)                  // KeyIso_free()                   
{
    int ret = 0;
    int pfxLength = 0;
    unsigned char *pfxBytes = NULL;     // KeyIso_free()
    char *clientData = NULL;            // Base64 encoded string

    *verifyChainError = 0;
    *pemCertLength = 0;
    *pemCert = NULL;

    ret = KeyIso_parse_pfx_engine_key_id(
        correlationId,
        keyId,
        &pfxLength,
        &pfxBytes,
        &clientData);
    if (ret) {
        ret = KeyIso_build_cert_chain_from_pfx(
            correlationId,
            keyisoFlags,
            pfxLength,
            pfxBytes,
            verifyChainError,
            pemCertLength,                 // excludes NULL terminator
            pemCert);
    }

    KeyIso_free(pfxBytes);
    KeyIso_clear_free_string(clientData);

    return ret;
}

// Returns 1 for success and 0 for an error
int KeyIso_create_self_sign_pfx(
    const uuid_t correlationId,
    int keyisoFlags,
    const char *confStr,
    int *pfxLength,
    unsigned char **pfxBytes,        // KeyIso_free()
    char **outClientData)            // Base64 encoded string
{
    int ret = 0;
    uuid_t randId;
    BIO *fileBio = NULL;

    if (correlationId == NULL) {
        KeyIso_rand_bytes(randId, sizeof(randId));
        correlationId = randId;
    }

    if (strncmp(confStr, "file:", 5) == 0) {
        char *fileString = NULL;        // don't free
        fileBio = KeyIsoP_read_file_string(correlationId, confStr + 5, 0,  &fileString);
        if (fileBio == NULL) {
            KEYISOP_trace_log(correlationId, 0, KEYISOP_CREATE_SELF_SIGN_TITLE, "Failed to read file");
            return STATUS_FAILED;
        }
        confStr = fileString;
    }
    
    if (_should_use_legacy_API(correlationId)) {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_CREATE_SELF_SIGN_TITLE, "PKCS12 backward-compatibility");
        ret = (KeyIso_CLIENT_self_sign_pfx(
                correlationId,
                keyisoFlags,
                confStr,
                pfxLength,
                pfxBytes,
                outClientData) ? STATUS_OK : STATUS_FAILED);
        BIO_free(fileBio);
        return ret;
    }
    ret = KeyIso_CLIENT_create_self_sign_pfx_p8(
        correlationId,
        keyisoFlags,
        confStr,
        pfxLength,
        pfxBytes,
        outClientData);

    BIO_free(fileBio);
    return ret;
}

// Returns 1 for success and 0 for an error
int KeyIso_create_self_sign_pfx_to_key_id(
    const uuid_t correlationId,
    int keyisoFlags,
    const char *confStr,
    char **keyId)                  // KeyIso_clear_free_string()
{
    int ret = 0;
    int pfxLength = 0;
    unsigned char *pfxBytes = NULL;     // KeyIso_free()
    char *clientData = NULL;            // Base64 encoded string

    *keyId = NULL;

    if (KeyIso_create_self_sign_pfx(
            correlationId,
            keyisoFlags,
            confStr,
            &pfxLength,
            &pfxBytes,
            &clientData) != STATUS_OK) {
                goto end;
    }

    if (!KeyIso_format_pfx_engine_key_id(
            correlationId,
            pfxLength,
            pfxBytes,
            clientData,
            keyId)) {
        goto end;
    }

    ret = 1;

end:
    KeyIso_free(pfxBytes);
    KeyIso_clear_free_string(clientData);

    return ret;
}

// Returns 1 for success and 0 for an error
// The pemCert consists of the end certificate followed by
// 1 or more CA certificates
int KeyIso_replace_pfx_certs(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *inClientData,
    int pemCertLength,
    const unsigned char *pemCertBytes,
    int *outPfxLength,
    unsigned char **outPfxBytes,        // KeyIso_clear_free()
    char  **outClientData)            // Base64 encoded string
{
    int ret = 0;

    *outClientData = NULL;
    
    // check for backward compatibility code
    if (_should_use_legacy_API(correlationId)) {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_HELPER_PFX_TITLE, "PKCS12 backward-compatibility");
        ret = KeyIso_CLIENT_replace_pfx_certs(
            correlationId,
            keyisoFlags,
            inPfxLength,
            inPfxBytes,
            inClientData,
            pemCertLength,
            pemCertBytes,
            outPfxLength,
            outPfxBytes,
            outClientData);
        return ret;
    }

    ret = KeyIso_replace_pfx_certs_p8(
        correlationId,
        keyisoFlags,
        inPfxLength,
        inPfxBytes,
        pemCertLength,
        pemCertBytes,
        outPfxLength,
        outPfxBytes);
    if (ret == STATUS_OK) {
        *outClientData = (char *) KeyIso_zalloc(strlen(inClientData) + 1);
        if (*outClientData != NULL)
            strcpy(*outClientData, inClientData);
    }

    return ret;
}

int KeyIso_replace_key_id_certs(
    const uuid_t correlationId,
    int keyisoFlags,
    const char *inKeyId,
    int pemCertLength,
    const unsigned char *pemCertBytes,
    char **outKeyId)                     // KeyIso_free()
{
    int ret = 0;
    int inPfxLength = 0;
    unsigned char *inPfxBytes = NULL;   // KeyIso_free()
    char *inClientData = NULL;                // KeyIso_clear_free_string()
    int outPfxLength = 0;
    unsigned char *outPfxBytes = NULL;  // KeyIso_free()
    char *outClientData = NULL;            // Base64 encoded string

    *outKeyId = NULL;
    if (!KeyIso_is_legacy(inKeyId) && _should_use_legacy_API(correlationId)) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_HELPER_PFX_TITLE, "Invalid keyId", "KeyId is in the new format but the service does not support it");
        goto end;
    }

    if (!KeyIso_parse_pfx_engine_key_id(
            correlationId,
            inKeyId,
            &inPfxLength,
            &inPfxBytes,
            &inClientData)) {
        goto end;
    }

    if (!KeyIso_replace_pfx_certs(
            correlationId,
            keyisoFlags,
            inPfxLength,
            inPfxBytes,
            inClientData,
            pemCertLength,
            pemCertBytes,
            &outPfxLength,
            &outPfxBytes,
            &outClientData)) {
        goto end;
    }

    if (!KeyIso_format_pfx_engine_key_id(
            correlationId,
            outPfxLength,
            outPfxBytes,
            outClientData,
            outKeyId)) {
        goto end;
    }

    ret = 1;

end:
    KeyIso_free(inPfxBytes);
    KeyIso_clear_free_string(inClientData);
    KeyIso_free(outPfxBytes);
    KeyIso_clear_free_string(outClientData);

    return ret;
}

int KeyIso_replace_key_id_certs2(
    const uuid_t correlationId,
    int keyisoFlags,
    const char *inKeyId,
    X509 *cert,
    STACK_OF(X509) *ca,                 // Optional
    char **outKeyId)                    // KeyIso_free()
{
    int ret = 0;
    int pemCertLength = 0;
    char *pemCert = NULL;    // KeyIso_free()

    *outKeyId = NULL;

    if (!KeyIsoP_pem_from_certs(
            correlationId,
            cert,
            ca,
            &pemCertLength,
            &pemCert)) {
        goto end;
    }

    if (!KeyIso_replace_key_id_certs(
            correlationId,
            keyisoFlags,
            inKeyId,
            pemCertLength,
            (unsigned char *) pemCert,
            outKeyId)) {                  // KeyIso_free()
        goto end;
    }

    ret = 1;

end:
    KeyIso_free(pemCert);
    return ret;
}

// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to import PFX.
int KeyIso_import_pfx_from_pem_to_key_id(
    const uuid_t correlationId,
    int keyisoFlags,
    int inKeyLength,
    const unsigned char *inKeyBytes,
    int inCertLength,
    const unsigned char *inCertBytes,
    const char *password,             // Optional
    int *verifyChainError,
    char **keyId)                     // KeyIso_free()
{
    int ret = 0;
    int outPfxLength = 0;
    unsigned char *outPfxBytes = NULL;  // KeyIso_free()
    char *clientData = NULL;                  // KeyIso_clear_free_string()
    
    *keyId = NULL;
    
    ret = KeyIso_import_pfx_from_pem(
        correlationId,
        keyisoFlags,
        inKeyLength,
        inKeyBytes,
        inCertLength,
        inCertBytes,
        password,             // Optional
        verifyChainError,
        &outPfxLength,
        &outPfxBytes,         // KeyIso_free()
        &clientData);
    if (ret != 0) {
        if (!KeyIso_format_pfx_engine_key_id(
                correlationId,
                outPfxLength,
                outPfxBytes,
                clientData,
                keyId)) {
            ret = 0;
        }
    }

    KeyIso_free(outPfxBytes);
    KeyIso_clear_free_string(clientData);
    return ret;
}

static int _create_pfx_from_pem(
    const uuid_t correlationId,
    int keyisoFlags,
    int inKeyLength,
    const unsigned char *inKeyBytes,  // Optional
    int inCertLength,
    const unsigned char *inCertBytes,
    const char *password,             // Optional
    int *verifyChainError,
    int *pfxLength,
    unsigned char **pfxBytes,
    BIO **pfxBio)                     // KeyIso_free()
{
    const char *title = KEYISOP_CREATE_PFX_TITLE;
    const char *loc = "";
    int ret = 0;
    int keyLength;
    const unsigned char *keyBytes = NULL;
    BIO *inKeyBio = NULL;
    BIO *inCertBio = NULL;
    EVP_PKEY *key = NULL;
    X509 *cert = NULL;
    STACK_OF(X509)* ca = NULL;

    *pfxLength = 0;
    *pfxBio = NULL;
    
    // We assume that if there is no separated buffer for the private key,
    // it will be included in the buffer of the certificates.
    if (inKeyBytes != NULL && inKeyLength > 0) {
        keyBytes = inKeyBytes;
        keyLength = inKeyLength;
    } else {
        keyBytes = inCertBytes;
        keyLength = inCertLength;
    }
    inKeyBio = BIO_new_mem_buf(keyBytes, keyLength);
    if (inKeyBio == NULL) {
        loc = "BIO_new_mem_buf_inKeyBio";
        goto openSslErr;
    }
    key = PEM_read_bio_PrivateKey(inKeyBio, NULL, NULL, NULL);
    if (key == NULL) {
        KEYISOP_trace_log(correlationId, 0, title, "PEM_read_bio_PrivateKey");
    }

    // if key is still empty (we failed to read a PKCS8 private key from bio),
    // we will try to read a PKCS1 private key)
    if (!KeyIso_load_pem_cert(
            correlationId,
            inCertLength,
            inCertBytes,
            &key,     // pkey
            &cert,
            &ca)) {
        goto end;
    }

    if (key == NULL) {
        KEYISOP_trace_log(correlationId, 0, title, "Failed to read private key");
        goto end;
    }

    // Create a temporary PFX to be imported
    *pfxBio = KeyIsoP_create_pfx(
        correlationId,
        key,
        cert,
        ca,
        password,
        pfxLength,
        pfxBytes);           // Don't free
    if (*pfxBio == NULL) {
        goto end;
    }

    ret = 1;

end:
    BIO_free(inKeyBio);
    BIO_free(inCertBio);
    EVP_PKEY_free(key);
    X509_free(cert);
    sk_X509_pop_free(ca, X509_free);

    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;

}

// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to import PFX.
int KeyIso_import_pfx_from_pem(
    const uuid_t correlationId,
    int keyisoFlags,
    int inKeyLength,
    const unsigned char *inKeyBytes,
    int inCertLength,
    const unsigned char *inCertBytes,
    const char *password,             // Optional
    int *verifyChainError,
    int *outPfxLength,
    unsigned char **outPfxBytes,      // KeyIso_free()
    char **clientData)
{
    int ret = 0;
    int pfxLength = 0;
    unsigned char *pfxBytes = NULL;
    BIO *pfxBio = NULL;

    ret = _create_pfx_from_pem (
        correlationId,
        keyisoFlags,
        inKeyLength,
        inKeyBytes,              // Optional
        inCertLength,
        inCertBytes,
        password,                // Optional
        verifyChainError,
        &pfxLength,
        &pfxBytes,
        &pfxBio);
    if (ret != 0) {
        ret = KeyIso_import_pfx(
            correlationId,
            keyisoFlags,
            pfxLength,
            pfxBytes,
            password,             // Optional
            verifyChainError,
            outPfxLength,
            outPfxBytes,         // KeyIso_free()
            clientData);
    }

    BIO_free(pfxBio);
    return ret;
}

static void _log_result(const uuid_t correlationId, const char *title, int ret)
{
    if (ret > 0) {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete - Success");
    } else {
        KEYISOP_trace_log_error(correlationId, 0, title, "Complete", "Failed");
    }
}

static bool _is_valid_key_context(const KEYISO_KEY_CTX *keyCtx, const char *title)
{
    if (keyCtx == NULL) {
        KEYISOP_trace_log_error(NULL, 0, title, "Complete - Failed", "no key context");
        return false;
    }
    return true;
}

static int _handle_non_p8_inproc_operation(KEYISO_KEY_CTX *keyCtx, const char* title, int operation, int flen, const unsigned char *from, int tlen, unsigned char *to, int padding)
{
    switch (operation) {
        case KEYISO_IPC_RSA_PRIV_ENCRYPT:
            return KeyIso_SERVER_rsa_private_encrypt_ossl(keyCtx->correlationId, keyCtx->pkey, flen, from, tlen, to, padding);
        case KEYISO_IPC_RSA_PRIV_DECRYPT:
            return KeyIso_SERVER_rsa_private_decrypt_ossl(keyCtx->correlationId, keyCtx->pkey, flen, from, tlen, to, padding);
        case KEYISO_IPC_RSA_SIGN:
            return KeyIso_SERVER_rsa_sign_ossl(keyCtx->correlationId, keyCtx->pkey, flen, from, tlen, to, padding);
        case KEYISO_IPC_PKEY_SIGN:
            return KeyIso_SERVER_pkey_rsa_sign_ossl(keyCtx->correlationId, keyCtx->pkey, flen, from, tlen, to, padding);
        default:
            KEYISOP_trace_log_error_para(keyCtx->correlationId, 0, title, "Invalid operation", "error", "operation:%d", operation);
            return -1;
    }
}

static int _handle_non_p8_compatible_rsa_key(KEYISO_KEY_CTX *keyCtx, int operation, int flen, const unsigned char *from, int tlen, unsigned char *to, int padding)
{
    const char *title = "RSA";
    int ret = -1;
    if (!_is_valid_key_context(keyCtx, title)) {
        return ret;
    }

    if (KEYISOP_inProc) {
        KEYISOP_trace_log(keyCtx->correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "NonP8 - InProc");
        ret = _handle_non_p8_inproc_operation(keyCtx, title, operation, flen, from, tlen, to, padding);
    } else {
        KEYISOP_trace_log(keyCtx->correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "NonP8 - Gdbus");
        ret = KMPP_GDBUS_CLIENT_rsa_private_encrypt_decrypt(keyCtx, operation, flen, from, tlen, to, padding);
    }

    return ret;
}

//
//     Key isolation client interface
//
// Helper function to handle RSA operations
static int _handle_rsa_crypto_operation(
    KEYISO_KEY_CTX *keyCtx,
    int operation,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding,
    int labelLen,
    const char *title)
{
    int ret = -1;

    KEYISOP_trace_log_para(keyCtx->correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Start", "Operation:%d", operation);
    ERR_clear_error();
    if (!_is_valid_key_context(keyCtx, title))
        return ret;

    if (!keyCtx->isP8Key) {
        // The encrypted key is asn1(pkcs#12) encoded key
        ret = _handle_non_p8_compatible_rsa_key(keyCtx, operation, flen, from, tlen, to, padding);
    } else {
        // The encrypted key is a p8 key. Same API call regardless if inProc or not         
        ret = g_msgHandlerImplementation.rsa_private_encrypt_decrypt(keyCtx, operation, flen, from, tlen, to, padding, labelLen);
    }

    _log_result(keyCtx->correlationId, title, ret);
    return ret;
}

// Wrapper functions for specific RSA operations
int KeyIso_CLIENT_rsa_private_encrypt(
    KEYISO_KEY_CTX *keyCtx,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding)
{
    if (g_keysinuse.isLibraryLoaded && keyCtx) {
        g_keysinuse.on_use_func(keyCtx->keysInUseCtx, KEYSISO_KEYSINUSE_SIGN_OPERATION);
    }
    
    return _handle_rsa_crypto_operation(keyCtx, KEYISO_IPC_RSA_PRIV_ENCRYPT, flen, from, tlen, to, padding, 0, KEYISOP_RSA_ENCRYPT_TITLE);
}

int KeyIso_CLIENT_rsa_private_decrypt(
    KEYISO_KEY_CTX *keyCtx,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding,
    int labelLen)
{
    if (g_keysinuse.isLibraryLoaded && keyCtx) {
        g_keysinuse.on_use_func(keyCtx->keysInUseCtx, KEYSISO_KEYSINUSE_DECRYPT_OPERATION);
    }
    
    return _handle_rsa_crypto_operation(keyCtx, KEYISO_IPC_RSA_PRIV_DECRYPT, flen, from, tlen, to, padding, labelLen, KEYISOP_RSA_DECRYPT_TITLE);
}

int KeyIso_CLIENT_rsa_sign(
    KEYISO_KEY_CTX *keyCtx,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding)
{
    if (g_keysinuse.isLibraryLoaded && keyCtx) {
        g_keysinuse.on_use_func(keyCtx->keysInUseCtx, KEYSISO_KEYSINUSE_SIGN_OPERATION);
    }
    
    return _handle_rsa_crypto_operation(keyCtx, KEYISO_IPC_RSA_SIGN, flen, from, tlen, to, padding, 0, KEYISOP_RSA_SIGN_TITLE);
}

int KeyIso_CLIENT_pkey_rsa_sign(
    KEYISO_KEY_CTX *keyCtx,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding)
{
    if (g_keysinuse.isLibraryLoaded && keyCtx) {
        g_keysinuse.on_use_func(keyCtx->keysInUseCtx, KEYSISO_KEYSINUSE_SIGN_OPERATION);
    }
    
    return _handle_rsa_crypto_operation(keyCtx, KEYISO_IPC_PKEY_SIGN, flen, from, tlen, to, padding, 0, KEYISOP_PKEY_RSA_SIGN_TITLE);
}

int KeyIso_CLIENT_ecdsa_sign(
    KEYISO_KEY_CTX *keyCtx,
    int type,
    const unsigned char *dgst,
    int dlen,
    unsigned char *sig,
    unsigned int siglen,
    unsigned int *outlen)
{
    const char *title = KEYISOP_ECC_SIGN_TITLE;
    int ret = -1;

    if (g_keysinuse.isLibraryLoaded && keyCtx) {
        g_keysinuse.on_use_func(keyCtx->keysInUseCtx, KEYSISO_KEYSINUSE_SIGN_OPERATION);
    }
    
    if (keyCtx == NULL || dgst == NULL) {
        KEYISOP_trace_log_error(NULL, 0, title, "Complete - Failed", "key context and dgst cant be null");
        return ret;
    }

    ERR_clear_error();
    KEYISOP_trace_log(keyCtx->correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Start");

    // check for backward compatibility code
    if (!keyCtx->isP8Key) { // The encrypted key is asn1 encoded key 
        if (KEYISOP_inProc) {
            ret = KeyIso_SERVER_ecdsa_sign(
                keyCtx->correlationId,
                keyCtx->pkey,
                type,
                dgst,
                dlen,
                sig,
                siglen,
                outlen);    
        } else {      
            ret = KMPP_GDBUS_CLIENT_ecdsa_sign( 
                keyCtx,
                type,
                dgst,
                dlen,
                sig,
                siglen,
                outlen);
        }
    } else {
        ret = g_msgHandlerImplementation.ecdsa_sign(
            keyCtx,
            type,
            dgst,
            dlen,
            sig,
            siglen,
            outlen);
    }
    _log_result(keyCtx->correlationId, title, ret);
    return ret;
}

int KeyIso_CLIENT_pfx_open(
    const uuid_t correlationId,
    int pfxLength,
    const unsigned char* pfxBytes,
    const char* salt,
    KEYISO_KEY_CTX** keyCtx)
{
    // None p8Compatible function - this is a backward compatibility code
    const char *title = KEYISOP_OPEN_PFX_TITLE;
    int ret = 0;
    KEYISO_KEY_CTX *ctx = NULL;

    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Start"); 

    ERR_clear_error();

    // Check that pfx size doesn't exceed the maximum
    if (pfxLength > KMPP_MAX_MESSAGE_SIZE) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, NULL, "Encrypted Pfx file is too big", "length: %d", pfxLength);
        return ret;
    }

    ctx = (KEYISO_KEY_CTX *) KeyIso_zalloc(sizeof(KEYISO_KEY_CTX));
    if (ctx == NULL) {
        goto end;
    }

    if (correlationId == NULL) {
        KeyIso_rand_bytes(ctx->correlationId, sizeof(ctx->correlationId));
    } else {
        memcpy(ctx->correlationId, correlationId, sizeof(ctx->correlationId));
    }

    if (KEYISOP_inProc) {
        ret = KeyIso_SERVER_pfx_open(
        ctx->correlationId,
        pfxLength,
        pfxBytes,
        salt,
        &ctx->pkey);
    } else {
        ret = KMPP_GDBUS_CLIENT_pfx_open(
        ctx,
        pfxLength,
        pfxBytes,
        salt);
    }

end:
    if (!ret) {
        KeyIso_CLIENT_pfx_close(ctx);
        ctx = NULL;
    }
    _log_result(correlationId, title, ret);
    *keyCtx = ctx;
    return ret;
}

void KeyIso_CLIENT_pfx_close(
    KEYISO_KEY_CTX *keyCtx)
{
    const char *title = KEYISOP_CLOSE_PFX_TITLE;
    if (keyCtx == NULL) {
        return;
    }

    KEYISOP_trace_log(keyCtx->correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Start");

    // KeysInUse notification on closing the key
    if (g_keysinuse.isLibraryLoaded) {
        g_keysinuse.unload_key_func(keyCtx->keysInUseCtx);
        keyCtx->keysInUseCtx = NULL;
    }

    // check for backward compatibility code
    if (!keyCtx->isP8Key) { // The encrypted key is asn1 encoded key 
        if (KEYISOP_inProc) {
            KeyIso_SERVER_pfx_free(keyCtx->pkey);            
        } else {
            KMPP_GDBUS_CLIENT_pfx_close(keyCtx);            
        }
        KEYISOP_trace_log(keyCtx->correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete - Success");
        KeyIso_free(keyCtx);
        return;
    }
    // The encrypted opened key is pkcs#8 compatible    
    g_msgHandlerImplementation.close_key(keyCtx);

    KEYISOP_trace_log(keyCtx->correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete - Success");

    KeyIso_free(keyCtx);
}

int KeyIso_CLIENT_import_pfx(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *inPassword,             // Optional
    int *outVerifyChainError,
    int *outPfxLength,
    unsigned char **outPfxBytes,         // KeyIso_free()
    char **outPfxSalt)                   // KeyIso_free()
{
    // None p8Compatible function - this is a backward compatibility code
    const char *title = KEYISOP_IMPORT_PFX_TITLE;
    int ret = 0;
    uuid_t randId;

    if (correlationId == NULL) {
        KeyIso_rand_bytes(randId, sizeof(randId));
        correlationId = randId;
    }

    KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Start", "flags: 0x%x length: %d", keyisoFlags, inPfxLength);

    ERR_clear_error();

    if (KEYISOP_inProc) {
        ret = KeyIso_SERVER_import_pfx(
            correlationId,
            keyisoFlags,
            inPfxLength,
            inPfxBytes,
            inPassword,             // Optional
            outVerifyChainError,
            outPfxLength,
            outPfxBytes,            // KeyIso_free()
            outPfxSalt);            // KeyIso_free()
    } else {
        ret = KMPP_GDBUS_CLIENT_import_pfx(
            correlationId,
            keyisoFlags,
            inPfxLength,
            inPfxBytes,
            inPassword,             // Optional
            outVerifyChainError,
            outPfxLength,
            outPfxBytes,            // KeyIso_free()
            outPfxSalt);            // KeyIso_free()
    }   
     if (ret > 0) {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete - Success");
    } else {
        if (ret < 0) {
            KEYISOP_trace_log_openssl_verify_cert_error(correlationId, 0, title, "X509_verify_cert", *outVerifyChainError);
            KEYISOP_trace_log_error(correlationId, 0, title, "Complete", "Import succeeded with certificate errors");
        } else
            KEYISOP_trace_log_error(correlationId, 0, title, "Complete", "Import failed");
    }

    return ret;
}

int KeyIso_CLIENT_import_symmetric_key(
    const uuid_t correlationId,
    const int inKeyLength,
    const unsigned char *inKeyBytes,
    const unsigned char *inImportKeyId, // Unique identifier to the imported key
    unsigned int *outKeyLength,
    unsigned char **outKeyBytes)        // KeyIso_free() 
{
    char **outClientData = NULL; // KeyIso_free()
    return KeyIso_CLIENT_import_symmetric_key_new(
        correlationId,
        inKeyLength,
        inKeyBytes,
        inImportKeyId,
        outKeyLength,
        outKeyBytes,       // KeyIso_free()
        outClientData);    // KeyIso_free()
}

int KeyIso_CLIENT_import_symmetric_key_new(
    const uuid_t correlationId,
    const int inKeyLength,
    const unsigned char *inKeyBytes,
    const unsigned char *inImportKeyId,  // Unique identifier to the imported key
    unsigned int *outKeyLength,
    unsigned char **outKeyBytes,        // KeyIso_free()
    char **outClientData)               // KeyIso_free()
{
    const char *title = KEYISOP_IMPORT_SYMMETRIC_KEY_TITLE;
    int status = STATUS_FAILED;
    uuid_t randId;

    if (correlationId == NULL) {
        KeyIso_rand_bytes(randId, sizeof(randId));
        correlationId = randId;
    }
    
    KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Start", "length: %d, solutionType: %d, isDefaultConfig: %d", inKeyLength, g_config.solutionType, g_config.isDefaultSolutionType);

    ERR_clear_error();
            
    status = g_msgHandlerImplementation.import_symmetric_key(
        correlationId,
        KEYISO_IPC_SYMMETRIC_KEY_AES_CBC,
        inKeyLength,
        inKeyBytes,
        inImportKeyId,
        outKeyLength,
        outKeyBytes,
        outClientData); 

    // Extract sha256 string out of the inImportKeyId for metric.
    char sha256HexHash[KMPP_AES_256_KEY_SIZE * 2 + 1]; // In asymmetric key import we take SHA256_DIGEST_LENGTH
    KeyIsoP_bytes_to_hex(KMPP_AES_256_KEY_SIZE, inImportKeyId, sha256HexHash);
    
    if (status != STATUS_OK) {  
        KEYISOP_trace_log_and_metric_error_para(correlationId, 0, g_config.solutionType, g_keysinuse.isLibraryLoaded, title, NULL, "Symmetric key import failed", "sha256:%s", sha256HexHash);
    } else {
        KEYISOP_trace_metric_para(correlationId, 0, g_config.solutionType, g_keysinuse.isLibraryLoaded, title, NULL, "Symmetric key import succeeded. sha256: %s", sha256HexHash);
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete - Success");
    }
    
    return status;
}

int KeyIso_CLIENT_symmetric_key_encrypt_decrypt(
    KEYISO_KEY_CTX *keyCtx,
    const int mode,
    const unsigned char *from,
    const unsigned int fromLen,
    unsigned char *to,
    unsigned int *toLen)
{
    const char *title = KEYISOP_SYMMETRIC_ENC_DEC_TITLE;
    int status = STATUS_FAILED;

    ERR_clear_error();

    if (keyCtx == NULL || keyCtx->keyDetails == NULL) {
        KEYISOP_trace_log_error(NULL, 0, title, "keyCtx", "Invalid argument"); 
        return STATUS_FAILED;
    }
            
    status = g_msgHandlerImplementation.symmetric_key_encrypt_decrypt(
        keyCtx,
        mode,   
        from,
        fromLen,
        to,
        toLen);

    if (status != STATUS_OK) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, title, "KeyIso_SERVER_symmetric_key_encrypt_decrypt", "failed");
    }
    return status;
}


int KeyIso_CLIENT_init_key_ctx(KEYISO_KEY_CTX *keyCtx, int keyLength, const unsigned char *keyBytes, const char *clientData)
{    
    return g_msgHandlerImplementation.init_key(keyCtx, keyLength, keyBytes, clientData);    
}

void KeyIso_CLIENT_free_key_ctx(KEYISO_KEY_CTX *keyCtx)
{    
    g_msgHandlerImplementation.free_keyCtx(keyCtx);
}

// Returns BIO_s_mem().
// Ensures a NULL terminator is always appended to the read file contents.
BIO *KeyIsoP_read_file_string(
    const uuid_t correlationId,
    const char *fileName,
    int disableTraceLog,
    char **str)
{
    const char *title = KEYISOP_SUPPORT_TITLE;
    int ret = 0;
    BIO *in = NULL;
    BIO *mem = NULL;
    char buff[512];

    ERR_clear_error();

    in = BIO_new_file(fileName, "rb");
    if (in == NULL) {
        if (!disableTraceLog) {
            KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, "BIO_new_file",
                "file: %s", fileName);
        }
        goto end;
    }

    mem = BIO_new(BIO_s_mem());
    if (mem == NULL) {
        goto memErr;
    }

    for (;;) {
        int inl = BIO_read(in, buff, sizeof(buff));

        if (inl <= 0) {
            break;
        }
        if (BIO_write(mem, buff, inl) != inl) {
            goto memErr;
        }
    }

    // Ensure output string is NULL terminated
    buff[0] = '\0';
    if (BIO_write(mem, buff, 1) != 1) {
        goto memErr;
    }

    if (BIO_get_mem_data(mem, str) < 1 || *str == NULL) {
        goto memErr;
    }

    ret = 1;
end:
    if (!ret) {
        BIO_free(mem);
        mem = NULL;
        *str = NULL;
    }

    BIO_free(in);
    return mem;

memErr:
    if (!disableTraceLog) {
        KEYISOP_trace_log_openssl_error(correlationId, 0, title, "mem");
    }
    goto end;
}

int KeyIso_CLIENT_self_sign_pfx(
    const uuid_t correlationId,
    int keyisoFlags,
    const char *confStr,
    int *pfxLength,
    unsigned char **pfxBytes,
    char **pfxSalt)
{
    // None p8Compatible function - this is a backward compatibility code
    const char *title = KEYISOP_CREATE_SELF_SIGN_TITLE;
    int ret = 0;    
    KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Start",
        "flags: 0x%x", keyisoFlags);

    ERR_clear_error();

    if (KEYISOP_inProc) {
        ret = KeyIso_SERVER_create_self_sign_pfx(
            correlationId,
            keyisoFlags,
            confStr,
            pfxLength,
            pfxBytes,            // KeyIso_free()
            pfxSalt);            // KeyIso_free()
    } else {
        ret = KMPP_GDBUS_CLIENT_create_self_sign_pfx(
            correlationId,
            keyisoFlags,
            confStr,
            pfxLength,
            pfxBytes,            // KeyIso_free()
            pfxSalt);            // KeyIso_free()
    }

    _log_result(correlationId, title, ret);
    return ret;
}

int KeyIso_CLIENT_replace_pfx_certs(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *inSalt,
    int pemCertLength,
    const unsigned char *pemCertBytes,
    int *outPfxLength,
    unsigned char **outPfxBytes,    
    char **outSalt)
{
    // None p8Compatible function - this is a backward compatibility code
    const char *title = KEYISOP_HELPER_PFX_TITLE;
    int ret = 0;
    uuid_t randId;

    *outPfxLength = 0;
    *outPfxBytes = NULL;
    *outSalt = NULL;

    if (correlationId == NULL) {
        KeyIso_rand_bytes(randId, sizeof(randId));
        correlationId = randId;
    }

    KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Start", "flags: 0x%x", keyisoFlags);

    ERR_clear_error();

    if (KEYISOP_inProc) {
        ret = KeyIso_SERVER_replace_pfx_certs(
            correlationId,
            keyisoFlags,
            inPfxLength,
            inPfxBytes,
            inSalt,
            pemCertLength,
            pemCertBytes,
            outPfxLength,
            outPfxBytes,                // KeyIso_free()
            outSalt);                   // KeyIso_free()
    } else {
        ret = KMPP_GDBUS_CLIENT_replace_pfx_certs(
            correlationId,
            keyisoFlags,
            inPfxLength,
            inPfxBytes,
            inSalt,
            pemCertLength,
            pemCertBytes,
            outPfxLength,
            outPfxBytes,                // KeyIso_free()
            outSalt);                   // KeyIso_free()
    }

   _log_result(correlationId, title, ret);
   return ret;
}

// Common function for both engine and provider in RSA sign
void KeyIso_rsa_sign_serialization(
    unsigned char *from,
    int type, 
    const unsigned char *m,
    unsigned int m_len)
{
    KEYISO_RSA_SIGN rsaSign;
    memset(&rsaSign, 0, sizeof(rsaSign));

    if (from == NULL) {
        return;
    }

    rsaSign.type = type;
    rsaSign.m_len = m_len;

    memcpy(from, &rsaSign, sizeof(KEYISO_RSA_SIGN));
    memcpy(from + sizeof(KEYISO_RSA_SIGN), m, m_len);
} 

// Common function for both engine and provider in RSA sign
void KeyIso_CLIENT_pkey_rsa_sign_serialization(
    unsigned char *from,
    const unsigned char *tbs,
    size_t tbsLen, 
    int saltLen,
    int mdType,
    int mgfmdType,
    size_t sigLen,
    int getMaxLen)
{
    KEYISO_EVP_PKEY_SIGN pkeyRsaSign;
    memset(&pkeyRsaSign, 0, sizeof(pkeyRsaSign));

    if (from == NULL) {
        return;        
    }

    pkeyRsaSign.tbsLen      = tbsLen;      // size_t to uint64_t
    pkeyRsaSign.saltLen     = saltLen;
    pkeyRsaSign.sigmdType   = mdType;
    pkeyRsaSign.mgfmdType   = mgfmdType;
    pkeyRsaSign.getMaxLen   = getMaxLen;
    pkeyRsaSign.sigLen      = sigLen;      // size_t to uint64_t

    memcpy(from, &pkeyRsaSign, sizeof(KEYISO_EVP_PKEY_SIGN));
    
    if (tbs != NULL) {
        memcpy(from + sizeof(KEYISO_EVP_PKEY_SIGN), tbs, tbsLen);
    } else {
        memset(from + sizeof(KEYISO_EVP_PKEY_SIGN), 0, tbsLen);
    }
}

//
// Support functions for engine and key id defined in keyisoclient.h
//

EVP_PKEY *KeyIso_load_engine_private_key(
    const uuid_t correlationId,
    const char *engineName,
    const char *engineKeyId)
{
    const char *title = KEYISOP_ENGINE_TITLE;
    const char *loc = "";
    EVP_PKEY *pkey = NULL;
    ENGINE *e = NULL;
    int engineInit = 0;

    e = KeyIso_load_engine(correlationId, engineName);
    if (e == NULL) {
        return pkey;
    }

    engineInit = 1;

    pkey = ENGINE_load_private_key(
        e,
        engineKeyId,
        NULL,               // *ui_method
        NULL);              // *callback_data
    if (pkey == NULL) {
        loc = "ENGINE_load_private_key";
        goto openSslErr;
    }

    // Setting the engine to the private key to supporting legacy keys in OSSL3.x
    if (!EVP_PKEY_set1_engine(pkey, e)) {
        loc = "EVP_PKEY_set1_engine";
        goto openSslErr;
    }  

end:
    if (e != NULL) {
        if (engineInit) {
            ENGINE_finish(e);   // for ENGINE_init()
        }
        ENGINE_free(e);     // for ENGINE_by_id()
    }
    return pkey;

openSslErr:
    KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

ENGINE *KeyIso_load_engine(
    const uuid_t correlationId,
    const char *engineName)
{
    const char *title = KEYISOP_ENGINE_TITLE;
    const char *loc = "";
    ENGINE *e = NULL;

    ERR_clear_error();

    // Following is needed to load the "dynamic" engine, that will load our engine
    ENGINE_load_dynamic();
    e = ENGINE_by_id(engineName);
    if (!e) {
        loc = "ENGINE_by_id";
        KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
        return e;
    }

    if (!(ENGINE_init(e))){
        loc = "ENGINE_init";
        KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
        return e;
    }

    return e;
}

static int _get_salt_legacy(
        const uuid_t correlationId,
        const char *startSaltPtr,
        size_t saltLength,
        char **outSalt) 
{
    const char *title = KEYISOP_HELPER_PFX_TITLE;
    int ret = STATUS_FAILED;
    char *salt = NULL;

    if (g_config.solutionType != KeyIsoSolutionType_process) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "legacy key strcut supported only for process based isolation solution", "invalid input", "selected solution type: %d", g_config.solutionType);
        return ret;
    }

    if (!startSaltPtr || !outSalt) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid parameter", "cant be null");
        return ret;
    }

    *outSalt = NULL;
    // KEYISO_SECRET_SALT_STR_BASE64_LEGACY_LEN takes in account a salt null terminator that in keyid is not present after the salt
    if (saltLength != KEYISO_SECRET_SALT_STR_BASE64_LEGACY_LEN - 1 ) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "failed to retrieve salt", "invalid salt length", "saltLength: %d, expected: %d", saltLength, KEYISO_SECRET_SALT_STR_BASE64_LEGACY_LEN);
        return ret;
    }
    
    salt = (char *) KeyIso_zalloc(saltLength + 1);
    if (salt == NULL) {
        // Allocation failed
        return ret;
    }
    
    memcpy(salt, startSaltPtr, saltLength);
    salt[saltLength] = '\0';
    
    *outSalt = salt;
    return STATUS_OK;
}

static bool _is_filename(const char *keyId)
{ 
    const char *pfxStartPtr = KeyIso_get_delimiter_ptr(keyId);
    if (pfxStartPtr == NULL) {
        // There is no delimiter -> file name only
        return true;
    }
    
    size_t clientDataLength = pfxStartPtr - keyId;

    // Legacy: verifies That SaltLength > MIN_SALT_LENGTH 
    // New version: Verifies that extra data >= base64(sizeof (KEYISO_ENCRYPTION_EXTRA_DATA_HEADER_ST))
    // If shorter then min length, it is a file name
    size_t minLength = KeyIso_get_client_data_minimum(keyId);
    return  clientDataLength < minLength;
}

// New Format:  'n' <Base64 ExtraDataBuffer> ':' <Base64 PFX>
// Legacy Format:  <Salt> ":" <Base64 PFX> , salt first byte is '0' or 't'
int KeyIso_parse_pfx_engine_key_id(
    const uuid_t correlationId,
    const char *keyId,
    int *pfxLength,
    unsigned char **pfxBytes,        // KeyIso_clear_free()
    char **clientData)               // Salt is sent for legacy keyid(MScrypt key)
                                     // Base64 encoded client data for kmpp key
{
    int status = STATUS_FAILED;
    const char *title = KEYISOP_HELPER_PFX_TITLE;
    BIO *fileBio = NULL;
    const char *pfxStr = NULL;  // Don't free
    char *fileString = NULL;    // Don't free
    
    ERR_clear_error();
 
    if (clientData == NULL || keyId == NULL || pfxLength == NULL || pfxBytes == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid parameter", "cant be null");
        return STATUS_FAILED;
    }

    // Initialize output parameters
    *pfxLength = 0;
    *pfxBytes = NULL; 
    *clientData = NULL;

    // Handle file references
    if (strncmp(keyId, "file:", 5) == 0) {
        // Direct file reference (file:path)
        fileBio = KeyIsoP_read_file_string(correlationId, keyId + 5, 0, &fileString);
        if (fileBio == NULL) {
            goto cleanup;
        }
        keyId = fileString;
    } else {
        // Check if keyId is a file path
        bool isFilename = _is_filename(keyId);
        fileBio = KeyIsoP_read_file_string(correlationId, keyId, !isFilename, &fileString);
        if (fileBio == NULL) {
            if (isFilename) {
                goto cleanup;
            }
        } else {
            keyId = fileString;
        }
    }

    // Find the delimiter between client data and PFX data
    size_t maxLengthToSearch = KeyIso_get_client_data_maximum(keyId);
    pfxStr = memchr(keyId, CLIENT_DATA_DELIMITER, maxLengthToSearch);
    if (pfxStr == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "strchr", "Invalid keyid format - no delimiter found");
        goto cleanup;
    } 

    // Extract client data portion (salt)
    size_t clientDataLength = pfxStr - keyId;
    pfxStr++; // Skip the ':' delimiter
        
    // Handle different format types
    if (KeyIso_is_legacy(keyId)) {
        // Legacy format - extract salt directly
        status = _get_salt_legacy(correlationId, keyId, clientDataLength, clientData); // For legacy keyid, this is the salt
        if (status != STATUS_OK) { 
            KEYISOP_trace_log_error(correlationId, 0, title, "Legacy Salt Retrieve", "_parse_keyid_legacy Failed");
            goto cleanup;
        }
    } else {
        // New format - get client data using solution type
        status = KeyIso_get_client_data_from_keyid(correlationId, g_config.solutionType, keyId, clientData);
        if (status != STATUS_OK) {
            KEYISOP_trace_log_error(correlationId, 0, title, "Client Data Retrieve", "_parse_keyid Failed");
            goto cleanup;
        }
    }
    
    // Decode the Base64 PFX data
    *pfxLength = KeyIso_base64_decode(correlationId, pfxStr, pfxBytes);
    if (*pfxLength <= 0 || *pfxBytes == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Base64 Decode", "Failed");
        goto cleanup;
    }
    
    status = STATUS_OK;

cleanup:
    if (status != STATUS_OK) {
        // Free allocated resources on error
        if (*pfxBytes != NULL) {
            KeyIso_free(*pfxBytes);
            *pfxBytes = NULL;
        }
        *pfxLength = 0;
        
        if (clientData != NULL && *clientData != NULL) {
            KeyIso_clear_free_string(*clientData);
            *clientData = NULL;
        }
    }

    BIO_free(fileBio);
    return status;
}

int KeyIso_format_pfx_engine_key_id(
    const uuid_t correlationId,
    int pfxLength,
    const unsigned char *pfxBytes,
    const char *clientData,
    char **keyId) // KeyIso_free()
{
    return _format_engine_key_id(correlationId, pfxLength, pfxBytes, clientData, keyId);
}
unsigned int KeyIso_CLIENT_get_version(const uuid_t correlationId)
{
    const char *title = KEYISOP_READ_WRITE_VERSION_TITLE;   
    unsigned int version = KEYISOP_INVALID_VERSION;

    if (KEYISOP_inProc || g_config.solutionType == KeyIsoSolutionType_tz) {
        KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Set to current version", "version:%d", KEYISOP_CURRENT_VERSION);
        return KEYISOP_CURRENT_VERSION;
    }
    
    if (KMPP_RAW_DBUS_CLIENT_get_version(correlationId, &version) == STATUS_FAILED) {
        KEYISOP_trace_log_error_para(correlationId, KEYISOP_TRACELOG_WARNING_FLAG, title, "", "Failed to retrieve the version of the service. The communication will consider the minimum version supported in the environment.", 
            "Minimum supported version: %u",  KMPP_MIN_SERVICE_VERSION);
        // If the minumum version does not support FIPS and we must notify the user
        if (KMPP_MIN_SERVICE_VERSION < KEYISOP_FIPS_MIN_VERSION) {
            KEYISOP_trace_log_error(correlationId, KEYISOP_TRACELOG_WARNING_FLAG, title, "", "The minimum version supported in the environment does not support FIPS. To enable FIPS, first verify that the service is available. Then, reboot the client to ensure it retrieves the current version of the service.");
        }
        return KMPP_MIN_SERVICE_VERSION;
    }

    KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete - succeeded to retrieve version", "version:%d", version);
    return version;
}

unsigned int KeyIso_get_min_compatible_version(const uuid_t correlationId, KeyisoCompatibilityMode mode)
{
    unsigned int min_version = KEYISOP_INVALID_VERSION;
    const char *title = KEYISOP_COMPATIBILITY_MODES_TITLE;
    const char *loc = "";

    switch (mode) {
        case KeyisoCompatibilityMode_fips:
        {
            min_version = KEYISOP_FIPS_MIN_VERSION;
            loc = "FIPS mode";
            break;
        }
        case KeyisoCompatibilityMode_pkcs8:
        {
            min_version = KEYISOP_PKCS8_MIN_VERSION;
            loc = "PKCS8 mode";
            break;
        }
        default:
        {
            loc = "Invalid mode";
            break;
        }
    }

    KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, loc, "mode: %d. min_version: %u", mode, min_version);
    return min_version;
}

static int _get_and_validate_compatibility_mode(const uuid_t correlationId, KeyisoCompatibilityMode mode)
{
    const char *title = KEYISOP_COMPATIBILITY_MODES_TITLE;
    int ret = NOT_COMPATIBLE;
    const unsigned int min_version = KeyIso_get_min_compatible_version(correlationId, mode);
    unsigned int current_version = KEYISOP_INVALID_VERSION;

    // Check if the minimum version is valid
    if (min_version <= KEYISOP_INVALID_VERSION) {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Invalid minimum version.");
        return ret;
    }

    current_version = KeyIso_CLIENT_get_version(correlationId);
    // Check if the service version is valid
    if (current_version <= KEYISOP_INVALID_VERSION) {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Invalid service version.");
        return ret;
    }

    // Check compatibility
     if (current_version >= min_version) {
        ret = COMPATIBLE;
        KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Supported mode",
            "mode: %d. service_version: %u. min_version: %u", 
            mode, current_version, min_version);
    } else {
        KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Unsupported mode",
            "mode: %d. service_version: %u. min_version: %u", 
            mode, current_version, min_version);
    }

    return ret;
}

int KeyIso_validate_current_service_compatibility_mode(const uuid_t correlationId, KeyisoCompatibilityMode type)
{
    const char* title = KEYISOP_COMPATIBILITY_MODES_TITLE;
    switch (type) {
        case KeyisoCompatibilityMode_fips:
        case KeyisoCompatibilityMode_pkcs8:
            return _get_and_validate_compatibility_mode(correlationId, type);
        default:
            KEYISOP_trace_log_error_para(correlationId, 0, title, "Invalid mode requested", "unknown compatibility mode type", "type: %d", (int)type);
            return NOT_COMPATIBLE; 
    }
}

static uint8_t _export_key_usage(EVP_PKEY *pkey)
{
    const ASN1_TYPE *attrType = NULL;
    int i = -1;
    uint8_t usage = KMPP_KEY_USAGE_INVALID;

    ERR_clear_error();

    i = EVP_PKEY_get_attr_by_NID(pkey, NID_key_usage, -1);
    attrType = X509_ATTRIBUTE_get0_type(EVP_PKEY_get_attr(pkey, i), 0);
    
    if ((attrType == NULL) || 
        (attrType->type != V_ASN1_BIT_STRING) || 
        (attrType->value.bit_string->length != 1) || 
        (attrType->value.bit_string->data == NULL)) {
            KEYISOP_trace_log_openssl_error(NULL, 0, KEYISOP_IMPORT_KEY_TITLE, "X509_ATTRIBUTE_get0_type");
            return usage;
        }

    memcpy(&usage, attrType->value.bit_string->data, attrType->value.bit_string->length);
    return usage;
}

// RSA Private Key 
static KEYISO_RSA_PKEY_ST* _cleanup_get_rsa_private_key(
    const uuid_t correlationId,
    int res,
    KEYISO_RSA_PKEY_ST* pRsaPkey,
    size_t keySize,
    BIGNUM *rsa_n,
    BIGNUM *rsa_e,
    BIGNUM *rsa_p,
    BIGNUM *rsa_q,
    const char* loc)
{
    if (res != STATUS_OK) {
        KeyIso_clear_free(pRsaPkey, keySize);
        KEYISOP_trace_log_openssl_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, loc);
        return NULL;
    }

    if (rsa_n) {
        BN_free(rsa_n);
    }
    if (rsa_e) {
        BN_free(rsa_e);
    }
    if (rsa_p) {
        BN_clear_free(rsa_p);
    }
    if (rsa_q) {
        BN_clear_free(rsa_q);
    }
    
    return pRsaPkey;
}

// Should be freed by the caller KeyIso_clear_free()
KEYISO_RSA_PKEY_ST* KeyIso_export_rsa_epkey (
    const uuid_t correlationId,
    const void* inPkey,
    size_t* outKeySize)
{
    if (outKeySize == NULL) {
        return _cleanup_get_rsa_private_key(correlationId, STATUS_FAILED, NULL, 0, NULL, NULL, NULL, NULL, "Invalid argument, keysize ptr is NULL");
    }

    uint64_t pkeyDynamicLen = 0;
    uint32_t index = 0;
    uint8_t rsaUsage = KMPP_KEY_USAGE_INVALID;

    BIGNUM *rsa_n = NULL; // Modulus
    BIGNUM *rsa_e = NULL; // Public exponent
    BIGNUM *rsa_p = NULL; // Prime1
    BIGNUM *rsa_q = NULL; // Prime2

    size_t  rsa_n_len = 0; 
    size_t  rsa_e_len = 0;
    size_t  rsa_p_len = 0; 
    size_t  rsa_q_len = 0; 

    EVP_PKEY *evp_pkey = (EVP_PKEY *) inPkey;
    if (!evp_pkey || 
        (EVP_PKEY_id(evp_pkey) != EVP_PKEY_RSA &&
         EVP_PKEY_id(evp_pkey) != EVP_PKEY_RSA_PSS)) {
        return _cleanup_get_rsa_private_key(correlationId, STATUS_FAILED, NULL, 0, NULL, NULL, NULL, NULL, "Input key is not RSA");
    }

    // Get the RSA parameters
    KeyIso_get_rsa_params((const EVP_PKEY *)evp_pkey, &rsa_n, &rsa_e, &rsa_p, &rsa_q);
    if (rsa_n == NULL || rsa_e == NULL) {
        return _cleanup_get_rsa_private_key(correlationId, STATUS_FAILED, NULL, 0, rsa_n, rsa_e, rsa_p, rsa_q, "KeyIso_get_rsa_params - Both RSA modulus and public exponent must be provided");
    }
    rsa_n_len = BN_num_bytes(rsa_n);
    rsa_e_len = BN_num_bytes(rsa_e);

    // Prime1 (can be empty)
    if (rsa_p) {
        rsa_p_len = BN_num_bytes(rsa_p);   
    }

    // Prime2 (can be empty)
    if (rsa_q ) {
        rsa_q_len = BN_num_bytes(rsa_q); 
    }
    pkeyDynamicLen =    
                    rsa_n_len +
                    rsa_e_len +
                    rsa_p_len +
                    rsa_q_len ;

    size_t structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_RSA_PKEY_ST, pkeyDynamicLen);
    KEYISO_RSA_PKEY_ST* pRsaPkey = (KEYISO_RSA_PKEY_ST*)KeyIso_zalloc(structSize); // KeyIso_clear_free() should be used to free this memory
    if (pRsaPkey == NULL) {
        return _cleanup_get_rsa_private_key(correlationId, STATUS_FAILED, pRsaPkey, 0, rsa_n, rsa_e, rsa_p, rsa_q, "Failed to allocate rsa pkey");
    }
    *outKeySize = structSize;

    rsaUsage = _export_key_usage(evp_pkey);
    if (rsaUsage == KMPP_KEY_USAGE_INVALID) {
        return _cleanup_get_rsa_private_key(correlationId, STATUS_FAILED, pRsaPkey, structSize, rsa_n, rsa_e, rsa_p, rsa_q, "Failed to extract key usage from the EVP_PKEY object");
    }

    pRsaPkey->rsaUsage = rsaUsage;
    pRsaPkey->rsaModulusLen = rsa_n_len;
    pRsaPkey->rsaPublicExpLen = rsa_e_len;
    pRsaPkey->rsaPrimes1Len = rsa_p_len;
    pRsaPkey->rsaPrimes2Len = rsa_q_len;

    KEYISO_KEY_HEADER_ST pKeyHeader;
    pKeyHeader.keyVersion = KEYISO_PKEY_VERSION;
    pKeyHeader.magic = KEYISO_RSA_PRIVATE_PKEY_MAGIC;
    pRsaPkey->header = pKeyHeader;

    if (BN_bn2bin(rsa_n, &pRsaPkey->rsaPkeyBytes[index]) != rsa_n_len) {
        return _cleanup_get_rsa_private_key(correlationId, STATUS_FAILED, pRsaPkey, structSize, rsa_n, rsa_e, rsa_p, rsa_q, "Failed to converts the modulus into big-endian");
    }
    index+= rsa_n_len;
    if (BN_bn2bin(rsa_e, &pRsaPkey->rsaPkeyBytes[index]) != rsa_e_len) {
        return _cleanup_get_rsa_private_key(correlationId, STATUS_FAILED, pRsaPkey, structSize, rsa_n, rsa_e, rsa_p, rsa_q, "Failed to converts the public exponent into big-endian");
    }
    index+= rsa_e_len;
    if (BN_bn2bin(rsa_p, &pRsaPkey->rsaPkeyBytes[index]) != rsa_p_len) {
        return _cleanup_get_rsa_private_key(correlationId, STATUS_FAILED, pRsaPkey, structSize, rsa_n, rsa_e, rsa_p, rsa_q, "Failed to converts prime1 into big-endian");
    }
    index+= rsa_p_len;
    if (BN_bn2bin(rsa_q, &pRsaPkey->rsaPkeyBytes[index]) != rsa_q_len) {
        return _cleanup_get_rsa_private_key(correlationId, STATUS_FAILED, pRsaPkey, structSize, rsa_n, rsa_e, rsa_p, rsa_q, "Failed to converts prime2 into big-endian");
    }
    index+= rsa_q_len;
    return _cleanup_get_rsa_private_key(correlationId, STATUS_OK, pRsaPkey, structSize, rsa_n, rsa_e, rsa_p, rsa_q, NULL);
}

// EC Private Key
static KEYISO_EC_PKEY_ST* _cleanup_get_ec_private_key_resources(
    const uuid_t correlationId,
    int res,
    KEYISO_EC_PKEY_ST* pEcPkey,
    size_t structSize,
    EC_KEY*  ecKey,
    BN_CTX*  bnCtx,
    BIGNUM* bnEcPubX,
    BIGNUM* bnEcPubY,
    const char* loc)
{
    BN_free(bnEcPubX);
    BN_free(bnEcPubY);
    BN_CTX_end(bnCtx);
    BN_CTX_free(bnCtx);
    EC_KEY_free(ecKey);

    if(res != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_ENGINE_TITLE, "Error", loc);
        KeyIso_clear_free(pEcPkey, structSize);
        return NULL;
    }
    return pEcPkey;
}

// Should be freed by the caller KeyIso_clear_free()
KEYISO_EC_PKEY_ST* KeyIso_export_ec_private_key(
    const uuid_t correlationId,
    const void* inPkey,
    size_t* outKeySize)
{
    if (!outKeySize) {
        return _cleanup_get_ec_private_key_resources(correlationId, STATUS_FAILED, NULL, 0, NULL, NULL, NULL, NULL, "Invalid argument, keysize ptr is NULL");
    }

    *outKeySize = 0;
    const BIGNUM*  bnEcPrivateKey = NULL;
    const EC_POINT* ecPubKey = NULL;
    const EC_GROUP *ecGroup = NULL;
    BIGNUM* bnEcPubX = NULL;
    BIGNUM* bnEcPubY = NULL;
    EVP_PKEY *evpPkey = NULL;
    BN_CTX* bnCtx = NULL;
    EC_KEY *ecKey = NULL;
    KEYISO_EC_PKEY_ST* pEcPkey = NULL; // KeyIso_clear_free() should be used to free this memory
    uint32_t ecPubXLen = 0;
    uint32_t ecPubYLen = 0;
    uint32_t ecPrivateKeyLen = 0;
    uint32_t pkeyDynamicLen = 0;
    uint32_t groupNid = 0;
    size_t structSize = 0;
    uint8_t ecUsage = KMPP_KEY_USAGE_INVALID;

    // Get the public key x and y
    evpPkey = (EVP_PKEY *) inPkey;
    if (!evpPkey || EVP_PKEY_id(evpPkey) != EVP_PKEY_EC) {
        return _cleanup_get_ec_private_key_resources(correlationId, STATUS_FAILED, NULL, 0, ecKey, bnCtx, bnEcPubX, bnEcPubY, "Input key is not EC");
    }
    ecKey = EVP_PKEY_get1_EC_KEY(evpPkey); //must be freed after use
    if (ecKey == NULL) {
        return _cleanup_get_ec_private_key_resources(correlationId, STATUS_FAILED, NULL, 0, ecKey, bnCtx, bnEcPubX, bnEcPubY, "Failed to retrieve EC key");
    }
    ecPubKey = EC_KEY_get0_public_key(ecKey);
    if (ecPubKey == NULL ) {
        return _cleanup_get_ec_private_key_resources(correlationId, STATUS_FAILED, NULL, 0, ecKey, bnCtx, bnEcPubX, bnEcPubY, "Public key is empty");
    }

    ecGroup = EC_KEY_get0_group(ecKey);
    if (ecGroup == NULL) {
        return _cleanup_get_ec_private_key_resources(correlationId, STATUS_FAILED, NULL, 0, ecKey, bnCtx, bnEcPubX, bnEcPubY, "Failed to retrieve EC group");
    }
    
    if (((bnEcPubX = BN_new()) == NULL) ||
        ((bnEcPubY = BN_new()) == NULL)) {
        return _cleanup_get_ec_private_key_resources(correlationId, STATUS_FAILED, NULL, 0, ecKey, bnCtx, bnEcPubX, bnEcPubY, "Failed create public BNs");
    }

    if ((bnCtx = BN_CTX_new()) == NULL) {
        return _cleanup_get_ec_private_key_resources(correlationId, STATUS_FAILED, NULL, 0, ecKey, bnCtx, bnEcPubX, bnEcPubY, "BN_CTX_new returned NULL");
    }
    
    BN_CTX_start(bnCtx);
    
    if (EC_POINT_get_affine_coordinates(ecGroup, ecPubKey, bnEcPubX, bnEcPubY, bnCtx) == 0 ) {
       return _cleanup_get_ec_private_key_resources(correlationId, STATUS_FAILED, NULL, 0, ecKey, bnCtx, bnEcPubX, bnEcPubY, "EC_POINT_get_affine_coordinates failed");
    }

    ecPubXLen = BN_num_bytes(bnEcPubX);
    ecPubYLen = BN_num_bytes(bnEcPubY);

    // Get private key
    bnEcPrivateKey= EC_KEY_get0_private_key(ecKey);
    if (bnEcPrivateKey == NULL) {
        return _cleanup_get_ec_private_key_resources(correlationId, STATUS_FAILED, NULL, 0, ecKey, bnCtx, bnEcPubX, bnEcPubY, "Failed EC_KEY_get0_private_key");
    }

    ecPrivateKeyLen = BN_num_bytes(bnEcPrivateKey);
    pkeyDynamicLen = ecPubXLen + ecPubYLen + ecPrivateKeyLen;

    structSize = GET_DYNAMIC_STRUCT_SIZE(KEYISO_EC_PKEY_ST, pkeyDynamicLen);
    pEcPkey = (KEYISO_EC_PKEY_ST*)KeyIso_zalloc(structSize); // KeyIso_clear_free() should be used to free this memory
    *outKeySize =  structSize;
    if (pEcPkey == NULL) {
        return _cleanup_get_ec_private_key_resources(correlationId, STATUS_FAILED, pEcPkey, 0, ecKey, bnCtx, bnEcPubX, bnEcPubY, "failed to allocate EC pkey struct");
    }
    groupNid = (uint32_t)EC_GROUP_get_curve_name(ecGroup); 
    if (groupNid == 0) {
        return _cleanup_get_ec_private_key_resources(correlationId, STATUS_FAILED, pEcPkey, structSize, ecKey, bnCtx, bnEcPubX, bnEcPubY, "failed EC_GROUP_get_curve_name");
    }
    
    ecUsage = _export_key_usage(evpPkey);
    if (ecUsage == KMPP_KEY_USAGE_INVALID) {
        return _cleanup_get_ec_private_key_resources(correlationId, STATUS_FAILED, pEcPkey, structSize, ecKey, bnCtx, bnEcPubX, bnEcPubY, "failed to extract key usage from the EVP_PKEY object");
    }
    
    pEcPkey->ecUsage = ecUsage;
    pEcPkey->ecCurve = groupNid;
    pEcPkey->ecPubXLen = ecPubXLen;
    pEcPkey->ecPubYLen = ecPubYLen;
    pEcPkey->ecPrivKeyLen = ecPrivateKeyLen;

    KEYISO_KEY_HEADER_ST pKeyHeader;
    pKeyHeader.keyVersion = KEYISO_PKEY_VERSION;
    pKeyHeader.magic = KEYISO_EC_PRIVATE_PKEY_MAGIC;
    pEcPkey->header = pKeyHeader;

    int index = 0;
    if (BN_bn2binpad(bnEcPubX, &pEcPkey->ecKeyBytes[index], ecPubXLen) != ecPubXLen) {
        return _cleanup_get_ec_private_key_resources(correlationId, STATUS_FAILED, pEcPkey, structSize, ecKey, bnCtx, bnEcPubX, bnEcPubY, "failed to converts the x to big-endian");
    }
    index += ecPubXLen;
    if (BN_bn2binpad(bnEcPubY, &pEcPkey->ecKeyBytes[index], ecPubYLen) != ecPubYLen) {
        return _cleanup_get_ec_private_key_resources(correlationId, STATUS_FAILED, pEcPkey, structSize, ecKey, bnCtx, bnEcPubX, bnEcPubY, "failed to converts the y to big-endian");
    }
    index += ecPubYLen;
    if (BN_bn2binpad(bnEcPrivateKey, &pEcPkey->ecKeyBytes[index], ecPrivateKeyLen) != ecPrivateKeyLen) {
        return _cleanup_get_ec_private_key_resources(correlationId, STATUS_FAILED, pEcPkey, structSize, ecKey, bnCtx, bnEcPubX, bnEcPubY, "failed to converts the private key to big-endian");
    }
    return _cleanup_get_ec_private_key_resources(correlationId, STATUS_OK, pEcPkey, structSize, ecKey, bnCtx, bnEcPubX, bnEcPubY, NULL);
}

static EVP_PKEY* _cleanup_get_rsa_evp_pub_key(
    const uuid_t correlationId,
    int res,
    EVP_PKEY* pkey,
    const char* loc)
{
    if (res != STATUS_OK) {
        KEYISOP_trace_log_openssl_error(correlationId, 0, KEYISOP_ENGINE_TITLE, loc);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    return pkey;
}

// Create an EVP_PKEY object from RSA modulus and public exponent bytes.
// The current implementation relies on deprecated OpenSSL functions.
// An alternative implementation compatible with OpenSSL 3.0 exists in keyisoclientprov.c but is currently disabled.
// When enabling it, ensure careful handling of endian conversion for the modulus and public exponent.
 EVP_PKEY* KeyIso_get_rsa_evp_pub_key(
    const uuid_t correlationId,
    const uint8_t *rsaModulusBytes,
    size_t rsaModulusLen,                            
    const uint8_t *rsaPublicExpBytes,
    size_t rsaPublicExpLen)
{
    ERR_clear_error();

    if (rsaModulusBytes == NULL || rsaModulusLen == 0 || rsaPublicExpBytes == NULL || rsaPublicExpLen == 0) {
        return _cleanup_get_rsa_evp_pub_key(correlationId, STATUS_FAILED, NULL, "Invalid input - NULL parameter or zero length");
    }
    RSA *rsa = RSA_new();
    if (rsa == NULL) {
        return _cleanup_get_rsa_evp_pub_key(correlationId, STATUS_FAILED, NULL, "RSA_new filed");
    }
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        return _cleanup_get_rsa_evp_pub_key(correlationId, STATUS_FAILED, pkey, "EVP_PKEY_new filed");
    }
    
    BIGNUM* rsa_n = BN_bin2bn(rsaModulusBytes, rsaModulusLen, NULL);
    if (rsa_n == NULL) {
        return _cleanup_get_rsa_evp_pub_key(correlationId, STATUS_FAILED,  pkey, "filed to converts the modulus in big-endian");
    }

    BIGNUM* rsa_e = BN_bin2bn(rsaPublicExpBytes, rsaPublicExpLen, NULL);
    if (rsa_e == NULL) {
        BN_free(rsa_n);
        return _cleanup_get_rsa_evp_pub_key(correlationId, STATUS_FAILED, pkey, "filed to converts the public exponent in big-endian");
    }
    
    // Set the public modulus and public exponent values of the RSA key
    // This function transfers the memory management of the values to the RSA object
    //  and therefore the values that have been passed in should not be freed by the caller after this function has been called.
    RSA_set0_key(rsa, rsa_n, rsa_e, NULL); 
    
    // Convert the RSA key to an EVP_PKEY key
    if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
        return _cleanup_get_rsa_evp_pub_key(correlationId, STATUS_FAILED, pkey, "EVP_PKEY_assign_RSA failed");
    }
    return _cleanup_get_rsa_evp_pub_key(correlationId, STATUS_OK, pkey, NULL);
}

static bool _cleanup_is_oid_pbe2(const uuid_t correlationId, bool ret, const char *title,  bool isError, const char *errMessage, X509_SIG *sig)
{
    if (isError == true) {
        KEYISOP_trace_log_openssl_error(correlationId, 0, title, errMessage);

    } else {
        // No error
        KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Completed OID comparison- Is PBE2", "ret: %d", ret);
    }
    if (sig) {
        X509_SIG_free(sig);
    }
    return ret;
}

// Is PBE2(PKCS#12)
bool KeyIso_is_oid_pbe2(
    const uuid_t correlationId, 
    const unsigned char *keyBytes, 
    int keyLength)
{
    const char *title = KEYISOP_OPEN_KEY_TITLE;
    X509_SIG *sig = NULL;
    const X509_ALGOR *alg = NULL;
    const ASN1_OBJECT* oid = NULL;
    const ASN1_OCTET_STRING* osEncKey = NULL;
    bool ret = false;
    bool isError = true;

    ERR_clear_error();

    // Parse the PKCS#12 structure
    int parseRet = KeyIso_pkcs12_parse_p8(correlationId, keyLength, keyBytes, &sig, NULL, NULL);
    if (parseRet != STATUS_OK) {
        return _cleanup_is_oid_pbe2(correlationId, ret, title, isError, "Failed to parse PKCS#12 structure", sig);
    }

    X509_SIG_get0(sig, &alg, &osEncKey);
    if (alg == NULL) {
        return _cleanup_is_oid_pbe2(correlationId, ret, title, isError, "Failed to get PBE algorithm, alg is null", sig);
    }
    
    X509_ALGOR_get0(&oid, NULL, NULL, alg);
    if (oid == NULL) {
        return _cleanup_is_oid_pbe2(correlationId, ret, title, isError, "Failed to get PBE algorithm OID", sig);
    }

    ret = KeyIso_is_equal_oid(oid, OID_PBE2);
    return _cleanup_is_oid_pbe2(correlationId, ret, title, false, "", sig); // No error retrieving the OID and no error message
}

static void _import_pfx_to_disk_cleanup(
    const uuid_t correlationId,
    char *keyId, 
    BIO *out, 
    const char *title, 
    const char *loc,
    bool ossl_error)
{
    // if ossl error
    if (loc != NULL && strlen(loc) > 0) {
        if (ossl_error) {
            KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
        } else {
            KEYISOP_trace_log_error(correlationId, 0, title, loc, "Error");
        }
    }
    KeyIso_clear_free_string(keyId);
    BIO_free(out);
}

int KeyIso_import_pfx_to_disk(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *password,             // Optional
    int *verifyChainError, 
    const char *outFilename)          
{
    const char *title = KEYISOP_IMPORT_KEY_TITLE ;
    const char *loc = "";
    int ret = 0;
    char *keyId = NULL;                 // KeyIso_clear_free_string()
    int keyIdLength = 0;
    BIO *out = NULL;
    uuid_t randId;
    
    if (correlationId == NULL) {
        KeyIso_rand_bytes(randId, sizeof(randId));
        correlationId = randId;
    }

    if (inPfxBytes == NULL || inPfxLength <= 0 || outFilename == NULL) {
        loc = "Invalid parameter";
        _import_pfx_to_disk_cleanup(correlationId, keyId, out, title, loc, false);
        return STATUS_FAILED;
    }

    KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Import PFX", "inPfxLength: %d", inPfxLength);
    ret = KeyIso_import_pfx_to_key_id(
        correlationId,
        keyisoFlags,
        inPfxLength,
        inPfxBytes,
        password,
        verifyChainError,
        &keyId);

    if (!ret || (ret < 0 && !(*verifyChainError))) {
        loc = "KeyIso_import_pfx_to_key_id FAILED";
        _import_pfx_to_disk_cleanup(correlationId, keyId, out, title, loc, false);
        return STATUS_FAILED;
    }

    if (ret < 0) {
        KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "verifyChainError", "%d 0x%x", *verifyChainError, *verifyChainError);
    }

    keyIdLength = (int)strlen(keyId);

    ERR_clear_error();
    out = BIO_new_file(outFilename, "wb");
    if (!out) {
        loc = "BIO_new_file";
        _import_pfx_to_disk_cleanup(correlationId, keyId, out, title, loc, true);
        return STATUS_FAILED;
    }

    if (BIO_write(out, keyId, keyIdLength) != keyIdLength) {
        loc = "BIO_write";
        _import_pfx_to_disk_cleanup(correlationId, keyId, out, title, loc, true);
        return STATUS_FAILED;
    }

    BIO_flush(out);
    _import_pfx_to_disk_cleanup(correlationId, keyId, out, title, NULL, false);
    return STATUS_OK;
}

static int _handle_service_p8_compatible(
    uuid_t correlationId, 
    KEYISO_KEY_CTX **keyCtx,
    unsigned char *pfxBytes, 
    int pfxLength, 
    const char  *clientData,    // Base64 encoded string
    bool isKeyP8Compatible, 
    const char *title)
{
    if (!isKeyP8Compatible) {
        KEYISOP_trace_log_error(correlationId, KEYISOP_TRACELOG_WARNING_FLAG, title, "",
                          "Opening an encrypted keyid from the legacy version with service that can support pkcs#8 key with symcrypt FIPS compliant lib - if not instructed to work in legacy mode, please re-import/re-generate the key with new service");
        return KeyIso_CLIENT_pfx_open(correlationId, pfxLength, pfxBytes, clientData, keyCtx); // BC flow (SALT)
    } else {
        if (g_config.isLegacyMode) {
            KEYISOP_trace_log_error(correlationId, KEYISOP_TRACELOG_WARNING_FLAG, title, "",
                          "Opening an encrypted keyid from the new version when legacy mode is set is not recommended");
        }
        return KeyIso_CLIENT_private_key_open_from_pfx(correlationId, pfxLength, pfxBytes, clientData, keyCtx); // Base64 encoded client data
    }
}

static int _handle_service_not_p8_compatible(
    uuid_t correlationId, 
    KEYISO_KEY_CTX **keyCtx,
    unsigned char *pfxBytes, 
    int pfxLength, 
    char *salt,
    bool isKeyP8Compatible, 
    const char *title)
{
    if (isKeyP8Compatible) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Not supported",
                                "Trying to open pkcs#8 new version key with service that is not supporting such key - please update the service or import the key with current service");
        return STATUS_FAILED;
    } else {
        return KeyIso_CLIENT_pfx_open(correlationId, pfxLength, pfxBytes, salt, keyCtx);
    }
}

int KeyIso_open_key_by_compatibility(
    uuid_t correlationId, 
    KEYISO_KEY_CTX **keyCtx,
    unsigned char *pfxBytes, 
    int pfxLength, 
    char *clientData,
    bool isKeyP8Compatible, 
    bool isServiceP8Compatible)
{
    const char *title = KEYISOP_ENGINE_TITLE;

    if (isServiceP8Compatible) {
        return _handle_service_p8_compatible(correlationId, keyCtx, pfxBytes, pfxLength, clientData, isKeyP8Compatible, title);
    } else {
        return _handle_service_not_p8_compatible(correlationId, keyCtx, pfxBytes, pfxLength, clientData, isKeyP8Compatible, title); // BC flow (SALT)
    }
}

static int _load_public_key_from_clientdata(
    const uuid_t correlationId,
    const char *title,
    KEYISO_KEY_CTX *keyCtx,
    EVP_PKEY **outPKey)
{
    if (!keyCtx || !outPKey) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid parameters", "NULL keyCtx or outPKey");
        return STATUS_FAILED;
    }
    *outPKey = NULL;
    
    // P8 compatible mode - load from client data structure
    KEYISO_KEY_DETAILS *keyDetails = keyCtx->keyDetails;
    if (!keyDetails) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Missing key details", "NULL keyDetails");
        return STATUS_FAILED;
    }
    
    KEYISO_CLIENT_DATA_ST *clientDataSt = keyDetails->clientData;
    if (!clientDataSt || !clientDataSt->pubKeyLen) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Missing public key", "NULL clientDataSt or pubKey");
        return STATUS_FAILED;
    }
    
    if (KeyIso_decode_public_key_asn1(clientDataSt->pubKeyBytes, clientDataSt->pubKeyLen, outPKey) != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Failed to decode public key", "KeyIso_decode_public_key_asn1 failed");
        return STATUS_FAILED;
    }
    
    return STATUS_OK;
}

int KeyIso_load_public_key_by_compatibility(
    const uuid_t correlationId,
    KEYISO_KEY_CTX *keyCtx, 
    int isKeyP8Compatible,
    int pfxLength,
    unsigned char *pfxBytes,
    EVP_PKEY **outPKey,
    X509 **outPCert,
    STACK_OF(X509) **outCa)
{
    const char *title = KEYISOP_HELPER_PFX_TITLE;
    KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "", "isKeyP8Compatible: %d", isKeyP8Compatible);
	
    // New keyId - public key is encoded in the keyId as asn1
    if (isKeyP8Compatible) {
        X509 *keyCert = NULL;
        int pubKeyResult = STATUS_FAILED;
        
        if (outPCert) {
            *outPCert = NULL;
        }
        if (outCa) {
            *outCa = NULL;
        }
        
        
        if (!KeyIsoP_load_pfx_certs(correlationId, pfxLength, pfxBytes, &keyCert, outCa)) {
            KEYISOP_trace_log_error(correlationId, 0, title, "Failed to load PFX certificates", "KeyIsoP_load_pfx_certs failed");
            return STATUS_FAILED;
        }
        
        // Try to load the public key from client data
        pubKeyResult = _load_public_key_from_clientdata(correlationId, title, keyCtx, outPKey);
        if (pubKeyResult != STATUS_OK) {
            // If public key loading fails, clean up the certificate we loaded
            X509_free(keyCert);
            if (outCa && *outCa) {
                sk_X509_pop_free(*outCa, X509_free);
                *outCa = NULL;
            }
            return pubKeyResult;
        }
        
        // Success - transfer certificate ownership to caller
        if (outPCert) {
            *outPCert = keyCert;
            keyCert = NULL;  // Transfer ownership to caller, don't free it
        } else {
            X509_free(keyCert);  // Only free if caller doesn't want it
            keyCert = NULL;
        }
        
        return STATUS_OK;
        
    } else { // Legacy key - public key is in the PFX's cert
        return KeyIso_load_pfx_pubkey(correlationId, pfxLength, pfxBytes, outPKey, outPCert, outCa);
    }
}

int KeyIso_encode_public_key_asn1(
    EVP_PKEY *pkey,
    unsigned char **outBytes,
    uint32_t *outLen)
{
    if (!pkey || !outBytes || !outLen)
        return STATUS_FAILED;

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
        return STATUS_FAILED;

    if (!i2d_PUBKEY_bio(bio, pkey)) {
        BIO_free(bio);
        return STATUS_FAILED;
    }

    BUF_MEM* bptr = NULL;
    BIO_get_mem_ptr(bio, &bptr);
    if (!bptr || !bptr->data || bptr->length <= 0) {
        BIO_free(bio);
        return STATUS_FAILED;
    }   

    *outBytes = KeyIso_zalloc(bptr->length);
    if (!*outBytes) {
        BIO_free(bio);
        return STATUS_FAILED;
    }

    memcpy(*outBytes, bptr->data, bptr->length);
    if (bptr->length > UINT32_MAX) {
        KeyIso_clear_free(*outBytes, bptr->length);
        BIO_free(bio);
        return STATUS_FAILED;
    }

    *outLen = (uint32_t)bptr->length; // Ensure that outLen is set to the correct length


    BIO_free(bio);
    return STATUS_OK;
}

int KeyIso_decode_public_key_asn1(
    unsigned char *inBytes,
    uint32_t intLen,
    EVP_PKEY **outPkey) 
{
    const char *title = KEYISOP_KEY_TITLE;
    if (!inBytes || !intLen || !outPkey) {
        KEYISOP_trace_log_error_para(NULL, 0, title, "Invalid input", "inBytes or intLen or outPkey is NULL", "intLen: %u", intLen);
        return STATUS_FAILED;
    }

    // Clear ossl error queue
    ERR_clear_error();

    BIO *bio = BIO_new_mem_buf(inBytes, intLen);
    if (!bio) {
        KEYISOP_trace_log_openssl_error(NULL, 0, title, "Failed to create BIO - BIO_new_mem_buf returned NULL");
        return STATUS_FAILED;
    }

    EVP_PKEY *pkey = d2i_PUBKEY_bio(bio, NULL);
    BIO_free(bio);

    if (!pkey) {
        KEYISOP_trace_log_openssl_error(NULL, 0, title, "Failed to decode public key - d2i_PUBKEY_bio returned NULL");
        return STATUS_FAILED;
    }

    *outPkey = pkey;
    return STATUS_OK;
}


int KeyIso_copy_client_data(
    const uuid_t correlationId,
    uint8_t serviceVersion,       // The version of the service that created the key
    uint16_t isolationSolution,  // The isolation solution of the service that created the key
    uint32_t pubKeyLen,
    const uint8_t *pubKeyBytes,
    KEYISO_CLIENT_DATA_ST **outClientData) 
{
    if (!outClientData) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "Invalid input", "outClientData is NULL");
        return STATUS_FAILED;
    }

    // check that pubKeyLen matches pubKeyBytes
    if ((pubKeyLen > 0 && pubKeyBytes == NULL) || (pubKeyLen == 0 && pubKeyBytes != NULL)) {
        KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "", "Public key and pubKeyBytes don't match", "pubKeyLen: %u", pubKeyLen);
        return STATUS_FAILED;
    }
    
    size_t clientDataLen = GET_DYNAMIC_STRUCT_SIZE(KEYISO_CLIENT_DATA_ST, pubKeyLen);
    KEYISO_CLIENT_DATA_ST *clientData = (KEYISO_CLIENT_DATA_ST *) KeyIso_zalloc(clientDataLen);
    if (clientData == NULL) {
        return STATUS_FAILED;
    }
    
    clientData->keyIdHeader.clientVersion = KEYISOP_CURRENT_VERSION; // Current client version
    clientData->keyIdHeader.keyType = KmppKeyIdType_asymmetric;             // Asymmetric key
    clientData->keyIdHeader.keyServiceVersion = serviceVersion;
    clientData->keyIdHeader.isolationSolution = isolationSolution;
    
    clientData->pubKeyLen = pubKeyLen;
    if (pubKeyLen > 0 && pubKeyBytes != NULL) {
        memcpy(clientData->pubKeyBytes, pubKeyBytes, pubKeyLen);
    }

    *outClientData = clientData;
    return STATUS_OK;
}


static EVP_PKEY* _cleanup_get_rsa_pub_key(
    EVP_PKEY *pubKey,
    const char *loc,
    const uuid_t correlationId,
    BIGNUM *rsaN,
    BIGNUM *rsaE,
    unsigned char *nBytes,
    unsigned char *eBytes)
{
    if (pubKey == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_GEN_KEY_TITLE, loc, NULL);
    }

    if(nBytes)
        KeyIso_free(nBytes);
    if(eBytes)
        KeyIso_free(eBytes);

    if(rsaN)
        BN_free(rsaN);
    if(rsaE)
        BN_free(rsaE);
        
    return pubKey;
}

#define _CLEANUP_GET_RSA_PUB(pubKey, loc) \
    _cleanup_get_rsa_pub_key(pubKey, loc, correlationId, rsaN, rsaE, nBytes, eBytes)

// Extracts the public key component from an RSA private key
EVP_PKEY* KeyIso_get_rsa_public_key(
    const uuid_t correlationId,
    const EVP_PKEY *privKey) 
{
    BIGNUM *rsaN = NULL;
    BIGNUM *rsaE = NULL;
    EVP_PKEY *pubKey = NULL;
    unsigned char *nBytes = NULL, *eBytes = NULL;
    
    if (privKey == NULL) {
        return NULL;
    }
    
    if (KeyIso_get_rsa_params(privKey, &rsaN, &rsaE, NULL, NULL) != STATUS_OK) {
        return _CLEANUP_GET_RSA_PUB(NULL, "Failed to get RSA parameters");
    }

    // Convert BIGNUMs to byte arrays
    size_t nLen = BN_num_bytes(rsaN);
    size_t eLen = BN_num_bytes(rsaE);
    
    nBytes = KeyIso_zalloc(nLen);
    eBytes = KeyIso_zalloc(eLen); 
    if (nBytes == NULL || eBytes == NULL) {
        return _CLEANUP_GET_RSA_PUB(NULL, "Memory allocation failed");
    }

    if (BN_bn2bin(rsaN, nBytes) <= 0 || BN_bn2bin(rsaE, eBytes) <= 0) {
        return _CLEANUP_GET_RSA_PUB(NULL, "Failed to convert BIGNUM to native padded byte array");
    }

    // Create public key from components
    if ((pubKey = KeyIso_get_rsa_evp_pub_key(correlationId, nBytes, nLen, eBytes, eLen)) == NULL) {
        return _CLEANUP_GET_RSA_PUB(NULL, "Failed to create public key");
    }

    return _CLEANUP_GET_RSA_PUB(pubKey, NULL);
}

/* CB-CHANGES: Once ECC support is added to the providers, this function will be moved to keyisoclienteng.c,
 * and the implementation in keyisoclientprov.c will be enabled.
 */
//Extracts the public key component from an EC private key.
EVP_PKEY* KeyIso_get_ec_public_key(const uuid_t correlationId, const EVP_PKEY *privKey)
{
    const EC_KEY *ecPriv = NULL;
    EC_KEY *ecPub = NULL;
    EVP_PKEY *pubKey = NULL;
    const EC_GROUP *group = NULL;
    const EC_POINT *pubPoint = NULL;

    if (!privKey) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "privKey", "NULL input");
        return NULL;
    }

    if ((ecPriv = EVP_PKEY_get0_EC_KEY((EVP_PKEY *)privKey)) == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "EVP_PKEY_get0_EC_KEY", "Failed");
        return NULL;
    }

    if((group = EC_KEY_get0_group(ecPriv)) == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "EC_KEY_get0_group", "Failed");
        return NULL;
    }

    if ((pubPoint = EC_KEY_get0_public_key(ecPriv)) == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "EC_KEY_get0_public_key", "Failed");
        return NULL;
    }

    if ((ecPub = EC_KEY_new()) == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "EC_KEY_new", "Failed");
        return NULL;
    }

    if (EC_KEY_set_group(ecPub, group) != 1) {
        EC_KEY_free(ecPub);
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "EC_KEY_set_group", "Failed");
        return NULL;
    }

    if (EC_KEY_set_public_key(ecPub, pubPoint) != 1) {
        EC_KEY_free(ecPub);
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "EC_KEY_set_public_key", "Failed");
        return NULL;
    }

    if ((pubKey = EVP_PKEY_new()) == NULL) {
        EC_KEY_free(ecPub);
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "EVP_PKEY_new", "Failed");
        return NULL;
    }

    if (EVP_PKEY_assign_EC_KEY(pubKey, ecPub) != 1) {
        EVP_PKEY_free(pubKey);
        EC_KEY_free(ecPub);
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_IMPORT_KEY_TITLE, "EVP_PKEY_assign_EC_KEY", "Failed");
        return NULL;
    }

    // ecPub ownership transferred to pubKey
    return pubKey;
}

void KeyIso_add_key_to_keys_in_use(
    uuid_t correlationId,
    KEYISO_KEY_CTX *keyCtx,
    EVP_PKEY *pKey)
{
    if (!keyCtx) {
        KEYISOP_trace_log_error(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_KEY_TITLE, "Invalid input", "keyCtx is NULL");
        return;
    }
    if (!pKey) {
        KEYISOP_trace_log_error(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_KEY_TITLE, "Invalid input", "pKey is NULL");
        return;
    }

    keyCtx->keysInUseCtx = NULL;

    if (g_keysinuse.isLibraryLoaded) {
        int encodedPubKeyLen = 0;
        unsigned char *encodedPubKey = NULL;
        // Encode the public key to DER format - needed for the KeysInUse library to load the key
        encodedPubKeyLen = i2d_PublicKey(pKey, &encodedPubKey);

        if (encodedPubKeyLen <= 0 || !encodedPubKey) {
            KEYISOP_trace_log_error(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_KEY_TITLE, "Encoding public key for KIU using i2d_PublicKey", "failed");            
            if (encodedPubKey) {
                KeyIso_free(encodedPubKey);
                encodedPubKey = NULL;
            }
            return;
        }

        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_KEY_TITLE, "Loading key to KeysInUse functionality");
        keyCtx->keysInUseCtx = g_keysinuse.load_key_func(encodedPubKey, encodedPubKeyLen);

        if (encodedPubKey) {
            KeyIso_free(encodedPubKey);
            encodedPubKey = NULL;
        }

         if (keyCtx->keysInUseCtx) {
            char *keyIdentifier = NULL;
            // First call to get_key_identifier_func with NULL buffer to determine required length
            unsigned int keyIdentifierLen = g_keysinuse.get_key_identifier_func(keyCtx->keysInUseCtx, NULL, 0);
            if (keyIdentifierLen > 0) {
                keyIdentifier = KeyIso_zalloc(keyIdentifierLen);
                if (keyIdentifier) {
                    // Second call to get_key_identifier_func with allocated buffer to retrieve actual data
                    if (g_keysinuse.get_key_identifier_func(keyCtx->keysInUseCtx, keyIdentifier, keyIdentifierLen) != 0) {
                        KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_KEY_TITLE, "keysinuse_ctx_get_key_identifier", "Key identifier loaded to KeysInUse library: %s", keyIdentifier);
                    }
                    KeyIso_free(keyIdentifier);
                }
            }
        } else {
            KEYISOP_trace_log_error(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_KEY_TITLE, "Failed to load key to KeysInUse library", "keysInUseCtx is NULL");
        }
    }    
}