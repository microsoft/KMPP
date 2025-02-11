/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <string.h>
#include <stdbool.h>

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/engine.h>

#include "keyisocommon.h"
#include "keyisoclientinternal.h"
#include "keyisoclientmsghandler.h"
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
#define VERSION_CHAR 'n'
#define EXTRA_DATA_DELIMITER ':'
#define MIN_EXTRA_DATA_LENGTH  sizeof(KEYISO_ENCRYPTION_EXTRA_DATA_HEADER_ST)
#define MAX_EXTRA_DATA_LENGTH  (sizeof(KEYISO_KMPP_SERVICE_EXTRA_DATA_ST) + KEYISO_SECRET_SALT_STR_BASE64_LEN)

#ifdef KMPP_GENERAL_PURPOSE_TARGET
#define KMPP_MIN_SERVICE_VERSION KEYISOP_VERSION_3
#else
#define KMPP_MIN_SERVICE_VERSION KEYISOP_VERSION_1
#endif

extern CLIENT_MSG_HANDLER_FUNCTIONS_TABLE_ST g_msgHandlerImplementation;
extern KEYISO_CLIENT_CONFIG_ST g_config;

int static _base64_encode_data(const uuid_t correlationId,
                               const char *title,
                               size_t inBuffLength,
                               unsigned char *inBuffer,
                               uint32_t *outBuffLength,
                               unsigned char **outBuff)
{
     // Base64 encode the extraData
    int base64Length = KEYISOP_BASE64_ENCODE_LENGTH(inBuffLength);
    
    // Allocate memory for the Base64 encoded extra data
    unsigned char* base64Data = (unsigned char*)KeyIso_zalloc(base64Length); 
    if (base64Data == NULL) {
        // Allocation failed
        return STATUS_FAILED;
    }
    // Encode the data
    int encodeLength = EVP_EncodeBlock(base64Data, inBuffer, inBuffLength);
    if (encodeLength != base64Length - 1) {
        KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, "EVP_EncodeBlock", "length: %d expected: %d", encodeLength, base64Length - 1);
        KeyIso_clear_free(base64Data, encodeLength);
        return STATUS_FAILED;
    }
    // Set output parameters
    *outBuff = base64Data;
    *outBuffLength = base64Length;
    return STATUS_OK;

}

static int _cleanup_get_default_isolation_extra_data_buff(
    int status,
    KEYISO_KMPP_SERVICE_EXTRA_DATA_ST *extraData,
    size_t extraDataLength,
    unsigned char *buffer,
    uint32_t buffSize)
{
    KeyIso_clear_free(extraData, extraDataLength);
    KeyIso_clear_free(buffer, buffSize);
    return status;
}

int static _get_kmpp_service_isolation_extra_data_buff(const uuid_t correlationId,
                                                  const char *salt,
                                                  const KeyIsoKeyType keyType,
                                                  unsigned char **outBuff,
                                                  uint32_t *outBuffLength)
{
    const char *title = KEYISOP_HELPER_PFX_TITLE;
    unsigned char* buffer = NULL;
    uint32_t buffSize = 0;
    KEYISO_KMPP_SERVICE_EXTRA_DATA_ST* extraData = NULL;
    int res = STATUS_FAILED;
    size_t extraDataLength = 0;
    size_t saltLength = 0;
    size_t offset = 0;

    // In case of pfx key type, the salt is mandatory(for symmetric key type, salt is not passed)
     if (keyType == KeyIsoKeyType_pfx && (salt == NULL || *salt == '\0')) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid parameter", "salt cant be null or empty");
        return STATUS_FAILED;
    }

    if (outBuff == NULL || outBuffLength == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid parameter", "outBuff or outBuffLength cant be null");
        return STATUS_FAILED;
    }

    *outBuff = NULL;
    *outBuffLength = 0;

    if (salt) { // when key type is symmetric, salt is not passed, in pfx the salt is mandatory and already validated above
        saltLength = strlen(salt) + 1; // +1 for the null-terminator
        if (saltLength != KEYISO_SECRET_SALT_STR_BASE64_LEN) {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "Invalid parameter", "salt length invalid", "size:%lu", saltLength);
            return STATUS_FAILED;
        }
    }

    extraDataLength = sizeof(*extraData) + saltLength;
    extraData = (KEYISO_KMPP_SERVICE_EXTRA_DATA_ST *)KeyIso_zalloc(extraDataLength);
    if (extraData == NULL) {
        // Allocation failed
        return STATUS_FAILED;
    }

    extraData->header.version = KEYISOP_CURRENT_VERSION;
    extraData->header.solutionType = g_config.solutionType;
    extraData->saltLength = saltLength;
    if (saltLength > 0) {
        memcpy(extraData->salt, salt, saltLength);
    }
    
    buffSize = sizeof(*extraData) + saltLength;
    buffer = (unsigned char*)KeyIso_zalloc(buffSize); 
    if (buffer == NULL) {
        // Allocation failed
        KeyIso_clear_free(extraData, extraDataLength);
        return STATUS_FAILED;
    }

    memcpy(buffer, &(extraData->header), sizeof(extraData->header));
    offset += sizeof(extraData->header);
    memcpy(buffer + offset, &(extraData->saltLength), sizeof(extraData->saltLength));
    offset += sizeof(extraData->saltLength);

    memcpy(buffer + offset, extraData->salt, saltLength);
    offset += saltLength;

   
    res = _base64_encode_data(correlationId, title, buffSize, buffer, outBuffLength, outBuff);
    return _cleanup_get_default_isolation_extra_data_buff(res, extraData, extraDataLength, buffer, buffSize);
}

static int  _get_generic_isolation_extra_data_buff(const uuid_t correlationId,
                                                  unsigned char **outBuff,
                                                  uint32_t *outBuffLength)
{
    // Isolation solution that has no data except the header
   const char *title = KEYISOP_HELPER_PFX_TITLE;
   unsigned char* buffer = NULL;
   uint32_t buffSize = 0;
   KEYISO_ENCRYPTION_EXTRA_DATA_HEADER_ST extraData;
   int res = STATUS_FAILED;
   
   memset(&extraData, 0, sizeof(extraData));
   extraData.version = KEYISOP_CURRENT_VERSION;
   extraData.solutionType = g_config.solutionType;

   buffSize = sizeof(extraData);
   buffer = (unsigned char*)KeyIso_zalloc(buffSize); 
   memcpy(buffer, &extraData, buffSize);
   res = _base64_encode_data(correlationId, title, buffSize, buffer, outBuffLength, outBuff);
   KeyIso_clear_free(buffer, buffSize);
   return res;
}


static int _cleanup_format_engine_key_id(
    int status,
    char *id,
    size_t idLength,
    unsigned char *extraDataBuff,
    uint32_t extraDataBuffLength)
{
    if (status == STATUS_FAILED && id != NULL) {
        KeyIso_clear_free(id, idLength);
    }
    if (extraDataBuff != NULL) {
        KeyIso_clear_free(extraDataBuff, extraDataBuffLength);
    }
    return status;
}


// Format:         'n' <Base64 ExtraDataBuffer> ':' <Base64 PFX>
// Legacy Format:  <Salt> ":" <Base64 PFX> , salt first byte is '0' or 't'
static int _format_engine_key_id(
    const uuid_t correlationId,
    int keyLength,
    const unsigned char *keyBytes,
    const KeyIsoKeyType keyType,
    const char *salt, // With new version, the salt can be null
    char **keyId) // KeyIso_free()
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

    if (salt) {
        size_t saltLen = strlen(salt);
        if(saltLen != KEYISO_SECRET_SALT_STR_BASE64_LEN - 1)
        {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "Invalid parameter", "salt is invalid", "size:%lu", saltLen);
            return ret;
        }
    }

    if (keyType < 0 || keyType >= KeyIsoKeyType_max) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "Invalid parameter", "keyType is invalid", "type:%d", keyType);
        return ret;
    }

    size_t idLength = 0;
    unsigned int encodeLength;
    uint32_t extraDataBuffLength = 0;
    char *id = NULL; // KeyIso_free()
    unsigned char *extraDataBuff = NULL; // KeyIso_free()
    unsigned int base64Length = KEYISOP_BASE64_ENCODE_LENGTH(keyLength); // includes NULL terminator

    ERR_clear_error();

    if (g_config.solutionType == KeyIsoSolutionType_process || g_config.solutionType == KeyIsoSolutionType_tz) {
        ret = _get_kmpp_service_isolation_extra_data_buff(correlationId, salt, keyType, &extraDataBuff, &extraDataBuffLength);
    } else if(g_config.solutionType == KeyIsoSolutionType_tpm) {
        ret = _get_generic_isolation_extra_data_buff(correlationId, &extraDataBuff, &extraDataBuffLength);
    } else {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "Invalid configuration", "solutionType is invalid", "type:%d", g_config.solutionType);
        return _cleanup_format_engine_key_id(ret, id, idLength, extraDataBuff, extraDataBuffLength);
    }

    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, title, "format pfx", "Failed to get default extra data");
        return _cleanup_format_engine_key_id(ret, id, idLength, extraDataBuff, extraDataBuffLength);
    }

    // Calculate the length of the keyid
    // The new version keyid is:   n<base64ExtraDataBuff>:<base64Pfx>
    // We add 2 to extraDataBuffLength, one for the version char and one for the ':' delimiter
    idLength = extraDataBuffLength + base64Length + 2;
  
    // Allocate memory for id
    id = (char*)KeyIso_zalloc(idLength);
    if (id == NULL) {
        // Allocation failed
        return _cleanup_format_engine_key_id(ret, id, idLength, extraDataBuff, extraDataBuffLength);
    }

    // Format id
    id[0] = VERSION_CHAR; // First byte is 'n' for new versions 0 for legacy code , 't' for legacy testing 
                          // The first byte of the salt will still be 0 or 't' in new version , it will just be inside the extra data struct
    unsigned int offset = 1;
    memcpy((id + offset), extraDataBuff, extraDataBuffLength - 1);
    offset += extraDataBuffLength - 1; 
    id[offset] = EXTRA_DATA_DELIMITER;
    offset += 1;

    // Encode keyBytes to base64 and append to id
    encodeLength = EVP_EncodeBlock((unsigned char*)(id + offset), keyBytes, keyLength);
    if (encodeLength != base64Length - 1) {
        KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, "EVP_EncodeBlock",
                                             "length: %d expected: %d", encodeLength, base64Length - 1);
        return _cleanup_format_engine_key_id(ret, id, idLength, extraDataBuff, extraDataBuffLength);
    }

    // Set output parameter and return success
    *keyId = id;
    ret = STATUS_OK;
    return _cleanup_format_engine_key_id(ret, id, idLength, extraDataBuff, extraDataBuffLength);
}

static bool _is_service_supporting_p8_keys(const uuid_t correlationId)
{
    // This function is used to check if the service supports PKCS8 keys, it retrieves the current service version to do so
    int p8Compatible = KeyIso_validate_current_service_compatibility_mode(correlationId, KeyisoCompatibilityMode_pkcs8);
    return p8Compatible == PKCS8_COMPATIBLE;
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
    char **salt)                      // KeyIso_free()
{
    int ret = 0;
    const char *title = KEYISOP_IMPORT_PFX_TITLE;

    // Check that pfx size doesn't exceed the maximum
    if (inPfxLength > KMPP_MAX_MESSAGE_SIZE) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, NULL, "Pfx file is too big", "length: %d", inPfxLength);
        return ret;
    }
    
    // None p8Compatible - this is a backward compatibility code
    if (!_is_service_supporting_p8_keys(correlationId)){
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
            salt);
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
        salt);
    
    // Added metric to get an average size of PFXs before and after their provsioning to make "KMPP_MAX_MESSAGE_SIZE" more accurate 
    KEYISOP_trace_metric_para(correlationId, 0, g_config.solutionType, title, NULL, "PFX size %d, encrypted key size: %d", inPfxLength, *pfxLength);

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
    char *salt = NULL;                  // KeyIso_clear_free_string()

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
        &salt);
    if (ret != 0) {
        if (!KeyIso_format_pfx_engine_key_id(
                correlationId,
                outPfxLength,
                outPfxBytes,
                salt,
                keyId)) {
            ret = 0;
        }
    }

    KeyIso_free(outPfxBytes);
    KeyIso_clear_free_string(salt);
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

    *keyId = NULL;
 
    unsigned char internalImportKeyId[KMPP_AES_256_KEY_SIZE] = {0};
 
    if (inImportKeyId == NULL || memcmp(inImportKeyId, "", FIRST_BYTE) == 0) {
        KeyIso_rand_bytes(internalImportKeyId, KMPP_AES_256_KEY_SIZE);
    } else {
        memcpy(internalImportKeyId, inImportKeyId, KMPP_AES_256_KEY_SIZE);
    }

    status = KeyIso_CLIENT_import_symmetric_key(
            correlationId,
            inKeyLength,
            inKeyBytes,
            internalImportKeyId,
            &outKeyLength,
            &outKeyBytes);
    if (status != STATUS_FAILED) {
        status = _format_engine_key_id(
                    correlationId,
                    outKeyLength,
                    outKeyBytes,
                    KeyIsoKeyType_symmetric,
                    NULL,
                    (char **)keyId);
    }

    KeyIso_free(outKeyBytes);
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

    *verifyChainError = 0;
    *pemCertLength = 0;
    *pemCert = NULL;

    ret = KeyIso_parse_pfx_engine_key_id(
        correlationId,
        keyId,
        &pfxLength,
        &pfxBytes,
        NULL);          // salt
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

    return ret;
}

// Returns 1 for success and 0 for an error
int KeyIso_create_self_sign_pfx(
    const uuid_t correlationId,
    int keyisoFlags,
    const char *confStr,
    int *pfxLength,
    unsigned char **pfxBytes,        // KeyIso_free()
    char **pfxSalt)                  // KeyIso_free()
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
    
    if (!_is_service_supporting_p8_keys(correlationId)) {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_CREATE_SELF_SIGN_TITLE, "PKCS12 backward-compatibility");
        ret = (KeyIso_CLIENT_self_sign_pfx(
                correlationId,
                keyisoFlags,
                confStr,
                pfxLength,
                pfxBytes,
                pfxSalt) ? STATUS_OK : STATUS_FAILED);
        BIO_free(fileBio);
        return ret;
    }
    ret = KeyIso_CLIENT_create_self_sign_pfx_p8(
        correlationId,
        keyisoFlags,
        confStr,
        pfxLength,
        pfxBytes,
        pfxSalt);

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
    char *salt = NULL;                  // KeyIso_clear_free_string()

    *keyId = NULL;

    if (KeyIso_create_self_sign_pfx(
            correlationId,
            keyisoFlags,
            confStr,
            &pfxLength,
            &pfxBytes,
            &salt) != STATUS_OK) {
                goto end;
    }

    if (!KeyIso_format_pfx_engine_key_id(
            correlationId,
            pfxLength,
            pfxBytes,
            salt,
            keyId)) {
        goto end;
    }

    ret = 1;

end:
    KeyIso_free(pfxBytes);
    KeyIso_clear_free_string(salt);

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
    const char *inSalt,
    int pemCertLength,
    const unsigned char *pemCertBytes,
    int *outPfxLength,
    unsigned char **outPfxBytes,        // KeyIso_clear_free()
    char **outSalt)                    // KeyIso_clear_free_string()
{
    int ret = 0;

    *outSalt = NULL;
    
    // check for backward compatibility code
    if (!_is_service_supporting_p8_keys(correlationId)) {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_HELPER_PFX_TITLE, "PKCS12 backward-compatibility");
        ret = KeyIso_CLIENT_replace_pfx_certs(
            correlationId,
            keyisoFlags,
            inPfxLength,
            inPfxBytes,
            inSalt,
            pemCertLength,
            pemCertBytes,
            outPfxLength,
            outPfxBytes,
            outSalt);
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
        *outSalt = (char *) KeyIso_zalloc(strlen(inSalt) + 1);
        if (*outSalt != NULL)
            strcpy(*outSalt, inSalt);
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
    char *inSalt = NULL;                // KeyIso_clear_free_string()
    int outPfxLength = 0;
    unsigned char *outPfxBytes = NULL;  // KeyIso_free()
    char *outSalt = NULL;               // KeyIso_clear_free_string()

    *outKeyId = NULL;

    if (!KeyIso_parse_pfx_engine_key_id(
            correlationId,
            inKeyId,
            &inPfxLength,
            &inPfxBytes,
            &inSalt)) {
        goto end;
    }

    if (!KeyIso_replace_pfx_certs(
            correlationId,
            keyisoFlags,
            inPfxLength,
            inPfxBytes,
            inSalt,
            pemCertLength,
            pemCertBytes,
            &outPfxLength,
            &outPfxBytes,
            &outSalt)) {
        goto end;
    }

    if (!KeyIso_format_pfx_engine_key_id(
            correlationId,
            outPfxLength,
            outPfxBytes,
            outSalt,
            outKeyId)) {
        goto end;
    }

    ret = 1;

end:
    KeyIso_free(inPfxBytes);
    KeyIso_clear_free_string(inSalt);
    KeyIso_free(outPfxBytes);
    KeyIso_clear_free_string(outSalt);

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
    char *salt = NULL;                  // KeyIso_clear_free_string()
    
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
        &salt);
    if (ret != 0) {
        if (!KeyIso_format_pfx_engine_key_id(
                correlationId,
                outPfxLength,
                outPfxBytes,
                salt,
                keyId)) {
            ret = 0;
        }
    }

    KeyIso_free(outPfxBytes);
    KeyIso_clear_free_string(salt);
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
    char **salt)
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
            salt);
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
        ret = g_msgHandlerImplementation.rsa_private_encrypt_decrypt(keyCtx, operation, flen, from, tlen, to, padding);
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
    return _handle_rsa_crypto_operation(keyCtx, KEYISO_IPC_RSA_PRIV_ENCRYPT, flen, from, tlen, to, padding, KEYISOP_RSA_ENCRYPT_TITLE);
}

int KeyIso_CLIENT_rsa_private_decrypt(
    KEYISO_KEY_CTX *keyCtx,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding)
{
    return _handle_rsa_crypto_operation(keyCtx, KEYISO_IPC_RSA_PRIV_DECRYPT, flen, from, tlen, to, padding, KEYISOP_RSA_DECRYPT_TITLE);
}

int KeyIso_CLIENT_rsa_sign(
    KEYISO_KEY_CTX *keyCtx,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding)
{
    return _handle_rsa_crypto_operation(keyCtx, KEYISO_IPC_RSA_SIGN, flen, from, tlen, to, padding, KEYISOP_RSA_SIGN_TITLE);
}

int KeyIso_CLIENT_pkey_rsa_sign(
    KEYISO_KEY_CTX *keyCtx,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding)
{
    return _handle_rsa_crypto_operation(keyCtx, KEYISO_IPC_PKEY_SIGN, flen, from, tlen, to, padding, KEYISOP_PKEY_RSA_SIGN_TITLE);
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
    // The encrypted opened key is pkcs#8 compatable    
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

    KEYISOP_trace_log_para(correlationId, 0, title, "Start", "flags: 0x%x length: %d", keyisoFlags, inPfxLength);

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
        KEYISOP_trace_log(correlationId, 0, title, "Complete - Success");
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
    const char *title = KEYISOP_IMPORT_SYMMETRIC_KEY_TITLE;
    int status = STATUS_FAILED;
    uuid_t randId;

    if (correlationId == NULL) {
        KeyIso_rand_bytes(randId, sizeof(randId));
        correlationId = randId;
    }
    
    KEYISOP_trace_log_para(correlationId, 0, title, "Start", "length: %d, solutionType: %d, isDefaultConfig: %d", inKeyLength, g_config.solutionType, g_config.isDefault);

    ERR_clear_error();
            
    status = g_msgHandlerImplementation.import_symmetric_key(
        correlationId,
        KEYISO_IPC_SYMMETRIC_KEY_AES_CBC,
        inKeyLength,
        inKeyBytes,
        inImportKeyId,
        outKeyLength,
        outKeyBytes); 

    // Extract sha256 string out of the inImportKeyId for metric.
    char sha256HexHash[KMPP_AES_256_KEY_SIZE * 2 + 1]; // In asymmetric key import we take SHA256_DIGEST_LENGTH
    KeyIsoP_bytes_to_hex(KMPP_AES_256_KEY_SIZE, inImportKeyId, sha256HexHash);
    
    if (status != STATUS_OK) {  
        KEYISOP_trace_log_and_metric_error_para(correlationId, 0, g_config.solutionType, title, NULL, "Symmetric key import failed", "sha256:%s", sha256HexHash);

    } else {
        KEYISOP_trace_metric_para(correlationId, 0, g_config.solutionType, title, NULL, "Symmetric key import succeeded. sha256: %s", sha256HexHash);
        KEYISOP_trace_log(correlationId, 0, title, "Complete - Success");
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


int KeyIso_CLIENT_init_key_ctx(KEYISO_KEY_CTX *keyCtx, int keyLength, const unsigned char *keyBytes, const char *salt)
{    
    return g_msgHandlerImplementation.init_key(keyCtx, keyLength, keyBytes, salt);    
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

    KEYISOP_trace_log_para(correlationId, 0, title, "Start",
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

    KEYISOP_trace_log_para(correlationId, 0, title, "Start", "flags: 0x%x", keyisoFlags);

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

static bool _is_valid_extra_data_header(
    const uuid_t correlationId,
    KEYISO_ENCRYPTION_EXTRA_DATA_HEADER_ST* header)
{
    const char *title = KEYISOP_HELPER_PFX_TITLE;

    if (header->version < KEYISOP_PKCS8_MIN_VERSION) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, NULL, "Invalid version", "version: %hu,  min version that supports extra data: %u", header->version, KEYISOP_PKCS8_MIN_VERSION);
        return false;
    }

    if (header->solutionType != g_config.solutionType ) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, NULL, "The key is encrypted by a different isolation solution then is currently selected by config", 
                                     "key type: %d, config type: %d", header->solutionType, g_config.solutionType);
        return false;
    }

    return true;
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
    // KEYISO_SECRET_SALT_STR_BASE64_LEN takes in account a salt null terminator that in keyid is not present after the salt
    if (saltLength != KEYISO_SECRET_SALT_STR_BASE64_LEN - 1 ) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "failed to retrieve salt", "invalid salt length", "saltLength: %d, expected: %d", saltLength, KEYISO_SECRET_SALT_STR_BASE64_LEN);
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

static int _get_extra_data(const uuid_t correlationId,
                           uint32_t solutionType, 
                           uint32_t extraDataLength,
                           unsigned char *extraDataBuff,
                           char **outSalt)
{
    const char *title = KEYISOP_HELPER_PFX_TITLE;
    int ret = STATUS_FAILED;

    // Read the extra data based on the solution type
    switch (solutionType) {
        case KeyIsoSolutionType_process:
        case KeyIsoSolutionType_tz:
        {
            KEYISO_KMPP_SERVICE_EXTRA_DATA_ST* defaultSolutionExtraDataSt = (KEYISO_KMPP_SERVICE_EXTRA_DATA_ST*)KeyIso_zalloc(extraDataLength);
            memcpy(defaultSolutionExtraDataSt, extraDataBuff, extraDataLength);
            if (defaultSolutionExtraDataSt->saltLength == 0) {
                KEYISOP_trace_log_error_para(correlationId, 0, title, "Invalid salt length", "salt cant be null for this isolation type", "isolation type: %d", defaultSolutionExtraDataSt->header.solutionType);
                KeyIso_clear_free(defaultSolutionExtraDataSt, extraDataLength);
                return ret;
            }

            char *salt = (char*) KeyIso_zalloc(defaultSolutionExtraDataSt->saltLength + 1);
            if (salt == NULL) {
                // Allocation failed
                KeyIso_clear_free(defaultSolutionExtraDataSt, extraDataLength);
                return ret;
            }

            memcpy(salt, &defaultSolutionExtraDataSt->salt, defaultSolutionExtraDataSt->saltLength);
            salt[defaultSolutionExtraDataSt->saltLength] = '\0';
            *outSalt = salt;
            KeyIso_clear_free(defaultSolutionExtraDataSt, extraDataLength);
            return STATUS_OK;
        }
        case KeyIsoSolutionType_tpm:
        {
            // No need for extra data for TPM , only header that defines the version and solution type
            // TPM additional data that needed for opening the key is stored in the pkcs#8 
            return STATUS_OK;

        }
        default:
            KEYISOP_trace_log_error_para(correlationId, 0, title, "Invalid solutionType", "cant parse keyid", "solutionType: %d", solutionType);
            return ret;
    }
}

static int _get_salt(const uuid_t correlationId,
                        const char *keyId,
                        unsigned int encodedExtraDataLength,
                        char **outSalt) 
{   
    int ret = STATUS_FAILED;
    const char *title = KEYISOP_HELPER_PFX_TITLE;
    unsigned char *extraDataBuff = NULL;
    char *encodedExtraData = NULL;

    if (keyId[0] != VERSION_CHAR) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "Invalid first byte", "Invalid version char", "char: %c", keyId[0]);
        return ret;
    }

    if (!outSalt) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid parameter", "outSalt ptr cant be null");
        return ret;
    }

    *outSalt = NULL;
    
    encodedExtraData = (char *) KeyIso_zalloc(encodedExtraDataLength);
    if (encodedExtraData == NULL) {
        // Allocation failed
        return ret;
    }
    
    memcpy(encodedExtraData, keyId + 1, encodedExtraDataLength - 1); // Skip the 'n' version byte and the ':' delimiter
    encodedExtraData[encodedExtraDataLength - 1] = '\0';        
    
    int extraDataLength = KeyIso_base64_decode(correlationId, encodedExtraData, &extraDataBuff);
    // Free buffer after decoding
    KeyIso_clear_free(encodedExtraData, encodedExtraDataLength);
    encodedExtraData = NULL;

    if (!extraDataBuff ) {
        KEYISOP_trace_log_error(correlationId, 0, title, "KeyIso_base64_decode failed", "decoded buffer is null");
        return ret;
    }

    if (extraDataLength < sizeof(KEYISO_ENCRYPTION_EXTRA_DATA_HEADER_ST)) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "Invalid decoded data length", "buffer too short", "extraDataLength: %d", extraDataLength);
        KeyIso_clear_free(extraDataBuff, extraDataLength);
        return ret;
    }
    
    KEYISO_ENCRYPTION_EXTRA_DATA_HEADER_ST header;
    memset(&header, 0, sizeof(header));
    
    // Read the header from the buffer
    memcpy(&header, extraDataBuff, sizeof(KEYISO_ENCRYPTION_EXTRA_DATA_HEADER_ST));

    if (!_is_valid_extra_data_header(correlationId, &header)) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid keyid", "invalid extradata header");
        KeyIso_clear_free(extraDataBuff, extraDataLength);
        return ret;
    }

    ret = _get_extra_data(correlationId, header.solutionType, extraDataLength, extraDataBuff, outSalt);
    if (ret != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid keyid", "cant parse keyid");
        KeyIso_clear_free(extraDataBuff, extraDataLength);
        return ret;
    }

    KeyIso_clear_free(extraDataBuff, extraDataLength);
    return STATUS_OK;
}

static bool _is_legacy(const char *keyId)
{
    return (keyId && (keyId[0] != VERSION_CHAR));
}

static size_t _get_extra_data_max_limit(const char *keyId)
{
    bool isLegacy = _is_legacy(keyId);

    size_t maxLimit = isLegacy ?
                      KEYISO_SECRET_SALT_STR_BASE64_LEN :
                      KEYISOP_BASE64_ENCODE_LENGTH(MAX_EXTRA_DATA_LENGTH) + 1;
    return maxLimit;
}

static bool _is_only_file(const char *keyId, bool isSaltRequeued)
{ 
    size_t keyIdLen = strnlen(keyId, KEYISO_MAX_KEY_ID_LEN);
    size_t extraDataLimit = _get_extra_data_max_limit(keyId);
    size_t maxLengthToSearch = (extraDataLimit > keyIdLen) ? keyIdLen : extraDataLimit;

    const char *pfxStartPtr = memchr(keyId, EXTRA_DATA_DELIMITER, maxLengthToSearch);

    if (pfxStartPtr == NULL) {
        // There is no delimiter -> file name only
        return true;
    }
    
    size_t extraDataLength = pfxStartPtr - keyId;

    // If there is a need to return the salt we verify that the buffer after the delimiter is large enough to hold the salt(otherwise its a file name only)
    // Legacy: verifies That SaltLength > MIN_SALT_LENGTH 
    // New version: Verifies that extra data >= base64(sizeof (KEYISO_ENCRYPTION_EXTRA_DATA_HEADER_ST))

    size_t minLength = _is_legacy(keyId) ? 
                       KEYISO_SECRET_SALT_STR_BASE64_LEN - 1 : 
                       KEYISOP_BASE64_ENCODE_LENGTH(sizeof(KEYISO_ENCRYPTION_EXTRA_DATA_HEADER_ST));
    return  extraDataLength < minLength;
}

// New Format:  'n' <Base64 ExtraDataBuffer> ':' <Base64 PFX>
// Legacy Format:  <Salt> ":" <Base64 PFX> , salt first byte is '0' or 't'
int KeyIso_parse_pfx_engine_key_id(
    const uuid_t correlationId,
    const char *keyId,
    int *pfxLength,
    unsigned char **pfxBytes,        // KeyIso_clear_free()
    char **salt)                     // Optional, KeyIso_clear_free_string()
{
    const char *title = KEYISOP_HELPER_PFX_TITLE;
    BIO *fileBio = NULL;
    const char *pfxStr = NULL;  // Don't free
    int ret = STATUS_FAILED;
    
    ERR_clear_error();

    if(keyId == NULL || pfxLength == NULL || pfxBytes == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title,  "Invalid parameter", "cant be null");
        return ret;
    }

    *pfxLength = 0;
    *pfxBytes = NULL;
    if (salt) {
        *salt = NULL;
    }

    if (strncmp(keyId, "file:", 5) == 0) {
        char *fileString = NULL;        // don't free

        fileBio = KeyIsoP_read_file_string(correlationId, keyId + 5, 0, &fileString);

        if (fileBio == NULL) {
            goto end;
        }
        keyId = fileString;
    } else {

        bool isSaltRequeued = salt != NULL;
        int onlyFilename = _is_only_file(keyId, isSaltRequeued);
        char *fileString = NULL;        // don't free

        fileBio = KeyIsoP_read_file_string(correlationId, keyId, !onlyFilename, &fileString);
        if (fileBio == NULL) {
            if (onlyFilename) {
                goto end;
            }
        } else {
            keyId = fileString;
        }
    }
    size_t maxLengthToSearch = _get_extra_data_max_limit(keyId);
    pfxStr = memchr(keyId, EXTRA_DATA_DELIMITER, maxLengthToSearch);
    if (pfxStr == NULL) {
        // We are expected to return salt but the salt part keyid is empty
        if (salt) { 
            KEYISOP_trace_log_error(correlationId, 0, title, "strchr", "No salt");
            goto end;
        }
        pfxStr = keyId;
    } else {
        // There is extra data in the key id (salt for legacy)
        size_t extraDataLength = pfxStr - keyId;
        pfxStr++; // Skip the ':' delimiter
        if(salt) {
            if(_is_legacy(keyId)) {
                ret = _get_salt_legacy(correlationId, keyId, extraDataLength , salt);
                if (ret != STATUS_OK) {
                    KEYISOP_trace_log_error(correlationId, 0, title, "Legacy Salt Retrieve", "_parse_keyid_legacy Failed");
                    goto end;
                }
            } else {
                ret = _get_salt(correlationId, keyId, extraDataLength, salt);
                if (ret != STATUS_OK) {
                    KEYISOP_trace_log_error(correlationId, 0, title, "Salt Retrieve", "_parse_keyid Failed");
                    goto end;
                }
            }
        }
    }

    *pfxLength = KeyIso_base64_decode(correlationId, pfxStr, pfxBytes);
    if (*pfxLength <= 0) {
        ret = STATUS_FAILED;
        goto end;
    }

    ret = STATUS_OK;
end:
    if (!ret) {
        if(pfxBytes && *pfxBytes) {
            KeyIso_free(*pfxBytes);
            *pfxBytes = NULL;
        }
        if(pfxLength) {
            *pfxLength = 0;
        }
        
         if (salt && *salt) {
            KeyIso_clear_free_string(*salt);
            *salt = NULL;
        }
    }

    BIO_free(fileBio);
    return ret;
}

int KeyIso_format_pfx_engine_key_id(
    const uuid_t correlationId,
    int pfxLength,
    const unsigned char *pfxBytes,
    const char *salt, // With new version, the salt can be null
    char **keyId) // KeyIso_free()
{
    return _format_engine_key_id(correlationId, pfxLength, pfxBytes, KeyIsoKeyType_pfx, salt, keyId);
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
        // If the minumum version does not support FIPS and we must notifiy the user
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
    const char* loc)
{
    if (res != STATUS_OK) {
        KeyIso_clear_free(pRsaPkey, keySize);
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Error", loc);
        return NULL;
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
        return _cleanup_get_rsa_private_key(correlationId, STATUS_FAILED, NULL, 0, "Invalid argument, keysize ptr is NULL");
    }

    uint64_t pkeyDynamicLen = 0;
    uint32_t index = 0;
    uint8_t rsaUsage = KMPP_KEY_USAGE_INVALID;

    const BIGNUM *rsa_n = NULL; // Modulus
    const BIGNUM *rsa_e = NULL; // Public exponent
    const BIGNUM *rsa_p = NULL; // Prime1
    const BIGNUM *rsa_q = NULL; // Prime2

    size_t  rsa_n_len = 0; 
    size_t  rsa_e_len = 0;
    size_t  rsa_p_len = 0; 
    size_t  rsa_q_len = 0; 

    EVP_PKEY *evp_pkey = (EVP_PKEY *) inPkey;
    if (!evp_pkey || 
        (EVP_PKEY_id(evp_pkey) != EVP_PKEY_RSA &&
         EVP_PKEY_id(evp_pkey) != EVP_PKEY_RSA_PSS)) {
        return _cleanup_get_rsa_private_key(correlationId, STATUS_FAILED, NULL, 0, "Input key is not RSA");
    }
    const RSA *rsa = EVP_PKEY_get0_RSA(evp_pkey); // get0 doesn't up_ref
    if (rsa == NULL) {
        return _cleanup_get_rsa_private_key(correlationId, STATUS_FAILED, NULL, 0, "EVP_PKEY_get0_RSA failed");
    } 
    RSA_get0_key(rsa, &rsa_n, &rsa_e, NULL); // should not be freed by the caller
    if (rsa_n == NULL || rsa_e == NULL) {
        return _cleanup_get_rsa_private_key(correlationId, STATUS_FAILED, NULL, 0, "RSA_get0_key failed - Both RSA modulus and public exponent must be provided");
    }
    rsa_n_len = BN_num_bytes(rsa_n);
    rsa_e_len = BN_num_bytes(rsa_e);

    RSA_get0_factors(rsa, &rsa_p, &rsa_q);

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
        return _cleanup_get_rsa_private_key(correlationId, STATUS_FAILED, pRsaPkey, 0, "Failed to allocate rsa pkey");
    }
    *outKeySize = structSize;

    rsaUsage = _export_key_usage(evp_pkey);
    if (rsaUsage == KMPP_KEY_USAGE_INVALID) {
        return _cleanup_get_rsa_private_key(correlationId, STATUS_FAILED, pRsaPkey, structSize, "Failed to extract key usage from the EVP_PKEY object");
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
        return _cleanup_get_rsa_private_key(correlationId, STATUS_FAILED, pRsaPkey, structSize, "Failed to converts the modulus into big-endian");
    }
    index+= rsa_n_len;
    if (BN_bn2bin(rsa_e, &pRsaPkey->rsaPkeyBytes[index]) != rsa_e_len) {
        return _cleanup_get_rsa_private_key(correlationId, STATUS_FAILED, pRsaPkey, structSize, "Failed to converts the public exponent into big-endian");
    }
    index+= rsa_e_len;
    if (BN_bn2bin(rsa_p, &pRsaPkey->rsaPkeyBytes[index]) != rsa_p_len) {
        return _cleanup_get_rsa_private_key(correlationId, STATUS_FAILED, pRsaPkey, structSize, "Failed to converts prime1 into big-endian");
    }
    index+= rsa_p_len;
    if (BN_bn2bin(rsa_q, &pRsaPkey->rsaPkeyBytes[index]) != rsa_q_len) {
        return _cleanup_get_rsa_private_key(correlationId, STATUS_FAILED, pRsaPkey, structSize, "Failed to converts prime2 into big-endian");
    }
    index+= rsa_q_len;
    return _cleanup_get_rsa_private_key(correlationId, STATUS_OK, pRsaPkey, structSize, NULL);
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

// RSA Public Key
 EVP_PKEY* KeyIso_get_rsa_evp_pub_key(
    const uuid_t correlationId,
    const KEYISO_RSA_PUBLIC_KEY_ST* pPubKey) 
{
    int index = 0;
    RSA *rsa = RSA_new();

    ERR_clear_error();

    if (rsa == NULL) {
        return _cleanup_get_rsa_evp_pub_key(correlationId, STATUS_FAILED, NULL, "RSA_new filed");
    }
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        return _cleanup_get_rsa_evp_pub_key(correlationId, STATUS_FAILED, pkey, "EVP_PKEY_new filed");
    }
    
    BIGNUM* rsa_n = BN_bin2bn(pPubKey->rsaPubKeyBytes, pPubKey->rsaModulusLen, NULL);
    if (rsa_n == NULL) {
        return _cleanup_get_rsa_evp_pub_key(correlationId, STATUS_FAILED,  pkey, "filed to converts the modulus in big-endian");
    }

    index = pPubKey->rsaModulusLen;
    BIGNUM* rsa_e = BN_bin2bn(&pPubKey->rsaPubKeyBytes[index], pPubKey->rsaPublicExpLen, NULL);
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

bool KeyIso_is_equal_oid(const ASN1_OBJECT *oid, const char* expectedAlgOid)
{
    size_t oid_length = 0;
    size_t oid_txt_length = 0;
    bool isValid = false;

     if (!oid) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "Algorithm identifier", "Failed to get OID");
        return isValid;
    }

    oid_length = OBJ_length(oid);
    if (!oid_length) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "Algorithm identifier", "OID length is zero");
        return isValid;
    }
    
    // Calculating the length for the oid text buffer
    // OBJ_obj2txt returns the length of the string written to buf if buf is not NULL and buf_len is big enough, 
    // otherwise the total string length. Note that this does not count the trailing NUL character.
    oid_txt_length = OBJ_obj2txt(NULL, 0, oid, KMPP_OID_NO_NAME);
    char *oid_txt = (char *) KeyIso_zalloc(oid_txt_length + 1);
    if (!oid_txt) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "Memory allocation", "Failed");
        return isValid;
    }

    if (OBJ_obj2txt(oid_txt, oid_txt_length + 1, oid, KMPP_OID_NO_NAME) != oid_txt_length) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "OBJ_obj2txt", "Failed");
        KeyIso_free(oid_txt);
        return isValid;
    }
    
    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_OPEN_KEY_TITLE, "Algorithm parameters:algorithm identifier", "OID: %s", oid_txt);
    isValid = (strcmp(oid_txt, expectedAlgOid) == 0);
    KeyIso_free(oid_txt);
    return isValid;
}

const void* KeyIso_pbe_get_algor_param_asn1(const char* title, const X509_ALGOR *alg, const char* expectedAlgOid)
{
    int paramType = 0;
    const void* param =  NULL;
    const ASN1_OBJECT* oid = NULL;

    if (alg == NULL) {
        KEYISOP_trace_log_error(NULL, 0, title, "get PBE algorithm parameters", "invalid parameters");
        return NULL;
    }
    
    ERR_clear_error();

    X509_ALGOR_get0(&oid, &paramType, &param, alg);
    if (oid == NULL || param == NULL) {
        KEYISOP_trace_log_openssl_error(NULL, 0, title, "get PBE algorithm parameters - failed to get PBE algorithm parameters");
        return NULL;
    }
    
    if (paramType != V_ASN1_SEQUENCE) {
        KEYISOP_trace_log_error(NULL, 0, title, "get PBE algorithm parameters", "invalid parameter type");
        return NULL;
    }

    if(!KeyIso_is_equal_oid(oid, expectedAlgOid)) {
        KEYISOP_trace_log_error(NULL, 0, title, "get PBE algorithm parameters", "invalid oid");
        return NULL;
    }

    return param;
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
bool KeyIso_is_oid_pbe2(const uuid_t correlationId, const unsigned char *keyBytes, int keyLength)
{
    const char *title = KEYISOP_OPEN_KEY_TITLE;
    X509_SIG *sig = NULL;
    const X509_ALGOR *alg = NULL;
    int paramType = 0;
    const void* param = NULL;
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
    
    X509_ALGOR_get0(&oid, &paramType, &param, alg);
    if (oid == NULL || param == NULL) {
        return _cleanup_is_oid_pbe2(correlationId, ret, title, isError, "Failed to get PBE algorithm parameters", sig);
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