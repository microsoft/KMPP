/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once 
#include<stdarg.h>

#ifdef KEYISO_TEST_WINDOWS
typedef unsigned char uuid_t[16];
#else
#include <uuid/uuid.h>
#endif

#ifdef  __cplusplus
extern "C" {
#endif 

extern int KEYISOP_traceLogTest;
extern int KEYISOP_traceLogVerbose;
extern int KEYISOP_traceLogConstructor;

#define KEYISOP_TRACELOG_PARA_LENGTH       256
#define KEYISOP_TRACELOG_ERROR_LENGTH      256

#define KEYISOP_TRACELOG_VERBOSE_FLAG      0x1
#define KEYISOP_TRACELOG_WARNING_FLAG      0x2

#define KEYISOP_ENGINE_TITLE               "KMPPEngine"
#define KEYISOP_PROVIDER_TITLE             "KMPPProvider"
#define KEYISOP_SUPPORT_TITLE              "KMPPSupport"
#define KEYISOP_MEMORY_ALLOC_TITLE         "KMPPMemoryAlloc"
#define KEYISOP_IMPORT_PFX_TITLE           "KMPPImportPfx"
#define KEYISOP_IMPORT_SYMMETRIC_KEY_TITLE "KMPPImportSymmetricKey"
#define KEYISOP_CREATE_PFX_TITLE           "KMPPCreatePfx"
#define KEYISOP_OPEN_PFX_TITLE             "KMPPOpenPfx"
#define KEYISOP_CLOSE_PFX_TITLE            "KMPPClosePfx"
#define KEYISOP_HELPER_PFX_TITLE           "KMPPHelperPfx"
#define KEYISOP_PFX_SECRET_TITLE           "KMPPPfxSecret"
#define KEYISOP_TPM_SECRET_TITLE           "KMPPTpmSecret"
#define KEYISOP_IMPORT_TRUSTED_TITLE       "KMPPImportTrusted"
#define KEYISOP_REMOVE_TRUSTED_TITLE       "KMPPRemoveTrusted"
#define KEYISOP_ENUM_TRUSTED_TITLE         "KMPPEnumTrusted"
#define KEYISOP_IS_TRUSTED_TITLE           "KMPPIsTrusted"
#define KEYISOP_IMPORT_DISALLOWED_TITLE    "KMPPImportDisallowed"
#define KEYISOP_REMOVE_DISALLOWED_TITLE    "KMPPRemoveDisallowed"
#define KEYISOP_ENUM_DISALLOWED_TITLE      "KMPPEnumDisallowed"
#define KEYISOP_IS_DISALLOWED_TITLE        "KMPPIsDisallowed"
#define KEYISOP_VERIFY_CERT_TITLE          "KMPPVerifyCert"
#define KEYISOP_HELPER_CERT_TITLE          "KMPPHelperCert"
#define KEYISOP_CREATE_SELF_SIGN_TITLE     "KMPPCreateSelfSign"
#define KEYISOP_RSA_ENCRYPT_TITLE          "KMPPRsaEncrypt"
#define KEYISOP_RSA_DECRYPT_TITLE          "KMPPRsaDecrypt"
#define KEYISOP_RSA_SIGN_TITLE             "KMPPRsaSign"
#define KEYISOP_PKEY_RSA_SIGN_TITLE        "KMPPPkeyRsaSign"
#define KEYISOP_RSA_PKEY_ENC_DEC_TITE      "KMPPPkeyEncryptDecrypt"
#define KEYISOP_ECDSA_PKEY_SIGN_TITLE      "KMPPPkeyEcdsaSign"
#define KEYISOP_ECC_SIGN_TITLE             "KMPPEccSign"
#define KEYISOP_CURL_TITLE                 "KMPPCurl"
#define KEYISOP_TEST_TITLE                 "KMPPTest"
#define KEYISOP_SERVICE_TITLE              "KMPPService"
#define KEYISOP_GDBUS_CLIENT_TITLE         "KMPPGdbusClient"
#define KEYISOP_IPC_CLIENT_TITLE           "KMPPIPCClient"
#define KEYISOP_ERROR_STACK_TITLE          "KMPPErrorStack"
#define KEYISOP_READ_WRITE_VERSION_TITLE   "KMPPVersion"
#define KEYISOP_COMPATIBILITY_MODES_TITLE  "KMPPCompatibility"
#define KEYISOP_IMPORT_KEY_TITLE           "KMPPImportKey"
#define KEYISOP_OPEN_KEY_TITLE             "KMPPOpenKey"
#define KEYISOP_GEN_KEY_TITLE              "KMPPGenerateKey"
#define KEYISOP_ENC_KEY_TITLE              "KMPPEncryptedKey"
#define KEYISOP_KEY_TITLE                  "KMPPKey"
#define KEYISOP_SYMMETRIC_ENC_DEC_TITLE    "KMPPSymmetricEncDec"
#define KEYISOP_OPTEE_CLIENT_TITLE         "KMPPOpTeeClient"
#define KEYISOP_LOAD_LIB_TITLE             "KMPPLoadLib"
#define KEYISOP_CLIENT_CONFIG              "KMPPClientConfig"
#define KEYISOP_VALIDATE_KEY_TITLE         "KMPPValidateKeyId"
// TPM
#define KEYISOP_TPM_SESSION_TITLE              "KMPPTpmSession"
#define KEYISOP_TPM_KEY_TITLE                  "KMPPTpmKey"
#define KEYISOP_TPM_RSA_SIGN_TITLE             "KMPPTpmRsaSign"
#define KEYISOP_TPM_EPKEY_RSA_SIGN_TITLE       "KMPPTpmEvpEsaSign"
#define KEYISOP_TPM_ECDSA_SIGN_TITLE           "KMPPTpmEcdsaSign"
#define KEYISOP_TPM_RSA_PRIV_ENC_DEC_TITE      "KMPPTpmPrivateEncryptDecrypt"
#define KEYISOP_TPM_RSA_PRIV_ENC_TITLE         "KMPPTpmPrivateEncrypt"
#define KEYISOP_TPM_RSA_PRIV_DEC_TITLE         "KMPPTpmPrivateDecrypt"
#define KEYISOP_TPM_IMPORT_PRIV_KEY_TITLE      "KMPPTpmPrivateImportKey"
#define KEYISOP_TPM_GEN_KEY_TITLE              "KMPPTpmGenerateKey"
#define KEYISOP_TPM_KMPP_PBE_TITLE             "KMPPTpmPbe"
#define KEYISOP_TPM_OPEN_KEY_TITLE             "KMPPTpmOpenKey"
#define KEYISOP_TPM_IMPORT_PRIVATE_KEY_TITLE   "KMPPTpmImportPrivateKey"
#define KEYISOP_TPM_IMPORT_SYMMETRIC_KEY_TITLE "KMPPTpmImportSymmetricKey"
#define KEYISOP_TPM_SYMMETRIC_ENC_DEC_TITLE    "KMPPTpmSymmetricEncDec"
// Cache
#define KEYISOP_CACHE_TITLE                    "KMPPCache"
typedef enum {
    LogLevel_Error=3,
    LogLevel_Warning=4,
    LogLevel_Info=6,
    LogLevel_Debug=7
} LogLevel;

typedef void (*KeyIso_log_provider_ptr)(int, const char*);

// An internal API to redirect the trace log output from stdout to the specified file
void KeyIsoP_internal_set_trace_log_filename(
    const char *filename) ;

void _KeyIsoP_trace_log_output(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    const char *error,
    const char *paraFormat,
    va_list paraArgs);

void _KeyIsoP_trace_output(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    const char *error,
    const char *initialStr,
    const char *paraFormat,
    va_list paraArgs);

void _KeyIsoP_trace_log_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    const char *format, ...);
#define KEYISOP_trace_log_para(correlationId, flags, title, loc, ...) \
    _KeyIsoP_trace_log_para(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc, __VA_ARGS__)

void _KeyIsoP_trace_log(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc);
#define KEYISOP_trace_log(correlationId, flags, title, loc) \
    _KeyIsoP_trace_log(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc)

void _KeyIsoP_trace_log_error_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    const char *errStr,
    const char *format, ...);
#define KEYISOP_trace_log_error_para(correlationId, flags, title, loc, errStr,  ...) \
    _KeyIsoP_trace_log_error_para(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc, errStr, __VA_ARGS__)

void _KeyIsoP_trace_log_error(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    const char *errStr);
#define KEYISOP_trace_log_error(correlationId, flags, title, loc, errStr) \
    _KeyIsoP_trace_log_error(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc, errStr)

void _KeyIsoP_trace_log_openssl_error_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    const char *format, ...);
#define KEYISOP_trace_log_openssl_error_para(correlationId, flags, title, loc, ...) \
    _KeyIsoP_trace_log_openssl_error_para(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc, __VA_ARGS__)

void _KeyIsoP_trace_log_openssl_error(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc);
#define KEYISOP_trace_log_openssl_error(correlationId, flags, title, loc) \
    _KeyIsoP_trace_log_openssl_error(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc)

void _KeyIsoP_trace_log_openssl_verify_cert_error_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    int err,
    const char *format, ...);
#define KEYISOP_trace_log_openssl_verify_cert_error_para(correlationId, flags, title, loc, err, ...) \
    _KeyIsoP_trace_log_openssl_verify_cert_error_para(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc, err, __VA_ARGS__)

void _KeyIsoP_trace_log_openssl_verify_cert_error(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    int err);
#define KEYISOP_trace_log_openssl_verify_cert_error(correlationId, flags, title, loc, err) \
    _KeyIsoP_trace_log_openssl_verify_cert_error(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc, err)

void _KeyIsoP_trace_log_errno_para(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    int err,
    const char *format, ...);
#define KEYISOP_trace_log_errno_para(correlationId, flags, title, loc, err, ...) \
    _KeyIsoP_trace_log_errno_para(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc, err, __VA_ARGS__)

void _KeyIsoP_trace_log_errno(
    const char *file,
    const char *func,
    const int line,
    const uuid_t correlationId,
    const int flags,
    const char *title,
    const char *loc,
    int err);
#define KEYISOP_trace_log_errno(correlationId, flags, title, loc, err) \
    _KeyIsoP_trace_log_errno(__FILE__, __FUNCTION__, __LINE__, correlationId, flags, title, loc, err)

#ifdef  __cplusplus
}
#endif