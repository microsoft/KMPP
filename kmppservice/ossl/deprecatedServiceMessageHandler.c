/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/bio.h>

#include "deprecatedServiceMessageHandler.h"
#include "keyisoserviceapiossl.h"
#include "keyisocommon.h"
#include "keyisoservicecommon.h"
#include "keyisolog.h"
#include "keyisotelemetry.h"
#include "keyisomemory.h"
#include "keyisoctrl.h"
#include "keyisoservicekeylist.h"
#include "keyisoservicekeylistgdbus.h"
#include "keyisoserviceapi.h"
#include "keyisoservicecrypto.h"
#include "keyisoservicekey.h"
#include  "keyisoutils.h"

#include "kmppgdbusclient.h"
#include "kmppgdbusclientcommon.h"

static const PFN_rsa_operation KEYISO_SERVER_rsa_operations[] = 
{
    KeyIso_SERVER_rsa_private_encrypt_ossl,
    KeyIso_SERVER_rsa_private_decrypt_ossl,
    KeyIso_SERVER_rsa_sign_ossl,
    KeyIso_SERVER_pkey_rsa_sign_ossl
};

/* Functions that depend on both OSSL and Symcrypt. New key format support from old flow. */
EVP_PKEY* KeyIso_convert_kmpp_key_to_evp(
    const uuid_t correlationId,
    PKMPP_KEY pKmppKey)
{
    const char *title = KEYISOP_SERVICE_TITLE;
    EVP_PKEY *evpKey = NULL; // KeyIso_SERVER_free_key()
    if (pKmppKey == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "KeyIso_convert_kmpp_key_to_evp", "Invalid argument");
        return NULL;
    }

    if (pKmppKey->type == KmppKeyType_rsa) {
        PSYMCRYPT_RSAKEY pSymCryptRsaKey = (PSYMCRYPT_RSAKEY)pKmppKey->key;
        if (pSymCryptRsaKey) {
            evpKey = KeyIso_convert_symcrypt_rsa_to_epkey(correlationId, pSymCryptRsaKey);
            if (evpKey == NULL) {
                KEYISOP_trace_log_error(correlationId, 0, title, "KeyIso_convert_kmpp_key_to_evp", "Failed to convert SymCrypt RSA key to EVP_PKEY");
                return NULL;
            }
        }
    } else if (pKmppKey->type == KmppKeyType_ec) {
        PSYMCRYPT_ECKEY pSymCryptEckey = (PSYMCRYPT_ECKEY)pKmppKey->key;
        if (pSymCryptEckey) {
            evpKey = KeyIso_convert_symcrypt_ecc_to_epkey(correlationId, pSymCryptEckey);
            if (evpKey == NULL) {
                KEYISOP_trace_log_error(correlationId, 0, title, "KeyIso_convert_kmpp_key_to_evp", "Failed to convert SymCrypt EC key to EVP_PKEY");
                return NULL;
            }
        }
    } else {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "KeyIso_convert_kmpp_key_to_evp", "Invalid key type", "key type: %d", pKmppKey->type);
        return NULL;
    }    
    return evpKey;
}

static void _cleanup_new_keyresources(char* salt, X509_SIG* p8, KEYISO_ENCRYPTED_PRIV_KEY_ST* enKeySt, PKMPP_KEY pKmppKey, const uuid_t correlationId) 
{
    if (salt != NULL) {
        KeyIso_clear_free_string(salt);
    }
    if (p8 != NULL) {
        X509_SIG_free(p8);
    }
    if (enKeySt != NULL) {
        KeyIso_free(enKeySt); 
    }
    if (pKmppKey != NULL) {
        KeyIso_SERVER_free_key(correlationId, pKmppKey); // Free the KMPP key holding the SymCrypt key
    }
}

#define _CLEANUP_NEW_KEY_RESOURCES() \
    _cleanup_new_keyresources(salt, p8, enKeySt, pKmppKey, correlationId)

PKMPP_KEY KeyIso_get_kmpp_key_from_pfx_bytes(
    const unsigned char *correlationId,
    const char *inSalt, // Salt for old keys, n + extra data for new keys
    int pfxBytesLength,
    const unsigned char *pfxBytes)
{
    const char *title = KEYISOP_SERVICE_TITLE;
    EVP_PKEY *evpKey = NULL; // KeyIso_SERVER_free_key()
    if (inSalt == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "KeyIso_get_kmpp_key_from_pfx_bytes", "Invalid argument");
        return NULL;
    }

    if (pfxBytes == NULL || pfxBytesLength <= 0) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "KeyIso_get_kmpp_key_from_pfx_bytes", "Invalid argument", "pfxBytesLength: %d", pfxBytesLength);
        return NULL;
    }
    if (pfxBytesLength > KMPP_MAX_MESSAGE_SIZE) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "KeyIso_get_kmpp_key_from_pfx_bytes", "PFX size exceeds maximum allowed length", "pfxBytesLength: %d", pfxBytesLength);
        return NULL;
    }

    size_t inSaltLength = strnlen(inSalt, MAX_EXTRA_DATA_BASE64_LENGTH + 2); // +1 for n , +1 for null
    if (inSaltLength >= (MAX_EXTRA_DATA_BASE64_LENGTH + 2)) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "KeyIso_get_kmpp_key_from_pfx_bytes", "Salt exceeds maximum allowed length or is not null-terminated", "salt length: %d", inSaltLength);
        return NULL;
    }

    if (inSalt[0] == VERSION_CHAR) {
        /* An old client is trying to open a new new through the old PFX-based API. */
        X509_SIG *p8 = NULL;
        KEYISO_ENCRYPTED_PRIV_KEY_ST* enKeySt = NULL;
        PKMPP_KEY pKmppKey = NULL;              // KeyIso_SERVER_free_key() 
        char *salt = NULL;
        
        // 1. Extract the salt from the extra data
        if (!KeyIso_get_salt_from_keyid(correlationId, KeyIsoSolutionType_process, inSalt, inSaltLength, &salt)) {
            KEYISOP_trace_log_error(correlationId, 0, title, "Failed to determent key version", "Failed to get salt");
            _CLEANUP_NEW_KEY_RESOURCES();
            return NULL;
        }

        // 2. Extract the encrypted private key from the PFX
        if (!KeyIso_pkcs12_parse_p8(correlationId, pfxBytesLength, pfxBytes, &p8, NULL, NULL)) {
            KEYISOP_trace_log_error(correlationId, 0, title, "Failed to determent key version", "KeyIso_pkcs12_parse_p8 failed");
            _CLEANUP_NEW_KEY_RESOURCES();
            return NULL;
        }

        // 3. Convert the P8 to a KMPP encrypted key
        if (!KeyIso_create_enckey_from_p8(p8, &enKeySt)) {
            KEYISOP_trace_log_error(correlationId, 0, title, "Failed to determent key version", "KeyIso_create_enckey_from_p8 failed");
            _CLEANUP_NEW_KEY_RESOURCES();
            return NULL;
        }

        // 4. Open the private key holding the SymCrypt key
        if (!KeyIso_SERVER_open_private_key(correlationId, salt, enKeySt, &pKmppKey)) {
           KEYISOP_trace_log_error(correlationId, 0, title, "Failed to open private key", "KeyIso_SERVER_open_private_key failed");
           _CLEANUP_NEW_KEY_RESOURCES();
           return NULL;
        }

        // 5. Convert the return Symcrypt key to an EVP_PKEY
        evpKey = KeyIso_convert_kmpp_key_to_evp(correlationId, pKmppKey);
        if (evpKey == NULL) {
            KEYISOP_trace_log_error(correlationId, 0, title, "Failed to convert KMPP key to EVP_PKEY", "KeyIso_convert_kmpp_key_to_evp failed");
            _CLEANUP_NEW_KEY_RESOURCES();
            return NULL;
        }
        _CLEANUP_NEW_KEY_RESOURCES();

    }  else {
        /*  An old client is trying to open an old key through the old PFX-based API. */
        if (!KeyIso_SERVER_pfx_open(correlationId, pfxBytesLength, pfxBytes, inSalt, (void**)(&evpKey))) {
            KEYISOP_trace_log_error(correlationId, 0, title, "Failed to open private key", "KeyIso_SERVER_pfx_open failed");
            return NULL;
        }
    }
    return KeyIso_kmpp_key_create(correlationId, KmppKeyType_epkey, evpKey); // Create a KMPP key holding the EVP_PKEY
}

gboolean KeyIso_on_handle_import_pfx(
    GdbusKmpp *interface,
    GDBusMethodInvocation *invocation,
    GVariant *arg_correlationId,
    gint arg_version,
    gint arg_keyisoFlags,
    GVariant *arg_inPfxBytes,
    const gchar *arg_inPassword,
    gpointer user_data)
{
    const gchar *senderName = g_dbus_method_invocation_get_sender(invocation);
    const char *title = KEYISOP_SERVICE_TITLE;
    const char *loc = "";
    const char *errStr = "";
    gint code = G_DBUS_ERROR_FAILED;
    int ret = 0;
    int chainRet = 0;
    uuid_t correlationId;
    gsize correlationIdLength = 0;
    guchar *correlationIdBytes = NULL;      // don't free
    gsize inPfxBytesLength = 0;
    guchar *inPfxBytes = NULL;              // don't free
    int outVerifyChainError = 0;
    int outPfxLength = 0;
    unsigned char *outPfxBytes = NULL;      // KeyIso_free()
    char *outPfxSalt  = NULL;               // KeyIso_clear_free_string()
    size_t outPfxSaltLength = 0;
    size_t outLength = 0;
    unsigned char *outBytes = NULL;         // KeyIso_free()
    unsigned char *outNext = NULL;          // don't free()
    GVariant *outVariant = NULL;            // GDBUS_g_variant_unref()
    unsigned int pfxBytesStart = 0;

    correlationIdBytes = (guchar *) g_variant_get_fixed_array(arg_correlationId,
        &correlationIdLength,
        sizeof(guchar));
    if (correlationIdBytes != NULL && correlationIdLength == sizeof(correlationId)) {
        memcpy(correlationId, correlationIdBytes, sizeof(correlationId));
    } else {
        memset(correlationId, 0, sizeof(correlationId));
    }

    KEYISOP_trace_log_para(correlationId, 0, title, "Start", "sender: %s version: %d arg_keyisoFlags: %x", senderName, arg_version, arg_keyisoFlags);

    inPfxBytes = (guchar *) g_variant_get_fixed_array(arg_inPfxBytes,
        &inPfxBytesLength,
        sizeof(guchar));
    if (inPfxBytes == NULL || inPfxBytesLength == 0) {
        loc = "inPfxBytes";
        errStr = "InvalidArg";
        code = G_DBUS_ERROR_INVALID_ARGS;
        goto err;
    }
    
    chainRet = KeyIso_SERVER_import_pfx(
        correlationId,
        arg_keyisoFlags,
        (int) inPfxBytesLength,
        &inPfxBytes[pfxBytesStart],
        arg_inPassword,             // Optional
        &outVerifyChainError,
        &outPfxLength,
        &outPfxBytes,            // KeyIso_free()
        &outPfxSalt);            // KeyIso_free()
    if (chainRet == 0) {
        loc = "KeyIso_SERVER_import_pfx";
        goto end;
    }

    outPfxSaltLength = strlen(outPfxSalt) + 1;
    outLength = sizeof(outVerifyChainError) + outPfxSaltLength + outPfxLength;
    outBytes = (unsigned char *) KeyIso_zalloc(outLength);
    if (outBytes == NULL) {
        loc = "KeyIso_zalloc";
        code = G_DBUS_ERROR_NO_MEMORY;
        goto end;
    }

    outNext = outBytes;
    memcpy(outNext, &outVerifyChainError, sizeof(outVerifyChainError));
    outNext += sizeof(outVerifyChainError);
    memcpy(outNext, outPfxSalt, outPfxSaltLength);
    outNext += outPfxSaltLength;
    memcpy(outNext, outPfxBytes, outPfxLength);

    outVariant = g_variant_new_fixed_array(
        G_VARIANT_TYPE_BYTE,
        outBytes,
        (gsize) outLength,
        sizeof(*outBytes));
    if (outVariant == NULL) {
        loc = "outVariant";
        errStr = "OutOfMemory";
        code = G_DBUS_ERROR_NO_MEMORY;
        goto err;
    }

    ret = chainRet;
end:
    KeyIso_free(outPfxBytes);
    KeyIso_free(outBytes);
    KeyIso_clear_free_string(outPfxSalt);

    if (ret != 0) {
        if (ret < 0) {
            KEYISOP_trace_log_error(correlationId, 0, title, "Complete",
                "Import succeeded with certificate errors");
        } else {
            KEYISOP_trace_log(correlationId, 0, title, "Complete");
        }
        // The following does a g_variant_unref(outVariant);
        gdbus_kmpp_complete_import_pfx(interface, invocation, outVariant);
    } else {
        KEYISOP_trace_log_error(correlationId, 0, title, "Complete", "Import failed");
        g_dbus_method_invocation_return_error_literal(
            invocation, G_DBUS_ERROR, code, loc);
    }
    return TRUE;

err:
    KEYISOP_trace_log_error(correlationId, 0, title, loc, errStr);
    goto end;

}

gboolean KeyIso_on_handle_create_self_sign_pfx(
    GdbusKmpp *interface,
    GDBusMethodInvocation *invocation,
    GVariant *arg_correlationId,
    gint arg_version,
    gint arg_keyisoFlags,
    const gchar *arg_confStr,
    gpointer user_data)
{
    const gchar *senderName = g_dbus_method_invocation_get_sender(invocation);
    const char *title = KEYISOP_SERVICE_TITLE;
    const char *loc = "";
    const char *errStr = "";
    gint code = G_DBUS_ERROR_FAILED;
    int ret = 0;
    uuid_t correlationId;
    gsize correlationIdLength = 0;
    guchar *correlationIdBytes = NULL;      // don't free
    int outPfxLength = 0;
    unsigned char *outPfxBytes = NULL;      // KeyIso_free()
    char *outPfxSalt  = NULL;               // KeyIso_clear_free_string()
    size_t outPfxSaltLength = 0;
    size_t outLength = 0;
    unsigned char *outBytes = NULL;         // KeyIso_free()
    unsigned char *outNext = NULL;          // don't free()
    GVariant *outVariant = NULL;            // GDBUS_g_variant_unref()
    
    correlationIdBytes = (guchar *) g_variant_get_fixed_array(arg_correlationId,
        &correlationIdLength,
        sizeof(guchar));
    if (correlationIdBytes != NULL && correlationIdLength == sizeof(correlationId)) {
        memcpy(correlationId, correlationIdBytes, sizeof(correlationId));
    } else {
        memset(correlationId, 0, sizeof(correlationId));
    }

    KEYISOP_trace_log_para(correlationId, 0, title, "Start", "sender: %s version: %d", senderName, arg_version);

    if (!KeyIso_SERVER_create_self_sign_pfx(
            correlationId,
            arg_keyisoFlags,
            arg_confStr,
            &outPfxLength,
            &outPfxBytes,            // KeyIso_free()
            &outPfxSalt)) {          // KeyIso_free()
        loc = "KeyIso_SERVER_create_self_sign_pfx";
        goto end;
    }

    outPfxSaltLength = strlen(outPfxSalt) + 1;
    outLength = outPfxSaltLength + outPfxLength;
    outBytes = (unsigned char *) KeyIso_zalloc(outLength);
    if (outBytes == NULL) {
        loc = "KeyIso_zalloc";
        code = G_DBUS_ERROR_NO_MEMORY;
        goto end;
    }

    outNext = outBytes;
    memcpy(outNext, outPfxSalt, outPfxSaltLength);
    outNext += outPfxSaltLength;
    memcpy(outNext, outPfxBytes, outPfxLength);

    outVariant = g_variant_new_fixed_array(
        G_VARIANT_TYPE_BYTE,
        outBytes,
        (gsize) outLength,
        sizeof(*outBytes));
    if (outVariant == NULL) {
        loc = "outVariant";
        errStr = "OutOfMemory";
        code = G_DBUS_ERROR_NO_MEMORY;
        goto err;
    }

    ret = 1;
end:
    KeyIso_free(outPfxBytes);
    KeyIso_free(outBytes);
    KeyIso_clear_free_string(outPfxSalt);

    if (ret != 0) {
        KEYISOP_trace_log(correlationId, 0, title, "Complete");
        // The following does a g_variant_unref(outVariant);
        gdbus_kmpp_complete_create_self_sign_pfx(interface, invocation, outVariant);
    } else {
        KEYISOP_trace_log_error(correlationId, 0, title, "Complete", "Create failed");
        g_dbus_method_invocation_return_error_literal(
            invocation, G_DBUS_ERROR, code, loc);
    }
    return TRUE;

err:
    KEYISOP_trace_log_error(correlationId, 0, title, loc, errStr);
    goto end;
}

gboolean KeyIso_on_handle_replace_pfx_certs(
    GdbusKmpp *interface,
    GDBusMethodInvocation *invocation,
    GVariant *arg_correlationId,
    gint arg_version,
    gint arg_keyisoFlags,
    GVariant *arg_pfxBytes,
    const gchar *arg_salt,
    GVariant *arg_pemCert,
    gpointer user_data)
{
    const gchar *senderName = g_dbus_method_invocation_get_sender(invocation);
    const char *title = KEYISOP_SERVICE_TITLE;
    const char *loc = "";
    const char *errStr = "";
    gint code = G_DBUS_ERROR_FAILED;
    int ret = 0;
    uuid_t correlationId;
    gsize correlationIdLength = 0;
    guchar *correlationIdBytes = NULL;      // don't free
    gsize inPfxLength = 0;
    guchar *inPfxBytes = NULL;              // don't free
    gsize pemCertLength = 0;
    guchar *pemCertBytes = NULL;              // don't free
    int outPfxLength = 0;
    unsigned char *outPfxBytes = NULL;      // KeyIso_free()
    char *outPfxSalt  = NULL;               // KeyIso_clear_free_string()
    size_t outPfxSaltLength = 0;
    size_t outLength = 0;
    unsigned char *outBytes = NULL;         // KeyIso_free()
    unsigned char *outNext = NULL;          // don't free()
    GVariant *outVariant = NULL;            // GDBUS_g_variant_unref()
    
    correlationIdBytes = (guchar *) g_variant_get_fixed_array(arg_correlationId,
        &correlationIdLength,
        sizeof(guchar));
    if (correlationIdBytes != NULL && correlationIdLength == sizeof(correlationId)) {
        memcpy(correlationId, correlationIdBytes, sizeof(correlationId));
    } else {
        memset(correlationId, 0, sizeof(correlationId));
    }

    inPfxBytes = (guchar *) g_variant_get_fixed_array(arg_pfxBytes,
        &inPfxLength,
        sizeof(guchar));
    if (inPfxBytes == NULL || inPfxLength == 0) {
        loc = "inPfxBytes";
        errStr = "InvalidArg";
        code = G_DBUS_ERROR_INVALID_ARGS;
        goto err;
    }

    pemCertBytes = (guchar *) g_variant_get_fixed_array(arg_pemCert,
        &pemCertLength,
        sizeof(guchar));
    if (pemCertBytes == NULL || pemCertLength == 0) {
        loc = "pemCertBytes";
        errStr = "InvalidArg";
        code = G_DBUS_ERROR_INVALID_ARGS;
        goto err;
    }

    KEYISOP_trace_log_para(correlationId, 0, title, "Start", "sender: %s version: %d", senderName, arg_version);

    if (!KeyIso_SERVER_replace_pfx_certs(
            correlationId,
            arg_keyisoFlags,
            inPfxLength,
            inPfxBytes,
            arg_salt,
            pemCertLength,
            pemCertBytes,
            &outPfxLength,
            &outPfxBytes,            // KeyIso_free()
            &outPfxSalt)) {          // KeyIso_free()
        loc = "KeyIso_SERVER_replace_pfx_certs";
        goto end;
    }

    outPfxSaltLength = strlen(outPfxSalt) + 1;
    outLength = outPfxSaltLength + outPfxLength;
    outBytes = (unsigned char *) KeyIso_zalloc(outLength);
    if (outBytes == NULL) {
        loc = "KeyIso_zalloc";
        code = G_DBUS_ERROR_NO_MEMORY;
        goto end;
    }

    outNext = outBytes;
    memcpy(outNext, outPfxSalt, outPfxSaltLength);
    outNext += outPfxSaltLength;
    memcpy(outNext, outPfxBytes, outPfxLength);

    outVariant = g_variant_new_fixed_array(
        G_VARIANT_TYPE_BYTE,
        outBytes,
        (gsize) outLength,
        sizeof(*outBytes));
    if (outVariant == NULL) {
        loc = "outVariant";
        errStr = "OutOfMemory";
        code = G_DBUS_ERROR_NO_MEMORY;
        goto err;
    }

    ret = 1;
end:
    KeyIso_free(outPfxBytes);
    KeyIso_free(outBytes);
    KeyIso_clear_free_string(outPfxSalt);

    if (ret != 0) {
        KEYISOP_trace_log(correlationId, 0, title, "Complete");
        // The following does a g_variant_unref(outVariant);
        gdbus_kmpp_complete_replace_pfx_certs(interface, invocation, outVariant);
    } else {
        KEYISOP_trace_log_error(correlationId, 0, title, "Complete", "Replace failed");
        g_dbus_method_invocation_return_error_literal(
            invocation, G_DBUS_ERROR, code, loc);
    }
    return TRUE;

err:
    KEYISOP_trace_log_error(correlationId, 0, title, loc, errStr);
    goto end;
}

gboolean KeyIso_on_handle_pfx_open(
    GdbusKmpp *interface,
    GDBusMethodInvocation *invocation,
    GVariant *arg_correlationId,
    gint arg_version,
    GVariant *arg_pfxBytes,
    const gchar *arg_salt,
    gpointer user_data)
{
    GDBusConnection *connection = g_dbus_method_invocation_get_connection(invocation);
    const gchar *senderName = g_dbus_method_invocation_get_sender(invocation);
    const char *title = KEYISOP_SERVICE_TITLE;
    const char *loc = "";
    const char *errStr = "";
    gint code = G_DBUS_ERROR_FAILED;
    uuid_t correlationId;
    gsize correlationIdLength = 0;
    guchar *correlationIdBytes = NULL;      // don't free
    gsize pfxBytesLength = 0;
    guchar *pfxBytes = NULL;                // don't free
    PKMPP_KEY pkeyPtr = NULL;              // KeyIso_SERVER_free_key()
    guint64 keyId = 0;

    correlationIdBytes = (guchar *) g_variant_get_fixed_array(arg_correlationId,
        &correlationIdLength,
        sizeof(guchar));
    if (correlationIdBytes != NULL && correlationIdLength == sizeof(correlationId)) {
        memcpy(correlationId, correlationIdBytes, sizeof(correlationId));
    } else {
        memset(correlationId, 0, sizeof(correlationId));
    }

    KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Start", "sender: %s version: %d", senderName, arg_version);

    pfxBytes = (guchar *) g_variant_get_fixed_array(arg_pfxBytes,
        &pfxBytesLength,
        sizeof(guchar));
    if (pfxBytes == NULL || pfxBytesLength == 0) {
        loc = "pfxBytes";
        errStr = "InvalidArg";
        code = G_DBUS_ERROR_INVALID_ARGS;
        goto err;
    }

    pkeyPtr = KeyIso_get_kmpp_key_from_pfx_bytes(correlationId, arg_salt, pfxBytesLength, pfxBytes);
    if (pkeyPtr == NULL) {
        loc = "KeyIso_get_kmpp_key_from_pfx_bytes";
        code = G_DBUS_ERROR_INVALID_ARGS;
        goto end;
    }

    // Ignore any add sender errors
    KeyIso_add_gdbus_sender_to_list(        
        connection,
        senderName);

    // For success, KeyIso_SERVER_key_up_ref() of pkey
    keyId = KeyIso_add_key_to_list(
        correlationId,
        senderName,
        pkeyPtr);
    if (keyId == 0ULL) {
        loc = "KeyIso_add_key_to_list";
        goto end;
    }
end:    
    KeyIso_SERVER_free_key(correlationId, pkeyPtr);

    if (keyId != 0) {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete");
        gdbus_kmpp_complete_pfx_open(interface, invocation, keyId);
    } else {
        KEYISOP_trace_log_error(correlationId, 0, title, "Complete", "Open failed");
        g_dbus_method_invocation_return_error_literal(
            invocation, G_DBUS_ERROR, code, loc);
    }

    return TRUE;
err:
    KEYISOP_trace_log_error(correlationId, 0, title, loc, errStr);
    goto end;
}

gboolean KeyIso_on_handle_pfx_close(
    GdbusKmpp *interface,
    GDBusMethodInvocation *invocation,
    GVariant *arg_correlationId,
    guint64 arg_keyId,
    gpointer user_data)
{
    const gchar *senderName = g_dbus_method_invocation_get_sender(invocation);
    const char *title = KEYISOP_SERVICE_TITLE;
    const char *loc = "";
    gint code = G_DBUS_ERROR_FAILED;
    uuid_t correlationId;
    gsize correlationIdLength = 0;
    guchar *correlationIdBytes = NULL;      // don't free
    
    correlationIdBytes = (guchar *) g_variant_get_fixed_array(arg_correlationId,
        &correlationIdLength,
        sizeof(guchar));
    if (correlationIdBytes != NULL && correlationIdLength == sizeof(correlationId)) {
        memcpy(correlationId, correlationIdBytes, sizeof(correlationId));
    } else {
        memset(correlationId, 0, sizeof(correlationId));
    }
    KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Start", "sender: %s", senderName);

    if (KeyIso_remove_key_from_list(
            correlationId,
            senderName,
            arg_keyId)) {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete");
        gdbus_kmpp_complete_pfx_close(interface, invocation);
    } else {
        KEYISOP_trace_log_error(correlationId, 0, title, "Complete", "Close failed");
        g_dbus_method_invocation_return_error_literal(
            invocation, G_DBUS_ERROR, code, loc);
    }

    return TRUE;
}

gboolean KeyIso_on_handle_ecdsa_sign(
    GdbusKmpp *interface,
    GDBusMethodInvocation *invocation,
    GVariant *arg_correlationId,
    gint arg_version,
    guint64 arg_keyId,
    gint arg_type,
    GVariant *arg_digestBytes,
    guint arg_siglen,
    gpointer user_data)
{
    const gchar *senderName = g_dbus_method_invocation_get_sender(invocation);
    const char *title = KEYISOP_SERVICE_TITLE;
    const char *loc = "";
    const char *errStr = "";
    gint code = G_DBUS_ERROR_FAILED;
    int ret = 0;
    uuid_t correlationId;
    gsize correlationIdLength = 0;
    guchar *correlationIdBytes = NULL;      // don't free
    gsize digestLength = 0;
    guchar *digestBytes = NULL;             // don't free
    guchar *signatureBytes = NULL;          // KeyIso_free()
    PKMPP_KEY pkeyPtr = NULL;               // KeyIso_SERVER_free_key()
    GVariant *outVariant = NULL;            // GDBUS_g_variant_unref()
    unsigned int outLen = 0;
    
    correlationIdBytes = (guchar *) g_variant_get_fixed_array(arg_correlationId,
        &correlationIdLength,
        sizeof(guchar));
    if (correlationIdBytes != NULL && correlationIdLength == sizeof(correlationId)) {
        memcpy(correlationId, correlationIdBytes, sizeof(correlationId));
    } else {
        memset(correlationId, 0, sizeof(correlationId));
    }

    // Only for testing. Will be noisy.
    KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Start", "sender: %s version: %d", senderName, arg_version);

    digestBytes = (guchar *) g_variant_get_fixed_array(arg_digestBytes,
        &digestLength,
        sizeof(guchar));
    if (digestBytes == NULL || digestLength == 0) {
        loc = "digestBytes";
        errStr = "InvalidArg";
        code = G_DBUS_ERROR_INVALID_ARGS;
        goto err;
    }

    if (arg_siglen != 0 && arg_siglen < 0x10000) {
        signatureBytes = (guchar *) KeyIso_zalloc(arg_siglen);
    }
    if (signatureBytes == NULL) {
        loc = "KeyIso_zalloc";
        code = G_DBUS_ERROR_NO_MEMORY;
        goto end;
    }

    pkeyPtr = KeyIso_get_key_in_list(
        correlationId,
        senderName,
        arg_keyId);
    if (pkeyPtr == NULL || pkeyPtr->key == NULL || pkeyPtr->type != KmppKeyType_epkey) {
        loc = "KeyIso_get_key_in_list";
        code = G_DBUS_ERROR_INVALID_ARGS;
        goto end;
    }

    ret = KeyIso_SERVER_ecdsa_sign_ossl(
            correlationId,
            pkeyPtr->key,
            arg_type,
            digestBytes,
            (int) digestLength,
            signatureBytes,
            arg_siglen,
            &outLen);
    if (!ret || outLen == 0 || outLen > arg_siglen) {
        ret = 0;
        loc = "KeyIso_SERVER_ecdsa_sign_ossl";
        goto end;
    }

    outVariant = g_variant_new_fixed_array(
        G_VARIANT_TYPE_BYTE,
        signatureBytes,
        (gsize) outLen,
        sizeof(*signatureBytes));
    if (outVariant == NULL) {
        ret = 0;
        loc = "outVariant";
        errStr = "OutOfMemory";
        code = G_DBUS_ERROR_NO_MEMORY;
        goto err;
    }

end:
    KeyIso_SERVER_free_key(correlationId, pkeyPtr);
    KeyIso_free(signatureBytes);

    if (ret) {
        // Only for verbose testing. Will be noisy.
        KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete",
            "outLen: %d", outLen);
        // The following does a g_variant_unref(outVariant);
        gdbus_kmpp_complete_ecdsa_sign(interface, invocation, outVariant);
    } else {
        KEYISOP_trace_log_error(correlationId, 0, title, "Complete", "ECC crypt failed");
        g_dbus_method_invocation_return_error_literal(
            invocation, G_DBUS_ERROR, code, loc);
    }

    return TRUE;

err:
    KEYISOP_trace_log_error(correlationId, 0, title, loc, errStr);
    goto end;
}

gboolean KeyIso_on_handle_rsa_private_encrypt_decrypt(
    GdbusKmpp *interface,
    GDBusMethodInvocation *invocation,
    GVariant *arg_correlationId,
    gint arg_version,
    gint arg_decrypt,
    guint64 arg_keyId,
    GVariant *arg_fromBytes,
    gint arg_padding,
    gint arg_tlen,
    gpointer user_data)
{
    const gchar *senderName = g_dbus_method_invocation_get_sender(invocation);
    const char *title = KEYISOP_SERVICE_TITLE;
    const char *loc = "";
    const char *errStr = "";
    gint code = G_DBUS_ERROR_FAILED;
    int ret = -1;
    uuid_t correlationId;
    gsize correlationIdLength = 0;
    guchar *correlationIdBytes = NULL;      // don't free
    gsize fromLength = 0;
    guchar *fromBytes = NULL;               // don't free
    guchar *toBytes = NULL;                 // KeyIso_free()
    PKMPP_KEY pkeyPtr = NULL; 
    GVariant *outVariant = NULL;            // GDBUS_g_variant_unref()
    
    correlationIdBytes = (guchar *) g_variant_get_fixed_array(arg_correlationId,
        &correlationIdLength,
        sizeof(guchar));
    if (correlationIdBytes != NULL && correlationIdLength == sizeof(correlationId)) {
        memcpy(correlationId, correlationIdBytes, sizeof(correlationId));
    } else {
        memset(correlationId, 0, sizeof(correlationId));
    }

    // Only for testing. Will be noisy.
    KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Start", "sender: %s version: %d", senderName, arg_version);

    fromBytes = (guchar *) g_variant_get_fixed_array(arg_fromBytes,
        &fromLength,
        sizeof(guchar));
    if (fromBytes == NULL || fromLength == 0) {
        loc = "fromBytes";
        errStr = "InvalidArg";
        code = G_DBUS_ERROR_INVALID_ARGS;
        goto err;
    }

    if ((arg_decrypt < 0) || (arg_decrypt >= sizeof(KEYISO_SERVER_rsa_operations))) {
        loc = "arg_decrypt";
        errStr = "InvalidArg";
        code = G_DBUS_ERROR_INVALID_ARGS;
        goto err;
    }

    if (arg_tlen != 0 && arg_tlen < 0x10000) {
        toBytes = (guchar *) KeyIso_zalloc(arg_tlen);
    }
    if (toBytes == NULL) {
        loc = "KeyIso_zalloc";
        code = G_DBUS_ERROR_NO_MEMORY;
        goto end;
    }

    pkeyPtr = KeyIso_get_key_in_list(
        correlationId,
        senderName,
        arg_keyId);
    if (pkeyPtr == NULL || pkeyPtr->key == NULL || pkeyPtr->type != KmppKeyType_epkey) {
        loc = "KeyIso_get_key_in_list";
        code = G_DBUS_ERROR_INVALID_ARGS;
        goto end;
    }

    ret = KEYISO_SERVER_rsa_operations[arg_decrypt] (correlationId,
            pkeyPtr->key,
            (int) fromLength,
            fromBytes,
            (int) arg_tlen,
            toBytes,
            arg_padding);

    if (ret <= 0 || ret > arg_tlen) {
        if (ret > arg_tlen) {
            ret = -1;
        }
        loc = "KeyIso_SERVER_rsa_operation";
        goto end;
    }

    outVariant = g_variant_new_fixed_array(
        G_VARIANT_TYPE_BYTE,
        toBytes,
        (gsize) ret,
        sizeof(*toBytes));
    if (outVariant == NULL) {
        ret = -1;
        loc = "outVariant";
        errStr = "OutOfMemory";
        code = G_DBUS_ERROR_NO_MEMORY;
        goto err;
    }
end:
    KeyIso_SERVER_free_key(correlationId, pkeyPtr);
    KeyIso_free(toBytes);

    if (ret > 0) {
        // Only for verbose testing. Will be noisy.
        KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete",
            "ret: %d", ret);
        // The following does a g_variant_unref(outVariant);
        gdbus_kmpp_complete_rsa_private_encrypt_decrypt(interface, invocation, outVariant);
    } else {
        KEYISOP_trace_log_error(correlationId, 0, title, "Complete", "RSA crypt failed");
        g_dbus_method_invocation_return_error_literal(
            invocation, G_DBUS_ERROR, code, loc);
    }

    return TRUE;

err:
    KEYISOP_trace_log_error(correlationId, 0, title, loc, errStr);
    goto end;
}
