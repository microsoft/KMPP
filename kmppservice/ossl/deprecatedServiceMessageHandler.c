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
#include "keyisoservicekey.h"

#include "kmppgdbusclient.h"
#include "kmppgdbusclientcommon.h"

static const PFN_rsa_operation KEYISO_SERVER_rsa_operations[] = 
{
    KeyIso_SERVER_rsa_private_encrypt_ossl,
    KeyIso_SERVER_rsa_private_decrypt_ossl,
    KeyIso_SERVER_rsa_sign_ossl,
    KeyIso_SERVER_pkey_rsa_sign_ossl
};

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
    EVP_PKEY* evpKey;
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

    if (!KeyIso_SERVER_pfx_open(
            correlationId,
            pfxBytesLength,
            pfxBytes,
            arg_salt,
            (void*)&evpKey)) {
        loc = "KeyIso_SERVER_pfx_open";
        goto end;
    }

    pkeyPtr = KeyIso_kmpp_key_create(correlationId, KmppKeyType_epkey, evpKey);
    if (!pkeyPtr) {
        loc = "KeyIso_SERVER_pfx_open";
        goto err;
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
