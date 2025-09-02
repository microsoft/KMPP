/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <dbus/dbus.h> 
#include <errno.h>

#include <openssl/crypto.h>
#include "keyisopfxclientinternal.h"

#include "keyisolog.h"
#include "keyisoclientinternal.h"
#include "keyisoctrl.h"  
#include "keyisoutils.h"
#include "keyisomemory.h"
#include "keyisocert.h"

#include "kmppgdbusgenerated.h"
#include "kmppgdbusclientcommon.h"

/////////////////////////////////////////////////////////
/*   Functionality towards KMPP PFX Service            */
/////////////////////////////////////////////////////////

int KMPP_GDBUS_CLIENT_import_pfx(
    const uuid_t correlationId,
    int keyisoFlags,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *inPassword,             // Optional
    int *outVerifyChainError,
    int *outPfxLength,
    unsigned char **outPfxBytes,        // KeyIso_free()
    char **outPfxSalt)                  // KeyIso_free()
{
    const char *title = KEYISOP_GDBUS_CLIENT_TITLE;
    const char *loc = "";
    const char *errStr = "Out of memory";
    int ret = 0;
    GVariant *correlationIdVariant = NULL;
    GVariant *inPfxBytesVariant = NULL;
    GVariant *outVerifyChainErrorSaltPfxBytesVariant = NULL;
    GdbusKmpp *proxy = NULL;
    GError *error = NULL;   // KMPP_GDBUS_trace_log_glib_error() frees
    unsigned char* combinedPfxBytes = NULL;

    *outVerifyChainError = 0;
    *outPfxLength = 0;
    *outPfxBytes = NULL;
    *outPfxSalt = NULL;

    correlationIdVariant = g_variant_new_fixed_array(
        G_VARIANT_TYPE_BYTE,
        correlationId,
        sizeof(uuid_t),
        sizeof(guchar));
    if (correlationIdVariant == NULL) {
        loc = "correlationIdVariant";
        goto err;
    }

    inPfxBytesVariant = g_variant_new_fixed_array(
        G_VARIANT_TYPE_BYTE,
         inPfxBytes,
        (gsize) inPfxLength,
        sizeof(*inPfxBytes)); // sizeof element
    if (inPfxBytesVariant == NULL) {
        loc = "inPfxBytesVariant";
        goto err;
    }

    proxy = GDBUS_get_kmpp_proxy(correlationId);
    if (proxy == NULL) {
        loc = "GDBUS_get_kmpp_proxy";
        errStr = "No proxy";
        goto err;
    }

    if (!gdbus_kmpp_call_import_pfx_sync(
            proxy,
            g_variant_ref(correlationIdVariant),
            KEYISOP_VERSION_1,
            keyisoFlags,
            g_variant_ref(inPfxBytesVariant),
            inPassword ? inPassword : "",
            &outVerifyChainErrorSaltPfxBytesVariant,
            NULL,                   // cancellable
            &error) || error || outVerifyChainErrorSaltPfxBytesVariant == NULL) {
        KMPP_GDBUS_trace_log_glib_error(correlationId, 0, title, loc, &error);
        goto end;
    } else {
        gsize outLength = 0;
        guchar *outBytes = NULL;
        gsize saltLength = 0;
        gchar *salt;

        outBytes = (guchar *) g_variant_get_fixed_array(
            outVerifyChainErrorSaltPfxBytesVariant,
            &outLength,
            sizeof(guchar));
        if (outBytes == NULL ||
                outLength < sizeof(int) + 3) {
            loc = "outVerifyChainErrorSaltPfxBytesVariant";
            errStr = "Format error";
            goto err;
        }

        memcpy(outVerifyChainError, outBytes, sizeof(int));
        outBytes += sizeof(int);
        outLength -= sizeof(int);

        saltLength = OPENSSL_strnlen((gchar *) outBytes, outLength);
        if (saltLength + 2 > outLength) {
            loc = "outVerifyChainErrorSaltPfxBytesVariant";
            errStr = "Format error";
            goto err;
        }

        salt = (gchar *) outBytes;
        saltLength++;
        outBytes += saltLength;
        outLength -= saltLength;

        *outPfxBytes = (unsigned char *) KeyIso_zalloc(outLength);
        *outPfxSalt = (char *) KeyIso_zalloc(saltLength);
        if (*outPfxBytes == NULL || *outPfxSalt == NULL) {
            goto end;
        }

        memcpy(*outPfxBytes, outBytes, outLength);
        *outPfxLength = outLength;
        memcpy(*outPfxSalt, salt, saltLength);
    }

    ret = *outVerifyChainError == 0 ? 1 : -1;

end:
    KeyIso_free(combinedPfxBytes);

    GDBUS_g_variant_unref(correlationIdVariant);
    GDBUS_g_variant_unref(inPfxBytesVariant);
    GDBUS_g_variant_unref(outVerifyChainErrorSaltPfxBytesVariant);
    if (proxy) {
        GDBUS_g_object_unref(proxy);
        proxy = NULL;
    }

    if (ret == 0) {
        *outPfxLength = 0;
        KeyIso_free(*outPfxBytes);
        *outPfxBytes = NULL;

        KeyIso_clear_free_string(*outPfxSalt);
        *outPfxSalt = NULL;
    }

    GDBUS_exhaust_main_loop_events();
    return ret;

err:
    KEYISOP_trace_log_error(correlationId, 0, title, loc, errStr);
    goto end;
}

// Called under lock
static int _gdbus_pfx_update_locked(
    KEYISO_KEY_CTX *keyCtx)
{
    const char *title = KEYISOP_GDBUS_CLIENT_TITLE;
    const char *loc = "";
    const char *errStr = "Out of memory";
    int ret = 0;
    GVariant *correlationIdVariant = NULL;
    GVariant *pfxBytesVariant = NULL;
    GError *error = NULL;   // KMPP_GDBUS_trace_log_glib_error() frees
    KEYISO_KEY_DETAILS *keyDetails = (KEYISO_KEY_DETAILS *)keyCtx->keyDetails;
    GdbusKmpp *proxy = NULL;
    guint64 keyId = 0ULL;

    correlationIdVariant = g_variant_new_fixed_array(
        G_VARIANT_TYPE_BYTE,
        keyCtx->correlationId,
        sizeof(uuid_t),
        sizeof(guchar));
    if (correlationIdVariant == NULL) {
        loc = "correlationIdVariant";
        goto err;
    }

    pfxBytesVariant = g_variant_new_fixed_array(
        G_VARIANT_TYPE_BYTE,
        keyDetails->keyBytes,
        (gsize) keyDetails->keyLength,
        sizeof(*keyDetails->keyBytes));
    if (pfxBytesVariant == NULL) {
        loc = "pfxBytesVariant";
        goto err;
    }

    proxy = GDBUS_get_kmpp_proxy(keyCtx->correlationId);
    if (proxy == NULL) {
        loc = "GDBUS_get_kmpp_proxy";
        errStr = "No proxy";
        goto err;
    }

    if (!gdbus_kmpp_call_pfx_open_sync(
            proxy,
            g_variant_ref(correlationIdVariant),
            KEYISOP_VERSION_1,
            g_variant_ref(pfxBytesVariant),
            keyDetails->clientData,
            &keyId,
            NULL,                   // cancellable
            &error) || error || keyId == 0) {
        KMPP_GDBUS_trace_log_glib_error(keyCtx->correlationId, 0, title, loc, &error);
        goto end;
    }

    GDBUS_SESSION *session = (GDBUS_SESSION*)keyDetails->interfaceSession;
    GDBUS_g_object_unref(session->proxy);
    session->proxy = proxy;
    proxy = NULL;
    keyDetails->keyId = keyId;

    ret = 1;
end:
    GDBUS_g_variant_unref(correlationIdVariant);
    GDBUS_g_variant_unref(pfxBytesVariant);
    if (proxy) {
        GDBUS_g_object_unref(proxy);
        proxy = NULL;
    }
    GDBUS_exhaust_main_loop_events();
    return ret;

err:
    KEYISOP_trace_log_error(keyCtx->correlationId, 0, title, loc, errStr);
    goto end;
}

static int _gdbus_pfx_retry_update(
    KEYISO_KEY_CTX *keyCtx)
{
    const char *title = KEYISOP_GDBUS_CLIENT_TITLE;
    int ret = 0;
    int retryCount = 1;
    KEYISO_KEY_DETAILS *keyDetails = (KEYISO_KEY_DETAILS *) keyCtx->keyDetails;    
    GDBUS_SESSION *session = (GDBUS_SESSION*)keyDetails->interfaceSession;
    g_mutex_lock(&session->mutex);

    for (;;) {
        // 500 milliseconds
        g_usleep((gulong)(SLEEP_BETWEEN_RETRIES_MILLI * 1000)); // Microseconds

        KEYISOP_trace_log_error_para(keyCtx->correlationId, 0, title, "UpdateRetry", "Warning",
            "updateRetryCount: %d", retryCount);

        if (_gdbus_pfx_update_locked(keyCtx)) {
            ret = 1;
            break;
        }

        if (++retryCount > 5) {
            break;
        }
    }

    g_mutex_unlock(&session->mutex);

    return ret;
}


static
int _get_gdbus_pfx_para(
    KEYISO_KEY_CTX *keyCtx,
    GdbusKmpp **proxy,       // GDBUS_g_object_unref()
    guint64 *keyId)
{
    int ret = 0;
    KEYISO_KEY_DETAILS *keyDetails = (KEYISO_KEY_DETAILS *) keyCtx->keyDetails;
    GDBUS_SESSION *session = (GDBUS_SESSION*)keyDetails->interfaceSession;

    *proxy = NULL;
    *keyId = 0ULL;

    // Get proxy and keyId under lock
    g_mutex_lock(&session->mutex);

    if (session->proxy == NULL) {
        const char *title = KEYISOP_GDBUS_CLIENT_TITLE;
        KEYISOP_trace_log(keyCtx->correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Start");

        if (!_gdbus_pfx_update_locked(keyCtx)) {
            KEYISOP_trace_log_error(keyCtx->correlationId, 0, title, "Complete", "Get failed");
            goto end;
        }

        KEYISOP_trace_log(keyCtx->correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete");
    }

    *proxy = session->proxy;
    g_object_ref(*proxy);
    *keyId = keyDetails->keyId;

    ret = 1;
end:
    g_mutex_unlock(&session->mutex);

    return ret;
}


int KMPP_GDBUS_CLIENT_pfx_open(
    KEYISO_KEY_CTX *keyCtx,
    int pfxLength,
    const unsigned char *pfxBytes,
    const char *salt)
{
    // Legacy code, MScrypt key
    size_t saltLength = strnlen(salt, KEYISO_SECRET_SALT_STR_BASE64_LEGACY_LEN); 
    if (saltLength == 0 || saltLength >= KEYISO_SECRET_SALT_STR_BASE64_LEGACY_LEN) {
        KEYISOP_trace_log_error(keyCtx->correlationId, 0, KEYISOP_GDBUS_CLIENT_TITLE, "salt", "Invalid argument");
        return 0;
    }
    saltLength+= 1; // +1 for NULL termination

    size_t dynamicLen = saltLength + pfxLength;
    KEYISO_KEY_DETAILS *keyDetails = (KEYISO_KEY_DETAILS *) KeyIso_zalloc(sizeof(KEYISO_KEY_DETAILS) + dynamicLen);
    if (keyDetails == NULL) 
        return 0;

    keyCtx->keyDetails = keyDetails;
    if (KeyIso_init_gdbus_in_keyDetails(keyCtx->keyDetails) == 0)
        return 0;
    
    keyDetails->keyLength = pfxLength;
    keyDetails->keyBytes = (unsigned char *) &keyDetails[1];
    memcpy(keyDetails->keyBytes, pfxBytes, pfxLength);
    keyDetails->clientData = (char *) (keyDetails->keyBytes + pfxLength); // BC(Salt)
    memcpy(keyDetails->clientData, salt, saltLength);
    return 1;    
}

void KMPP_GDBUS_CLIENT_pfx_close(
    KEYISO_KEY_CTX *keyCtx)
{
    const char *title = KEYISOP_GDBUS_CLIENT_TITLE;
    const char *loc = "";
    const char *errStr = "Out of memory";
    GVariant *correlationIdVariant = NULL;
    GError *error = NULL;   // KMPP_GDBUS_trace_log_glib_error() frees
    KEYISO_KEY_DETAILS *keyDetails = NULL;

    if (keyCtx == NULL || keyCtx->keyDetails == NULL) {
        return;
    }

    keyDetails = (KEYISO_KEY_DETAILS *) keyCtx->keyDetails;
    GDBUS_SESSION *session = (GDBUS_SESSION*)keyDetails->interfaceSession;
    if (session->proxy == NULL) {
        goto end;
    }

    correlationIdVariant = g_variant_new_fixed_array(
        G_VARIANT_TYPE_BYTE,
        keyCtx->correlationId,
        sizeof(uuid_t),
        sizeof(guchar));
    if (correlationIdVariant == NULL) {
        loc = "correlationIdVariant";
        goto err;
    }

    if (!gdbus_kmpp_call_pfx_close_sync(
            session->proxy,
            g_variant_ref(correlationIdVariant),
            keyDetails->keyId,
            NULL,                   // cancellable
            &error) || error) {
        KMPP_GDBUS_trace_log_glib_error(keyCtx->correlationId, 0, title, loc, &error);
        goto end;
    }

end:
    GDBUS_g_variant_unref(correlationIdVariant);
    if (session && session->proxy)  {
        GDBUS_g_object_unref(session->proxy);
        session->proxy = NULL;
    }

    if (keyDetails->keyBytes != NULL && keyDetails->keyLength != 0) {
        KeyIso_cleanse(keyDetails->keyBytes, keyDetails->keyLength);
    }

    if (keyDetails->clientData != NULL) {
        KeyIso_cleanse(keyDetails->clientData, strlen(keyDetails->clientData));
    }

    KeyIso_destroy_gdbus_session(session);
    KeyIso_CLIENT_free_key_ctx(keyCtx);

    GDBUS_exhaust_main_loop_events();
    return;

err:
    KEYISOP_trace_log_error(keyCtx->correlationId, 0, title, loc, errStr);
    goto end;
}

int KMPP_GDBUS_CLIENT_get_version(
    unsigned int *outVersion)
{
    int ret = 0;
    gint out_version = 0;
    GError *error = NULL;
    GdbusKmpp *proxy = NULL;
    const char *loc = "";
    proxy = GDBUS_get_kmpp_proxy(NULL);
    if (proxy == NULL) {
        loc = "can't get proxy";
        goto err;
    }
    if (!gdbus_kmpp_call_get_version_sync(
            proxy,
            &out_version,
            NULL,                   // cancellable
            &error) || error) {
        KMPP_GDBUS_trace_log_glib_error(NULL, 0, KEYISOP_GDBUS_CLIENT_TITLE, "gdbus_kmpp_call_get_version_sync", &error);
        out_version = KEYISOP_INVALID_VERSION;
        goto end;
    }
    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_GDBUS_CLIENT_TITLE, 
                            "get_version", "version: %d", out_version);
    ret = 1;

end:
    if (proxy) {
        GDBUS_g_object_unref(proxy);
        GDBUS_exhaust_main_loop_events();
        proxy = NULL;
    }
    *outVersion = (unsigned int)out_version;
    return ret;

err:
    KEYISOP_trace_log(NULL, 0, KEYISOP_GDBUS_CLIENT_TITLE, loc);
    out_version = KEYISOP_INVALID_VERSION;
    goto end;
}

int KMPP_GDBUS_CLIENT_rsa_private_encrypt_decrypt(
    KEYISO_KEY_CTX *keyCtx,
    int decrypt,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding)
{
    const char *title = KEYISOP_GDBUS_CLIENT_TITLE;
    const char *loc = "";
    const char *errStr = "Out of memory";
    int ret = -1;
    GVariant *correlationIdVariant = NULL;
    GVariant *fromVariant = NULL;
    GVariant *toVariant = NULL;
    GError *error = NULL;   // KMPP_GDBUS_trace_log_glib_error() frees
    int retryCount = 0;

    if (keyCtx == NULL || keyCtx->keyDetails == NULL) {
        KEYISOP_trace_log_error(NULL, 0, title, loc, "Invalid argument");
        return -1;
    }

    correlationIdVariant = g_variant_new_fixed_array(
        G_VARIANT_TYPE_BYTE,
        keyCtx->correlationId,
        sizeof(uuid_t),
        sizeof(guchar));
    if (correlationIdVariant == NULL) {
        loc = "correlationIdVariant";
        goto err;
    }

    fromVariant = g_variant_new_fixed_array(
        G_VARIANT_TYPE_BYTE,
        from,
        (gsize) flen,
        sizeof(*from));
    if (fromVariant == NULL) {
        loc = "fromVariant";
        goto err;
    }

    for (;;) {
        GdbusKmpp *proxy = NULL;
        guint64 keyId = 0ULL;
        gboolean callRet = FALSE;
        gboolean enableRetry = FALSE;

        if (retryCount != 0) {
            if (!_gdbus_pfx_retry_update(keyCtx)) {
                loc = "UpdateRetry";
                errStr = "Update failed";
                goto err;
            }
        }

        if (!_get_gdbus_pfx_para(keyCtx, &proxy, &keyId)) {
            goto end;
        }
        callRet = gdbus_kmpp_call_rsa_private_encrypt_decrypt_sync(
            proxy,
            g_variant_ref(correlationIdVariant),
            KEYISOP_VERSION_1,
            decrypt,
            keyId,
            g_variant_ref(fromVariant),
            padding,
            tlen,
            &toVariant,
            NULL,                   // cancellable
            &error);
        if (proxy) {
            GDBUS_g_object_unref(proxy);
            proxy = NULL;
        }

        if (callRet && error == NULL && toVariant != NULL) {
            break;
        }

        GDBUS_g_variant_unref(toVariant);
        toVariant = NULL;

        if (++retryCount < 5 && GDBUS_is_gdbus_retry_error(error)) {
            enableRetry = TRUE;
        }

        KMPP_GDBUS_trace_log_glib_error(keyCtx->correlationId, 0, title, loc, &error);
        if (!enableRetry) {
            goto end;
        }

        KEYISOP_trace_log_error_para(keyCtx->correlationId, KEYISOP_TRACELOG_WARNING_FLAG, title, "RsaRetry", "Call failed",
            "RsaRetryCount: %d", retryCount);
    }

    {
        guchar *toBytes = NULL;
        gsize toLength = 0;

        toBytes = (guchar *) g_variant_get_fixed_array(
            toVariant,
            &toLength,
            sizeof(guchar));
        if (toBytes == NULL ||
                toLength <= 0 ||
                (int) toLength > tlen) {
            loc = "toVariant";
            errStr = "Format error";
            goto err;
        }

        ret = (int) toLength;
        memcpy(to, toBytes, ret);
    }

end:
    GDBUS_g_variant_unref(correlationIdVariant);
    GDBUS_g_variant_unref(fromVariant);
    GDBUS_g_variant_unref(toVariant);
    return ret;

err:
    KEYISOP_trace_log_error(keyCtx->correlationId, 0, title, loc, errStr);
    goto end;
}

int KMPP_GDBUS_CLIENT_ecdsa_sign(
    KEYISO_KEY_CTX *keyCtx,
    int type,
    const unsigned char *dgst,
    int dlen,
    unsigned char *sig,
    unsigned int siglen,
    unsigned int *outlen)
{
    const char *title = KEYISOP_GDBUS_CLIENT_TITLE;
    const char *loc = "";
    const char *errStr = "Out of memory";
    int ret = 0;
    GVariant *correlationIdVariant = NULL;
    GVariant *dgstVariant = NULL;
    GVariant *sigVariant = NULL;
    GError *error = NULL;   // KMPP_GDBUS_trace_log_glib_error() frees
    int retryCount = 0;

    if (keyCtx == NULL || keyCtx->keyDetails == NULL) {
        KEYISOP_trace_log_error(NULL, 0, title, loc, "Invalid argument");
        return 0;
    }

    *outlen = 0;

    correlationIdVariant = g_variant_new_fixed_array(
        G_VARIANT_TYPE_BYTE,
        keyCtx->correlationId,
        sizeof(uuid_t),
        sizeof(guchar));
    if (correlationIdVariant == NULL) {
        loc = "correlationIdVariant";
        goto err;
    }

    dgstVariant = g_variant_new_fixed_array(
        G_VARIANT_TYPE_BYTE,
        dgst,
        (gsize) dlen,
        sizeof(*dgst));
    if (dgstVariant == NULL) {
        loc = "dgstVariant";
        goto err;
    }

    for (;;) {
        GdbusKmpp *proxy = NULL;
        guint64 keyId = 0ULL;
        gboolean callRet = FALSE;
        gboolean enableRetry = FALSE;

        if (retryCount != 0) {
            if (!_gdbus_pfx_retry_update(keyCtx)) {
                loc = "UpdateRetry";
                errStr = "Update failed";
                goto err;
            }
        }

        if (!_get_gdbus_pfx_para(keyCtx, &proxy, &keyId)) {
            goto end;
        }
        callRet = gdbus_kmpp_call_ecdsa_sign_sync(
            proxy,
            g_variant_ref(correlationIdVariant),
            KEYISOP_VERSION_1,
            keyId,
            type,
            g_variant_ref(dgstVariant),
            siglen,
            &sigVariant,
            NULL,                   // cancellable
            &error);
        if (proxy) {
            GDBUS_g_object_unref(proxy);
            proxy = NULL;
        }

        if (callRet && error == NULL && sigVariant != NULL) {
            break;
        }

        GDBUS_g_variant_unref(sigVariant);
        sigVariant = NULL;

        if (++retryCount < 5 && GDBUS_is_gdbus_retry_error(error)) {
            enableRetry = TRUE;
        }

        KMPP_GDBUS_trace_log_glib_error(keyCtx->correlationId, 0, title, loc, &error);
        if (!enableRetry) {
            goto end;
        }

        KEYISOP_trace_log_error_para(keyCtx->correlationId, KEYISOP_TRACELOG_WARNING_FLAG, title, "EcdsaRetry", "Call failed",
            "EcdsaRetryCount: %d", retryCount);
    }

    {
        guchar *sigBytes = NULL;
        gsize outLength = 0;

        sigBytes = (guchar *) g_variant_get_fixed_array(
            sigVariant,
            &outLength,
            sizeof(guchar));
        if (sigBytes == NULL ||
                outLength <= 0 ||
                (int) outLength > siglen) {
            loc = "sigVariant";
            errStr = "Format error";
            goto err;
        }

        *outlen = (int) outLength;
        memcpy(sig, sigBytes, (int) outLength);
        ret = 1;
    }

end:
    GDBUS_g_variant_unref(correlationIdVariant);
    GDBUS_g_variant_unref(dgstVariant);
    GDBUS_g_variant_unref(sigVariant);
    return ret;

err:
    KEYISOP_trace_log_error(keyCtx->correlationId, 0, title, loc, errStr);
    goto end;
}

int KMPP_GDBUS_CLIENT_create_self_sign_pfx(
    const uuid_t correlationId,
    int keyisoFlags,
    const char *confStr,
    int *outPfxLength,
    unsigned char **outPfxBytes,        // KeyIso_free()
    char **outPfxSalt)                  // KeyIso_free()
{
    const char *title = KEYISOP_GDBUS_CLIENT_TITLE;
    const char *loc = "";
    const char *errStr = "Out of memory";
    int ret = 0;
    GVariant *correlationIdVariant = NULL;
    GVariant *outSaltPfxBytesVariant = NULL;
    GdbusKmpp *proxy = NULL;
    GError *error = NULL;   // KMPP_GDBUS_trace_log_glib_error() frees

    *outPfxLength = 0;
    *outPfxBytes = NULL;
    *outPfxSalt = NULL;

    correlationIdVariant = g_variant_new_fixed_array(
        G_VARIANT_TYPE_BYTE,
        correlationId,
        sizeof(uuid_t),
        sizeof(guchar));
    if (correlationIdVariant == NULL) {
        loc = "correlationIdVariant";
        goto err;
    }

    proxy = GDBUS_get_kmpp_proxy(correlationId);
    if (proxy == NULL) {
        loc = "GDBUS_get_kmpp_proxy";
        errStr = "No proxy";
        goto err;
    }

    if (!gdbus_kmpp_call_create_self_sign_pfx_sync(
            proxy,
            g_variant_ref(correlationIdVariant),
            KEYISOP_VERSION_1,
            keyisoFlags,
            confStr,
            &outSaltPfxBytesVariant,
            NULL,                   // cancellable
            &error) || error || outSaltPfxBytesVariant == NULL) {
        KMPP_GDBUS_trace_log_glib_error(correlationId, 0, title, loc, &error);
        goto end;
    } else {
        gsize outLength = 0;
        guchar *outBytes = NULL;
        gsize saltLength = 0;
        gchar *salt;

        outBytes = (guchar *) g_variant_get_fixed_array(
            outSaltPfxBytesVariant,
            &outLength,
            sizeof(guchar));
        if (outBytes == NULL ||
                outLength < 3) {
            loc = "outSaltPfxBytesVariant";
            errStr = "Format error";
            goto err;
        }

        saltLength = OPENSSL_strnlen((gchar *) outBytes, outLength);
        if (saltLength + 2 > outLength) {
            loc = "outSaltPfxBytesVariant";
            errStr = "Format error";
            goto err;
        }

        salt = (gchar *) outBytes;
        saltLength++;
        outBytes += saltLength;
        outLength -= saltLength;

        *outPfxBytes = (unsigned char *) KeyIso_zalloc(outLength);
        *outPfxSalt = (char *) KeyIso_zalloc(saltLength);
        if (*outPfxBytes == NULL || *outPfxSalt == NULL) {
            goto end;
        }

        memcpy(*outPfxBytes, outBytes, outLength);
        *outPfxLength = outLength;
        memcpy(*outPfxSalt, salt, saltLength);
    }

    ret = 1;
end:
    GDBUS_g_variant_unref(correlationIdVariant);
    GDBUS_g_variant_unref(outSaltPfxBytesVariant);
    if (proxy) {
        GDBUS_g_object_unref(proxy);
        proxy = NULL;
    }

    if (ret == 0) {
        *outPfxLength = 0;
        KeyIso_free(*outPfxBytes);
        *outPfxBytes = NULL;

        KeyIso_clear_free_string(*outPfxSalt);
        *outPfxSalt = NULL;
    }

    GDBUS_exhaust_main_loop_events();
    return ret;

err:
    KEYISOP_trace_log_error(correlationId, 0, title, loc, errStr);
    goto end;
}

// The pemCert consists of the end certificate followed by
// 1 or more CA certificates
int KMPP_GDBUS_CLIENT_replace_pfx_certs(
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
    const char *title = KEYISOP_GDBUS_CLIENT_TITLE;
    const char *loc = "";
    const char *errStr = "Out of memory";
    int ret = 0;
    GVariant *correlationIdVariant = NULL;
    GVariant *inPfxBytesVariant = NULL;
    GVariant *pemCertVariant = NULL;
    GVariant *outSaltPfxBytesVariant = NULL;
    GdbusKmpp *proxy = NULL;
    GError *error = NULL;   // KMPP_GDBUS_trace_log_glib_error() frees

    *outPfxLength = 0;
    *outPfxBytes = NULL;
    *outSalt = NULL;

    correlationIdVariant = g_variant_new_fixed_array(
        G_VARIANT_TYPE_BYTE,
        correlationId,
        sizeof(uuid_t),
        sizeof(guchar));
    if (correlationIdVariant == NULL) {
        loc = "correlationIdVariant";
        goto err;
    }

    inPfxBytesVariant = g_variant_new_fixed_array(
        G_VARIANT_TYPE_BYTE,
        inPfxBytes,
        (gsize) inPfxLength,
        sizeof(*inPfxBytes));
    if (inPfxBytesVariant == NULL) {
        loc = "inPfxBytesVariant";
        goto err;
    }

    pemCertVariant = g_variant_new_fixed_array(
        G_VARIANT_TYPE_BYTE,
        pemCertBytes,
        (gsize) pemCertLength,
        sizeof(*pemCertBytes));
    if (pemCertVariant == NULL) {
        loc = "pemCertBytesVariant";
        goto err;
    }

    proxy = GDBUS_get_kmpp_proxy(correlationId);
    if (proxy == NULL) {
        loc = "GDBUS_get_kmpp_proxy";
        errStr = "No proxy";
        goto err;
    }

    if (!gdbus_kmpp_call_replace_pfx_certs_sync(
            proxy,
            g_variant_ref(correlationIdVariant),
            KEYISOP_VERSION_1,
            keyisoFlags,
            g_variant_ref(inPfxBytesVariant),
            inSalt,
            g_variant_ref(pemCertVariant),
            &outSaltPfxBytesVariant,
            NULL,                   // cancellable
            &error) || error || outSaltPfxBytesVariant == NULL) {
        KMPP_GDBUS_trace_log_glib_error(correlationId, 0, title, loc, &error);
        goto end;
    } else {
        gsize outLength = 0;
        guchar *outBytes = NULL;
        gsize saltLength = 0;
        gchar *salt;

        outBytes = (guchar *) g_variant_get_fixed_array(
            outSaltPfxBytesVariant,
            &outLength,
            sizeof(guchar));
        if (outBytes == NULL ||
                outLength < 3) {
            loc = "outSaltPfxBytesVariant";
            errStr = "Format error";
            goto err;
        }

        saltLength = OPENSSL_strnlen((gchar *) outBytes, outLength);
        if (saltLength + 2 > outLength) {
            loc = "outSaltPfxBytesVariant";
            errStr = "Format error";
            goto err;
        }

        salt = (gchar *) outBytes;
        saltLength++;
        outBytes += saltLength;
        outLength -= saltLength;

        *outPfxBytes = (unsigned char *) KeyIso_zalloc(outLength);
        *outSalt = (char *) KeyIso_zalloc(saltLength);
        if (*outPfxBytes == NULL || *outSalt == NULL) {
            goto end;
        }

        memcpy(*outPfxBytes, outBytes, outLength);
        *outPfxLength = outLength;
        memcpy(*outSalt, salt, saltLength);
    }

    ret = 1;
end:
    GDBUS_g_variant_unref(correlationIdVariant);
    GDBUS_g_variant_unref(inPfxBytesVariant);
    GDBUS_g_variant_unref(pemCertVariant);
    GDBUS_g_variant_unref(outSaltPfxBytesVariant);
    if (proxy) {
        GDBUS_g_object_unref(proxy);
        proxy = NULL;
    }

    if (ret == 0) {
        *outPfxLength = 0;
        KeyIso_free(*outPfxBytes);
        *outPfxBytes = NULL;

        KeyIso_clear_free_string(*outSalt);
        *outSalt = NULL;
    }

    GDBUS_exhaust_main_loop_events();
    return ret;

err:
    KEYISOP_trace_log_error(correlationId, 0, title, loc, errStr);
    goto end;
}

/*                  DBUS                      */
/* RAW dbus call for version retrial*/
static int _dbus_kmpp_call_get_version_sync(
    const uuid_t correlationId,
    const char *bus_name,
    const char *object_path,
    const char *interface_name,
    int *out_version)
{
    const char* title = KEYISOP_READ_WRITE_VERSION_TITLE;
    DBusConnection *connection;
    DBusError dbus_error;
    DBusMessage *message;
    DBusMessage *reply;
    int result = STATUS_OK;
    int retryCount = 0;

    dbus_error_init(&dbus_error);

    do {
        // Resetting result and connection for each retry
        result = STATUS_OK;

        // Connecting to the system bus
        connection = dbus_bus_get(DBUS_BUS_SYSTEM, &dbus_error);
        if (dbus_error_is_set(&dbus_error)) {
            KEYISOP_trace_log_error_para(correlationId, KEYISOP_TRACELOG_WARNING_FLAG, title, "dbus_bus_get", "returned an error", "Connection Error (%s)", dbus_error.message);
            dbus_error_free(&dbus_error);
            result = STATUS_FAILED;
            retryCount++;
            usleep((unsigned long)(SLEEP_BETWEEN_RETRIES_MILLI * 1000));
            continue;
        }

        if (connection == NULL) {
            KEYISOP_trace_log_error(correlationId, KEYISOP_TRACELOG_WARNING_FLAG, title, "Failed to open connection", "Connection Null");
            result = STATUS_FAILED;
            retryCount++;
            usleep((unsigned long)(SLEEP_BETWEEN_RETRIES_MILLI * 1000));
            continue;
        }

        message = dbus_message_new_method_call(bus_name, object_path, interface_name, "GetVersion");
        if (message == NULL) {
            KEYISOP_trace_log_error(correlationId, KEYISOP_TRACELOG_WARNING_FLAG, title, "Message Null", "constructs a new message to invoke a method on a remote object");
            dbus_connection_unref(connection);
            result = STATUS_FAILED;
            retryCount++;
            usleep((unsigned long)(SLEEP_BETWEEN_RETRIES_MILLI * 1000));
            continue;
        }
        // Sending the message and get a handle for a reply
        reply = dbus_connection_send_with_reply_and_block(connection, message, (SLEEP_BETWEEN_RETRIES_MILLI * 1000) , &dbus_error);
        if (dbus_error_is_set(&dbus_error)) {
            KEYISOP_trace_log_error_para(correlationId, KEYISOP_TRACELOG_WARNING_FLAG, title, "send_with_reply_and_block error", "GetVersion method call failed", "Message (%s)", dbus_error.message);
            dbus_error_free(&dbus_error);
            dbus_message_unref(message);
            dbus_connection_unref(connection);
            result = STATUS_FAILED;
            retryCount++;
            usleep((unsigned long)(SLEEP_BETWEEN_RETRIES_MILLI * 1000));
            continue;
        }

        if (reply == NULL) {
            KEYISOP_trace_log_error(correlationId, KEYISOP_TRACELOG_WARNING_FLAG, title, "GetVersion error","Reply Null");
            dbus_message_unref(message);
            dbus_connection_unref(connection);
            result = STATUS_FAILED;
            retryCount++;
            usleep((unsigned long)(SLEEP_BETWEEN_RETRIES_MILLI * 1000));
            continue;
        }

        // Reading the parameters from the reply
        if (!dbus_message_get_args(reply, &dbus_error, DBUS_TYPE_INT32, out_version, DBUS_TYPE_INVALID)) {
            KEYISOP_trace_log_error_para(correlationId, KEYISOP_TRACELOG_WARNING_FLAG, title,"GetVersion failed","Failed get parameters from reply",  "Error getting message args (%s)", dbus_error.message);
            dbus_error_free(&dbus_error);
            dbus_message_unref(reply);
            dbus_message_unref(message);
            dbus_connection_unref(connection);
            result = STATUS_FAILED;
            retryCount++;
            usleep((unsigned long)(SLEEP_BETWEEN_RETRIES_MILLI * 1000));
            continue;
        }

        dbus_message_unref(reply);
        dbus_message_unref(message);
     
        //https://dbus.freedesktop.org/doc/api/html/group__DBusConnection.html#ga2522ac5075dfe0a1535471f6e045e1ee 
        // Connections created with dbus_connection_open() or dbus_bus_get() are shared.
        //  You may not close a shared connection.
        // These connections are owned by libdbus, and applications should only unref them, never close them. 
        dbus_connection_unref(connection);
        connection = NULL;
        break;
    } while (retryCount < MAX_DBUS_RETRY);
    KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, "GetVersion", "dbus raw call", "version:%d, result:%d", *out_version, result);
    return result;
}

int KMPP_RAW_DBUS_CLIENT_get_version(
    const uuid_t correlationId,
    unsigned int *outVersionPtr)
{
    int ret = STATUS_FAILED;
    int out_version = 0;
    const char* title = KEYISOP_GDBUS_CLIENT_TITLE;
    const char* bus_name = KMPP_BUS_NAME;
    const char* object_path = "/";
    const char *interface_name = KMPP_BUS_NAME; 

    // Call the D-Bus method
    if (_dbus_kmpp_call_get_version_sync(correlationId, bus_name, object_path, interface_name, &out_version) == STATUS_FAILED || out_version < 0) {

        KEYISOP_trace_log_error_para(correlationId, 0, title, "Invalid version", "Received negative version", "Received version: %d", out_version);
        out_version = KEYISOP_INVALID_VERSION;

    } else {

        ret = STATUS_OK;
    }

    // Set the output version
    *outVersionPtr = (unsigned int)out_version;

    // Log the result
    KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "D-Bus get version", "Version: %d", out_version);
    return ret;
}