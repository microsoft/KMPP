/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <sys/mman.h>
#include <sys/stat.h>        // For mode constants
#include <fcntl.h>           // For O_* constants
#include <errno.h>
#include <openssl/crypto.h>
#include "keyisopfxclientinternal.h"
#include "keyisoclientinternal.h"

#include "keyisolog.h"
#include "keyisoctrl.h" 
#include "keyisoutils.h"
#include "keyisomemory.h"
#include "keyisocert.h"

#include "kmppctrlgdbusgenerated.h"
#include "kmppgdbusctrlclient.h"
#include "kmppgdbusclientcommon.h"


/////////////////////////////////////////////////////////
/*   Functionality towards KMPP Control Service        */
/////////////////////////////////////////////////////////


struct KEYISO_GDBUS_shared_mem_st {
    int             fd;
    char            *name;
};

int KMPP_GDBUS_open_shared_mem(
    KEYISO_SHARED_MEM *sharedMem)
{
    const char *title = KEYISOP_GDBUS_CLIENT_TITLE;
    int ret = 0;
    const char *namePrefix = "/KMPPMem";
    unsigned char rand[16];
    char nameRand[sizeof(rand) * 2 + 1];
    size_t nameLength = strlen(namePrefix) + sizeof(nameRand);

    sharedMem->gdbus = (KEYISO_GDBUS_SHARED_MEM *) KeyIso_zalloc(
        sizeof(KEYISO_GDBUS_SHARED_MEM) + nameLength);
    if (sharedMem->gdbus == NULL) {
        goto end;
    }

    sharedMem->gdbus->name = (char *) &sharedMem->gdbus[1];
    if (KeyIso_rand_bytes(rand, sizeof(rand)) != STATUS_OK) {
        KEYISOP_trace_log_error(sharedMem->correlationId, 0, title, "Error","failed to get random bytes");
        goto end;
    }
    KeyIsoP_bytes_to_hex((int) sizeof(rand), rand, nameRand);
    BIO_snprintf(sharedMem->gdbus->name, nameLength, "%s%s",
        namePrefix, nameRand);

    //
    // Only the owner will be able to write
    // Everyone will be able to read. This is OK, these are
    // public certificates.
    //
    sharedMem->gdbus->fd = shm_open(
        sharedMem->gdbus->name,
        O_RDWR | O_CREAT,
        S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (sharedMem->gdbus->fd == -1) {
        int err = errno;
        KEYISOP_trace_log_errno(sharedMem->correlationId, 0, title, "shm_open", err);
        sharedMem->gdbus->name = NULL;
        goto end;
    }

    if (ftruncate(sharedMem->gdbus->fd, sharedMem->memLength) != 0) {
        int err = errno;
        KEYISOP_trace_log_errno(sharedMem->correlationId, 0, title, "ftruncate", err);
        goto end;
    }
    // 
    // Workaround: change mode of shared memory file,
    // so other users has read access to it.
    //
    if (fchmod(sharedMem->gdbus->fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) < 0)
    {
        int err = errno;
        KEYISOP_trace_log_errno(sharedMem->correlationId, 0, title, "fchmod", err);
    }
    sharedMem->memBytes = mmap(
        NULL,       // void *addr
        (size_t) sharedMem->memLength,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        sharedMem->gdbus->fd,
        0);         // offt_t offset
    if (sharedMem->memBytes == MAP_FAILED) {
        int err = errno;
        KEYISOP_trace_log_errno(sharedMem->correlationId, 0, title, "mmap", err);
        sharedMem->memBytes = NULL;
        goto end;
    }

    close(sharedMem->gdbus->fd);
    sharedMem->gdbus->fd = -1;
    ret = 1;

end:
    return ret;
}


void KMPP_GDBUS_close_shared_mem(
    KEYISO_SHARED_MEM *sharedMem)
{
    const char *title = KEYISOP_GDBUS_CLIENT_TITLE;
    if (sharedMem == NULL || sharedMem->gdbus == NULL) {
        return;
    }

    if (sharedMem->gdbus->fd != -1) {
        close(sharedMem->gdbus->fd);
    }

    if (sharedMem->memBytes != NULL) {
        if (munmap(sharedMem->memBytes, (size_t) sharedMem->memLength) != 0) {
            int err = errno;
            KEYISOP_trace_log_errno(sharedMem->correlationId, 0, title, "munmap", err);
        }
    }

    if (sharedMem->gdbus->name != NULL) {
        if (shm_unlink(sharedMem->gdbus->name) != 0) {
            int err = errno;
            KEYISOP_trace_log_errno(sharedMem->correlationId, 0, title, "shm_unlink", err);
        }
    }

    KeyIso_free(sharedMem->gdbus);
}


static
GdbusKMPPctrl *_get_kmppctrl_proxy(
    const uuid_t correlationId)
{
    const char *title = KEYISOP_GDBUS_CLIENT_TITLE;
    GdbusKMPPctrl *proxy = NULL;
    GError *error = NULL;   // KMPP_GDBUS_trace_log_glib_error() frees

    proxy = gdbus_kmppctrl_proxy_new_for_bus_sync(
        G_BUS_TYPE_SYSTEM,
        0,                          // flags
        KMPPCTRL_BUS_NAME,
        "/" ,                       // object_path
        NULL,
        &error);
    if (error) {
        KMPP_GDBUS_trace_log_glib_error(correlationId, 0, title, NULL, &error);
    }

    if (proxy != NULL) {
        // The default timeout is 25 seconds

        // Set to 5 minutes. Timeout is in milliseconds.
        g_dbus_proxy_set_default_timeout(G_DBUS_PROXY(proxy), 5 * 60 * 1000);
    }

    return proxy;
}


int KMPP_GDBUS_CLIENT_cert_ctrl(
    const uuid_t correlationId,
    KEYISO_SHARED_MEM *sharedMem,
    int ctrl,
    int location,
    int format,
    int length,
    const unsigned char *bytes)
{
    const char *title = KEYISOP_GDBUS_CLIENT_TITLE;
    const char *loc = "";
    const char *errStr = "Out of memory";
    int ret = 0;
    gint out_ret = 0;
    GVariant *correlationIdVariant = NULL;
    KEYISO_SHARED_MEM *allocSharedMem = NULL;
    GdbusKMPPctrl *proxy = NULL;
    GError *error = NULL;   // KMPP_GDBUS_trace_log_glib_error() frees
    int retryCount = 0;

    if (sharedMem == NULL) {
        unsigned char *sharedMemBytes = NULL;           // don't free

        allocSharedMem = KeyIso_open_shared_mem(
            correlationId,
            length,
            &sharedMemBytes);
        if (allocSharedMem == NULL) {
            goto end;
        }

        sharedMem = allocSharedMem;
        memcpy(sharedMemBytes, bytes, length);
    }

    correlationIdVariant = g_variant_new_fixed_array(
        G_VARIANT_TYPE_BYTE,
        correlationId,
        sizeof(uuid_t),
        sizeof(guchar));
    if (correlationIdVariant == NULL) {
        loc = "correlationIdVariant";
        goto err;
    }

    proxy = _get_kmppctrl_proxy(correlationId);
    if (proxy == NULL) {
        loc = "_get_kmppctrl_proxy";
        errStr = "No proxy";
        goto err;
    }

    for (;;) {
        gboolean enableRetry = FALSE;
        gboolean callRet = gdbus_kmppctrl_call_cert_ctrl_sync(
                proxy,
                g_variant_ref(correlationIdVariant),
                KEYISOP_VERSION_1,
                ctrl,
                location,
                format,
                length,
                sharedMem->gdbus->name,
                &out_ret,
                NULL,                   // cancellable
                &error);
        if (callRet && error == NULL) {
            break;
        }

        if (++retryCount <= 2 && GDBUS_is_gdbus_retry_error(error)) {
            enableRetry = TRUE;
        }

        KMPP_GDBUS_trace_log_glib_error(correlationId, 0, title, "call_cert_ctrl", &error);
        if (!enableRetry) {
            goto end;
        }

        KEYISOP_trace_log_error_para(correlationId, KEYISOP_TRACELOG_WARNING_FLAG, title, "call_cert_ctrl", "Retry",
            "retryCount: %d", retryCount);

        GDBUS_g_object_unref(proxy);
        proxy = NULL;

        // 5 seconds
        g_usleep((gulong)(5000 * 1000)); // Microseconds

        proxy = _get_kmppctrl_proxy(correlationId);
        if (proxy == NULL) {
            loc = "_get_kmppctrl_proxy";
            errStr = "No proxy";
            goto err;
        }
    }

    ret = out_ret;

end:
    GDBUS_g_variant_unref(correlationIdVariant);
    KeyIso_close_shared_mem(allocSharedMem);
    if (proxy != NULL) {
        GDBUS_g_object_unref(proxy);
        proxy = NULL;
    }
    GDBUS_exhaust_main_loop_events();
    return ret;

err:
    KEYISOP_trace_log_error(correlationId, 0, title, loc, errStr);
    goto end;
}
