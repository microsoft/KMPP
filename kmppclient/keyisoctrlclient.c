/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <string.h>

#include <openssl/err.h>

#include "keyisoctrl.h"
#include "keyisocert.h"
#include "keyisocommon.h"
#include "keyisomemory.h"
#include "keyisolog.h"
#include "keyisoutils.h"
#include "keyisocertinternal.h"
#include "kmppgdbusctrlclient.h"

//
// External API's defined in keyisoctrlclient.h
//

// 
// Return:
//  +1 - Success with all certificates removed.
//  -1 - Partial Success. Removed at least one certificate. Failed to
//       remove one or more certificates.
//   0 - Error, unable to remove any certificates.
int KeyIso_remove_trusted_certs(
    const uuid_t correlationId,
    int certFormat,
    int certLength,
    const unsigned char *certBytes)
{
    return KeyIso_CLIENT_cert_ctrl(
        correlationId,
        NULL,
        KEYISO_CERT_CTRL_REMOVE,
        KEYISO_CERT_LOCATION_ROOT,
        certFormat,
        certLength,
        certBytes);
}

// Return:
//  +1 - Success with all certificates imported.
//  -1 - Partial Success. Imported at least one certificate. Failed to
//       import one or more certificates.
//   0 - Error, unable to import any certificates.
int KeyIso_import_disallowed_certs(
    const uuid_t correlationId,
    int certFormat,
    int certLength,
    const unsigned char *certBytes)
{
    return KeyIso_CLIENT_cert_ctrl(
        correlationId,
        NULL,
        KEYISO_CERT_CTRL_IMPORT,
        KEYISO_CERT_LOCATION_DISALLOWED,
        certFormat,
        certLength,
        certBytes);
}

// Return:
//  +1 - Success with all certificates removed.
//  -1 - Partial Success. Removed at least one certificate. Failed to
//       remove one or more certificates.
//   0 - Error, unable to remove any certificates.
int KeyIso_remove_disallowed_certs(
    const uuid_t correlationId,
    int certFormat,
    int certLength,
    const unsigned char *certBytes)
{
    return KeyIso_CLIENT_cert_ctrl(
        correlationId,
        NULL,
        KEYISO_CERT_CTRL_REMOVE,
        KEYISO_CERT_LOCATION_DISALLOWED,
        certFormat,
        certLength,
        certBytes);
}

//
// Shared Memory Functions called from the client defined in keyisoctrl.h or keyisointernalctrl.h
//

KEYISO_SHARED_MEM *KeyIso_open_shared_mem(
    const uuid_t correlationId,
    int memLength,
    unsigned char **memBytes)
{
    int ret = 0;
    KEYISO_SHARED_MEM *sharedMem = NULL;
    uuid_t randId;

    *memBytes = NULL;

    if (correlationId == NULL) {
        KeyIso_rand_bytes(randId, sizeof(randId));
        correlationId = randId;
    }

    sharedMem = (KEYISO_SHARED_MEM *) KeyIso_zalloc(sizeof(KEYISO_SHARED_MEM));
    if (sharedMem == NULL) {
        goto end;
    }

    memcpy(sharedMem->correlationId, correlationId, sizeof(sharedMem->correlationId));
    sharedMem->memLength = memLength;

    if (KEYISOP_inProc) {
        sharedMem->memBytes = (unsigned char *) KeyIso_zalloc(memLength);
        if (sharedMem->memBytes == NULL) {
            goto end;
        }
        ret = 1;
    } else {
        ret = KMPP_GDBUS_open_shared_mem(sharedMem);
    }

    *memBytes = sharedMem->memBytes;

end:
    if (!ret) {
        KeyIso_close_shared_mem(sharedMem);
        sharedMem = NULL;
    }

    return sharedMem;
}

void KeyIso_close_shared_mem(
    KEYISO_SHARED_MEM *sharedMem)
{
    if (sharedMem == NULL) {
        return;
    }

    if (KEYISOP_inProc) {
        KeyIso_free(sharedMem->memBytes);
    } else {
        KMPP_GDBUS_close_shared_mem(sharedMem);
    }

    KeyIso_free(sharedMem);
}

int KeyIso_CLIENT_cert_ctrl(
    const uuid_t correlationId,
    KEYISO_SHARED_MEM *sharedMem,
    int ctrl,
    int location,
    int format,
    int length,
    const unsigned char *bytes)
{
    const char *title = KeyIsoP_get_cert_ctrl_title(ctrl, location);
    int ret = 0;
    uuid_t randId;
    const char *formatStr = "";

    if (correlationId == NULL) {
        KeyIso_rand_bytes(randId, sizeof(randId));
        correlationId = randId;
    }


    switch (format) {
        case KEYISO_CERT_FORMAT_DER:
            formatStr = "der";
            break;
        case KEYISO_CERT_FORMAT_PEM:
            formatStr = "pem";
            break;
        case KEYISO_CERT_FORMAT_SST:
            formatStr = "sst";
            break;
        default:
            formatStr = "???";
    }

    KEYISOP_trace_log_para(correlationId, 0, title, "Start",
        "format: %s length: %d",
        formatStr, length);

    ERR_clear_error();

    if (KEYISOP_inProc) {
        ret = KeyIso_SERVER_cert_ctrl(
            correlationId,
            ctrl,
            location,
            format,
            length,
            bytes);
    } else {
        ret = KMPP_GDBUS_CLIENT_cert_ctrl(
            correlationId,
            sharedMem,
            ctrl,
            location,
            format,
            length,
            bytes);
    }

    if (ret > 0) {
        KEYISOP_trace_log(correlationId, 0, title, "Complete");
    } else {
        KEYISOP_trace_log_error(correlationId, 0, title, "Complete",
            ret < 0 ? "Partial updates" : "No updates");
    }

    return ret;
}

// Return:
//  +1 - Success with all certificates imported.
//  -1 - Partial Success. Imported at least one certificate. Failed to
//       import one or more certificates.
//   0 - Error, unable to import any certificates.
int KeyIso_import_trusted_certs(
    const uuid_t correlationId,
    int certFormat,
    int certLength,
    const unsigned char *certBytes)
{
    return KeyIso_CLIENT_cert_ctrl(
        correlationId,
        NULL,
        KEYISO_CERT_CTRL_IMPORT,
        KEYISO_CERT_LOCATION_ROOT,
        certFormat,
        certLength,
        certBytes);
}