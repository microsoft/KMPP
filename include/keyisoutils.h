/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#ifdef KEYISO_TEST_WINDOWS
typedef unsigned char uuid_t[16];
#include <windows.h>

struct timeval {
    int     tv_sec;     /* seconds */
    int     tv_usec;    /* microseconds */
};

struct timezone {
    int     tz_minuteswest;     /* minutes west of Greenwich */
    int     tz_dsttime;         /* type of DST correction */
};

int gettimeofday(
    struct timeval* tv,
    struct timezone* tz);

#else
#include <uuid/uuid.h>
#endif // #ifdef KEYISO_TEST_WINDOWS

#ifdef  __cplusplus
extern "C" {
#endif

#define KEYISOP_TRACE_LOG_TEST_EXECUTE_FLAG    0x2
#define KEYISOP_TRACE_LOG_VERBOSE_EXECUTE_FLAG 0x4
#define KEYISOP_LAST_EXTERNAL_EXECUTE_FLAG     KEYISOP_TRACE_LOG_VERBOSE_EXECUTE_FLAG

void KeyIsoP_set_execute_flags(
    int flags);

// Call the following to redirect the trace log output
// from stdout to the specified file.
void KeyIsoP_set_trace_log_filename(
    const char *filename);

#ifndef KMPP_ROOT_DIR
#ifdef KMPP_TEST_WINDOWS
#define KMPP_ROOT_DIR ""
#else
#define KMPP_ROOT_DIR "/var/opt/msft/kmpp"
#endif
#endif

#ifndef KMPP_PRIVATE_ROOT_DIR
#ifdef KMPP_TEST_WINDOWS
#define KMPP_PRIVATE_ROOT_DIR ""
#else
#define KMPP_PRIVATE_ROOT_DIR "/var/opt/msft/kmpp-private"
#endif
#endif

#define KMPP_CERTS_DIR KMPP_ROOT_DIR "/certs"

#ifndef KMPP_INSTALL_IMAGE_DIR
#ifdef KMPP_TEST_WINDOWS
#define KMPP_INSTALL_IMAGE_DIR ""
#else
#define KMPP_INSTALL_IMAGE_DIR "/opt/msft/kmpp"
#endif
#endif


void KeyIsoP_set_default_dir(
    const char *defaultCertArea,
    const char *defaultCertDir);

const char *KeyIsoP_get_default_cert_area();
const char *KeyIsoP_get_default_private_area();
const char *KeyIsoP_get_default_cert_dir();
const char *KeyIsoP_get_install_image_dir();

// Includes NULL terminator character
#define KEYISOP_BASE64_ENCODE_LENGTH(inLength) ((((inLength + 3 - 1) / 3) * 4) + 1)

// Returns number of decode bytes. For a decode error returns -1.
int KeyIso_base64_decode(
    const uuid_t correlationId,
    const char *str,
    unsigned char **bytes);     // KeyIso_free()

// Converts binary bytes to NULL terminated ascii hex characters.
// Returned hex needs (len * 2 + 1) characters
void KeyIsoP_bytes_to_hex(
    int len,
    const unsigned char *pb,
    char *hex);

// KeyIso_free() returned path name
char *KeyIsoP_get_path_name(
    const char *dir,
    const char *subPath);

int KeyIso_rand_bytes(
    unsigned char *buffer,
    int size);

#ifdef  __cplusplus
}
#endif

