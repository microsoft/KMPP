/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

 #include <string.h>
 
#include <openssl/crypto.h>

#include "keyisomemory.h"
#include "keyisolog.h"


//
// KEYISO memory functions
//

void* KeyIso_zalloc(
    size_t num)
{    
    return OPENSSL_zalloc(num);
}

void* KeyIso_realloc(
    void *mem,
    size_t num)
{
    return OPENSSL_realloc(mem, num);
}

void* KeyIso_clear_realloc(
    void *mem,
    size_t old_num,
    size_t num)
{    
    return OPENSSL_clear_realloc(mem, old_num, num);
}

void KeyIso_free(
    void *mem)
{
    OPENSSL_free(mem);
}

void KeyIso_clear_free(
    void *mem,
    size_t num)
{
    OPENSSL_clear_free(mem, num);
}

void KeyIso_clear_free_string(
    char *str)
{
    if (str != NULL) {
        KeyIso_clear_free(str, strlen(str));
    }
}

void KeyIso_cleanse(
    void *mem,
    size_t num)
{
    OPENSSL_cleanse(mem, num);
}

char *KeyIso_strndup(
    const char *str,
    size_t maxStrLen)
{    
    return OPENSSL_strndup(str, maxStrLen);
}

unsigned char *KeyIso_memdup(
    const void *src,
    size_t len)
{
    return OPENSSL_memdup(src, len);
}

////~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~////
////            NOT TO USE FUNCTIONS - backward compatibility reasons only  !!!!!!!                  ////
////~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~////

// The following KeyIso_strdup should not be used. use KeyIso_strndup instead
char* KeyIso_strdup(
    const char *str)
{   
    KEYISOP_trace_log_error(NULL, 0, "KMPPMemory", "KeyIso_strdup function should not be used !!!", "NULL as return value for error indication");     

    return NULL; // This function should not be used. Returning NULL for error indication.
}