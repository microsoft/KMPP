/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once 

# ifdef KEYISO_TEST_WINDOWS
typedef unsigned char uuid_t[16];
# else
#   include <uuid/uuid.h>
# endif

#ifdef  __cplusplus
extern "C" {
#endif 

//
// KEYISO memory functions
//

void* KeyIso_zalloc(
    size_t num);

// KeyIso_clear_realloc must be used when the memory holding sensitive data
// (KeyIso_realloc does not clear the memory)
//*************************************************************************

void* KeyIso_realloc(
    void *mem,
    size_t num);

void* KeyIso_clear_realloc(
    void *mem,
    size_t old_num,
    size_t num);
//*************************************************************************

// KeyIso_clear_free must be used when the memory holding sensitive data
//*************************************************************************
void KeyIso_free(
    void *mem);

void KeyIso_clear_free(
    void *mem,
    size_t num);
    
//*************************************************************************

void KeyIso_clear_free_string(
    char *str);

void KeyIso_cleanse(
    void *mem,
    size_t num);

char* KeyIso_strndup(
    const char *str,
    size_t maxStrLen);
    

////~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~////
////            NOT TO USE FUNCTIONS - backward compatibility reasons only  !!!!!!!                  ////
////~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~////

// The following KeyIso_strdup should not be used. use KeyIso_strndup instead
__attribute__ ((deprecated))
char* KeyIso_strdup(
    const char *str);

#ifdef  __cplusplus
}
#endif