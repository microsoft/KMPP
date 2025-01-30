/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdlib.h> 
#include <string.h>
#include "keyisomemory.h"

//
// KEYISO memory functions
//

typedef void *(*memset_t)(void *, int, size_t);
static volatile memset_t memset_func = memset;

void KeyIso_cleanse(void *mem, size_t num)
{    
    if (NULL != mem) {
        // To prevent potential compiler optimization to memset, we defined a volatile function pointer  
        memset_func(mem, 0, num);
    }    
}

void KeyIso_free(
    void *mem)
{
    if (NULL != mem) {
        free(mem);
    }
}

void* KeyIso_zalloc(
    size_t num)
{     
    void *ret = NULL;

    if (0 != num) {
        ret = calloc(1, num);
    }   

    return ret;
}

void* KeyIso_realloc(
    void *mem,
    size_t num)
{  
    void *ret = NULL;
   
    if (0 == num) {
        KeyIso_free(mem);
        return NULL;
    }    
 
    ret = (NULL == mem) ? malloc(num) : realloc(mem, num);    
 
    return ret;
}

void* KeyIso_clear_realloc(
    void *mem,
    size_t old_num,
    size_t num)
{
    void *ret = NULL;

    if (NULL == mem) {
        if (0 == num) {
            return NULL;
        }        
        return calloc(1, num);
    }

    if (0 == num) {
        KeyIso_clear_free(mem, old_num);
        return NULL;
    }       

    if (num < old_num) {
        // In this case - cleaning the |old_num - num| bytes from the end and "shrinking" the buffer.
        KeyIso_cleanse((char*)mem + num, old_num - num);
        return mem;
    }

    ret = calloc(1, num);

    if (NULL != ret) {
        memcpy(ret, mem, old_num);
        KeyIso_clear_free(mem, old_num);
    }

    return ret;
}

void KeyIso_clear_free(
    void *mem,
    size_t num)
{
    if (NULL == mem) {
        return;
    }

    if (num) {
        KeyIso_cleanse(mem, num);
    }
    
    KeyIso_free(mem);
}

void KeyIso_clear_free_string(
    char *str)
{
    if (NULL != str) {
        KeyIso_clear_free(str, strlen(str));
    }
}

char *KeyIso_strndup(
    const char *str,
    size_t maxStrLen)
{    
    // Using strndup to duplicate the string up to maxStrLen characters
    return strndup(str, maxStrLen);    
}

////~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~////
////            NOT TO USE FUNCTIONS - backward compatibility reasons only  !!!!!!!                  ////
////~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~////

// The following KeyIso_strdup should not be used. use KeyIso_strndup instead
char* KeyIso_strdup(
    const char *str)
{
    (void)str; // Mark the parameter as unused
    return NULL; // This function should not be used. Returning NULL for error indication.
}