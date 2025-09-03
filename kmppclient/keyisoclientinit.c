/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <dlfcn.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>

#include "keyisoclientinternal.h"
#include "keyisolog.h"
#include "keyisomemory.h"

#ifndef KMPP_GENERAL_PURPOSE_TARGET
#include "kmppopteeclient.h"
#endif


#define KMPP_CONFIG_PATH KMPP_INSTALL_IMAGE_DIR "/config.cnf"
#define KMPP_CONFIG_SECTION "kmpp_config"
#define KMPP_CONFIG_SOLUTION_TYPE "keyiso_solution_type"
#define KMPP_CONFIG_KMPP_ENABLE_BY_DEFAULT_TYPE "enable_by_default"
#define KMPP_CONFIG_KMPP_ENABLE_BY_DEFAULT_ACTIVE "active"
#define KMPP_CONFIG_SOLUTION_TYPE_PROCESS "process"
#define KMPP_CONFIG_SOLUTION_TYPE_TZ "tz"
#define KMPP_CONFIG_SOLUTION_TYPE_TPM "tpm"
#define KMPP_CONFIG_MAX_SIZE PATH_MAX


extern CLIENT_MSG_HANDLER_FUNCTIONS_TABLE_ST TPMMsgHandlerImplementation;
extern CLIENT_MSG_HANDLER_FUNCTIONS_TABLE_ST keyIsoMsgHandlerImplementation;

CLIENT_MSG_HANDLER_FUNCTIONS_TABLE_ST g_msgHandlerImplementation;
KEYISO_CLIENT_CONFIG_ST g_config;

// Global instance of KeysInUse state and functions
KEYISO_KEYSINUSE_ST g_keysinuse = {0}; // Initialize the KeysInUse state

static CRYPTO_ONCE selectedKeyIsoSolutionTypeOnce = CRYPTO_ONCE_STATIC_INIT; // Make sure that the selectedKeyIsoSolutionType is initialized only once
static CRYPTO_ONCE keysinuse_init_once = CRYPTO_ONCE_STATIC_INIT;

static void _unload_keysInUse_library()
{   
    g_keysinuse.isLibraryLoaded = false;
    g_keysinuse.load_key_func = NULL;
    g_keysinuse.on_use_func = NULL;
    g_keysinuse.unload_key_func = NULL;
    g_keysinuse.get_key_identifier_func = NULL;

    if (g_keysinuse.handle) {
        if (dlclose(g_keysinuse.handle) != 0) {
            char *error = dlerror();
            KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_LOAD_LIB_TITLE, "Failed to unload KeysInUse shared library", "%s", error);
        }
        g_keysinuse.handle = NULL;
    }
}

static void _load_keysInUse_library_once(void)
{ 
    g_keysinuse.isLibraryLoaded = false;
    
    // Explicit validation that the path is absolute and trusted
    if (KMPP_KEYS_IN_USE_LIB_PATH[0] != '/') {
        KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_LOAD_LIB_TITLE, "Invalid library path", "The library path is not absolute", "path: %s", KMPP_KEYS_IN_USE_LIB_PATH);
        return;
    }
    
    g_keysinuse.handle = dlopen(KMPP_KEYS_IN_USE_LIB_PATH, RTLD_NOW);
    if (!g_keysinuse.handle) {        
        KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_LOAD_LIB_TITLE, "Failed to load KeysInUse shared library", "%s", dlerror());        
        return;
    }

    dlerror(); // Clear any existing error
    // Load all function pointers
    g_keysinuse.load_key_func = (keysinuse_load_key_func_ptr)dlsym(g_keysinuse.handle, "keysinuse_load_key");
    g_keysinuse.on_use_func = (keysinuse_on_use_func_ptr)dlsym(g_keysinuse.handle, "keysinuse_on_use");
    g_keysinuse.unload_key_func = (keysinuse_unload_key_func_ptr)dlsym(g_keysinuse.handle, "keysinuse_unload_key");
    g_keysinuse.get_key_identifier_func = (keysinuse_get_key_identifier_func_ptr)dlsym(g_keysinuse.handle, "keysinuse_ctx_get_key_identifier");

    char *error = dlerror();
    // Verify all functions were loaded
    if (!g_keysinuse.load_key_func || !g_keysinuse.on_use_func || !g_keysinuse.unload_key_func || !g_keysinuse.get_key_identifier_func || error != NULL) {
        const char *errorMsg = error ? error : "Unknown error";
        KEYISOP_trace_log_para(NULL, 0, KEYISOP_LOAD_LIB_TITLE, "Failed to load KeysInUse functions", "%s", errorMsg);        
        _unload_keysInUse_library();     
        return;
    }
    
    g_keysinuse.isLibraryLoaded = true;        
}

bool KeyIso_load_keysInUse_library()
{
    CRYPTO_THREAD_run_once(&keysinuse_init_once, _load_keysInUse_library_once);    
    return g_keysinuse.isLibraryLoaded;
}

static void _set_isolation_solution(KeyIsoSolutionType solution, CLIENT_MSG_HANDLER_FUNCTIONS_TABLE_ST msgHandlerImp, bool isDefaultSolutionType) 
{
    // legacymode should be set to true when the OVL version is less than 3 and also it is not gb200 
    g_config.isLegacyMode = false;  // legacy mode means creating MsCrypt key format
#ifndef KMPP_GENERAL_PURPOSE_TARGET
    if (KeyIso_get_isolation_solution_for_tz() != KeyIsoSolutionType_tz) {
        g_config.isLegacyMode = true;
    }
#endif
    g_config.solutionType = solution;
    g_config.isDefaultSolutionType = isDefaultSolutionType;
    g_msgHandlerImplementation = msgHandlerImp;
    g_msgHandlerImplementation.set_config(&g_config);
}

static void _set_default_isolation_solution()
{
    KeyIsoSolutionType solution = KeyIsoSolutionType_process;
#ifndef KMPP_GENERAL_PURPOSE_TARGET
    
    solution = KeyIso_get_isolation_solution_for_tz();
#endif
    CLIENT_MSG_HANDLER_FUNCTIONS_TABLE_ST msgHandlerImp = keyIsoMsgHandlerImplementation;
    _set_isolation_solution(solution, msgHandlerImp, true);
    g_config.isKmppEnabledByDefault = false;
}

static KeyIsoSolutionType _get_solution_type(const char *solutionType)
{
    if (strcmp(solutionType, KMPP_CONFIG_SOLUTION_TYPE_PROCESS) == 0) {
        return KeyIsoSolutionType_process;
    } else if (strcmp(solutionType, KMPP_CONFIG_SOLUTION_TYPE_TZ) == 0) {
        return KeyIsoSolutionType_tz;
    } else if (strcmp(solutionType, KMPP_CONFIG_SOLUTION_TYPE_TPM) == 0) {
        return KeyIsoSolutionType_tpm;
    } else {

        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_LOAD_LIB_TITLE, "Invalid config value", "the string from config file not supported", "solutionType: %s", solutionType);
        return KeyIsoSolutionType_invalid;
    }
}

static int _validate_and_load_config(const char *configFilePath, CONF **conf) 
{
    struct stat configSt;
    if (stat(configFilePath, &configSt) != 0 || configSt.st_size > KMPP_CONFIG_MAX_SIZE) {
        int err = errno;
        // If the file does not exist, it is not an error
        if (err != ENOENT) {
            KEYISOP_trace_log_errno_para(NULL, 0, KEYISOP_LOAD_LIB_TITLE, "A custom configuration exists but validation failed", err, "configFilePath %s", configFilePath);
        }
        return STATUS_FAILED;
    }

    *conf = NCONF_new(NULL);
    if (NCONF_load(*conf, configFilePath, NULL) <= 0) {
        KEYISOP_trace_log_openssl_error_para(NULL, 0, KEYISOP_LOAD_LIB_TITLE, "", "Failed to load config file. Setting default configuration", "configFilePath %s", configFilePath);
        NCONF_free(*conf);
        *conf = NULL;
        return STATUS_FAILED;
    }
    return STATUS_OK;
}

// Get solution type from config the configuration file
static KeyIsoSolutionType _get_solution_type_from_config(CONF *conf)
{
    KeyIsoSolutionType solution = KeyIsoSolutionType_invalid;

    char *solution_type_str = NCONF_get_string(conf, KMPP_CONFIG_SECTION, KMPP_CONFIG_SOLUTION_TYPE);
    if (solution_type_str == NULL) {
        KEYISOP_trace_log_openssl_error_para(NULL, 0, KEYISOP_LOAD_LIB_TITLE, "config load failed", "solution_type not found in config file, setting to default", "configFilePath %s", KMPP_CUSTOM_CONFIG_PATH);
        return solution;  // Invalid
    }
    return _get_solution_type(solution_type_str);
}

static bool _get_enable_by_default_from_config(CONF* conf)
{
    char* enableByDefaultStr = NCONF_get_string(conf, KMPP_CONFIG_KMPP_ENABLE_BY_DEFAULT_TYPE, KMPP_CONFIG_KMPP_ENABLE_BY_DEFAULT_ACTIVE);
    if (enableByDefaultStr == NULL) {
        KEYISOP_trace_log_openssl_error_para(NULL, 0, KEYISOP_LOAD_LIB_TITLE, "config load failed", "kmpp_enable_by_default not found in config file", "configFilePath %s", KMPP_CUSTOM_CONFIG_PATH);
        return false;  // Default to false
    }

    return strncmp(enableByDefaultStr, "1", 1) == 0;
}

// Main function to load the client configuration
static void _kmpp_client_load_config() 
{
    CONF *conf = NULL;
    const char* title = KEYISOP_LOAD_LIB_TITLE;
    KeyIsoSolutionType solution = KeyIsoSolutionType_invalid;
    CLIENT_MSG_HANDLER_FUNCTIONS_TABLE_ST msgHandlerImp;

    if (_validate_and_load_config(KMPP_CUSTOM_CONFIG_PATH, &conf) == STATUS_FAILED) {
        _set_default_isolation_solution();
        return;
    }

    // Get solution type from config
    solution = _get_solution_type_from_config(conf);
    if (solution == KeyIsoSolutionType_invalid) {
        _set_default_isolation_solution();
        NCONF_free(conf);
        return;
    }

    // Set the enable by default flag per the subscription according to the configuration
    g_config.isKmppEnabledByDefault = _get_enable_by_default_from_config(conf);

    // Set message handler implementation based on solution type
    switch (solution) {
        case KeyIsoSolutionType_process:
            msgHandlerImp = keyIsoMsgHandlerImplementation;
            break;
#ifndef KMPP_GENERAL_PURPOSE_TARGET
        case KeyIsoSolutionType_tz:
            solution = KeyIso_get_isolation_solution_for_tz();
            msgHandlerImp = keyIsoMsgHandlerImplementation;
            break;
#else
        case KeyIsoSolutionType_tpm:
            msgHandlerImp = TPMMsgHandlerImplementation;
            g_config.tpmConfig = KeyIso_load_tpm_config(conf);
            break;
#endif
        default:
            KEYISOP_trace_log_error_para(NULL, 0, title, "config load failed", "invalid solution type", "solutionType %d", solution);
            _set_default_isolation_solution();
            NCONF_free(conf);
            return;
    }
    // Set isolation solution
    _set_isolation_solution(solution, msgHandlerImp, false);
    NCONF_free(conf);
}

/*
This function is used to set the selected key iso solution type according to the configuration file
It will load the config file only once
In case of a failure or invalid type it will set the default solution type 
*/
static void _init_selected_keyIso_solution() 
{
    if (!CRYPTO_THREAD_run_once(&selectedKeyIsoSolutionTypeOnce, _kmpp_client_load_config)) {
        KEYISOP_trace_log_openssl_error(NULL, 0, KEYISOP_LOAD_LIB_TITLE, "_kmpp_client_load_config execution failed");
    }
}

// This function is called when the library is loaded, 
__attribute__((constructor))
void kmpp_client_init(void)
{
    KEYISOP_traceLogConstructor = 1; // to enable logging in the constructor scope
    
    _init_selected_keyIso_solution();
#ifdef KMPP_GENERAL_PURPOSE_TARGET
    KeyIso_validate_user_privileges(g_config.solutionType);
#endif
    KEYISOP_traceLogConstructor = 0;
}

__attribute__((destructor))
void kmpp_client_cleanup(void)
{
    if (g_keysinuse.isLibraryLoaded) {
        _unload_keysInUse_library();
    }
}