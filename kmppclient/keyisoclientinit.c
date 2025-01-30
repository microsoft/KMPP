/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

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
#define KMPP_CONFIG_SOLUTION_TYPE_PROCESS "process"
#define KMPP_CONFIG_SOLUTION_TYPE_TZ "tz"
#define KMPP_CONFIG_SOLUTION_TYPE_TPM "tpm"
#define KMPP_CONFIG_MAX_SIZE PATH_MAX


extern CLIENT_MSG_HANDLER_FUNCTIONS_TABLE_ST TPMMsgHandlerImplementation;
extern CLIENT_MSG_HANDLER_FUNCTIONS_TABLE_ST keyIsoMsgHandlerImplementation;

CLIENT_MSG_HANDLER_FUNCTIONS_TABLE_ST g_msgHandlerImplementation;
KEYISO_CLIENT_CONFIG_ST g_config;

static CRYPTO_ONCE selectedKeyIsoSolutionTypeOnce = CRYPTO_ONCE_STATIC_INIT; // Make sure that the selectedKeyIsoSolutionType is initialized only once

static void _set_isolation_solution(KeyIsoSolutionType solution, CLIENT_MSG_HANDLER_FUNCTIONS_TABLE_ST msgHandlerImp, bool isDefault) 
{
    g_config.solutionType = solution;
    g_config.isDefault = isDefault;
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
        return;
    }

    // Set message handler implementation based on solution type
    switch (solution) {
        case KeyIsoSolutionType_process:
#ifndef KMPP_GENERAL_PURPOSE_TARGET
        case KeyIsoSolutionType_tz:
            solution = KeyIso_get_isolation_solution_for_tz(); 
#endif
            msgHandlerImp = keyIsoMsgHandlerImplementation;
            break;
#ifdef KMPP_GENERAL_PURPOSE_TARGET
        case KeyIsoSolutionType_tpm:
            msgHandlerImp = TPMMsgHandlerImplementation;
            g_config.tpmConfig = KeyIso_load_tpm_config(conf);
            break;
#endif
        default:
            KEYISOP_trace_log_error_para(NULL, 0, title, "config load failed", "invalid solution type", "solutionType %d", solution);
            _set_default_isolation_solution();
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
