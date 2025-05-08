/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <jansson.h>

#include "keyisocommon.h"
#include "keyisojsonutils.h"
#include "keyisolog.h"
#include "keyisomemory.h"

#define ALLOWED_APPS_ARRAY_NAME "allowed_apps"
#define MAX_PROC_NAME_LENGTH 256
#define PROC_SELF_EXE "/proc/self/exe"

static CRYPTO_ONCE jsonInitOnce = CRYPTO_ONCE_STATIC_INIT;
static json_t *cachedJson = NULL; // Store JSON for reuse
static int cachedStatus = AllowedAppStatus_FileNotFound;

// Function to check if a file exists
static int _file_exists(const char *path)
{
    struct stat buffer;
    return (stat(path, &buffer) == 0);
}

// Function to load and validate JSON
static AllowedAppStatus _load_and_validate_json(json_t **jsonOut)
{
    if (!_file_exists(KMPP_ALLOWED_APPS_JSON_CONFIG)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_KMPP_ALLOWED_APPS_TITLE, "Invalid file", "kmpp_apps.json file does not exist");
        return AllowedAppStatus_FileNotFound; // File not found
    }

    json_error_t error;
    json_t *json = json_load_file(KMPP_ALLOWED_APPS_JSON_CONFIG, 0, &error);
    if (!json) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_KMPP_ALLOWED_APPS_TITLE, "Invalid file", "Unable to load JSON file");
        return AllowedAppStatus_FileCorrupted; // File error
    }

    // Check if "allowed_apps" exists and is an array
    json_t *appsArray = json_object_get(json, ALLOWED_APPS_ARRAY_NAME);
    if (!json_is_array(appsArray)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_KMPP_ALLOWED_APPS_TITLE, "Invalid file", "'allowed_apps' is missing or not an array in JSON file");
        json_decref(json);
        return AllowedAppStatus_ArrayInvalid; // Schema error
    }

    // Check that all elements in the array are strings
    size_t index;
    json_t *value;
    json_array_foreach(appsArray, index, value) {
        if (!json_is_string(value)) {
            KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_KMPP_ALLOWED_APPS_TITLE, 
                "validate_json", "Invalid file", 
                "Element at index %zu in 'allowed_apps' is not a string in JSON file", 
                index);
            json_decref(json);
            return AllowedAppStatus_ArrayInvalid; // Schema error
        }
    }

    *jsonOut = json;
    return AllowedAppStatus_FileValidationSuccess; // Success
}

static void _init_json(void)
{
    json_t *json = NULL;
    int status = _load_and_validate_json(&json);

    if (status == AllowedAppStatus_FileValidationSuccess) {
        cachedJson = json; // Store the loaded JSON
    } else {
        json_decref(json); // Cleanup if it failed
    }
    cachedStatus = status;
}

static AllowedAppStatus _load_and_validate_json_once(json_t **jsonOut)
{
    if (!CRYPTO_THREAD_run_once(&jsonInitOnce, _init_json)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_KMPP_ALLOWED_APPS_TITLE, "Invalid file", "_load_and_validate_json_once Failed");
        return AllowedAppStatus_FileCorrupted;
    }

    if (cachedStatus == AllowedAppStatus_FileValidationSuccess) {
        *jsonOut = cachedJson;
    } else {
        *jsonOut = NULL;
    }
    
    return cachedStatus;
}


// Function to check if a procName exists in the JSON file
AllowedAppStatus KeyIso_is_app_configured(const char *procName)
{
    int ret = AllowedAppStatus_AppNotAllowed; // Default to failure
    json_t *json = NULL;
    json_t *appsArray = NULL;

    // Check input parameters
    if ((!procName) || (strnlen(procName, MAX_PROC_NAME_LENGTH) == 0)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_KMPP_ALLOWED_APPS_TITLE, "Invalid proccess name", "NULL or empty procName provided");
        return AllowedAppStatus_ProcNameInvalid;
    }

    // Load and validate JSON file
    ret = _load_and_validate_json_once(&json);
    if (ret == AllowedAppStatus_FileValidationSuccess) {
        appsArray = json_object_get(json, ALLOWED_APPS_ARRAY_NAME);
        size_t arraySize = json_array_size(appsArray);

        if (arraySize == 0) {
            KEYISOP_trace_log(NULL, 0, KEYISOP_KMPP_ALLOWED_APPS_TITLE, "'allowed_apps' is an empty array in JSON file");
            ret = AllowedAppStatus_ArrayEmpty; // No apps are allowed
        }
        // If the only element is "all", allow all apps
        else if (arraySize == 1) {
            json_t *firstElement = json_array_get(appsArray, 0);
            const char *firstValue = json_string_value(firstElement);
            if (firstValue && strncmp(firstValue, "all", strnlen(firstValue, MAX_PROC_NAME_LENGTH)) == 0) {
                KEYISOP_trace_log(NULL, 0, KEYISOP_KMPP_ALLOWED_APPS_TITLE, "All apps are allowed");
                ret = AllowedAppStatus_AppAllowed; // Allow all apps
            }
            else {
                // Continue to check if app name matches
                ret = AllowedAppStatus_AppNotAllowed;
            }
        }

        // If status wasn't determined yet, search for the specific app procName
        if (ret != AllowedAppStatus_ArrayEmpty && ret != AllowedAppStatus_AppAllowed) {
            size_t index;
            json_t *value;
            ret = AllowedAppStatus_AppNotAllowed; // Default to not found

            json_array_foreach(appsArray, index, value) {
                const char *appName = json_string_value(value);
                if (appName && (strncmp(appName, procName, MAX_PROC_NAME_LENGTH) == 0)) {
                    ret = AllowedAppStatus_AppAllowed; // Name found
                    break;
                }
            }
        }
    }

    // Cleanup resources
    if (json) {
        json_decref(json);
    }

    return ret;
}

// Function to check if a procName exists in the JSON file and validate permissions
AllowedAppStatus KeyIso_get_allowed_app_status(const char *procName)
{
    struct stat fileStat;
    
    if (stat(KMPP_ALLOWED_APPS_JSON_CONFIG, &fileStat) < 0) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_KMPP_ALLOWED_APPS_TITLE, "Error in stat", "Error in stat");
        return AllowedAppStatus_FileNotFound;
    }

    // Validate ownership: must be owned by root (UID 0)
    if (fileStat.st_uid != 0) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_KMPP_ALLOWED_APPS_TITLE, "File ownership error", "File must be owned by root");
        return AllowedAppStatus_WrongPermissions;
    }

    // Ensure:
    // 1. Only root can write -> Writable ONLY by owner (root)
    // 2. Readable by everyone (others)
    if ((fileStat.st_mode & (S_IWGRP | S_IWOTH)) ||  // Group/Others cannot write
        !(fileStat.st_mode & S_IROTH) ||            // Others must be able to read
        !(fileStat.st_mode & S_IWUSR)) {            // Owner (root) must be able to write
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_KMPP_ALLOWED_APPS_TITLE, "File permissions error", "Incorrect file permissions");
        return AllowedAppStatus_WrongPermissions;
    }

    return KeyIso_is_app_configured(procName);
}

char* KeyIso_get_process_name()
{
    char path[KEYISO_MAX_PATH_LEN] = {0};

    ssize_t len = readlink(PROC_SELF_EXE, path, sizeof(path) - 1);
    if (len == -1) {
        return NULL;
    }
    path[len] = '\0';

    // Extract the process name from the path
    char *procName = strrchr(path, '/');
    if (procName) {
        procName++;
    } else {
        procName = path;
    }

	// Check if the process name is too long
	if (strnlen(procName, MAX_PROC_NAME_LENGTH) >= MAX_PROC_NAME_LENGTH) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_KMPP_ALLOWED_APPS_TITLE, "Invalid proccess name", "Too long");
		return NULL;
	}

    char *result = strndup(procName, MAX_PROC_NAME_LENGTH);
    if (!result) {
        return NULL;
    }

    return result;
}


bool KeyIso_is_app_allowed(const char* procName)
{
    AllowedAppStatus status = KeyIso_get_allowed_app_status(procName);

    if (status == AllowedAppStatus_AppAllowed) {
        return true;
    }
    return false;
}
