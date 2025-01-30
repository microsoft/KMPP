/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <grp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h> 

#include "keyisocommon.h"
#include "keyisolog.h"
#include "keyisotpmcommon.h"
#include "keyisomemory.h"

#define KMPP_CONFIG_TPM_ISOLATION_SECTION   "tpm_isolation"
#define KMPP_CONFIG_SRK_NVRAM_INDEX         "srk_nvram_index"
#define KMPP_CONFIG_TCTI                    "tcti"
#define TSS_GROUP_NAME                      "tss"

static int _validate_tcti(const char* tcti) 
{
    const char* title = KEYISOP_LOAD_LIB_TITLE;
    size_t len = strnlen(tcti, PATH_MAX);
    if (len == 0 || len == PATH_MAX) {
        KEYISOP_trace_log_error_para(NULL, 0, title, "config load failed", "tcti len is invalid", "len %d", len);
        return STATUS_FAILED;
    }
    return STATUS_OK;
}

static int _parse_and_validate_tpm_nvram_index(const char* nvramIndexStr, uint32_t* nvramIndex) {
    const char* title = KEYISOP_LOAD_LIB_TITLE;
    char* endPtr;
    errno = 0; 

    if (nvramIndex == NULL) {
        KEYISOP_trace_log_error(NULL, 0, title, "config load failed", "nvramIndexStr cant be NULL");
        return STATUS_FAILED;
    }

    unsigned long index = strtoul(nvramIndexStr, &endPtr, 16);
    if ((errno == ERANGE && (index == ULONG_MAX)) || (errno != 0 && index == 0)) {
        KEYISOP_trace_log_error_para(NULL, 0, title, "config load failed", "strtoul failed", "errno %d", errno);
        return STATUS_FAILED;
    }

    // Validate that endPtr does not point to the beginning of the nvramIndexStr and not to any other character then the null terminator
    // i.e validate that the entire string was converted to a number and there are no invalid characters
    if (endPtr == nvramIndexStr || *endPtr != '\0') {
        KEYISOP_trace_log_error(NULL, 0, title, "config load failed", "invalid characters found in NVRAM index string");
        return STATUS_FAILED;
    }

    if (index > UINT32_MAX) {
        KEYISOP_trace_log_error_para(NULL, 0, title, "config load failed", "NVRAM index is too big", "index %lu", index);
        return STATUS_FAILED;
    }

    *nvramIndex = (uint32_t)index;
    return STATUS_OK;
}

KEYISO_TPM_CONFIG_ST KeyIso_load_tpm_config(const CONF *conf)
{
    KEYISO_TPM_CONFIG_ST tpmConf = {
        .nvIndex = DEFAULT_NV_INDEX,
        .tctiNameConf = DEFAULT_TCTI_CONFIG
    };

    char *tcti = NCONF_get_string(conf, KMPP_CONFIG_TPM_ISOLATION_SECTION, KMPP_CONFIG_TCTI);
    if (tcti && (_validate_tcti(tcti) == STATUS_OK) ) {
        strcpy(tpmConf.tctiNameConf, tcti);
        KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_LOAD_LIB_TITLE, "TPM config", "tctiNameConf: '%s'", tpmConf.tctiNameConf);

    } else {
        KEYISOP_trace_log_para(NULL, 0, KEYISOP_LOAD_LIB_TITLE, "empty or invalid  tcti config, using default value", "tctiNameConf: '%s'", tpmConf.tctiNameConf);
    }

    char *srkIndexStr = NCONF_get_string(conf, KMPP_CONFIG_TPM_ISOLATION_SECTION, KMPP_CONFIG_SRK_NVRAM_INDEX);
    uint32_t srkIndex = 0;
    if (srkIndexStr && (_parse_and_validate_tpm_nvram_index(srkIndexStr, &srkIndex) == STATUS_OK) ) {
        tpmConf.nvIndex = (TPM2_HANDLE )srkIndex;
    } else {
        KEYISOP_trace_log(NULL, 0, KEYISOP_LOAD_LIB_TITLE, "Empty or invalid NVRAM index config, using default NVRAM index");
    }
    return tpmConf;
}

// This function returns 1 if the user is in the specified group, 0 if not, and -1 on error
static int _is_user_in_group(const char *groupName) 
{
    struct group *grp;
    gid_t *groups = NULL;
    gid_t gid;
    int ngroups;

    const char* title = KEYISOP_LOAD_LIB_TITLE;
    grp = getgrnam(groupName);
    if (grp == NULL) {
        KEYISOP_trace_log_error_para(NULL, 0, title, "group membership check failed", "Group id not found by name", "groupName %s", groupName);
        return -1;
    }
    gid = grp->gr_gid;

    ngroups = getgroups(0, NULL);
    if (ngroups == -1) {
        KEYISOP_trace_log_error_para(NULL, 0, title, "group membership check failed", "Failed to get the number of groups the user belongs to", "groupName %s", groupName);
        return -1;
    }
    
    if (ngroups == 0) {
        return 0; //  The user does not belong to any supplementary groups
    }

    size_t size = ngroups * sizeof(gid_t);
    groups = KeyIso_zalloc(size);
    if (groups == NULL) {
        KEYISOP_trace_log_error_para(NULL, 0, title, "group membership check failed", "Failed to allocate memory for groups", "groupName %s, size:%lu", groupName, size);
        return -1;
    }

    if (getgroups(ngroups, groups) == -1) {
        KEYISOP_trace_log_error_para(NULL, 0, title, "group membership check failed", "Failed to get the list of group IDs", "groupName %s", groupName);
        KeyIso_free(groups);
        return -1;
    }

    for (int i = 0; i < ngroups; i++) {
        if (groups[i] == gid) {
            KeyIso_free(groups);
            return 1; // User is in the group
        }
    }

    // Clean up
    KeyIso_free(groups);
    return 0; // User is not in the group
}

void KeyIso_validate_user_privileges(KeyIsoSolutionType solutionType) 
{
    const char* title = KEYISOP_LOAD_LIB_TITLE;

    int res = _is_user_in_group(TSS_GROUP_NAME);
    switch (res) {
        case -1:
            KEYISOP_trace_log_error(NULL, KEYISOP_TRACELOG_WARNING_FLAG, title, "", "Failed to check if the user belongs to the 'tss' group");
            break;
        case 0:
            KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "User does not belong to the 'tss' group");
            break;
        case 1:
            KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "User belongs to the 'tss' group");
            // If the user executing the application belongs to the TSS group but a non-TPM  isolation solution is configured,
            // then the application should terminate. This is a security measure to ensure that the application is not run with excessive privileges.
            if ((solutionType != KeyIsoSolutionType_tpm) && (getuid() != getpwnam(KMPP_USER_NAME)->pw_uid)) {
                KEYISOP_trace_log_error_para(NULL, 0, title, "Process was terminated", "Detected excessive privileges. The configured isolation solution is different then TPM, yet the process run by user that belongs to the 'tss' group", "solutionType %d", solutionType);
                exit(EXIT_FAILURE);
            }
            break;
        default:
            KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, title, "", "Failed to check if the user belongs to the 'tss' group, invalid return value of _init_selected_keyIso_solution", "res %d", res);
            break;
    }
}