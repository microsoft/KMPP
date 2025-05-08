#pragma once

#ifdef  __cplusplus
extern "C" {
#endif

typedef enum {
    AllowedAppStatus_FileValidationSuccess = 0,
    AllowedAppStatus_AppAllowed,
    AllowedAppStatus_AppNotAllowed,
    AllowedAppStatus_FileCorrupted,
    AllowedAppStatus_FileNotFound,
    AllowedAppStatus_ArrayInvalid,
    AllowedAppStatus_ArrayEmpty,
    AllowedAppStatus_ProcNameInvalid,
    AllowedAppStatus_WrongPermissions
} AllowedAppStatus;

AllowedAppStatus KeyIso_is_app_configured(const char *procName);

AllowedAppStatus KeyIso_get_allowed_app_status(const char* procName);

char* KeyIso_get_process_name();

bool KeyIso_is_app_allowed(const char *procName);

#ifdef  __cplusplus

}
#endif