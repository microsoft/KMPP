/* 
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <errno.h>
#include <features.h>
#include <linux/limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <uuid/uuid.h>

#include "keyisocommon.h"
#include "keyisoguidlookupcache.h"
#include "keyisolog.h"
#include "keyisomachinesecretrotation.h"
#include "keyisomemory.h"
#include "keyisoserviceapiossl.h"
#include "keyisoservicecommon.h"
#include "keyisoutils.h"

#define KEYISO_LATEST_FILENAME "latest"
#define KEYISO_GUID_STRING_LENGTH 36 // GUID string length 
#define KEYISO_SECRET_ROTATION_INTERVAL_DAYS 90  // Default secret rotation interval in days(and also the maximum allowed days for rotation(by LIQUID))
#define KEYISO_CURRENT_MACHINE_SECRET_SIZE 32 // Secret size in bytes - both legacy and latest
#define KEYISO_MAX_MACHINE_SECRET_SIZE KEYISO_CURRENT_MACHINE_SECRET_SIZE // Latest secret size in bytes
#define KEYISO_SECRET_ROTATION_INTERVAL_SECONDS(days) ((days) * 24 * 60 * 60) // Secret rotation interval in seconds
#define KEYISO_PRIVATE_DIR "/private/" // Directory for storing private key files
#define KEYISO_TEMP_FILE_SUFFIX ".tmp" // Temporary file suffix for atomic operations
#define KEYISO_GUID_COLLISION_MAX_ATTEMPTS 5 // Maximum attempts to generate unique GUID

typedef struct latest_info_st LATEST_INFO;
struct latest_info_st{
    uuid_t guid;
    uint32_t machineSecretSize;
    uint8_t machineSecret[KEYISO_MAX_MACHINE_SECRET_SIZE];
    time_t creationTime;
};

static KEYISO_GUID_LOOKUP_CACHE* _machineSecretCache = NULL; // Cache for guid-secret mapping
static LATEST_INFO* _latestMachineSecretInfo = NULL;
static uint32_t _secretRotationDays; // Remove uint32_t prefix as it's a declaration, not initialization

// Thread synchronization - Single RW lock approach
static pthread_rwlock_t _latestInfoRWLock = PTHREAD_RWLOCK_INITIALIZER;

// Forward declarations for static functions
static int _stat_file(const char* path, struct stat* st, const char* title);

// Safe time difference calculation for time_t values
static int _safe_time_diff(time_t later, time_t earlier, time_t *diff)
{
    if (!diff) {
        return STATUS_FAILED;
    }
    
    // Check for invalid time values
    if (later == (time_t)-1 || earlier == (time_t)-1) {
        return STATUS_FAILED;
    }
    
    // Check for time going backwards
    if (later < earlier) {
        return STATUS_FAILED;
    }
    
    // Use overflow-safe subtraction
    if (KEYISO_SUB_OVERFLOW(later, earlier, diff)) {
        return STATUS_FAILED;
    }
    
    return STATUS_OK;
}

static int _safe_time_to_int64(time_t time, int64_t *out)
{
    if (!out) {
        return STATUS_FAILED;
    }
    
    if (time < INT64_MIN || time > INT64_MAX) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_MACHINE_SECRET_ROTATION_TITLE, "Time conversion error", "Time value out of int64_t range");
        return STATUS_FAILED; // Overflow or underflow
    }
    *out = (int64_t)time;
    return STATUS_OK;
}

// Check if secret rotation is needed based on time
// Uses global _secretRotationDays for rotation threshold
static bool _is_secret_expired(time_t creationTime)
{
    const char* title = KEYISOP_MACHINE_SECRET_ROTATION_TITLE;
    time_t now = time(NULL);
    
    // Validate current time
    if (now == (time_t)-1) {
        KEYISOP_trace_log_error(NULL, 0, title, "Time error", "Failed to get current time");
        return true; // Treat time error as rotation required
    }
    
    // Validate creation time
    if (creationTime == (time_t)-1 || creationTime == 0) {
        KEYISOP_trace_log_error(NULL, 0, title, "Invalid creation time", "Recived an invalid secret creation time");
        return true;
    }
    
    // Use the safe time difference function to calculate age
    time_t age = 0;
    if (_safe_time_diff(now, creationTime, &age) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, title, "Time calculation error", "Failed to calculate secret age safely");
        return true;
    }
    
    // Convert age to int64_t safely for comparison with rotation interval
    int64_t ageSeconds = 0;
    if (_safe_time_to_int64(age, &ageSeconds) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, title, "Time conversion error", "Failed to convert age to int64_t safely");
        return true;
    }
    
    int64_t rotationThreshold = KEYISO_SECRET_ROTATION_INTERVAL_SECONDS(_secretRotationDays);
    bool isExpired = (ageSeconds > rotationThreshold);
    if (isExpired) {
        KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title,
                              "Secret expired, rotation required - Secret age exceeds threshold",
                              "age: %ld, threshold: %ld", (long)ageSeconds, (long)rotationThreshold);
    }
    
    return isExpired;
}

// Cleanup function for _get_latest_secret_data
static int _cleanup_get_latest_valid_secret_data(int result)
{
    if (pthread_rwlock_unlock(&_latestInfoRWLock) != 0) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_MACHINE_SECRET_ROTATION_TITLE, "Unlock error", "Failed to release read lock");
    }
    return result;
}

// Get valid secret data if available and not expired
// Returns STATUS_OK if successful, caller must free outValue with KeyIso_clear_free
static int _get_latest_secret_data(uuid_t outGuid, uint8_t **outValue, uint32_t *outValueSize, time_t *outCreationTime)
{
    const char* title = KEYISOP_MACHINE_SECRET_ROTATION_TITLE;
    if (!outValue || !outValueSize || !outCreationTime) {
        KEYISOP_trace_log_error(NULL, 0, title, "Invalid parameters", "Output value or size is NULL");
        return STATUS_FAILED;
    }
    
    *outValue = NULL;
    *outValueSize = 0;
    
    if (pthread_rwlock_rdlock(&_latestInfoRWLock) != 0) {
        KEYISOP_trace_log_error(NULL, 0, title, "Lock error", "Failed to acquire read lock");
        return STATUS_FAILED;
    }
    
    if (!_latestMachineSecretInfo || _latestMachineSecretInfo->machineSecretSize == 0) {
        KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title,"No latest secret info - Latest machine secret info is NULL or empty");
        return _cleanup_get_latest_valid_secret_data(STATUS_FAILED);
    }

     if (_is_secret_expired(_latestMachineSecretInfo->creationTime)) {
        KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Secret expired - Need to rotate secret");
        return _cleanup_get_latest_valid_secret_data(STATUS_FAILED);
    }
    
    // Copy secret data
    *outValue = (uint8_t*)KeyIso_memdup(_latestMachineSecretInfo->machineSecret, _latestMachineSecretInfo->machineSecretSize);
    if (!*outValue) {
        return _cleanup_get_latest_valid_secret_data(STATUS_FAILED);
    }
    
    memcpy(outGuid, _latestMachineSecretInfo->guid, sizeof(uuid_t));
    *outValueSize = _latestMachineSecretInfo->machineSecretSize;
    *outCreationTime = _latestMachineSecretInfo->creationTime;

    return _cleanup_get_latest_valid_secret_data(STATUS_OK);
}

// Free latest secret info safely and set pointer to NULL
static void _free_latest_secret_info(void)
{
    if (pthread_rwlock_wrlock(&_latestInfoRWLock) != 0) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_MACHINE_SECRET_ROTATION_TITLE, "Lock error", "Failed to acquire write lock for cleanup");
        return;
    }
    
    if (_latestMachineSecretInfo) {
        KeyIso_clear_free(_latestMachineSecretInfo, sizeof(LATEST_INFO));
        _latestMachineSecretInfo = NULL;
    }
    
    pthread_rwlock_unlock(&_latestInfoRWLock);
}

// Write data to a file atomically using temp file approach
static int _write_file_atomic(const char* path, const void* data, size_t dataSize)
{
    const char* title = KEYISOP_MACHINE_SECRET_ROTATION_TITLE;
    if (!path || !data || dataSize == 0) {
        KEYISOP_trace_log_error(NULL, 0, title, "Invalid parameters", "Path, data, or title is NULL/empty");
        return STATUS_FAILED;
    }

    // Validate final path length
    size_t pathLen = strnlen(path, PATH_MAX);
    if (pathLen >= PATH_MAX) {
        KEYISOP_trace_log_error(NULL, 0, title, "Invalid path", "Final path is too long");
        return STATUS_FAILED;
    }

    // Create temporary file path with .tmp suffix
    size_t tempPathLen = pathLen + strlen(KEYISO_TEMP_FILE_SUFFIX) + 1; // +1 for null terminator
    if (tempPathLen >= PATH_MAX) {
        KEYISOP_trace_log_error(NULL, 0, title, "Invalid temp path", "Temporary path is too long");
        return STATUS_FAILED;
    }
    
    char* tempPath = (char*)KeyIso_zalloc(tempPathLen);
    if (!tempPath) {
        KEYISOP_trace_log_error(NULL, 0, title, "Memory allocation", "Failed to allocate memory for temp path");
        return STATUS_FAILED;
    }
    snprintf(tempPath, tempPathLen, "%s%s", path, KEYISO_TEMP_FILE_SUFFIX);

    BIO* bio = NULL;
    int result = STATUS_FAILED;
    mode_t prevMask = 0;

    // Clear ossl error queue
    ERR_clear_error();

    // Set restrictive permissions for security
    prevMask = umask(077);

    // Write to temporary file first
    bio = BIO_new_file(tempPath, "wb");

    // Restore previous umask
    umask(prevMask);

    if (!bio) {
        KEYISOP_trace_log_openssl_error_para(NULL, 0, title, "BIO creation error", "Could not create BIO for temp file", "path: %s", tempPath);
        KeyIso_free(tempPath);
        return STATUS_FAILED;
    }

    // Write data to temporary file
    if (BIO_write(bio, data, dataSize) != dataSize) {
        KEYISOP_trace_log_openssl_error_para(NULL, 0, title, "BIO write error", "Could not write data to temp file", "path: %s", tempPath);
        BIO_free(bio);
        // Clean up temporary file on write failure
        unlink(tempPath);
        KeyIso_free(tempPath);
        return STATUS_FAILED;
    }

    // Flush and sync to ensure data is written to disk
    if (BIO_flush(bio) != 1) {
        KEYISOP_trace_log_openssl_error_para(NULL, 0, title, "BIO flush error", "Could not flush data to temp file", "path: %s", tempPath);
        BIO_free(bio);
        unlink(tempPath);
        KeyIso_free(tempPath);
        return STATUS_FAILED;
    }

    BIO_free(bio);
    bio = NULL;

    // Atomically rename temp file to final path
    if (rename(tempPath, path) != 0) {
        int err = errno;
        KEYISOP_trace_log_errno_para(NULL, 0, title, "Rename error", err, "temp: %s, final: %s", tempPath, path);
        unlink(tempPath);
        KeyIso_free(tempPath);
        return STATUS_FAILED;
    }

    result = STATUS_OK;
    KeyIso_free(tempPath);
    return result;
}

// Get the file path for a given GUID
// Returns a newly allocated string (KeyIso_free), caller must free
static char* _get_secret_file_path(const char* fileName, size_t fileNameLen)
{
    if (!fileName || fileNameLen == 0 || fileNameLen >= PATH_MAX) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_MACHINE_SECRET_ROTATION_TITLE, "Invalid file name", "File name is NULL, empty, or too long");
        return NULL;
    }

    // Get base directory
    const char *baseDir = KeyIsoP_get_default_private_area();
    if (!baseDir) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_MACHINE_SECRET_ROTATION_TITLE, "Get secret directory", "Failed to get default private area");
        return NULL;
    }
    
    size_t baseDirLen = strnlen(baseDir, PATH_MAX);
    if (baseDirLen >= PATH_MAX) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_MACHINE_SECRET_ROTATION_TITLE, "Get secret directory", "Base directory is too long");
        return NULL;
    }
    
    // baseDir + KEYISO_PRIVATE_DIR + fileName + null terminator
    size_t pathLen = baseDirLen + strlen(KEYISO_PRIVATE_DIR) + fileNameLen + 1;  // +1 for null terminator
    
    // Check for integer overflow
    if (pathLen < baseDirLen || pathLen >= PATH_MAX) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_MACHINE_SECRET_ROTATION_TITLE, "Path calculation error", "Path length calculation overflow or too long");
        return NULL;
    }
    
    char* path = (char*)KeyIso_zalloc(pathLen);
    if (!path) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_MACHINE_SECRET_ROTATION_TITLE, "Memory allocation", "Failed to allocate memory for secret file path");
        return NULL;
    }
    snprintf(path, pathLen, "%s%s%s", baseDir, KEYISO_PRIVATE_DIR, fileName);
    
    return path;
}
static char* _get_guid_path(const uuid_t guid)
{
    char guidStr[KEYISO_GUID_STRING_LENGTH + 1] = {0};
    
    // Convert UUID to string representation
    uuid_unparse_lower(guid, guidStr);
    
    guidStr[KEYISO_GUID_STRING_LENGTH] = '\0';

    return _get_secret_file_path(guidStr, KEYISO_GUID_STRING_LENGTH);
}

// Check if a GUID has collision with existing files on the disk
// Returns STATUS_OK if no collision, STATUS_FAILED if collision exists or error occurred
static int _check_guid_collision(const uuid_t guid, const char* title)
{
    char* guidPath = _get_guid_path(guid);
    if (!guidPath) {
        KEYISOP_trace_log_error(NULL, 0, title, "Path generation error", "Failed to generate path for GUID collision check");
        return STATUS_FAILED;
    }
    
    struct stat st;
    int result = _stat_file(guidPath, &st, title);
    KeyIso_free(guidPath);
    
    // If _stat_file returns STATUS_FAILED, file doesn't exist (no collision)
    return (result == STATUS_OK) ? STATUS_FAILED : STATUS_OK;
}

// Generate a unique GUID with collision detection
// Returns STATUS_OK if successful, STATUS_FAILED if unable to generate unique GUID
static int _generate_unique_guid(uuid_t outGuid, const char* title)
{
    for (int attempt = 0; attempt < KEYISO_GUID_COLLISION_MAX_ATTEMPTS; attempt++) {
        uuid_generate_random(outGuid);
        
        if (_check_guid_collision(outGuid, title) == STATUS_OK) {
            // No collision found, we can use this GUID
            return STATUS_OK;
        }
        
        // Collision detected
        KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title,
                              "GUID collision detected - Generated GUID already exists on disk", "attempt: %d", attempt + 1);
        
        if (attempt == KEYISO_GUID_COLLISION_MAX_ATTEMPTS - 1) {
            // This was the last attempt and it still collided
            KEYISOP_trace_log_error(NULL, 0, title, "GUID collision error", "Failed to generate unique GUID after maximum attempts - extremely rare event");
            return STATUS_FAILED;
        }
    }
    
    return STATUS_FAILED;
}

static int _stat_file(const char* path, struct stat* st, const char* title)
{
    if (!path || !st || !title) {
        KEYISOP_trace_log_error(NULL, 0, title, "Invalid parameters", "Path or stat structure is NULL");
        return STATUS_FAILED;
    }

    // Validate path length
    size_t len = strnlen(path, PATH_MAX);
    if (len >= PATH_MAX) {
        KEYISOP_trace_log_error(NULL, 0, title, "Invalid path", "Path is too long");
        return STATUS_FAILED;
    }

    // Perform stat operation
    if (stat(path, st) != 0) {
        if (errno == ENOENT) {
            // File does not exist(migt be okay - as this function is used to check if file exists)
            return STATUS_FAILED;
        }
        // Other error occurred
        int err = errno;
        KEYISOP_trace_log_errno_para(NULL, 0, title, "Stat error", err, "path: %s", path);
        return STATUS_FAILED;
    }
    return STATUS_OK;
}

// Cleanup function for _read_secret_by_guid_from_disk
static int _cleanup_read_secret_file(int result, BIO *bio, char *path, uint8_t *secretData, uint32_t secretSize)
{
    if (bio) {
        BIO_free(bio);
        bio = NULL;
    }
    if (path) {
        KeyIso_free(path);
        path = NULL;
    }
    if (secretData) {
        KeyIso_clear_free(secretData, secretSize);
        secretData = NULL;
    }
    return result;
}

static int _read_secret_by_guid_from_disk(const uuid_t guid, uint8_t **outValue, uint32_t *outValueSize, time_t *outCreationTime)
{
    const char* title = KEYISOP_MACHINE_SECRET_ROTATION_TITLE;
    if (!outValue || !outValueSize) {
        KEYISOP_trace_log_error(NULL, 0, title, "Invalid parameters", "Output value or size is NULL");
        return STATUS_FAILED;
    }

    *outValueSize = 0;
    *outValue = NULL; // Initialize output value to NULL

    BIO *bio = NULL;
    struct stat st;
    uint32_t fileVersion = 0;
    uint32_t secretSize = 0;
    int status = STATUS_FAILED;
    uint8_t *secretData = NULL;
    char *path = _get_guid_path(guid); // KeyIso_free()
    
    if (!path) {
        KEYISOP_trace_log_error(NULL, 0, title, "Invalid path", "Path is NULL");
        return STATUS_FAILED;
    }

    if (_stat_file(path, &st, title) != STATUS_OK) {
        return _cleanup_read_secret_file(STATUS_FAILED, bio, path, secretData, secretSize);
    }
    
    // Clear ossl error queue
    ERR_clear_error();
    bio = BIO_new_file(path, "rb");
    if (!bio) {
        KEYISOP_trace_log_openssl_error_para(NULL, 0, title, "BIO creation error", "Could not create BIO for secret file", "path: %s", path);
        return _cleanup_read_secret_file(STATUS_FAILED, bio, path, secretData, secretSize);
    }
    
    // Read version
    if (BIO_read(bio, &fileVersion, sizeof(uint32_t)) != sizeof(uint32_t)) {
        KEYISOP_trace_log_openssl_error_para(NULL, 0, title, "BIO read error", "Could not read version from secret file", "path: %s", path);
        return _cleanup_read_secret_file(STATUS_FAILED, bio, path, secretData, secretSize);
    }
    
    // Read secret size
    if (BIO_read(bio, &secretSize, sizeof(uint32_t)) != sizeof(uint32_t)) {
        KEYISOP_trace_log_openssl_error_para(NULL, 0, title, "BIO read error", "Could not read secret size from secret file", "path: %s", path);
        return _cleanup_read_secret_file(STATUS_FAILED, bio, path, secretData, secretSize);
    }
    
    if (secretSize > KEYISO_MAX_MACHINE_SECRET_SIZE) {
        KEYISOP_trace_log_error_para(NULL, 0, title, "Secret size mismatch", "Secret size in file is too long", "path: %s, size: %u", path, secretSize);
        return _cleanup_read_secret_file(STATUS_FAILED, bio, path, secretData, secretSize);
    }
    secretData = (uint8_t *)KeyIso_zalloc(secretSize + 1); // Allocate space for secret data + null terminator
    if (!secretData) {
        KEYISOP_trace_log_error(NULL, 0, title, "Memory allocation error", "Could not allocate memory for secret data");
        return _cleanup_read_secret_file(STATUS_FAILED, bio, path, secretData, secretSize);
    }
    // Read secret data
    if (BIO_read(bio, secretData, secretSize) != (int)secretSize) {
        KEYISOP_trace_log_error_para(NULL, 0, title, "BIO read error", "Could not read secret from secret file", "path: %s, expected size: %u", path, secretSize);
        return _cleanup_read_secret_file(STATUS_FAILED, bio, path, secretData, secretSize);
    }
    
    *outValueSize = secretSize;
    *outValue = secretData;
    if (outCreationTime) {
        *outCreationTime = st.st_mtime;
    }
    status = STATUS_OK;
    return _cleanup_read_secret_file(status, bio, path, NULL, 0);
}

static int _write_secret_file(const uuid_t guid, const uint8_t *secretValue, uint32_t secretSize)
{
    const char* title = KEYISOP_MACHINE_SECRET_ROTATION_TITLE;

    if (!secretValue || secretSize == 0 || secretSize > KEYISO_MAX_MACHINE_SECRET_SIZE) {
        KEYISOP_trace_log_error(NULL, 0, title, "Invalid parameters", "GUID, secret value, or size is invalid");
        return STATUS_FAILED;
    }
    
    char *path = _get_guid_path(guid); // KeyIso_free()
    if (!path) {
        KEYISOP_trace_log_error_para(NULL, 0, title, "Invalid path", "Path is NULL or too long", "guid-path");
        return STATUS_FAILED;
    }

    uint32_t fileVersion = KEYISOP_CURRENT_VERSION; // Current version of the secret file format
    
    // Prepare data buffer with version, size, and secret
    // fileVersion| secretSize | secretValue
    size_t totalDataSize = sizeof(uint32_t) + sizeof(uint32_t) + secretSize;
    uint8_t* dataBuffer = (uint8_t*)KeyIso_zalloc(totalDataSize);
    if (!dataBuffer) {
        KEYISOP_trace_log_error(NULL, 0, title, "Memory allocation", "Failed to allocate buffer for secret data");
        KeyIso_free(path);
        return STATUS_FAILED;
    }
    
    // Copy data to buffer using clear indexing
    size_t bufferIndex = 0;
    
    // Copy file version
    memcpy(dataBuffer + bufferIndex, &fileVersion, sizeof(uint32_t));
    bufferIndex += sizeof(uint32_t); // + fileVersion size
    
    // Copy secret size
    memcpy(dataBuffer + bufferIndex, &secretSize, sizeof(uint32_t));
    bufferIndex += sizeof(uint32_t); // + secretSize size
    
    // Copy secret data
    memcpy(dataBuffer + bufferIndex, secretValue, secretSize);
    
    // Write atomically using helper function
    int result = _write_file_atomic(path, dataBuffer, totalDataSize);
    // Clean up
    KeyIso_clear_free(dataBuffer, totalDataSize);
    KeyIso_free(path);
    return result;
}

static int _read_latest_guid(uuid_t outGuid)
{
    BIO *bio = NULL;
    char guidStr[KEYISO_GUID_STRING_LENGTH + 1] = {0};
    char* path = _get_secret_file_path(KEYISO_LATEST_FILENAME, sizeof(KEYISO_LATEST_FILENAME));
    
    int ret = STATUS_FAILED;
    
    if (!path) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_MACHINE_SECRET_ROTATION_TITLE, "Path error", "Failed to get path for latest guid file");
        return STATUS_FAILED;
    }
    
    // Clear ossl error queue
    ERR_clear_error();

    bio = BIO_new_file(path, "rb");
    if (!bio) {
        // Latest file can be missing in clean state
        KeyIso_free(path);
        return STATUS_FAILED;
    }
    if (BIO_read(bio, guidStr, KEYISO_GUID_STRING_LENGTH) != KEYISO_GUID_STRING_LENGTH) {
        KEYISOP_trace_log_openssl_error_para(NULL, 0, KEYISOP_MACHINE_SECRET_ROTATION_TITLE, "BIO read error - Could not read guid from latest guid file", "path: %s", path);
        BIO_free(bio);
        KeyIso_free(path);
        return STATUS_FAILED;
    }
    guidStr[KEYISO_GUID_STRING_LENGTH] = '\0';
    if (uuid_parse(guidStr, outGuid) != 0) {
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_MACHINE_SECRET_ROTATION_TITLE, "GUID parse error", "Could not parse guid from latest guid file", "guid: %s", guidStr);
        BIO_free(bio);
        KeyIso_free(path);
        return STATUS_FAILED;
    }
    ret = STATUS_OK;
    BIO_free(bio);
    KeyIso_free(path);
    return ret;
}

static int _write_latest_guid_to_file(const uuid_t guid)
{
    const char* title = KEYISOP_MACHINE_SECRET_ROTATION_TITLE;
    char guidStr[KEYISO_GUID_STRING_LENGTH + 1] = {0};
    char* path = _get_secret_file_path(KEYISO_LATEST_FILENAME, strlen(KEYISO_LATEST_FILENAME));
    
    if (!path) {
        KEYISOP_trace_log_error(NULL, 0, title, "Path error", "Failed to get path for latest guid file");
        return STATUS_FAILED;
    }
    
    uuid_unparse_lower(guid, guidStr);
    guidStr[KEYISO_GUID_STRING_LENGTH] = '\0'; // Ensure null termination
    
    // Debug logging
    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title,
                          "Writing latest GUID - GUID being written to latest file", 
                          "guid: %s, length: %zu", guidStr, strlen(guidStr));
    
    // Delete existing latest file first (if it exists)
    if (unlink(path) != 0 && errno != ENOENT) {
        int err = errno;
        KEYISOP_trace_log_errno_para(NULL, 0, title, "File delete error", err, "Could not delete existing latest file: %s", path);
        KeyIso_free(path);
        return STATUS_FAILED;
    }
    
    // Write atomically using helper function
    int result = _write_file_atomic(path, guidStr, KEYISO_GUID_STRING_LENGTH);
    KeyIso_free(path);
    return result;
}

static int _generate_new_secret(uuid_t outGuid, uint8_t *outValue, uint32_t *outValueSize)
{
    const char* title = KEYISOP_MACHINE_SECRET_ROTATION_TITLE;
    if (!outGuid || !outValue || !outValueSize) {
        KEYISOP_trace_log_error(NULL, 0, title, "Invalid parameters", "Output guid, value or size is NULL");
        return STATUS_FAILED;
    }
    
    // Generate unique GUID with collision detection
    if (_generate_unique_guid(outGuid, title) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, title, "GUID generation error", "Failed to generate unique GUID");
        return STATUS_FAILED;
    }
    
    // Generate random bytes for the secret
    if (KeyIso_rand_bytes(outValue, KEYISO_CURRENT_MACHINE_SECRET_SIZE) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_MACHINE_SECRET_ROTATION_TITLE, "Random bytes generation error", "Could not generate random bytes for new secret");
        return STATUS_FAILED;
    }
    *outValueSize = KEYISO_CURRENT_MACHINE_SECRET_SIZE;
    return STATUS_OK;
}

// Updates the latest machine secret info and adds it to the cache - Must be called under write lock!!!
static int _update_latest_machine_secret_info(const uuid_t guid, const uint8_t *machineSecret, uint32_t machineSecretSize, time_t creationTime)
{
    const char* title = KEYISOP_MACHINE_SECRET_ROTATION_TITLE;
    if (machineSecretSize == 0 || machineSecretSize > KEYISO_MAX_MACHINE_SECRET_SIZE) {
        KEYISOP_trace_log_error(NULL, 0, title, "Invalid parameters", "Machine secret size is invalid");
        return STATUS_FAILED;
    }
    
    // Allocate new secret info structure
    LATEST_INFO* newSecretInfo = (LATEST_INFO*)KeyIso_zalloc(sizeof(LATEST_INFO));
    if (newSecretInfo == NULL) {
        return STATUS_FAILED;
    }
    
    // Populate the new secret info structure
    memcpy(newSecretInfo->guid, guid, sizeof(uuid_t));
    memcpy(newSecretInfo->machineSecret, machineSecret, machineSecretSize);
    newSecretInfo->machineSecretSize = machineSecretSize;
    newSecretInfo->creationTime = creationTime;
    
    LATEST_INFO* oldInfo = _latestMachineSecretInfo;
    _latestMachineSecretInfo = newSecretInfo;
    
    if (oldInfo) {
        KeyIso_clear_free(oldInfo, sizeof(LATEST_INFO));
    }
    
    return STATUS_OK;
}

static int _rotate_secret()
{
    // Acquire write lock for entire rotation process
    if (pthread_rwlock_wrlock(&_latestInfoRWLock) != 0) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_MACHINE_SECRET_ROTATION_TITLE, "Lock error", "Failed to acquire write lock for rotation");
        return STATUS_FAILED;
    }
    
    // Check under lock if rotation is still needed
    if (_latestMachineSecretInfo && 
        _latestMachineSecretInfo->machineSecretSize > 0 && 
        !_is_secret_expired(_latestMachineSecretInfo->creationTime)) {
        KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, KEYISOP_MACHINE_SECRET_ROTATION_TITLE, "Secret rotation not needed, existing secret is still valid");
        pthread_rwlock_unlock(&_latestInfoRWLock);
        return STATUS_OK; // No rotation needed
    }

    const char* title = KEYISOP_MACHINE_SECRET_ROTATION_TITLE;
    uuid_t newGuid;
    uint8_t newSecret[KEYISO_MAX_MACHINE_SECRET_SIZE];
    uint32_t newSecretSize = 0;
    time_t creationTime = 0;
    
    // Generate new secret and GUID
    if (_generate_new_secret(newGuid, newSecret, &newSecretSize) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, title, "Secret generation error", "Failed to generate new secret");
        KeyIso_cleanse(newSecret, newSecretSize);
        if (pthread_rwlock_unlock(&_latestInfoRWLock) != 0) {
            KEYISOP_trace_log_error(NULL, 0, KEYISOP_MACHINE_SECRET_ROTATION_TITLE, "Unlock error", "Failed to release write lock");
        }
        return STATUS_FAILED;
    }
    
    // Persist the secret to file
    if (_write_secret_file(newGuid, newSecret, newSecretSize) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, title, "Secret file write error", "Failed to write new secret to file");
        KeyIso_cleanse(newSecret, newSecretSize);
        if (pthread_rwlock_unlock(&_latestInfoRWLock) != 0) {
            KEYISOP_trace_log_error(NULL, 0, KEYISOP_MACHINE_SECRET_ROTATION_TITLE, "Unlock error", "Failed to release write lock");
        }
        return STATUS_FAILED;
    }
    
    // Update the latest GUID reference
    if (_write_latest_guid_to_file(newGuid) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, title, "Latest guid write error", "Failed to write new guid to latest file");
        KeyIso_cleanse(newSecret, newSecretSize);
        if (pthread_rwlock_unlock(&_latestInfoRWLock) != 0) {
            KEYISOP_trace_log_error(NULL, 0, KEYISOP_MACHINE_SECRET_ROTATION_TITLE, "Unlock error", "Failed to release write lock");
        }
        return STATUS_FAILED;
    }

    // Set creation time to current time
    creationTime = time(NULL);
    if (creationTime == (time_t)-1) {
        KEYISOP_trace_log_error(NULL, 0, title, "Time error", "Failed to get current time for secret creation");
        KeyIso_cleanse(newSecret, newSecretSize);
        if (pthread_rwlock_unlock(&_latestInfoRWLock) != 0) {
            KEYISOP_trace_log_error(NULL, 0, KEYISOP_MACHINE_SECRET_ROTATION_TITLE, "Unlock error", "Failed to release write lock");
        }
        return STATUS_FAILED;
    }

    // Update the latest machine secret - Must be called under write lock
    if(_update_latest_machine_secret_info(newGuid, newSecret, newSecretSize, creationTime) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, title, "Latest secret info update error", "Failed to update latest machine secret info");
        KeyIso_cleanse(newSecret, newSecretSize);
        if (pthread_rwlock_unlock(&_latestInfoRWLock) != 0) {
            KEYISOP_trace_log_error(NULL, 0, KEYISOP_MACHINE_SECRET_ROTATION_TITLE, "Unlock error", "Failed to release write lock");
        }
        return STATUS_FAILED;
    }
   
    // Add to cache inside the same critical section (ignore cache update errors)
    if (KeyIso_guid_lookup_cache_put(_machineSecretCache, newGuid, newSecret, newSecretSize) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, title, "Cache update error", "Failed to add secret to cache, continuing without caching");
    }

    if (pthread_rwlock_unlock(&_latestInfoRWLock) != 0) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_MACHINE_SECRET_ROTATION_TITLE, "Unlock error", "Failed to release write lock");
    }

    KeyIso_cleanse(newSecret, newSecretSize);
    return STATUS_OK;
}
static int _try_read_valid_secret_from_disk(uuid_t guid, uint8_t **outValue, uint32_t *outValueSize, time_t *outCreationTime)
{
    const char* title = KEYISOP_MACHINE_SECRET_ROTATION_TITLE;
    
    // Write lock to ensure atomicity of reading and initializing secret
    if (pthread_rwlock_wrlock(&_latestInfoRWLock) != 0) {
        KEYISOP_trace_log_error(NULL, 0, title, "Lock error", "Failed to acquire write lock for secret initialization");
        return STATUS_FAILED;
    }

    // Try to read latest GUID from disk
    if (_read_latest_guid(guid) != STATUS_OK) {
        pthread_rwlock_unlock(&_latestInfoRWLock);
        return STATUS_FAILED;
    }
    
    // Try to read secret by GUID from disk
    if (_read_secret_by_guid_from_disk(guid, outValue, outValueSize, outCreationTime) != STATUS_OK) {
        pthread_rwlock_unlock(&_latestInfoRWLock);
        return STATUS_FAILED;
    }

    // Check if secret is expired
    if (_is_secret_expired(*outCreationTime)) {
        KeyIso_clear_free(*outValue, *outValueSize);
        *outValue = NULL;
        *outValueSize = 0;
        pthread_rwlock_unlock(&_latestInfoRWLock);
        return STATUS_FAILED;
    }
    
    // Update the latest machine secret info
    if (_update_latest_machine_secret_info(guid, *outValue, *outValueSize, *outCreationTime) != STATUS_OK) {
        KeyIso_clear_free(*outValue, *outValueSize);
        *outValue = NULL;
        *outValueSize = 0;
        pthread_rwlock_unlock(&_latestInfoRWLock);
        return STATUS_FAILED;
    }

    // Add to cache inside the same critical section (ignore cache update errors)
    if (KeyIso_guid_lookup_cache_put(_machineSecretCache, guid, *outValue, *outValueSize) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, title, "Cache update error", "Failed to add secret to cache, continuing without caching");
    }

    pthread_rwlock_unlock(&_latestInfoRWLock);
    
    return STATUS_OK;
}

int KeyIso_get_current_valid_secret(
    const uuid_t correlationId,
    uint32_t *outGuidSize,
    uint8_t *outGuid,               // Static buffer, only sizeof(uuid_t) is being used in process based
    uint32_t *outValueSize,
    uint8_t **outValue)             // Caller must free this memory using KeyIso_clear_free 
{
    const char* title = KEYISOP_MACHINE_SECRET_ROTATION_TITLE;
    if (!outGuid || !outGuidSize || !outValueSize || !outValue) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid parameters", "Output guid, size or value is NULL");
        return STATUS_FAILED;
    }
    
    // Initialize output parameters
    *outGuidSize = sizeof(uuid_t);
    *outValueSize = 0;
    *outValue = NULL;
    
    uuid_t tempGuid;
    time_t creationTime = 0;
    
    // Try to get valid data from memory first
    if (_get_latest_secret_data(tempGuid, outValue, outValueSize, &creationTime) == STATUS_OK) {
        memcpy(outGuid, tempGuid, sizeof(uuid_t));
        return STATUS_OK;
    }
    
    // Try read from the disk
    if (_try_read_valid_secret_from_disk(tempGuid, outValue, outValueSize, &creationTime) == STATUS_OK) {
        memcpy(outGuid, tempGuid, sizeof(uuid_t));
        return STATUS_OK;
    }

    // Rotate secret and try again
    if (_rotate_secret() != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Secret rotation error", "Failed to rotate secret");
        return STATUS_FAILED;
    }

    if (_get_latest_secret_data(tempGuid, outValue, outValueSize, &creationTime) == STATUS_OK) {
        memcpy(outGuid, tempGuid, sizeof(uuid_t));
        return STATUS_OK;
    }

    // All attempts failed
    KEYISOP_trace_log_error(correlationId, 0, title, "Secret retrieval error", "Failed to get valid secret after rotation");
    return STATUS_FAILED;
}

int KeyIso_get_secret_by_id(
    const uuid_t correlationId,
    uint32_t guidSize,
    const uint8_t *guid, // Static buffer, only sizeof(uuid_t) is being used in process based
    uint32_t* outValueSize,
    uint8_t** outValue) // Caller must free this memory, KeyIso_clear_free
{
    const char* title = KEYISOP_MACHINE_SECRET_ROTATION_TITLE;
    
    // Validate input parameters
    if (outValueSize == NULL || outValue == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid parameters", "Output value or size parameters are NULL");
        return STATUS_FAILED;
    }
    
    if (guid == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid parameters", "GUID parameter is NULL");
        return STATUS_FAILED;
    }
    
    if (guidSize != sizeof(uuid_t)) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid GUID size", "Expected size is 16 bytes");
        return STATUS_FAILED;
    }

    // copy the incoming guid to a local uuid type
    uuid_t uuidGuid;
    memcpy(uuidGuid, guid, guidSize);

    // Initialize output parameters
    *outValue = NULL;
    *outValueSize = 0;
    
    // Try cache first under read lock - validate that cached data is non-empty before returning
    if (pthread_rwlock_rdlock(&_latestInfoRWLock) == 0) {
        int cacheResult = KeyIso_guid_lookup_cache_get(_machineSecretCache, uuidGuid, outValue, outValueSize);
        pthread_rwlock_unlock(&_latestInfoRWLock);
        
        if (cacheResult == STATUS_OK) {
            return STATUS_OK;
        }
    }
    
    // Cache miss or invalid cache data - read from file
    time_t creationTime = 0;
    if (_read_secret_by_guid_from_disk(uuidGuid, outValue, outValueSize, &creationTime) != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, title, "File read error", "Could not read secret file for guid");
        *outValue = NULL;
        *outValueSize = 0;
        return STATUS_FAILED;
    }
    
    // Update cache for future lookups under write lock (ignore cache update error status)
    if (pthread_rwlock_wrlock(&_latestInfoRWLock) == 0) {
        if (KeyIso_guid_lookup_cache_put(_machineSecretCache, uuidGuid, *outValue, *outValueSize) != STATUS_OK) {
            KEYISOP_trace_log_error(correlationId, 0, title, "Cache update error", "Failed to add secret to cache, continuing without caching");
        }
        pthread_rwlock_unlock(&_latestInfoRWLock);
    }
    return STATUS_OK;
}

static int _init_current_valid_secret(void)
{
    const char* title = KEYISOP_MACHINE_SECRET_ROTATION_TITLE;
    uuid_t guid;
    uint8_t *secretValue = NULL;
    uint32_t secretSize = 0;
    time_t creationTime = 0;
    
    // Try to read valid secret from disk (includes updating latest machine secret info)
    if (_try_read_valid_secret_from_disk(guid, &secretValue, &secretSize, &creationTime) == STATUS_OK) {
        KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Valid secret found - Using existing secret from disk");
        if (secretValue) {
            KeyIso_clear_free(secretValue, secretSize);
            secretValue = NULL;
        }
        return STATUS_OK;
    }
    
    // If we couldn't load a valid secret, create a new one
    return _rotate_secret();
}

int KeyIso_secret_rotation_initialize(uint32_t secretRotationDays)
{
    const char* title = KEYISOP_MACHINE_SECRET_ROTATION_TITLE;
    
    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Initializing secret rotation, setting rotation days", "rotationDays: %u", secretRotationDays);

    // Initialize legacy pfx.0 secret first for backward compatibility
    if (KeyIsoP_create_pfx_secret(NULL) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, title, "Legacy secret initialization error", "Failed to create legacy pfx secret");
        return STATUS_FAILED;
    }

    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Legacy secret initialized successfully");
    if (secretRotationDays > KEYISO_SECRET_ROTATION_INTERVAL_DAYS ) {
        KEYISOP_trace_log_error_para(NULL, 0, title, "Invalid rotation days", "Secret rotation days exceeds maximum allowed", "rotationDays: %u", secretRotationDays);
        return STATUS_FAILED;
    }

    _secretRotationDays = secretRotationDays;
    
    // Initialize the GUID lookup cache if not already initialized
    if (_machineSecretCache == NULL) {
        _machineSecretCache = KeyIso_create_guid_lookup_cache();
        if (_machineSecretCache == NULL) {
            KEYISOP_trace_log_error(NULL, 0, title, "Cache initialization error", "Failed to create GUID lookup cache");
            return STATUS_FAILED;
        }
    }

    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "GUID lookup cache initialized successfully");

    // Create or load the current secret (with rotation if needed)
    if(_init_current_valid_secret() != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_MACHINE_SECRET_ROTATION_TITLE, "Secret creation error", "Failed to create or load current secret");
        return STATUS_FAILED;
    }

    KEYISOP_trace_log(NULL, 0, title, "Secret rotation initialized successfully");
    
    // Set current valid secret function pointers
    return KeyIso_set_secret_methods(KeyIso_get_current_valid_secret, KeyIso_get_secret_by_id, KeyIso_get_legacy_machine_secret);
}

int KeyIso_secret_rotation_cleanup(void)
{
    const char* title = KEYISOP_MACHINE_SECRET_ROTATION_TITLE;
    int result = STATUS_OK;
    
    if (_machineSecretCache) {
        KeyIso_free_guid_lookup_cache(_machineSecretCache);
        _machineSecretCache = NULL;
    }
    
    // Clean up secret info - _free_latest_secret_info handles its own locking
    _free_latest_secret_info();
    
    // Destroy the rwlock
    if (pthread_rwlock_destroy(&_latestInfoRWLock) != 0) {
        KEYISOP_trace_log_error(NULL, 0, title, "Lock cleanup error", "Failed to destroy rwlock during cleanup");
        result = STATUS_FAILED;
    }
    
    KEYISOP_trace_log_para(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, title, 
                          "Cleanup completed - Thread synchronization primitives cleaned up", 
                          "status: %s", (result == STATUS_OK) ? "OK" : "FAILED");
    return result;
}
