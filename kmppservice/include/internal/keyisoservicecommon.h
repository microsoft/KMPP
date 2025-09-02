/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#ifdef  __cplusplus
extern "C" {
#endif 

#include <uuid/uuid.h>
#include <stdint.h>
#include <stdbool.h>

#include "keyisocommon.h"

#define KEYISO_SECRET_KEY_LENGTH   32
#define KEYISO_SECRET_FILE_LENGTH  (KEYISO_SECRET_SALT_LENGTH + KEYISO_SECRET_KEY_LENGTH)

// The values below are taken from the OpenSSL's evp.h file
#define KMPP_EVP_PKEY_EC_NID       408 // Equivalent to EVP_PKEY_EC value
#define KMPP_EVP_PKEY_RSA_NID      6   // Equivalent to EVP_PKEY_RSA value
#define KMPP_EVP_PKEY_RSA_PSS_NID  912 // Equivalent to EVP_PKEY_RSA_PSS value

#define KEYISO_AES_PADDING_PKCS7   0
#define KEYISO_AES_PADDING_NONE    1

#define KEYISO_KEY_DEFAULT_HASH_SIZE 30 // The default number of keys that the in-memory cache can hold opened at the same time
#define KMPP_DEFAULT_ROTATION_INTERVAL_DAYS 90 // Default secret rotation interval in days

extern bool g_isSaltValidationRequired;
extern KeyIsoSolutionType g_isolationSolutionType;

typedef int (*PFN_rsa_operation) (const uuid_t correlationId, void *pkey, 
                                    int flen, const unsigned char *from, 
                                    int tlen, unsigned char *to, int padding);

typedef int (*PFN_ecc_operation) (const uuid_t correlationId, void *pkey, int type,
                                    const unsigned char *dgst, int dlen, 
                                    unsigned char *sig, unsigned int siglen, unsigned int *outlen);

typedef struct keyiso_encrypted_private_key_st KEYISO_ENCRYPTED_PRIV_KEY_ST;
struct keyiso_encrypted_private_key_st {
    uint32_t algVersion;
    uint32_t secretSaltLen;
    uint32_t ivLen;
    uint32_t hmacLen;
    uint32_t encKeyLen;
    uint32_t secretIdLen; //Stores the machine secret guid length for process based isolation and extra salt length in TA
    uint8_t  encryptedKeyBytes[];
};

int KeyIso_get_enc_key_bytes_len(
    const KEYISO_ENCRYPTED_PRIV_KEY_ST *encKeySt,
    uint32_t *outLen);


int KeyIso_is_valid_salt_prefix(
    const uuid_t correlationId,
    const unsigned char *salt,
    const unsigned char *secret);

int KeyIso_is_valid_salt(
    const uuid_t correlationId,
    const char *salt,
    const unsigned char* secret);

int KeyIso_generate_salt_bytes(
    const uuid_t correlationId,
    unsigned char *saltBytes,
    const int saltBytesLength);

int KeyIso_generate_salt(
    const uuid_t correlationId,
    char **salt);

int KeyIso_generate_password_from_salt(
    const uuid_t correlationId,
    const char *salt,
    char **password);    // KeyIso_free()

/////////////////////////////////////////////////////
/////////////// Internal HMAC methods ///////////////
/////////////////////////////////////////////////////

int KeyIso_sha256_hmac_calculation(
	const uuid_t correlationId,
	const unsigned char* data,
	const unsigned int data_len,
	const unsigned char* key,
    const unsigned int key_len,
	unsigned char* hmac_result);


int KeyIso_hmac_validation(
    const unsigned char* hmac1,
    const unsigned char* hmac2,
    unsigned int hmacLen);

///////////////////////////////////////////////////////////////////////////////////////
// Calculate the length of the in message structure.
// The function should be implemented for each IPC command.
// This funtion is common for IPCs that does not required serialization (such as OP-TEE)
//////////////////////////////////////////////////////////////////////////////////////

typedef void (*PFN_print_err)(const char *msg);
typedef void * (*PFN_mem_move)(void *dest, const void *src, size_t size);

size_t KeyIso_msg_in_length(
    int command, 
    const uint8_t *inSt,
    size_t inLen,
    const PFN_mem_move memMove);

///////////////////////////////////////////////////////////////////////////////////////
// The current valid secret is calculated differently in different isolation solutions
// Defined here the function signature for the machine secret retrieval
//////////////////////////////////////////////////////////////////////////////////////
typedef int (*KeyIso_get_current_valid_secret_func_ptr)(const uuid_t, uint32_t*, uint8_t*, uint32_t*, uint8_t**);
typedef int (*KeyIso_get_secret_by_id_func_ptr)(const uuid_t, uint32_t, const uint8_t*, uint32_t*, uint8_t **);
typedef const uint8_t *(*KeyIso_get_legacy_machine_secret_func_ptr)(void);

int KeyIso_set_secret_methods(
    KeyIso_get_current_valid_secret_func_ptr getCurrentValidSecretFunc,
    KeyIso_get_secret_by_id_func_ptr getSecretByIdFunc,
    KeyIso_get_legacy_machine_secret_func_ptr getLegacyMachineSecretFunc);


#ifdef  __cplusplus
}
#endif