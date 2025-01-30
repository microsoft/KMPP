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

#define KEYISO_SECRET_KEY_LENGTH   32
#define KEYISO_SECRET_FILE_LENGTH  (KEYISO_SECRET_SALT_LENGTH + KEYISO_SECRET_KEY_LENGTH)

// The values below are taken from the OpenSSL's evp.h file
#define KMPP_EVP_PKEY_EC_NID       408 // Equivalent to EVP_PKEY_EC value
#define KMPP_EVP_PKEY_RSA_NID      6   // Equivalent to EVP_PKEY_RSA value
#define KMPP_EVP_PKEY_RSA_PSS_NID  912 // Equivalent to EVP_PKEY_RSA_PSS value

#define KEYISO_AES_PADDING_PKCS7   0
#define KEYISO_AES_PADDING_NONE    1

#define KEYISO_KEY_DEFAULT_HASH_SIZE 30 // The default number of keys that the in-memory cache can hold opened at the same time

extern bool g_isSaltValidationRequired;

typedef int (*PFN_rsa_operation) (const uuid_t correlationId, void *pkey, 
                                    int flen, const unsigned char *from, 
                                    int tlen, unsigned char *to, int padding);

typedef int (*PFN_ecc_operation) (const uuid_t correlationId, void *pkey, int type,
                                    const unsigned char *dgst, int dlen, 
                                    unsigned char *sig, unsigned int siglen, unsigned int *outlen);


int KeyIso_is_valid_salt_prefix(
    const uuid_t correlationId,
    const unsigned char *salt,
    const unsigned char *secret);

int KeyIso_is_valid_salt(
    const uuid_t correlationId,
    const char *salt,
    unsigned char* secret);

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
// The machine secret should be retrievd differently in different isolation solutions
// Defined here the function signature for the machine secret retrieval
//////////////////////////////////////////////////////////////////////////////////////
typedef int (*KeyIso_get_machine_secret_func_ptr)(uint8_t*, uint16_t);

int KeyIso_set_machine_secret_method(
    const uuid_t correlationId,
    KeyIso_get_machine_secret_func_ptr getMachineSecretFunc);

#ifdef  __cplusplus
}
#endif