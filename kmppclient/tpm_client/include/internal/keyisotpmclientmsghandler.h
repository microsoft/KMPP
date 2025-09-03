/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include "keyisocommon.h"
#include "keyisotpmcommon.h"

int KeyIso_client_tpm_msg_generate_rsa_key_pair(
    const uuid_t correlationId,
    unsigned int rsaBits,
    uint8_t keyUsage, 
    EVP_PKEY **outPubKey,                   // Should be freed by the caller (EVP_PKEY_free)
    X509_SIG **outEncryptedKeyDataP8,       // The key details that holds the encrypted private key of the generated key pair(and other) - Should be freed by the caller
   KEYISO_CLIENT_METADATA_HEADER_ST *outMetaData);  // Holds salt for othe isolation providers - not used in TPM.

int KeyIso_client_tpm_msg_generate_ec_key_pair(
    const uuid_t correlationId,
    unsigned int curve,
    uint8_t keyUsage,
    EC_GROUP **outEcGroup,           // Should be freed by the caller (EC_GROUP_free)
    EC_KEY **outPubKey,              // Should be freed by the caller (EC_KEY_free)
    X509_SIG **outEncryptedPkeyP8,   // Should be freed by the caller ( KeyIso_free)
    KEYISO_CLIENT_METADATA_HEADER_ST *outMetaData);                // Not used in TPM.

int KeyIso_client_tpm_msg_handler_init_key(
    KEYISO_KEY_CTX *keyCtx,
    int keyLength,
    const unsigned char *keyBytes,
    const char *param);

void KeyIso_client_tpm_msg_handler_free_keyCtx(
    KEYISO_KEY_CTX *keyCtx);

void KeyIso_client_tpm_msg_close_key(
    KEYISO_KEY_CTX *keyCtx);

int KeyIso_client_tpm_msg_rsa_private_encrypt_decrypt(
    KEYISO_KEY_CTX *keyCtx,
    int decrypt,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding,
    int labelLen);

int KeyIso_client_tpm_msg_ecdsa_sign(
    KEYISO_KEY_CTX *keyCtx,
    int type,
    const unsigned char *dgst,
    int dlen,
    unsigned char *sig,
    unsigned int sigLen,
    unsigned int *outLen);

int KeyIso_client_tpm_msg_import_symmetric_key(
    const uuid_t correlationId, 
    int inSymmetricKeyType,
    unsigned int inKeyLength, 
    const unsigned char *inKeyBytes,
    const unsigned char *inImportKeyId,
    unsigned int *outKeyLength, 
    unsigned char **outKeyBytes,
    char **outClientData);

int KeyIso_client_tpm_msg_symmetric_key_encrypt_decrypt(
    KEYISO_KEY_CTX *keyCtx,
    int mode, 
    const unsigned char *from,
    const unsigned int fromLen,
    unsigned char *to,
    unsigned int *toLen);

int KeyIso_client_tpm_msg_import_private_key(
    const uuid_t correlationId,
    int keyType,
    const unsigned char *inKeyBytes,
    X509_SIG **outEncKey,
    KEYISO_CLIENT_DATA_ST **outClientData);

void KeyIso_client_tpm_set_config(
    const KEYISO_CLIENT_CONFIG_ST *config);
