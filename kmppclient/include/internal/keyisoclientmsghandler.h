/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include "keyisoclientinternal.h"
#include "keyisocommon.h"

int KeyIso_client_msg_handler_init_key(
    KEYISO_KEY_CTX *keyCtx,
    int keyLength,
    const unsigned char *keyBytes,
    const char *clientData);

void KeyIso_client_msg_handler_free_keyCtx(
    KEYISO_KEY_CTX *keyCtx);

void KeyIso_client_msg_close_key(
    KEYISO_KEY_CTX *keyCtx);

int KeyIso_client_msg_rsa_private_encrypt_decrypt(
    KEYISO_KEY_CTX *keyCtx,
    int decrypt,
    int flen,
    const unsigned char *from,
    int tlen,
    unsigned char *to,
    int padding,
    int labelLen);

int KeyIso_client_msg_ecdsa_sign(
    KEYISO_KEY_CTX *keyCtx,
    int type,
    const unsigned char *dgst,
    int dlen,
    unsigned char *sig,
    unsigned int sigLen,
    unsigned int *outLen);

int KeyIso_client_msg_import_symmetric_key(
    const uuid_t correlationId, 
    int inSymmetricKeyType,
    unsigned int inKeyLength, 
    const unsigned char *inKeyBytes,
    const unsigned char *inImportKeyId,
    unsigned int *outKeyLength, 
    unsigned char **outKeyBytes,
    char **outClientData);

int KeyIso_client_msg_symmetric_key_encrypt_decrypt(
    KEYISO_KEY_CTX *keyCtx,
    int mode, 
    const unsigned char *from,
    const unsigned int fromLen,
    unsigned char *to,
    unsigned int *toLen);

int KeyIso_client_msg_import_private_key(
    const uuid_t correlationId,
    int keyType,
    const unsigned char *inKeyBytes,
    X509_SIG **outEncKey,
    KEYISO_CLIENT_DATA_ST **outClientData);

int KeyIso_client_msg_generate_rsa_key_pair(
    const uuid_t correlationId,
    unsigned int rsaBits,
    uint8_t keyUsage, 
    EVP_PKEY **outPubKey,
    X509_SIG **outEncryptedPkeyP8,
    KEYISO_CLIENT_METADATA_HEADER_ST  *outMetaData);

int KeyIso_client_msg_generate_ec_key_pair(
    const uuid_t correlationId,
    unsigned int curve,
    uint8_t keyUsage,
    EC_GROUP **outEcGroup,
    EC_KEY **outPubKey,
    X509_SIG **outEncryptedPkeyP8,
   KEYISO_CLIENT_METADATA_HEADER_ST  *outMetaData);

void KeyIso_client_set_config(
    const KEYISO_CLIENT_CONFIG_ST *config);

int KeyIso_client_open_priv_key_message( 
    KEYISO_KEY_CTX *keyCtx);