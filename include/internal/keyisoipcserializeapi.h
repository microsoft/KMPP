/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include "keyisoipccommands.h"

#ifdef  __cplusplus
extern "C" {
#endif

// Close key
uint8_t* KeyIso_serialize_close_key_in(const void *stToEncode, size_t *encodedLen);
int KeyIso_deserialize_close_key_in(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);
size_t KeyIso_get_len_close_key_in(const uint8_t *encodedSt, size_t encodedLen);

uint8_t* KeyIso_serialize_close_key_out(const void *stToEncode, size_t *encodedLen);
int KeyIso_deserialize_close_key_out(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);

// Ecdsa sign
uint8_t* KeyIso_serialize_ecdsa_sign_in(const void *stToEncode, size_t *encodedLen);
int KeyIso_deserialize_ecdsa_sign_in(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);
size_t KeyIso_get_len_ecdsa_sign_in(const uint8_t *encodedSt, size_t encodedLen);

uint8_t* KeyIso_serialize_ecdsa_sign_out(const void *stToEncode, size_t *encodedLen);
size_t KeyIso_get_len_ecdsa_sign_out(const uint8_t *encodedSt, size_t encodedLen);
int KeyIso_deserialize_ecdsa_sign_out(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);

// Ecdsa sign with attached key
uint8_t* KeyIso_serialize_ecdsa_sign_with_attached_key_in(const void *stToEncode, size_t *encodedLen);
size_t KeyIso_get_len_ecdsa_sign_with_attached_key_in(const uint8_t *encodedSt, size_t encodedLen);
int KeyIso_deserialize_ecdsa_sign_with_attached_key_in(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);

uint8_t* KeyIso_serialize_ecdsa_sign_with_attached_key_out(const void *stToEncode, size_t *encodedLen);
size_t KeyIso_get_len_ecdsa_sign_with_attached_key_out(const uint8_t *encodedSt, size_t encodedLen);
int KeyIso_deserialize_ecdsa_sign_with_attached_key_out(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);

// Rsa encrypt decrypt
uint8_t* KeyIso_serialize_rsa_enc_dec_in(const void *stToEncode, size_t *encodedLen);
size_t KeyIso_get_len_rsa_enc_dec_in(const uint8_t *encodedSt, size_t encodedLen);
int KeyIso_deserialize_rsa_enc_dec_in(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);

uint8_t* KeyIso_serialize_rsa_enc_dec_out(const void *stToEncode, size_t *encodedLen);
size_t KeyIso_get_len_rsa_enc_dec_out(const uint8_t *encodedSt, size_t encodedLen);
int KeyIso_deserialize_rsa_enc_dec_out(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);

// Rsa encrypt decrypt with attached encrypted key
uint8_t* KeyIso_serialize_rsa_enc_dec_with_attached_key_in(const void* stToEncode, size_t *encodedLen);
size_t KeyIso_get_len_rsa_enc_dec_with_attached_key_in(const uint8_t *encodedSt, size_t encodedLen);
int KeyIso_deserialize_rsa_enc_dec_with_attached_key_in(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);

uint8_t* KeyIso_serialize_rsa_enc_dec_with_attached_key_out(const void* stToEncode, size_t *encodedLen);
size_t KeyIso_get_len_rsa_enc_dec_with_attached_key_out(const uint8_t *encodedSt, size_t encodedLen);
int KeyIso_deserialize_rsa_enc_dec_with_attached_key_out(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);

// Open Private Key
uint8_t* KeyIso_serialize_open_priv_key_in(const void *stToEncode, size_t *encodedLen);
size_t KeyIso_get_len_open_priv_key_in(const uint8_t *encodedSt, size_t encodedLen);
int KeyIso_deserialize_open_priv_key_in(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);

uint8_t* KeyIso_serialize_open_priv_key_out(const void *stToEncode, size_t *encodedLen);
int KeyIso_deserialize_open_priv_key_out(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);

// Generate RSA Key Pair
uint8_t* KeyIso_serialize_gen_rsa_key_pair_in(const void *stToEncode, size_t *encodedLen);
size_t KeyIso_get_len_gen_rsa_key_pair_in(const uint8_t *encodedSt, size_t encodedLen);
int KeyIso_deserialize_gen_rsa_key_pair_in(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);

uint8_t* KeyIso_serialize_gen_rsa_key_pair_out(const void *stToEncode, size_t *encodedLen);
size_t KeyIso_get_len_gen_rsa_key_pair_out(const uint8_t *encodedSt, size_t encodedLen);
int KeyIso_deserialize_gen_rsa_key_pair_out(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);

// Generate EC Key Pair
uint8_t* KeyIso_serialize_gen_ec_key_pair_in(const void *stToEncode, size_t *encodedLen);
size_t KeyIso_get_len_gen_ec_key_pair_in(const uint8_t *encodedSt, size_t encodedLen);
int KeyIso_deserialize_gen_ec_key_pair_in(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);

uint8_t* KeyIso_serialize_gen_ec_key_pair_out(const void *stToEncode, size_t *encodedLen);
size_t KeyIso_get_len_gen_ec_key_pair_out(const uint8_t *encodedSt, size_t encodedLen);
int KeyIso_deserialize_gen_ec_key_pair_out(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);

// Import Private Key
uint8_t* KeyIso_serialize_import_priv_key_out(const void *stToEncode, size_t *encodedLen);
size_t KeyIso_get_len_import_priv_key_out(const uint8_t *encodedSt, size_t encodedLen);

// Import Rsa Private Key
uint8_t* KeyIso_serialize_import_rsa_priv_key_in(const void *stToEncode, size_t *encodedLen);
size_t KeyIso_get_len_import_rsa_priv_key_in(const uint8_t *encodedSt, size_t encodedLen);
int KeyIso_deserialize_import_rsa_priv_key_in(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);

int KeyIso_deserialize_import_rsa_priv_key_out(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);

// Import EC Private Key
uint8_t* KeyIso_serialize_import_ec_priv_key_in(const void* stToEncode, size_t *encodedLen);
size_t KeyIso_get_len_import_ec_priv_key_in(const uint8_t *encodedSt, size_t encodedLen);
int KeyIso_deserialize_import_ec_priv_key_in(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);

int KeyIso_deserialize_import_ec_priv_key_out(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);

// Symmetric Key - Import key
uint8_t* KeyIso_serialize_import_symmetric_key_in(const void *stToEncode, size_t *encodedLen);
size_t KeyIso_get_len_import_symmetric_key_in(const uint8_t *encodedSt, size_t encodedLen);
int KeyIso_deserialize_import_symmetric_key_in(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);

uint8_t* KeyIso_serialize_import_symmetric_key_out(const void *stToEncode, size_t *encodedLen);
size_t KeyIso_get_len_import_symmetric_key_out(const uint8_t *encodedSt, size_t encodedLen);
int KeyIso_deserialize_import_symmetric_key_out(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);

// Symmetric Key - Encrypt Decrypt
uint8_t* KeyIso_serialize_enc_dec_symmetric_key_in(const void *stToEncode, size_t *encodedLen);
size_t KeyIso_get_len_enc_dec_symmetric_key_in(const uint8_t *encodedSt, size_t encodedLen);
int KeyIso_deserialize_enc_dec_symmetric_key_in(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);

uint8_t* KeyIso_serialize_enc_dec_symmetric_key_out(const void *stToEncode, size_t *encodedLen);
size_t KeyIso_get_len_enc_dec_symmetric_key_out(const uint8_t *encodedSt, size_t encodedLen);
int KeyIso_deserialize_enc_dec_symmetric_key_out(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt);

#ifdef  __cplusplus
}
#endif
