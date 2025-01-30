/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include <inttypes.h> 
#include <uuid/uuid.h>

#include "keyisocommon.h"
#include "keyisoutils.h"


#define GET_DYNAMIC_STRUCT_SIZE(structType, dynamicSize) \
({ \
    size_t _result; \
    if (KEYISO_ADD_OVERFLOW(sizeof(structType), ((size_t)(dynamicSize)) * sizeof(uint8_t), &_result)) { \
        _result = 0; \
    } \
    _result; \
})

typedef enum {
    IpcCommand_OpenPrivateKey,
    IpcCommand_CloseKey,
    IpcCommand_EcdsaSign,
    IpcCommand_RsaPrivateEncryptDecrypt,
    IpcCommand_GenerateRsaKeyPair,
    IpcCommand_GenerateEcKeyPair,
    IpcCommand_ImportRsaPrivateKey,
    IpcCommand_ImportEcPrivateKey,
    IpcCommand_ImportSymmetricKey,
    IpcCommand_SymmetricKeyEncryptDecrypt,
    IpcCommand_RsaPrivateEncryptDecryptWithAttachedKey, // Send RSA private encrypt decrypt message with encrypted key attached
    IpcCommand_EcdsaSignWithAttachedKey,                // Send ECDSA sign message with encrypted key attached
    IpcCommand_Max
}IpcCommand;

//////////////////////////////////////////////////////////////////////////////////////////////////
//
// IPC generic structures - to be encoded / decoded
//
//////////////////////////////////////////////////////////////////////////////////////////////////

// Each structure that is sent should include this header
#define CORRELATION_ID_LEN 16
#define HEADER_VERSION KEYISOP_CURRENT_VERSION

#define NUM_OF_HEADER_IN_ELEMENTS 3
typedef struct keyiso_input_header_st KEYISO_INPUT_HEADER_ST;
struct keyiso_input_header_st {
    uint8_t  version;
    uint32_t command;  // IpcCommand enum
    uint8_t  correlationId[CORRELATION_ID_LEN];
};

// Each structure that is replied should include this header
#define NUM_OF_HEADER_OUT_ELEMENTS 2
typedef struct keyiso_output_header_st KEYISO_OUTPUT_HEADER_ST;
struct keyiso_output_header_st {
    uint32_t command;  // IpcCommand enum
    uint32_t result; //both gdbus and OP-TEE results are 32 bits. Don't change that size.
};

#define NUM_OF_ENC_KEY_ELEMENTS 6
typedef struct keyiso_encrypted_private_key_st KEYISO_ENCRYPTED_PRIV_KEY_ST;
struct keyiso_encrypted_private_key_st {
    uint32_t algVersion;
    uint32_t saltLen;
    uint32_t ivLen;
    uint32_t hmacLen;
    uint32_t encKeyLen;
    uint8_t encryptedKeyBytes[];
};

//////////////////////////////////////////////////////////////////////////////////////////////////
//
// Specific messages structures - to be encoded / decoded
//
//////////////////////////////////////////////////////////////////////////////////////////////////

#define NUM_OF_IMPORT_PRIV_KEY_OUT_ELEMENTS 3
typedef struct keyiso_import_private_key_output_st KEYISO_IMPORT_PRIV_KEY_OUT_ST;
struct keyiso_import_private_key_output_st {
    KEYISO_OUTPUT_HEADER_ST headerSt;
    int8_t  secretSalt[KEYISO_SECRET_SALT_STR_BASE64_LEN];
    KEYISO_ENCRYPTED_PRIV_KEY_ST encKeySt;
};

// Structures for IpcCommand_ImportRsaPrivateKey
#define NUM_OF_IMPORT_RSA_PRIV_KEY_IN_ELEMENTS 2
typedef struct keyiso_import_rsa_private_key_input_st KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST;
struct keyiso_import_rsa_private_key_input_st {
    KEYISO_INPUT_HEADER_ST headerSt;
    KEYISO_RSA_PKEY_ST pkeySt;
};

// Structures for IpcCommand_ImportEcPrivateKey
#define NUM_OF_IMPORT_EC_PRIV_KEY_IN_ELEMENTS 2
typedef struct keyiso_import_ec_private_key_input_st KEYISO_IMPORT_EC_PRIV_KEY_IN_ST;
struct keyiso_import_ec_private_key_input_st {
    KEYISO_INPUT_HEADER_ST headerSt;
    KEYISO_EC_PKEY_ST pkeySt;
};

//////////////////////////////////////////////////////////////////////////////////////////////////
// Structures for IpcCommand_GenerateRsaKeyPair
#define NUM_OF_GENERATE_RSA_KEY_PAIR_IN_ELEMENTS 3
typedef struct keyiso_generate_rsa_key_pair_input_st KEYISO_GEN_RSA_KEY_PAIR_IN_ST;
struct keyiso_generate_rsa_key_pair_input_st {
    KEYISO_INPUT_HEADER_ST headerSt;
    uint32_t bits;      // rsa_bits
    uint8_t keyUsage;   // encrypt/sign
};

#define NUM_OF_GENERATE_RSA_KEY_PAIR_OUT_ELEMENTS 10
typedef struct keyiso_generate_rsa_key_pair_output_st KEYISO_GEN_RSA_KEY_PAIR_OUT_ST;
struct keyiso_generate_rsa_key_pair_output_st {
    KEYISO_OUTPUT_HEADER_ST headerSt;
    int8_t   secretSalt[KEYISO_SECRET_SALT_STR_BASE64_LEN];
    uint32_t algVersion;
    uint32_t saltLen;
    uint32_t ivLen;
    uint32_t hmacLen;
    uint32_t encKeyLen;
    uint32_t rsaModulusLen;      // n len (public key modulus length)
    uint32_t rsaPublicExpLen;    // e len (public key exponent length)
    uint8_t generateRsaKeyBytes[];
};

//////////////////////////////////////////////////////////////////////////////////////////////////
// Structures for IpcCommand_GenerateEcKeyPair
#define NUM_OF_GENERATE_KEY_PAIR_IN_ELEMENTS 3
typedef struct keyiso_generate_ec_key_pair_input_st KEYISO_GEN_EC_KEY_PAIR_IN_ST;
struct keyiso_generate_ec_key_pair_input_st {
    KEYISO_INPUT_HEADER_ST headerSt;
    uint32_t curve;      // curve_nid (EC)
    uint8_t keyUsage;   // ecdsa/ecdh
};

#define NUM_OF_GENERATE_EC_KEY_PAIR_OUT_ELEMENTS 10
typedef struct keyiso_generate_ec_key_pair_output_st KEYISO_GEN_EC_KEY_PAIR_OUT_ST;
struct keyiso_generate_ec_key_pair_output_st {
    KEYISO_OUTPUT_HEADER_ST headerSt;
    int8_t   secretSalt[KEYISO_SECRET_SALT_STR_BASE64_LEN];
    uint32_t algVersion;
    uint32_t saltLen;
    uint32_t ivLen;
    uint32_t hmacLen;
    uint32_t encKeyLen;
    uint32_t ecCurve;       // Curve group NID
    uint32_t ecPubKeyLen;  // Public EC key bytes len
    uint8_t generateEcKeyBytes[];
};

//////////////////////////////////////////////////////////////////////////////////////////////////
// Structures for IpcCommand_OpenPrivateKey
#define NUM_OF_OPEN_PRIV_KEY_IN_ELEMENTS 3
typedef struct keyiso_open_private_key_input_st KEYISO_OPEN_PRIV_KEY_IN_ST;
struct keyiso_open_private_key_input_st {
    KEYISO_INPUT_HEADER_ST headerSt;
    int8_t  secretSalt[KEYISO_SECRET_SALT_STR_BASE64_LEN];
    KEYISO_ENCRYPTED_PRIV_KEY_ST encKeySt;    
};

#define NUM_OF_OPEN_PRIV_KEY_OUT_ELEMENTS 2
typedef struct keyiso_open_private_key_output_st KEYISO_OPEN_PRIV_KEY_OUT_ST;
struct keyiso_open_private_key_output_st {
    KEYISO_OUTPUT_HEADER_ST headerSt;
    uint64_t keyId;
};

//////////////////////////////////////////////////////////////////////////////////////////////////
// Structures for IpcCommand_CloseKey
#define NUM_OF_CLOSE_KEY_IN_ELEMENTS 2
typedef struct keyiso_close_key_input_st KEYISO_CLOSE_KEY_IN_ST;
struct keyiso_close_key_input_st {
    KEYISO_INPUT_HEADER_ST headerSt;
    uint64_t keyId;    
};

#define NUM_OF_CLOSE_KEY_OUT_ELEMENTS 1
typedef struct keyiso_close_key_output_st KEYISO_CLOSE_KEY_OUT_ST;
struct keyiso_close_key_output_st {
    KEYISO_OUTPUT_HEADER_ST headerSt;
};

//////////////////////////////////////////////////////////////////////////////////////////////////
// Structures for IpcCommand_EcdsaSign
#define NUM_OF_ECDSA_SIGN_IN_ELEMENTS 6
typedef struct keyiso_ecdsa_sign_input_params_st KEYISO_ECDSA_SIGN_IN_PARAMS_ST;
struct keyiso_ecdsa_sign_input_params_st {
    int32_t type;
    uint32_t sigLen;
    int32_t digestLen;
    uint8_t digestBytes[];
};

typedef struct keyiso_ecdsa_sign_input_st KEYISO_ECDSA_SIGN_IN_ST;
struct keyiso_ecdsa_sign_input_st {
    KEYISO_INPUT_HEADER_ST headerSt;
    uint64_t keyId;
    KEYISO_ECDSA_SIGN_IN_PARAMS_ST params;
};

#define NUM_OF_ECDSA_SIGN_OUT_ELEMENTS 3
typedef struct keyiso_ecdsa_sign_output_st KEYISO_ECDSA_SIGN_OUT_ST;
struct keyiso_ecdsa_sign_output_st {
    KEYISO_OUTPUT_HEADER_ST headerSt;
    int32_t bytesLen;
    uint8_t signatureBytes[];
};

//////////////////////////////////////////////////////////////////////////////////////////////////
// Structures for IpcCommand_EcdsaSignWithAttacheKey
#define NUM_OF_ECDSA_SIGN_WITH_ATTACHED_KEY_IN_ELEMENTS 11
typedef struct keyiso_ecdsa_sign_with_attached_key_in_st KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_IN_ST;
struct keyiso_ecdsa_sign_with_attached_key_in_st {
    KEYISO_INPUT_HEADER_ST headerSt;
    int8_t secretSalt[KEYISO_SECRET_SALT_STR_BASE64_LEN];
    // Encrypted Key
    uint32_t algVersion;
    uint32_t saltLen;
    uint32_t ivLen;
    uint32_t hmacLen;
    uint32_t encKeyLen;
    // ECDSA Sign Parameters
    int32_t type;
    uint32_t sigLen;
    int32_t digestLen;
    // Bytes
    uint8_t bytes[];
};

#define NUM_OF_ECDSA_SIGN_WITH_ATTACHED_KEY_OUT_ELEMENTS 4
typedef struct keyiso_ecdsa_sign_with_attached_key_output_st KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_OUT_ST;
struct keyiso_ecdsa_sign_with_attached_key_output_st {
    KEYISO_OUTPUT_HEADER_ST headerSt;
    uint64_t keyId;
    int32_t bytesLen;
    uint8_t signatureBytes[];
};

//////////////////////////////////////////////////////////////////////////////////////////////////
// Structures for IpcCommand_RsaPrivateEncryptDecrypt

#define NUM_OF_RSA_PRIVATE_ENC_DEC_IN_ELEMENTS NUM_OF_RSA_PRIVATE_ENC_DEC_IN_PARAMS_ELEMENTS + 2
typedef struct keyiso_rsa_private_encrypt_decrypt_input_st KEYISO_RSA_PRIVATE_ENC_DEC_IN_ST;
struct keyiso_rsa_private_encrypt_decrypt_input_st {
    KEYISO_INPUT_HEADER_ST headerSt;
    uint64_t keyId; 
   KEYISO_RSA_PRIVATE_ENC_DEC_IN_PARAMS_ST params;
};

#define NUM_OF_RSA_PRIVATE_ENC_DEC_OUT_ELEMENTS 3
typedef struct keyiso_rsa_private_encrypt_decrypt_output_st KEYISO_RSA_PRIVATE_ENC_DEC_OUT_ST;
struct keyiso_rsa_private_encrypt_decrypt_output_st {
    KEYISO_OUTPUT_HEADER_ST headerSt;
    int32_t bytesLen;
    uint8_t toBytes[];
};

//////////////////////////////////////////////////////////////////////////////////////////////////
// Structures for IpcCommand_RsaPrivateEncryptDecryptWithAttachedKey
#define NUM_OF_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_IN_ELEMENTS 13
typedef struct keyiso_rsa_private_encrypt_decrypt_with_attached_key_input_st KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_IN_ST;
struct keyiso_rsa_private_encrypt_decrypt_with_attached_key_input_st {
    KEYISO_INPUT_HEADER_ST headerSt;
    int8_t secretSalt[KEYISO_SECRET_SALT_STR_BASE64_LEN];
    // Encrypted Key
    uint32_t algVersion;
    uint32_t saltLen;
    uint32_t ivLen;
    uint32_t hmacLen;
    uint32_t encKeyLen;
    // RSA Private Encrypt Decrypt Parameters
    int32_t decrypt;
    int32_t padding; 
    int32_t tlen; 
    int32_t fromBytesLen; 
    int32_t labelLen;
    // Bytes
    uint8_t bytes[];
};

#define NUM_OF_RSA_PRIVATE_ENC_DEC_WITH_ENC_KEY_OUT_ELEMENTS 4
typedef struct keyiso_rsa_private_encrypt_decrypt_with_attached_key_output_st KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_OUT_ST;
struct keyiso_rsa_private_encrypt_decrypt_with_attached_key_output_st {
    KEYISO_OUTPUT_HEADER_ST headerSt;
    uint64_t keyId;  // The new keyId
    int32_t bytesLen;
    uint8_t toBytes[];
};

//////////////////////////////////////////////////////////////////////////////////////////////////
// Structures for IpcCommand_ImportSymmetricKey
#define NUM_OF_IMPORT_SYMMETRIC_KEY_IN_ELEMENTS 5
typedef struct keyiso_import_symmetric_key_input_st KEYISO_IMPORT_SYMMETRIC_KEY_IN_ST;
struct keyiso_import_symmetric_key_input_st {
    KEYISO_INPUT_HEADER_ST headerSt;
    int32_t symmetricKeyType;
    uint8_t importKeyId[KMPP_AES_256_KEY_SIZE];
    uint32_t keyLen;
    uint8_t keyBytes[];
};

#define NUM_OF_IMPORT_SYMMETRIC_KEY_OUT_ELEMENTS 3
typedef struct keyiso_import_symmetric_key_output_st KEYISO_IMPORT_SYMMETRIC_KEY_OUT_ST;
struct keyiso_import_symmetric_key_output_st {
    KEYISO_OUTPUT_HEADER_ST headerSt;
    uint32_t encryptedKeyLen;
    uint8_t  encryptedKeyBytes[];
};

//////////////////////////////////////////////////////////////////////////////////////////////////
// Structures for IpcCommand_SymmetricKeyEncryptDecrypt 
#define NUM_OF_SYMMETRIC_ENCRYPT_DECRYPT_IN_ELEMENTS 5
typedef struct keyiso_symmetric_encrypt_decrypt_input_st KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST;
struct keyiso_symmetric_encrypt_decrypt_input_st {
    KEYISO_INPUT_HEADER_ST headerSt; 
    int32_t   decrypt; 
    uint32_t  encryptedKeyLen;
    uint32_t  fromBytesLen; 
    uint8_t   encDecBytes[]; //Note the following order: 1.encryptedKey, 2.fromBytes
};

#define NUM_OF_SYMMETRIC_ENCRYPT_DECRYPT_OUT_ELEMENTS 3
typedef struct keyiso_symmetric_encrypt_decrypt_output_st KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_OUT_ST;
struct keyiso_symmetric_encrypt_decrypt_output_st {
    KEYISO_OUTPUT_HEADER_ST headerSt;
    uint32_t bytesLen; 
    uint8_t toBytes[]; 
};