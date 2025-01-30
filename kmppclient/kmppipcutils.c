/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stddef.h>

#include <openssl/obj_mac.h>

#include "keyisocommon.h"
#include "keyisoipcgenericmessage.h"
#include "keyisoipccommands.h"

#define KMPP_RSA_COMMON_PRIVATE_KEY_LEN         4096
#define KMPP_RSA_DEFAULT_PUBLIC_EXPONENT_LEN    3   // The default exponent value is 65537 (2^16+1)

#define KMPP_ECC_PRIME192V1_FIELD_LEN           24  // 192 bits
#define KMPP_ECC_PRIME256V1_FIELD_LEN           32  // 256 bits
#define KMPP_ECC_SECP224R1_FIELD_LEN            28  // 224 bits
#define KMPP_ECC_SECP384R1_FIELD_LEN            48  // 384 bits
#define KMPP_ECC_SECP521R1_FIELD_LEN            66  // 521 bits

#define KMPP_ECC_MAX_PRIVATE_KEY_LEN            KMPP_ECC_SECP521R1_FIELD_LEN  // secp521r1
#define KMPP_DER_ENCODING_HEADER_LEN            7

// The maximum length of the DER encoded ECDSA signature
#define KMPP_ECC_MAX_ECDSA_SIG_DER_ENCODED  ((2 * KMPP_ECC_MAX_PRIVATE_KEY_LEN) + KMPP_DER_ENCODING_HEADER_LEN)   

#define INT_TO_BYTESIZE(x)  (((x) + 7) / 8)
/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////// Internal functions //////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////

static size_t _get_estimate_import_priv_key_out_len(int command, IPC_SEND_RECEIVE_ST *ipcSt)
{
    void *inKey = NULL;              // KEYISO_RSA_PKEY_ST or KEYISO_EC_PKEY_ST
    size_t inKeyLen = 0;             // size of the input private key
    size_t dynamicLen = 0;           // size of the dynamic part of the structure
    unsigned int paddedKeyLen = 0;   // size of the padded key

    //1. Calculating the size of the input private key
    if (command == IpcCommand_ImportRsaPrivateKey) {
        inKey = &((KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST *)ipcSt->inSt)->pkeySt;
        inKeyLen = GET_DYNAMIC_STRUCT_SIZE(KEYISO_RSA_PKEY_ST, KeyIso_get_rsa_pkey_bytes_len((KEYISO_RSA_PKEY_ST *)inKey));
    } else if (command == IpcCommand_ImportEcPrivateKey){
        inKey = &((KEYISO_IMPORT_EC_PRIV_KEY_IN_ST *)ipcSt->inSt)->pkeySt;
        inKeyLen = GET_DYNAMIC_STRUCT_SIZE(KEYISO_EC_PKEY_ST, KeyIso_get_ec_pkey_bytes_len((KEYISO_EC_PKEY_ST *)inKey));
    }
    
    //2. Adding extra bytes for storing the type of the key
    inKeyLen += sizeof(int);         // sizeof(KmppKeyType)
    
    //3. Calculating the size of the padded key
    paddedKeyLen = KeyIso_get_key_padded_size(inKeyLen);
    
    //4. Adding the size of the salt, IV, and HMAC to the padded key
    dynamicLen = KEYISO_KDF_SALT_LEN + KMPP_AES_BLOCK_SIZE + KMPP_HMAC_SHA256_KEY_SIZE + (size_t)paddedKeyLen;
    
    //5. Adding the dynamic length to the size of the strucutre
    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_IMPORT_PRIV_KEY_OUT_ST, dynamicLen);
}

static size_t _get_estimate_generate_rsa_key_out_len(int command, IPC_SEND_RECEIVE_ST *ipcSt)
{
    unsigned int encKeyLen = 0;       // length of the encrypted key (in bytes)
    uint32_t pubKeyLen = 0;           // length of the public key (in bytes)
    uint32_t rsaModulusLen = 0;       // length of the modulus (in bytes)
    uint32_t rsaPublicExpLen = 0;     // length of the public exponent (in bytes)
    size_t inKeyLen = 0;              // size of the input private key structure (in bytes)
    size_t rsaKeyLen = 0;             // length of the input private key (in bytes)   
    size_t dynamicLen = 0;            // size of the dynamic part of the structure (in bytes)

    //1. Calculating the size of the generated private key elements
    rsaModulusLen = INT_TO_BYTESIZE(((KEYISO_GEN_RSA_KEY_PAIR_IN_ST *)ipcSt->inSt)->bits);
    rsaPublicExpLen = KMPP_RSA_DEFAULT_PUBLIC_EXPONENT_LEN;

    //2. Calculating the size of the generated public key
    pubKeyLen = rsaModulusLen + rsaPublicExpLen;

    //3. Calculating the size of the encrypted private key
    // RSA key length = (modulus length * (numbers of primes)) + public exponent length
    rsaKeyLen = (rsaModulusLen * KEYISO_SYMCRYPT_RSA_SUPPORTED_NUM_OF_PRIMES) + rsaPublicExpLen;
    inKeyLen = GET_DYNAMIC_STRUCT_SIZE(KEYISO_RSA_PKEY_ST, rsaKeyLen) + sizeof(int); // sizeof(KmppKeyType)
    encKeyLen = KeyIso_get_key_padded_size(inKeyLen);
    
    //4. Calculating the size of the dynamic part of the structure
    dynamicLen = KEYISO_KDF_SALT_LEN + KMPP_AES_BLOCK_SIZE + KMPP_HMAC_SHA256_KEY_SIZE + (size_t)encKeyLen + (size_t)pubKeyLen;
    
    //5. Returning the total size of the structure
    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_GEN_RSA_KEY_PAIR_OUT_ST, dynamicLen);
}

static size_t _get_field_size_in_bytes(unsigned int curve)
{
    switch (curve)
    {
        case NID_X9_62_prime192v1:
            return KMPP_ECC_PRIME192V1_FIELD_LEN;
        case NID_X9_62_prime256v1:
            return KMPP_ECC_PRIME256V1_FIELD_LEN;
        case NID_secp224r1:
            return KMPP_ECC_SECP224R1_FIELD_LEN;
        case NID_secp384r1:
            return KMPP_ECC_SECP384R1_FIELD_LEN;
        case NID_secp521r1:
            return KMPP_ECC_SECP521R1_FIELD_LEN;
        default:
            return 0;
    }
}

static size_t _get_estimate_generate_ecc_key_out_len(int command, IPC_SEND_RECEIVE_ST *ipcSt)
{
    size_t fieldLen = 0;              // size of the field (in bytes)
    size_t inKeyLen = 0;              // size of the input private key structure (in bytes)
    size_t dynamicLen = 0;            // size of the dynamic part of the structure (in bytes)
    unsigned int encKeyLen = 0;       // length of the encrypted key (in bytes)

    //1. Getting the size (in bytes) of the prime field defined by the curve
    fieldLen = _get_field_size_in_bytes(((KEYISO_GEN_EC_KEY_PAIR_IN_ST *)ipcSt->inSt)->curve);
    
    //2. Calculating the size of the encrypted private key
    // EC key length = ecPubXLen + ecPubYLen + ecPrivKeyLen = (fieldLen * 3)
    inKeyLen = GET_DYNAMIC_STRUCT_SIZE(KEYISO_EC_PKEY_ST, (fieldLen * 3) + sizeof(int));  // sizeof(KmppKeyType)
    encKeyLen = KeyIso_get_key_padded_size(inKeyLen);
    
    //3. Calculating the size of the dynamic part of the structure
    dynamicLen = KEYISO_KDF_SALT_LEN + KMPP_AES_BLOCK_SIZE + KMPP_HMAC_SHA256_KEY_SIZE + (size_t)encKeyLen + (fieldLen * 2);
    
    //4. Returning the total size of the structure
    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_GEN_EC_KEY_PAIR_OUT_ST, dynamicLen);
}

static size_t _get_estimate_rsa_encrypt_decrypt_out_len(int command, IPC_SEND_RECEIVE_ST *ipcSt)
{
    // The ciphertext / signature of RSA algorithms can't be larger then key modulus length.
    // The KMPP engine calls the client functions with 'tlen' equals to the key length.
    size_t maxBytesLen = KMPP_RSA_COMMON_PRIVATE_KEY_LEN / 8;
    int32_t bytesLen = ((KEYISO_RSA_PRIVATE_ENC_DEC_IN_ST *)ipcSt->inSt)->params.tlen;  // RSA key length
    if (bytesLen < 0 || bytesLen > maxBytesLen)
        bytesLen = KMPP_RSA_COMMON_PRIVATE_KEY_LEN / 8;
    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_RSA_PRIVATE_ENC_DEC_OUT_ST, bytesLen);
}

static size_t _get_estimate_ecdsa_sign_out_len(int command, IPC_SEND_RECEIVE_ST *ipcSt)
{
    // The KMPP engine calls the client function with 'sigLen' equals to 
    // the maximum length of the DER encoded signature.
    int32_t bytesLen = ((KEYISO_ECDSA_SIGN_IN_ST *)ipcSt->inSt)->params.sigLen;
    if (bytesLen < 0 || bytesLen > KMPP_ECC_MAX_ECDSA_SIG_DER_ENCODED)
        bytesLen = KMPP_ECC_MAX_ECDSA_SIG_DER_ENCODED;
    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_ECDSA_SIGN_OUT_ST, bytesLen);
}

/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////// External functions //////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////

size_t KeyIso_get_estimate_out_len(int command, IPC_SEND_RECEIVE_ST *ipcSt) 
{
    if (ipcSt == NULL || ipcSt->inSt == NULL)
        return 0;

    size_t estimateOutLen = 0;
    switch (command) {
        case IpcCommand_OpenPrivateKey:
        {
            estimateOutLen = sizeof(KEYISO_OPEN_PRIV_KEY_OUT_ST);
            break;
        }
        case IpcCommand_CloseKey:
        {
            estimateOutLen = sizeof(KEYISO_CLOSE_KEY_OUT_ST);
            break;
        }
        case IpcCommand_ImportRsaPrivateKey:
        case IpcCommand_ImportEcPrivateKey:
        {
            estimateOutLen = _get_estimate_import_priv_key_out_len(command, ipcSt);
            break;
        }
        case IpcCommand_GenerateRsaKeyPair:
        {
            estimateOutLen = _get_estimate_generate_rsa_key_out_len(command, ipcSt);
            break;
        }
        case IpcCommand_GenerateEcKeyPair:
        {
            estimateOutLen = _get_estimate_generate_ecc_key_out_len(command, ipcSt);
            break;
        }
        case IpcCommand_RsaPrivateEncryptDecrypt:
        {
            estimateOutLen = _get_estimate_rsa_encrypt_decrypt_out_len(command, ipcSt);
            break;
        }
        case IpcCommand_EcdsaSign:
        {   
            estimateOutLen = _get_estimate_ecdsa_sign_out_len(command, ipcSt);
            break;
        }
        case IpcCommand_ImportSymmetricKey:
        {
            unsigned int encryptedKeyLen = 0;
            KeyIso_symmetric_key_encrypt_decrypt_size(
                KEYISO_AES_ENCRYPT_MODE,
                ((KEYISO_IMPORT_SYMMETRIC_KEY_IN_ST *)ipcSt->inSt)->keyLen,
                KMPP_SYMMETRICKEY_META_DATA_LEN,
                &encryptedKeyLen); 
            estimateOutLen = GET_DYNAMIC_STRUCT_SIZE(KEYISO_IMPORT_SYMMETRIC_KEY_OUT_ST, encryptedKeyLen);
            break;
        }
        case IpcCommand_SymmetricKeyEncryptDecrypt:
        {
            // In the mode of decryption, we can not know the exact padding length, so we use the maximum length of the padding - 16 bytes.
            unsigned int bytesLen = 0;
            KeyIso_symmetric_key_encrypt_decrypt_size(
                ((KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST *)ipcSt->inSt)->decrypt,
                ((KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST *)ipcSt->inSt)->fromBytesLen,
                0,
                &bytesLen);
            estimateOutLen = GET_DYNAMIC_STRUCT_SIZE(KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_OUT_ST, bytesLen);
            break;
        }
        default:
            break;
    }
    return estimateOutLen;
}