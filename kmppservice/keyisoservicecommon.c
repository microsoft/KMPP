/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <string.h>
#include <stdio.h>

#include "kmppsymcryptwrapper.h"

#include "keyisocommon.h"
#include "keyisoipccommands.h"
#include "keyisolog.h"
#include "keyisomemory.h"
#include "keyisoservicecommon.h"
#include "keyisoutils.h"


KeyIso_get_machine_secret_func_ptr KeyIso_get_machine_secret_func;

// The gdbus service can configure this value by dbus config but the lru cache/key list and common are compiled to service lib(to be used for optee or inproc tests)
// It is defines in service lib header as extern, set to default value for code linking to srvlib with default hash size
uint32_t g_keyCacheCapacity = KEYISO_KEY_DEFAULT_HASH_SIZE;


int KeyIso_set_machine_secret_method(
    const uuid_t correlationId,
    KeyIso_get_machine_secret_func_ptr getMachineSecretFunc)
{
    if (getMachineSecretFunc == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_PFX_SECRET_TITLE,
                               "Invalid input",
                               "getMachineSecretFunc can't be null");
        return STATUS_FAILED;
    }
    KeyIso_get_machine_secret_func = getMachineSecretFunc;
    return STATUS_OK;
}

int KeyIso_is_valid_salt_prefix(
    const uuid_t correlationId,
    const unsigned char *salt,
    const unsigned char *secret)
{
    const char *title = KEYISOP_PFX_SECRET_TITLE;    
    if (secret[0] == 0) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, "PFX secret not created at service start");     
        return STATUS_FAILED;
    }

    if (memcmp(secret, salt, KEYISO_SECRET_SALT_LENGTH) != 0) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, "Salt doesn't match PFX secret");
        return STATUS_FAILED;
    }

    return STATUS_OK;
}

static int _cleanup_is_valid_salt(
    const uuid_t correlationId, 
    int status,
    unsigned char *decoded,
    const char *errStr,
    int decodedLength)
{
    const char *title = KEYISOP_PFX_SECRET_TITLE;
    if (status == STATUS_FAILED) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, errStr);
    }

    KeyIso_clear_free(decoded, decodedLength);

    return status;
}

int KeyIso_is_valid_salt(
    const uuid_t correlationId,
    const char *salt,
    unsigned char* secret)
{
    if (salt == NULL || secret == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_PFX_SECRET_TITLE, NULL, "Salt or secret is NULL");
        return STATUS_FAILED;
    }
        
    // Use strnlen to safely determine the length of the salt
    size_t saltLength = strnlen(salt, KEYISO_SECRET_SALT_STR_BASE64_LEN);
    
    // Check if the salt length is within the expected range
    // Ensure that the length is not zero and does not exceed KEYISO_SECRET_SALT_STR_BASE64_LEN - 1
    if (saltLength == 0 || saltLength >= KEYISO_SECRET_SALT_STR_BASE64_LEN) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_PFX_SECRET_TITLE, NULL, "Invalid salt length");
        return STATUS_FAILED;
    }

    // "0." <base64 salt> (data content checks)
    if (saltLength < 3 || salt[0] != '0') {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_PFX_SECRET_TITLE, NULL, "Invalid salt");
        return STATUS_FAILED;
    }

    unsigned char *decoded = NULL;  // KeyIso_free()
    int decodedLength = 0;

    decodedLength = KeyIso_base64_decode(correlationId, &salt[2], &decoded); //Index 2 since salt starts with "0."
    
    if (decodedLength < KEYISO_SECRET_SALT_LENGTH) {
        return _cleanup_is_valid_salt(correlationId, STATUS_FAILED, decoded, "Invalid decoded salt", decodedLength);
    }

    if (KeyIso_is_valid_salt_prefix(correlationId, decoded, secret) == STATUS_FAILED) {
        return _cleanup_is_valid_salt(correlationId, STATUS_FAILED, decoded, "Invalid salt", decodedLength);
    }

    return _cleanup_is_valid_salt(correlationId, STATUS_OK, decoded, NULL, decodedLength);
}

int KeyIso_generate_salt_bytes(
    const uuid_t correlationId,
    unsigned char *saltBytes,
    const int saltBytesLength)  
{
    const char *title = KEYISOP_PFX_SECRET_TITLE;
    uint8_t machine_secret[KEYISO_SECRET_FILE_LENGTH] = { };

    if (saltBytesLength < KEYISO_SECRET_SALT_LENGTH) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, "salt length");
        return STATUS_FAILED;
    }


    if(!KeyIso_get_machine_secret_func){
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, "machine secret retrieval function not set");
        return STATUS_FAILED;
    }

    if (KeyIso_get_machine_secret_func(machine_secret, sizeof(machine_secret)) != STATUS_OK) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, "Failed to get machine secret");
        return STATUS_FAILED;
    }

    memcpy(saltBytes, machine_secret, KEYISO_SECRET_SALT_LENGTH);
    KeyIso_cleanse(machine_secret, sizeof(machine_secret));     

    if (KeyIso_rand_bytes(
            saltBytes + KEYISO_SECRET_SALT_LENGTH,
            saltBytesLength - KEYISO_SECRET_SALT_LENGTH) != STATUS_OK) {
                KEYISOP_trace_log_error(correlationId, 0, title, NULL, "RAND_bytes");
                return STATUS_FAILED;
    }

    return STATUS_OK;
}

// salt
//  t.<base64>  -- test salt
//  0.<base64>  -- persisted pfx secret
int KeyIso_generate_salt(
    const uuid_t correlationId,
    char **salt)    // KeyIso_free()
{
    const char *title = KEYISOP_PFX_SECRET_TITLE;
    int ret = 0;
    const char versionChar ='0';
    unsigned char randBytes[KEYISO_SECRET_SALT_LENGTH + 16];
    char* base64Bytes = NULL; 
    int encodeLength = 0;

    *salt = NULL;

    if (KeyIso_generate_salt_bytes(
        correlationId,
        randBytes,
        sizeof(randBytes)) != STATUS_OK) {
        goto end;
    }

   int expectedSize = KEYISOP_BASE64_ENCODE_LENGTH(KEYISO_SECRET_SALT_LENGTH + 16);
   encodeLength = KeyIso_base64_encode(correlationId, randBytes, (int)sizeof(randBytes), &base64Bytes);
    if (encodeLength != expectedSize) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "KeyIso_base64_encode", "encode failed",
            "length: %d expected: %d", encodeLength, expectedSize);
        goto end;
    }
    
    int saltLength = 2 + expectedSize;
    *salt = (char *) KeyIso_zalloc(saltLength);
    if (*salt == NULL) {
        goto end;
    }

    snprintf(*salt, saltLength, "%c.%s",
        versionChar,
        base64Bytes);

    ret = 1;

end:
    KeyIso_cleanse(randBytes, sizeof(randBytes));
    KeyIso_free(base64Bytes);
    return ret;
}

static int _cleanup_generate_password_from_salt(
    const uuid_t correlationId,
    int status,
    unsigned char *hmacBytes,
    uint8_t *machine_secret,
    const char *errStr)
{
    const char *title = KEYISOP_IMPORT_KEY_TITLE;
    if (status == STATUS_FAILED) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, errStr);
    }
    if(hmacBytes){
        KeyIso_cleanse(hmacBytes, sizeof(hmacBytes));
    }
    KeyIso_cleanse(machine_secret, sizeof(machine_secret));
    return status;
}

int KeyIso_generate_password_from_salt(
    const uuid_t correlationId,
    const char *salt,
    char **password)    // KeyIso_free()
{
    unsigned char *hmacKey = NULL;
    unsigned char hmacBytes[KMPP_HMAC_SHA256_KEY_SIZE] = { 0 };
    uint8_t machine_secret[KEYISO_SECRET_FILE_LENGTH] = { 0 };
    int encodeLength = 0;

    *password = NULL;

    if (salt == NULL) {
        salt = "";
    }

    if(!KeyIso_get_machine_secret_func){
        return _cleanup_generate_password_from_salt(correlationId, STATUS_FAILED, hmacBytes, machine_secret, "machine secret retrieval function not set");
    }
    
    if (KeyIso_get_machine_secret_func(machine_secret, sizeof(machine_secret)) != STATUS_OK) {
        return _cleanup_generate_password_from_salt(correlationId, STATUS_FAILED, hmacBytes, machine_secret, "Failed getting machine secret");
    }        
    
    if (g_isSaltValidationRequired && !KeyIso_is_valid_salt(correlationId, salt, machine_secret)) {
        return _cleanup_generate_password_from_salt(correlationId, STATUS_FAILED, hmacBytes, machine_secret, "Invalid salt");
    }
    
    // Key follows the secret's salt
    hmacKey = &machine_secret[KEYISO_SECRET_SALT_LENGTH];

    // Use strnlen to safely determine the length of the salt.
    size_t saltLength = strnlen(salt, KEYISO_SECRET_SALT_STR_BASE64_LEN);
    
    // Check if the salt length is within the expected range
    // Ensure that the length is not zero and does not exceed KEYISO_SECRET_SALT_STR_BASE64_LEN - 1
    if (saltLength == 0 || saltLength >= KEYISO_SECRET_SALT_STR_BASE64_LEN) {
        return _cleanup_generate_password_from_salt(correlationId, STATUS_FAILED, hmacBytes, machine_secret, "Invalid salt");
    }

    int ret = KeyIso_sha256_hmac_calculation(correlationId, (unsigned char*)salt, saltLength,
                                         hmacKey, KMPP_HMAC_SHA256_KEY_SIZE, hmacBytes);
    if(ret != STATUS_OK) {
        return  _cleanup_generate_password_from_salt(correlationId, STATUS_FAILED, hmacBytes, machine_secret, "KeyIso_sha256_hmac_calculation HMAC calculation failed");
    }

    encodeLength = KeyIso_base64_encode(correlationId, hmacBytes, KMPP_AES_256_KEY_SIZE, password);

    if (!encodeLength) {
        return  _cleanup_generate_password_from_salt(correlationId, STATUS_FAILED, hmacBytes, machine_secret, "_base64_encode failed");
    }

    return _cleanup_generate_password_from_salt(correlationId, STATUS_OK, hmacBytes, machine_secret, NULL);
}

/////////////////////////////////////////////////////
/////////////// Internal HMAC methods ///////////////
/////////////////////////////////////////////////////

int KeyIso_sha256_hmac_calculation(const uuid_t correlationId,
                            const unsigned char* data,
                            const unsigned int data_len,
                            const unsigned char* key,
                            const unsigned int key_len,
                            unsigned char* hmac_result)
{
    const char *title = KEYISOP_IMPORT_KEY_TITLE;
    SYMCRYPT_HMAC_SHA256_STATE hmac_state ;
    SYMCRYPT_HMAC_SHA256_EXPANDED_KEY hmac_key;
    
    if (key_len != KMPP_AES_256_KEY_SIZE) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "Key", "Invalid length", "key len:%d", key_len);
        return STATUS_FAILED;
    }

    // Ensure the structures are zeroed out
    memset(&hmac_state, 0, sizeof(hmac_state));
    memset(&hmac_key, 0, sizeof(hmac_key));

    if (SymCryptHmacSha256ExpandKey(&hmac_key, key, key_len) != SYMCRYPT_NO_ERROR) {
        KEYISOP_trace_log_error(correlationId, 0, title, "SymCryptHmacSha256ExpandKey", "key generation failed");
        return STATUS_FAILED;
    }

    SymCryptHmacSha256Init(&hmac_state, &hmac_key);
    SymCryptHmacSha256Append(&hmac_state, data, data_len);
    SymCryptHmacSha256Result(&hmac_state, hmac_result);

    // Clean up the HMAC state
    SymCryptWipe(&hmac_state, sizeof(hmac_state));

    return STATUS_OK;
}

int KeyIso_hmac_validation(
    const unsigned char* hmac1,
    const unsigned char* hmac2,
    unsigned int hmacLen)
{
    /*
    This function contains a temporary implementation copy from SymCryptEqual function
    The implementation will be changed to use SymCrypt method SymCryptEqual when they are ready to be consumed from SymCrypt
    */
    UINT32 neq = 0;
    BYTE b;
    volatile BYTE * p1 = (volatile BYTE *) hmac1;
    volatile BYTE * p2 = (volatile BYTE *) hmac2;

    //
    // We use forced-access memory reads to ensure that the compiler doesn't get
    // smart and implement an early-out solution.
    //
// Avoid cast-align warning since that this is a symcrypt code that we want to use as is
// SymCrypt implementation assumes unaligned issues
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
    while( hmacLen >= 4 )
    {
        neq |= SYMCRYPT_FORCE_READ32( (volatile UINT32 *) p1 ) ^ SYMCRYPT_FORCE_READ32( (volatile UINT32 *) p2 );
        p1 += 4;
        p2 += 4;
        hmacLen -= 4;
    }
#pragma GCC diagnostic pop

    // We have to deal with the remaining bytes using a separate accumulator to work around an issue in the ARM64 compiler.
    if( hmacLen > 0 )
    {
        b = 0;
        while( hmacLen > 0 )
        {
            b |= SYMCRYPT_FORCE_READ8( p1 ) ^ SYMCRYPT_FORCE_READ8( p2 );
            p1++;
            p2++;
            hmacLen--;
        }
        neq |= b;
    }

    return neq == 0 ? STATUS_OK : STATUS_FAILED;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////// IN message length functions //////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef size_t (*PFN_msg_length_ipc)(const uint8_t *inSt, const PFN_mem_move memMove);

// Length Functions prototypes
static size_t _open_private_key_msg_in_length(const uint8_t *inSt, const PFN_mem_move memMove);
static size_t _close_key_msg_in_length(const uint8_t *inSt, const PFN_mem_move memMove);
static size_t _ecdsa_sign_msg_in_length(const uint8_t *inSt, const PFN_mem_move memMove);
static size_t _rsa_private_enc_dec_in_length(const uint8_t *inSt, const PFN_mem_move memMove);
static size_t _generate_rsa_key_pair_msg_in_length(const uint8_t *inSt, const PFN_mem_move memMove);
static size_t _generate_ecc_key_pair_msg_in_length(const uint8_t *inSt, const PFN_mem_move memMove);
static size_t _import_rsa_private_key_msg_in_length(const uint8_t *inSt, const PFN_mem_move memMove);
static size_t _import_ec_private_key_msg_in_length(const uint8_t *inSt, const PFN_mem_move memMove);
static size_t _import_symmetric_key_msg_in_length(const uint8_t *inSt, const PFN_mem_move memMove);
static size_t _symmetric_key_enc_dec_msg_in_length(const uint8_t *inSt, const PFN_mem_move memMove);

// Declare an array of function pointers
static const PFN_msg_length_ipc msgLengthFunctions[] = {
    _open_private_key_msg_in_length,
    _close_key_msg_in_length,
    _ecdsa_sign_msg_in_length,
    _rsa_private_enc_dec_in_length,
    _generate_rsa_key_pair_msg_in_length,
    _generate_ecc_key_pair_msg_in_length,
    _import_rsa_private_key_msg_in_length,
    _import_ec_private_key_msg_in_length,
    _import_symmetric_key_msg_in_length,
    _symmetric_key_enc_dec_msg_in_length
};

static const size_t inMsgMinStructSizes[] = {
    sizeof(KEYISO_OPEN_PRIV_KEY_IN_ST),             //IpcCommand_OpenPrivateKey
    sizeof(KEYISO_CLOSE_KEY_IN_ST),                 //IpcCommand_CloseKey
    sizeof(KEYISO_ECDSA_SIGN_IN_ST),                //IpcCommand_EcdsaSign
    sizeof(KEYISO_RSA_PRIVATE_ENC_DEC_IN_ST),       //IpcCommand_RsaPrivateEncryptDecrypt
    sizeof(KEYISO_GEN_RSA_KEY_PAIR_IN_ST),          //IpcCommand_GenerateRsaKeyPair
    sizeof(KEYISO_GEN_EC_KEY_PAIR_IN_ST),           //IpcCommand_GenerateEcKeyPair
    sizeof(KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST),       //IpcCommand_ImportRsaPrivateKey
    sizeof(KEYISO_IMPORT_EC_PRIV_KEY_IN_ST),        //IpcCommand_ImportEcPrivateKey
    sizeof(KEYISO_IMPORT_SYMMETRIC_KEY_IN_ST),      //IpcCommand_ImportSymmetricKey
    sizeof(KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST)  //IpcCommand_SymmetricKeyEncryptDecrypt
};

static size_t _open_private_key_msg_in_length(const uint8_t *inSt, const PFN_mem_move memMove)
{    
    // getting the offset of the inner structure encKeySt inside the KEYISO_OPEN_PRIV_KEY_IN_ST
    size_t encKeyStOffset = offsetof(KEYISO_OPEN_PRIV_KEY_IN_ST, encKeySt);

    // Getting the values (from the inSt) of the followings fields saltLen, ivLen, hmacLen, encKeyLen 
    uint32_t saltLenFieldValue = 0;
    memMove(&saltLenFieldValue, inSt + encKeyStOffset + offsetof(KEYISO_ENCRYPTED_PRIV_KEY_ST, saltLen), sizeof(uint32_t));
        
    uint32_t ivLenFieldValue = 0;    
    memMove(&ivLenFieldValue, inSt + encKeyStOffset + offsetof(KEYISO_ENCRYPTED_PRIV_KEY_ST, ivLen), sizeof(uint32_t));
        
    uint32_t hmacLenFieldValue = 0;
    memMove(&hmacLenFieldValue, inSt + encKeyStOffset + offsetof(KEYISO_ENCRYPTED_PRIV_KEY_ST, hmacLen), sizeof(uint32_t));
    
    uint32_t encKeyLenFieldValue = 0;
    memMove(&encKeyLenFieldValue, inSt + encKeyStOffset + offsetof(KEYISO_ENCRYPTED_PRIV_KEY_ST, encKeyLen), sizeof(uint32_t));
                
    // Calculating the size of the dynamic array
    uint32_t openInStDynamicArraySize = 0;
    if (!KEYISO_ADD_OVERFLOW(saltLenFieldValue, ivLenFieldValue, &openInStDynamicArraySize) &&
        !KEYISO_ADD_OVERFLOW(openInStDynamicArraySize, hmacLenFieldValue, &openInStDynamicArraySize) &&
        !KEYISO_ADD_OVERFLOW(openInStDynamicArraySize, encKeyLenFieldValue, &openInStDynamicArraySize)) { 
        // Calculating the size of the in structure (where as the dynamic array length == openInStDynamicArraySize)
        return GET_DYNAMIC_STRUCT_SIZE(KEYISO_OPEN_PRIV_KEY_IN_ST, openInStDynamicArraySize);
    }
    
    return 0;
}

static size_t _close_key_msg_in_length(const uint8_t *inSt, const PFN_mem_move memMove)
{
    (void)inSt;
    (void)memMove;

    // As there is not any dynamic array in this structure
    return sizeof(KEYISO_CLOSE_KEY_IN_ST);
}

static size_t _ecdsa_sign_msg_in_length(const uint8_t *inSt, const PFN_mem_move memMove)
{
    size_t inStLenCalc = 0;

    // Getting the value of the field digestLenOffset from the inSt
    size_t digestLenOffset = offsetof(KEYISO_ECDSA_SIGN_IN_ST, params) +  offsetof(KEYISO_ECDSA_SIGN_IN_PARAMS_ST, digestLen);
    int32_t digestLenFieldValue = 0;
    memMove(&digestLenFieldValue, inSt + digestLenOffset, sizeof(int32_t));

    //checking for invalid input for dynamic array size (digestBytes[])
    if (digestLenFieldValue < 0) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_SERVICE_TITLE, "", "Invalid input length");
    } else {        
        // Calculating the size of the in structure (where as the dynamic array length == digestLenFieldValue)
        inStLenCalc = GET_DYNAMIC_STRUCT_SIZE(KEYISO_ECDSA_SIGN_IN_ST, digestLenFieldValue);
    }
    
    return inStLenCalc;
}

static size_t _generate_ecc_key_pair_msg_in_length(const uint8_t *inSt, const PFN_mem_move memMove)
{
    (void)inSt;
    (void)memMove;

    // As there is not any dynamic array in this structure
    return sizeof(KEYISO_GEN_EC_KEY_PAIR_IN_ST); 
}

static size_t _rsa_private_enc_dec_in_length(const uint8_t *inSt, const PFN_mem_move memMove)
{
    size_t inStLenCalc = 0;

    // Getting the value of the field fromBytesLen from the inSt
    size_t paramsOffset =  offsetof(KEYISO_RSA_PRIVATE_ENC_DEC_IN_ST,params);
    size_t fromBytesLenOffset = paramsOffset + offsetof(KEYISO_RSA_PRIVATE_ENC_DEC_IN_PARAMS_ST, fromBytesLen);
    size_t labelOffset = paramsOffset + offsetof(KEYISO_RSA_PRIVATE_ENC_DEC_IN_PARAMS_ST, labelLen);

    int32_t fromBytesLenFieldValue = 0;
    memMove(&fromBytesLenFieldValue, inSt + fromBytesLenOffset, sizeof(int32_t));

    int32_t labelLenFieldValue = 0;
    memMove(&labelLenFieldValue, inSt + labelOffset, sizeof(int32_t));
    
    //checking for invalid input for dynamic array size (fromBytes[])
    if (fromBytesLenFieldValue < 0 || labelLenFieldValue < 0) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_SERVICE_TITLE, "", "Invalid input length");
    } else {        
        // Calculating the size of the in structure (where as the dynamic array length == fromBytesLenFieldValue)
        size_t dynamicLen = KeyIso_get_rsa_enc_dec_params_dynamic_len(fromBytesLenFieldValue, labelLenFieldValue);
        inStLenCalc = GET_DYNAMIC_STRUCT_SIZE(KEYISO_RSA_PRIVATE_ENC_DEC_IN_ST, dynamicLen);
    }
    return inStLenCalc;
}

static size_t _import_symmetric_key_msg_in_length(const uint8_t *inSt, const PFN_mem_move memMove)
{
    size_t inStLenCalc = 0;

    // Getting the value of the field keyLen from the inSt
    size_t keyLenOffset = offsetof(KEYISO_IMPORT_SYMMETRIC_KEY_IN_ST, keyLen);
    uint32_t keyLenFieldValue = 0;
    memMove(&keyLenFieldValue, inSt + keyLenOffset, sizeof(uint32_t));

    // Calculating the size of the in structure (where as the dynamic array length == keyLenFieldValue)
    inStLenCalc = GET_DYNAMIC_STRUCT_SIZE(KEYISO_IMPORT_SYMMETRIC_KEY_IN_ST, keyLenFieldValue);

    return inStLenCalc;
}

static size_t _import_rsa_private_key_msg_in_length(const uint8_t *inSt, const PFN_mem_move memMove)
{
    // getting the offset of the inner structure encKeySt inside the KEYISO_OPEN_PRIV_KEY_IN_ST 
    size_t pkeyStOffset = offsetof(KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST, pkeySt);

    // Getting the values (from the inSt) of the following fields rsaModulusLen, rsaPublicExpLen, rsaPrimes1Len, rsaPrimes2Len
    uint32_t rsaModulusLenFieldValue = 0;
    memMove(&rsaModulusLenFieldValue, inSt + pkeyStOffset + offsetof(KEYISO_RSA_PKEY_ST, rsaModulusLen), sizeof(uint32_t));

    uint32_t rsaPublicExpLenFieldValue = 0;
    memMove(&rsaPublicExpLenFieldValue, inSt + pkeyStOffset + offsetof(KEYISO_RSA_PKEY_ST, rsaPublicExpLen), sizeof(uint32_t));

    uint32_t rsaPrimes1LenFieldValue = 0;
    memMove(&rsaPrimes1LenFieldValue, inSt + pkeyStOffset + offsetof(KEYISO_RSA_PKEY_ST, rsaPrimes1Len), sizeof(uint32_t));

    uint32_t rsaPrimes2LenFieldValue = 0;
    memMove(&rsaPrimes2LenFieldValue, inSt + pkeyStOffset + offsetof(KEYISO_RSA_PKEY_ST, rsaPrimes2Len), sizeof(uint32_t));

    // Calculating the size of the dynamic array
    uint32_t rsaImportInStDynamicArraySize = 0;
    if (!KEYISO_ADD_OVERFLOW(rsaModulusLenFieldValue, rsaPublicExpLenFieldValue, &rsaImportInStDynamicArraySize) &&
        !KEYISO_ADD_OVERFLOW(rsaImportInStDynamicArraySize, rsaPrimes1LenFieldValue, &rsaImportInStDynamicArraySize) &&
        !KEYISO_ADD_OVERFLOW(rsaImportInStDynamicArraySize, rsaPrimes2LenFieldValue, &rsaImportInStDynamicArraySize)) {            
        // Calculating the size of the in structure (where as the dynamic array length == rsaImportInStDynamicArraySize)
        return GET_DYNAMIC_STRUCT_SIZE(KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST, rsaImportInStDynamicArraySize);
    }

    return 0;
}

static size_t _import_ec_private_key_msg_in_length(const uint8_t *inSt, const PFN_mem_move memMove)
{
    // getting the offset of the inner structure encKeySt inside the KEYISO_OPEN_PRIV_KEY_IN_ST 
    size_t pkeyStOffset = offsetof(KEYISO_IMPORT_EC_PRIV_KEY_IN_ST, pkeySt);

    // Getting the values (from the inSt) of the following fields ecPubXLen, ecPubYLen, ecPrivKeyLen
    uint32_t ecPubXLenFieldValue = 0;
    memMove(&ecPubXLenFieldValue, inSt + pkeyStOffset + offsetof(KEYISO_EC_PKEY_ST, ecPubXLen), sizeof(uint32_t));

    uint32_t ecPubYLenFieldValue = 0;
    memMove(&ecPubYLenFieldValue, inSt + pkeyStOffset + offsetof(KEYISO_EC_PKEY_ST, ecPubYLen), sizeof(uint32_t));

    uint32_t ecPrivKeyLenFieldValue = 0;
    memMove(&ecPrivKeyLenFieldValue, inSt + pkeyStOffset + offsetof(KEYISO_EC_PKEY_ST, ecPrivKeyLen), sizeof(uint32_t));

    // Calculating the size of the dynamic array
    uint32_t ecImportInStDynamicArraySize = 0;
    if (!KEYISO_ADD_OVERFLOW(ecPubXLenFieldValue, ecPubYLenFieldValue, &ecImportInStDynamicArraySize) &&
        !KEYISO_ADD_OVERFLOW(ecImportInStDynamicArraySize, ecPrivKeyLenFieldValue, &ecImportInStDynamicArraySize)) {
        // Calculating the size of the in structure (where as the dynamic array length == ecImportInStDynamicArraySize)
        return GET_DYNAMIC_STRUCT_SIZE(KEYISO_IMPORT_EC_PRIV_KEY_IN_ST, ecImportInStDynamicArraySize);
    }

    return 0;
}

static size_t _generate_rsa_key_pair_msg_in_length(const uint8_t *inSt, const PFN_mem_move memMove)
{
    (void)inSt;
    (void)memMove;

    // As there is not any dynamic array in this structure
    return sizeof(KEYISO_GEN_RSA_KEY_PAIR_IN_ST);    
}

static size_t _symmetric_key_enc_dec_msg_in_length(const uint8_t *inSt, const PFN_mem_move memMove)
{
    // Getting the values (from the inSt) of the following fields: encryptedKeyLen, fromBytesLen
    uint32_t encryptedKeyLenFieldValue = 0;
    memMove(&encryptedKeyLenFieldValue, inSt + offsetof(KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST, encryptedKeyLen), sizeof(uint32_t));

    uint32_t fromBytesLenFieldValue = 0;
    memMove(&fromBytesLenFieldValue, inSt + offsetof(KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST, fromBytesLen), sizeof(uint32_t));

    // Calculating the size of the dynamic array
    uint32_t symEncDecInStDynamicArraySize = 0;
    if (!KEYISO_ADD_OVERFLOW(encryptedKeyLenFieldValue, fromBytesLenFieldValue, &symEncDecInStDynamicArraySize)) {
        // Calculating the size of the in structure (where as the dynamic array length == symEncDecInStDynamicArraySize)
        return GET_DYNAMIC_STRUCT_SIZE(KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST, symEncDecInStDynamicArraySize);
    }
    
    return 0;
}

size_t KeyIso_msg_in_length(int command, const uint8_t *inSt, size_t inLen, const PFN_mem_move memMove)
{   
    if (command < 0 || command >= IpcCommand_Max) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_SERVICE_TITLE, "", "Invalid command");
        return 0;
    }

    size_t minimal_length = inMsgMinStructSizes[command];
    if ( minimal_length == 0 || minimal_length > inLen) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_SERVICE_TITLE, "", "Invalid input length - lower bound");
        return 0;
    }
    
    size_t estimated_length = msgLengthFunctions[command](inSt, memMove);
    if (estimated_length != inLen) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_SERVICE_TITLE, "", "Invalid input length - upper bound");
        return 0;
    }
    return estimated_length;
}