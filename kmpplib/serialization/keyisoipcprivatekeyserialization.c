/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include "keyiso.h"
#include "keyisocommon.h"
#include "keyisolog.h"
#include "keyisoipccommands.h"
#include "keyisoipccommonserialize.h"
#include "keyisoutils.h"

/*
    Tags definitions 
*/

//Internal message tags
#define CBOR_PARAM_KEY_ID                         "keyId"
#define CBOR_PARAM_TYPE                           "type"
#define CBOR_PARAM_PADDING                        "padding"
#define CBOR_PARAM_DECRYPT                        "decrypt"
#define CBOR_PARAM_SIGNATURE_LEN                  "sigLen"
#define CBOR_PARAM_SIGNATURE_BYTES                "sigBytes"
#define CBOR_PARAM_DIGEST_LEN                     "digLen"
#define CBOR_PARAM_DIGEST_BYTES                   "digBytes"
#define CBOR_PARAM_FROM_LEN                       "fromLen"
#define CBOR_PARAM_LABEL_LEN                      "labelLen"
#define CBOR_PARAM_BYTES                          "bytes"                       
#define CBOR_PARAM_TO_LEN                         "toLen"
#define CBOR_PARAM_TO_BYTES                       "toBytes"
#define CBOR_PARAM_ALG_VER                        "algVersion"
#define CBOR_PARAM_SALT_LEN                       "saltLen"
#define CBOR_PARAM_IV_LEN                         "ivLen"
#define CBOR_PARAM_HMAC_LEN                       "hmacLen"
#define CBOR_PARAM_ENCRYPTED_KEY_LEN              "encKeyLen"
#define CBOR_PARAM_ENC_KEY_BYTES                  "encKeyBytes"
#define CBOR_PARAM_ENC_KEY                        "encKey"
#define CBOR_PARAM_KEY_LEN                        "keyBytesLen"
#define CBOR_PARAM_KEY_BYTES                      "keyBytes"
#define CBOR_PARAM_PKEY                           "pkey"
#define CBOR_PARAM_PUBLIC_KEY_LEN                 "publicKeyLen"
#define CBOR_PARAM_ENCRYPTED_KEY_PAIR_BYTES       "encKeyBytes"
#define CBOR_PARAM_SECRET_SALT                    "secretSalt"
#define CBOR_PARAM_KEY_USAGE                      "keyUsage"
#define CBOR_PARAM_KEY_HEADER                     "keyHeader"
#define CBOR_PARAM_MAGIC                          "magic"
#define CBOR_PARAM_KEY_VERSION                    "keyVersion"
#define CBOR_PARAM_RSA_ENC_DEC_WITH_KEY_BYTES     "rsaEncDecWithKeyBytes"
#define CBOR_PARAM_RSA_ENC_DEC_WITH_KEY_BYTES_LEN "rsaEncDecWithKeyBytesLen"
#define CBOR_PARAM_ECC_SIGN_WITH_KEY_BYTES        "eccSignWithKeyBytes"
#define CBOR_PARAM_ECC_SIGN_WITH_KEY_BYTES_LEN    "eccSignWithKeyBytesLen"

// RSA  key tags:
#define CBOR_PARAM_RSA_MODULUS_LEN                "n_len"
#define CBOR_PARAM_RSA_PUBLIC_EXP_LEN             "e_len"
#define CBOR_PARAM_RSA_PRIME1_LEN                 "p_len"
#define CBOR_PARAM_RSA_PRIME2_LEN                 "q_len"
#define CBOR_PARAM_RSA_KEY_BYTES                  "rsaKeyBytes"
#define CBOR_PARAM_RSA_BITS                       "rsaBits"

// EC key tags:
#define CBOR_PARAM_EC_CRV                         "crv"
#define CBOR_PARAM_EC_PUB_X_LEN                   "x_len"
#define CBOR_PARAM_EC_PUB_Y_LEN                   "y_len"
#define CBOR_PARAM_EC_PRIVATE_KEY_LEN             "d_len"
#define CBOR_PARAM_EC_KEY_BYTES                   "ecKeyBytes"
#define CBOR_PARAM_EC_CRV_NID                     "curveNID"

// Symmetric key tags:
#define CBOR_PARAM_SYMMETRIC_KEY_TYPE             "symKeyType"
#define CBOR_PARAM_SYMMETRIC_KEY_LEN              "keyLen"
#define CBOR_PARAM_SYMMETRIC_KEY_BYTES            "keyBytes"
#define CBOR_PARAM_SYMMETRIC_ENC_KEY_LEN          "encKeyLen"
#define CBOR_PARAM_SYMMETRIC_IMPORT_KEY_ID       "importKeyId"
#define CBOR_PARAM_SYMMETRIC_ENC_KEY_BYTES        "encKeyBytes"
#define CBOR_PARAM_SYMMETRIC_DECRYPT              "decrypt"
#define CBOR_PARAM_SYMMETRIC_FROM_BYTES_LEN       "fromBytesLen"
#define CBOR_PARAM_SYMMETRIC_BYTES_LEN            "bytesLen"
#define CBOR_PARAM_SYMMETRIC_TO_BYTES             "toBytes"

/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    Common private key serialization encode/decode 
*/

SerializeStatus _encode_enc_priv_key(CborEncoder* encKeyMapEncoder,  uint32_t algVersion, uint32_t saltLen, uint32_t ivLen, uint32_t hmacLen, uint32_t encKeyLen, size_t *totalBuflen)
{
    CborError cborErr = CborNoError;

    size_t encKeybytesLen = KeyIso_get_enc_key_bytes_len(NULL, saltLen,ivLen, hmacLen, encKeyLen);
    if (encKeybytesLen > UINT32_MAX) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "Invalid input");
        return SerializeStatus_InvalidFormat;
    }
    *totalBuflen = encKeybytesLen;

    // Encode algVersion  
    CBOR_OPERATION(cbor_encode_text_stringz(encKeyMapEncoder, CBOR_PARAM_ALG_VER))
    CBOR_OPERATION(cbor_encode_uint(encKeyMapEncoder, (uint64_t)algVersion))

    // Encode saltLen  
    CBOR_OPERATION(cbor_encode_text_stringz(encKeyMapEncoder, CBOR_PARAM_SALT_LEN))
    CBOR_OPERATION(cbor_encode_uint(encKeyMapEncoder, (uint64_t)saltLen))

    // Encode ivLen  
    CBOR_OPERATION(cbor_encode_text_stringz(encKeyMapEncoder, CBOR_PARAM_IV_LEN))
    CBOR_OPERATION(cbor_encode_uint(encKeyMapEncoder, (uint64_t)ivLen))
    
    // Encode hmacLen  
    CBOR_OPERATION(cbor_encode_text_stringz(encKeyMapEncoder, CBOR_PARAM_HMAC_LEN))
    CBOR_OPERATION(cbor_encode_uint(encKeyMapEncoder, (uint64_t)hmacLen))

    // Encode encKeyLen  
    CBOR_OPERATION(cbor_encode_text_stringz(encKeyMapEncoder, CBOR_PARAM_ENCRYPTED_KEY_LEN))
    CBOR_OPERATION(cbor_encode_uint(encKeyMapEncoder, (uint64_t)encKeyLen))

    return SerializeStatus_Success;  
}

SerializeStatus _encode_enc_priv_key_st(CborEncoder *mapEncoder, KEYISO_ENCRYPTED_PRIV_KEY_ST *encKeySt) 
{
    CborError cborErr = CborNoError;
    CborEncoder encKeyMapEncoder = { 0 };

    CBOR_OPERATION(cbor_encode_text_stringz(mapEncoder, CBOR_PARAM_ENC_KEY))

    CBOR_OPERATION(cbor_encoder_create_map(mapEncoder, &encKeyMapEncoder, NUM_OF_ENC_KEY_ELEMENTS))

    size_t totalBuflen = 0; 
    CBOR_CHECK_STATUS(_encode_enc_priv_key(&encKeyMapEncoder, encKeySt->algVersion, encKeySt->saltLen, encKeySt->ivLen, encKeySt->hmacLen, encKeySt->encKeyLen, &totalBuflen))
    
    // Encode encryptedKeyBytes  
    CBOR_OPERATION(cbor_encode_text_stringz(&encKeyMapEncoder, CBOR_PARAM_ENC_KEY_BYTES))
    CBOR_OPERATION(cbor_encode_byte_string(&encKeyMapEncoder, encKeySt->encryptedKeyBytes, totalBuflen))

    CBOR_OPERATION(cbor_encoder_close_container(mapEncoder, &encKeyMapEncoder))
     
    return SerializeStatus_Success;
}

SerializeStatus _decode_enc_priv_key(CborValue *encKeyMap, uint32_t *algVersion, uint32_t *saltLen, uint32_t *ivLen, uint32_t *hmacLen, uint32_t *encKeyLen)
{
    // Decode algVersion  
    CBOR_CHECK_STATUS(validate_tag(encKeyMap, CBOR_PARAM_ALG_VER))
    CBOR_CHECK_STATUS(get_uint32_val(encKeyMap, algVersion))

    // Decode saltLen  
    CBOR_CHECK_STATUS(validate_tag(encKeyMap, CBOR_PARAM_SALT_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(encKeyMap, saltLen))
    
    // Decode ivLen  
    CBOR_CHECK_STATUS(validate_tag(encKeyMap, CBOR_PARAM_IV_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(encKeyMap, ivLen))
    
    // Decode hmacLen  
    CBOR_CHECK_STATUS(validate_tag(encKeyMap, CBOR_PARAM_HMAC_LEN))        
    CBOR_CHECK_STATUS(get_uint32_val(encKeyMap, hmacLen))
     
    // Decode encKeyLen            
    CBOR_CHECK_STATUS(validate_tag(encKeyMap, CBOR_PARAM_ENCRYPTED_KEY_LEN))        
    CBOR_CHECK_STATUS(get_uint32_val(encKeyMap, encKeyLen))

    return SerializeStatus_Success;  
}

SerializeStatus _decode_enc_priv_key_st(CborValue *map, KEYISO_ENCRYPTED_PRIV_KEY_ST* encKeySt)
{
    CborError cborErr = CborNoError;
    CborValue encKeyMap = { 0 };
    
    CBOR_CHECK_STATUS(validate_tag(map, CBOR_PARAM_ENC_KEY))
    
    // Enter the header map
    CBOR_OPERATION(cbor_value_enter_container(map, &encKeyMap))

    CBOR_CHECK_STATUS(_decode_enc_priv_key(&encKeyMap, &encKeySt->algVersion, &encKeySt->saltLen, &encKeySt->ivLen, &encKeySt->hmacLen, &encKeySt->encKeyLen))

    size_t totalBuflen = KeyIso_get_enc_key_bytes_len(NULL, encKeySt->saltLen, encKeySt->ivLen, encKeySt->hmacLen, encKeySt->encKeyLen);
    if (totalBuflen == 0 || totalBuflen > UINT32_MAX) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "Invalid input");
        return SerializeStatus_InvalidFormat;
    }

    // Decode encryptedKeyBytes  (totalLen , encryptedKeyBytes)
    CBOR_CHECK_STATUS(decode_string_ptr_by_len(&encKeyMap, totalBuflen, CBOR_PARAM_ENC_KEY_BYTES, encKeySt->encryptedKeyBytes))

    CBOR_OPERATION(cbor_value_leave_container(map, &encKeyMap)) //Updates map to point to the next element after the container.  

    return SerializeStatus_Success;
}

static bool _sum_enc_priv_key_len(uint32_t saltLen, uint32_t ivLen, uint32_t hmacLen, uint32_t encKeyLen, uint32_t* paramSumRes)
{
     bool isSumResValid = false;        

    if (saltLen < 0 || ivLen < 0 || hmacLen < 0 || encKeyLen < 0) {
        isSumResValid = false; // In case of invalid input

    } else if (saltLen > UINT32_MAX || ivLen > UINT32_MAX || hmacLen > UINT32_MAX || encKeyLen > UINT32_MAX) {
        isSumResValid = false; // In case of invalid input
    }
    else {        
        // After verifying the input boundaries, we can safely cast the values to uint32_t    
        if (!KEYISO_ADD_OVERFLOW(saltLen, ivLen, paramSumRes) &&
            !KEYISO_ADD_OVERFLOW(*paramSumRes, hmacLen, paramSumRes) &&
            !KEYISO_ADD_OVERFLOW(*paramSumRes, encKeyLen, paramSumRes)) {
            isSumResValid = true; // The sum of all parameters is valid
        } else {        
            isSumResValid = false; // In case of overflow 
        }  
    }
    return isSumResValid;
}

static bool _get_len_nested_enc_priv_key(const uint8_t *encodedSt, size_t encodedLen, uint32_t* paramSumRes)
{
    int64_t saltLen = get_dynamic_len_nested(encodedSt, encodedLen, CBOR_PARAM_SALT_LEN, CBOR_PARAM_ENC_KEY);
    int64_t ivLen = get_dynamic_len_nested(encodedSt, encodedLen, CBOR_PARAM_IV_LEN, CBOR_PARAM_ENC_KEY);
    int64_t hmacLen = get_dynamic_len_nested(encodedSt, encodedLen, CBOR_PARAM_HMAC_LEN, CBOR_PARAM_ENC_KEY);
    int64_t encKeyLen = get_dynamic_len_nested(encodedSt, encodedLen, CBOR_PARAM_ENCRYPTED_KEY_LEN, CBOR_PARAM_ENC_KEY);
    return _sum_enc_priv_key_len(saltLen, ivLen, hmacLen, encKeyLen, paramSumRes);
}

static bool _get_len_enc_priv_key(const uint8_t *encodedSt, size_t encodedLen, uint32_t* paramSumRes)
{
    int64_t saltLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_SALT_LEN);
    int64_t ivLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_IV_LEN);
    int64_t hmacLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_HMAC_LEN);
    int64_t encKeyLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_ENCRYPTED_KEY_LEN);
    return _sum_enc_priv_key_len(saltLen, ivLen, hmacLen, encKeyLen, paramSumRes);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    PfxClose In 
*/

static SerializeStatus _encode_pfx_close_in_st(KEYISO_CLOSE_KEY_IN_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
   
    // Encode headerSt
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_CLOSE_KEY_IN_ELEMENTS))
    CBOR_CHECK_STATUS(encode_header_in_st(&mapEncoder, &stToEncode->headerSt))    

    // Encode keyId
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_KEY_ID))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, stToEncode->keyId))

    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))
    
    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;   
}


static SerializeStatus _decode_pfx_close_in_st(const uint8_t *buffer, size_t bufferSize, KEYISO_CLOSE_KEY_IN_ST *decodedSt)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    //Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "invalid format");
        return SerializeStatus_InvalidFormat;
    }

    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_in_st(&map, &decodedSt->headerSt, IpcCommand_CloseKey))

    //keyId
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_KEY_ID))
    CBOR_OPERATION(cbor_value_get_uint64(&map, &(decodedSt->keyId)))
    CBOR_OPERATION(cbor_value_advance_fixed(&map))

    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}


uint8_t* KeyIso_serialize_close_key_in(const void *stToEncode, size_t *encodedLen)
{
    size_t allocatesSize = sizeof(KEYISO_CLOSE_KEY_IN_ST) * SIZE_MULTIPLE_TO_ALLOC_IN_STRUCT;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
    int8_t counter = 0;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_pfx_close_in_st((KEYISO_CLOSE_KEY_IN_ST*)stToEncode, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {            
            if (status == SerializeStatus_OutOfMemory) {
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_ENGINE_TITLE, "realloc", "retry", "%ld bytes", allocatesSize);     
                allocatesSize *= REALLOC_MULTIPLE;       
                buffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "Serialize error");
                KeyIso_free(buffer);
                return NULL;
            }
        } else {
            return buffer;
        }
    } 
    KeyIso_free(buffer);
    return NULL;
}

int KeyIso_deserialize_close_key_in(const uint8_t *encodedSt, size_t encodedLen, void* decodedSt)
{
    SerializeStatus status = _decode_pfx_close_in_st(encodedSt, encodedLen, (KEYISO_CLOSE_KEY_IN_ST*)decodedSt);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}

size_t KeyIso_get_len_close_key_in(const uint8_t *encodedSt, size_t encodedLen)
{
    return sizeof(KEYISO_CLOSE_KEY_IN_ST);
}


/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    PfxClose Out 
*/

static SerializeStatus _encode_pfx_close_out_st(KEYISO_CLOSE_KEY_OUT_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
   
    // Encode headerSt
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_CLOSE_KEY_OUT_ELEMENTS))
    CBOR_CHECK_STATUS(encode_header_out_st(&mapEncoder, &stToEncode->headerSt))    

    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))
    
    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;   
}


static SerializeStatus _decode_pfx_close_out_st(const uint8_t *buffer, size_t bufferSize, KEYISO_CLOSE_KEY_OUT_ST *decodedSt)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "invalid format");
        return SerializeStatus_InvalidFormat;
    }

    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_out_st(&map, &decodedSt->headerSt, IpcCommand_CloseKey))

    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}


uint8_t* KeyIso_serialize_close_key_out(const void *stToEncode, size_t *encodedLen)
{
    size_t allocatesSize = sizeof(KEYISO_CLOSE_KEY_OUT_ST) * SIZE_MULTIPLE_TO_ALLOC_OUT_STRUCT;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
    int8_t counter = 0;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_pfx_close_out_st((KEYISO_CLOSE_KEY_OUT_ST*)stToEncode, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {                
                allocatesSize *= REALLOC_MULTIPLE;  
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_ENGINE_TITLE, "realloc", "retry", "%ld bytes", allocatesSize);     
                buffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "Serialize error");
                KeyIso_free(buffer);
                return NULL;
            }
        } else {
            return buffer;
        }
    } 
    KeyIso_free(buffer);
    return NULL;
}


int KeyIso_deserialize_close_key_out(const uint8_t *encodedSt, size_t encodedLen, void* decodedSt)
{
    SerializeStatus status = _decode_pfx_close_out_st(encodedSt, encodedLen, (KEYISO_CLOSE_KEY_OUT_ST*)decodedSt);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}


/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    ECDSA sign In 
*/
static SerializeStatus _ecode_ecdsa_sign_op_params_to_map(CborEncoder* mapEncoderPtr, int32_t type, uint32_t sigLen, int32_t digestLen)
{
    CborError   cborErr = CborNoError;
    // Encode type
    CBOR_OPERATION(cbor_encode_text_stringz(mapEncoderPtr, CBOR_PARAM_TYPE))
    CBOR_OPERATION(cbor_encode_int(mapEncoderPtr, (int64_t)type))

    // Encode siglen
    CBOR_OPERATION(cbor_encode_text_stringz(mapEncoderPtr, CBOR_PARAM_SIGNATURE_LEN))
    CBOR_OPERATION(cbor_encode_int(mapEncoderPtr, (int64_t)sigLen))

    // Encode digestLen
    CBOR_OPERATION(cbor_encode_text_stringz(mapEncoderPtr, CBOR_PARAM_DIGEST_LEN))
    CBOR_OPERATION(cbor_encode_int(mapEncoderPtr, (int64_t)digestLen))

    return SerializeStatus_Success;
}

static SerializeStatus _encode_ecdsa_sign_in_st(KEYISO_ECDSA_SIGN_IN_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
   
    // Encode headerSt
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_ECDSA_SIGN_IN_ELEMENTS))
    CBOR_CHECK_STATUS(encode_header_in_st(&mapEncoder, &stToEncode->headerSt))    

    // Encode keyId
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_KEY_ID))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, stToEncode->keyId))

    // Encode params
    CBOR_CHECK_STATUS(_ecode_ecdsa_sign_op_params_to_map(&mapEncoder, stToEncode->params.type, stToEncode->params.sigLen, stToEncode->params.digestLen))

    // Encode digestBytes
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_DIGEST_BYTES))  
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->params.digestBytes,stToEncode->params.digestLen))

    // Close the top-level map
    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))
    
    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;   
}

static SerializeStatus _decode_ecdsa_sign_op_params_to_map(CborValue *map, int32_t *outType, uint32_t *sigLen, int32_t *digestLen)
{
    // type
    CBOR_CHECK_STATUS(validate_tag(map, CBOR_PARAM_TYPE))
    CBOR_CHECK_STATUS(get_int32_val(map, outType))

    // sigLen
    CBOR_CHECK_STATUS(validate_tag(map, CBOR_PARAM_SIGNATURE_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(map, sigLen))

    // digestLen
    CBOR_CHECK_STATUS(validate_tag(map, CBOR_PARAM_DIGEST_LEN))
    CBOR_CHECK_STATUS(get_int32_val(map, digestLen))

    return SerializeStatus_Success;
}

static SerializeStatus _decode_ecdsa_sign_in_st(const uint8_t *buffer, size_t bufferSize, KEYISO_ECDSA_SIGN_IN_ST *decodedSt)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "invalid format");
        return SerializeStatus_InvalidFormat;
    }

    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_in_st(&map, &decodedSt->headerSt, IpcCommand_EcdsaSign))

    // keyId
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_KEY_ID))
    CBOR_OPERATION(cbor_value_get_uint64(&map, &(decodedSt->keyId)))
    CBOR_OPERATION(cbor_value_advance_fixed(&map))

    // Sign operation parameters
    CBOR_CHECK_STATUS(_decode_ecdsa_sign_op_params_to_map(&map, &decodedSt->params.type, &decodedSt->params.sigLen, &decodedSt->params.digestLen))

    // digestLen , digestBytes
    CBOR_CHECK_STATUS(decode_string_ptr_by_len(&map, decodedSt->params.digestLen, CBOR_PARAM_DIGEST_BYTES, decodedSt->params.digestBytes))
    
    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}


uint8_t* KeyIso_serialize_ecdsa_sign_in(const void *stToEncode, size_t *encodedLen)
{
    KEYISO_ECDSA_SIGN_IN_ST *st = (KEYISO_ECDSA_SIGN_IN_ST*)stToEncode;
    size_t allocatesSize = (sizeof(*st) * SIZE_MULTIPLE_TO_ALLOC_IN_STRUCT) + st->params.digestLen;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
    int8_t counter = 0;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_ecdsa_sign_in_st((KEYISO_ECDSA_SIGN_IN_ST*)stToEncode, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {                
                allocatesSize *= REALLOC_MULTIPLE;  
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_ENGINE_TITLE, "realloc", "retry", "%ld bytes", allocatesSize);     
                buffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "Serialize error");
                KeyIso_free(buffer);
                return NULL;
            }
        } else {
            return buffer;
        }
    } 
    KeyIso_free(buffer);
    return NULL;
}


size_t KeyIso_get_len_ecdsa_sign_in(const uint8_t *encodedSt, size_t encodedLen)
{
    int64_t dynamicSize = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_DIGEST_LEN);

    // digestLen field boundaries check
    if (dynamicSize < 0 || dynamicSize > INT32_MAX) {
        return 0;
    }

    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_ECDSA_SIGN_IN_ST, dynamicSize);
}


int KeyIso_deserialize_ecdsa_sign_in(const uint8_t *encodedSt, size_t encodedLen, void* decodedSt)
{  
    SerializeStatus status = _decode_ecdsa_sign_in_st(encodedSt, encodedLen, (KEYISO_ECDSA_SIGN_IN_ST*)decodedSt);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    ECDSA sign Out 
*/
static SerializeStatus _encode_ecdsa_sign_out_st(KEYISO_ECDSA_SIGN_OUT_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
   
    // Encode headerSt
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_ECDSA_SIGN_OUT_ELEMENTS))
    CBOR_CHECK_STATUS(encode_header_out_st(&mapEncoder, &stToEncode->headerSt))    

    // Encode bytesLen
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SIGNATURE_LEN))
    CBOR_OPERATION(cbor_encode_int(&mapEncoder, (int64_t)stToEncode->bytesLen))

    // Encode signatureBytes
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SIGNATURE_BYTES))    
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->signatureBytes, stToEncode->bytesLen))

    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))
    
    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;   
}


static SerializeStatus _decode_ecdsa_sign_out_st(const uint8_t *buffer, size_t bufferSize, KEYISO_ECDSA_SIGN_OUT_ST *decodedSt)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "SerializeStatus_InvalidFormat");
        return SerializeStatus_InvalidFormat;
    }

    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_out_st(&map, &decodedSt->headerSt, IpcCommand_EcdsaSign))

   // bytesLen , signatureBytes
    CBOR_CHECK_STATUS(decode_string_ptr(&map, CBOR_PARAM_SIGNATURE_LEN, &decodedSt->bytesLen, CBOR_PARAM_SIGNATURE_BYTES, decodedSt->signatureBytes))
  
    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}


uint8_t* KeyIso_serialize_ecdsa_sign_out(const void *stToEncode, size_t *encodedLen)
{
    size_t allocatesSize = sizeof(KEYISO_ECDSA_SIGN_OUT_ST) * SIZE_MULTIPLE_TO_ALLOC_OUT_STRUCT + ((KEYISO_ECDSA_SIGN_OUT_ST*)stToEncode)->bytesLen;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
    int8_t counter = 0;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_ecdsa_sign_out_st((KEYISO_ECDSA_SIGN_OUT_ST*)stToEncode, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {                
                allocatesSize *= REALLOC_MULTIPLE;  
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_ENGINE_TITLE, "realloc", "retry", "%ld bytes", allocatesSize);     
                buffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "Serialize error");
                KeyIso_free(buffer);
                return NULL;
            }
        } else {
            return buffer;
        }
    } 
    KeyIso_free(buffer);
    return NULL;
}


size_t KeyIso_get_len_ecdsa_sign_out(const uint8_t *encodedSt, size_t encodedLen)
{
    int64_t dynamicSize = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_SIGNATURE_LEN);

    // bytesLen field boundaries check
    if (dynamicSize < 0 || dynamicSize > INT32_MAX) { 
        return 0;
    }
    
    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_ECDSA_SIGN_OUT_ST, dynamicSize);
}


int KeyIso_deserialize_ecdsa_sign_out(const uint8_t *encodedSt, size_t encodedLen, void* decodedSt)
{  
    SerializeStatus status = _decode_ecdsa_sign_out_st(encodedSt, encodedLen, (KEYISO_ECDSA_SIGN_OUT_ST*)decodedSt);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    RSA PRIVATE ENC DEC WITH ENCRYPTED KEY ATTACHED In 
*/
/////////////////////////////////////////////////////////////////////////////////////////////////////
static SerializeStatus _encode_ecdsa_sign_with_attached_key_in_st(KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_IN_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    //NUM_OF_ECDSA_SIGN_WITH_ATTACHED_KEY_IN_ELEMENTS
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);

    // Encode headerSt  
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_ECDSA_SIGN_WITH_ATTACHED_KEY_IN_ELEMENTS))
    CBOR_CHECK_STATUS(encode_header_in_st(&mapEncoder, &stToEncode->headerSt))

    // Encode secretSalt  
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SECRET_SALT))
    CBOR_OPERATION(cbor_encode_text_string(&mapEncoder, (char*)stToEncode->secretSalt, sizeof(stToEncode->secretSalt)))

    // Encode encrypted key
    size_t encKeyBuffLen = 0;
    CBOR_CHECK_STATUS(_encode_enc_priv_key(&mapEncoder, stToEncode->algVersion, stToEncode->saltLen, stToEncode->ivLen, stToEncode->hmacLen, stToEncode->encKeyLen, &encKeyBuffLen))

    // Encode sign operation parameters
    CBOR_CHECK_STATUS(_ecode_ecdsa_sign_op_params_to_map(&mapEncoder, stToEncode->type, stToEncode->sigLen, stToEncode->digestLen))

    // Encode the bytes
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_ECC_SIGN_WITH_KEY_BYTES))
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->bytes, encKeyBuffLen + stToEncode->digestLen))

    // Close the top-level map
    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))
    
    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;
}

static SerializeStatus _decode_ecdsa_sign_with_attached_key_in_st(const uint8_t *buffer, size_t bufferSize, KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_IN_ST *decodedSt)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "SerializeStatus_InvalidFormat");
        return SerializeStatus_InvalidFormat;
    }
    
    // Enter the header map
    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_in_st(&map, &decodedSt->headerSt, IpcCommand_EcdsaSignWithAttachedKey))

    // Decode secretSalt  
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_SECRET_SALT))
    size_t size;
    CBOR_OPERATION(cbor_value_get_string_length(&map, &size))
    CBOR_OPERATION(cbor_value_copy_text_string(&map, (char*)decodedSt->secretSalt, &size, &map))

    // Decode the encrypted key
    uint32_t encryptedKeyLen = 0;
     if (!_get_len_enc_priv_key(buffer, bufferSize, &encryptedKeyLen)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid format", "_get_len_enc_priv_key Failed");
        return SerializeStatus_InvalidFormat;
    }

    CBOR_CHECK_STATUS(_decode_enc_priv_key(&map, &decodedSt->algVersion, &decodedSt->saltLen, &decodedSt->ivLen, &decodedSt->hmacLen, &decodedSt->encKeyLen))
    
    CBOR_CHECK_STATUS(_decode_ecdsa_sign_op_params_to_map(&map, &decodedSt->type, &decodedSt->sigLen, &decodedSt->digestLen))

    uint32_t totalBuflen = 0;
    if (KEYISO_ADD_OVERFLOW(encryptedKeyLen, decodedSt->digestLen, &totalBuflen)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid format", "Invalid total buffer length");
        return SerializeStatus_InvalidFormat;
    }

    // Decode bytes
    CBOR_CHECK_STATUS(decode_string_ptr_by_len(&map, totalBuflen, CBOR_PARAM_ECC_SIGN_WITH_KEY_BYTES, decodedSt->bytes))

    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}

uint8_t* KeyIso_serialize_ecdsa_sign_with_attached_key_in(const void *stToEncode, size_t *encodedLen)
{
    KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_IN_ST* inSt = (KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_IN_ST*)stToEncode;
    size_t dynamicSize = KeyIso_get_ecdsa_sign_with_attached_key_in_dynamic_bytes_len(NULL, inSt->saltLen, inSt->ivLen, inSt->hmacLen, inSt->encKeyLen, inSt->digestLen);
    if (dynamicSize > UINT32_MAX) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid input", "KeyIso_get_ecdsa_sign_with_attached_key_in_dynamic_bytes_len Failed");
        return NULL;
    }
    size_t allocatesSize =  (sizeof(*inSt) * SIZE_MULTIPLE_TO_ALLOC_IN_STRUCT) + dynamicSize;

    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
    int8_t counter = 0;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_ecdsa_sign_with_attached_key_in_st(inSt, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {                
                allocatesSize *= REALLOC_MULTIPLE;  
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_ENGINE_TITLE, "realloc", "retry", "%ld bytes", allocatesSize);     
                buffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "Serialize error");
                KeyIso_free(buffer);
                return NULL;
            }
        } else {
            return buffer;
        }
    } 
    KeyIso_free(buffer);
    return NULL;
    
}

int KeyIso_deserialize_ecdsa_sign_with_attached_key_in(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt)
{
    SerializeStatus status = _decode_ecdsa_sign_with_attached_key_in_st(encodedSt, encodedLen, (KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_IN_ST*)decodedSt);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}

size_t KeyIso_get_len_ecdsa_sign_with_attached_key_in(const uint8_t *encodedSt, size_t encodedLen)
{
    uint32_t encryptedKeySize = 0;
    size_t dynamicSize = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_DIGEST_LEN); // Digest buffer length
    if (dynamicSize > UINT32_MAX) {
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid encrypted key size", "Failed", "size: %ld", dynamicSize);
        return SerializeStatus_InvalidFormat;
    }

    // Encrypted key length
    if (!_get_len_enc_priv_key(encodedSt, encodedLen, &encryptedKeySize)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ECDSA_PKEY_SIGN_TITLE, "Invalid format", "_get_len_enc_priv_key Failed");
        return 0;
    }

    // Digest and encrypted key dynamic size
    if (KEYISO_ADD_OVERFLOW(dynamicSize, encryptedKeySize, &dynamicSize)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ECDSA_PKEY_SIGN_TITLE, "Invalid format", "Invalid dynamic size");
        return 0;
    }

    // Dynamic size boundaries check
    if (dynamicSize > UINT32_MAX) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ECDSA_PKEY_SIGN_TITLE, "Invalid format", "Invalid dynamic size");
        return 0;
    }

    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_IN_ST, dynamicSize);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    RSA PRIVATE ENC DEC WITH ENCRYPTED KEY ATTACHED Out 
*/
static SerializeStatus _encode_ecdsa_sign_with_attached_key_out_st(KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_OUT_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
   
    // Encode headerSt
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_ECDSA_SIGN_WITH_ATTACHED_KEY_OUT_ELEMENTS))
    CBOR_CHECK_STATUS(encode_header_out_st(&mapEncoder, &stToEncode->headerSt))    

    // Encode keyid
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_KEY_ID))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, stToEncode->keyId));


    // Encode bytesLen
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SIGNATURE_LEN))
    CBOR_OPERATION(cbor_encode_int(&mapEncoder, (int64_t)stToEncode->bytesLen))

    // Encode signatureBytes
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SIGNATURE_BYTES))    
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->signatureBytes, stToEncode->bytesLen))

    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))
    
    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;   
}


static SerializeStatus _decode_ecdsa_sign_with_attached_key_out_st(const uint8_t *buffer, size_t bufferSize, KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_OUT_ST *decodedSt)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "SerializeStatus_InvalidFormat");
        return SerializeStatus_InvalidFormat;
    }

    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_out_st(&map, &decodedSt->headerSt, IpcCommand_EcdsaSignWithAttachedKey))

    // keyId
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_KEY_ID))
    CBOR_OPERATION(cbor_value_get_uint64(&map, &(decodedSt->keyId)))
    CBOR_OPERATION(cbor_value_advance_fixed(&map))

   // bytesLen , signatureBytes
    CBOR_CHECK_STATUS(decode_string_ptr(&map, CBOR_PARAM_SIGNATURE_LEN, &decodedSt->bytesLen, CBOR_PARAM_SIGNATURE_BYTES, decodedSt->signatureBytes))
  
    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}

uint8_t* KeyIso_serialize_ecdsa_sign_with_attached_key_out(const void *stToEncode, size_t *encodedLen)
{
    KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_OUT_ST *inSt = (KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_OUT_ST*)stToEncode;
    size_t allocatesSize = sizeof(*inSt) * SIZE_MULTIPLE_TO_ALLOC_OUT_STRUCT + inSt->bytesLen;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
    int8_t counter = 0;
    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_ecdsa_sign_with_attached_key_out_st(inSt, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {                
                allocatesSize *= REALLOC_MULTIPLE;  
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_ENGINE_TITLE, "realloc", "retry", "%ld bytes", allocatesSize);     
                buffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "Serialize error");
                KeyIso_free(buffer);
                return NULL;
            }
        } else {
            return buffer;
        }
    } 
    KeyIso_free(buffer);
    return NULL;
}

int KeyIso_deserialize_ecdsa_sign_with_attached_key_out(const uint8_t *encodedSt, size_t encodedLen, void *decodedSt)
{
    SerializeStatus status = _decode_ecdsa_sign_with_attached_key_out_st(encodedSt, encodedLen, (KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_OUT_ST*)decodedSt);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}

size_t KeyIso_get_len_ecdsa_sign_with_attached_key_out(const uint8_t *encodedSt, size_t encodedLen)
{
    int64_t dynamicSize = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_SIGNATURE_LEN);

    // bytesLen field boundaries check
    if (dynamicSize < 0 || dynamicSize > INT32_MAX) { 
        return 0;
    }
    
    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_OUT_ST, dynamicSize);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    RSA PRIVATE ENC DEC In 
*/
static  SerializeStatus _encode_rsa_enc_dec_op_params_to_map(CborEncoder* mapEncoderPtr, uint32_t decrypt, uint32_t padding, uint32_t tlen, uint32_t fromBytesLen, uint32_t labelLen)
{
    CborError   cborErr = CborNoError;
    // Encode decrypt
    CBOR_OPERATION(cbor_encode_text_stringz(mapEncoderPtr, CBOR_PARAM_DECRYPT))
    CBOR_OPERATION(cbor_encode_int(mapEncoderPtr, (int64_t)decrypt))

    // Encode padding
    CBOR_OPERATION(cbor_encode_text_stringz(mapEncoderPtr, CBOR_PARAM_PADDING))
    CBOR_OPERATION(cbor_encode_int(mapEncoderPtr, (int64_t)padding))

    // Encode tlen
    CBOR_OPERATION(cbor_encode_text_stringz(mapEncoderPtr, CBOR_PARAM_TO_LEN))
    CBOR_OPERATION(cbor_encode_int(mapEncoderPtr, (int64_t)tlen))
    
    // Encode fromBytesLen
    CBOR_OPERATION(cbor_encode_text_stringz(mapEncoderPtr, CBOR_PARAM_FROM_LEN))
    CBOR_OPERATION(cbor_encode_int(mapEncoderPtr, (int64_t)fromBytesLen))

    // Encode labelLen
    CBOR_OPERATION(cbor_encode_text_stringz(mapEncoderPtr, CBOR_PARAM_LABEL_LEN))
    CBOR_OPERATION(cbor_encode_int(mapEncoderPtr, (int64_t)labelLen))

    return SerializeStatus_Success;   

}

static SerializeStatus _encode_rsa_enc_dec_in_st(KEYISO_RSA_PRIVATE_ENC_DEC_IN_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
   
    // Encode headerSt
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_RSA_PRIVATE_ENC_DEC_IN_ELEMENTS))
    CBOR_CHECK_STATUS(encode_header_in_st(&mapEncoder, &stToEncode->headerSt))    

    // Encode keyId
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_KEY_ID))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, stToEncode->keyId))

    CBOR_CHECK_STATUS(_encode_rsa_enc_dec_op_params_to_map(&mapEncoder, stToEncode->params.decrypt, stToEncode->params.padding, stToEncode->params.tlen, stToEncode->params.fromBytesLen, stToEncode->params.labelLen))

    // Encode fromBytes
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_BYTES))
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->params.bytes, KeyIso_get_rsa_enc_dec_params_dynamic_len(stToEncode->params.fromBytesLen, stToEncode->params.labelLen))) 

    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))
    
    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);  
    return SerializeStatus_Success;    
}

static SerializeStatus _decode_rsa_enc_dec_op_params_to_map(CborValue *map, int32_t *decrypt, int32_t *padding, int32_t *tlen, int32_t *fromBytesLen, int32_t *labelLen) 
{
    // decrypt
    CBOR_CHECK_STATUS(validate_tag(map, CBOR_PARAM_DECRYPT))
    CBOR_CHECK_STATUS(get_int32_val(map, decrypt))

    // padding
    CBOR_CHECK_STATUS(validate_tag(map, CBOR_PARAM_PADDING))
    CBOR_CHECK_STATUS(get_int32_val(map, padding))

    // toLen
    CBOR_CHECK_STATUS(validate_tag(map, CBOR_PARAM_TO_LEN))
    CBOR_CHECK_STATUS(get_int32_val(map, tlen))

    // fromBytesLen
    CBOR_CHECK_STATUS(validate_tag(map, CBOR_PARAM_FROM_LEN))
    CBOR_CHECK_STATUS(get_int32_val(map, fromBytesLen))

    // labelLen
    CBOR_CHECK_STATUS(validate_tag(map, CBOR_PARAM_LABEL_LEN))
    CBOR_CHECK_STATUS(get_int32_val(map, labelLen))
    
    return SerializeStatus_Success;
}

static SerializeStatus _decode_rsa_enc_dec_in_st(const uint8_t *buffer, size_t bufferSize, KEYISO_RSA_PRIVATE_ENC_DEC_IN_ST *decodedSt)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "invalid format");
        return SerializeStatus_InvalidFormat;
    }

    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_in_st(&map, &decodedSt->headerSt, IpcCommand_RsaPrivateEncryptDecrypt))

    // keyId
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_KEY_ID))
    CBOR_OPERATION(cbor_value_get_uint64(&map, &(decodedSt->keyId)))
    CBOR_OPERATION(cbor_value_advance_fixed(&map))

    // Encrypt/Decrypt operation parameters
    CBOR_CHECK_STATUS(_decode_rsa_enc_dec_op_params_to_map(&map, &decodedSt->params.decrypt, &decodedSt->params.padding, &decodedSt->params.tlen, &decodedSt->params.fromBytesLen, &decodedSt->params.labelLen))

    // fromBytesLen , fromBytes
    int32_t dynamicLen =  KeyIso_get_rsa_enc_dec_params_dynamic_len(decodedSt->params.fromBytesLen, decodedSt->params.labelLen);
    CBOR_CHECK_STATUS(decode_string_ptr_by_len(&map, dynamicLen, CBOR_PARAM_BYTES, decodedSt->params.bytes))
   
    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}
uint8_t* KeyIso_serialize_rsa_enc_dec_in(const void *stToEncode, size_t *encodedLen)
{
    KEYISO_RSA_PRIVATE_ENC_DEC_IN_ST* st = (KEYISO_RSA_PRIVATE_ENC_DEC_IN_ST*)stToEncode;
    size_t allocatesSize = (sizeof(*st) * SIZE_MULTIPLE_TO_ALLOC_IN_STRUCT) + KeyIso_get_rsa_enc_dec_params_dynamic_len(st->params.fromBytesLen, st->params.labelLen);
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
    int8_t counter = 0;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_rsa_enc_dec_in_st(st, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {                
                allocatesSize *= REALLOC_MULTIPLE;  
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_ENGINE_TITLE, "realloc", "retry", "%ld bytes", allocatesSize);     
                buffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "Serialize error");
                KeyIso_free(buffer);
                return NULL;
            }
        } else { //SerializeStatus_Success
            return buffer;
        }
    } 
    KeyIso_free(buffer);
    return NULL;
}

size_t KeyIso_get_len_rsa_enc_dec_in(const uint8_t *encodedSt, size_t encodedLen)
{
    int64_t fromLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_FROM_LEN);
    int64_t labelLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_LABEL_LEN);

    // fromBytesLen field boundaries check
    if (fromLen < 0 || fromLen > INT32_MAX || labelLen < 0 || labelLen > INT32_MAX) {
        return 0;
    }

    uint64_t dynamicSize = 0;
    if (KEYISO_ADD_OVERFLOW((uint32_t)fromLen, (uint32_t)labelLen, &dynamicSize)) {
        return 0;
    }
   
    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_RSA_PRIVATE_ENC_DEC_IN_ST, dynamicSize);
}


int KeyIso_deserialize_rsa_enc_dec_in(const uint8_t *encodedSt, size_t encodedLen, void* decodedSt)
{  
    SerializeStatus status = _decode_rsa_enc_dec_in_st(encodedSt, encodedLen, (KEYISO_RSA_PRIVATE_ENC_DEC_IN_ST*)decodedSt);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    RSA PRIVATE ENC DEC OUT
*/
static SerializeStatus _encode_rsa_enc_dec_out_st(KEYISO_RSA_PRIVATE_ENC_DEC_OUT_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
   
    // Encode headerSt
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_RSA_PRIVATE_ENC_DEC_OUT_ELEMENTS))
    CBOR_CHECK_STATUS(encode_header_out_st(&mapEncoder, &stToEncode->headerSt)) 

    // Encode toLen
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_TO_LEN))
    CBOR_OPERATION(cbor_encode_int(&mapEncoder, (int64_t)stToEncode->bytesLen))

    // Encode toBytes
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_TO_BYTES))    
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->toBytes, stToEncode->bytesLen))

    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))
    
    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;   
}


static SerializeStatus _decode_rsa_enc_dec_out_st(const uint8_t *buffer, size_t bufferSize, KEYISO_RSA_PRIVATE_ENC_DEC_OUT_ST *decodedSt)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value));

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "SerializeStatus_InvalidFormat");
        return SerializeStatus_InvalidFormat;
    }

    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_out_st(&map, &decodedSt->headerSt, IpcCommand_RsaPrivateEncryptDecrypt))

   // toLen , toBytes
    CBOR_CHECK_STATUS(decode_string_ptr(&map, CBOR_PARAM_TO_LEN, &decodedSt->bytesLen, CBOR_PARAM_TO_BYTES, decodedSt->toBytes))
  
    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}


uint8_t* KeyIso_serialize_rsa_enc_dec_out(const void *stToEncode, size_t *encodedLen)
{
    size_t allocatesSize = sizeof(KEYISO_RSA_PRIVATE_ENC_DEC_OUT_ST)* SIZE_MULTIPLE_TO_ALLOC_OUT_STRUCT + ((KEYISO_RSA_PRIVATE_ENC_DEC_OUT_ST*)stToEncode)->bytesLen;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
    int8_t counter = 0;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_rsa_enc_dec_out_st((KEYISO_RSA_PRIVATE_ENC_DEC_OUT_ST*)stToEncode, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {                
                allocatesSize *= REALLOC_MULTIPLE;  
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_ENGINE_TITLE, "realloc", "retry", "%ld bytes", allocatesSize);     
                buffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "Serialize error");
                KeyIso_free(buffer);
                return NULL;
            }
        } else {
            return buffer;
        }
    } 
    KeyIso_free(buffer);
    return NULL;
}


size_t KeyIso_get_len_rsa_enc_dec_out(const uint8_t *encodedSt, size_t encodedLen)
{
    int64_t dynamicSize = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_TO_LEN);

    // bytesLen field boundaries check
    if (dynamicSize < 0 || dynamicSize > INT32_MAX) {
        return 0;
    }

    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_RSA_PRIVATE_ENC_DEC_OUT_ST, dynamicSize);
}


int KeyIso_deserialize_rsa_enc_dec_out(const uint8_t *encodedSt, size_t encodedLen, void* decodedSt)
{  
    SerializeStatus status = _decode_rsa_enc_dec_out_st(encodedSt, encodedLen, (KEYISO_RSA_PRIVATE_ENC_DEC_OUT_ST*)decodedSt);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    RSA PRIVATE ENC DEC WITH ATTACHED KEY In
*/
/////////////////////////////////////////////////////////////////////////////////////////////////////

static SerializeStatus _encode_rsa_enc_dec_with_attached_key_st(KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_IN_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
   
    // Encode headerSt
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_IN_ELEMENTS))
    CBOR_CHECK_STATUS(encode_header_in_st(&mapEncoder, &stToEncode->headerSt))    

    // Encode secretSalt  
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SECRET_SALT))
    CBOR_OPERATION(cbor_encode_text_string(&mapEncoder, (char*)stToEncode->secretSalt, sizeof(stToEncode->secretSalt)))

    // Encode encrypted key
    size_t encKeyBuffLen = 0;
    CBOR_CHECK_STATUS(_encode_enc_priv_key(&mapEncoder, stToEncode->algVersion, stToEncode->saltLen, stToEncode->ivLen, stToEncode->hmacLen, stToEncode->encKeyLen, &encKeyBuffLen))

    // Encode encrypt/decrypt operation parameters
    CBOR_CHECK_STATUS(_encode_rsa_enc_dec_op_params_to_map(&mapEncoder, stToEncode->decrypt, stToEncode->padding, stToEncode->tlen, stToEncode->fromBytesLen, stToEncode->labelLen))

    //Encode encrypt/decrypt operation parameters
    size_t dynamicLen = KeyIso_get_rsa_enc_dec_with_attached_key_in_dynamic_bytes_len(NULL, stToEncode->saltLen, stToEncode->ivLen, stToEncode->hmacLen, stToEncode->encKeyLen, stToEncode->fromBytesLen, stToEncode->labelLen);
    if (dynamicLen == 0 || dynamicLen > UINT32_MAX) {
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid encrypted key size", "Failed", "size: %ld", dynamicLen);
    }

    // Encode the bytes
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_RSA_ENC_DEC_WITH_KEY_BYTES))
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->bytes, dynamicLen))

    // Close top-level container
    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))
    
    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);  
    return SerializeStatus_Success;    
}

static SerializeStatus _decode_rsa_enc_dec_with_attached_key_st(const uint8_t *buffer, size_t bufferSize, KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_IN_ST *decodedSt)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))
    const char* title = KEYISOP_ENGINE_TITLE;

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, title, NULL, "invalid format");
        return SerializeStatus_InvalidFormat;
    }
    // Enter the header map
    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_in_st(&map, &decodedSt->headerSt, IpcCommand_RsaPrivateEncryptDecryptWithAttachedKey))

    // Decode secretSalt  
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_SECRET_SALT))
    size_t size;
    CBOR_OPERATION(cbor_value_get_string_length(&map, &size))
    CBOR_OPERATION(cbor_value_copy_text_string(&map, (char*)decodedSt->secretSalt, &size, &map))

    // Decode the encrypted key
    uint32_t encryptedKeyLen = 0;
     if (!_get_len_enc_priv_key(buffer, bufferSize, &encryptedKeyLen)) {
        KEYISOP_trace_log_error(NULL, 0, title, "Invalid format", "_get_len_enc_priv_key Failed");
        return SerializeStatus_InvalidFormat;
    }

    // Decode private ket
    CBOR_CHECK_STATUS(_decode_enc_priv_key(&map, &decodedSt->algVersion, &decodedSt->saltLen, &decodedSt->ivLen, &decodedSt->hmacLen, &decodedSt->encKeyLen))

    // Decode encrypt/decrypt operation parameters
    CBOR_CHECK_STATUS(_decode_rsa_enc_dec_op_params_to_map(&map, &decodedSt->decrypt, &decodedSt->padding, &decodedSt->tlen, &decodedSt->fromBytesLen, &decodedSt->labelLen))

    size_t totalBuflen = KeyIso_get_rsa_enc_dec_with_attached_key_in_dynamic_bytes_len(NULL, decodedSt->saltLen, decodedSt->ivLen, decodedSt->hmacLen, decodedSt->encKeyLen, decodedSt->fromBytesLen, decodedSt->labelLen);
    if (totalBuflen == 0 || totalBuflen > UINT32_MAX) {
        KEYISOP_trace_log_error_para(NULL, 0, title, "Invalid encrypted key size", "Failed", "size: %ld", totalBuflen);
        return SerializeStatus_InvalidFormat;
    }

    // Get the bytes
    CBOR_CHECK_STATUS(decode_string_ptr_by_len(&map, totalBuflen, CBOR_PARAM_RSA_ENC_DEC_WITH_KEY_BYTES, decodedSt->bytes))
    return SerializeStatus_Success;
}

uint8_t* KeyIso_serialize_rsa_enc_dec_with_attached_key_in(const void *stToEncode, size_t *encodedLen)
{
    KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_IN_ST *st = (KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_IN_ST*)stToEncode;
    size_t dynamicSize = KeyIso_get_rsa_enc_dec_with_attached_key_in_dynamic_bytes_len(NULL, st->saltLen, st->ivLen, st->hmacLen, st->encKeyLen, st->fromBytesLen, st->labelLen);
    if (dynamicSize == 0 || dynamicSize > UINT32_MAX) {
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid encrypted key size", "Failed", "size: %ld", dynamicSize);
        return NULL;
    }
    size_t allocatesSize = ( sizeof(*st) * SIZE_MULTIPLE_TO_ALLOC_IN_STRUCT) + dynamicSize;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
    int8_t counter = 0;
    const char* title = KEYISOP_ENGINE_TITLE;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_rsa_enc_dec_with_attached_key_st(st, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {                
                allocatesSize *= REALLOC_MULTIPLE;  
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, title, "realloc", "retry", "%ld bytes", allocatesSize);     
                buffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error_para(NULL, 0, title, NULL, "Serialize error", "status: %d", status);
                KeyIso_free(buffer);
                return NULL;
            }
        } else { //SerializeStatus_Success
            return buffer;
        }
    } 
    KeyIso_free(buffer);
    return NULL;
}

int KeyIso_deserialize_rsa_enc_dec_with_attached_key_in(const uint8_t *encodedSt, size_t encodedLen, void* decodedSt)
{  
    SerializeStatus status = _decode_rsa_enc_dec_with_attached_key_st(encodedSt, encodedLen, (KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_IN_ST*)decodedSt);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}

size_t KeyIso_get_len_rsa_enc_dec_with_attached_key_in(const uint8_t *encodedSt, size_t encodedLen)
{
    size_t dynamicSize = 0;
    uint32_t encryptedKeySize = 0;

    int64_t fromLen =  get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_FROM_LEN); // From buffer length
    int64_t labelLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_LABEL_LEN); // Label length

   // Add from and label lengths
    if (KEYISO_ADD_OVERFLOW(fromLen, labelLen, &dynamicSize)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_RSA_PKEY_ENC_DEC_TITE, "Invalid format", "Invalid dynamic size");
        return 0;
    }
    
    // Encrypted key length
    if (!_get_len_enc_priv_key(encodedSt, encodedLen, &encryptedKeySize)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_RSA_PKEY_ENC_DEC_TITE, "Invalid format", "_get_len_enc_priv_key Failed");
        return 0;
    }

    // From and encrypted key dynamic size
    if (KEYISO_ADD_OVERFLOW(dynamicSize, encryptedKeySize, &dynamicSize)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_RSA_PKEY_ENC_DEC_TITE, "Invalid format", "Invalid dynamic size");
        return 0;
    }

    // Dynamic size boundaries check
    if (dynamicSize > UINT32_MAX) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_RSA_PKEY_ENC_DEC_TITE, "Invalid format", "Invalid dynamic size");
        return 0;
    }
   
    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_IN_ST, dynamicSize);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    RSA ENC/DEC WITH ATTACHED KEY OUT
*/
/////////////////////////////////////////////////////////////////////////////////////////////////////
static SerializeStatus _encode_rsa_enc_dec_with_attached_key_out_st(KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_OUT_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
   
    // Encode headerSt
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_RSA_PRIVATE_ENC_DEC_WITH_ENC_KEY_OUT_ELEMENTS))
    CBOR_CHECK_STATUS(encode_header_out_st(&mapEncoder, &stToEncode->headerSt))    

    // Encode keyId
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_KEY_ID))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, stToEncode->keyId)) 

    // Encode toLen
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_TO_LEN))
    CBOR_OPERATION(cbor_encode_int(&mapEncoder, (int64_t)stToEncode->bytesLen))

    // Encode toBytes
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_TO_BYTES))    
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->toBytes, stToEncode->bytesLen))

    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))
    
    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;   
}

static SerializeStatus _decode_rsa_enc_dec_with_attached_key_out_st(const uint8_t *buffer, size_t bufferSize, KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_OUT_ST *decodedSt)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    cbor_parser_init(buffer, bufferSize, 0, &parser, &value);

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "SerializeStatus_InvalidFormat");
        return SerializeStatus_InvalidFormat;
    }

    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_out_st(&map, &decodedSt->headerSt, IpcCommand_RsaPrivateEncryptDecryptWithAttachedKey))

    // keyId
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_KEY_ID))
    CBOR_OPERATION(cbor_value_get_uint64(&map, &(decodedSt->keyId)))
    CBOR_OPERATION(cbor_value_advance_fixed(&map))

   // toLen , toBytes
    CBOR_CHECK_STATUS(decode_string_ptr(&map, CBOR_PARAM_TO_LEN, &decodedSt->bytesLen, CBOR_PARAM_TO_BYTES, decodedSt->toBytes))
  
    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}

uint8_t* KeyIso_serialize_rsa_enc_dec_with_attached_key_out(const void *stToEncode, size_t *encodedLen)
{
    size_t allocatesSize = sizeof(KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_OUT_ST) * SIZE_MULTIPLE_TO_ALLOC_OUT_STRUCT +
                         ((KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_OUT_ST*)stToEncode)->bytesLen;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
    int8_t counter = 0;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_rsa_enc_dec_with_attached_key_out_st((KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_OUT_ST*)stToEncode, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {                
                allocatesSize *= REALLOC_MULTIPLE;  
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_ENGINE_TITLE, "realloc", "retry", "%ld bytes", allocatesSize);     
                buffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "Serialize error");
                KeyIso_free(buffer);
                return NULL;
            }
        } else {
            return buffer;
        }
    } 
    KeyIso_free(buffer);
    return NULL;

}

size_t KeyIso_get_len_rsa_enc_dec_with_attached_key_out(const uint8_t *encodedSt, size_t encodedLen)
{
    int64_t dynamicSize = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_TO_LEN);

    // bytesLen field boundaries check
    if (dynamicSize < 0 || dynamicSize > INT32_MAX) {
        return 0;
    }

    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_OUT_ST, dynamicSize);
}

int KeyIso_deserialize_rsa_enc_dec_with_attached_key_out(const uint8_t *encodedSt, size_t encodedLen, void* decodedSt)
{  
    SerializeStatus status = _decode_rsa_enc_dec_with_attached_key_out_st(encodedSt, encodedLen, (KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_OUT_ST*)decodedSt);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    Key Serialization
*/
static SerializeStatus _encode_header_key_st(CborEncoder *mapEncoder, KEYISO_KEY_HEADER_ST *keyHeaderSt)
{
    CborError cborErr = CborNoError;
    CborEncoder headerMapEncoder = { 0 };

    CBOR_OPERATION(cbor_encode_text_stringz(mapEncoder, CBOR_PARAM_KEY_HEADER))
    CBOR_OPERATION(cbor_encoder_create_map(mapEncoder, &headerMapEncoder, NUM_OF_PKEY_HEADER_ELEMENTS))

    // Encode keyVersion  
    CBOR_OPERATION(cbor_encode_text_stringz(&headerMapEncoder, CBOR_PARAM_KEY_VERSION)) 
    CBOR_OPERATION(cbor_encode_uint(&headerMapEncoder, keyHeaderSt->keyVersion))

    // Encode magic
    CBOR_OPERATION(cbor_encode_text_stringz(&headerMapEncoder, CBOR_PARAM_MAGIC))
    CBOR_OPERATION(cbor_encode_uint(&headerMapEncoder, keyHeaderSt->magic))

    CBOR_OPERATION(cbor_encoder_close_container(mapEncoder, &headerMapEncoder))
    return SerializeStatus_Success;  
}

static SerializeStatus _decode_header_key_st(CborValue *map, KEYISO_KEY_HEADER_ST *keyHeaderSt)
{
    CborError cborErr = CborNoError;
    CborValue headerMap = { 0 };
 
    CBOR_CHECK_STATUS(validate_tag(map, CBOR_PARAM_KEY_HEADER))
    // Enter the header map
    CBOR_OPERATION(cbor_value_enter_container(map, &headerMap))

    // Decode key version  
    CBOR_CHECK_STATUS(validate_tag(&headerMap, CBOR_PARAM_KEY_VERSION))
    CBOR_OPERATION(get_uint32_val(&headerMap, &keyHeaderSt->keyVersion))

    // Decode magic
    CBOR_CHECK_STATUS(validate_tag(&headerMap, CBOR_PARAM_MAGIC))
    CBOR_OPERATION(get_uint32_val(&headerMap, &keyHeaderSt->magic))
    
    CBOR_OPERATION(cbor_value_leave_container(map, &headerMap)) //Updates map to point to the next element after the container.  
    return SerializeStatus_Success;  
}

// RSA 
static SerializeStatus _encode_rsa_pkey_st(CborEncoder *mapEncoder, KEYISO_RSA_PKEY_ST *rsaPkeySt)
{
    CborError cborErr = CborNoError;
    CborEncoder pkeyMapEncoder = { 0 };
    uint32_t pkeyBytesLen = KeyIso_get_rsa_pkey_bytes_len(rsaPkeySt);

    CBOR_OPERATION(cbor_encode_text_stringz(mapEncoder, CBOR_PARAM_PKEY))
    CBOR_OPERATION(cbor_encoder_create_map(mapEncoder, &pkeyMapEncoder, NUM_OF_RSA_PKEY_ELEMENTS))

    // Encode headerSt
    CBOR_CHECK_STATUS(_encode_header_key_st(&pkeyMapEncoder, &rsaPkeySt->header));

    // Encode key usage
    CBOR_OPERATION(cbor_encode_text_stringz(&pkeyMapEncoder, CBOR_PARAM_KEY_USAGE))
    CBOR_OPERATION(cbor_encode_simple_value(&pkeyMapEncoder, rsaPkeySt->rsaUsage))

    // Encode modulus len
    CBOR_OPERATION(cbor_encode_text_stringz(&pkeyMapEncoder,CBOR_PARAM_RSA_MODULUS_LEN))
    CBOR_OPERATION(cbor_encode_uint(&pkeyMapEncoder, rsaPkeySt->rsaModulusLen))

    // Encode public exponent len
    CBOR_OPERATION(cbor_encode_text_stringz(&pkeyMapEncoder,CBOR_PARAM_RSA_PUBLIC_EXP_LEN))
    CBOR_OPERATION(cbor_encode_uint(&pkeyMapEncoder, rsaPkeySt->rsaPublicExpLen))
    
    // Encode primeNumber1 len
    CBOR_OPERATION(cbor_encode_text_stringz(&pkeyMapEncoder,CBOR_PARAM_RSA_PRIME1_LEN))
    CBOR_OPERATION(cbor_encode_uint(&pkeyMapEncoder, rsaPkeySt->rsaPrimes1Len))

    // Encode primeNumber2 len
    CBOR_OPERATION(cbor_encode_text_stringz(&pkeyMapEncoder,CBOR_PARAM_RSA_PRIME2_LEN))
    CBOR_OPERATION(cbor_encode_uint(&pkeyMapEncoder, rsaPkeySt->rsaPrimes2Len))

    // Encode rsaKeyBytes 
    CBOR_OPERATION(cbor_encode_text_stringz(&pkeyMapEncoder, CBOR_PARAM_RSA_KEY_BYTES))
    CBOR_OPERATION(cbor_encode_byte_string(&pkeyMapEncoder, rsaPkeySt->rsaPkeyBytes, pkeyBytesLen))
    
    CBOR_OPERATION(cbor_encoder_close_container(mapEncoder, &pkeyMapEncoder))
    
    return SerializeStatus_Success;   
}

static SerializeStatus _decode_rsa_pkey_st(CborValue *map, KEYISO_RSA_PKEY_ST *rsaPkeySt)
{
    CborError cborErr = CborNoError;
    CborValue pkeyMap = { 0 };

    CBOR_CHECK_STATUS(validate_tag(map, CBOR_PARAM_PKEY))
    CBOR_OPERATION(cbor_value_enter_container(map, &pkeyMap))

    // Decode header
    CBOR_CHECK_STATUS(_decode_header_key_st(&pkeyMap, &rsaPkeySt->header));
    
    // Decode key usage
    CBOR_CHECK_STATUS(validate_tag(&pkeyMap, CBOR_PARAM_KEY_USAGE))
    CBOR_OPERATION(cbor_value_get_simple_type(&pkeyMap, &rsaPkeySt->rsaUsage))
    CBOR_OPERATION(cbor_value_advance_fixed(&pkeyMap))

    // Decode modulus  
    CBOR_CHECK_STATUS(validate_tag(&pkeyMap, CBOR_PARAM_RSA_MODULUS_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(&pkeyMap, &rsaPkeySt->rsaModulusLen))

    // Decode public exponent
    CBOR_CHECK_STATUS(validate_tag(&pkeyMap, CBOR_PARAM_RSA_PUBLIC_EXP_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(&pkeyMap, &rsaPkeySt->rsaPublicExpLen))

    // Decode primeNumber1
    CBOR_CHECK_STATUS(validate_tag(&pkeyMap, CBOR_PARAM_RSA_PRIME1_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(&pkeyMap, &rsaPkeySt->rsaPrimes1Len))

    // Decode primeNumber2
    CBOR_CHECK_STATUS(validate_tag(&pkeyMap, CBOR_PARAM_RSA_PRIME2_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(&pkeyMap, &rsaPkeySt->rsaPrimes2Len))

    // Decode rsaPkeyBytes 
    uint32_t pkeyBytesLen = KeyIso_get_rsa_pkey_bytes_len(rsaPkeySt);
    CBOR_CHECK_STATUS(decode_string_ptr_by_len(&pkeyMap, pkeyBytesLen, CBOR_PARAM_RSA_KEY_BYTES, rsaPkeySt->rsaPkeyBytes))
    
    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(map, &pkeyMap))
    return SerializeStatus_Success;
}

// EC
static SerializeStatus _encode_ec_pkey_st(CborEncoder *mapEncoder, KEYISO_EC_PKEY_ST *ecPkeySt)
{
    CborError cborErr = CborNoError;
    CborEncoder pkeyMapEncoder = { 0 };
    uint32_t pkeyBytesLen = KeyIso_get_ec_pkey_bytes_len(ecPkeySt);
    
    CBOR_OPERATION(cbor_encode_text_stringz(mapEncoder, CBOR_PARAM_PKEY))
    CBOR_OPERATION(cbor_encoder_create_map(mapEncoder, &pkeyMapEncoder, NUM_OF_EC_PKEY_ELEMENTS))

    // Encode headerSt
    CBOR_CHECK_STATUS(_encode_header_key_st(&pkeyMapEncoder, &ecPkeySt->header));

    // Encode key usage
    CBOR_OPERATION(cbor_encode_text_stringz(&pkeyMapEncoder, CBOR_PARAM_KEY_USAGE))
    CBOR_OPERATION(cbor_encode_simple_value(&pkeyMapEncoder, ecPkeySt->ecUsage))

    // Ecode ec curve
    CBOR_OPERATION(cbor_encode_text_stringz(&pkeyMapEncoder, CBOR_PARAM_EC_CRV))
    CBOR_OPERATION(cbor_encode_uint(&pkeyMapEncoder, ecPkeySt->ecCurve))

    // Ecode public key x len
    CBOR_OPERATION(cbor_encode_text_stringz(&pkeyMapEncoder, CBOR_PARAM_EC_PUB_X_LEN))
    CBOR_OPERATION(cbor_encode_uint(&pkeyMapEncoder, ecPkeySt->ecPubXLen))

    // Ecode public key y len
    CBOR_OPERATION(cbor_encode_text_stringz(&pkeyMapEncoder, CBOR_PARAM_EC_PUB_Y_LEN))
    CBOR_OPERATION(cbor_encode_uint(&pkeyMapEncoder, ecPkeySt->ecPubYLen))

    // Ecode ec private key len
    CBOR_OPERATION(cbor_encode_text_stringz(&pkeyMapEncoder, CBOR_PARAM_EC_PRIVATE_KEY_LEN))
    CBOR_OPERATION(cbor_encode_uint(&pkeyMapEncoder, ecPkeySt->ecPrivKeyLen))

    // Encode ec key bytes
    CBOR_OPERATION(cbor_encode_text_stringz(&pkeyMapEncoder, CBOR_PARAM_EC_KEY_BYTES))
    CBOR_OPERATION(cbor_encode_byte_string(&pkeyMapEncoder, ecPkeySt->ecKeyBytes, pkeyBytesLen))
    
    CBOR_OPERATION(cbor_encoder_close_container(mapEncoder, &pkeyMapEncoder))
    
    return SerializeStatus_Success; 
}

static SerializeStatus _decode_ec_pkey_st(CborValue *map, KEYISO_EC_PKEY_ST *ecPkeySt)
{
    CborError cborErr = CborNoError;
    CborValue pkeyMap = { 0 };

    CBOR_CHECK_STATUS(validate_tag(map, CBOR_PARAM_PKEY))
    CBOR_OPERATION(cbor_value_enter_container(map, &pkeyMap))

    CBOR_CHECK_STATUS(_decode_header_key_st(&pkeyMap, &ecPkeySt->header));

    // Decode key usage
    CBOR_CHECK_STATUS(validate_tag(&pkeyMap, CBOR_PARAM_KEY_USAGE))
    CBOR_OPERATION(cbor_value_get_simple_type(&pkeyMap, &ecPkeySt->ecUsage))
    CBOR_OPERATION(cbor_value_advance_fixed(&pkeyMap))

    // Decode ec curve
    CBOR_CHECK_STATUS(validate_tag(&pkeyMap, CBOR_PARAM_EC_CRV))
    CBOR_CHECK_STATUS(get_uint32_val(&pkeyMap, &ecPkeySt->ecCurve))

    // Decode public key x len
    CBOR_CHECK_STATUS(validate_tag(&pkeyMap, CBOR_PARAM_EC_PUB_X_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(&pkeyMap, &ecPkeySt->ecPubXLen))

    // Decode public key y len
    CBOR_CHECK_STATUS(validate_tag(&pkeyMap, CBOR_PARAM_EC_PUB_Y_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(&pkeyMap, &ecPkeySt->ecPubYLen))

    // Decode ec private key len
    CBOR_CHECK_STATUS(validate_tag(&pkeyMap, CBOR_PARAM_EC_PRIVATE_KEY_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(&pkeyMap, &ecPkeySt->ecPrivKeyLen))

    // Decode ec key bytes 
    uint32_t pkeyBytesLen = KeyIso_get_ec_pkey_bytes_len(ecPkeySt);
    CBOR_CHECK_STATUS(decode_string_ptr_by_len(&pkeyMap, pkeyBytesLen, CBOR_PARAM_EC_KEY_BYTES, ecPkeySt->ecKeyBytes))
    
    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(map, &pkeyMap))
    return SerializeStatus_Success;

}
/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    OPEN PRIVATE KEY IN
*/

static SerializeStatus _encode_open_priv_key_in_st(KEYISO_OPEN_PRIV_KEY_IN_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_OPEN_PRIV_KEY_IN_ELEMENTS))

    // Encode headerSt
    CBOR_CHECK_STATUS(encode_header_in_st(&mapEncoder, &stToEncode->headerSt))

    // Encode secretSalt  
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SECRET_SALT))
    CBOR_OPERATION(cbor_encode_text_string(&mapEncoder, (char*)stToEncode->secretSalt, sizeof(stToEncode->secretSalt)))

    // Encode encKeySt
    CBOR_CHECK_STATUS(_encode_enc_priv_key_st(&mapEncoder, &stToEncode->encKeySt))

    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))
    
    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;   
}

static SerializeStatus _decode_open_priv_key_in_st(const uint8_t *buffer, size_t bufferSize, KEYISO_OPEN_PRIV_KEY_IN_ST *decodedSt)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, NULL, "invalid format");
        return SerializeStatus_InvalidFormat;
    }

    // header
    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_in_st(&map, &decodedSt->headerSt, IpcCommand_OpenPrivateKey))

    // secretSalt  
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_SECRET_SALT))
    size_t size;
    CBOR_OPERATION(cbor_value_get_string_length(&map, &size))
    CBOR_OPERATION(cbor_value_copy_text_string(&map, (char*)decodedSt->secretSalt, &size, &map))

    // encKey
    CBOR_CHECK_STATUS(_decode_enc_priv_key_st(&map, &decodedSt->encKeySt))
   
    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}

uint8_t* KeyIso_serialize_open_priv_key_in(const void* stToEncode, size_t *encodedLen)
{   
    KEYISO_OPEN_PRIV_KEY_IN_ST *inST  = (KEYISO_OPEN_PRIV_KEY_IN_ST*)stToEncode;
    size_t totalBuflen = KeyIso_get_enc_key_bytes_len(NULL, inST->encKeySt.saltLen, inST->encKeySt.ivLen, inST->encKeySt.hmacLen, inST->encKeySt.encKeyLen);

    size_t allocatesSize = sizeof(KEYISO_OPEN_PRIV_KEY_IN_ST) * SIZE_MULTIPLE_TO_ALLOC_IN_STRUCT + totalBuflen;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
    int8_t counter = 0;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_open_priv_key_in_st((KEYISO_OPEN_PRIV_KEY_IN_ST*)stToEncode, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {                
                allocatesSize *= REALLOC_MULTIPLE;  
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_OPEN_KEY_TITLE, "realloc", "retry", "%ld bytes", allocatesSize);     
                buffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, NULL, "Serialize error");
                KeyIso_free(buffer);
                return NULL;
            }
        } else { //SerializeStatus_Success
            return buffer;
        }
    } 
    KeyIso_free(buffer);
    return NULL;
}

size_t KeyIso_get_len_open_priv_key_in(const uint8_t *encodedSt, size_t encodedLen)
{
    uint32_t structDynamicSize = 0;

    if (!_get_len_nested_enc_priv_key(encodedSt, encodedLen, &structDynamicSize)) {
        return 0;
    }
    
    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_OPEN_PRIV_KEY_IN_ST, structDynamicSize);
}

int KeyIso_deserialize_open_priv_key_in(const uint8_t *encodedSt, size_t encodedLen, void* decodedSt)
{  
    SerializeStatus status = _decode_open_priv_key_in_st(encodedSt, encodedLen, (KEYISO_OPEN_PRIV_KEY_IN_ST*)decodedSt);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    OPEN PRIVATE KEY OUT
*/

static SerializeStatus _encode_open_priv_key_out_st(KEYISO_OPEN_PRIV_KEY_OUT_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_OPEN_PRIV_KEY_OUT_ELEMENTS))

    // Encode headerSt
    CBOR_CHECK_STATUS(encode_header_out_st(&mapEncoder, &stToEncode->headerSt))

    // Encode keyId
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_KEY_ID))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, stToEncode->keyId))     

    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))
    
    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;   
}

static SerializeStatus _decode_open_priv_key_out_st(const uint8_t *buffer, size_t bufferSize, KEYISO_OPEN_PRIV_KEY_OUT_ST *decodedSt)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, NULL, "invalid format");
        return SerializeStatus_InvalidFormat;
    }

    // header
    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_out_st(&map, &decodedSt->headerSt, IpcCommand_OpenPrivateKey))

    // keyId
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_KEY_ID))
    CBOR_OPERATION(cbor_value_get_uint64(&map, &(decodedSt->keyId)))
    CBOR_OPERATION(cbor_value_advance_fixed(&map))
   
    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}

uint8_t* KeyIso_serialize_open_priv_key_out(const void *stToEncode, size_t *encodedLen)
{
    size_t allocatesSize = sizeof(KEYISO_OPEN_PRIV_KEY_OUT_ST) * SIZE_MULTIPLE_TO_ALLOC_OUT_STRUCT;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
    int8_t counter = 0;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_open_priv_key_out_st((KEYISO_OPEN_PRIV_KEY_OUT_ST*)stToEncode, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {                
                allocatesSize *= REALLOC_MULTIPLE;  
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_OPEN_KEY_TITLE, "realloc", "retry", "%ld bytes", allocatesSize);     
                buffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, NULL, "Serialize error");
                KeyIso_free(buffer);
                return NULL;
            }
        } else { //SerializeStatus_Success
            return buffer;
        }
    } 
    KeyIso_free(buffer);
    return NULL;
}

int KeyIso_deserialize_open_priv_key_out(const uint8_t *encodedSt, size_t encodedLen, void* decodedSt)
{  
    SerializeStatus status = _decode_open_priv_key_out_st(encodedSt, encodedLen, (KEYISO_OPEN_PRIV_KEY_OUT_ST*)decodedSt);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}


/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    GENERATE RSA KEY PAIR IN
*/

static SerializeStatus _encode_gen_rsa_key_pair_in_st(KEYISO_GEN_RSA_KEY_PAIR_IN_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_GENERATE_RSA_KEY_PAIR_IN_ELEMENTS))

    // Encode headerSt
    CBOR_CHECK_STATUS(encode_header_in_st(&mapEncoder, &stToEncode->headerSt))

    // Encode rsaBits  
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_RSA_BITS))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->bits))

    // Encode keyUsage
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_KEY_USAGE))
    CBOR_OPERATION(cbor_encode_simple_value(&mapEncoder, stToEncode->keyUsage))

    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))
    
    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;   
}

static SerializeStatus _decode_gen_rsa_key_pair_in_st(const uint8_t *buffer, size_t bufferSize, KEYISO_GEN_RSA_KEY_PAIR_IN_ST *decodedSt)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, NULL, "invalid format");
        return SerializeStatus_InvalidFormat;
    }

    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_in_st(&map, &decodedSt->headerSt, IpcCommand_GenerateRsaKeyPair))

    // Decode rsaBits  
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_RSA_BITS))
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->bits))

    // Decode key usage
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_KEY_USAGE))
    CBOR_OPERATION(cbor_value_get_simple_type(&map, &decodedSt->keyUsage))
    CBOR_OPERATION(cbor_value_advance_fixed(&map))
   
    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}

uint8_t* KeyIso_serialize_gen_rsa_key_pair_in(void *stToEncode, size_t *encodedLen)
{
    size_t allocatesSize = sizeof(KEYISO_GEN_RSA_KEY_PAIR_IN_ST) * SIZE_MULTIPLE_TO_ALLOC_IN_STRUCT;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
    int8_t counter = 0;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_gen_rsa_key_pair_in_st((KEYISO_GEN_RSA_KEY_PAIR_IN_ST*)stToEncode, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {                
                allocatesSize *= REALLOC_MULTIPLE;  
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_GEN_KEY_TITLE, "realloc", "retry", "%ld bytes", allocatesSize);     
                buffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, NULL, "Serialize error");
                KeyIso_free(buffer);
                return NULL;
            }
        } else { //SerializeStatus_Success
            return buffer;
        }
    } 
    KeyIso_free(buffer);
    return NULL;
}

size_t KeyIso_get_len_gen_rsa_key_pair_in(const uint8_t *encodedSt, size_t encodedLen)
{
    return sizeof(KEYISO_GEN_RSA_KEY_PAIR_IN_ST);
}

int KeyIso_deserialize_gen_rsa_key_pair_in(const uint8_t *encodedSt, size_t encodedLen, void* decodedSt)
{  
    SerializeStatus status = _decode_gen_rsa_key_pair_in_st(encodedSt, encodedLen, (KEYISO_GEN_RSA_KEY_PAIR_IN_ST*)decodedSt);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    GENERATE EC KEY PAIR IN
*/

static SerializeStatus _encode_gen_ec_key_pair_in_st(KEYISO_GEN_EC_KEY_PAIR_IN_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_GENERATE_RSA_KEY_PAIR_IN_ELEMENTS))

    // Encode headerSt
    CBOR_CHECK_STATUS(encode_header_in_st(&mapEncoder, &stToEncode->headerSt))

    // Encode curveNID  
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_EC_CRV_NID))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->curve))    

    // Encode keyUsage
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_KEY_USAGE))
    CBOR_OPERATION(cbor_encode_simple_value(&mapEncoder, stToEncode->keyUsage))

    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))
    
    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;   
}

static SerializeStatus _decode_gen_ec_key_pair_in_st(const uint8_t *buffer, size_t bufferSize, KEYISO_GEN_EC_KEY_PAIR_IN_ST *decodedSt)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, NULL, "invalid format");
        return SerializeStatus_InvalidFormat;
    }

    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_in_st(&map, &decodedSt->headerSt, IpcCommand_GenerateEcKeyPair))

    // Decode curveNID  
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_EC_CRV_NID))
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->curve))    

    // Decode key usage
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_KEY_USAGE))
    CBOR_OPERATION(cbor_value_get_simple_type(&map, &decodedSt->keyUsage))
    CBOR_OPERATION(cbor_value_advance_fixed(&map))
   
    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}

uint8_t* KeyIso_serialize_gen_ec_key_pair_in(const void *stToEncode, size_t *encodedLen)
{
    size_t allocatesSize = sizeof(KEYISO_GEN_EC_KEY_PAIR_IN_ST) * SIZE_MULTIPLE_TO_ALLOC_IN_STRUCT;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
    int8_t counter = 0;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_gen_ec_key_pair_in_st((KEYISO_GEN_EC_KEY_PAIR_IN_ST*)stToEncode, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {                
                allocatesSize *= REALLOC_MULTIPLE;  
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_GEN_KEY_TITLE, "realloc", "retry", "%ld bytes", allocatesSize);     
                buffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, NULL, "Serialize error");
                KeyIso_free(buffer);
                return NULL;
            }
        } else { //SerializeStatus_Success
            return buffer;
        }
    } 
    KeyIso_free(buffer);
    return NULL;
}

size_t KeyIso_get_len_gen_ec_key_pair_in(const uint8_t *encodedSt, size_t encodedLen)
{
    return sizeof(KEYISO_GEN_EC_KEY_PAIR_IN_ST);
}

int KeyIso_deserialize_gen_ec_key_pair_in(const uint8_t *encodedSt, size_t encodedLen, void* decodedSt)
{  
    SerializeStatus status = _decode_gen_ec_key_pair_in_st(encodedSt, encodedLen, (KEYISO_GEN_EC_KEY_PAIR_IN_ST*)decodedSt);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    GENERATE RSA KEY PAIR OUT
*/
static uint64_t _get_gen_rsa_key_pair_out_len(const KEYISO_GEN_RSA_KEY_PAIR_OUT_ST *stToEncode) {
    if(stToEncode) {
        return    
         stToEncode->saltLen + 
         stToEncode->ivLen + 
         stToEncode->hmacLen + 
         stToEncode->encKeyLen +
         stToEncode->rsaModulusLen +
         stToEncode->rsaPublicExpLen;
    }
    return 0;
}

static SerializeStatus _encode_gen_rsa_key_pair_out_st(KEYISO_GEN_RSA_KEY_PAIR_OUT_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    // A map of a key pair : the public key and the generated private key
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };
    uint64_t totalBuflen =  _get_gen_rsa_key_pair_out_len(stToEncode);

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_GENERATE_RSA_KEY_PAIR_OUT_ELEMENTS))

    // Encode headerSt
    CBOR_CHECK_STATUS(encode_header_out_st(&mapEncoder, &stToEncode->headerSt))

    // Encode secretSalt  
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SECRET_SALT))
    CBOR_OPERATION(cbor_encode_text_string(&mapEncoder, (char*)stToEncode->secretSalt, sizeof(stToEncode->secretSalt)))

    /* Encrypted private key */
    // Encode algVersion
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_ALG_VER))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->algVersion))

    // Encode saltLen  
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SALT_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->saltLen))

    // Encode ivLen  
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_IV_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->ivLen))
    
    // Encode hmacLen  
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_HMAC_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->hmacLen))

    // Encode encrypted private key length  
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_ENCRYPTED_KEY_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->encKeyLen))

    // Encode rsa pub key modulus length
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_RSA_MODULUS_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->rsaModulusLen))

    // Encode rsa pub key exponent length
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_RSA_PUBLIC_EXP_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->rsaPublicExpLen))

    // Encode encryptedKeyBytes  
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_ENCRYPTED_KEY_PAIR_BYTES))
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->generateRsaKeyBytes, totalBuflen))

    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))
    
    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;   
}

static SerializeStatus _decode_gen_rsa_key_pair_out_st(const uint8_t *buffer, size_t bufferSize, KEYISO_GEN_RSA_KEY_PAIR_OUT_ST *decodedSt)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    uint64_t totalBuflen = 0;

    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, NULL, "invalid format");
        return SerializeStatus_InvalidFormat;
    }

    // header
    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_out_st(&map, &decodedSt->headerSt, IpcCommand_GenerateRsaKeyPair))

    // secretSalt  
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_SECRET_SALT))
    size_t size;
    CBOR_OPERATION(cbor_value_get_string_length(&map, &size))
    CBOR_OPERATION(cbor_value_copy_text_string(&map, (char*)decodedSt->secretSalt, &size, &map))

    /* Encrypted private key */
    // Decode algVersion
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_ALG_VER))
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->algVersion))

    // Decode saltLen  
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_SALT_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->saltLen))
    
    // Decode ivLen  
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_IV_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->ivLen))
    
    // Decode hmacLen  
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_HMAC_LEN))        
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->hmacLen))
     
    // Decode encKeyLen            
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_ENCRYPTED_KEY_LEN))        
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->encKeyLen))

    // Decode rsa pub key exponent length  
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_RSA_MODULUS_LEN))        
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->rsaModulusLen))

    // Decode rsa public exponent length
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_RSA_PUBLIC_EXP_LEN))        
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->rsaPublicExpLen))

    // Decode encryptedKeyPair bytes
    totalBuflen = _get_gen_rsa_key_pair_out_len(decodedSt);
    CBOR_CHECK_STATUS(decode_string_ptr_by_len(&map, totalBuflen, CBOR_PARAM_ENCRYPTED_KEY_PAIR_BYTES, decodedSt->generateRsaKeyBytes))
   
    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}

uint8_t* KeyIso_serialize_gen_rsa_key_pair_out(void *stToEncode, size_t *encodedLen)
{
    size_t totalBuflen = _get_gen_rsa_key_pair_out_len((KEYISO_GEN_RSA_KEY_PAIR_OUT_ST*)stToEncode);

    size_t allocatesSize = sizeof(KEYISO_GEN_RSA_KEY_PAIR_OUT_ST) * SIZE_MULTIPLE_TO_ALLOC_OUT_STRUCT + totalBuflen;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
    int8_t counter = 0;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_gen_rsa_key_pair_out_st((KEYISO_GEN_RSA_KEY_PAIR_OUT_ST*)stToEncode, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {                
                allocatesSize *= REALLOC_MULTIPLE;  
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_GEN_KEY_TITLE, "realloc", "retry", "%ld bytes", allocatesSize);     
                buffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, NULL, "Serialize error");
                KeyIso_free(buffer);
                return NULL;
            }
        } else { //SerializeStatus_Success
            return buffer;
        }
    } 
    KeyIso_free(buffer);
    return NULL;
}

static bool _get_gen_rsa_key_pair_out_dynamic_len(const uint8_t *encodedSt, size_t encodedLen, uint32_t* dynamicSize)
{       
    if (!_get_len_enc_priv_key(encodedSt,encodedLen, dynamicSize)) {
        return false;
    }

    // getting the value of the rsa modulus
    int64_t rsaModulusLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_RSA_MODULUS_LEN);
    if (rsaModulusLen < 0 || rsaModulusLen > UINT32_MAX) {
        return false;
    }

    // summing the rsa modulus + dynamic size fo far
    if (KEYISO_ADD_OVERFLOW(*dynamicSize, (uint32_t)rsaModulusLen, dynamicSize)) {
        return false;
    }

    // getting the value of the rsa public exponent
    int64_t rsaPublicExpLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_RSA_PUBLIC_EXP_LEN);
    if (rsaPublicExpLen < 0 || rsaPublicExpLen > UINT32_MAX) {
        return false;
    }

    // summing the rsaPublicExpLen + dynamic size fo far
    if (KEYISO_ADD_OVERFLOW(*dynamicSize, (uint32_t)rsaPublicExpLen, dynamicSize)) {
        return false;
    }

    return true;
}

size_t KeyIso_get_len_gen_rsa_key_pair_out(const uint8_t *encodedSt, size_t encodedLen)
{
    uint32_t dynamicLen = 0;
    
    if (_get_gen_rsa_key_pair_out_dynamic_len(encodedSt, encodedLen, &dynamicLen) == false) {
        return 0;
    }
    
    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_GEN_RSA_KEY_PAIR_OUT_ST, dynamicLen);
}


int KeyIso_deserialize_gen_rsa_key_pair_out(const uint8_t *encodedSt, size_t encodedLen, void* decodedSt)
{  
    SerializeStatus status = _decode_gen_rsa_key_pair_out_st(encodedSt, encodedLen, (KEYISO_GEN_RSA_KEY_PAIR_OUT_ST*)decodedSt);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    GENERATE EC KEY PAIR OUT
*/
static uint64_t _get_encrypted_ec_key_pair_len(const KEYISO_GEN_EC_KEY_PAIR_OUT_ST *stToEncode) {
    if(stToEncode) {
        return    
         stToEncode->saltLen + 
         stToEncode->ivLen + 
         stToEncode->hmacLen + 
         stToEncode->encKeyLen +
         stToEncode->ecPubKeyLen;
    }
    return 0;
}

static SerializeStatus _encode_gen_ec_key_pair_out_st(KEYISO_GEN_EC_KEY_PAIR_OUT_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
   
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };
    uint64_t totalBuflen =  _get_encrypted_ec_key_pair_len(stToEncode);

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_GENERATE_EC_KEY_PAIR_OUT_ELEMENTS))

    // Encode headerSt
    CBOR_CHECK_STATUS(encode_header_out_st(&mapEncoder, &stToEncode->headerSt))

    // Encode secretSalt  
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SECRET_SALT))
    CBOR_OPERATION(cbor_encode_text_string(&mapEncoder, (char*)stToEncode->secretSalt, sizeof(stToEncode->secretSalt)))

    /* Encrypted private key */
    // Encode algVersion
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_ALG_VER))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->algVersion))

    // Encode saltLen  
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SALT_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->saltLen))

    // Encode ivLen  
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_IV_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->ivLen))
    
    // Encode hmacLen  
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_HMAC_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->hmacLen))

    // Encode encrypted private key len  
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_ENCRYPTED_KEY_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->encKeyLen))

    // Ec key curve
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_EC_CRV))        
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder,(uint64_t)stToEncode->ecCurve))

    // Encode rsa pub key len
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_PUBLIC_KEY_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->ecPubKeyLen))

    // Encode encryptedKeyBytes  
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_ENCRYPTED_KEY_PAIR_BYTES))
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->generateEcKeyBytes, totalBuflen))

    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))
    
    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;   
}

static SerializeStatus _decode_gen_ec_key_pair_out_st(const uint8_t *buffer, size_t bufferSize, KEYISO_GEN_EC_KEY_PAIR_OUT_ST *decodedSt)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    uint64_t totalBuflen = 0;

    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, NULL, "invalid format");
        return SerializeStatus_InvalidFormat;
    }

    // header
    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_out_st(&map, &decodedSt->headerSt, IpcCommand_GenerateEcKeyPair))

    // secretSalt  
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_SECRET_SALT))
    size_t size;
    CBOR_OPERATION(cbor_value_get_string_length(&map, &size))
    CBOR_OPERATION(cbor_value_copy_text_string(&map, (char*)decodedSt->secretSalt, &size, &map))

    /* Encrypted private key */
    // Decode algVersion
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_ALG_VER))
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->algVersion))

    // Decode saltLen  
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_SALT_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->saltLen))
    
    // Decode ivLen  
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_IV_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->ivLen))
    
    // Decode hmacLen  
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_HMAC_LEN))        
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->hmacLen))
     
    // Decode encKeyLen            
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_ENCRYPTED_KEY_LEN))        
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->encKeyLen))

    // Decode ec curve
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_EC_CRV))        
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->ecCurve))

    // Decode rsa public key len          
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_PUBLIC_KEY_LEN))        
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->ecPubKeyLen))

    // Decode encryptedKeyPair bytes
    totalBuflen = _get_encrypted_ec_key_pair_len(decodedSt);
    CBOR_CHECK_STATUS(decode_string_ptr_by_len(&map, totalBuflen, CBOR_PARAM_ENCRYPTED_KEY_PAIR_BYTES, decodedSt->generateEcKeyBytes))
   
    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}


uint8_t* KeyIso_serialize_gen_ec_key_pair_out(const void *stToEncode, size_t *encodedLen)
{
    size_t totalBuflen = _get_encrypted_ec_key_pair_len((KEYISO_GEN_EC_KEY_PAIR_OUT_ST*)stToEncode);

    size_t allocatesSize = sizeof(KEYISO_GEN_EC_KEY_PAIR_OUT_ST) * SIZE_MULTIPLE_TO_ALLOC_OUT_STRUCT + totalBuflen;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
    int8_t counter = 0;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_gen_ec_key_pair_out_st((KEYISO_GEN_EC_KEY_PAIR_OUT_ST*)stToEncode, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {                
                allocatesSize *= REALLOC_MULTIPLE;  
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_GEN_KEY_TITLE, "realloc", "retry", "%ld bytes", allocatesSize);     
                buffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, NULL, "Serialize error");
                KeyIso_free(buffer);
                return NULL;
            }
        } else { //SerializeStatus_Success
            return buffer;
        }
    } 
    KeyIso_free(buffer);
    return NULL;
}

static bool _get_gen_ec_key_pair_out_dynamic_len(const uint8_t *encodedSt, size_t encodedLen, uint32_t *dynamicSizeRes)
{
    bool isSumResValid = false;
    uint32_t dynamicSize = 0;

    if (_get_len_enc_priv_key(encodedSt,encodedLen, &dynamicSize)) { 
        int64_t ecPubKeyLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_PUBLIC_KEY_LEN);
        if (ecPubKeyLen >= 0 && ecPubKeyLen <= UINT32_MAX) {                 
            if(!KEYISO_ADD_OVERFLOW((uint32_t)ecPubKeyLen, dynamicSize, dynamicSizeRes)) {   // Safe cast after boundaries check                                        
                isSumResValid = true;
            }   
        }
    }
    return isSumResValid; // In case of invalid input or overflow we will return false
}

size_t KeyIso_get_len_gen_ec_key_pair_out(const uint8_t *encodedSt, size_t encodedLen)
{
    uint32_t genEcKeyPairOutDynamicLen = 0;
    
    // get the dynamic length of the structure    
    if (_get_gen_ec_key_pair_out_dynamic_len(encodedSt, encodedLen, &genEcKeyPairOutDynamicLen) == false) {
        return 0;
    }

    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_GEN_EC_KEY_PAIR_OUT_ST, genEcKeyPairOutDynamicLen);
}


int KeyIso_deserialize_gen_ec_key_pair_out(const uint8_t *encodedSt, size_t encodedLen, KEYISO_GEN_EC_KEY_PAIR_OUT_ST* decodedSt)
{  
    SerializeStatus status = _decode_gen_ec_key_pair_out_st(encodedSt, encodedLen, decodedSt);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}


/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    IMPORT RSA PRIVATE KEY IN
*/
static SerializeStatus _encode_import_rsa_priv_key_in_st(KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_IMPORT_RSA_PRIV_KEY_IN_ELEMENTS))

    // Encode headerSt
    CBOR_CHECK_STATUS(encode_header_in_st(&mapEncoder, &stToEncode->headerSt))
    
    // Encode RSA private key
    CBOR_CHECK_STATUS(_encode_rsa_pkey_st(&mapEncoder, &stToEncode->pkeySt))

    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))

    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;   
}

static SerializeStatus _decode_import_rsa_priv_key_in_st(const uint8_t *buffer, size_t bufferSize, KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST *decodedSt)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, NULL, "invalid format");
        return SerializeStatus_InvalidFormat;
    }

    // Decode header
    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_in_st(&map, &decodedSt->headerSt, IpcCommand_ImportRsaPrivateKey))

    // Decode RSA pkey
    CBOR_CHECK_STATUS(_decode_rsa_pkey_st(&map, &decodedSt->pkeySt))

    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}


uint8_t* KeyIso_serialize_import_rsa_priv_key_in(const void *stToEncode, size_t *encodedLen)
{
    size_t allocatesSize = sizeof(KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST)*SIZE_MULTIPLE_TO_ALLOC_IN_STRUCT + KeyIso_get_rsa_pkey_bytes_len(&((KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST*)stToEncode)->pkeySt);
    size_t oldSize = 0;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
    int8_t counter = 0;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_import_rsa_priv_key_in_st((KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST*)stToEncode, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {   
                oldSize = allocatesSize;          
                allocatesSize *= REALLOC_MULTIPLE;  
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_GEN_KEY_TITLE, "realloc", "retry", "%ld bytes", allocatesSize);     
                buffer = (uint8_t*)KeyIso_clear_realloc(buffer, oldSize, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, NULL, "Serialize error");
                KeyIso_free(buffer);
                return NULL;
            }
        } else { //SerializeStatus_Success
            return buffer;
        }
    } 
    KeyIso_free(buffer);
    return NULL;
}

static bool _get_rsa_pkey_dynamic_len(const uint8_t *encodedSt, size_t encodedLen, uint32_t* paramSumRes)
{
    bool isSumResValid;        
    int64_t rsaModulusLen = get_dynamic_len_nested(encodedSt, encodedLen, CBOR_PARAM_RSA_MODULUS_LEN, CBOR_PARAM_PKEY);
    int64_t rsaPublicExpLen = get_dynamic_len_nested(encodedSt, encodedLen, CBOR_PARAM_RSA_PUBLIC_EXP_LEN, CBOR_PARAM_PKEY);
    int64_t rsaPrimes1Len = get_dynamic_len_nested(encodedSt, encodedLen, CBOR_PARAM_RSA_PRIME1_LEN, CBOR_PARAM_PKEY);
    int64_t rsaPrimes2Len = get_dynamic_len_nested(encodedSt, encodedLen, CBOR_PARAM_RSA_PRIME2_LEN, CBOR_PARAM_PKEY);

    if (rsaModulusLen < 0 || rsaPublicExpLen < 0 || rsaPrimes1Len < 0 || rsaPrimes2Len < 0) {
        isSumResValid = false; // In case of invalid input

    } else if (rsaModulusLen > UINT32_MAX || rsaPublicExpLen > UINT32_MAX || rsaPrimes1Len > UINT32_MAX || rsaPrimes2Len > UINT32_MAX) {
        isSumResValid = false; // In case of invalid input
    }
    else {        
        // After verifying the input boundaries, we can safely cast the values to uint32_t    
        if (!KEYISO_ADD_OVERFLOW((uint32_t)rsaModulusLen, (uint32_t)rsaPublicExpLen, paramSumRes) &&
            !KEYISO_ADD_OVERFLOW(*paramSumRes, (uint32_t)rsaPrimes1Len, paramSumRes) &&
            !KEYISO_ADD_OVERFLOW(*paramSumRes, (uint32_t)rsaPrimes2Len, paramSumRes)) {
            isSumResValid = true; // The sum of all parameters is valid
        } else {        
            isSumResValid = false; // In case of overflow 
        }  
    }
    return isSumResValid;
}

size_t KeyIso_get_len_import_rsa_priv_key_in(const uint8_t *encodedSt, size_t encodedLen)
{
    uint32_t dynamicLen = 0;

    if (_get_rsa_pkey_dynamic_len(encodedSt, encodedLen, &dynamicLen) == false) {
        return 0;
    }
    
    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST, dynamicLen);
}

int KeyIso_deserialize_import_rsa_priv_key_in(const uint8_t *encodedSt, size_t encodedLen, void* decodedSt)
{  
    SerializeStatus status = _decode_import_rsa_priv_key_in_st(encodedSt, encodedLen, (KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST*)decodedSt);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    IMPORT EC PRIVATE KEY IN
*/
static SerializeStatus _encode_import_ec_priv_key_in_st(KEYISO_IMPORT_EC_PRIV_KEY_IN_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_IMPORT_EC_PRIV_KEY_IN_ELEMENTS))

    // Encode headerSt
    CBOR_CHECK_STATUS(encode_header_in_st(&mapEncoder, &stToEncode->headerSt))

    CBOR_CHECK_STATUS(_encode_ec_pkey_st(&mapEncoder, &stToEncode->pkeySt))

    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))

    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;   
}

static SerializeStatus _decode_import_ec_priv_key_in_st(const uint8_t *buffer, size_t bufferSize, KEYISO_IMPORT_EC_PRIV_KEY_IN_ST *decodedSt)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };

    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, NULL, "invalid format");
        return SerializeStatus_InvalidFormat;
    }

    // Decode header
    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_in_st(&map, &decodedSt->headerSt, IpcCommand_ImportEcPrivateKey))

    // Decode EC pkey
    CBOR_CHECK_STATUS(_decode_ec_pkey_st(&map, &decodedSt->pkeySt))
   
    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}


uint8_t* KeyIso_serialize_import_ec_priv_key_in(const void *stToEncode, size_t *encodedLen)
{
    int8_t counter = 0;
    int oldSize = 0;
    size_t allocatesSize = sizeof(KEYISO_IMPORT_EC_PRIV_KEY_IN_ST)*SIZE_MULTIPLE_TO_ALLOC_IN_STRUCT +
                           KeyIso_get_ec_pkey_bytes_len(&((KEYISO_IMPORT_EC_PRIV_KEY_IN_ST*)stToEncode)->pkeySt);
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize); // KeyIso_clear_free()
    
    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Memory allocation", "Failed");
        return NULL;
    }
    
    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_import_ec_priv_key_in_st((KEYISO_IMPORT_EC_PRIV_KEY_IN_ST*)stToEncode, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {  
                oldSize = allocatesSize;
                allocatesSize *= REALLOC_MULTIPLE;
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_GEN_KEY_TITLE, "realloc", "retry", "%ld bytes", allocatesSize);
                buffer = (uint8_t*)KeyIso_clear_realloc(buffer, oldSize, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, NULL, "Serialize error");
                KeyIso_clear_free(buffer, allocatesSize);
                return NULL;
            }
        } else { //SerializeStatus_Success
            return buffer;
        }
    } 
    KeyIso_clear_free(buffer, allocatesSize);
    return NULL;
}
static bool _get_ec_pkey_dynamic_len(const uint8_t *encodedSt, size_t encodedLen, uint32_t* paramSumRes)
{
    bool isSumResValid;        
    int64_t ecPubXLen = get_dynamic_len_nested(encodedSt, encodedLen, CBOR_PARAM_EC_PUB_X_LEN, CBOR_PARAM_PKEY);
    int64_t ecPubYLen = get_dynamic_len_nested(encodedSt, encodedLen, CBOR_PARAM_EC_PUB_Y_LEN, CBOR_PARAM_PKEY);
    int64_t ecPrivKeyLen = get_dynamic_len_nested(encodedSt, encodedLen, CBOR_PARAM_EC_PRIVATE_KEY_LEN, CBOR_PARAM_PKEY);
    
    if (ecPubXLen < 0 || ecPubYLen < 0 || ecPrivKeyLen < 0) {
        isSumResValid = false; // In case of invalid input

    } else if (ecPubXLen > UINT32_MAX || ecPubYLen > UINT32_MAX || ecPrivKeyLen > UINT32_MAX) {
        isSumResValid = false; // In case of invalid input
    }
    else {        
        // After verifying the input boundaries, we can safely cast the values to uint32_t    
        if (!KEYISO_ADD_OVERFLOW((uint32_t)ecPubXLen, (uint32_t)ecPubYLen, paramSumRes) &&
            !KEYISO_ADD_OVERFLOW(*paramSumRes, (uint32_t)ecPrivKeyLen, paramSumRes)) {
            isSumResValid = true; // The sum of all parameters is valid
        } else {        
            isSumResValid = false; // In case of overflow 
        }  
    }

    return isSumResValid;
}

size_t KeyIso_get_len_import_ec_priv_key_in(const uint8_t *encodedSt, size_t encodedLen)
{
    uint32_t dynamicLen = 0;

    if (_get_ec_pkey_dynamic_len(encodedSt, encodedLen, &dynamicLen) == false) {
        return 0;
    }
    
    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_IMPORT_EC_PRIV_KEY_IN_ST, dynamicLen);
}


int KeyIso_deserialize_import_ec_priv_key_in(const uint8_t *encodedSt, size_t encodedLen, void* decodedSt)
{  
    SerializeStatus status = _decode_import_ec_priv_key_in_st(encodedSt, encodedLen, (KEYISO_IMPORT_EC_PRIV_KEY_IN_ST*)decodedSt);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}


/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    IMPORT PRIVATE KEY OUT
*/

static SerializeStatus _encode_import_priv_key_out_st(KEYISO_IMPORT_PRIV_KEY_OUT_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_IMPORT_PRIV_KEY_OUT_ELEMENTS))

    // Encode headerSt
    CBOR_CHECK_STATUS(encode_header_out_st(&mapEncoder, &stToEncode->headerSt))

    // Encode secretSalt  
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SECRET_SALT))
    CBOR_OPERATION(cbor_encode_text_string(&mapEncoder, (char*)stToEncode->secretSalt, sizeof(stToEncode->secretSalt)))

    // Encode encKeySt
    CBOR_CHECK_STATUS(_encode_enc_priv_key_st(&mapEncoder, &stToEncode->encKeySt))

    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))
    
    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;   
}

static SerializeStatus _decode_import_priv_key_out_st(const uint8_t *buffer, size_t bufferSize, KEYISO_IMPORT_PRIV_KEY_OUT_ST *decodedSt, IpcCommand command)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, NULL, "invalid format");
        return SerializeStatus_InvalidFormat;
    }

    // header
    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_out_st(&map, &decodedSt->headerSt, command))

    // secretSalt  
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_SECRET_SALT))
    size_t size;
    CBOR_OPERATION(cbor_value_get_string_length(&map, &size))
    CBOR_OPERATION(cbor_value_copy_text_string(&map, (char*)decodedSt->secretSalt, &size, &map))

    // encKey
    CBOR_CHECK_STATUS(_decode_enc_priv_key_st(&map, &decodedSt->encKeySt))
   
    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}

uint8_t* KeyIso_serialize_import_priv_key_out(void *stToEncode, size_t *encodedLen)
{
    KEYISO_IMPORT_PRIV_KEY_OUT_ST *st = (KEYISO_IMPORT_PRIV_KEY_OUT_ST*)stToEncode;
    size_t dynamicBytes = KeyIso_get_enc_key_bytes_len(NULL, st->encKeySt.saltLen, st->encKeySt.ivLen, st->encKeySt.hmacLen, st->encKeySt.encKeyLen);
    size_t allocatesSize = sizeof(KEYISO_IMPORT_PRIV_KEY_OUT_ST) * SIZE_MULTIPLE_TO_ALLOC_OUT_STRUCT + dynamicBytes;
    size_t oldSize = 0;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize); // KeyIso_clear_free()
    int8_t counter = 0;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_import_priv_key_out_st((KEYISO_IMPORT_PRIV_KEY_OUT_ST*)stToEncode, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {   
                oldSize = allocatesSize;
                allocatesSize *= REALLOC_MULTIPLE;  
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_GEN_KEY_TITLE, "realloc", "retry", "%ld bytes", allocatesSize);     
                buffer = (uint8_t*)KeyIso_clear_realloc(buffer, oldSize, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, NULL, "Serialize error");
                KeyIso_clear_free(buffer, allocatesSize);
                return NULL;
            }
        } else { //SerializeStatus_Success
            return buffer;
        }
    } 
    KeyIso_clear_free(buffer, allocatesSize);
    return NULL;
}

size_t KeyIso_get_len_import_priv_key_out(const uint8_t *encodedSt, size_t encodedLen)
{
    uint32_t structDynamicSize = 0;

    if (!_get_len_nested_enc_priv_key(encodedSt, encodedLen, &structDynamicSize)) {
        return 0;
    }
    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_IMPORT_PRIV_KEY_OUT_ST, structDynamicSize);    
}

int KeyIso_deserialize_import_rsa_priv_key_out(const uint8_t *encodedSt, size_t encodedLen, KEYISO_IMPORT_PRIV_KEY_OUT_ST* decodedSt)
{
    SerializeStatus status = _decode_import_priv_key_out_st(encodedSt, encodedLen, decodedSt, IpcCommand_ImportRsaPrivateKey);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}

int KeyIso_deserialize_import_ec_priv_key_out(const uint8_t *encodedSt, size_t encodedLen, KEYISO_IMPORT_PRIV_KEY_OUT_ST* decodedSt)
{
    SerializeStatus status = _decode_import_priv_key_out_st(encodedSt, encodedLen, decodedSt, IpcCommand_ImportEcPrivateKey);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    Import Symmetric key IN
*/

static SerializeStatus _encode_import_symmetric_key_in_st(KEYISO_IMPORT_SYMMETRIC_KEY_IN_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_IMPORT_SYMMETRIC_KEY_IN_ELEMENTS))

    // Encode headerSt
    CBOR_CHECK_STATUS(encode_header_in_st(&mapEncoder, &stToEncode->headerSt))

    // Encode Key Type
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SYMMETRIC_KEY_TYPE))
    CBOR_OPERATION(cbor_encode_int(&mapEncoder, (int64_t)stToEncode->symmetricKeyType))

    // Encode Import Key ID
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SYMMETRIC_IMPORT_KEY_ID))
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->importKeyId, sizeof(stToEncode->importKeyId)))

    // Encode Key Length
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SYMMETRIC_KEY_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->keyLen))

    // Encode Key Bytes
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SYMMETRIC_KEY_BYTES))    
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->keyBytes, stToEncode->keyLen))

    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))

    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;   
}

static SerializeStatus _decode_import_symmetric_key_in_st(const uint8_t *buffer, size_t bufferSize, KEYISO_IMPORT_SYMMETRIC_KEY_IN_ST *decodedSt)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_SYMMETRIC_KEY_TITLE, NULL, "invalid format");
        return SerializeStatus_InvalidFormat;
    }

    // Decode header
    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_in_st(&map, &decodedSt->headerSt, IpcCommand_ImportSymmetricKey))

    // Decode Key Type
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_SYMMETRIC_KEY_TYPE))        
    CBOR_CHECK_STATUS(get_int32_val(&map, &decodedSt->symmetricKeyType))

    // Decode Import Key ID
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_SYMMETRIC_IMPORT_KEY_ID))        
    size_t size;
    CBOR_OPERATION(cbor_value_get_string_length(&map, &size))
    CBOR_OPERATION(cbor_value_copy_byte_string(&map, decodedSt->importKeyId, &size, &map))

    // Decode Key Length
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_SYMMETRIC_KEY_LEN))        
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->keyLen))

    // Decode Dynamic Bytes
    CBOR_CHECK_STATUS(decode_string_ptr_by_len(&map, decodedSt->keyLen, CBOR_PARAM_SYMMETRIC_KEY_BYTES, decodedSt->keyBytes))

    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}

uint8_t* KeyIso_serialize_import_symmetric_key_in(const void* stToEncode, size_t *encodedLen)
{
    size_t allocatesSize = sizeof(KEYISO_IMPORT_SYMMETRIC_KEY_IN_ST) * SIZE_MULTIPLE_TO_ALLOC_IN_STRUCT + ((KEYISO_IMPORT_SYMMETRIC_KEY_IN_ST*)stToEncode)->keyLen;
    size_t oldSize = 0;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize); // KeyIso_clear_free()
    int8_t counter = 0;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_SYMMETRIC_KEY_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_import_symmetric_key_in_st((KEYISO_IMPORT_SYMMETRIC_KEY_IN_ST*)stToEncode, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {  
                oldSize = allocatesSize;      
                allocatesSize *= REALLOC_MULTIPLE;  
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_IMPORT_SYMMETRIC_KEY_TITLE, "realloc", "retry", "%ld bytes", allocatesSize);     
                buffer = (uint8_t*)KeyIso_clear_realloc(buffer, oldSize, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_SYMMETRIC_KEY_TITLE, NULL, "Serialize error");
                KeyIso_clear_free(buffer, allocatesSize);
                return NULL;
            }
        } else { //SerializeStatus_Success
            return buffer;
        }
    } 
    KeyIso_clear_free(buffer, allocatesSize);
    return NULL;
}

size_t KeyIso_get_len_import_symmetric_key_in(const uint8_t *encodedSt, size_t encodedLen)
{
    int64_t dynamicSize = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_SYMMETRIC_KEY_LEN);

    // keyLen field boundaries check
    if (dynamicSize < 0 || dynamicSize > UINT32_MAX) {
        return 0;
    }

    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_IMPORT_SYMMETRIC_KEY_IN_ST, dynamicSize);
}

int KeyIso_deserialize_import_symmetric_key_in(const uint8_t *encodedSt, size_t encodedLen, void* decodedSt)
{
    SerializeStatus status = _decode_import_symmetric_key_in_st(encodedSt, encodedLen, (KEYISO_IMPORT_SYMMETRIC_KEY_IN_ST*)decodedSt);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    Import Symmetric key OUT
*/

static SerializeStatus _encode_import_symmetric_key_out_st(KEYISO_IMPORT_SYMMETRIC_KEY_OUT_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_IMPORT_SYMMETRIC_KEY_OUT_ELEMENTS))

    // Encode headerSt
    CBOR_CHECK_STATUS(encode_header_out_st(&mapEncoder, &stToEncode->headerSt))

    // Encode Encrypted Key Length
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SYMMETRIC_ENC_KEY_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->encryptedKeyLen))

    // Encode Bytes
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SYMMETRIC_ENC_KEY_BYTES))  
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->encryptedKeyBytes, stToEncode->encryptedKeyLen))

    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))

    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;   
}

static SerializeStatus _decode_import_symmetric_key_out_st(const uint8_t *buffer, size_t bufferSize, KEYISO_IMPORT_SYMMETRIC_KEY_OUT_ST *decodedSt)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_SYMMETRIC_KEY_TITLE, NULL, "invalid format");
        return SerializeStatus_InvalidFormat;
    }

    // Decode header
    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_out_st(&map, &decodedSt->headerSt, IpcCommand_ImportSymmetricKey))

    // Decode Encrypted Key Length
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_SYMMETRIC_ENC_KEY_LEN))        
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->encryptedKeyLen))

    // Decode Dynamic Bytes
    CBOR_CHECK_STATUS(decode_string_ptr_by_len(&map, decodedSt->encryptedKeyLen, CBOR_PARAM_SYMMETRIC_ENC_KEY_BYTES, decodedSt->encryptedKeyBytes))

    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}

uint8_t* KeyIso_serialize_import_symmetric_key_out(void *stToEncode, size_t *encodedLen)
{
    size_t totalBuflen = ((KEYISO_IMPORT_SYMMETRIC_KEY_OUT_ST*)stToEncode)->encryptedKeyLen;

    size_t allocatesSize = sizeof(KEYISO_IMPORT_SYMMETRIC_KEY_OUT_ST) * SIZE_MULTIPLE_TO_ALLOC_OUT_STRUCT + totalBuflen;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
    int8_t counter = 0;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_SYMMETRIC_KEY_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_import_symmetric_key_out_st((KEYISO_IMPORT_SYMMETRIC_KEY_OUT_ST*)stToEncode, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {                
                allocatesSize *= REALLOC_MULTIPLE;  
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_IMPORT_SYMMETRIC_KEY_TITLE, "realloc", "retry", "%ld bytes", allocatesSize);     
                buffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_SYMMETRIC_KEY_TITLE, NULL, "Serialize error");
                KeyIso_free(buffer);
                return NULL;
            }
        } else { //SerializeStatus_Success
            return buffer;
        }
    } 
    KeyIso_free(buffer);
    return NULL;
}

size_t KeyIso_get_len_import_symmetric_key_out(const uint8_t *encodedSt, size_t encodedLen)
{
    int64_t dynamicSize =  
      get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_SYMMETRIC_ENC_KEY_LEN);

    // encryptedKeyLen field boundaries check
    if (dynamicSize < 0 || dynamicSize > UINT32_MAX) {
        return 0;
    }

    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_IMPORT_SYMMETRIC_KEY_OUT_ST, dynamicSize);
}

int KeyIso_deserialize_import_symmetric_key_out(const uint8_t *encodedSt, size_t encodedLen, KEYISO_IMPORT_SYMMETRIC_KEY_OUT_ST* decodedSt)
{
    SerializeStatus status = _decode_import_symmetric_key_out_st(encodedSt, encodedLen, decodedSt);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}



/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    Symmetric key Enc Dec IN
*/

static uint64_t _get_enc_dec_symmetric_key_in_len(const KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST *stToEncode)
{
    if(stToEncode) {
        return    
         stToEncode->encryptedKeyLen + 
         stToEncode->fromBytesLen;
    }
    return 0;
}

static SerializeStatus _encode_enc_dec_symmetric_key_in_st(KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_SYMMETRIC_ENCRYPT_DECRYPT_IN_ELEMENTS))

    // Encode headerSt
    CBOR_CHECK_STATUS(encode_header_in_st(&mapEncoder, &stToEncode->headerSt))

    // Encode Decrypt
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SYMMETRIC_DECRYPT))
    CBOR_OPERATION(cbor_encode_int(&mapEncoder, (int64_t)stToEncode->decrypt))

    // Encode Encrypted Key Length
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SYMMETRIC_ENC_KEY_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->encryptedKeyLen))

    // Encode Bytes Length
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SYMMETRIC_FROM_BYTES_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->fromBytesLen))
    
    // Encode Dynamic Bytes
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SYMMETRIC_ENC_KEY_BYTES))    
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->encDecBytes, _get_enc_dec_symmetric_key_in_len(stToEncode)))

    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))

    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;   
}

static SerializeStatus _decode_enc_dec_symmetric_key_in_st(const uint8_t *buffer, size_t bufferSize, KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST *decodedSt)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_SYMMETRIC_ENC_DEC_TITLE, NULL, "invalid format");
        return SerializeStatus_InvalidFormat;
    }

    // Decode header
    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_in_st(&map, &decodedSt->headerSt, IpcCommand_SymmetricKeyEncryptDecrypt))
    
    // Decode Decrypt
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_SYMMETRIC_DECRYPT))        
    CBOR_CHECK_STATUS(get_int32_val(&map, &decodedSt->decrypt))

    // Decode Encrypted Key Length
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_SYMMETRIC_ENC_KEY_LEN))        
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->encryptedKeyLen))

    // Decode Bytes Length
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_SYMMETRIC_FROM_BYTES_LEN))        
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->fromBytesLen))
        
    // Decode Dynamic Bytes
    CBOR_CHECK_STATUS(decode_string_ptr_by_len(&map, _get_enc_dec_symmetric_key_in_len(decodedSt), CBOR_PARAM_SYMMETRIC_ENC_KEY_BYTES, decodedSt->encDecBytes))

    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}

uint8_t* KeyIso_serialize_enc_dec_symmetric_key_in(const void* stToEncode, size_t *encodedLen)
{
    size_t totalBuflen = _get_enc_dec_symmetric_key_in_len((KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST*)stToEncode);

    size_t allocatesSize = sizeof(KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST) * SIZE_MULTIPLE_TO_ALLOC_IN_STRUCT + totalBuflen;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
    int8_t counter = 0;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_SYMMETRIC_ENC_DEC_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_enc_dec_symmetric_key_in_st((KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST*)stToEncode, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {                
                allocatesSize *= REALLOC_MULTIPLE;  
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_SYMMETRIC_ENC_DEC_TITLE, "realloc", "retry", "%ld bytes", allocatesSize);     
                buffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_SYMMETRIC_ENC_DEC_TITLE, NULL, "Serialize error");
                KeyIso_free(buffer);
                return NULL;
            }
        } else { //SerializeStatus_Success
            return buffer;
        }
    } 
    KeyIso_free(buffer);
    return NULL;
}

size_t KeyIso_get_len_enc_dec_symmetric_key_in(const uint8_t *encodedSt, size_t encodedLen)
{
    int64_t encryptedKeyLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_SYMMETRIC_ENC_KEY_LEN);
    int64_t fromBytesLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_SYMMETRIC_FROM_BYTES_LEN);

    // encryptedKeyLen and fromBytesLen fields boundaries check (both are uint32_t)
    if (encryptedKeyLen < 0 || fromBytesLen < 0 || encryptedKeyLen > UINT32_MAX || fromBytesLen > UINT32_MAX) {
        return 0;
    }

    uint32_t dynamicSize = 0;
    // After verifying the input boundaries, we can safely cast the values to uint32_t and calculate the dynamic size    
    if (KEYISO_ADD_OVERFLOW((uint32_t)encryptedKeyLen, (uint32_t)fromBytesLen, &dynamicSize)) {
        return 0;
    }

    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST, dynamicSize);
}

int KeyIso_deserialize_enc_dec_symmetric_key_in(const uint8_t *encodedSt, size_t encodedLen, void* decodedSt)
{
    SerializeStatus status = _decode_enc_dec_symmetric_key_in_st(encodedSt, encodedLen, (KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST*)decodedSt);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    Symmetric key Enc Dec OUT
*/

static SerializeStatus _encode_enc_dec_symmetric_key_out_st(KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_OUT_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_SYMMETRIC_ENCRYPT_DECRYPT_OUT_ELEMENTS))

    // Encode headerSt
    CBOR_CHECK_STATUS(encode_header_out_st(&mapEncoder, &stToEncode->headerSt))

    // Encode Bytes Length
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SYMMETRIC_BYTES_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, stToEncode->bytesLen))

   // Encode keyBytes
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_SYMMETRIC_KEY_BYTES))    
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->toBytes, stToEncode->bytesLen))

    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))

    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;   
}

static SerializeStatus _decode_enc_dec_symmetric_key_out_st(const uint8_t *buffer, size_t bufferSize, KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_OUT_ST *decodedSt)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_SYMMETRIC_ENC_DEC_TITLE, NULL, "invalid format");
        return SerializeStatus_InvalidFormat;
    }

    // Decode header
    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_out_st(&map, &decodedSt->headerSt, IpcCommand_SymmetricKeyEncryptDecrypt))
    
    // Decode Bytes
    CBOR_CHECK_STATUS(decode_string_ptr_unsigned(&map, CBOR_PARAM_SYMMETRIC_BYTES_LEN, &decodedSt->bytesLen, CBOR_PARAM_SYMMETRIC_KEY_BYTES, decodedSt->toBytes))

    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}

uint8_t* KeyIso_serialize_enc_dec_symmetric_key_out(const void *stToEncode, size_t *encodedLen)
{
    size_t allocatesSize = sizeof(KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_OUT_ST) * SIZE_MULTIPLE_TO_ALLOC_OUT_STRUCT + ((KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_OUT_ST*)stToEncode)->bytesLen;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
    int8_t counter = 0;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_SYMMETRIC_ENC_DEC_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_enc_dec_symmetric_key_out_st((KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_OUT_ST*)stToEncode, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {                
                allocatesSize *= REALLOC_MULTIPLE;  
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_SYMMETRIC_ENC_DEC_TITLE, "realloc", "retry", "%ld bytes", allocatesSize);     
                buffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_SYMMETRIC_ENC_DEC_TITLE, NULL, "Serialize error");
                KeyIso_free(buffer);
                return NULL;
            }
        } else { //SerializeStatus_Success
            return buffer;
        }
    } 
    KeyIso_free(buffer);
    return NULL;

}

size_t KeyIso_get_len_enc_dec_symmetric_key_out(const uint8_t *encodedSt, size_t encodedLen)
{
    int64_t dynamicSize = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_SYMMETRIC_BYTES_LEN);

    // bytesLen field boundaries check
    if (dynamicSize < 0 || dynamicSize > UINT32_MAX) {
        return 0;
    }

    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_OUT_ST, dynamicSize);
}

int KeyIso_deserialize_enc_dec_symmetric_key_out(const uint8_t *encodedSt, size_t encodedLen, KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_OUT_ST* decodedSt)
{
    SerializeStatus status = _decode_enc_dec_symmetric_key_out_st(encodedSt, encodedLen, decodedSt);
    return (status == SerializeStatus_Success) ? STATUS_OK : STATUS_FAILED;
}