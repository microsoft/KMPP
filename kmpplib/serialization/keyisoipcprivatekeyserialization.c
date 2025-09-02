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
#define CBOR_PARAM_ENCRYPTED_KEY_LEN              "encKeyLen"
#define CBOR_PARAM_ENC_KEY_BYTES                  "encKeyBytes"
#define CBOR_PARAM_ENC_KEY                        "encKey"
#define CBOR_PARAM_KEY_LEN                        "keyBytesLen"
#define CBOR_PARAM_KEY_BYTES                      "keyBytes"
#define CBOR_PARAM_PKEY                           "pkey"
#define CBOR_PARAM_PUBLIC_KEY_LEN                 "publicKeyLen"
#define CBOR_PARAM_ENCRYPTED_KEY_PAIR_BYTES       "encKeyBytes"
#define CBOR_PARAM_KEY_USAGE                      "keyUsage"
#define CBOR_PARAM_KEY_HEADER                     "keyHeader"
#define CBOR_PARAM_MAGIC                          "magic"
#define CBOR_PARAM_KEY_VERSION                    "keyVersion"
#define CBOR_PARAM_RSA_ENC_DEC_WITH_KEY_BYTES     "rsaEncDecWithKeyBytes"
#define CBOR_PARAM_RSA_ENC_DEC_WITH_KEY_BYTES_LEN "rsaEncDecWithKeyBytesLen"
#define CBOR_PARAM_ECC_SIGN_WITH_KEY_BYTES        "eccSignWithKeyBytes"
#define CBOR_PARAM_ECC_SIGN_WITH_KEY_BYTES_LEN    "eccSignWithKeyBytesLen"
#define CBOR_PARAM_DATA                           "data"
#define CBOR_PARAM_OPAQUE_KEY_LEN                 "opaqueKeyLen"
#define CBOR_PARAM_PUBLIC_KEY_LEN                 "publicKeyLen"

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
                uint8_t* newBuffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                if (!newBuffer) {
                    KeyIso_free(buffer);
                    return NULL;
                }
                buffer = newBuffer;
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
                uint8_t* newBuffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                if (!newBuffer) {
                    KeyIso_free(buffer);
                    return NULL;
                }
                buffer = newBuffer;
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
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, KEYISOP_ENGINE_TITLE, "realloc", "retry", "%zu bytes", allocatesSize);     
                uint8_t* newBuffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                if (!newBuffer) {
                    KeyIso_free(buffer);
                    return NULL;
                }
                buffer = newBuffer;
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
    if (dynamicSize < 0 || dynamicSize > UINT32_MAX) {
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

    // Encode client metadata header
    CBOR_CHECK_STATUS(encode_client_metadata_header_in_st(&mapEncoder, &stToEncode->clientDataHeader))

    // Encode key lengths
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_PUBLIC_KEY_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, stToEncode->publicKeyLen))

    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_OPAQUE_KEY_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, stToEncode->opaqueEncryptedKeyLen))

    // Encode sign operation parameters
    CBOR_CHECK_STATUS(_ecode_ecdsa_sign_op_params_to_map(&mapEncoder, stToEncode->type, stToEncode->sigLen, stToEncode->digestLen))

    // Encode the concatenated data array containing encrypted key and digest 
    uint32_t totalBuflen = 0;
    if (KeyIso_get_ecdsa_sign_with_attached_key_in_dynamic_bytes_len(NULL, stToEncode->publicKeyLen, stToEncode->opaqueEncryptedKeyLen, stToEncode->digestLen, &totalBuflen) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid format", "Invalid dynamic size");
        return SerializeStatus_InvalidLen;
    }
    
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_DATA))
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->data, totalBuflen))
    
    // Close the top-level map
    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))
    
    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;
}

size_t KeyIso_get_len_ecdsa_sign_with_attached_key_in(const uint8_t *encodedSt, size_t encodedLen)
{
    int64_t publicKeyLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_PUBLIC_KEY_LEN);
    int64_t encryptedKeyLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_OPAQUE_KEY_LEN);
    int64_t sigLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_SIGNATURE_LEN);
    int64_t digestLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_DIGEST_LEN);

    if (publicKeyLen < 0 || encryptedKeyLen < 0 || sigLen < 0 || digestLen < 0) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid format", "Invalid length");
        return 0;
    }
    
    if (publicKeyLen > UINT32_MAX || encryptedKeyLen > UINT32_MAX || sigLen > UINT32_MAX || digestLen > UINT32_MAX) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid format", "Invalid length");
        return 0;
    }

    // Calculate dynamic size
    uint32_t dynamicSize = 0;
    if (KeyIso_get_ecdsa_sign_with_attached_key_in_dynamic_bytes_len(NULL, (uint32_t)publicKeyLen, (uint32_t)encryptedKeyLen, (uint32_t)digestLen, &dynamicSize) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid format", "Invalid dynamic size");
        return 0;
    }

    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_IN_ST, dynamicSize);
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

    // Decode client metadata header
    CBOR_CHECK_STATUS(decode_client_metadata_header_in_st(&map, &decodedSt->clientDataHeader))

    // Decode key lengths
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_PUBLIC_KEY_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->publicKeyLen))
    
    // Decode opaque encrypted key length
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_OPAQUE_KEY_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->opaqueEncryptedKeyLen))

    // Decode sign operation parameters
    CBOR_CHECK_STATUS(_decode_ecdsa_sign_op_params_to_map(&map, &decodedSt->type, &decodedSt->sigLen, &decodedSt->digestLen))

    // Calculate total buffer length
    uint32_t totalBuflen = 0;
    if (KeyIso_get_ecdsa_sign_with_attached_key_in_dynamic_bytes_len(NULL, decodedSt->publicKeyLen, decodedSt->opaqueEncryptedKeyLen, decodedSt->digestLen, &totalBuflen) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid format", "Invalid dynamic size");
        return SerializeStatus_InvalidLen;
    }

    // Decode data bytes
    CBOR_CHECK_STATUS(decode_string_ptr_by_len(&map, (uint32_t)totalBuflen, CBOR_PARAM_DATA, decodedSt->data))

    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}

uint8_t* KeyIso_serialize_ecdsa_sign_with_attached_key_in(const void *stToEncode, size_t *encodedLen)
{
    KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_IN_ST* inSt = (KEYISO_ECDSA_SIGN_WITH_ATTACHED_KEY_IN_ST*)stToEncode;
    uint32_t dynamicSize = 0;
    if (KeyIso_get_ecdsa_sign_with_attached_key_in_dynamic_bytes_len(NULL, inSt->publicKeyLen, inSt->opaqueEncryptedKeyLen, inSt->digestLen, &dynamicSize) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid format", "Invalid dynamic size");
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
                uint8_t* newBuffer = (uint8_t*)KeyIso_realloc(buffer, allocatesSize);
                if (!newBuffer) {
                    KeyIso_free(buffer);
                    return NULL;
                }
                buffer = newBuffer;
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
    if (dynamicSize < 0 || dynamicSize > UINT32_MAX) {
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
    uint32_t dynamicLen = 0;
    const char* title = KEYISOP_RSA_ENCRYPT_TITLE;
    if (KeyIso_get_rsa_enc_dec_params_dynamic_len(stToEncode->params.fromBytesLen, stToEncode->params.labelLen, &dynamicLen) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, title, "Invalid format", "Invalid dynamic size");
        return SerializeStatus_InvalidLen;
    }
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->params.bytes, dynamicLen)) 

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

size_t KeyIso_get_len_rsa_enc_dec_in(const uint8_t *encodedSt, size_t encodedLen)
{
    int64_t fromLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_FROM_LEN);
    int64_t labelLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_LABEL_LEN);

    // fromBytesLen field boundaries check
    if (fromLen < 0 || fromLen > UINT32_MAX || labelLen < 0 || labelLen > UINT32_MAX) {
        return 0;
    }

    uint32_t dynamicSize = 0;
    if (KEYISO_ADD_OVERFLOW((uint32_t)fromLen, (uint32_t)labelLen, &dynamicSize)) {
        return 0;
    }
   
    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_RSA_PRIVATE_ENC_DEC_IN_ST, dynamicSize);
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

    // Validate bytes tag
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_BYTES))
    
    // Get actual size of the byte string
    size_t byteStringSize = 0;
    CBOR_OPERATION(cbor_value_get_string_length(&map, &byteStringSize))
    
    // Calculate expected size - this is the sum of fromBytesLen and labelLen
    uint32_t expectedSize = 0;
    if (KeyIso_get_rsa_enc_dec_params_dynamic_len(decodedSt->params.fromBytesLen, decodedSt->params.labelLen, &expectedSize) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid dynamic length", "Failed to calculate expected size");
        return SerializeStatus_InvalidFormat;
    }
    
    // For safety, make sure the actual byte string is at least as large as fromBytesLen
    if (byteStringSize < (size_t)decodedSt->params.fromBytesLen) {
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid byte string length", 
                                   "Decode error", "actual=%zu, expected fromBytesLen=%d", 
                                   byteStringSize, decodedSt->params.fromBytesLen);
        return SerializeStatus_InvalidLen;
    }
    
    // Copy the byte string data
    size_t copySize = byteStringSize;
    CBOR_OPERATION(cbor_value_copy_byte_string(&map, decodedSt->params.bytes, &copySize, &map))
    
    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}
uint8_t* KeyIso_serialize_rsa_enc_dec_in(const void *stToEncode, size_t *encodedLen)
{
    KEYISO_RSA_PRIVATE_ENC_DEC_IN_ST* st = (KEYISO_RSA_PRIVATE_ENC_DEC_IN_ST*)stToEncode;
    uint32_t dynamicLen = 0;
    if (KeyIso_get_rsa_enc_dec_params_dynamic_len(st->params.fromBytesLen, st->params.labelLen, &dynamicLen) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "Invalid size");
        return NULL;
    }
    size_t allocatesSize = (sizeof(*st) * SIZE_MULTIPLE_TO_ALLOC_IN_STRUCT) + dynamicLen;
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
    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "SerializeStatus_InvalidFormat");
        return SerializeStatus_InvalidFormat;
    }

    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_out_st(&map, &decodedSt->headerSt, IpcCommand_RsaPrivateEncryptDecrypt))

    // Decode bytesLen and toBytes
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_TO_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->bytesLen))
    
    // Decode toBytes
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_TO_BYTES))
    size_t dataLen = decodedSt->bytesLen;
    CBOR_OPERATION(cbor_value_copy_byte_string(&map, decodedSt->toBytes, &dataLen, &map))
    
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
    
    // Encode client metadata header
    CBOR_CHECK_STATUS(encode_client_metadata_header_in_st(&mapEncoder, &stToEncode->clientDataHeader))

    // Encode publicKey length
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_PUBLIC_KEY_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, stToEncode->publicKeyLen))

    // Encode opaqueEncryptedKey length
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_OPAQUE_KEY_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, stToEncode->opaqueEncryptedKeyLen))

    // Encode encrypt/decrypt operation parameters
    CBOR_CHECK_STATUS(_encode_rsa_enc_dec_op_params_to_map(&mapEncoder, stToEncode->decrypt, stToEncode->padding, stToEncode->tlen, stToEncode->fromBytesLen, stToEncode->labelLen))

    uint32_t dynamicLen = 0;
    if (KeyIso_get_rsa_enc_dec_with_attached_key_in_dynamic_bytes_len(NULL, stToEncode->publicKeyLen, stToEncode->opaqueEncryptedKeyLen, stToEncode->fromBytesLen, stToEncode->labelLen, &dynamicLen) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid input", "Failed");
        return SerializeStatus_InvalidFormat;
    }

    // Encode the data array containing encrypted key and from/label bytes
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_DATA))
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->data, dynamicLen))

    // Close top-level container
    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))
    
    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);  
    return SerializeStatus_Success;    
}

size_t KeyIso_get_len_rsa_enc_dec_with_attached_key_in(const uint8_t *encodedSt, size_t encodedLen)
{
    int64_t fromLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_FROM_LEN);
    int64_t labelLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_LABEL_LEN);
    int64_t publicKeyLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_PUBLIC_KEY_LEN);
    int64_t opaqueKeyLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_OPAQUE_KEY_LEN);

    // Length field boundaries check
    if (fromLen < 0 || labelLen < 0 || publicKeyLen < 0 || opaqueKeyLen < 0 || 
        fromLen > UINT32_MAX || labelLen > INT32_MAX || publicKeyLen > UINT32_MAX || opaqueKeyLen > UINT32_MAX) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid input lengths", "Failed");
        return 0;
    }

    // Calculate total dynamic size
    uint32_t dynamicSize = 0;
    int status = KeyIso_get_rsa_enc_dec_with_attached_key_in_dynamic_bytes_len(
        NULL, 
        (uint32_t)publicKeyLen,
        (uint32_t)opaqueKeyLen,
        (uint32_t)fromLen,
        (uint32_t)labelLen,
        &dynamicSize);      
    if (status != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid input", "Failed to calculate dynamic size");
        return 0;
    }

    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_IN_ST, dynamicSize);
}

static SerializeStatus _decode_rsa_enc_dec_with_attached_key_st(const uint8_t *buffer, size_t bufferSize, 
    KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_IN_ST *decodedSt)
{
    CborError cborErr = CborNoError;
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    const char* title = KEYISOP_ENGINE_TITLE;

    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, title, NULL, "invalid format");
        return SerializeStatus_InvalidFormat;
    }

    // Enter the header map
    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_in_st(&map, &decodedSt->headerSt, IpcCommand_RsaPrivateEncryptDecryptWithAttachedKey))

    // Decode client metadata header
    CBOR_CHECK_STATUS(decode_client_metadata_header_in_st(&map, &decodedSt->clientDataHeader))

    // Decode publicKeyLen
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_PUBLIC_KEY_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->publicKeyLen))
    
    // Decode the opaqueEncryptedKeyLen 
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_OPAQUE_KEY_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->opaqueEncryptedKeyLen))

    // Decode encrypt/decrypt operation parameters
    CBOR_CHECK_STATUS(_decode_rsa_enc_dec_op_params_to_map(&map, &decodedSt->decrypt, &decodedSt->padding, &decodedSt->tlen, &decodedSt->fromBytesLen, &decodedSt->labelLen))

    uint32_t dynamicLen = 0;
    if (KeyIso_get_rsa_enc_dec_with_attached_key_in_dynamic_bytes_len(NULL, decodedSt->publicKeyLen, decodedSt->opaqueEncryptedKeyLen, decodedSt->fromBytesLen, decodedSt->labelLen, &dynamicLen) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid input", "Failed");
        return SerializeStatus_InvalidFormat;
    }

    // Get the data array
    CBOR_CHECK_STATUS(decode_string_ptr_by_len(&map, (uint32_t)dynamicLen, CBOR_PARAM_DATA, decodedSt->data))
    return SerializeStatus_Success;
}

uint8_t* KeyIso_serialize_rsa_enc_dec_with_attached_key_in(const void *stToEncode, size_t *encodedLen)
{
    KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_IN_ST *st = (KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_IN_ST*)stToEncode;
    uint32_t dynamicSize = 0;
    if (KeyIso_get_rsa_enc_dec_with_attached_key_in_dynamic_bytes_len(NULL, st->publicKeyLen, st->opaqueEncryptedKeyLen, st->fromBytesLen, st->labelLen, &dynamicSize) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid input", "Failed");
        return NULL;
    }
    
    int8_t counter = 0;
    const char* title = KEYISOP_ENGINE_TITLE;
    size_t allocatesSize = (sizeof(*st) * SIZE_MULTIPLE_TO_ALLOC_IN_STRUCT) + dynamicSize;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
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
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_OUT_ELEMENTS))
    CBOR_CHECK_STATUS(encode_header_out_st(&mapEncoder, &stToEncode->headerSt))    

    // Encode keyId
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_KEY_ID))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, stToEncode->keyId)) 

    // Encode bytesLen
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
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CborValue map = { 0 };
    const char* title = KEYISOP_ENGINE_TITLE;

    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, title, NULL, "invalid format");
        return SerializeStatus_InvalidFormat;
    }

    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_out_st(&map, &decodedSt->headerSt, IpcCommand_RsaPrivateEncryptDecryptWithAttachedKey))

    // Decode keyId
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_KEY_ID))
    CBOR_OPERATION(cbor_value_get_uint64(&map, &(decodedSt->keyId)))
    CBOR_OPERATION(cbor_value_advance_fixed(&map))

    // Decode bytesLen and toBytes
    CBOR_CHECK_STATUS(decode_string_ptr(&map, CBOR_PARAM_TO_LEN, &decodedSt->bytesLen, CBOR_PARAM_TO_BYTES, decodedSt->toBytes))
  
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}

uint8_t* KeyIso_serialize_rsa_enc_dec_with_attached_key_out(const void *stToEncode, size_t *encodedLen)
{
    KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_OUT_ST *st = (KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_OUT_ST*)stToEncode;
    size_t allocatesSize = (sizeof(*st) * SIZE_MULTIPLE_TO_ALLOC_OUT_STRUCT) + st->bytesLen;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
    int8_t counter = 0;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_rsa_enc_dec_with_attached_key_out_st(st, allocatesSize, buffer, encodedLen);
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
    int64_t bytesLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_TO_LEN);

    // bytesLen field boundaries check
    if (bytesLen < 0 || bytesLen > UINT32_MAX) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid output length", "Failed");
        return 0;
    }

    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_RSA_PRIVATE_ENC_DEC_WITH_ATTACHED_KEY_OUT_ST, (uint32_t)bytesLen);
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
    uint32_t pkeyBytesLen = 0;
    if (KeyIso_get_rsa_pkey_bytes_len(rsaPkeySt, &pkeyBytesLen) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid pkey size", "Failed");
        return SerializeStatus_InvalidFormat;
    }

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

size_t KeyIso_get_len_import_rsa_priv_key_in(const uint8_t *encodedSt, size_t encodedLen)
{
    const char* title = KEYISOP_GEN_KEY_TITLE;
    if (encodedSt == NULL || encodedLen == 0) {
        KEYISOP_trace_log_error(NULL, 0, title, "Invalid input", "Failed");
        return 0;
    }
    int64_t rsaModulusLen = get_dynamic_len_nested(encodedSt, encodedLen, CBOR_PARAM_RSA_MODULUS_LEN, CBOR_PARAM_PKEY);
    int64_t rsaPublicExpLen = get_dynamic_len_nested(encodedSt, encodedLen, CBOR_PARAM_RSA_PUBLIC_EXP_LEN, CBOR_PARAM_PKEY);
    int64_t rsaPrimes1Len = get_dynamic_len_nested(encodedSt, encodedLen, CBOR_PARAM_RSA_PRIME1_LEN, CBOR_PARAM_PKEY);
    int64_t rsaPrimes2Len = get_dynamic_len_nested(encodedSt, encodedLen, CBOR_PARAM_RSA_PRIME2_LEN, CBOR_PARAM_PKEY);

    if (rsaModulusLen < 0 || rsaPublicExpLen < 0 || rsaPrimes1Len < 0 || rsaPrimes2Len < 0) {
        KEYISOP_trace_log_error(NULL, 0, title, "Invalid input lengths, negative values", "Failed");
        return 0;

    } 
    
    if (rsaModulusLen > UINT32_MAX || rsaPublicExpLen > UINT32_MAX || rsaPrimes1Len > UINT32_MAX || rsaPrimes2Len > UINT32_MAX) {
        KEYISOP_trace_log_error(NULL, 0, title, "Invalid input lengths, too large", "Failed");
        return 0;
    }

    uint32_t dynamicLen = 0; 
    if (KEYISO_ADD_OVERFLOW((uint32_t)rsaModulusLen, (uint32_t)rsaPublicExpLen, &dynamicLen) ||
        KEYISO_ADD_OVERFLOW(dynamicLen, (uint32_t)rsaPrimes1Len, &dynamicLen) ||
        KEYISO_ADD_OVERFLOW(dynamicLen, (uint32_t)rsaPrimes2Len, &dynamicLen)) {
            KEYISOP_trace_log_error(NULL, 0, title, "Size overflow", "Failed");
            return 0;
            
    } 
    
    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST, dynamicLen);
}

static SerializeStatus _decode_rsa_pkey_st(CborValue *map, const uint8_t *buffer, size_t bufferSize, KEYISO_RSA_PKEY_ST *rsaPkeySt)
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
    uint32_t pkeyBytesLen = 0;
    if (KeyIso_get_rsa_pkey_bytes_len(rsaPkeySt, &pkeyBytesLen) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid pkey size", "Failed");
        return SerializeStatus_InvalidFormat;
    }
    CBOR_CHECK_STATUS(decode_string_ptr_by_len(&pkeyMap, (uint32_t)pkeyBytesLen, CBOR_PARAM_RSA_KEY_BYTES, rsaPkeySt->rsaPkeyBytes))
    
    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(map, &pkeyMap))
    return SerializeStatus_Success;
}

// EC
static SerializeStatus _encode_ec_pkey_st(CborEncoder *mapEncoder, KEYISO_EC_PKEY_ST *ecPkeySt)
{
    CborError cborErr = CborNoError;
    CborEncoder pkeyMapEncoder = { 0 };
    uint32_t pkeyBytesLen = 0;
    if (KeyIso_get_ec_pkey_bytes_len(ecPkeySt, &pkeyBytesLen) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid EC pkey size", "Failed");
        return SerializeStatus_InvalidFormat;
    }
    
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

size_t KeyIso_get_len_import_ec_priv_key_in(const uint8_t *encodedSt, size_t encodedLen)
{
    int64_t ecPubXLen = get_dynamic_len_nested(encodedSt, encodedLen, CBOR_PARAM_EC_PUB_X_LEN, CBOR_PARAM_PKEY);
    int64_t ecPubYLen = get_dynamic_len_nested(encodedSt, encodedLen, CBOR_PARAM_EC_PUB_Y_LEN, CBOR_PARAM_PKEY);
    int64_t ecPrivKeyLen = get_dynamic_len_nested(encodedSt, encodedLen, CBOR_PARAM_EC_PRIVATE_KEY_LEN, CBOR_PARAM_PKEY);
    
    if (ecPubXLen < 0 || ecPubYLen < 0 || ecPrivKeyLen < 0) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Failed to retrieve dynamic length", "Invalid negative input lengths");
        return 0;
    } 
    
    if (ecPubXLen > UINT32_MAX || ecPubYLen > UINT32_MAX || ecPrivKeyLen > UINT32_MAX) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Failed to retrieve dynamic length", "Invalid input lengths");
        return 0;
    }
     
    uint32_t dynamicLen = 0;
    // After verifying the input boundaries, we can safely cast the values to uint32_t    
    if (KEYISO_ADD_OVERFLOW((uint32_t)ecPubXLen, (uint32_t)ecPubYLen, &dynamicLen) ||
        KEYISO_ADD_OVERFLOW(dynamicLen, (uint32_t)ecPrivKeyLen, &dynamicLen)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Size overflow", "Failed");
        return 0;
    }
    
    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_IMPORT_EC_PRIV_KEY_IN_ST, dynamicLen);
}

static SerializeStatus _decode_ec_pkey_st(CborValue *map, const uint8_t *buffer, size_t bufferSize, KEYISO_EC_PKEY_ST *ecPkeySt)
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
    uint32_t pkeyBytesLen = 0;
    if (KeyIso_get_ec_pkey_bytes_len(ecPkeySt, &pkeyBytesLen) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid EC pkey size", "Failed");
        return SerializeStatus_InvalidFormat;
    }

    // Decode ec key bytes
    CBOR_CHECK_STATUS(decode_string_ptr_by_len(&pkeyMap, pkeyBytesLen, CBOR_PARAM_EC_KEY_BYTES, ecPkeySt->ecKeyBytes))
    
    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(map, &pkeyMap))
    return SerializeStatus_Success;

}
/////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    OPEN PRIVATE KEY IN
*/
static int _get_open_priv_key_dyn_in_len(const KEYISO_OPEN_PRIV_KEY_IN_ST *stToEncode, uint32_t *outDynamicLen)
{
    if (stToEncode == NULL || outDynamicLen == NULL) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid input", "Failed");
        return STATUS_FAILED;
    }
    uint32_t dynamicLen = 0;
    if (KEYISO_ADD_OVERFLOW(stToEncode->publicKeyLen, stToEncode->opaqueEncryptedKeyLen, &dynamicLen)){
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Size overflow", "Failed");
        return STATUS_FAILED;
    }
    *outDynamicLen = dynamicLen;
    return STATUS_OK;
}

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

    // Encode client metadata header
    CBOR_CHECK_STATUS(encode_client_metadata_header_in_st(&mapEncoder, &stToEncode->clientDataHeader))

    // Encode public key
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_PUBLIC_KEY_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, stToEncode->publicKeyLen))

    // Encode opaque key length
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_OPAQUE_KEY_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, stToEncode->opaqueEncryptedKeyLen))

    // Encode data
    uint32_t dynamicLen = 0;
    if (_get_open_priv_key_dyn_in_len(stToEncode, &dynamicLen) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "Invalid input size", "Failed");
        return SerializeStatus_InvalidLen;
    }
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_DATA))
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->data, dynamicLen))
    

    CBOR_OPERATION(cbor_encoder_close_container(&encoder, &mapEncoder))
    
    // Get the size of the encoded data
    *encodedSize = cbor_encoder_get_buffer_size(&encoder, buffer);    
    return SerializeStatus_Success;   
}

size_t KeyIso_get_len_open_priv_key_in(const uint8_t *encodedSt, size_t encodedLen)
{
    if (encodedSt == NULL || encodedLen == 0) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "Invalid input", "Failed");
        return 0;
    }
    int64_t publicKeyLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_PUBLIC_KEY_LEN);
    int64_t opaqueKeyLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_OPAQUE_KEY_LEN);
    // Length field boundaries check
    if (publicKeyLen < 0 || opaqueKeyLen < 0 || 
        publicKeyLen > UINT32_MAX || opaqueKeyLen > UINT32_MAX) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "Invalid input lengths", "Failed");
        return 0;
    }
    
    // Calculate total dynamic size
    uint32_t structDynamicSize = 0;
    if (KEYISO_ADD_OVERFLOW((uint32_t)publicKeyLen, (uint32_t)opaqueKeyLen, &structDynamicSize)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Size overflow", "Failed");
        return 0;
    }
    
    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_OPEN_PRIV_KEY_IN_ST, structDynamicSize);
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

    // Decode client metadata header
    CBOR_CHECK_STATUS(decode_client_metadata_header_in_st(&map, &decodedSt->clientDataHeader))

    // Decode publicKeyLen
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_PUBLIC_KEY_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->publicKeyLen))

    // Decode opaqueEncryptedKeyLen
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_OPAQUE_KEY_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->opaqueEncryptedKeyLen))

    // Decode the data array
    uint32_t totalBuflen = 0;
    if (_get_open_priv_key_dyn_in_len(decodedSt, &totalBuflen) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "Invalid input size", "Failed");
        return SerializeStatus_InvalidFormat;
    }
    CBOR_CHECK_STATUS(decode_string_ptr_by_len(&map, totalBuflen, CBOR_PARAM_DATA, decodedSt->data))

   
    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}

uint8_t* KeyIso_serialize_open_priv_key_in(const void* stToEncode, size_t *encodedLen)
{   
    KEYISO_OPEN_PRIV_KEY_IN_ST *inST  = (KEYISO_OPEN_PRIV_KEY_IN_ST*)stToEncode;
    uint32_t dynamicLen = 0;
    if (_get_open_priv_key_dyn_in_len(inST, &dynamicLen) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_OPEN_KEY_TITLE, "Invalid input size", "Failed");
        return NULL;
    }
    size_t allocatesSize = sizeof(KEYISO_OPEN_PRIV_KEY_IN_ST) * SIZE_MULTIPLE_TO_ALLOC_IN_STRUCT + dynamicLen;
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
static int _get_gen_rsa_key_pair_dyn_out_len(const KEYISO_GEN_RSA_KEY_PAIR_OUT_ST *stToEncode, size_t *outLen) 
{
    if (stToEncode == NULL || outLen == NULL) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Invalid input", "Failed");
        return STATUS_FAILED;
    }
    uint32_t dynamicLen = 0;
    if (KEYISO_ADD_OVERFLOW(stToEncode->rsaModulusLen, stToEncode->rsaPublicExpLen, &dynamicLen)){
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Size overflow", "Failed");
        return STATUS_FAILED;
    }
    if (KEYISO_ADD_OVERFLOW(dynamicLen, stToEncode->opaqueEncryptedKeyLen, &dynamicLen)){
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Size overflow", "Failed");
        return STATUS_FAILED;
    }
    *outLen =  dynamicLen;
    return STATUS_OK;
}

static SerializeStatus _encode_gen_rsa_key_pair_out_st(KEYISO_GEN_RSA_KEY_PAIR_OUT_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
    // A map of a key pair : the public key and the generated private key
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };
    
    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_GENERATE_RSA_KEY_PAIR_OUT_ELEMENTS))

    // Encode headerSt
    CBOR_CHECK_STATUS(encode_header_out_st(&mapEncoder, &stToEncode->headerSt))

    // Encode rsa pub key modulus length
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_RSA_MODULUS_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->rsaModulusLen))

    // Encode rsa pub key exponent length
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_RSA_PUBLIC_EXP_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->rsaPublicExpLen))

    // Encode Opaque encrypted key length
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_ENCRYPTED_KEY_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->opaqueEncryptedKeyLen))

    size_t totalBuflen = 0;
    if (_get_gen_rsa_key_pair_dyn_out_len(stToEncode, &totalBuflen) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Invalid input size", "Failed");
        return SerializeStatus_InvalidLen;
    }

    // Encode the data 
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_DATA))
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->data, totalBuflen))


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

    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, NULL, "invalid format");
        return SerializeStatus_InvalidFormat;
    }

    // header
    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_out_st(&map, &decodedSt->headerSt, IpcCommand_GenerateRsaKeyPair))

    // Decode rsa pub key modulus length  
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_RSA_MODULUS_LEN))        
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->rsaModulusLen))

    // Decode rsa public exponent length
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_RSA_PUBLIC_EXP_LEN))        
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->rsaPublicExpLen))

    // Decode opaque encrypted key length
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_ENCRYPTED_KEY_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->opaqueEncryptedKeyLen))

    // Decode the data
    size_t totalBuflen =  0;
    if (_get_gen_rsa_key_pair_dyn_out_len(decodedSt, &totalBuflen) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Invalid input size", "Failed");
        return SerializeStatus_InvalidLen;
    }
   
    CBOR_CHECK_STATUS(decode_string_ptr_by_len(&map, totalBuflen, CBOR_PARAM_DATA, decodedSt->data))

    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}

uint8_t* KeyIso_serialize_gen_rsa_key_pair_out(void *stToEncode, size_t *encodedLen)
{
    size_t totalBuflen = 0;
    if (_get_gen_rsa_key_pair_dyn_out_len((KEYISO_GEN_RSA_KEY_PAIR_OUT_ST*)stToEncode, &totalBuflen) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Invalid input size", "Failed");
        return NULL;
    }

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

size_t KeyIso_get_len_gen_rsa_key_pair_out(const uint8_t *encodedSt, size_t encodedLen)
{
     // getting the value of the rsa modulus
    int64_t rsaModulusLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_RSA_MODULUS_LEN);
    if (rsaModulusLen < 0 || rsaModulusLen > UINT32_MAX) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Invalid input lengths", "Failed");
        return 0;
    }
    
    // getting the value of the rsa public exponent
    int64_t rsaPublicExpLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_RSA_PUBLIC_EXP_LEN);
    if (rsaPublicExpLen < 0 || rsaPublicExpLen > UINT32_MAX) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Invalid input lengths", "Failed");
        return 0;
    }

    // getting the value of the opaque encrypted key length
    int64_t opaqueEncryptedKeyLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_ENCRYPTED_KEY_LEN);
    if (opaqueEncryptedKeyLen < 0 || opaqueEncryptedKeyLen > UINT32_MAX) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Invalid input lengths", "Failed");
        return 0;
    }

    uint32_t dynamicSize = 0;
    // summing the rsaPublicExpLen + dynamic size fo far
    if (KEYISO_ADD_OVERFLOW((uint32_t)rsaModulusLen, (uint32_t)rsaPublicExpLen, &dynamicSize) || 
        KEYISO_ADD_OVERFLOW(dynamicSize, (uint32_t)opaqueEncryptedKeyLen, &dynamicSize)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Size overflow", "Failed");
        return 0;
    }

    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_GEN_RSA_KEY_PAIR_OUT_ST, dynamicSize);
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
static size_t _get_encrypted_ec_key_pair_len(const KEYISO_GEN_EC_KEY_PAIR_OUT_ST *stToEncode) {
    if(stToEncode) {
        uint32_t dynamicLen = 0;
        if (KEYISO_ADD_OVERFLOW(stToEncode->ecPubKeyLen, stToEncode->opaqueEncryptedKeyLen, &dynamicLen)){
            KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Size overflow", "Failed");
            return 0;
        }
        return dynamicLen;
    }
    KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Invalid input", "Failed");
    return 0;
}

static SerializeStatus _encode_gen_ec_key_pair_out_st(KEYISO_GEN_EC_KEY_PAIR_OUT_ST *stToEncode, size_t allocatesSize, uint8_t *buffer, size_t *encodedSize) 
{
   
    CborError   cborErr = CborNoError;
    CborEncoder encoder = { 0 };
    CborEncoder mapEncoder = { 0 };

    // Initialize the encoder
    cbor_encoder_init(&encoder, buffer, allocatesSize, 0);
    CBOR_OPERATION(cbor_encoder_create_map(&encoder, &mapEncoder, NUM_OF_GENERATE_EC_KEY_PAIR_OUT_ELEMENTS))

    // Encode headerSt
    CBOR_CHECK_STATUS(encode_header_out_st(&mapEncoder, &stToEncode->headerSt))

    // Ec key curve
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_EC_CRV))        
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder,(uint64_t)stToEncode->ecCurve))

    // Encode rsa pub key len
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_PUBLIC_KEY_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->ecPubKeyLen))

   // Encode opaque encrypted key length
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_ENCRYPTED_KEY_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, (uint64_t)stToEncode->opaqueEncryptedKeyLen))

    // Encode the data 
    size_t totalBuflen =  _get_encrypted_ec_key_pair_len(stToEncode);
    if (totalBuflen == 0 || totalBuflen > UINT32_MAX) {
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Invalid input size", "Failed", "%ld bytes", totalBuflen);
        return SerializeStatus_InvalidFormat;
    }
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_DATA))
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->data, totalBuflen))

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

    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))

    // Ensure the top-level value is a map
    if (!cbor_value_is_map(&value) || !cbor_value_is_container(&value)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, NULL, "invalid format");
        return SerializeStatus_InvalidFormat;
    }

    // header
    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_out_st(&map, &decodedSt->headerSt, IpcCommand_GenerateEcKeyPair))

    // Decode ec curve
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_EC_CRV))        
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->ecCurve))

    // Decode rsa public key len          
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_PUBLIC_KEY_LEN))        
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->ecPubKeyLen))

   // Decode opaque encrypted key length
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_ENCRYPTED_KEY_LEN))        
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->opaqueEncryptedKeyLen))

    size_t totalBuflen = _get_encrypted_ec_key_pair_len(decodedSt);
    if (totalBuflen == 0 || totalBuflen > UINT32_MAX) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Invalid input size", "Failed");
        return SerializeStatus_InvalidFormat;
    }
    
    // Decode the data
    CBOR_CHECK_STATUS(decode_string_ptr_by_len(&map, totalBuflen, CBOR_PARAM_DATA, decodedSt->data))

    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}

uint8_t* KeyIso_serialize_gen_ec_key_pair_out(const void *stToEncode, size_t *encodedLen)
{
    size_t totalBuflen = _get_encrypted_ec_key_pair_len((KEYISO_GEN_EC_KEY_PAIR_OUT_ST*)stToEncode);
    if (totalBuflen == 0 || totalBuflen > UINT32_MAX) {
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Invalid input size", "Failed", "%ld bytes", totalBuflen);
        return NULL;
    }

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

size_t KeyIso_get_len_gen_ec_key_pair_out(const uint8_t *encodedSt, size_t encodedLen)
{
    // getting the value of the ec public key length
    int64_t ecPubKeyLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_PUBLIC_KEY_LEN);
    if (ecPubKeyLen < 0 || ecPubKeyLen > UINT32_MAX) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Invalid input lengths", "Failed");
        return 0;
    }

    // getting the value of the opaque encrypted key length
    int64_t opaqueEncryptedKeyLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_ENCRYPTED_KEY_LEN);
    if (opaqueEncryptedKeyLen < 0 || opaqueEncryptedKeyLen > UINT32_MAX) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Invalid input lengths", "Failed");
        return 0;
    }

    uint32_t dynamicLen = 0;
    // summing the ecPubKeyLen + dynamic size fo far
    if (KEYISO_ADD_OVERFLOW((uint32_t)ecPubKeyLen, (uint32_t)opaqueEncryptedKeyLen, &dynamicLen)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Size overflow", "Failed");
        return 0;
    }

    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_GEN_EC_KEY_PAIR_OUT_ST, dynamicLen);
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
    CBOR_CHECK_STATUS(_decode_rsa_pkey_st(&map, buffer, bufferSize, &decodedSt->pkeySt))

    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}


uint8_t* KeyIso_serialize_import_rsa_priv_key_in(const void *stToEncode, size_t *encodedLen)
{
    uint32_t pkeyBytesLen = 0;
    if (KeyIso_get_rsa_pkey_bytes_len(&((KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST*)stToEncode)->pkeySt, &pkeyBytesLen) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Invalid pkey size", "Failed");
        return NULL;
    }
    size_t allocatesSize = sizeof(KEYISO_IMPORT_RSA_PRIV_KEY_IN_ST)*SIZE_MULTIPLE_TO_ALLOC_IN_STRUCT + pkeyBytesLen;
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
                uint8_t* newBuffer = (uint8_t*)KeyIso_clear_realloc(buffer, oldSize, allocatesSize);
                if (!newBuffer) {
                    KeyIso_clear_free(buffer, oldSize);
                    buffer = NULL; 
                    return NULL;
                }
                buffer = newBuffer;
                counter++;
            } else { 
                KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, NULL, "Serialize error");
                KeyIso_clear_free(buffer, oldSize > 0 ? oldSize : allocatesSize);
                return NULL;
            }
        } else { //SerializeStatus_Success
            return buffer;
        }
    } 
    KeyIso_clear_free(buffer, allocatesSize);
    return NULL;
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
    CBOR_CHECK_STATUS(_decode_ec_pkey_st(&map, buffer, bufferSize, &decodedSt->pkeySt))

    // Decode
   
    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}


uint8_t* KeyIso_serialize_import_ec_priv_key_in(const void *stToEncode, size_t *encodedLen)
{
    int8_t counter = 0;
    int oldSize = 0;
    uint32_t pkeyBytesLen = 0;
    if (KeyIso_get_ec_pkey_bytes_len(&((KEYISO_IMPORT_EC_PRIV_KEY_IN_ST*)stToEncode)->pkeySt, &pkeyBytesLen) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_GEN_KEY_TITLE, "Invalid pkey size", "Failed");
        return NULL;
    }
    size_t allocatesSize = sizeof(KEYISO_IMPORT_EC_PRIV_KEY_IN_ST)*SIZE_MULTIPLE_TO_ALLOC_IN_STRUCT + pkeyBytesLen;
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

    // Encode publicKeyLen
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_PUBLIC_KEY_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, stToEncode->publicKeyLen))

    // Encode opaque encrypted key length
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_OPAQUE_KEY_LEN))
    CBOR_OPERATION(cbor_encode_uint(&mapEncoder, stToEncode->opaqueEncryptedKeyLen))

    // Encode data bytes
    CBOR_OPERATION(cbor_encode_text_stringz(&mapEncoder, CBOR_PARAM_DATA))
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->data, stToEncode->opaqueEncryptedKeyLen))

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

    // Decode header
    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_out_st(&map, &decodedSt->headerSt, command))

    // Decode publicKeyLen
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_PUBLIC_KEY_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->publicKeyLen))

    // Decode opaque encrypted key length  
    CBOR_CHECK_STATUS(validate_tag(&map, CBOR_PARAM_OPAQUE_KEY_LEN))
    CBOR_CHECK_STATUS(get_uint32_val(&map, &decodedSt->opaqueEncryptedKeyLen))

    // Decode data bytes
    CBOR_CHECK_STATUS(decode_string_ptr_by_len(&map, decodedSt->opaqueEncryptedKeyLen, CBOR_PARAM_DATA, decodedSt->data))

    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}

uint8_t* KeyIso_serialize_import_priv_key_out(void *stToEncode, size_t *encodedLen)
{
    const char* title = KEYISOP_GEN_KEY_TITLE;
    if (stToEncode == NULL) {
        KEYISOP_trace_log_error(NULL, 0, title, "Invalid input", "Failed");
        return 0;
    }
    KEYISO_IMPORT_PRIV_KEY_OUT_ST *st = (KEYISO_IMPORT_PRIV_KEY_OUT_ST*)stToEncode;
    size_t allocatesSize = sizeof(KEYISO_IMPORT_PRIV_KEY_OUT_ST) * SIZE_MULTIPLE_TO_ALLOC_OUT_STRUCT + st->opaqueEncryptedKeyLen + st->publicKeyLen;
    uint8_t *buffer = (uint8_t*)KeyIso_zalloc(allocatesSize);
    size_t oldSize = 0;
    int8_t counter = 0;

    if (!buffer) {
        KEYISOP_trace_log_error(NULL, 0, title, "Memory allocation", "Failed");
        return NULL;
    }

    while (counter < MAX_REALLOC) {
        SerializeStatus status = _encode_import_priv_key_out_st(st, allocatesSize, buffer, encodedLen);
        if (status != SerializeStatus_Success) {
            if (status == SerializeStatus_OutOfMemory) {
                oldSize = allocatesSize;
                allocatesSize *= REALLOC_MULTIPLE;
                KEYISOP_trace_log_error_para(NULL, KEYISOP_TRACELOG_WARNING_FLAG, title, "realloc", "retry", "%ld bytes", allocatesSize);
                uint8_t* newBuffer = (uint8_t*)KeyIso_clear_realloc(buffer, oldSize, allocatesSize);
                if (!newBuffer) {
                    KeyIso_clear_free(buffer, oldSize);
                    return NULL;
                }
                buffer = newBuffer;
                counter++;
            } else {
                KEYISOP_trace_log_error(NULL, 0, title, NULL, "Serialize error");
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
    int64_t opaqueKeyLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_OPAQUE_KEY_LEN);
    int64_t publicKeyLen = get_dynamic_len(encodedSt, encodedLen, CBOR_PARAM_PUBLIC_KEY_LEN);
    
    // opaqueLen and publicKeyLen fields boundaries check (both are uint32_t)
    if (opaqueKeyLen < 0 || publicKeyLen < 0 || opaqueKeyLen > UINT32_MAX || publicKeyLen > UINT32_MAX) {
        return 0;
    }
    
    uint32_t dynamicSize = 0;
    // After verifying the input boundaries, we can safely cast the values to uint32_t and calculate the dynamic size    
    if (KEYISO_ADD_OVERFLOW((uint32_t)opaqueKeyLen, (uint32_t)publicKeyLen, &dynamicSize)) {
        return 0;
    }

    return GET_DYNAMIC_STRUCT_SIZE(KEYISO_IMPORT_PRIV_KEY_OUT_ST, (uint32_t)dynamicSize);
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

    // Decode header with legacy support
    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_out_st_with_legacy_support(&map, &decodedSt->headerSt, IpcCommand_ImportSymmetricKey))

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
    if (totalBuflen > UINT32_MAX) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_SYMMETRIC_KEY_TITLE, "Invalid input size", "Failed");
        return NULL;
    }

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

static int _get_enc_dec_symmetric_key_in_len(const KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST *stToEncode, size_t *outLen)
{
    if (stToEncode == NULL) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid input", "Failed");
        return STATUS_FAILED;
    }

    uint32_t dynamicLen = 0;
    if (KEYISO_ADD_OVERFLOW(stToEncode->encryptedKeyLen, stToEncode->fromBytesLen, &dynamicLen)){
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Size overflow", "Failed");
        return STATUS_FAILED;
    }
    *outLen = dynamicLen;
    return STATUS_OK;
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
    size_t dynamicLen = 0;
    if (_get_enc_dec_symmetric_key_in_len(stToEncode, &dynamicLen) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid format", "Invalid dynamic size");
        return SerializeStatus_InvalidLen;
    }
    CBOR_OPERATION(cbor_encode_byte_string(&mapEncoder, stToEncode->encDecBytes, dynamicLen))

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
    uint32_t totalLen = 0;
    size_t totalSize = 0;
    if (_get_enc_dec_symmetric_key_in_len(decodedSt, &totalSize) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_SYMMETRIC_ENC_DEC_TITLE, "Size overflow", "Failed");
        return SerializeStatus_InvalidLen;
    }
    totalLen = (uint32_t)totalSize;
    if (totalLen != totalSize) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_SYMMETRIC_ENC_DEC_TITLE, "Size overflow", "Failed");
        return SerializeStatus_InvalidLen;
    }
    CBOR_CHECK_STATUS(decode_string_ptr_by_len(&map, totalLen, CBOR_PARAM_SYMMETRIC_ENC_KEY_BYTES, decodedSt->encDecBytes))

    // Exit the top-level map
    CBOR_OPERATION(cbor_value_leave_container(&value, &map))
    return SerializeStatus_Success;
}

uint8_t* KeyIso_serialize_enc_dec_symmetric_key_in(const void* stToEncode, size_t *encodedLen)
{
    size_t totalBuflen = 0;
    if (_get_enc_dec_symmetric_key_in_len((KEYISO_SYMMETRIC_ENCRYPT_DECRYPT_IN_ST*)stToEncode, &totalBuflen) != STATUS_OK) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_SYMMETRIC_ENC_DEC_TITLE, "Invalid input size", "Failed");
        return NULL;
    }
 
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

    // Decode header with legacy support
    CBOR_OPERATION(cbor_value_enter_container(&value, &map))
    CBOR_CHECK_STATUS(decode_header_out_st_with_legacy_support(&map, &decodedSt->headerSt, IpcCommand_SymmetricKeyEncryptDecrypt))
    
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
