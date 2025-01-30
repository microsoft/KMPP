/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include "keyiso.h"
#include "keyisolog.h"
#include "keyisocommon.h"
#include "keyisoipccommands.h"
#include "keyisoipccommonserialize.h"
#include "keyisoutils.h"

/*
    Tags definitions 
*/

//Header tags
#define CBOR_PARAM_HEADER           "header"
#define CBOR_PARAM_VERSION          "version"
#define CBOR_PARAM_COMMAND          "command"
#define CBOR_PARAM_CORRELATION_ID   "corrId"
#define CBOR_PARAM_RESULT           "result"

//////////////////////////////////////////////////////////////////////////////////////////////////
/*
    Internal functions
*/
static SerializeStatus _decode_string_ptr_by_unsigned_len(CborValue *map, uint32_t decodedLen, const char *bytesTag, uint8_t *decodedBytes) 
{
    CborError cborErr = CborNoError;

    // Decode bytes  
    CBOR_CHECK_STATUS(validate_tag(map, bytesTag))
    size_t size;
    CBOR_OPERATION(cbor_value_get_string_length(map, &size))
    if (size != decodedLen) {
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid string len", "Decode error", "len(decodedBytes) = %ld, decodedLen = %u", size, decodedLen);        
        return SerializeStatus_InvalidLen;
    } 
    // The iterator is promoted in the copying function if the last parameter is given as an iterator
    CBOR_OPERATION(cbor_value_copy_byte_string(map, decodedBytes, &size, map))
    return SerializeStatus_Success;  
}
//////////////////////////////////////////////////////////////////////////////////////////////////
/*
    Internal encoder utilities 
*/

SerializeStatus encode_header_in_st(CborEncoder *mapEncoder, KEYISO_INPUT_HEADER_ST *headerSt)
{
    CborError cborErr = CborNoError;
    CborEncoder headerMapEncoder = { 0 };

    CBOR_OPERATION(cbor_encode_text_stringz(mapEncoder, CBOR_PARAM_HEADER))
    CBOR_OPERATION(cbor_encoder_create_map(mapEncoder, &headerMapEncoder, NUM_OF_HEADER_IN_ELEMENTS))

    // Encode version  
    CBOR_OPERATION(cbor_encode_text_stringz(&headerMapEncoder, CBOR_PARAM_VERSION))
    CBOR_OPERATION(cbor_encode_simple_value(&headerMapEncoder, headerSt->version))
    
    // Encode command  
    CBOR_OPERATION(cbor_encode_text_stringz(&headerMapEncoder, CBOR_PARAM_COMMAND))
    CBOR_OPERATION(cbor_encode_uint(&headerMapEncoder, (uint64_t)headerSt->command))

    // Encode correlationId  
    CBOR_OPERATION(cbor_encode_text_stringz(&headerMapEncoder, CBOR_PARAM_CORRELATION_ID))
    CBOR_OPERATION(cbor_encode_byte_string(&headerMapEncoder, headerSt->correlationId, sizeof(headerSt->correlationId)))

    CBOR_OPERATION(cbor_encoder_close_container(mapEncoder, &headerMapEncoder))
    return SerializeStatus_Success;  
}


SerializeStatus encode_header_out_st(CborEncoder *mapEncoder, KEYISO_OUTPUT_HEADER_ST *headerSt)
{
    CborError cborErr = CborNoError;
    CborEncoder headerMapEncoder = { 0 };

    CBOR_OPERATION(cbor_encode_text_stringz(mapEncoder, CBOR_PARAM_HEADER))
    CBOR_OPERATION(cbor_encoder_create_map(mapEncoder, &headerMapEncoder, NUM_OF_HEADER_OUT_ELEMENTS))

    // Encode command  
    CBOR_OPERATION(cbor_encode_text_stringz(&headerMapEncoder, CBOR_PARAM_COMMAND))
    CBOR_OPERATION(cbor_encode_uint(&headerMapEncoder, (uint64_t)headerSt->command))

    // Encode result  
    CBOR_OPERATION(cbor_encode_text_stringz(&headerMapEncoder, CBOR_PARAM_RESULT))
    CBOR_OPERATION(cbor_encode_uint(&headerMapEncoder, (uint64_t)headerSt->result))

    CBOR_OPERATION(cbor_encoder_close_container(mapEncoder, &headerMapEncoder))
    return SerializeStatus_Success;  
} 


//////////////////////////////////////////////////////////////////////////////////////////////////
/*
    Internal decoder utilities 
*/

SerializeStatus get_int32_val(CborValue *map, int32_t *value)
{
    CborError cborErr = CborNoError;
    int64_t intValue;

    CBOR_OPERATION(cbor_value_get_int64(map, &intValue))
    CBOR_OPERATION(cbor_value_advance_fixed(map))
    if (intValue > 0x7FFFFFFF || intValue < -0x7FFFFFFF) {
        return SerializeStatus_InvalidIntValue;
    }
    *value = (int32_t)intValue;
    return SerializeStatus_Success;  
}


SerializeStatus get_uint32_val(CborValue *map, uint32_t *value)
{
    CborError cborErr = CborNoError;
    uint64_t uintValue;

    CBOR_OPERATION(cbor_value_get_uint64(map, &uintValue))
    CBOR_OPERATION(cbor_value_advance_fixed(map))
    if (uintValue > 0xFFFFFFFF) {
        return SerializeStatus_InvalidIntValue;
    }
    *value = (uint32_t)uintValue;
    return SerializeStatus_Success;  
}


SerializeStatus validate_tag(CborValue *map, const char *tag)
{
    CborError cborErr = CborNoError;
    bool bEqual = false;

    if (!cbor_value_is_text_string(map)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "string is expected");
        return SerializeStatus_InvalidFormat;
    }    

    CBOR_OPERATION(cbor_value_text_string_equals(map, tag, &bEqual))
    if (!bEqual) {
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid tag", "Decode error", "expected tag: %s", tag);        
        return SerializeStatus_InvalidFormat;
    }

    CBOR_OPERATION(cbor_value_advance(map))   
    return SerializeStatus_Success;  
}


SerializeStatus decode_string_ptr(CborValue *map, const char *lenTag, int32_t *decodedLen, const char *bytesTag, uint8_t *decodedBytes)
{
    // Decode len  
    CBOR_CHECK_STATUS(validate_tag(map, lenTag)) 
    CBOR_CHECK_STATUS(get_int32_val(map, decodedLen))
    CBOR_CHECK_STATUS(decode_string_ptr_by_len(map, *decodedLen, bytesTag, decodedBytes))
    return SerializeStatus_Success;
}

SerializeStatus decode_string_ptr_by_len(CborValue *map, int32_t decodedLen, const char *bytesTag, uint8_t *decodedBytes) 
{
    CborError cborErr = CborNoError;

    // Decode bytes  
    CBOR_CHECK_STATUS(validate_tag(map, bytesTag))
    size_t size;
    CBOR_OPERATION(cbor_value_get_string_length(map, &size))
    if ((decodedLen > UINT32_MAX) || (size != (uint32_t)decodedLen)) {
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid string len", "Decode error", "len(decodedBytes) = %ld, decodedLen = %d", size, decodedLen);        
        return SerializeStatus_InvalidLen;
    } 
    // The iterator is promoted in the copying function if the last parameter is given as an iterator
    CBOR_OPERATION(cbor_value_copy_byte_string(map, decodedBytes, &size, map))
    return SerializeStatus_Success;  
}

SerializeStatus decode_string_ptr_unsigned(CborValue *map, const char *lenTag, uint32_t *decodedLen, const char *bytesTag, uint8_t *decodedBytes)
{
    // Decode len  
    CBOR_CHECK_STATUS(validate_tag(map, lenTag)) 
    CBOR_CHECK_STATUS(get_uint32_val(map, decodedLen))
    CBOR_CHECK_STATUS(_decode_string_ptr_by_unsigned_len(map, *decodedLen, bytesTag, decodedBytes))
    return SerializeStatus_Success;
}

int64_t get_dynamic_len_nested(const uint8_t *buffer, size_t bufferSize, const char *lenTag, const char *parentTag)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))
    
    CborValue parent = { 0 };
    CBOR_OPERATION(cbor_value_map_find_value(&value, parentTag, &parent))
    
    int64_t intValue;
    CborValue lenVal = { 0 };
    CBOR_OPERATION(cbor_value_map_find_value(&parent, lenTag, &lenVal))
    CBOR_OPERATION(cbor_value_get_int64(&lenVal, &intValue))
    return intValue;
}


int64_t get_dynamic_len(const uint8_t *buffer, size_t bufferSize, const char *lenTag)
{
    CborError cborErr = CborNoError;

    // Initialize the decode
    CborParser parser = { 0 };
    CborValue value = { 0 };
    CBOR_OPERATION(cbor_parser_init(buffer, bufferSize, 0, &parser, &value))
    
    int64_t intValue;
    CborValue lenVal = { 0 };
    CBOR_OPERATION(cbor_value_map_find_value(&value, lenTag, &lenVal))
    CBOR_OPERATION(cbor_value_get_int64(&lenVal, &intValue))
    return intValue;
}


SerializeStatus decode_header_in_st(CborValue *map, KEYISO_INPUT_HEADER_ST *headerSt, IpcCommand expectedCommand)
{
    CborError cborErr = CborNoError;
    CborValue headerMap = { 0 };
 
    CBOR_CHECK_STATUS(validate_tag(map, CBOR_PARAM_HEADER))
    // Enter the header map
    CBOR_OPERATION(cbor_value_enter_container(map, &headerMap))

    // Decode version  
    CBOR_CHECK_STATUS(validate_tag(&headerMap, CBOR_PARAM_VERSION))
    CBOR_OPERATION(cbor_value_get_simple_type(&headerMap, &(headerSt->version)))          
    CBOR_OPERATION(cbor_value_advance_fixed(&headerMap))
    
    // Decode command            
    CBOR_CHECK_STATUS(validate_tag(&headerMap, CBOR_PARAM_COMMAND))        
    CBOR_CHECK_STATUS(get_uint32_val(&headerMap, &headerSt->command))
  
    if (headerSt->command != expectedCommand) {
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_ENGINE_TITLE, "unexpected command", "Decode error", "eaderSt->command = %d, expectedCommand = %d", headerSt->command, expectedCommand);        
        return SerializeStatus_InvalidCommand;
    }

    // Decode correlation id  
    CBOR_CHECK_STATUS(validate_tag(&headerMap, CBOR_PARAM_CORRELATION_ID))
    size_t size;
    CBOR_OPERATION(cbor_value_get_string_length(&headerMap, &size))
    CBOR_OPERATION(cbor_value_copy_byte_string(&headerMap, headerSt->correlationId, &size, &headerMap))

    CBOR_OPERATION(cbor_value_leave_container(map, &headerMap)) //Updates map to point to the next element after the container.  
    return SerializeStatus_Success;  
}


SerializeStatus decode_header_out_st(CborValue *map, KEYISO_OUTPUT_HEADER_ST *headerSt, IpcCommand expectedCommand)
{
    CborError cborErr = CborNoError;
    CborValue headerMap = { 0 };

    CBOR_CHECK_STATUS(validate_tag(map, CBOR_PARAM_HEADER))
    // Enter the header map
    CBOR_OPERATION(cbor_value_enter_container(map, &headerMap))
    
    // Decode command        
    CBOR_CHECK_STATUS(validate_tag(&headerMap, CBOR_PARAM_COMMAND))
    CBOR_CHECK_STATUS(get_uint32_val(&headerMap, &headerSt->command))   

    if (headerSt->command != expectedCommand) {
        KEYISOP_trace_log_error_para(NULL, 0, KEYISOP_ENGINE_TITLE, "unexpected command", "Decode error", "eaderSt->command = %d, expectedCommand = %d", headerSt->command, expectedCommand);        
        return SerializeStatus_InvalidCommand;
    }

    // Decode result  
    CBOR_CHECK_STATUS(validate_tag(&headerMap, CBOR_PARAM_RESULT))
    CBOR_CHECK_STATUS(get_uint32_val(&headerMap, &headerSt->result))   
    
    CBOR_OPERATION(cbor_value_leave_container(map, &headerMap)) //Updates map to point to the next element after the container.  
    return SerializeStatus_Success;  
}
