/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#include "../thirdparty/tinycbor/src/cbor.h"

/*////////////
    Enum
////////////*/

typedef enum {
    SerializeStatus_Success,
    SerializeStatus_OutOfMemory,     // cbor encoder has recieved not too small memory allocation
    SerializeStatus_InternalError,   // internal cbor library error
    SerializeStatus_InvalidFormat,   // format recieved is not as expected
    SerializeStatus_InvalidLen,      // length is different than expected
    SerializeStatus_InvalidIntValue, // int32 ot uint32 value exceeds limit
    SerializeStatus_InvalidCommand,  // command is not as expected
    SerializeStatus_InvalidParams,   // invalid parameter
}SerializeStatus;


/*////////////
    Macro
////////////*/

#define MAX_REALLOC                       3
#define SIZE_MULTIPLE_TO_ALLOC_IN_STRUCT  3
#define SIZE_MULTIPLE_TO_ALLOC_OUT_STRUCT 4
#define REALLOC_MULTIPLE                  2

//Calls cbor api and manipulate the returned value
#define CBOR_OPERATION(command) \
    cborErr = command;     \
    if (cborErr != CborNoError)  \
    { return (cborErr == CborErrorOutOfMemory) ? SerializeStatus_OutOfMemory : SerializeStatus_InternalError; }

//Calls an internal function and exit in case of a failure
#define CBOR_CHECK_STATUS(status) \
    if (status != SerializeStatus_Success) { return status; }


/*////////////
   Functions
////////////*/

//Internal encoder utilities 
SerializeStatus encode_header_in_st(CborEncoder *mapEncoder, KEYISO_INPUT_HEADER_ST *headerSt);
SerializeStatus encode_header_out_st(CborEncoder *mapEncoder, KEYISO_OUTPUT_HEADER_ST *headerSt);

// Internal decoder utilities 
SerializeStatus get_int32_val(CborValue *map, int32_t *value);
SerializeStatus get_uint32_val(CborValue *map, uint32_t *value);
SerializeStatus validate_tag(CborValue *map, const char *tag);
SerializeStatus decode_string_ptr(CborValue *map, const char *lenTag, int32_t *decodedLen, const char *bytesTag, uint8_t *decodedBytes);
SerializeStatus decode_string_ptr_by_len(CborValue *map, int32_t decodedLen, const char *bytesTag, uint8_t *decodedBytes);
SerializeStatus decode_string_ptr_unsigned(CborValue *map, const char *lenTag, uint32_t *decodedLen, const char *bytesTag, uint8_t *decodedBytes);
SerializeStatus decode_header_in_st(CborValue *map, KEYISO_INPUT_HEADER_ST *headerSt, IpcCommand expectedCommand);
SerializeStatus decode_header_out_st(CborValue *map, KEYISO_OUTPUT_HEADER_ST *headerSt, IpcCommand expectedCommand);
int64_t get_dynamic_len(const uint8_t *pBuffer, size_t bufferSize, const char *lenTag);
int64_t get_dynamic_len_nested(const uint8_t *buffer, size_t bufferSize, const char *lenTag, const char *parentTag);
