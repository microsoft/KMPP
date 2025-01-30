/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>

#ifdef KMPP_OPENSSL_SUPPORT
#include <openssl/err.h>
#include <openssl/rand.h>
#else
#include "kmppsymcryptwrapper.h"
#endif //KMPP_OPENSSL_SUPPORT


#include "keyisocommon.h"
#include "keyisomemory.h"
#include "keyisolog.h"
#include "keyisoutils.h"
#include "keyisoipccommands.h"


// InProc is off by default.
int KEYISOP_inProc = 0;

static char *KEYISOP_defaultCertArea;
static char *KEYISOP_defaultCertDir;

#ifdef KMPP_OPENSSL_SUPPORT
const char *KeyIsoP_get_default_cert_area()
{
    if (KEYISOP_defaultCertArea) {
        return KEYISOP_defaultCertArea;
    } else {
        const char *rootDir = KMPP_ROOT_DIR;
        if (*rootDir == '\0') {
            return X509_get_default_cert_area();
        } else {
            return KMPP_ROOT_DIR;
        }
    }
}
const char *KeyIsoP_get_default_private_area()
{
    if (KEYISOP_defaultCertArea) {
        return KEYISOP_defaultCertArea;
    } else {
        const char *rootDir = KMPP_PRIVATE_ROOT_DIR;
        if (*rootDir == '\0') {
            return X509_get_default_cert_area();
        } else {
            return KMPP_PRIVATE_ROOT_DIR;
        }
    }
}

const char *KeyIsoP_get_default_cert_dir()
{
    if (KEYISOP_defaultCertDir) {
        return KEYISOP_defaultCertDir;
    } else {
        const char *rootDir = KMPP_ROOT_DIR;
        if (*rootDir == '\0') {
            return X509_get_default_cert_dir();
        } else {
            return KMPP_CERTS_DIR;
        }
    }
}

const char *KeyIsoP_get_install_image_dir()
{
    const char *dir = KMPP_INSTALL_IMAGE_DIR;
    if (*dir == '\0') {
        return X509_get_default_cert_dir();
    } else {
        return KMPP_INSTALL_IMAGE_DIR;
    }
}

//
// KEYISO_ file support functions
//

unsigned int KeyIsoP_read_version_file(
    const uuid_t correlationId,
    const char *filename)
{
    const char *title = KEYISOP_READ_WRITE_VERSION_TITLE;
    const char *loc = "";
    unsigned int outVersion = KEYISOP_INVALID_VERSION;
    BIO *in = NULL;
    unsigned char version[1];

    ERR_clear_error();

    in = BIO_new_file(filename, "rb");
    if (in == NULL) {
        if (ERR_GET_REASON(ERR_peek_last_error()) != BIO_R_NO_SUCH_FILE) {
            loc = "BIO_new_file";
            goto openSslErr;
        }
        goto end;
    }

    if (BIO_read(in, version, sizeof(version)) != sizeof(version)) {
        loc = "BIO_read";
        goto openSslErr;
    }
    
    outVersion = version[0] - '0';

end:
    BIO_free(in);
    return outVersion;

openSslErr:
    KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, loc,
        "filename: %s", filename);
    goto end;
}

int KeyIso_rand_bytes(unsigned char *buffer,  int size) {
    if (RAND_bytes(buffer,size) == 1) {
        // Random bytes were generated successfully
        return STATUS_OK;
    }
    return STATUS_FAILED;
}
#else

int KeyIso_rand_bytes(unsigned char *buffer,  int size) {
    SymCryptRandom(buffer,size);
    return STATUS_OK;
}

#endif//KMPP_OPENSSL_SUPPORT

void KeyIsoP_set_default_dir(
    const char *defaultCertArea,
    const char *defaultCertDir)
{
    if (defaultCertArea && *defaultCertArea) {
        KeyIso_free(KEYISOP_defaultCertArea);
        KEYISOP_defaultCertArea = KeyIso_strndup(defaultCertArea, KEYISO_MAX_FILE_NAME);
    }

    if (defaultCertDir && *defaultCertDir) {
        KeyIso_free(KEYISOP_defaultCertDir);
        KEYISOP_defaultCertDir = KeyIso_strndup(defaultCertDir, KEYISO_MAX_PATH_LEN); // NULL terminator is included in KEYISO_MAX_PATH_LEN
    }
}


// Converts binary bytes to NULL terminated ascii hex characters.
// Returned hex needs (len * 2 + 1) characters
void KeyIsoP_bytes_to_hex(
    int len,
    const unsigned char *pb,
    char *hex)
{
    for (int i = 0; i < len; i++) {
        int b = (*pb & 0xF0) >> 4;
        *hex++ = (char) ((b <= 9) ? b + L'0' : (b - 10) + L'a');
        b = *pb & 0x0F;
        *hex++ = (char) ((b <= 9) ? b + L'0' : (b - 10) + L'a');
        pb++;
    }
    *hex++ = 0;
}

//
// KEYISO configuration functions. Mainly to configure for testing
//
// KeyIso_free() returned path name
char *KeyIsoP_get_path_name(
    const char *dir,
    const char *subPath)
{
    size_t dirLength = strlen(dir);
    size_t subPathLength = strlen(subPath);
    size_t pathNameLength = dirLength + 1 + subPathLength + 1;
    char *pathName = (char *) KeyIso_zalloc(pathNameLength);

    if (pathName != NULL) {
        snprintf(pathName, pathNameLength, "%s/%s",
            dir, subPath);
    }

    return pathName;
}

// Common 

void KeyIsoP_set_trace_log_filename(
    const char *filename)
{
    KeyIsoP_internal_set_trace_log_filename(filename);
}


void KeyIsoP_set_execute_flags_internal(
    int flags)
{
    if (flags & KEYISOP_IN_PROC_EXECUTE_FLAG) {
        KEYISOP_inProc = 1;
    }

    KeyIsoP_set_execute_flags(flags);
}


void KeyIsoP_set_execute_flags(
    int flags)
{
    if (flags & KEYISOP_TRACE_LOG_TEST_EXECUTE_FLAG) {
        KEYISOP_traceLogTest = 1;
    }

    if (flags & KEYISOP_TRACE_LOG_VERBOSE_EXECUTE_FLAG) {
        KEYISOP_traceLogVerbose = 1;
    }
}

//
// Key structure helper functions
//

size_t KeyIso_get_rsa_pkey_bytes_len(const KEYISO_RSA_PKEY_ST *rsaPkeySt)
{
    if(rsaPkeySt){
        return 
            rsaPkeySt->rsaModulusLen   +   // n
            rsaPkeySt->rsaPublicExpLen +   // e
            rsaPkeySt->rsaPrimes1Len   +   // p
            rsaPkeySt->rsaPrimes2Len;      // q
    }
    return 0;
}

size_t KeyIso_get_ec_pkey_bytes_len(const KEYISO_EC_PKEY_ST *ecPkeySt)
{
    // EC private key dynamic len
    if(ecPkeySt){
        return 
            ecPkeySt->ecPubXLen      +   // x
            ecPkeySt->ecPubYLen      +   // y
            ecPkeySt->ecPrivKeyLen;      // d (private key)
    }
    return 0;
}

size_t KeyIso_get_enc_key_bytes_len(const uuid_t correlationId, uint32_t saltLen, uint32_t ivLen, uint32_t hmacLen, uint32_t encKeyLen)
{
    size_t totalLen = 0;
    if (KEYISO_ADD_OVERFLOW(saltLen, ivLen, &totalLen) ||
        KEYISO_ADD_OVERFLOW(totalLen, hmacLen, &totalLen) ||
        KEYISO_ADD_OVERFLOW(totalLen, encKeyLen, &totalLen)) {
            KEYISOP_trace_log_error(correlationId, 0, KEYISOP_OPEN_KEY_TITLE, "KeyIso_get_enc_key_bytes_len", "Addition overflow");
            return 0;
        }
    
    return totalLen;
}

size_t KeyIso_get_rsa_enc_dec_with_attached_key_in_dynamic_bytes_len(const uuid_t correlationId, uint32_t saltLen, uint32_t ivLen, uint32_t hmacLen, uint32_t encKeyLen, uint32_t fromBytesLen, uint32_t labelLen)
{
    size_t dynamicLen = 0;
    size_t encDecParamDynamicLen = KeyIso_get_rsa_enc_dec_params_dynamic_len(fromBytesLen, labelLen);
    size_t encKeyDynamicLen = KeyIso_get_enc_key_bytes_len(correlationId, saltLen, ivLen, hmacLen, encKeyLen);

    if (KEYISO_ADD_OVERFLOW(encDecParamDynamicLen, encKeyDynamicLen, &dynamicLen)) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_RSA_PKEY_ENC_DEC_TITE, "KeyIso_get_rsa_enc_dec_with_attached_key_in_dynamic_bytes_len", "Addition with enc key overflow");
        return 0;
    }
    
    return dynamicLen;
}

size_t KeyIso_get_ecdsa_sign_with_attached_key_in_dynamic_bytes_len(const uuid_t correlationId, uint32_t saltLen, uint32_t ivLen, uint32_t hmacLen, uint32_t encKeyLen, uint32_t digestLen)
{
    size_t dynamicLen = 0;
    size_t encKeyDynamicLen = KeyIso_get_enc_key_bytes_len(correlationId, saltLen, ivLen, hmacLen, encKeyLen);
    if (KEYISO_ADD_OVERFLOW(encKeyDynamicLen, digestLen, &dynamicLen)) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_ECDSA_PKEY_SIGN_TITLE, "KeyIso_get_ecdsa_sign_with_attached_key_in_dynamic_bytes_len", "Addition overflow");
        return 0;
    }
    
    return dynamicLen;
}

size_t KeyIso_get_rsa_enc_dec_params_dynamic_len(uint32_t fromBytesLen, uint32_t labelLen)
{
    int32_t totalLen = 0;
    if (KEYISO_ADD_OVERFLOW(fromBytesLen, labelLen, &totalLen)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid format", "Invalid total length");
        return 0;
    }

    if (totalLen  <= 0) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, "Invalid format", "Invalid total length");
        return 0;
    }

    return (size_t)totalLen;
}

void KeyIso_fill_rsa_enc_dec_param(
    KEYISO_RSA_PRIVATE_ENC_DEC_IN_PARAMS_ST *params,
    int decrypt,
    int padding,
    int tlen,
    int flen,
    int labelLen,
    const unsigned char *bytes)
{
    params->decrypt = decrypt;
    params->padding = padding;
    params->tlen = tlen;
    params->fromBytesLen = flen;
    params->labelLen = labelLen;
    size_t dynamicLen = KeyIso_get_rsa_enc_dec_params_dynamic_len(flen, labelLen);
    if (dynamicLen == 0 || bytes == NULL) {
        return;
    }
    memcpy(params->bytes, bytes, dynamicLen);
}

unsigned int KeyIso_get_key_padded_size(const unsigned int inLength){
    // Calculate the blocks needed - PKCS7 rounds the latest block to 16, if the block is 16 it will add another block
    // This will add 16 to inLength, then round down to the nearest multiple of 16 by doing AND with all zeros of the -1 value
    return (inLength + KMPP_AES_BLOCK_SIZE) & ~(KMPP_AES_BLOCK_SIZE - 1);
}

// Puts the size into outLength and returns status if the calculation was succeeded
int KeyIso_symmetric_key_encrypt_decrypt_size(
    const int mode,
    const unsigned int inLength,
    const unsigned int metadataLength,
    unsigned int *outLength)
{
    unsigned int blobLen = KMPP_SYMMETRICKEY_BLOB_LEN;
    
    if (mode == KEYISO_AES_ENCRYPT_MODE) {
        *outLength = blobLen + metadataLength + KeyIso_get_key_padded_size(inLength);
    } else if (mode == KEYISO_AES_DECRYPT_MODE){
        if (inLength < blobLen + metadataLength) {
            return STATUS_FAILED;
        }
        *outLength = inLength - blobLen - metadataLength;
    } else {
        return STATUS_FAILED;
    }

    return STATUS_OK;
}



/////////////////////////////////////////////////////////////////
/////////////// BASE 64 Encode/Decode  /////////////////////////
///////////////////////////////////////////////////////////////

// Based o the following implementation : https://microsoft.visualstudio.com/OS/_git/os.2020?path=/onecore/ds/ds/src/util/base64/base64.c&_a=contents&version=GBofficial/main

static int _base64encode(
    const uuid_t correlationId,
    const void* pDecodedBuffer,
    uint32_t cbDecodedBufferSize,
    char* pszEncodedString,
    uint32_t cchEncodedStringSize,
    uint32_t* pcchEncoded)
/*

Routine Description:

    Encode string to base64

Arguments:

    pDecodedBuffer (IN) - buffer to encode.
    cbDecodedBufferSize (IN) - size of buffer to encode.
    cchEncodedStringSize (IN) - size of the buffer for the encoded string.
    pszEncodedString (OUT) = the encoded string.
    pcchEncoded (OUT) - size in characters of the encoded string.

Return Values:

    STATUS_OK
    STATUS_FAILED

--*/
{
    static char rgchEncodeTable[64] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
    };

    uint32_t  ib;
    uint32_t  ich;
    uint32_t  cchEncoded;
    uint8_t    b0, b1, b2;
    uint8_t *  pbDecodedBuffer = (uint8_t *) pDecodedBuffer;
    const char *title = "BASE64_ENCODE";

    // Calculate encoded string size.
    cchEncoded = KEYISOP_BASE64_ENCODE_LENGTH(cbDecodedBufferSize);
    
    if (NULL != pcchEncoded) {
        *pcchEncoded = cchEncoded;
    }

    if (cchEncodedStringSize == 0 && pszEncodedString == NULL) {
        return STATUS_FAILED;
    }

    if (cchEncodedStringSize < cchEncoded) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "base64 encode", " given buffer is too small to hold encoded string.",
            "Buffer encoded len: %d, expected: %d", cchEncodedStringSize, cchEncoded);
        return STATUS_FAILED;
    }

    // Encode data byte triplets into four-byte clusters.
    ib = ich = 0;
    while (ib < cbDecodedBufferSize) {
        b0 = pbDecodedBuffer[ib++];
        b1 = (ib < cbDecodedBufferSize) ? pbDecodedBuffer[ib++] : 0;
        b2 = (ib < cbDecodedBufferSize) ? pbDecodedBuffer[ib++] : 0;

        pszEncodedString[ich++] = rgchEncodeTable[b0 >> 2];
        pszEncodedString[ich++] = rgchEncodeTable[((b0 << 4) & 0x30) | ((b1 >> 4) & 0x0f)];
        pszEncodedString[ich++] = rgchEncodeTable[((b1 << 2) & 0x3c) | ((b2 >> 6) & 0x03)];
        pszEncodedString[ich++] = rgchEncodeTable[b2 & 0x3f];
    }

    // Pad the last cluster as necessary to indicate the number of data bytes
    // it represents.
    switch (cbDecodedBufferSize % 3) {
      case 0:
        break;
      case 1:
        pszEncodedString[ich - 2] = '=';
        // fall through
      case 2:
        pszEncodedString[ich - 1] = '=';
        break;
      default:
        // This can't happen because (cbDecodedBufferSize % 3) is 0..2.
        // Added to prevent compiler warning.
        break;
    }
    
    pszEncodedString[ich++] = '\0';
    return STATUS_OK;
}


static int _base64decode(
    const uuid_t correlationId,
    const char* pszEncodedString,
    void* pDecodeBuffer,
    uint32_t cbDecodeBufferSize,
    uint32_t* pcbDecoded)
/*

Routine Description:

    Decode a base64-encoded string.

Arguments:
    pszEncodedString (IN) - base64-encoded string to decode.
    cbDecodeBufferSize (IN) - size in bytes of the decode buffer.
    pbDecodeBuffer (OUT) - holds the decoded data.
    pcbDecoded (OUT) - number of data bytes in the decoded data (if success)

Return Values:
    STATUS_OK
    STATUS_FAILED
--*/
{
#define NA (255)
#define DECODE(x) (((size_t)(x) < sizeof(rgbDecodeTable)) ? rgbDecodeTable[x] : NA)

    static uint8_t rgbDecodeTable[128] = {
       NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,  // 0-15
       NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,  // 16-31
       NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 62, NA, NA, NA, 63,  // 32-47
       52, 53, 54, 55, 56, 57, 58, 59, 60, 61, NA, NA, NA,  0, NA, NA,  // 48-63
       NA,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,  // 64-79
       15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, NA, NA, NA, NA, NA,  // 80-95
       NA, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,  // 96-111
       41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, NA, NA, NA, NA, NA,  // 112-127
    };

    uint32_t  cbDecoded;
    uint32_t  cchEncodedSize;
    uint32_t  ich;
    uint32_t  ib;
    uint8_t   b0, b1, b2, b3;
    uint8_t*  pbDecodeBuffer = (uint8_t *) pDecodeBuffer;
    const char *title = "BASE64_DECODE";

    cchEncodedSize = strlen(pszEncodedString);
    if (NULL != pcbDecoded) {
        *pcbDecoded = 0;
    }

    if ((0 == cchEncodedSize) || (0 != (cchEncodedSize % 4))) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "base64 decode", 
                    "input string is not sized correctly to be base64", "encoded len: %d", cchEncodedSize);
        return STATUS_FAILED;
    }

    // Calculate decoded buffer size.
    cbDecoded = (cchEncodedSize + 3) / 4 * 3;
    // Check for trailing zero bytes: "xxx=" "xx=="
    if (pszEncodedString[cchEncodedSize-1] == '=') {
        if (pszEncodedString[cchEncodedSize-2] == '=') {
            // Only one data byte is encoded in the last cluster.
            cbDecoded -= 2;
        }
        else {
            // Only two data bytes are encoded in the last cluster.
            cbDecoded -= 1;
        }
    }

    if (NULL != pcbDecoded) {
        *pcbDecoded = cbDecoded;
    }

    if (cbDecodeBufferSize == 0 && pDecodeBuffer == NULL) {
        return STATUS_OK;
    }

    if (cbDecoded > cbDecodeBufferSize) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "base64 decode", 
            "Supplied buffer is too small.", "decoded buff len: %d, decoded len:%d", cbDecodeBufferSize, cbDecoded);
        return STATUS_FAILED;
    }

    // Decode each four-byte cluster into the corresponding three data bytes.
    ich = ib = 0;
    while (ich < cchEncodedSize) {
        // pszEncodedString is casted to unsigned char to avoid compiler warning about negative index
        b0 = DECODE((unsigned char)pszEncodedString[ich]); ich++;
        b1 = DECODE((unsigned char)pszEncodedString[ich]); ich++;
        b2 = DECODE((unsigned char)pszEncodedString[ich]); ich++;
        b3 = DECODE((unsigned char)pszEncodedString[ich]); ich++;

        if ((NA == b0) || (NA == b1) || (NA == b2) || (NA == b3)) {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "base64 decode", 
                    "Contents of input string are not base64", "ich:%u , buff:%s\n", ich, pszEncodedString);
            return STATUS_FAILED;
        }

        pbDecodeBuffer[ib++] = (b0 << 2) | (b1 >> 4);

        if (ib < cbDecoded) {
            pbDecodeBuffer[ib++] = (b1 << 4) | (b2 >> 2);

            if (ib < cbDecoded) {
                pbDecodeBuffer[ib++] = (b2 << 6) | b3;
            }
        }
    }

    return STATUS_OK;
}

//-----------------------------------------------------------------------
// Returns number of encoded bytes. For a decode error returns -1.
int KeyIso_base64_encode(
    const uuid_t correlationId,
    const unsigned char *bytes,
    int bytesLength,
    char **str)      // KeyIso_free()
{
    const char *title = KEYISOP_SUPPORT_TITLE;
    unsigned int encodeLength = 0;
    unsigned int base64Length = KEYISOP_BASE64_ENCODE_LENGTH(bytesLength); // includes NULL terminator
    int res = -1;

    *str = NULL;

    *str = (char*) KeyIso_zalloc(base64Length);
    if (*str == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "KeyIso_base64_encode", "allocation failed");
        return res;
    }
    
    if (_base64encode(correlationId, bytes, bytesLength, *str, base64Length, &encodeLength) != STATUS_OK) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "KeyIso_base64_encode", "base64encode failed",
            "length: %d expected: %d", encodeLength, base64Length);
        KeyIso_free(*str);
        return res;
    }
    if (encodeLength != base64Length) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "KeyIso_base64_encode", "Invalid encode length",
            "length: %d expected: %d", encodeLength, base64Length);
        KeyIso_free(*str);
        return res;
    }

    return encodeLength;
}

int KeyIso_base64_decode(
    const uuid_t correlationId,
    const char *str,
    unsigned char **bytes)      // KeyIso_free()
{
    const char *title = KEYISOP_SUPPORT_TITLE;
    unsigned int length = -1;
    int res = -1;
    int strLength = (int) strlen(str);
    int allocLength = 0;

    *bytes = NULL;

    // Remove any trailing \r\n or whitespace that might have been appended while editing the file
    // containing.
    for (; strLength > 0; strLength--) {
        if (!isspace(str[strLength - 1])) {
            break;
        }
    }

    if (strLength % 4 != 0 || strLength / 4 == 0) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "LengthCheck", "Invalid length",
            "length: %d", strLength);
        return length;
    }

    allocLength = ((strLength + 3) / 4) * 3 ;
    *bytes = (unsigned char *) KeyIso_zalloc(allocLength);
    if (*bytes == NULL) {
        return length;
    }

    res = _base64decode(correlationId, str, *bytes, allocLength, &length);
    if (res != STATUS_OK ) {
          KEYISOP_trace_log_error_para(correlationId, 0, title, "base64_decode", "base64decode failed",
            "res: %d, length: %d, expected: %d", res, length, allocLength);

        KeyIso_free(*bytes);
        *bytes = NULL;
        length = -1;
        return length;
    }


    return length;
}

// Retrieve the RSA sign data from the buffer
int KeyIso_retrieve_rsa_sig_data( const uuid_t correlationId, const char* title,
                                    uint32_t modulusSize, int flen, const unsigned char *from, 
                                     int tlen, KEYISO_RSA_SIGN *rsaSign)
{
    int res = STATUS_FAILED;
    unsigned int hashOffset = 0;

    if (from == NULL || rsaSign == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid input", "from, to and rsaSign can't be null");
        return res;
    }

    hashOffset = sizeof(*rsaSign);
    if ((uint32_t)tlen < modulusSize) {
         KEYISOP_trace_log_error_para(correlationId, 0, title, "SignatureLength","Invalid length", "Length: %d Expected max length: %d", tlen, modulusSize);
        return res;
    }

    if ((uint32_t)flen <= hashOffset) {
         KEYISOP_trace_log_error_para(correlationId, 0, title, "flen", "Invalid Length", "Length: %d Expected max length: %d", flen, hashOffset);
        return res;
    }

    memcpy(rsaSign, from, hashOffset);
    if (rsaSign->m_len != (uint32_t)flen - hashOffset) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "hashOffset", "Invalid message Length", "Length: %d, flen: %d, hashOffset: %d", rsaSign->m_len, flen, hashOffset);
        return res;
    }
    return STATUS_OK;
}

int KeyIso_retrieve_evp_pkey_sign_data( const uuid_t correlationId, const char* title,
                             uint32_t modulusSize, int flen, const unsigned char *from, 
                             int tlen, KEYISO_EVP_PKEY_SIGN *pkeySign)
{
    int res = STATUS_FAILED;
    unsigned int hashOffset =  0;

    if (from == NULL || pkeySign == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Invalid input", "from and pkeySign can't be null");
        return res;
    }

    hashOffset = sizeof(*pkeySign);

    if (tlen < 0  || flen < 0 ) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "Length", "Invalid length", "to len: %d from len: %d", tlen, flen);
        return res;
    }

    if ((uint32_t)tlen < modulusSize) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "SignatureLength", "Invalid length", "Length: %d Expected: %d", tlen, modulusSize);
        return res;
    }
    
    if ((uint32_t)flen < hashOffset) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "flen", "Invalid Length", "Length: %u Expected: %d", (uint32_t)flen, hashOffset);
        return res;
    }

    memcpy(pkeySign, from, hashOffset);
    if (pkeySign->tbsLen != (uint32_t)flen - hashOffset) {
        KEYISOP_trace_log_error(correlationId, 0, title, "hashOffset", "Invalid message Length");
        return res;
    }
    return STATUS_OK;
}