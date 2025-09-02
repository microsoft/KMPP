/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#pragma once

#ifdef KMPP_OPENSSL_SUPPORT
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#endif //KMPP_OPENSSL_SUPPORT

#include <inttypes.h>
#include <stdbool.h>

#ifdef KEYISO_TEST_WINDOWS
typedef unsigned char uuid_t[16];
#else
#include <uuid/uuid.h>
#endif

#ifdef  __cplusplus
extern "C" {
#endif 

//  This header file should contain only declarations and definitions that are common for both KMPP client and key isolation service 

/*
//     Definitions
*/

#define KEYISO_ADD_OVERFLOW(a, b, res) __builtin_add_overflow(a, b, res)
#define KEYISO_SUB_OVERFLOW(a, b, res) __builtin_sub_overflow(a, b, res)
#define KEYISO_MUL_OVERFLOW(a, b, res) __builtin_mul_overflow(a, b, res)

// Includes NULL terminator character
#define KEYISOP_BASE64_ENCODE_LENGTH(inLength) ((((inLength + 3 - 1) / 3) * 4) + 1)

#define STATUS_FAILED                      0
#define STATUS_OK                          1
#define STATUS_NOT_FOUND                   2

#define KEYISO_MAX_FILE_NAME 256 //  == NAME_MAX (which is not supported for TA compilation) + 1 for NULL terminator
#define KEYISO_MAX_PATH_LEN 4096 // == PATH_MAX (which is not supported for TA compilation). NULL terminator is included.

// IPC defines for private_encrypt_decrypt
#define KEYISO_IPC_RSA_PRIV_ENCRYPT        0
#define KEYISO_IPC_RSA_PRIV_DECRYPT        1
#define KEYISO_IPC_RSA_SIGN                2
#define KEYISO_IPC_PKEY_SIGN               3

// IPC defines for import_symmetric_key
#define KEYISO_IPC_SYMMETRIC_KEY_AES_CBC   0

#define KEYISO_CERT_LOCATION_ROOT          1 
#define KEYISO_CERT_LOCATION_DISALLOWED    2 

#define KEYISO_CERT_CTRL_IMPORT            1
#define KEYISO_CERT_CTRL_REMOVE            2
#define KEYISO_CERT_CTRL_FIND              3
#define KEYISO_CERT_CTRL_ENUM              4

#define KEYISO_SECRET_SALT_LENGTH          4    // The client must knows this value for the serialization
#define KEYISO_SECRET_SALT_STR_BASE64_LEGACY_LEN  2 + KEYISOP_BASE64_ENCODE_LENGTH(KEYISO_SECRET_SALT_LENGTH + 16) // including 0. prefix and null terminator
#define KEYISO_SECRET_SALT_STR_BASE64_LEN  KEYISOP_BASE64_ENCODE_LENGTH(32 + 2) // including 0. prefix and null terminator
           
// The rest of the execute flags are external and defined in keyisoutils.h. Only the ones below are internal and should not be exposed. 
// Those values should be in correlation with the values in keyisoutils.h
#define KEYISOP_IN_PROC_EXECUTE_FLAG           (KEYISOP_LAST_EXTERNAL_EXECUTE_FLAG * 2) //8

#define KMPP_KEY_USAGE_STR                 "key_usage"
#define KEYISO_SERVICE_VERSION_FILENAME    "service.version"

// Compatibility modes
#define NOT_COMPATIBLE             0
#define COMPATIBLE                 1

#define NOT_FIPS_COMPATIBLE        NOT_COMPATIBLE
#define FIPS_COMPATIBLE            COMPATIBLE

#define NOT_PKCS8_COMPATIBLE       NOT_COMPATIBLE
#define PKCS8_COMPATIBLE           COMPATIBLE

typedef enum
{
    KeyisoCompatibilityMode_fips = 0,
    KeyisoCompatibilityMode_pkcs8,
    KeyisoCompatibilityMode_max
} KeyisoCompatibilityMode;

// KeyIso versions
#define KEYISOP_INVALID_VERSION    0
#define KEYISOP_VERSION_1          1
#define KEYISOP_VERSION_2          2
#define KEYISOP_VERSION_3          3
#define KEYISOP_VERSION_4          4

// service.version == KEYISOP_CURRENT_VERSION
#define KEYISOP_CURRENT_VERSION                     KEYISOP_VERSION_4
#define KEYISOP_FIPS_MIN_VERSION                    KEYISOP_VERSION_2
#define KEYISOP_PKCS8_MIN_VERSION                   KEYISOP_VERSION_3

#define KEYISO_PKEY_VERSION 1

#define KEYISO_RSA_PRIVATE_PKEY_MAGIC   0x32415352 // RSA2
#define KEYISO_EC_PRIVATE_PKEY_MAGIC    0x32434345 // ECC2
#define KEYISO_PKEY_MAGIC_UNINITIALIZED 0x00000000 // uninitialized magic, for structs that don't fully support magic yet

#define KEYISO_AES_ENCRYPT_MODE     0
#define KEYISO_AES_DECRYPT_MODE     1

#define KMPP_AES_BLOCK_SIZE         16  //The value of SYMCRYPT_AES_BLOCK_SIZE
#define KMPP_AES_256_KEY_SIZE       32
#define KMPP_AES_512_KEY_SIZE       64

#define KMPP_SALT_SHA256_SIZE             32
#define KMPP_MAX_SECRET_ID_SIZE           32 // Secret id in process-based is the GUID (size of UUID) and in TA is the extra salt that used to derive from HUK (32 bytes buffer)
#define KMPP_HMAC_SHA256_KEY_SIZE         32
#define KMPP_AES_256_HMAC_SHA256_KEY_SIZE KMPP_AES_256_KEY_SIZE + KMPP_HMAC_SHA256_KEY_SIZE

#define KMPP_RSA_MIN_MODULUS_BITS           2048
#define KMPP_OPENSSL_RSA_MAX_MODULUS_BITS   16384 //same as OPENSSL_RSA_MAX_MODULUS_BIT in rsa.h

#define KMPP_ONE_KILOBYTE 1024
#define KMPP_ONE_MEGABYTE KMPP_ONE_KILOBYTE * KMPP_ONE_KILOBYTE
#define KMPP_MAX_MESSAGE_SIZE KMPP_ONE_MEGABYTE * 32 // based on "max_message_size" which is the upper limit in GDBUS for a message size including pfx
#define KEYISO_MAX_OPAQUE_DATA_LEN KMPP_MAX_MESSAGE_SIZE

// Limit the keyId to the max message length that could returned    
// in GDBUS after the initial encryption in base64 which is the format of the keyId
#define KEYISO_MAX_KEY_ID_LEN KEYISOP_BASE64_ENCODE_LENGTH(KMPP_MAX_MESSAGE_SIZE) 

#define KEYISO_SYMCRYPT_RSA_SUPPORTED_NUM_OF_PRIMES      2
#define KEYISO_SYMCRYPT_RSA_MIN_BITSIZE_MODULUS          256  // based on SYMCRYPT_RSAKEY_MIN_BITSIZE_MODULUS


// SymCrypt & OpenSSL params
#define KEYISO_SYMCRYPT_RSA_PARAMS_VERSION           1
#define KEYISO_SYMCRYPT_RSA_PARAMS_N_PUB_EXP         1

// OpenSSL Paddings
#define KMPP_RSA_PKCS1_PADDING       1     // RSA_PKCS1_PADDING
#define KMPP_RSA_NO_PADDING          3     // RSA_NO_PADDING
#define KMPP_RSA_PKCS1_OAEP_PADDING  4     // RSA_PKCS1_OAEP_PADDING
#define KMPP_RSA_PKCS1_PSS_PADDING   6     // RSA_PKCS1_PSS_PADDING

// The minimum PKCS1 padding is 11 bytes
#define KMPP_MIN_PKCS1_PADDING 11
#define KMPP_MIN_OAEP_PADDING  42

#define KMPP_RSA_DEFAULT_BITS	     2048 //SCOSSL_RSA_DEFAULT_BITS

// Hash digest lengths (same values as defined in OpenSSL)
#define KMPP_MD5_DIGEST_LENGTH      16
#define KMPP_SHA1_DIGEST_LENGTH     20
#define KMPP_MD5_SHA1_DIGEST_LENGTH (KMPP_MD5_DIGEST_LENGTH + KMPP_SHA1_DIGEST_LENGTH) // 36
#define KMPP_SHA256_DIGEST_LENGTH   32
#define KMPP_SHA384_DIGEST_LENGTH   48
#define KMPP_SHA512_DIGEST_LENGTH   64

// Hash digest identifier (same values as defined in OpenSSL)
#define KMPP_NID_sha1       64   // NID_sha1
#define KMPP_NID_md5        4 
#define KMPP_NID_md5_sha1   114
#define KMPP_NID_sha256     672
#define KMPP_NID_sha384     673
#define KMPP_NID_sha512     674
#define KMPP_NID_sha3_256   1097
#define KMPP_NID_sha3_384   1098
#define KMPP_NID_sha3_512   1099

// Same values as defined in rsa.h OpenSSL header
/* Salt length matches digest */
#define KMPP_RSA_PSS_SALTLEN_DIGEST -1
/* Verify only: auto detect salt length */
#define KMPP_RSA_PSS_SALTLEN_AUTO   -2
/* Set salt length to maximum possible */
#define KMPP_RSA_PSS_SALTLEN_MAX    -3
/* Old compatible max salt length for sign only */
# define KMPP_RSA_PSS_SALTLEN_MAX_SIGN    -2
/* Maximum salt length for the digest, relevant from OpenSSL 3.1 */
#define KMPP_RSA_PSS_SALTLEN_AUTO_DIGEST_MAX             -4 

#define VERSION_CHAR                  'n' // The first byte of the keyId is 'n' for new versions and 0 for legacy code
#define CLIENT_DATA_DELIMITER          ':'
#define MIN_CLIENT_DATA_LENGTH         sizeof(KEYISO_CLIENT_KEYID_HEADER_ST)
#define MIN_CLIENT_DATA_LENGTH_BASE64_LEN  KEYISOP_BASE64_ENCODE_LENGTH(MIN_CLIENT_DATA_LENGTH)
#define MAX_CLIENT_DATA_BASE64_LENGTH  KMPP_MAX_MESSAGE_SIZE

// Log provider defines
typedef enum
{
    KeyisoLogProvider_syslog = 0,
    KeyisoLogProvider_stdout,
    KeyisoLogProvider_max
} KeyisoLogProvider;

typedef enum {
    KeyIsoSolutionType_invalid = 0,
    KeyIsoSolutionType_process,
    KeyIsoSolutionType_tz,
    KeyIsoSolutionType_tpm, 
    KeyIsoSolutionType_max
} KeyIsoSolutionType;

#if defined(KMPP_RUNNING_ON_CONTAINERS)
    #define KEYISO_PROVIDER_DEFAULT KeyisoLogProvider_stdout
#else
    #define KEYISO_PROVIDER_DEFAULT KeyisoLogProvider_syslog
#endif

// Symmetric Key defines
#define KMPP_SYMMETRICKEY_VERSION_BYTES  2 // the version contains 2 bytes for version and security version
// Every symmetric key contains versions + IV(KMPP_AES_BLOCK_SIZE)
#define KMPP_SYMMETRICKEY_KEY_LEN        KMPP_SYMMETRICKEY_VERSION_BYTES + KMPP_AES_BLOCK_SIZE
// Symmetric key blob len contains KMPP_SYMMETRICKEY_KEY_LEN + HMAC result (KMPP_HMAC_SHA256_KEY_SIZE)
#define KMPP_SYMMETRICKEY_BLOB_LEN       KMPP_SYMMETRICKEY_KEY_LEN + KMPP_HMAC_SHA256_KEY_SIZE
// Key metadata contains salt (KMPP_SALT_SHA256_SIZE) and importKeyId (KMPP_AES_256_KEY_SIZE)
#define KMPP_SYMMETRICKEY_META_DATA_LEN  KMPP_SALT_SHA256_SIZE + KMPP_AES_256_KEY_SIZE

// Externals
extern int KEYISOP_inProc;
extern int KEYISOP_useTestPfxSecret;

/*
*    Structures
*/

typedef struct KeyIso_key_details_st KEYISO_KEY_DETAILS;
struct KeyIso_key_details_st
{
    unsigned long        keyId;
    int                  keyLength;
    unsigned char        *keyBytes;      // Allocation included in outer struct
    void                 *clientData;     // Points to KEYISO_CLIENT_DATA_ST structure
    void                 *interfaceSession;
}; 


typedef struct KeyIso_key_ctx_st KEYISO_KEY_CTX;
struct KeyIso_key_ctx_st {
    uuid_t                     correlationId;
    void                       *pkey;
    void                       *keyDetails;
    bool                       isP8Key;  // Indication whether the encrypted key is pkcs#8 or does it expects the pkcs#12 format(BC)
    void                       *keysInUseCtx; //An opaque handle for the keys in use context
};

typedef struct KeyIso_rsa_sign_st KEYISO_RSA_SIGN;
struct KeyIso_rsa_sign_st {
    int32_t                     type;       // Message digest algorithm
    uint32_t                    m_len;      // Message digest length
};

typedef struct KeyIso_evp_pkey_sign_st KEYISO_EVP_PKEY_SIGN;
struct KeyIso_evp_pkey_sign_st {
    uint64_t                    tbsLen;     // Length of the data to be signed
    uint64_t                    sigLen;     // Length of the signature
    int32_t                     saltLen;    // RSA PSS salt length
    int32_t                     sigmdType;  // NID of signature algorithm
    int32_t                     mgfmdType;  // NID of MGF1 digest
    int32_t                     getMaxLen;  // Indicate to only calculate the max siglen 
};

#define NUM_OF_PKEY_HEADER_ELEMENTS 2
typedef struct keyiso_key_header_st KEYISO_KEY_HEADER_ST;
struct keyiso_key_header_st {
    uint32_t  keyVersion;         // Key version
    uint32_t  magic;              // RSA key magic number
};

#define NUM_OF_RSA_PKEY_ELEMENTS 7
typedef struct keyiso_rsa_pkey_st KEYISO_RSA_PKEY_ST;
struct keyiso_rsa_pkey_st {
    KEYISO_KEY_HEADER_ST header;
    uint8_t   rsaUsage;           // key usage
    uint32_t  rsaModulusLen;      // n len
    uint32_t  rsaPublicExpLen;    // e len
    uint32_t  rsaPrimes1Len;      // p len
    uint32_t  rsaPrimes2Len;      // q len
//  uint32_t  rsa_d_len;  // Private Exponent
//  uint32_t  rsa_dp_len; // Exponent1(used in the CRT optimization)
//  uint32_t  rsa_dq_len; // Exponent2(used in the CRT optimization)
//  uint32_t  rsa_qInv;   // CRT coefficient 
    uint8_t rsaPkeyBytes[];
};

typedef struct keyiso_rsa_public_key_st KEYISO_RSA_PUBLIC_KEY_ST;
struct keyiso_rsa_public_key_st {
    KEYISO_KEY_HEADER_ST header;
    uint32_t  rsaModulusLen;      // n len
    uint32_t  rsaPublicExpLen;    // e len
    uint8_t   rsaPubKeyBytes[];
};

#define NUM_OF_EC_PKEY_ELEMENTS 7
typedef struct keyiso_ec_pkey_st KEYISO_EC_PKEY_ST;
struct keyiso_ec_pkey_st {
    KEYISO_KEY_HEADER_ST header;
    uint8_t  ecUsage;       // key usage
    uint32_t ecCurve;       // crv group NID
    uint32_t ecPubXLen;     // x len
    uint32_t ecPubYLen;     // y len
    uint32_t ecPrivKeyLen;  // d len
    uint8_t ecKeyBytes[];  
};

typedef struct keyiso_ec_public_key_st KEYISO_EC_PUBLIC_KEY_ST;
struct keyiso_ec_public_key_st {
    KEYISO_KEY_HEADER_ST header;
    uint32_t ecCurve;       // crv group NID
    uint32_t ecPubKeyLen;
    uint8_t  ecPubKeyBytes[];
};

// Header sent from the service 
// Contains version and isolation solution that the key was created by
#define NUM_OF_CLIENT_METADATA_HEADER_IN_ELEMENTS 2
typedef struct keyiso_client_metadata_header_st {
    uint8_t version;
    uint16_t isolationSolution;
} __attribute__((packed)) KEYISO_CLIENT_METADATA_HEADER_ST;

typedef enum {
    KmppKeyIdType_asymmetric = 0,
    KmppKeyIdType_symmetric,
    KmppKeyIdType_max
} KmppKeyIdType;

// KeyId metadata header
typedef struct keyiso_client_keyid_header_st KEYISO_CLIENT_KEYID_HEADER_ST;
struct keyiso_client_keyid_header_st {
    uint8_t clientVersion;       // Version of the client that created the keyid 
    uint8_t keyServiceVersion;   // Version of the service that created the key
    uint16_t isolationSolution;  // Isolation solution used to create the key
    KmppKeyIdType keyType;       // Symmetric/Asymmetric key-id type
};

// Client data structure - Asymmetric key - Formted to keyid by the client
typedef struct keyiso_encryption_extra_data_header_st KEYISO_CLIENT_DATA_ST;
struct keyiso_encryption_extra_data_header_st {
    KEYISO_CLIENT_KEYID_HEADER_ST keyIdHeader;   // KeyId metadata header
    uint32_t pubKeyLen;  
    uint8_t pubKeyBytes[]; // ASN1 encoded public key 
};

#define NUM_OF_RSA_PRIVATE_ENC_DEC_IN_PARAMS_ELEMENTS 6
typedef struct keyiso_rsa_private_encrypt_decrypt_input_params_st KEYISO_RSA_PRIVATE_ENC_DEC_IN_PARAMS_ST;
struct keyiso_rsa_private_encrypt_decrypt_input_params_st {
    int32_t decrypt;
    int32_t padding; 
    int32_t tlen; 
    int32_t fromBytesLen; 
    int32_t labelLen;
    uint8_t bytes[]; // From and label bytes
};

/*
*    Functions
*/

static inline bool KeyIso_is_legacy(const char *keyId) {
    return (keyId && (keyId[0] != VERSION_CHAR));
}

static inline size_t KeyIso_get_client_data_maximum(const char *keyId) {
    return KeyIso_is_legacy(keyId) ? KEYISO_SECRET_SALT_STR_BASE64_LEGACY_LEN : MAX_CLIENT_DATA_BASE64_LENGTH + 1;
}

static inline size_t KeyIso_get_client_data_minimum(const char *keyId) 
{
    return KeyIso_is_legacy(keyId) ? KEYISO_SECRET_SALT_STR_BASE64_LEGACY_LEN - 1 : MIN_CLIENT_DATA_LENGTH_BASE64_LEN;
}

// Implemented in keyisolog.c
void KeyIso_set_log_provider(
    KeyisoLogProvider provider);

/*
//     Common Utils Functions 
//     implemented in keyisoutils.c
*/

bool KeyIso_is_valid_keyid_header(
    const uuid_t correlationId,
    KeyIsoSolutionType expectedSolutionType,
    const KEYISO_CLIENT_KEYID_HEADER_ST* keyIdHeader);

// Find delimiter between client data and PFX bytes
const char *KeyIso_get_delimiter_ptr(const char *keyId);

// Extracts the client data from the keyId, used also by the gdbus service(KMPP key opened by MScrypt client)
int KeyIso_get_client_data_from_keyid(
    const uuid_t correlationId,
    KeyIsoSolutionType expectedSolutionType,
    const char *keyId, // Expects new version keyid format:  'n' <Base64 ExtraDataBuffer> ':' <Base64 PFX>
    char **clientData); // Base64 encoded string, KeyIso_free()

char* KeyIso_get_base64_client_data(
    const uuid_t correlationId,
    const char *title,
    const KEYISO_CLIENT_DATA_ST  *clientDataSt);

// Decode client client data string from base 64 format and validate.
int KeyIso_decode_and_validate_base64_client_data(
    const uuid_t correlationId,
    const char *clientDataStr,
    KEYISO_CLIENT_DATA_ST **outDecodedClientData,
    uint32_t *outClientDataLen);

// Extracts the client data from the PFX bytes
int KeyIso_get_client_data_from_key_bytes(
    const uuid_t correlationId, 
    const char *clientDataStr, 
    KEYISO_CLIENT_DATA_ST **outClientData);

void KeyIsoP_set_execute_flags_internal(
    int flags);
    
unsigned int KeyIsoP_read_version_file(
    const uuid_t correlationId,
    const char *filename);

// Placed here so will not be exposed to KMPP users
// Returns number of encoded bytes. For a decode error returns -1.
int KeyIso_base64_encode(
    const uuid_t correlationId,
    const unsigned char *bytes,
    int bytesLength,
    char **str);      // KeyIso_free()

int KeyIso_get_rsa_pkey_bytes_len(const KEYISO_RSA_PKEY_ST *rsaPkeySt, uint32_t *outLen);
int KeyIso_get_ec_pkey_bytes_len(const KEYISO_EC_PKEY_ST *ecPkeySt, uint32_t *outLen);
int KeyIso_get_enc_key_bytes_len_params(const uuid_t correlationId, uint32_t secretSaltLen, uint32_t ivLen, uint32_t hmacLen, uint32_t encKeyLen, uint32_t secretIdLen, uint32_t *outLen);
int KeyIso_get_rsa_enc_dec_with_attached_key_in_dynamic_bytes_len(const uuid_t correlationId, uint32_t publicKeyLen, uint32_t opaqueEncKeyLen, uint32_t fromBytesLen, uint32_t labelLen, uint32_t *outLen);
int KeyIso_get_ecdsa_sign_with_attached_key_in_dynamic_bytes_len(const uuid_t correlationId, uint32_t publicKeyLen, uint32_t opaqueEncKeyLen, uint32_t digestLen, uint32_t *outLen);
int KeyIso_get_rsa_enc_dec_params_dynamic_len(uint32_t fromBytesLen, uint32_t labelLen, uint32_t *outLen);
void KeyIso_fill_rsa_enc_dec_param(KEYISO_RSA_PRIVATE_ENC_DEC_IN_PARAMS_ST *params, int decrypt, int padding, int tlen, int flen, int labelLen,const unsigned char *bytes);

// Helper function to get the size of the padded key (PKCS#7 padding)
unsigned int KeyIso_get_key_padded_size(const unsigned int inLength);

// Puts the size into outLength and returns status if the calculation was succeeded
int KeyIso_symmetric_key_encrypt_decrypt_size(
    const int mode,
    const unsigned int inLength,
    const unsigned int metadataLength,
    unsigned int *outLength);

int KeyIso_retrieve_rsa_sig_data(
    const uuid_t correlationId,
    const char* title,
    uint32_t modulusSize,
    int flen,
    const unsigned char *from, 
    int tlen,
    KEYISO_RSA_SIGN *rsaSign);

int KeyIso_retrieve_evp_pkey_sign_data(
    const uuid_t correlationId,
    const char* title,
    uint32_t modulusSize,
    int flen,
    const unsigned char *from, 
    int tlen,
    KEYISO_EVP_PKEY_SIGN *pkeySign);

/*
//     PFX Common Functions 
//     implemented in keyisopfxcommon.c
*/

#ifdef KMPP_OPENSSL_SUPPORT
// Helper function for PKCS#12 creation
// Returns BIO_s_mem().
BIO *KeyIsoP_create_pfx(
    const uuid_t correlationId,
    EVP_PKEY *key,
    X509 *cert,
    STACK_OF(X509) *ca,               // Optional
    const char *password,
    int *pfxLength,
    unsigned char **pfxBytes);       // Don't free

BIO *KeyIsoP_create_pfx_bio(
    const uuid_t correlationId,
    PKCS12 *p12,
    int *pfxLength,
    unsigned char **pfxBytes);

// Helper function for PKCS#12 parsing
// returns 1 for success and zero if an error occurred.
int KeyIso_pkcs12_parse(
    const uuid_t correlationId,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *inPassword,             // optional
    EVP_PKEY **outPkey,
    X509 **outCert,
    STACK_OF(X509) **outCa);

// Helper function for PKCS#12 parsing, 
// extracting PKCS#8 encrypted private key
// returns 1 for success and zero if an error occurred.
int KeyIso_pkcs12_parse_p8(
    const uuid_t correlationId,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    X509_SIG **outP8,
    X509 **outCert,
    STACK_OF(X509) **outCa);

int KeyIso_create_enckey_from_p8(
    const X509_SIG *p8,
    unsigned int *opaqueEncryptedKeyLen,
    unsigned char **opaqueEncryptedKey);

// Helper function for Key Generation
// OpenSSL Conf string loading.
int KeyIso_conf_load(
    const uuid_t correlationId,
    const char *confStr,
    CONF **conf);

// Helper function for Key Generation
// OpenSSL Conf string parsing.
const char *KeyIso_conf_get_string(
    const uuid_t correlationId,
    const CONF *conf,
    const char *name);

int KeyIso_conf_get_number(
    const uuid_t correlationId,
    const CONF *conf,
    const char *name,
    long *value);

int KeyIso_conf_get_curve_nid(
    const uuid_t correlationId,
    const CONF *conf,
    uint32_t *curve_nid);

int KeyIso_conf_get_name(
    const uuid_t correlationId,
    const CONF *conf,
    X509 *cert);

int KeyIso_conf_get_extensions(
    const uuid_t correlationId,
    CONF *conf,
    X509 *cert);

int KeyIso_conf_get_time(
    const uuid_t correlationId,
    const CONF *conf,
    X509 *cert);

EVP_PKEY *KeyIso_conf_generate_rsa(
    const uuid_t correlationId,
    const CONF *conf);

EVP_PKEY *KeyIso_conf_generate_ecc(
    const uuid_t correlationId,
    const CONF *conf);

int KeyIso_conf_sign(
    const uuid_t correlationId,
    CONF *conf,
    X509 *cert,
    EVP_PKEY *pkey);


void KeyIsoP_X509_pubkey_sha256_hex_hash(
	X509* x,
	char* hexHash);

void KeyIso_pkey_sha256_hex_hash(
    EVP_PKEY* pkey,
    char* hexHash);

// Converting received public key to EVP_PKEY
int KeyIso_get_ec_evp_pkey(
    const uuid_t correlationId,
    const KEYISO_EC_PKEY_ST* inEcStPkey,
    EC_KEY** outEcKey, 
    EC_GROUP** outEcGroup);

int KeyIso_get_ec_evp_pub_key(
    const uuid_t correlationId,
    uint32_t curve,
    const unsigned char *xBuff,
    uint32_t xLen,
    const unsigned char *yBuff,
    uint32_t yLen,
    EC_KEY** outEcKey, 
    EC_GROUP** outEcGroup);

// Implemented in keyisopbe.c
const void* KeyIso_pbe_get_algor_param_asn1(
    const char* title,
    const X509_ALGOR *algor,
    const char* expectedAlgOid);

bool KeyIso_is_equal_oid(const ASN1_OBJECT *oid, const char* expectedAlgOid);

#endif //KMPP_OPENSSL_SUPPORT

#ifdef  __cplusplus
}
#endif
