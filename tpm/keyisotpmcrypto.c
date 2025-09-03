/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <string.h>
#include <stdbool.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include "keyisotpmcrypto.h"
#include "keyisomemory.h"
#include "keyisolog.h"
#include "keyisotpmutils.h"

//***********************************
//             RSA                 **
//***********************************
//`RSA_private_encrypt()` handle RSA signatures at a low-level - usually this should not be invoked directly.
//  signs a message (`from`) of length `flen` using `rsa` private key, 
// storing the signature in `to`, which must have memory size of `RSA_size(rsa)`.
// `padding` is the padding mode, which must be one of the following: `RSA_PKCS1_PADDING`, `RSA_X931_PADDING`, or `RSA_NO_PADDING`.
// Returns the size of the signature on success, or -1 on error.
static bool _is_valid_input(const uuid_t correlationId, const char* title, const KEYISO_TPM_KEY_DETAILS *details)
{
    if (details == NULL || details->tpmContext == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "invalid input parameters", "details and tpm context can't be null");
        return false;
    }
     
    if (details->tpmContext->ectx == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "invalid input parameters", "Esys context is not initialized");
        return false;
    }
    
    if (details->keyHandle == ESYS_TR_NONE) {
        KEYISOP_trace_log_error(correlationId, 0, title, "invalid input parameters", "Key handle is not initialized");
        return false;
    }
    return true;
}

int KeyIso_TPM_rsa_private_decrypt(
    const uuid_t correlationId,
    const KEYISO_TPM_KEY_DETAILS *details,
    unsigned int flen,
    const unsigned char *from,
    unsigned int tlen,
    unsigned char *to,
    int padding,
    int labelLen)
{
    const char* title = KEYISOP_TPM_RSA_PRIV_DEC_TITLE;
    int ret = -1;
    TSS2_RC r;
    TPM2B_PUBLIC_KEY_RSA *message = NULL;
    TPMT_RSA_DECRYPT inScheme;
    
    if (!_is_valid_input(correlationId, title, details) || !from || !to) {
        KEYISOP_trace_log_error(correlationId, 0, title, "rsa private decrypt failed", "Invalid input parameters");
        return ret;
    }

    TPM2B_PUBLIC_KEY_RSA cipher = { .size = flen };
    if (flen > sizeof(cipher.buffer)) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "rsa private decrypt failed", "invalid from buff len", "flen:%d", flen);
        return ret;
    }

    memcpy(&cipher.buffer[0], from, flen);

    // Copy the last labelLen chars into label
    TPM2B_DATA label = { .size = labelLen };
    if (labelLen > 0) {
        if (labelLen > sizeof(label.buffer)) {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "rsa private decrypt failed", "invalid label len", "labelLen:%d", labelLen);
            return ret;
        }
        memcpy(&label.buffer[0], from + flen, labelLen);
    }
    
    switch (padding) {
        case RSA_PKCS1_PADDING:
            inScheme.scheme = TPM2_ALG_RSAES;
            break;
        case RSA_PKCS1_OAEP_PADDING:
            inScheme.scheme = TPM2_ALG_OAEP;
            inScheme.details.oaep.hashAlg = TPM2_ALG_SHA1;
            break;
        case RSA_NO_PADDING:
            inScheme.scheme = TPM2_ALG_NULL;
            break;
        default:
            KEYISOP_trace_log_error_para(correlationId, 0, title,  "rsa private decrypt failed", "Unsupported padding", "padding:%d", padding);
            return ret;
    }

    r = Esys_RSA_Decrypt(details->tpmContext->ectx, details->keyHandle,
                         ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                         &cipher, &inScheme, &label, &message);
    if (r != TSS2_RC_SUCCESS) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "rsa private decrypt failed", "Esys_RSA_Decrypt failed", "rc:%d", r);
        return ret;
    }

    int msgSize = (int)message->size;
    if (msgSize > tlen) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "rsa private decrypt failed", "Output buffer is too small", "msgSize:%d, tlen:%d", msgSize, tlen);
        Esys_Free(message);
        return ret;
    }

    memcpy(to, &message->buffer[0], msgSize);
    Esys_Free(message);
    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete: successful rsa private decrypt");
    return msgSize;
}

static uint16_t _get_hash_digest_size(const uuid_t correlationId,  const char* title, TPMI_ALG_HASH hashAlg) {
    switch (hashAlg) {
        case TPM2_ALG_SHA1:
            return SHA_DIGEST_LENGTH; // SHA-1 produces a 160-bit (20-byte) digest

        case TPM2_ALG_SHA256:
        case TPM2_ALG_SHA3_256:
            return SHA256_DIGEST_LENGTH; // SHA-256 produces a 256-bit (32-byte) digest

        case TPM2_ALG_SHA384:
        case TPM2_ALG_SHA3_384:
            return SHA384_DIGEST_LENGTH; // SHA-384 produces a 384-bit (48-byte) digest
        
        case TPM2_ALG_SHA512:
        case TPM2_ALG_SHA3_512:
            return SHA512_DIGEST_LENGTH; // SHA-512 produces a 512-bit (64-byte) digest
        
        default:
            KEYISOP_trace_log_error_para(correlationId, 0, title, "failed to get hash digest size", "Unknown or unsupported hash algorithm", "hashAlg:%u", hashAlg);
            return 0; // Unknown or unsupported hash algorithm
    }
}

static KEYISO_TPM_RET _sign(
    const uuid_t correlationId,
    const char* title,
    const KEYISO_TPM_KEY_DETAILS *details, 
    TPM2B_DIGEST *tpmDigestData,
    TPMT_SIG_SCHEME *inScheme,
    TPMT_TK_HASHCHECK *validation,
    TPMT_SIGNATURE **signature)
{
    if (!signature) {
        KEYISOP_trace_log_error(correlationId, 0, title, "tpm sign failed", "Invalid input parameters");
        return KEYISO_TPM_RET_BAD_PARAM;
    }

    TSS2_RC rc = Esys_Sign(details->tpmContext->ectx, details->keyHandle, 
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           tpmDigestData, inScheme, validation, signature);

    if (rc != TSS2_RC_SUCCESS) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "tpm sign failed", "Esys_Sign failed", "rc:%d", rc);
        KeyIso_free(*signature);
        *signature = NULL;
        return KeyIso_convert_ret_val(rc);
    }

    return KEYISO_TPM_RET_SUCCESS;
}

static int _rsa_sign(
    const uuid_t correlationId,
    const char* title,
    const KEYISO_TPM_KEY_DETAILS *details,
    unsigned int mLength,
    const unsigned char *m,
    unsigned int siglen,
    unsigned char* sig,
    TPMI_ALG_SIG_SCHEME sigScheme,
    TPMI_ALG_HASH  hashAlg)
{
    int ret = -1;
    uint16_t keySize = 0;

    if (_is_valid_input(correlationId, title, details) == false || !m ) {
        KEYISOP_trace_log_error(correlationId, 0, title, "rsa sign failed", "Invalid input parameters");
        return ret;
    }

    keySize = details->pub.publicArea.unique.rsa.size;
    if (!sig) {
        // The request is to get size
        return (int)keySize;
    }

    if  (siglen < keySize) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "rsa sign failed", "Output buffer is too small", "siglen:%u, keySize:%u", siglen, keySize);
        return ret;
    }

    if (keySize > INT_MAX) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "rsa sign failed", "Key size greater then int max value", "keySize:%u", keySize);
        return ret;
    }

    uint16_t algSize = _get_hash_digest_size(correlationId, title, hashAlg);
    if (mLength != algSize) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "rsa sign failed", 
                                    "The digest size is incompatible with algorithm size",
                                    "mLength:%u, maxSize:%u, hashAlg:%u", mLength, algSize, hashAlg);
        return ret;
    }
    
    if (hashAlg == TPM2_ALG_SHA1) {
         KEYISOP_trace_log_error(correlationId, KEYISOP_TRACELOG_WARNING_FLAG, title, 
                                 "Compliance warning",
                                 "Using Hmac algorithm SHA1 which is not FIPS compliant");
    }

    TPMT_SIG_SCHEME inScheme = {
        .scheme = sigScheme, 
        .details.rsassa.hashAlg = hashAlg,
    };

    TPMT_TK_HASHCHECK validation = {0};
    validation.tag = TPM2_ST_HASHCHECK;
    validation.hierarchy = TPM2_RH_OWNER;

    TPM2B_DIGEST tpmDigestData = { .size = mLength };
    if (tpmDigestData.size > sizeof(tpmDigestData.buffer)) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "rsa sign failed", "Digest size is too large", "digest.size:%u", tpmDigestData.size);
        return ret;
    }

    memcpy(tpmDigestData.buffer, m, mLength);
    
    TPMT_SIGNATURE *signature = NULL;
    if (_sign(correlationId, title, details, &tpmDigestData, &inScheme, &validation, &signature) != KEYISO_TPM_RET_SUCCESS) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "rsa sign failed", "Failed to sign", "ret:%d", ret);
        return ret;
    }

    if (keySize != signature->signature.rsassa.sig.size) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "rsa sign failed", "Signature size is incompatible with key size", "keySize:%u, sigSize:%u", keySize, signature->signature.rsassa.sig.size);
        Esys_Free(signature);
        return ret;
    }

    memcpy(sig, signature->signature.rsassa.sig.buffer, keySize);
    ret = (int)keySize;
    Esys_Free(signature);
    return ret;
}

static TPMI_ALG_HASH _get_tpm_hash_alg(uint32_t mdnid) 
{
    switch (mdnid)
    {
        case NID_sha256:
         return  TPM2_ALG_SHA256;
        case NID_sha384:
         return  TPM2_ALG_SHA384;
        case NID_sha512:  
            return TPM2_ALG_SHA512;          
        default:
            return TPM2_ALG_NULL;
    }
}

int KeyIso_TPM_pkey_rsa_sign(
    const uuid_t correlationId,
    const KEYISO_TPM_KEY_DETAILS *details,
    uint32_t mdnid,
    unsigned int mLength,
    const unsigned char *m,
    unsigned int siglen,
    unsigned char* sig,
    int padding)
{
   const char* title = KEYISOP_TPM_EPKEY_RSA_SIGN_TITLE;
   TPMI_ALG_HASH  hashAlg = _get_tpm_hash_alg(mdnid);
   TPMI_ALG_SIG_SCHEME sigScheme = TPM2_ALG_RSAPSS;
   int res = -1;
   if (hashAlg == TPM2_ALG_NULL) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "evp pkey rsa sign failed", "Unsupported hash algorithm", "mdnid:%u", mdnid);
        return res;
    }

    switch (padding) {
        case RSA_PKCS1_PADDING:
        // RSA-PKCS1
        sigScheme = TPM2_ALG_RSASSA;  //  NOT FIPS? ADD a warning?
        break;
    case RSA_PKCS1_PSS_PADDING:
        // TPM2_ALG_RSAPSS scheme is RSA-PSS (Probabilistic Signature Scheme) is a more secure signature scheme than RSA-PKCS1
        sigScheme = TPM2_ALG_RSAPSS;
        break;
    default:
        KEYISOP_trace_log_error_para(correlationId, 0, title, "evp pkey rsa sign failed", "Unsupported padding", "padding:%d", padding);
        return res;
    }

   int ret = _rsa_sign(correlationId, title, details, mLength, m, siglen, sig, sigScheme, hashAlg);

   if (ret <= 0) {
        KEYISOP_trace_log_error(correlationId, 0, title, "evp pkey rsa sign failed", "Failed to sign");  
   } else {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete: successful evp pkey rsa sign");
   }
    return ret;
}

int KeyIso_TPM_rsa_sign(
    const uuid_t correlationId,
    const KEYISO_TPM_KEY_DETAILS *details,
    uint32_t mdnid, // Message digest algorithm
    unsigned int mLength,
    const unsigned char *m,
    unsigned int siglen,
    unsigned char* sig)
{
    const char* title = KEYISOP_TPM_RSA_SIGN_TITLE;
    TPMI_ALG_HASH  hashAlg = _get_tpm_hash_alg(mdnid);
    if (hashAlg == TPM2_ALG_NULL) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "evp pkey rsa sign failed", "Unsupported hash algorithm", "mdnid:%u", mdnid);
        return -1;
    }
    int ret =  _rsa_sign(correlationId, title, details, mLength, m, siglen, sig, TPM2_ALG_RSASSA, hashAlg); // RSA-PKCS1 scheme
    if (ret < 0) {
        KEYISOP_trace_log_error(correlationId, 0, title, "rsa sign failed", "Failed to sign");  
   } else {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete: successful rsa sign");
    }
    return ret;
}

//***********************************
//             ECC                 **
//***********************************
static int _cleanup_tpm_ecdsa_sign(
    int ret,
    BIGNUM *bns,
    BIGNUM *bnr,
    ECDSA_SIG *ecdsaSig)
{
    if (bns) {
        BN_free(bns);
    }
    if (bnr) {
        BN_free(bnr);
    }

    if (ecdsaSig) {
        ECDSA_SIG_free(ecdsaSig);
    }

    return ret;
}

#define _CLEANUP_ECDSA_SIGN(ret) _cleanup_tpm_ecdsa_sign(ret, bns, bnr, ecdsaSig)

static uint16_t _get_key_size(const uuid_t correlationId, const char* title, TPMI_ECC_CURVE curveID) {
    switch (curveID) {
        case TPM2_ECC_NIST_P192:
         return 192;
        case TPM2_ECC_NIST_P224:
         return 224;
        case TPM2_ECC_NIST_P256:
         return 256;
        case TPM2_ECC_NIST_P384:
            return 384;
        case TPM2_ECC_NIST_P521:
            return 521;
        case TPM2_ECC_BN_P256:
            return 256;
        case TPM2_ECC_BN_P638:
            return 638;
        case TPM2_ECC_SM2_P256:
             return 256;
        default:
         return 0; // Unsupported curve
    }
}

int KeyIso_TPM_ecdsa_sign(
    const uuid_t correlationId,
    const KEYISO_TPM_KEY_DETAILS *details,
    const unsigned char *m,
    unsigned int mLength,
    unsigned char *sig,
    unsigned int siglen)
{
    const char* title = KEYISOP_TPM_ECDSA_SIGN_TITLE;
    int ret = -1;
    TPMI_ALG_HASH hashAlg;
    
    if (!_is_valid_input(correlationId, title, details) || !m) {
        KEYISOP_trace_log_error(correlationId, 0, title, "ecdsa sign failed", "Invalid input parameters");
        return ret;
    }

    uint16_t keySize = _get_key_size(correlationId, title, details->pub.publicArea.parameters.eccDetail.curveID);
    if (keySize == 0) {
        KEYISOP_trace_log_error(correlationId, 0, title, "ecdsa sign failed", "Unsupported curve");
        return ret;
    }

    if (!sig) {
        // The request is to get key size 
        return (int)keySize;
    }

    // Validate mLength is less then curve size
    if (keySize < mLength) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "ecdsa sign failed", "Digest size is incompatible with curve size", "mLength:%u, curveLen:%u", mLength, keySize);
        return ret;
    }

    TPMT_TK_HASHCHECK validation = { .tag = TPM2_ST_HASHCHECK,
                                     .hierarchy = TPM2_RH_OWNER};

    // We can only support digest sizes that are equal to or less than the curve size   
    if (mLength == SHA_DIGEST_LENGTH) {
	    hashAlg = TPM2_ALG_SHA1;
	    mLength = SHA_DIGEST_LENGTH;
    } else if (mLength == SHA256_DIGEST_LENGTH) {
	    hashAlg = TPM2_ALG_SHA256;
	    mLength = SHA256_DIGEST_LENGTH;
    } else if (mLength == SHA384_DIGEST_LENGTH ) {
	    hashAlg = TPM2_ALG_SHA384;
	    mLength = SHA384_DIGEST_LENGTH;
    } else if (mLength == SHA512_DIGEST_LENGTH) {
	    hashAlg = TPM2_ALG_SHA512;
	    mLength = SHA512_DIGEST_LENGTH;
    } else {
       KEYISOP_trace_log_error_para(correlationId, 0, title, "ecdsa sign failed", "Unsupported digest size", "mLength:%u", mLength);
        return ret;
    }

    TPMT_SIG_SCHEME inScheme = {
      .scheme = TPM2_ALG_ECDSA,
      .details.ecdsa.hashAlg = hashAlg,
    };

    TPM2B_DIGEST tpmDigestData = { .size = mLength };
    if (tpmDigestData.size > sizeof(tpmDigestData.buffer)) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "ecdsa sign failed", "Digest size is too large", "digest.size:%u", tpmDigestData.size);
        return ret;
    }
    memcpy(tpmDigestData.buffer, m, mLength);
    
    BIGNUM *bns = NULL;
    BIGNUM *bnr = NULL;
    ECDSA_SIG *ecdsaSig = NULL;
    TPMT_SIGNATURE *tpmSignature = NULL;

     if (_sign(correlationId, title, details, &tpmDigestData, &inScheme, &validation, &tpmSignature) != KEYISO_TPM_RET_SUCCESS) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "ecdsa sign failed", "Failed to sign", "ret:%d", ret);
        return _CLEANUP_ECDSA_SIGN(ret);
    }
     
    bns = BN_bin2bn(&tpmSignature->signature.ecdsa.signatureS.buffer[0],
                    tpmSignature->signature.ecdsa.signatureS.size, NULL);
    bnr = BN_bin2bn(&tpmSignature->signature.ecdsa.signatureR.buffer[0],
                    tpmSignature->signature.ecdsa.signatureR.size, NULL);

    KeyIso_free(tpmSignature);

    if (!bns || !bnr) {
        KEYISOP_trace_log_error(correlationId, 0, title, "ecdsa sign failed", "Failed to convert signature to BIGNUM");
        return _CLEANUP_ECDSA_SIGN(ret);
    }

    ecdsaSig = ECDSA_SIG_new();
    if (ecdsaSig == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "ecdsa sign failed", "Failed to create ECDSA_SIG");
        return _CLEANUP_ECDSA_SIGN(ret);
    }

    if (ECDSA_SIG_set0(ecdsaSig, bnr, bns) == 0) {
        KEYISOP_trace_log_error(correlationId, 0, title, "ecdsa sign failed", "Failed to set BIGNUM to ECDSA_SIG");
        return _CLEANUP_ECDSA_SIGN(ret);
    }

    // ECDSA_SIG_set0 takes ownership of the s and r BIGNUMs, so we must not free them but the ecdsaSig itself from this point
    bns = NULL;
    bnr = NULL;
    
    int derLen = i2d_ECDSA_SIG(ecdsaSig, &sig);
    if (derLen <= 0) {
        KEYISOP_trace_log_error(correlationId, 0, title, "ecdsa sign failed", "Failed to convert ECDSA_SIG to DER format");
        return _CLEANUP_ECDSA_SIGN(ret);
    }

    if (derLen < 0 || (unsigned int)derLen > siglen) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "ecdsa sign failed", "sig output buffer is too small", "derLen:%d, siglen:%d", derLen, siglen);
        return _CLEANUP_ECDSA_SIGN(ret);
    }

    KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete: successful ecdsa sign"); 
    ret = derLen;
    return _CLEANUP_ECDSA_SIGN(ret);
}