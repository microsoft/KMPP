/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <openssl/x509v3.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include "keyisolog.h"
#include "keyisocommon.h"
#include "keyisomemory.h"
#include "keyisoutils.h"

#define KEYISOP_ONE_HOUR_SECONDS     (60 * 60)

static STACK_OF(CONF_VALUE) *_conf_get_section(
    const uuid_t correlationId,
    const CONF *conf,
    const char *section)
{
    const char *title = KEYISOP_CREATE_SELF_SIGN_TITLE;
    STACK_OF(CONF_VALUE) *values = NULL;

    ERR_clear_error();

    values = NCONF_get_section(conf, section);
    if (values == NULL) {
        KEYISOP_trace_log_openssl_error(correlationId, 0, title, section);
    }

    ERR_clear_error();

    return values;
}

// Helper struct to define a field name and its new value
typedef struct {
    const char *name;  // Field name to update
    const char *value; // New value to set
} KeyIsoFieldUpdate;

static int _edit_conf_section(
    const uuid_t correlationId,
    CONF *conf,
    const char *section_name,
    const KeyIsoFieldUpdate *updates,
    size_t update_count)
{
    const char *title = KEYISOP_CREATE_SELF_SIGN_TITLE;
    STACK_OF(CONF_VALUE) *values = _conf_get_section(correlationId, conf, section_name);
    if (values == NULL) {
        KEYISOP_trace_log_openssl_error(correlationId, 0, title, "NCONF_get_section");
        return STATUS_FAILED;
    }
    
    for (int i = 0; i < sk_CONF_VALUE_num(values); i++) {
        CONF_VALUE *value = sk_CONF_VALUE_value(values, i);
        if (value == NULL) {
            KEYISOP_trace_log_openssl_error(correlationId, 0, title, "sk_CONF_VALUE_value");
            return STATUS_FAILED;
        }
        
        // Look for this field in our update list
        for (size_t j = 0; j < update_count; j++) {
            if (strncmp(value->name, updates[j].name, strlen(updates[j].name)) == 0) {
                // Create a new copy of the update value
                char *new_value = OPENSSL_strdup(updates[j].value);
                if (new_value == NULL) {
                    KEYISOP_trace_log_openssl_error(correlationId, 0, title, "OPENSSL_strdup");
                    return STATUS_FAILED;
                }
                
                // Free the existing value if it exists
                if (value->value != NULL) {
                    OPENSSL_free(value->value);
                }
                
                // Set the new value
                value->value = new_value;
                break;
            }
        }
    }
    
    return STATUS_OK;
}

int KeyIso_edit_alt_names_section(
    const uuid_t correlationId,
    CONF *conf,
    const char *dns1,
    const char *dns2)
{
    if (dns1 == NULL || dns2 == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_CREATE_SELF_SIGN_TITLE, "dns1 or dns2", "NULL");
        return STATUS_FAILED;
    }
    
    // Define the updates we want to make
    const KeyIsoFieldUpdate updates[] = {
        {"DNS.1", dns1},  
        {"DNS.2", dns2}
    };

    // Use our generic function to update the alt_names section
    return _edit_conf_section(correlationId, conf, "alt_names", updates, sizeof(updates)/sizeof(updates[0]));
}


// Helper function for PCKS#12 creation
// Returns BIO_s_mem().
BIO *KeyIsoP_create_pfx(
    const uuid_t correlationId,
    EVP_PKEY *key,
    X509 *cert,
    STACK_OF(X509) *ca,               // Optional
    const char *password,
    int *pfxLength,
    unsigned char **pfxBytes)         // Don't free
{
    const char *title = KEYISOP_HELPER_PFX_TITLE;
    const char *loc = "";
    PKCS12 *p12 = NULL;
    BIO *bioPfx = NULL;

    ERR_clear_error();

    p12 = PKCS12_create(
        password,
        NULL,                                   // name
        key,
        cert,
        ca,
//        NID_pbe_WithSHA1And3_Key_TripleDES_CBC, // key_pbe
        NID_aes_256_cbc,                        // key_pbe
        -1,                                     // cert_pbe, -1 => no encryption
        PKCS12_DEFAULT_ITER,                    // iter
        -1,                                     // mac_iter
        0);                                     // keytype
    if (p12 == NULL) {
        loc = "PKCS12_create";
        goto openSslErr;
    }

    if (!PKCS12_set_mac(
            p12,
            password,
            -1,                                 // passlen, -1 => NULL terminated
            NULL,                               // salt
            0,                                  // saltlen
            PKCS12_DEFAULT_ITER,                // iter
            EVP_sha256())) {                    // const EVP_MD* md_type, NULL => sha1
        loc = "PKCS12_set_mac";
        goto openSslErr;
    }

    bioPfx = KeyIsoP_create_pfx_bio(
        correlationId,
        p12,
        pfxLength,
        pfxBytes);

end:
    PKCS12_free(p12);
    return bioPfx;

openSslErr:
    KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

// Helper function for PCKS#12 creation
// Returns BIO_s_mem().
BIO *KeyIsoP_create_pfx_bio(
    const uuid_t correlationId,
    PKCS12 *p12,
    int *pfxLength,
    unsigned char **pfxBytes)         // Don't free
{
    const char *title = KEYISOP_HELPER_PFX_TITLE;
    const char *loc = "";
    int ret = 0;
    BIO *bioPfx = NULL;

    ERR_clear_error();

    bioPfx = BIO_new(BIO_s_mem());
    if (bioPfx == NULL) {
        loc = "BIO_new";
        goto openSslErr;
    }

    if (!i2d_PKCS12_bio(bioPfx, p12)) {
        loc = "i2d_PKCS12_bio";
        goto openSslErr;
    }

    if (pfxBytes != NULL && pfxLength != NULL) {
        *pfxLength = (int) BIO_get_mem_data(bioPfx, pfxBytes);
        if (*pfxLength == 0 || *pfxBytes == NULL) {
            loc = "BIO_get_mem_data";
            goto openSslErr;
        }
    }

    ret = 1;
end:
    if (!ret) {
        BIO_free(bioPfx);
        bioPfx = NULL;
        if (pfxBytes != NULL) {
            *pfxBytes = NULL;
        } 
        if (pfxLength != NULL) {
            *pfxLength = 0;
        }
    }

    return bioPfx;

openSslErr:
    KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

// Helper function for PKCS#12 parsing
// returns 1 for success and zero if an error occurred.
int KeyIso_pkcs12_parse(
    const uuid_t correlationId,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    const char *inPassword,             // optional
    EVP_PKEY **outPkey,
    X509 **outCert,
    STACK_OF(X509) **outCa)
{
    const char *title = KEYISOP_IMPORT_PFX_TITLE;
    const char *loc = "";
    int ret = 0;
	
    BIO *bioInPfx = NULL;
    PKCS12 *inP12 = NULL;
 
    ERR_clear_error();

    bioInPfx = BIO_new_mem_buf(inPfxBytes, inPfxLength);
    if (bioInPfx == NULL) {
		loc = "BIO_new_mem_buf";
        goto openSslErr;
    }

    inP12 = d2i_PKCS12_bio(bioInPfx, NULL);
    if (inP12 == NULL) {
        loc = "d2i_PKCS12_bio";
        goto openSslErr;
    }
	
    if (!PKCS12_parse(inP12, inPassword, outPkey, outCert, outCa)) {
        loc = "PKCS12_parse";
        goto openSslErr;
    }
	
	ret = 1;

end:
    PKCS12_free(inP12);
    BIO_free(bioInPfx);

    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}              

int KeyIso_conf_load(
    const uuid_t correlationId,
    const char *confStr,
    CONF **conf)
{
    const char *title = KEYISOP_CREATE_SELF_SIGN_TITLE;
    const char *loc = "";
    long errorLine = -1;
    int ret = 0;
    BIO *in = NULL;
    ERR_clear_error();
    *conf = NCONF_new(NULL);
    if (*conf == NULL) {
        goto openSslErr;
    }
    in = BIO_new_mem_buf(confStr, (int) strlen(confStr));
    if (in == NULL) {
        goto openSslErr;
    }
    if (!NCONF_load_bio(*conf, in, &errorLine)) {
        loc = "NCONF_load_bio";
        goto openSslErr;
    }
    ret = 1;
end:
    BIO_free(in);
    if (!ret) {
        NCONF_free(*conf);
        *conf = NULL;
    }
    ERR_clear_error();
    return ret;
openSslErr:
    KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, loc,
        "errorLine: %ld", errorLine);
    goto end;
}

const char *KeyIso_conf_get_string(
    const uuid_t correlationId,
    const CONF *conf,
    const char *name)
{
    const char *title = KEYISOP_CREATE_SELF_SIGN_TITLE;
    char *str = NULL;
    int flags = 0;

    ERR_clear_error();

    str = NCONF_get_string(conf, "self_sign", name);
    if (str == NULL) {
        if (strcmp(name, KMPP_KEY_USAGE_STR) == 0) {
            flags = KEYISOP_TRACELOG_WARNING_FLAG;
        } 
        KEYISOP_trace_log_openssl_error(correlationId, flags, title, name);
    }

    ERR_clear_error();

    return (const char *) str;
}

int KeyIso_conf_get_number(
    const uuid_t correlationId,
    const CONF *conf,
    const char *name,
    long *value)
{
    int ret = 0;
    const char *str = NULL; // don't free

    *value = 0;

    str = KeyIso_conf_get_string(correlationId, conf, name);
    if (str == NULL) {
        goto end;
    }

    *value = strtol(str, NULL, 0);
    ret = 1;
end:
    return ret;
}

int KeyIso_conf_get_curve_nid(
    const uuid_t correlationId,
    const CONF *conf,
    uint32_t *curve_nid)
{
    int nid = 0;
    const char *eccCurve = NULL;   // don't free

    eccCurve = KeyIso_conf_get_string(correlationId, conf, "ecc_curve");
    if (eccCurve == NULL) {
        return STATUS_FAILED;
    }

    /*
     * workaround for the SECG curve names secp192r1 and secp256r1 (which
     * are the same as the curves prime192v1 and prime256v1 defined in
     * X9.62)
     */
    if (strcmp(eccCurve, "secp192r1") == 0) {
        nid = NID_X9_62_prime192v1;
    } else if (strcmp(eccCurve, "secp256r1") == 0) {
        nid = NID_X9_62_prime256v1;
    } else {
        nid = OBJ_sn2nid(eccCurve);
    }

    if (nid == 0) {
        nid = EC_curve_nist2nid(eccCurve);
    }

    if (nid <= 0 || nid > INT32_MAX) {
        KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_CREATE_SELF_SIGN_TITLE, "ecc_curve", "Unknown",
            "ecc_curve: %s, curve_nid: %d", eccCurve, nid);
        return STATUS_FAILED;
    }

    *curve_nid = (uint32_t)nid;
    return STATUS_OK;
}

#ifdef KMPP_OPENSSL_3
static EVP_PKEY* _cleanup_rsa_key_ossl_3(int ret, const char *loc, const uuid_t correlationId, EVP_PKEY *pKey, EVP_PKEY_CTX *ctx, BIGNUM *bn) 
{
    if(ret != STATUS_OK)
        KEYISOP_trace_log_openssl_error(correlationId, 0, KEYISOP_CREATE_SELF_SIGN_TITLE, loc);

    if (bn != NULL) {
        BN_free(bn);
    }
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    return pKey;
}
#define _CLEANUP_RSA_GENERATE_RSA_KEY_OSSL_3(ret, loc) \
    _cleanup_rsa_key_ossl_3(ret, loc, correlationId, pKey, ctx, bn)

static EVP_PKEY* _generate_rsa_key_ossl_3(const uuid_t correlationId, long rsaBits, long rsaExp) 
{
    EVP_PKEY *pKey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    BIGNUM *bn = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", "provider=default");
    if (ctx == NULL) {
        return _CLEANUP_RSA_GENERATE_RSA_KEY_OSSL_3(STATUS_FAILED, "EVP_PKEY_CTX_new_from_name");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        return _CLEANUP_RSA_GENERATE_RSA_KEY_OSSL_3(STATUS_FAILED, "EVP_PKEY_keygen_init");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, (int) rsaBits) <= 0) {
        return _CLEANUP_RSA_GENERATE_RSA_KEY_OSSL_3(STATUS_FAILED, "EVP_PKEY_CTX_set_rsa_keygen_bits");
    }

    bn = BN_new();
    if (bn == NULL || !BN_set_word(bn, (BN_ULONG) rsaExp)) {
        return _CLEANUP_RSA_GENERATE_RSA_KEY_OSSL_3(STATUS_FAILED, "BN_set_word");
    }

    if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, bn) <= 0) {
        return _CLEANUP_RSA_GENERATE_RSA_KEY_OSSL_3(STATUS_FAILED, "EVP_PKEY_CTX_set1_rsa_keygen_pubexp");
    }

    if (EVP_PKEY_keygen(ctx, &pKey) <= 0) {
        return _CLEANUP_RSA_GENERATE_RSA_KEY_OSSL_3(STATUS_FAILED, "EVP_PKEY_keygen");
    }

    return _CLEANUP_RSA_GENERATE_RSA_KEY_OSSL_3(STATUS_OK, "");
}
#else // NOT KMPP_OPENSSL_3
static EVP_PKEY* _cleanup_rsa_key_ossl_1(int ret, const char *loc, const uuid_t correlationId, EVP_PKEY *pKey, RSA *rsa, BIGNUM *bn) 
{
    if(ret != STATUS_OK)
        KEYISOP_trace_log_openssl_error(correlationId, 0, KEYISOP_CREATE_SELF_SIGN_TITLE, loc);

    if (rsa != NULL) {
        RSA_free(rsa);
    }
    if (bn != NULL) {
        BN_free(bn);
    }

    return pKey;
}
#define _CLEANUP_RSA_GENERATE_RSA_KEY_OSSL_1(ret, loc) \
    _cleanup_rsa_key_ossl_1(ret, loc, correlationId, pKey, rsa, bn)

static EVP_PKEY* _generate_rsa_key_ossl_1(const uuid_t correlationId, long rsaBits, long rsaExp) 
{
    EVP_PKEY *pKey = NULL;
    RSA *rsa = NULL;
    BIGNUM *bn = NULL;

    rsa = RSA_new();
    bn = BN_new();
    pKey = EVP_PKEY_new();
    if (rsa == NULL || bn == NULL || pKey == NULL) {
        return _CLEANUP_RSA_GENERATE_RSA_KEY_OSSL_1(STATUS_FAILED, "RSA_new or BN_new or EVP_PKEY_new");
    }

    if (!BN_set_word(bn, (BN_ULONG) rsaExp)) {
        return _CLEANUP_RSA_GENERATE_RSA_KEY_OSSL_1(STATUS_FAILED, "BN_set_word");
    }

    if (!RSA_generate_key_ex(rsa, (int) rsaBits, bn, NULL)) {
        return _CLEANUP_RSA_GENERATE_RSA_KEY_OSSL_1(STATUS_FAILED, "RSA_generate_key_ex");
    }

    if (!EVP_PKEY_assign_RSA(pKey, rsa)) {
        return _CLEANUP_RSA_GENERATE_RSA_KEY_OSSL_1(STATUS_FAILED, "EVP_PKEY_assign_RSA");
    }
    rsa = NULL;

    return _CLEANUP_RSA_GENERATE_RSA_KEY_OSSL_1(STATUS_OK, "");
}
#endif // KMPP_OPENSSL_3

EVP_PKEY *KeyIso_conf_generate_rsa(
    const uuid_t correlationId,
    const CONF *conf)
{
    EVP_PKEY *pKey = NULL;
    long rsaBits = 0;
    long rsaExp = 0;

    if (!KeyIso_conf_get_number(correlationId, conf, "rsa_bits", &rsaBits) ||
        !KeyIso_conf_get_number(correlationId, conf, "rsa_exp", &rsaExp) ||
        rsaBits <= 0 ||
        rsaExp <= 0) {
        return NULL;
    }

    if (rsaBits > KMPP_OPENSSL_RSA_MAX_MODULUS_BITS || rsaBits < KMPP_RSA_MIN_MODULUS_BITS) {
        KEYISOP_trace_log_error_para(correlationId, 0, KEYISOP_CREATE_SELF_SIGN_TITLE, "rsa_bits", "Invalid length", "rsa_bits: %ld", rsaBits);
        return NULL;
    }

#ifdef KMPP_OPENSSL_3
    pKey = _generate_rsa_key_ossl_3(correlationId, rsaBits, rsaExp);
#else
    pKey = _generate_rsa_key_ossl_1(correlationId, rsaBits, rsaExp);
#endif

    return pKey;
}

EVP_PKEY *KeyIso_conf_generate_ecc(
    const uuid_t correlationId,
    const CONF *conf)
{
    const char *title = KEYISOP_CREATE_SELF_SIGN_TITLE;
    const char *loc = "";
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EC_KEY *ecc = NULL;
    unsigned int nid = 0;

    if (!KeyIso_conf_get_curve_nid(correlationId, conf, &nid)) {
        loc = "KeyIso_conf_get_curve_nid";
        goto end;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        goto openSslErr;
    }

    ecc = EC_KEY_new_by_curve_name((int)nid);
    if (ecc == NULL) {
        loc = "EC_KEY_new_by_curve_name";
        goto end;
    }

    EC_KEY_set_asn1_flag(ecc, OPENSSL_EC_NAMED_CURVE);

    if (!EC_KEY_generate_key(ecc)) {
        loc = "EC_KEY_generate_key";
        goto openSslErr;
    }

    // The assign takes the ecc refCount
    if (!EVP_PKEY_assign_EC_KEY(pkey, ecc)) {
        loc = "EVP_PKEY_assign_EC_KEY";
        goto openSslErr;
    }
    ecc = NULL;

    ret = 1;

end:
    if (!ret) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    EC_KEY_free(ecc);
    return pkey;

openSslErr:
    KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

int KeyIso_conf_get_name(
    const uuid_t correlationId,
    const CONF *conf,
    X509 *cert)
{
    const char *title = KEYISOP_CREATE_SELF_SIGN_TITLE;
    int ret = 0;
    const char *dnSect = NULL;              // don't free
    STACK_OF(CONF_VALUE) *dnValues = NULL;  // don't free
    X509_NAME *subj = NULL;                 // don't free

    dnSect = KeyIso_conf_get_string(correlationId, conf, "distinguished_name");
    if (dnSect == NULL) {
        goto end;
    }

    dnValues = _conf_get_section(correlationId, conf, dnSect);
    if (dnValues == NULL) {
        goto end;
    }

    if (sk_CONF_VALUE_num(dnValues) == 0) {
        KEYISOP_trace_log_error(correlationId, 0, title, "Values", "Empty");
        goto end;
    }

    subj = X509_get_subject_name(cert);

    for (int i = 0; i < sk_CONF_VALUE_num(dnValues); i++) {
        CONF_VALUE *v = sk_CONF_VALUE_value(dnValues, i);
        const char *type = v->name;
        int mval = 0;   // 0 => not multi-valued

        ERR_clear_error();

        /*
         * Skip past any leading X. X: X, etc to allow for multiple instances
         */
        for (const char *p = v->name; *p; p++) {
            if (*p == ':' || *p == ',' || *p == '.') {
                p++;
                if (*p) {
                    type = p;
                }
                break;
            }
        }

        // "+" is used for multi-valued
        if (*type == '+') {
            type++;
            mval = -1;
        }

        if (!X509_NAME_add_entry_by_txt(
                subj,
                type,                           // For example, "C", "ST", "L", "CN", ...
                MBSTRING_UTF8,
                (unsigned char *) v->value,
                -1,                             // len, -1 => NULL terminated
                -1,                             // loc, -1 => append
                mval)) {                        // 0 => not multivalued
            KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, "X509_NAME_add_entry_by_txt",
                "name: %s value: %s", v->name, v->value);
            goto end;
        }
    }

    if (!X509_set_issuer_name(cert, subj)) {
        KEYISOP_trace_log_openssl_error(correlationId, 0, title, "X509_set_issuer_name");
        goto end;
    }

    ret = 1;
end:
    return ret;
}

int KeyIso_conf_get_extensions(
    const uuid_t correlationId,
    CONF *conf,
    X509 *cert)
{
    const char *title = KEYISOP_CREATE_SELF_SIGN_TITLE;
    const char *loc = "";
    int ret = 0;
    const char *extensions = NULL;              // don't free
    X509V3_CTX ctx;

    // Extensions aren't required
    extensions = KeyIso_conf_get_string(correlationId, conf, "x509_extensions");
    if (extensions == NULL) {
        ret = 1;
        goto end;
    }

    X509V3_set_ctx_test(&ctx);
    X509V3_set_nconf(&ctx, conf);
    if (!X509V3_EXT_add_nconf(conf, &ctx, extensions, NULL)) {
        loc = "test x509_extensions";
        goto openSslErr;
    }

    X509V3_set_ctx(
        &ctx,
        cert,           // issuer
        cert,           // subj
        NULL,           // req
        NULL,           // crl
        0);             // flags
    X509V3_set_nconf(&ctx, conf);
    if (!X509V3_EXT_add_nconf(conf, &ctx, extensions, cert)) {
        loc = "x509_extensions";
        goto openSslErr;
    }

    ret = 1;
end:
    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

int KeyIso_conf_get_time(
    const uuid_t correlationId,
    const CONF *conf,
    X509 *cert)
{
    const char *title = KEYISOP_CREATE_SELF_SIGN_TITLE;
    const char *loc = "";
    int ret = 0;
    long days = 0;

    if (!KeyIso_conf_get_number(correlationId, conf, "days", &days) || days <= 0) {
        goto end;
    }

    // Set notBefore to one hour before current time
    if (X509_time_adj_ex(X509_getm_notBefore(cert), 0, -KEYISOP_ONE_HOUR_SECONDS, NULL) == NULL) {
        loc = "notBefore";
        goto openSslErr;
    }

    // Set notAfter to "days" after current time
    if (X509_time_adj_ex(X509_getm_notAfter(cert), (int) days, 0, NULL) == NULL) {
        loc = "notAfter";
        goto openSslErr;
    }

    ret = 1;
end:
    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

int KeyIso_conf_sign(
    const uuid_t correlationId,
    CONF *conf,
    X509 *cert,
    EVP_PKEY *pkey)
{
    const char *title = KEYISOP_CREATE_SELF_SIGN_TITLE;
    const char *loc = "";
    int ret = 0;
    const char *signDigest = NULL;  // don't free
    const char *keyType = NULL;     // don't free
    const EVP_MD *digest = NULL;    // don't free
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;      // don't free

    signDigest = KeyIso_conf_get_string(correlationId, conf, "sign_digest");
    if (signDigest == NULL) {
        goto end;
    }

    digest = EVP_get_digestbyname(signDigest);
    if (digest == NULL) {
        loc = "EVP_get_digestbyname";
        KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, loc,
            "sign_digest: %s", signDigest);
        goto end;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        goto openSslErr;
    }
    
    if (!EVP_DigestSignInit(ctx, &pctx, digest, NULL, pkey)) {
        loc = "EVP_DigestSignInit";
        goto openSslErr;
    }

    keyType = KeyIso_conf_get_string(correlationId, conf, "key_type");
    if (keyType != NULL && strcmp(keyType, "rsa") == 0) {
        long rsaPadding = 0;

        // Padding values:
        //  # define RSA_PKCS1_PADDING       1
        //  # define RSA_PKCS1_PSS_PADDING   6

        if (!KeyIso_conf_get_number(correlationId, conf, "rsa_padding", &rsaPadding) || rsaPadding <= 0) {
            goto end;
        }

        if (EVP_PKEY_CTX_set_rsa_padding(pctx, (int) rsaPadding) <= 0) {
            loc = "EVP_PKEY_CTX_set_rsa_padding";
            goto openSslErr;
        }
    }

    if (X509_sign_ctx(cert, ctx) <= 0) {
        loc = "X509_sign_ctx";
        goto openSslErr;
    }

    ret = 1;
end:
    EVP_MD_CTX_free(ctx);       // also frees pctx

    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

void KeyIsoP_X509_pubkey_sha256_hex_hash(
    X509 *x,
    char *hexHash)
{
    unsigned char md[SHA256_DIGEST_LENGTH];

    X509_pubkey_digest(x, EVP_sha256(), md, NULL);
    KeyIsoP_bytes_to_hex(
        sizeof(md),
        md,
        hexHash);

    if(!hexHash)
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_SUPPORT_TITLE, "KeyIsoP_bytes_to_hex", "Hash is NULL");
}

void KeyIso_pkey_sha256_hex_hash(
    EVP_PKEY *pkey,
    char *hexHash)
{
    const char *title = KEYISOP_SUPPORT_TITLE;
    unsigned char md[SHA256_DIGEST_LENGTH];
    unsigned char *buf = NULL;
    int len = 0;

    if (!pkey || !hexHash) {
        KEYISOP_trace_log_error(NULL, 0, title, "Invalid argument", "pkey or hexHash is NULL");
        return;
    }

    // Extract the public key in DER format
    if ((len = i2d_PUBKEY(pkey, &buf)) <= 0) {
        KEYISOP_trace_log_openssl_error(NULL, 0, title, "i2d_PUBKEY");
        KeyIso_free(buf);
        return;
    }

    // Compute the SHA-256 hash of the public key
    if (!EVP_Digest(buf, len, md, NULL, EVP_sha256(), NULL)) {
        KEYISOP_trace_log_openssl_error(NULL, 0, title, "EVP_Digest");
        KeyIso_free(buf);
        return;
    }

    // Convert the hash to a hexadecimal string
    KeyIsoP_bytes_to_hex(sizeof(md), md, hexHash);

    if (!hexHash) {
        KEYISOP_trace_log_error(NULL, 0, title, "KeyIsoP_bytes_to_hex", "Hash is NULL");
    }

    // Clean up
    KeyIso_free(buf);
}

static int _cleanup_get_ec_evp_key(
    const uuid_t correlationId,
    int res,
    EVP_PKEY* evpKey,
    EC_KEY* ecKey, 
    EC_GROUP* ecGroup,
    BN_CTX* bnCtx,
    BIGNUM* bnEcPubX,
    BIGNUM* bnEcPubY,
    BIGNUM *bnEcPrivD,
    EC_POINT* ecPoint,
    const char* loc)
{
    EC_POINT_free(ecPoint);
    BN_free(bnEcPubX);
    BN_free(bnEcPubY);
    BN_free(bnEcPrivD);
    BN_CTX_end(bnCtx);
    BN_CTX_free(bnCtx);

    if (res != STATUS_OK) {
        KEYISOP_trace_log_openssl_error(correlationId, 0, KEYISOP_ENGINE_TITLE, loc);
        EVP_PKEY_free(evpKey);
        EC_KEY_free(ecKey);
        EC_GROUP_free(ecGroup);

    }
    return res;
}

#define _CLEANUP_GET_EC_EVP_KEY(res, message) \
    _cleanup_get_ec_evp_key(correlationId, res, evpKey, ecKey, ecGroup, bnCtx, bnEcPubX, bnEcPubY, bnEcPrivD, ecPoint, message)

static int _get_ec_evp_key(
    const uuid_t correlationId,
    uint32_t curve,
    uint32_t ecPubKeyLen,
    const uint8_t* ecPubKeyBytes,
    uint32_t ecPrivateKeyLen,
    const uint8_t* ecPrivateKeyBytes,
    EC_KEY** outEcKey, 
    EC_GROUP** outEcGroup)
{
    EC_POINT* ecPoint = NULL;
    BIGNUM* bnEcPubX = NULL;
    BIGNUM* bnEcPubY = NULL;
    BIGNUM *bnEcPrivD = NULL;
    BN_CTX* bnCtx = NULL;
    EC_KEY* ecKey = NULL;
    EC_GROUP* ecGroup = NULL;
    EVP_PKEY *evpKey = NULL;

    ERR_clear_error();
 
    uint32_t pubCoordLen = ecPubKeyLen/2;
    const unsigned char* xBuff = ecPubKeyBytes;
    const unsigned char* yBuff = (ecPubKeyBytes + pubCoordLen);
    if (KeyIso_get_ec_evp_pub_key(correlationId, curve, xBuff, pubCoordLen, yBuff, pubCoordLen,  &ecKey, &ecGroup) != STATUS_OK) {
        return _CLEANUP_GET_EC_EVP_KEY(STATUS_FAILED, "KeyIso_get_ec_evp_pub_key failed");
    }

    if (ecPrivateKeyBytes != NULL) {
        // If private key was passed set private key
        bnEcPrivD =  BN_bin2bn(ecPrivateKeyBytes, ecPrivateKeyLen, NULL);
        if (!bnEcPrivD) {
            return _CLEANUP_GET_EC_EVP_KEY(STATUS_FAILED, "bnEcPrivD - BN_bin2bn failed");
        }
        if (EC_KEY_set_private_key(ecKey, bnEcPrivD) != 1) {
             return _CLEANUP_GET_EC_EVP_KEY(STATUS_FAILED, "EC_KEY_set_private_key failed");
        }
    }

    *outEcKey = ecKey;
    *outEcGroup = ecGroup;
    return _CLEANUP_GET_EC_EVP_KEY(STATUS_OK, NULL);
}

int KeyIso_get_ec_evp_pub_key_from_st(
    const uuid_t correlationId,
    const KEYISO_EC_PUBLIC_KEY_ST* inEcStPublicKey,
    EC_KEY** outEcKey, 
    EC_GROUP** outEcGroup)
{
    if (!outEcKey || !outEcGroup || !inEcStPublicKey) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_KEY_TITLE, "Invalid argument", "NULL");
        return STATUS_FAILED;
    }

    return _get_ec_evp_key(correlationId,
                           inEcStPublicKey->ecCurve,
                           inEcStPublicKey->ecPubKeyLen,
                           inEcStPublicKey->ecPubKeyBytes,
                           0,
                           NULL, // No need for private key here
                           outEcKey,
                           outEcGroup); 
}

int KeyIso_get_ec_evp_pkey(
    const uuid_t correlationId,
    const KEYISO_EC_PKEY_ST* inEcStPkey,
    EC_KEY** outEcKey, 
    EC_GROUP** outEcGroup)
{
    if (!outEcKey || !outEcGroup || !inEcStPkey) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_KEY_TITLE, "Invalid argument", "NULL");
        return STATUS_FAILED;
    }

    uint32_t ecPubKeyLen = inEcStPkey->ecPubXLen + inEcStPkey->ecPubYLen;
    return _get_ec_evp_key(correlationId,
                           inEcStPkey->ecCurve,
                           ecPubKeyLen,
                           inEcStPkey->ecKeyBytes,
                           inEcStPkey->ecPrivKeyLen,
                           (inEcStPkey->ecKeyBytes + ecPubKeyLen),
                           outEcKey,
                           outEcGroup);
}

static int _cleanup_get_ec_evp_pub_key(
    const uuid_t correlationId,
    int res,
    const char* message,
    BN_CTX *ctx, 
    BIGNUM* x,
    BIGNUM* y,
    EC_POINT* ecPoint,
    EC_KEY* ecKey, 
    EC_GROUP* ecGroup)
{
    const char* title = KEYISOP_KEY_TITLE;
    if (res != STATUS_OK) {
        KEYISOP_trace_log_openssl_error(correlationId, 0, title, message);
        EC_KEY_free(ecKey);
        EC_GROUP_free(ecGroup);
        return STATUS_FAILED;
    }

    BN_free(x);
    BN_free(y);
    BN_CTX_free(ctx);
    EC_POINT_free(ecPoint);
    return STATUS_OK;
}

#define _CLEANUP_GET_EC_PUB_KEY(res, message) \
    _cleanup_get_ec_evp_pub_key(correlationId, res, message, ctx, x, y, ecPoint, ecKey, ecGroup)

int KeyIso_get_ec_evp_pub_key(
    const uuid_t correlationId,
    uint32_t curve,
    const unsigned char* xBuff,
    uint32_t xLen,
    const unsigned char* yBuff,
    uint32_t yLen,
    EC_KEY** outEcKey, 
    EC_GROUP** outEcGroup)
{
    ERR_clear_error();

    EC_KEY* ecKey = NULL;
    EC_POINT* ecPoint = NULL;
    BN_CTX* ctx = NULL;
    EC_GROUP* ecGroup = NULL;
    BIGNUM* x = NULL;
    BIGNUM* y = NULL;

    x = BN_bin2bn(xBuff, xLen, NULL);
    if (!x) {
        return _CLEANUP_GET_EC_PUB_KEY(STATUS_FAILED, "get public key from key data - failed to convert x to BIGNUM");
    }

    y = BN_bin2bn(yBuff, yLen, NULL);
    if (!y) {
        return _CLEANUP_GET_EC_PUB_KEY(STATUS_FAILED, "get public key from key data - failed to convert y to BIGNUM");
    }
    
    if ((ctx = BN_CTX_new()) == NULL) {
        return _CLEANUP_GET_EC_PUB_KEY(STATUS_FAILED, "failed to create BN_CTX");
    }

    ecGroup = EC_GROUP_new_by_curve_name((int)curve);
    if (!ecGroup) {
        return _CLEANUP_GET_EC_PUB_KEY(STATUS_FAILED, "failed to create EC_GROUP");
    }

    ecPoint = EC_POINT_new(ecGroup);
    if (!ecPoint) {
        return _CLEANUP_GET_EC_PUB_KEY(STATUS_FAILED, "failed to create EC_POINT");
    }

    if (EC_POINT_set_affine_coordinates(ecGroup, ecPoint, x, y, ctx) == 0) {
        return _CLEANUP_GET_EC_PUB_KEY(STATUS_FAILED, "failed to set affine coordinates");
    }

    ecKey = EC_KEY_new_by_curve_name((int)curve);
    if (ecKey == NULL) {
        return _CLEANUP_GET_EC_PUB_KEY(STATUS_FAILED, "failed to create EC_KEY");
    }

    if (EC_KEY_set_group(ecKey, ecGroup) != 1 ) {
        return _CLEANUP_GET_EC_PUB_KEY(STATUS_FAILED, "failed to create EC_KEY or set its group");
    }

    if (EC_KEY_set_public_key(ecKey, ecPoint) != 1 ) {
        return _CLEANUP_GET_EC_PUB_KEY(STATUS_FAILED, "failed to set public key");
    }

    *outEcKey = ecKey;
    *outEcGroup = ecGroup;
    return _CLEANUP_GET_EC_PUB_KEY(STATUS_OK, NULL);
}