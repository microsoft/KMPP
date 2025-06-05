/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include "keyisoclientinternal.h"
#include "keyisolog.h"

#include <openssl/err.h>
#include <openssl/pkcs12.h>


/*
* This file is a copy of the OpenSSL implementation in https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/pkcs12/p12_kiss.c
* The original implementation was copied and modified so the PKCS12_parse rerutns encrypted key (X509_SIG) instead of key (EVP_PKEY).
*/
 
struct X509_sig_st {
    X509_ALGOR *algor;
    ASN1_OCTET_STRING *digest;
};

/* Simplified PKCS#12 routines */

static int _pkcs12_parse_p8(PKCS12 *p12, const char *pass, X509_SIG **p8, X509 **cert, STACK_OF(X509) **ca);
static int _parse_pk12(PKCS12 *p12, const char *pass, int passlen, X509_SIG *p8, STACK_OF(X509) *ocerts);
static int _parse_bags(const STACK_OF(PKCS12_SAFEBAG) *bags, X509_SIG *p8, STACK_OF(X509) *ocerts);
static int _parse_bag(PKCS12_SAFEBAG *bag, X509_SIG *p8, STACK_OF(X509) *ocerts);
static int _pkcs12_add_bag(STACK_OF(PKCS12_SAFEBAG) **pbags, PKCS12_SAFEBAG *bag);
static PKCS12_SAFEBAG *_pkcs12_add_cert_bag(STACK_OF(PKCS12_SAFEBAG) **pbags, X509 *cert, const char *name, int namelen, unsigned char *keyid, int keyidlen);

int KeyIso_pkcs12_parse_p8(
    const uuid_t correlationId,
    int inPfxLength,
    const unsigned char *inPfxBytes,
    X509_SIG **outP8,
    X509 **outCert,
    STACK_OF(X509) **outCa)
{
    const char *title = KEYISOP_IMPORT_PFX_TITLE;
    const char *loc = "";
    int ret = 0;
	
    BIO *bioInPfx = NULL;
    PKCS12 *inP12 = NULL;

    if (!outP8 && !outCert && !outCa)
        return STATUS_FAILED;
 
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
	
    if (!_pkcs12_parse_p8(inP12, NULL, outP8, outCert, outCa)) {
        KEYISOP_trace_log_error(correlationId, 0, title, "_pkcs12_parse_p8", "Failed");
        goto end;
    }
	
	ret = STATUS_OK;

end:
    PKCS12_free(inP12);
    BIO_free(bioInPfx);

    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

PKCS12 *KeyIso_pkcs12_create_p8(
    X509_SIG *p8, 
    X509 *cert, 
    STACK_OF(X509) *ca)
{
    PKCS12 *p12 = NULL;
    STACK_OF(PKCS7) *safes = NULL;
    STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
    PKCS12_SAFEBAG *bag = NULL;
    int i;
    unsigned char keyid[EVP_MAX_MD_SIZE];
    unsigned char *pkeyid = NULL;
    unsigned int keyidlen = 0;
    int namelen = -1;
    int pkeyidlen = -1;

    if (!p8 && !cert && !ca) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_PFX_TITLE, "Invalid argument", "NULL");
        return NULL;
    }

    if (cert) {
        /* The private key is encrypted so we cannot check the consistency of the private key with the public key in the certificate.
        if (!X509_check_private_key(cert, pkey))
            return NULL;*/

        if (!X509_digest(cert, EVP_sha1(), keyid, &keyidlen)) {
			KEYISOP_trace_log_openssl_error(NULL, 0, KEYISOP_IMPORT_PFX_TITLE, "X509_digest");
			return NULL;
        }      

        char *name = (char *)X509_alias_get0(cert, &namelen);
        if (keyidlen > 0) {
            pkeyid = keyid;
            pkeyidlen = keyidlen;
        } else {
            pkeyid = X509_keyid_get0(cert, &pkeyidlen);
        }

        bag = _pkcs12_add_cert_bag(&bags, cert, name, namelen, pkeyid, pkeyidlen);
    }

    /* Add all other certificates */
    if (ca) {
        for (i = 0; i < sk_X509_num(ca); i++) {
            if (!PKCS12_add_cert(&bags, sk_X509_value(ca, i)))
                goto err;
        }
    }

    if (bags && !PKCS12_add_safe(&safes, bags, -1, PKCS12_DEFAULT_ITER, NULL))
        goto err;

    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    bags = NULL;

    if (p8) {
        bag = PKCS12_SAFEBAG_create0_pkcs8(p8);
        if (!bag)
            goto err;

        if (!_pkcs12_add_bag(&bags, bag)) {
            PKCS12_SAFEBAG_free(bag);
            goto err;
        }
    }

    if (bags && !PKCS12_add_safe(&safes, bags, -1, PKCS12_DEFAULT_ITER, NULL))
        goto err;

    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    bags = NULL;

    p12 = PKCS12_add_safes(safes, 0);
    if (!p12)
        goto err;

    sk_PKCS7_pop_free(safes, PKCS7_free);
    safes = NULL;

    return p12;

 err:
    PKCS12_free(p12);
    sk_PKCS7_pop_free(safes, PKCS7_free);
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    return NULL;
}

int KeyIso_x509_sig_dup(const X509_SIG *in, X509_SIG *out)
{
    const X509_ALGOR *in_algorithm = NULL;
    const ASN1_OCTET_STRING *in_digest = NULL;
    X509_ALGOR *out_algorithm = NULL;
    ASN1_OCTET_STRING *out_digest = NULL;

    if (!in || !out)
        return STATUS_FAILED;

    X509_SIG_get0(in, &in_algorithm, &in_digest);

    out_algorithm = X509_ALGOR_dup((X509_ALGOR *) in_algorithm);
    out_digest = ASN1_OCTET_STRING_dup(in_digest);

    if (!out_algorithm || !out_digest) {
        X509_ALGOR_free(out_algorithm);
        ASN1_OCTET_STRING_free(out_digest);
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_PFX_TITLE, NULL, "Failed to duplicate X509_SIG");
        return STATUS_FAILED;
    }
    
    X509_ALGOR_free(out->algor);
    ASN1_OCTET_STRING_free(out->digest);
    out->algor = out_algorithm;
    out->digest = out_digest;

    return STATUS_OK;
}

////////////////////////////////////////////////
/////// Internal PKCS#12 helper functions //////
////////////////////////////////////////////////

// Parse and decrypt a PKCS#12 structure returning encrypted key, 
// user cert and other (CA) certs.
static int _pkcs12_parse_p8(
    PKCS12 *p12, 
    const char *pass, 
    X509_SIG **p8, 
    X509 **cert, 
    STACK_OF(X509) **ca)
{
    STACK_OF(X509) *ocerts = NULL;
    X509 *x = NULL;
    X509_SIG *op8 = NULL;

    if (p8)
        *p8 = NULL;
    if (cert)
        *cert = NULL;

    /* Check for NULL PKCS12 structure */

    if (!p12) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_PFX_TITLE, "Invalid argument", "NULL");
        return STATUS_FAILED;
    }

    // Allocate stack for other certificates
    ocerts = sk_X509_new_null();
    if (!ocerts) {
        KEYISOP_trace_log_openssl_error(NULL, 0, KEYISOP_IMPORT_PFX_TITLE, "sk_X509_new_null");
        goto err;
    }

    // Allocate PKCS#8 encrypted key
    op8 = X509_SIG_new();
    if (!op8) {
        KEYISOP_trace_log_openssl_error(NULL, 0, KEYISOP_IMPORT_PFX_TITLE, "X509_SIG_new");
        goto err;
    }

    if (!_parse_pk12(p12, pass, -1, op8, ocerts)) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_IMPORT_PFX_TITLE, "_parse_pk12", "Failed");
        goto err;
    }

    while ((x = sk_X509_pop(ocerts))) {
        if (ca && x) {
            if (!*ca)
                *ca = sk_X509_new_null();
            if (!*ca)
                goto err;
            if (!sk_X509_push(*ca, x))
                goto err;
            x = NULL;
        }
        X509_free(x);
    }

    sk_X509_pop_free(ocerts, X509_free);
    
    if (p8)
        *p8 = op8;

    return STATUS_OK;

 err:
    if (cert) {
        X509_free(*cert);
        *cert = NULL;
    }
    X509_free(x);
    sk_X509_pop_free(ocerts, X509_free);
    X509_SIG_free(op8);
    return STATUS_FAILED;
}

/* Parse the outer PKCS#12 structure */

static int _parse_pk12(PKCS12 *p12, const char *pass, int passlen,
                      X509_SIG *p8, STACK_OF(X509) *ocerts)
{
    STACK_OF(PKCS7) *asafes;
    STACK_OF(PKCS12_SAFEBAG) *bags;
    int i, bagnid;
    PKCS7 *p7;

    if ((asafes = PKCS12_unpack_authsafes(p12)) == NULL)
        return STATUS_FAILED;
    for (i = 0; i < sk_PKCS7_num(asafes); i++) {
        p7 = sk_PKCS7_value(asafes, i);
        bagnid = OBJ_obj2nid(p7->type);
        if (bagnid == NID_pkcs7_data) {
            bags = PKCS12_unpack_p7data(p7);
        } else if (bagnid == NID_pkcs7_encrypted) {
            bags = PKCS12_unpack_p7encdata(p7, pass, passlen);
        } else
            continue;
        if (!bags) {
            sk_PKCS7_pop_free(asafes, PKCS7_free);
            return STATUS_FAILED;
        }
        if (!_parse_bags(bags, p8, ocerts)) {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            sk_PKCS7_pop_free(asafes, PKCS7_free);
            return STATUS_FAILED;
        }
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    }
    sk_PKCS7_pop_free(asafes, PKCS7_free);
    return STATUS_OK;
}

static int _parse_bags(const STACK_OF(PKCS12_SAFEBAG) *bags, X509_SIG *p8, STACK_OF(X509) *ocerts)
{
    for (int i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
        PKCS12_SAFEBAG *bag = sk_PKCS12_SAFEBAG_value(bags, i);
        if (!_parse_bag(bag, p8, ocerts))
            return STATUS_FAILED;
    }

    return STATUS_OK;
}

static int _parse_bag(PKCS12_SAFEBAG *bag, X509_SIG *p8, STACK_OF(X509) *ocerts)
{
    X509 *x509;
    const ASN1_TYPE *attrib;
    const X509_SIG *shkey = NULL;
    ASN1_BMPSTRING *fname = NULL;
    ASN1_OCTET_STRING *lkid = NULL;

    if ((attrib = PKCS12_SAFEBAG_get0_attr(bag, NID_friendlyName)))
        fname = attrib->value.bmpstring;

    if ((attrib = PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID)))
        lkid = attrib->value.octet_string;

    switch (PKCS12_SAFEBAG_get_nid(bag)) {
        case NID_pkcs8ShroudedKeyBag:
        {
            if (p8) {
                shkey = PKCS12_SAFEBAG_get0_pkcs8(bag);
                if (!shkey) {
                    KEYISOP_trace_log_openssl_error(NULL, 0, "parse_bag", "PKCS12_SAFEBAG_get0_pkcs8");
                    return STATUS_FAILED;
                }
                if (KeyIso_x509_sig_dup(shkey, p8) != STATUS_OK) {
                    KEYISOP_trace_log_error(NULL, 0, "parse_bag", "X509_SIG_dup", "Failed");
                } else {
                    KEYISOP_trace_log(NULL, KEYISOP_TRACELOG_VERBOSE_FLAG, "parse_bag", "NID_pkcs8ShroudedKeyBag: success");
                }
            } else {
                KEYISOP_trace_log_error(NULL, 0, "parse_bag", "NID_pkcs8ShroudedKeyBag", "Not initialized p8");
            }
            break;
        }
            
        case NID_certBag:
        {
            if (PKCS12_SAFEBAG_get_bag_nid(bag) != NID_x509Certificate)
                return STATUS_OK;
            if ((x509 = PKCS12_SAFEBAG_get1_cert(bag)) == NULL)
                return STATUS_FAILED;
            if (lkid && !X509_keyid_set1(x509, lkid->data, lkid->length)) {
                X509_free(x509);
                return STATUS_FAILED;
            }

            if (fname) {
                int len, r;
                unsigned char *data;
                len = ASN1_STRING_to_UTF8(&data, fname);
                if (len >= 0) {
                    r = X509_alias_set1(x509, data, len);
                    OPENSSL_free(data);
                    if (!r) {
                        X509_free(x509);
                        return STATUS_FAILED;
                    }
                }
            }

            if (!sk_X509_push(ocerts, x509)) {
                X509_free(x509);
                return STATUS_FAILED;
            }
            break;
        }

        default:
            return STATUS_OK;
    }

    return STATUS_OK;
}

static int _pkcs12_add_bag(
    STACK_OF(PKCS12_SAFEBAG) **pbags,
    PKCS12_SAFEBAG *bag)
{
    int free_bags;
    if (!pbags)
        return STATUS_OK;
    if (!*pbags) {
        *pbags = sk_PKCS12_SAFEBAG_new_null();
        if (!*pbags)
            return STATUS_FAILED;
        free_bags = 1;
    } else {
        free_bags = 0;
    }
    
    if (!sk_PKCS12_SAFEBAG_push(*pbags, bag)) {
        if (free_bags) {
            sk_PKCS12_SAFEBAG_free(*pbags);
            *pbags = NULL;
        }
        return STATUS_FAILED;
    }

    return STATUS_OK;
}

static PKCS12_SAFEBAG *_pkcs12_add_cert_bag(
    STACK_OF(PKCS12_SAFEBAG) **pbags,
    X509 *cert,
    const char *name,
    int namelen,
    unsigned char *keyid,
    int keyidlen)
{
    PKCS12_SAFEBAG *bag = NULL;

    /* Add user certificate */
    if ((bag = PKCS12_SAFEBAG_create_cert(cert)) == NULL)
        goto err;

    if (name != NULL && !PKCS12_add_friendlyname(bag, name, namelen))
        goto err;

    if (keyid != NULL && !PKCS12_add_localkeyid(bag, keyid, keyidlen))
        goto err;

    if (!_pkcs12_add_bag(pbags, bag))
        goto err;

    return bag;

 err:
    PKCS12_SAFEBAG_free(bag);
    return NULL;
}