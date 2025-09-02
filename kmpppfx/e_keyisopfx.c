/*
 * Copyright 2008-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdbool.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <openssl/engine.h>
#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>

#include "e_keyisosymmetric.h"
#include "e_keyisopfx_err.h"

#include "keyisocertinternal.h"
#include "keyisoclientinternal.h"
#include "keyisopfxclientinternal.h"
#include "keyisolog.h"
#include "keyisotelemetry.h"
#include "keyisocommon.h"

#include "keyisoclient.h"
#include "keyisomemory.h"
#include "keyisocert.h"
#include "keyisoutils.h"

extern KEYISO_CLIENT_CONFIG_ST g_config;
extern KEYISO_KEYSINUSE_ST g_keysinuse;
static const char *engine_kmpppfx_id = KMPP_ENGINE_ID;
static const char *engine_kmpppfx_name = KMPP_ENGINE_NAME;

static CRYPTO_ONCE once_pkey_meths = CRYPTO_ONCE_STATIC_INIT;
static CRYPTO_ONCE once_compatibility_modes = CRYPTO_ONCE_STATIC_INIT;
static int fips_compatibility_mode  = -1;
static int pkcs8_compatibility_mode  = -1;

static const int kmpppfx_pkey_nids[] = {
    EVP_PKEY_RSA,
    EVP_PKEY_RSA_PSS,
    EVP_PKEY_EC};
static const int evp_nids_count = sizeof(kmpppfx_pkey_nids)/sizeof(kmpppfx_pkey_nids[0]);

typedef struct KMPPPFX_CTX_st KMPPPFX_CTX;
typedef struct KMPPPFX_KEY_st KMPPPFX_KEY;

static void KMPPPFX_trace(KMPPPFX_CTX *ctx, char *format, ...);

void kmpppfx_free_key(KMPPPFX_KEY *key);

static EVP_PKEY *kmpppfx_load_privkey(ENGINE *eng, const char *key_id,
                                         UI_METHOD *ui_method, void *callback_data);

static int kmpppfx_load_ssl_client_cert(ENGINE *e, SSL *ssl,
                                     STACK_OF(X509_NAME) *ca_dn, X509 **pcert,
                                     EVP_PKEY **pkey, STACK_OF(X509) **pother,
                                     UI_METHOD *ui_method,
                                     void *callback_data);

static int kmpppfx_rsa_priv_enc(int flen, const unsigned char *from,
                                   unsigned char *to, RSA *rsa, int padding);
static int kmpppfx_rsa_priv_dec(int flen, const unsigned char *from,
                                   unsigned char *to, RSA *rsa, int padding);
static int kmpppfx_rsa_sign(int type, const unsigned char *m, unsigned int m_len,
                                   unsigned char *sigret, unsigned int *siglen, const RSA *rsa);
static int kmpppfx_rsa_free(RSA *rsa);

static int kmpppfx_pkey_rsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                                    const unsigned char *tbs, size_t tbslen);

static int kmpppfx_eckey_sign(int type, const unsigned char *dgst, int dlen,
                                 unsigned char *sig, unsigned int *siglen,
                                 const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);

static int kmpppfx_pkey_meths(ENGINE* e, EVP_PKEY_METHOD** pmeth,
                                    const int** nids, int nid);

static int kmpppfx_eckey_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                                       BIGNUM **rp);

static ECDSA_SIG *kmpppfx_eckey_sign_sig(const unsigned char *dgst, int dgst_len,
                                            const BIGNUM *in_kinv, const BIGNUM *in_r,
                                            EC_KEY *eckey);
static void kmpppfx_eckey_free(EC_KEY *eckey);

static void kmpppfx_rsa_sign_serialization(unsigned char *from, int type, 
                                                const unsigned char *m, unsigned int m_len);

static void kmpppfx_pkey_rsa_sign_serialization(unsigned char *from, const unsigned char *tbs, 
                                                    size_t tbslen, int saltlen, int sigmdtype, 
                                                    int mgfmdtype, size_t siglen, int getMaxLen);

/*
 * This structure contains KMPPPFX ENGINE specific data: it contains various
 * global options and affects how other functions behave.
 */

# define KMPPPFX_DBG_TRACE  2
# define KMPPPFX_DBG_ERROR  1


struct KMPPPFX_CTX_st {
    int debug_level;
    char *debug_file;
};

static KMPPPFX_CTX *kmpppfx_ctx_new(void);
static void kmpppfx_ctx_free(KMPPPFX_CTX *ctx);

# define KMPPPFX_CMD_DEBUG_LEVEL            ENGINE_CMD_BASE
# define KMPPPFX_CMD_DEBUG_FILE             (ENGINE_CMD_BASE + 1)
# define KMPPPFX_CMD_EXECUTE_FLAGS          (ENGINE_CMD_BASE + 2)
# define KMPPPFX_CMD_LOG_THRESHOLD          (ENGINE_CMD_BASE + 3)

static const ENGINE_CMD_DEFN kmpppfx_cmd_defns[] = {
    {KMPPPFX_CMD_DEBUG_LEVEL,
     "debug_level",
     "debug level (1=errors, 2=trace)",
     ENGINE_CMD_FLAG_NUMERIC},

    {KMPPPFX_CMD_DEBUG_FILE,
     "debug_file",
     "debugging filename)",
     ENGINE_CMD_FLAG_STRING},

    {KMPPPFX_CMD_EXECUTE_FLAGS,
     "execute_flags",
     "kmpp execute flags: 0x1 = inProc, 0x2 = traceLogTest",
     ENGINE_CMD_FLAG_NUMERIC},
#ifndef KMPP_TELEMETRY_DISABLED
    {KMPPPFX_CMD_LOG_THRESHOLD,
     "log_threshold",
     "kmpp log aggreagtion counter of key operations",
     ENGINE_CMD_FLAG_NUMERIC},
#endif
    {0, NULL, NULL, 0},
};

static int kmpppfx_idx = -1;
static int rsa_kmpppfx_idx = -1;
static int eckey_kmpppfx_idx = -1;

static EVP_PKEY_METHOD* g_kmpppfx_pkey_rsa_meth = NULL;
static EVP_PKEY_METHOD* g_kmpppfx_pkey_rsa_pss_meth = NULL;
static EVP_PKEY_METHOD* g_kmpppfx_pkey_ec_meth = NULL;

static const EVP_PKEY_METHOD* default_pkey_rsa_meth = NULL;
static const EVP_PKEY_METHOD* default_pkey_rsa_pss_meth = NULL;
static const EVP_PKEY_METHOD* default_pkey_ec_meth = NULL;

typedef int (*PFN_PKEY_rsa_sign_init) (EVP_PKEY_CTX *ctx);
typedef int (*PFN_PKEY_rsa_sign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                                    const unsigned char *tbs, size_t tbslen);

static int _init_kmpppfx_pkey_methods();
static int _get_fips_compatibility_mode_once();
static int _get_p8_compatibility_mode_once();

static int _get_pkey_rsa_meth(EVP_PKEY_METHOD **pkey_rsa_meth)
{
    if (pkey_rsa_meth == NULL || !_init_kmpppfx_pkey_methods()) {
        return 0;
    }
    *pkey_rsa_meth = g_kmpppfx_pkey_rsa_meth;
    return 1;
}

static int _get_pkey_rsa_pss_meth(EVP_PKEY_METHOD **pkey_rsa_pss_meth)
{
    if (pkey_rsa_pss_meth == NULL || !_init_kmpppfx_pkey_methods()) {
        return 0;
    }
    *pkey_rsa_pss_meth = g_kmpppfx_pkey_rsa_pss_meth;
    return 1;
}

static int _get_pkey_ec_meth(EVP_PKEY_METHOD **pkey_ec_meth)
{
    if (pkey_ec_meth == NULL || !_init_kmpppfx_pkey_methods()) {
        return 0;
    }
    *pkey_ec_meth = g_kmpppfx_pkey_ec_meth;
    return 1;
}

static void _trace_log_configuration()
{
    if (g_config.isDefaultSolutionType) {
        KEYISOP_trace_log_para(NULL, 0, KEYISOP_ENGINE_TITLE, "default solution type", "config file does not exist or failed to be loaded. solutionType: %d", g_config.solutionType);
    } else {
        KEYISOP_trace_log_para(NULL, 0, KEYISOP_ENGINE_TITLE, "non-default solution type", "config file was loaded. solutionType: %d", g_config.solutionType);
    }
}

static int kmpppfx_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    int ret = 1;
    KMPPPFX_CTX *ctx;
    char *tmpstr;
    if (kmpppfx_idx == -1) {
        KMPPPFXerr(KMPPPFX_F_CTRL, KMPPPFX_R_ENGINE_NOT_INITIALIZED);
        return 0;
    }
    ctx = ENGINE_get_ex_data(e, kmpppfx_idx);
    switch (cmd) {

    case KMPPPFX_CMD_DEBUG_LEVEL:
        ctx->debug_level = (int)i;
        KMPPPFX_trace(ctx, "Setting debug level to %d\n", ctx->debug_level);
        break;

    case KMPPPFX_CMD_DEBUG_FILE:
        OPENSSL_free(ctx->debug_file);
        ctx->debug_file = NULL;
        tmpstr = OPENSSL_strdup(p);
        if (tmpstr != NULL) {
            ctx->debug_file = tmpstr;
            KMPPPFX_trace(ctx, "Setting debug file to %s\n", ctx->debug_file);
        } else {
            KMPPPFXerr(KMPPPFX_F_CTRL, KMPPPFX_R_ALLOC_FAILURE);
            ret = 0;
        }
        break;

    case KMPPPFX_CMD_EXECUTE_FLAGS:
        KMPPPFX_trace(ctx, "Setting execute flags to 0x%lx\n", i);
        printf("Setting execute flags to 0x%lx\n", i);
        KeyIsoP_set_execute_flags((int) i);
        break;
#ifndef KMPP_TELEMETRY_DISABLED
    case KMPPPFX_CMD_LOG_THRESHOLD:
        KMPPPFX_trace(ctx, "Setting log counter threshold %ld\n", i);
        KeyIso_set_counter_th((int) i);
        break;
#endif
    default:
        KMPPPFXerr(KMPPPFX_F_CTRL, KMPPPFX_R_UNKNOWN_COMMAND);
        ret = 0;
    }

    return ret;
}

static int _meth_init(EVP_PKEY_METHOD **meth, int id, int flags, const EVP_PKEY_METHOD *default_meth)
{
    if (meth == NULL || default_meth == NULL) {
        return STATUS_FAILED;
    }
    *meth = EVP_PKEY_meth_new(id, flags);
    if (*meth == NULL) {
        return STATUS_FAILED;
    }
    EVP_PKEY_meth_copy(*meth, default_meth);
    return STATUS_OK;
}

static void _meth_clear(EVP_PKEY_METHOD **meth)
{
    if (meth != NULL && *meth != NULL) {
        EVP_PKEY_meth_free(*meth);
        *meth = NULL;
    }
}

static void _pkey_meths_init()
{
    int flags = 0;
    PFN_PKEY_rsa_sign_init psign_init = NULL;

    int fipsCompatible = _get_fips_compatibility_mode_once();
    if (fipsCompatible != FIPS_COMPATIBLE) {
        flags = EVP_PKEY_FLAG_AUTOARGLEN;
    }

    if (_meth_init(&g_kmpppfx_pkey_rsa_meth, EVP_PKEY_RSA, flags, default_pkey_rsa_meth) != STATUS_OK ||
        _meth_init(&g_kmpppfx_pkey_rsa_pss_meth, EVP_PKEY_RSA_PSS, flags, default_pkey_rsa_pss_meth) != STATUS_OK ||
        _meth_init(&g_kmpppfx_pkey_ec_meth, EVP_PKEY_EC, flags, default_pkey_ec_meth) != STATUS_OK) {
        goto err;
    }

    if (fipsCompatible == FIPS_COMPATIBLE) {
        EVP_PKEY_meth_get_sign(g_kmpppfx_pkey_rsa_meth, &psign_init, NULL);
        EVP_PKEY_meth_set_sign(g_kmpppfx_pkey_rsa_meth, psign_init, kmpppfx_pkey_rsa_sign);
        psign_init = NULL;
        EVP_PKEY_meth_get_sign(g_kmpppfx_pkey_rsa_pss_meth, &psign_init, NULL);
        EVP_PKEY_meth_set_sign(g_kmpppfx_pkey_rsa_pss_meth, psign_init, kmpppfx_pkey_rsa_sign);
    }

    return;

err:
    // It is very rare to reach this point when the value of pkey_rsa_meth or
    // pkey_rsapss_meth is not equal to NULL. However, we would like to prevent
    // memory leakage in such cases.
    _meth_clear(&g_kmpppfx_pkey_rsa_meth);
    _meth_clear(&g_kmpppfx_pkey_rsa_pss_meth);
    _meth_clear(&g_kmpppfx_pkey_ec_meth);   
    KMPPPFXerr(KMPPPFX_F_PKEY_METHS_INIT, KMPPPFX_R_CANT_GET_METHOD);
    return;
}

static int _init_kmpppfx_pkey_methods()
{
    return default_pkey_rsa_meth != NULL &&
        default_pkey_rsa_pss_meth != NULL &&
        default_pkey_ec_meth != NULL &&
        CRYPTO_THREAD_run_once(&once_pkey_meths, _pkey_meths_init) &&
        g_kmpppfx_pkey_rsa_meth != NULL &&
        g_kmpppfx_pkey_rsa_pss_meth != NULL &&
        g_kmpppfx_pkey_ec_meth != NULL;
}

static void _init_compatibility_modes()
{
    fips_compatibility_mode = KeyIso_validate_current_service_compatibility_mode(
        NULL,        // correlationId
        KeyisoCompatibilityMode_fips);
    if (fips_compatibility_mode == NOT_FIPS_COMPATIBLE) {
        pkcs8_compatibility_mode = NOT_PKCS8_COMPATIBLE;
    } else {
        pkcs8_compatibility_mode = KeyIso_validate_current_service_compatibility_mode(
            NULL,        // correlationId
            KeyisoCompatibilityMode_pkcs8);
    }
}

static int _get_fips_compatibility_mode_once()
{
    if (!CRYPTO_THREAD_run_once(&once_compatibility_modes, _init_compatibility_modes)) {
        return NOT_FIPS_COMPATIBLE;
    }
    return fips_compatibility_mode;
}

static int _get_p8_compatibility_mode_once()
{
    if (!CRYPTO_THREAD_run_once(&once_compatibility_modes, _init_compatibility_modes)) {
        return NOT_PKCS8_COMPATIBLE;
    }
    return pkcs8_compatibility_mode;
}

static const EVP_PKEY_METHOD *pkey_get_default_method(int nid)
{
    int compatible = _get_fips_compatibility_mode_once();
    ENGINE *default_pkey_engine = ENGINE_get_pkey_meth_engine(nid);

    if ((compatible == FIPS_COMPATIBLE) && (default_pkey_engine != NULL))
    {
        // get EVP_PKEY_METHOD from default engine supporting nid.
        return ENGINE_get_pkey_meth(default_pkey_engine, nid);
    }
    else
    {
        // This function first searches through the user-defined method objects and then the built-in objects.
        return EVP_PKEY_meth_find(nid);
    }
}

static void kmpppfx_get_default_methods()
{
    if (!default_pkey_rsa_meth) {
        default_pkey_rsa_meth = pkey_get_default_method(EVP_PKEY_RSA);
    }

    if (!default_pkey_rsa_pss_meth) {
        default_pkey_rsa_pss_meth = pkey_get_default_method(EVP_PKEY_RSA_PSS);
    }

    if (!default_pkey_ec_meth) {
        default_pkey_ec_meth = pkey_get_default_method(EVP_PKEY_EC);
    }
}

static int kmpppfx_init(ENGINE *e)
{
    KMPPPFX_CTX *ctx = NULL;
    __attribute__((unused)) const char *loc = ""; // To avoid unused var warning, only used in 'memerr' label.

    if (kmpppfx_idx < 0) {

        kmpppfx_idx = ENGINE_get_ex_new_index(0, NULL, NULL, NULL, 0);
        if (kmpppfx_idx < 0) {
            loc = "ENGINE_get_ex_new_index";
            goto memerr;
        } 

        /* Setup RSA_METHOD */
        rsa_kmpppfx_idx = RSA_get_ex_new_index(0, NULL, NULL, NULL, 0);

        /* Setup EC_METHOD */
        eckey_kmpppfx_idx = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, 0);
    }

    ctx = kmpppfx_ctx_new();
    if (ctx == NULL) {
        loc = "kmpppfx_ctx_new";
        goto memerr;
    }
        
    if (!_init_kmpppfx_pkey_methods()) {
        loc = "pkey_meths_init";
        goto memerr;
    }

    ENGINE_set_ex_data(e, kmpppfx_idx, ctx);

#ifndef KMPP_TELEMETRY_DISABLED
    // Setting the counters threshold according to environment variables
    int countTh = 0, timeTh = 0; 
    KeyIso_init_counter_th(&countTh, &timeTh, g_config.solutionType, g_keysinuse.isLibraryLoaded);
    KEYISOP_trace_metric_para(NULL, 0, g_config.solutionType, g_keysinuse.isLibraryLoaded, KEYISOP_ENGINE_TITLE, NULL,"Engine Init - counters and time thresholds: %d, %d", countTh, timeTh);
#endif

    return 1;

 memerr:
    if (ctx) {
        kmpppfx_ctx_free(ctx);
    }
    KMPPPFXerr(KMPPPFX_F_INIT, KMPPPFX_R_ALLOC_FAILURE);
    KEYISOP_trace_metric_error(NULL, 0, g_config.solutionType, g_keysinuse.isLibraryLoaded, KEYISOP_ENGINE_TITLE, loc, "Failed");
    return 0;
}

static int kmpppfx_destroy(ENGINE *e)
{
    RSA_METHOD *kmpppfx_rsa_method = (RSA_METHOD *) ENGINE_get_RSA(e);
    EC_KEY_METHOD *kmpppfx_eckey_method = (EC_KEY_METHOD *) ENGINE_get_EC(e);

    if (kmpppfx_rsa_method) {
        RSA_meth_free(kmpppfx_rsa_method);
        ENGINE_set_RSA(e, NULL);
    }
    if (kmpppfx_eckey_method) {
        EC_KEY_METHOD_free(kmpppfx_eckey_method);
        ENGINE_set_EC(e, NULL);
    }
    kmpp_symmetric_destroy(e);

#ifndef KMPP_TELEMETRY_DISABLED
    KeyIso_check_all_metrics(KeyisoKeyOperation_Max, KeyisoCleanCounters_All);
#endif
    ERR_unload_KMPPPFX_strings();
    return 1;
}

static int kmpppfx_finish(ENGINE *e)
{
    KMPPPFX_CTX *ctx;
    ctx = ENGINE_get_ex_data(e, kmpppfx_idx);

    if (ctx) {
        ENGINE_set_ex_data(e, kmpppfx_idx, NULL);
        kmpppfx_ctx_free(ctx);
    }
    return 1;
}

struct KMPPPFX_KEY_st {
    KEYISO_KEY_CTX *keyCtx;
    // engine is not in use since that we are using EVP_PKEY_set1_engine
    // ENGINE *eng;
};

static int bind_kmpppfx(ENGINE *e)
{
    int fipsCompatible = _get_fips_compatibility_mode_once();  
    int p8Compatible = _get_p8_compatibility_mode_once();

    RSA_METHOD *kmpppfx_rsa_method = RSA_meth_dup(RSA_get_default_method());
    EC_KEY_METHOD *kmpppfx_eckey_method = EC_KEY_METHOD_new(EC_KEY_get_default_method());

    if (!kmpppfx_rsa_method || !kmpppfx_eckey_method)
        goto memerr;

    _trace_log_configuration();

    // Load KeysInUse library during engine initialization
    if (!g_keysinuse.isLibraryLoaded) {
        KeyIso_load_keysInUse_library();
    }

    /* Setup RSA_METHOD */
    RSA_meth_set1_name(kmpppfx_rsa_method, "KMPP PFX RSA method");
    if (((g_config.solutionType != KeyIsoSolutionType_tz) && !RSA_meth_set_priv_enc(kmpppfx_rsa_method, kmpppfx_rsa_priv_enc))
         || !RSA_meth_set_priv_dec(kmpppfx_rsa_method, kmpppfx_rsa_priv_dec)
         || !RSA_meth_set_finish(kmpppfx_rsa_method, kmpppfx_rsa_free)) {
        
        goto memerr;
    }    

    // When PKCS8_COMPATIBLE, the service has SymCrypt based implementation, so we need to intercept RSA sign operation.
    // If not, we need to intercept RSA sign operation only if a default sign method was set (SCOSSL engine).
    // We do not support the case where KMPP is not PKCS8 compatible in OSSL 3.x.
    if (p8Compatible == PKCS8_COMPATIBLE) {
        // Always intercept RSA Sign operation. KMPP service has its owm SymCrypt based implementation.
        if (!RSA_meth_set_sign(kmpppfx_rsa_method, kmpppfx_rsa_sign)) {
            goto memerr;
        }
    } else {
        // Intercepts RSA Sign operation only if a default sign method was set.
        if (RSA_meth_get_sign(kmpppfx_rsa_method) != NULL) {
            if (fipsCompatible == FIPS_COMPATIBLE) {
                if (!RSA_meth_set_sign(kmpppfx_rsa_method, kmpppfx_rsa_sign)) {
                    goto memerr;
                }
            } else {
                // In case we are not in full-compatibility mode, we need to set 'NULL'
                // to the sign method so SCOSSL will not intercept it.
                if (!RSA_meth_set_sign(kmpppfx_rsa_method, NULL)) {
                    goto memerr;
                }
            }
        }
    }

    /* Setup EC_METHOD */
    EC_KEY_METHOD_set_init(kmpppfx_eckey_method, NULL, kmpppfx_eckey_free, NULL, NULL, NULL, NULL);
    EC_KEY_METHOD_set_sign(kmpppfx_eckey_method, kmpppfx_eckey_sign, kmpppfx_eckey_sign_setup,
                           kmpppfx_eckey_sign_sig);

    if (!ENGINE_set_id(e, engine_kmpppfx_id)
        || !ENGINE_set_name(e, engine_kmpppfx_name)
        || !ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL)
        || !ENGINE_set_init_function(e, kmpppfx_init)
        || !ENGINE_set_finish_function(e, kmpppfx_finish)
        || !ENGINE_set_destroy_function(e, kmpppfx_destroy)
        || !ENGINE_set_RSA(e, kmpppfx_rsa_method)
        || !ENGINE_set_EC(e, kmpppfx_eckey_method)
        || !ENGINE_set_pkey_meths(e, kmpppfx_pkey_meths)
        || !ENGINE_set_load_privkey_function(e, kmpppfx_load_privkey)
        || !ENGINE_set_load_ssl_client_cert_function(e, kmpppfx_load_ssl_client_cert)
        || !ENGINE_set_cmd_defns(e, kmpppfx_cmd_defns)
        || !ENGINE_set_ctrl_function(e, kmpppfx_ctrl))
        goto memerr;

    if (!kmpp_symmetric_bind_engine(e))
        goto memerr;

    ERR_load_KMPPPFX_strings();

    kmpppfx_get_default_methods();

    return 1;

 memerr:
    if (kmpppfx_rsa_method) {
        RSA_meth_free(kmpppfx_rsa_method);
        ENGINE_set_RSA(e, NULL);
    }
    if (kmpppfx_eckey_method) {
        EC_KEY_METHOD_free(kmpppfx_eckey_method);
        ENGINE_set_EC(e, NULL);
    }
    
    return 0;
}

static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_kmpppfx_id) != 0))
        return 0;
    if (!bind_kmpppfx(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)

static int kmpppfx_load(ENGINE *eng, const char *key_id,
                           EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca)
{
    const char *title = KEYISOP_ENGINE_TITLE;
    const char *loc = "";
    const char *errStr = "Failed";
    int ret = 0;
    KMPPPFX_CTX *ctx = NULL;
    KMPPPFX_KEY *key = NULL;
    uuid_t correlationId;
    int pfxLength = 0;
    unsigned char *pfxBytes = NULL;     // KeyIso_free()
    char *clientData = NULL;                  // KeyIso_clear_free_string()
    bool isKeyP8Compatible ;
    bool isServiceP8Compatible = (PKCS8_COMPATIBLE == _get_p8_compatibility_mode_once());

    *pkey = NULL;
    if (cert)
        *cert = NULL;

    KeyIso_rand_bytes(correlationId, sizeof(correlationId));

    ERR_clear_error();

    ctx = ENGINE_get_ex_data(eng, kmpppfx_idx);
    if (!ctx) {
        KMPPPFXerr(KMPPPFX_F_LOAD, KMPPPFX_R_CANT_FIND_KMPPPFX_CONTEXT);
        loc = "ENGINE_get_ex_data";
        goto err;
    }

    key = KeyIso_zalloc(sizeof(*key));
    if (!key) {
        KMPPPFXerr(KMPPPFX_F_LOAD, KMPPPFX_R_ALLOC_FAILURE);
        loc = "KeyIso_zalloc";
        goto err;
    }

    if (!KeyIso_parse_pfx_engine_key_id(
            correlationId,
            key_id,
            &pfxLength,
            &pfxBytes,
            &clientData)) {
        KMPPPFXerr(KMPPPFX_F_LOAD, KMPPPFX_R_PARSE_PFX_KEY_ID_ERROR);
        loc = "KeyIso_parse_pfx_engine_key_id";
        goto err;
    }
    
    isKeyP8Compatible = !KeyIso_is_oid_pbe2(correlationId, pfxBytes, pfxLength);

    if (!KeyIso_open_key_by_compatibility(correlationId, &key->keyCtx, pfxBytes, pfxLength, clientData, isKeyP8Compatible, isServiceP8Compatible)) {
        KMPPPFXerr(KMPPPFX_F_LOAD, KMPPPFX_R_PFX_OPEN_ERROR);
        loc = "KeyIso_open_key_by_compatibility";
        goto err;
    }

    if (!KeyIso_load_public_key_by_compatibility(correlationId, key->keyCtx, isKeyP8Compatible,  pfxLength, pfxBytes, pkey, cert, ca)) {
        KMPPPFXerr(KMPPPFX_F_LOAD, KMPPPFX_R_LOAD_PFX_PUBKEY_ERROR);
        loc = "KeyIso_load_public_key_by_compatibility";
        goto err;
    }

    KeyIso_add_key_to_keys_in_use(correlationId, key->keyCtx, *pkey);

    if (EVP_PKEY_id(*pkey) == EVP_PKEY_RSA ||
        EVP_PKEY_id(*pkey) == EVP_PKEY_RSA_PSS) {
        loc = "rsa";
        RSA *rsa = (RSA *)EVP_PKEY_get0_RSA(*pkey);        // get0 doesn't up_ref

        // Workaround for OpelSSL 3.x - Self signed certificate scenario
        // X509_get0_pubkey returns a legacy key, however it doesn't have a ASN1 method (ameth),
        // which is required for X509_sign_ctx.
        EVP_PKEY *evpkey = EVP_PKEY_new();
        if (!evpkey || !rsa || !EVP_PKEY_set1_RSA(evpkey, rsa)) {
            KMPPPFXerr(KMPPPFX_F_LOAD, KMPPPFX_R_INVALID_RSA);
            goto err;
        }
        EVP_PKEY_free(*pkey);
        *pkey = evpkey;

        const RSA_METHOD *kmpppfx_rsa_method = ENGINE_get_RSA(eng);
        if (!kmpppfx_rsa_method) {
            KMPPPFXerr(KMPPPFX_F_LOAD, KMPPPFX_R_CANT_GET_METHOD);
            goto err;
        }

        RSA_set_method(rsa, kmpppfx_rsa_method);
        RSA_set_ex_data(rsa, rsa_kmpppfx_idx, key);
        if (!EVP_PKEY_set1_engine(*pkey, eng)) {// moving ownership to EVP_PKEY, engine ref count will be increased by one and will be decreased when client calls to EVP_PKEY_free
            KMPPPFXerr(KMPPPFX_F_LOAD, KMPPPFX_R_ENGINE_NOT_INITIALIZED);
            loc = "EVP_PKEY_set1_engine";
            goto err;
        } 
    } else if (EVP_PKEY_id(*pkey) == EVP_PKEY_EC) {
        loc = "ec";
        EC_KEY *eckey = (EC_KEY *)EVP_PKEY_get0_EC_KEY(*pkey);   // get0 doesn't up_ref
        
        // Workaround for OpelSSL 3.x - Self signed certificate scenario
        // X509_get0_pubkey returns a legacy key, however it doesn't have a ASN1 method (ameth),
        // which is required for X509_sign_ctx.
        EVP_PKEY *evpkey = EVP_PKEY_new();
        if (!evpkey || !eckey || !EVP_PKEY_set1_EC_KEY(evpkey, eckey)) {
            KMPPPFXerr(KMPPPFX_F_LOAD, KMPPPFX_R_INVALID_EC_KEY);
            goto err;
        }
        EVP_PKEY_free(*pkey);
        *pkey = evpkey;
        
        const EC_KEY_METHOD *kmpppfx_eckey_method = ENGINE_get_EC(eng);
        if (!kmpppfx_eckey_method) {
            KMPPPFXerr(KMPPPFX_F_LOAD, KMPPPFX_R_CANT_GET_METHOD);
            goto err;
        }

        EC_KEY_set_method(eckey, kmpppfx_eckey_method);
        EC_KEY_set_ex_data(eckey, eckey_kmpppfx_idx, key);
        if (!EVP_PKEY_set1_engine(*pkey, eng)) {// moving ownership to EVP_PKEY, engine ref count will be increased by one and will be decreased when client calls to EVP_PKEY_free
            KMPPPFXerr(KMPPPFX_F_LOAD, KMPPPFX_R_ENGINE_NOT_INITIALIZED);
            loc = "EVP_PKEY_set1_engine";
            goto err;
        }         
    } else {
        loc = "unsupported";
        KMPPPFXerr(KMPPPFX_F_LOAD, KMPPPFX_R_UNSUPPORTED_KEY_ALGORITHM);
        goto err;
    }

    ret = 1;

end:
    if (ret == 1) {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Complete");
        KEYISOP_trace_log_and_metric_para(correlationId, 0, g_config.solutionType, g_keysinuse.isLibraryLoaded, title, "", 
            "key was successfully loaded. Key type: %d. isKeyP8Compatible: %d. isServiceP8Compatible: %d. isDefaultSolutionType: %d", 
            EVP_PKEY_id(*pkey), isKeyP8Compatible, isServiceP8Compatible, g_config.isDefaultSolutionType);
    }

    KeyIso_free(pfxBytes);
    KeyIso_clear_free_string(clientData);
    return ret;

err:
    KEYISOP_trace_log_error(correlationId, 0, title, loc, errStr);

    kmpppfx_free_key(key);
    if (*pkey) {
        EVP_PKEY_free(*pkey);
        *pkey = NULL;
    }
    if (cert && *cert) {
        X509_free(*cert);
        *cert = NULL;
    }

    goto end;
}


static EVP_PKEY *kmpppfx_load_privkey(ENGINE *eng, const char *key_id,
                                         UI_METHOD *ui_method, void *callback_data)
{
    EVP_PKEY *pkey = NULL;

    kmpppfx_load(eng, key_id, &pkey, NULL, NULL);
    return pkey;
}

static int kmpppfx_load_ssl_client_cert(ENGINE *e, SSL *ssl,
                                           STACK_OF(X509_NAME) *ca_dn, X509 **pcert,
                                           EVP_PKEY **pkey, STACK_OF(X509) **pother,
                                           UI_METHOD *ui_method,
                                           void *callback_data)
{
    // Need key_id
    KMPPPFXerr(KMPPPFX_F_LOAD, KMPPPFX_R_UNSUPPORTED_SSL_CLIENT_CERT);
    KEYISOP_trace_log_error(NULL, 0, KEYISOP_ENGINE_TITLE, NULL, "Not supported");
    return 0;

#if 0
    return kmpppfx_load(e, NULL, pkey, pcert, pother);
#endif
}


/* KMPP PFX RSA operations */


static int get_rsa_key_ctx(RSA *rsa,
                           KEYISO_KEY_CTX **keyCtx)
{
    KMPPPFX_KEY *kmpppfx_key;

    *keyCtx = 0;

    kmpppfx_key = RSA_get_ex_data(rsa, rsa_kmpppfx_idx);
    if (!kmpppfx_key || !kmpppfx_key->keyCtx) {
//        KMPPPFXerr(KMPPPFX_F_GET_PRIVATE_RSA, KMPPPFX_R_CANT_GET_KEY);
        return 0;
    }

    *keyCtx = kmpppfx_key->keyCtx;

    return 1;
}

typedef int (*PFN_RSA_meth_priv_enc)(
    int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding);

static int kmpppfx_rsa_priv_enc(int flen, const unsigned char* from,
                                   unsigned char *to, RSA *rsa, int padding)
{
    KEYISO_KEY_CTX *keyCtx = NULL;
    int ret = -1;

    // Start measuring time for metrics
    START_MEASURE_TIME();

    if (get_rsa_key_ctx(rsa, &keyCtx)) {
        ret = KeyIso_CLIENT_rsa_private_encrypt(
            keyCtx,
            flen,
            from,
	        RSA_size(rsa),
            to,
            padding);
    } else {
        const RSA_METHOD *ossl_rsa_meth = RSA_get_default_method();
        PFN_RSA_meth_priv_enc pfn_rsa_meth_priv_enc = RSA_meth_get_priv_enc(ossl_rsa_meth);
        if (!pfn_rsa_meth_priv_enc) {
            KMPPPFXerr(KMPPPFX_F_RSA_PRIV_ENC, KMPPPFX_R_CANT_GET_METHOD);
            ret = -1;
            goto end;
        }

        ret = pfn_rsa_meth_priv_enc(flen, from, to, rsa, padding);
    }

end:
    STOP_MEASURE_TIME(KeyisoKeyOperation_RsaPrivEnc);

     return ret;
}

typedef int (*PFN_RSA_meth_priv_dec)(
    int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding);

static int kmpppfx_rsa_priv_dec(int flen, const unsigned char *from,
                                   unsigned char *to, RSA *rsa, int padding)
{
    KEYISO_KEY_CTX *keyCtx = NULL;
    int ret = -1;

    // Start measuring time for metrics
    START_MEASURE_TIME();

    if (get_rsa_key_ctx(rsa, &keyCtx)) {
        ret = KeyIso_CLIENT_rsa_private_decrypt(
            keyCtx,
            flen,
            from,
	        RSA_size(rsa),
            to,
            padding,
            0);
    } else {
        const RSA_METHOD *ossl_rsa_meth = RSA_get_default_method();
        PFN_RSA_meth_priv_dec pfn_rsa_meth_priv_dec = RSA_meth_get_priv_dec(ossl_rsa_meth);

        if (!pfn_rsa_meth_priv_dec) {
            KMPPPFXerr(KMPPPFX_F_RSA_PRIV_DEC, KMPPPFX_R_CANT_GET_METHOD);
            ret = -1;
            goto end;
        }

        ret = pfn_rsa_meth_priv_dec(flen, from, to, rsa, padding);
    }

end:
    STOP_MEASURE_TIME(KeyisoKeyOperation_RsaPrivDec);

     return ret;
}

typedef int (*PFN_RSA_meth_sign) (int type, const unsigned char *m, unsigned int m_len,
                                   unsigned char *sigret, unsigned int *siglen, const RSA *rsa);

static int kmpppfx_rsa_sign(int type, const unsigned char *m, unsigned int m_len,
                                   unsigned char *sigret, unsigned int *siglen, const RSA *rsa)
{
    int ret = -1;                   // RSA_sign() return 1 on success.
    unsigned int flen;
    unsigned char *from     = NULL;
    KEYISO_KEY_CTX *keyCtx = NULL;

    // Start measuring time for metrics
    START_MEASURE_TIME();

    if (get_rsa_key_ctx((RSA *)rsa, &keyCtx)) {
        flen = sizeof(KEYISO_RSA_SIGN) + m_len; 
        from = (unsigned char *) KeyIso_zalloc(flen);

        if(from == NULL) {
            KMPPPFXerr(KMPPPFX_F_RSA_SIGN, KMPPPFX_R_ALLOC_FAILURE);
            goto end;
        }
        
        kmpppfx_rsa_sign_serialization(from, type, m, m_len);

        ret = KeyIso_CLIENT_rsa_sign(
            keyCtx,
            (int)flen,       
            from,
	        RSA_size(rsa),
            sigret,         
            0);         // padding mode
        
        if (ret <= 0) {
            goto end;
        }

        *siglen = ret;
        ret = 1;

    } else {
        // kmpppfx_rsa_sign is being called only if RSA sign 
        // method is supported in the default RSA methods.
         
        const RSA_METHOD *default_rsa_meth = RSA_get_default_method();
        PFN_RSA_meth_sign pfn_default_rsa_sign = RSA_meth_get_sign(default_rsa_meth);

        if (pfn_default_rsa_sign == NULL) {
            KMPPPFXerr(KMPPPFX_F_RSA_SIGN, KMPPPFX_R_CANT_GET_METHOD);
            goto end;
        }

        ret = pfn_default_rsa_sign(type, m, m_len, sigret, siglen, (RSA *)rsa);
    }


end:
    if (from != NULL) {
        KeyIso_free(from);
        from = NULL;
    }

    STOP_MEASURE_TIME(KeyisoKeyOperation_RsaSign); 

    return ret;
}

static void kmpppfx_rsa_sign_serialization(unsigned char *from, int type, 
                                                const unsigned char *m, unsigned int m_len)
{
    return KeyIso_rsa_sign_serialization(from, type, m, m_len);
} 

typedef int (*PFN_RSA_meth_finish)(RSA *rsa);

static int kmpppfx_rsa_free(RSA *rsa)
{
    KMPPPFX_KEY *kmpppfx_key;
    const RSA_METHOD *ossl_rsa_meth = RSA_get_default_method();
    PFN_RSA_meth_finish pfn_rsa_meth_finish = RSA_meth_get_finish(ossl_rsa_meth);

    if (pfn_rsa_meth_finish) {
        pfn_rsa_meth_finish(rsa);
    }

    kmpppfx_key = RSA_get_ex_data(rsa, rsa_kmpppfx_idx);
    kmpppfx_free_key(kmpppfx_key);
    RSA_set_ex_data(rsa, rsa_kmpppfx_idx, NULL);
    return 1;
}


/* KMPP EVP PKEY RSA methods */

static int kmpppfx_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                                    const int **nids, int nid)
{
    int ret = 0;

    if (pmeth == NULL || nid == 0)
    {
        *nids = kmpppfx_pkey_nids;
        return evp_nids_count;
    }

    switch(nid)
    {
        case EVP_PKEY_RSA:
        {
            ret = _get_pkey_rsa_meth(pmeth);
            break;
        }
        case EVP_PKEY_RSA_PSS:
        {
            ret = _get_pkey_rsa_pss_meth(pmeth);
            break;
        }
        case EVP_PKEY_EC:
        {
            ret = _get_pkey_ec_meth(pmeth);
            break;
        }
        default:
        {
            *pmeth = NULL;
            break;
        }
    }
    
    return ret;
}

static int kmpppfx_pkey_rsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                                    const unsigned char *tbs, size_t tbslen)
{
    // return 1 for success. 0 or negative for failure.

    EVP_PKEY *pkey;
    RSA *rsa;

    int padding;
    int sigmdtype;
    int getMaxLen;       // if sig is NULL we set this flag to 1.
    unsigned int flen;
    unsigned int tlen;
    size_t siglength;    // if sig is not NULL we set this param to *siglen.

    int ret         = 0;
    int mgfmdtype   = 0;
    int saltlen     = RSA_PSS_SALTLEN_AUTO;

    KEYISO_KEY_CTX *keyCtx = NULL;
    const EVP_MD *sigmd     = NULL;
    const EVP_MD *mgfmd     = NULL;
    unsigned char *from     = NULL;
    unsigned char *to       = NULL;

    // Start measuring time for metrics
    START_MEASURE_TIME();

    pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    if (pkey == NULL) {
        KMPPPFXerr(KMPPPFX_F_PKEY_RSA_SIGN, KMPPPFX_R_CANT_GET_KEY);
        goto end;
    }

    rsa = (RSA *)EVP_PKEY_get0_RSA(pkey);
    if (rsa == NULL) {
        KMPPPFXerr(KMPPPFX_F_PKEY_RSA_SIGN, KMPPPFX_R_INVALID_RSA);
        goto end;
    }

    if (get_rsa_key_ctx(rsa, &keyCtx)) {

        if (EVP_PKEY_CTX_get_signature_md(ctx, &sigmd) <= 0) {
            KMPPPFXerr(KMPPPFX_F_PKEY_RSA_SIGN, KMPPPFX_R_CANT_GET_SIGNATURE_MD);
            goto end;
        }
        if(sigmd == NULL) {
            KMPPPFXerr(KMPPPFX_F_PKEY_RSA_SIGN, KMPPPFX_R_PADDING_NOT_SUPPORTED);
            goto end;
        }
        sigmdtype = EVP_MD_type(sigmd);
        if (EVP_PKEY_CTX_get_rsa_padding(ctx, &padding) <= 0) {
            KMPPPFXerr(KMPPPFX_F_PKEY_RSA_SIGN, KMPPPFX_R_CANT_GET_PADDING);
            goto end;
        }
        if (padding != RSA_PKCS1_PSS_PADDING && padding != RSA_PKCS1_PADDING) {
            KMPPPFXerr(KMPPPFX_F_PKEY_RSA_SIGN, KMPPPFX_R_PADDING_NOT_SUPPORTED);
            goto end;
        }
        if (padding == RSA_PKCS1_PSS_PADDING) {
            if (EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, &saltlen) <= 0 ) {
                KMPPPFXerr(KMPPPFX_F_PKEY_RSA_SIGN, KMPPPFX_R_CANT_GET_SALT_LENGTH);
                goto end;
            }
            if (EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &mgfmd) <= 0) {
                KMPPPFXerr(KMPPPFX_F_PKEY_RSA_SIGN, KMPPPFX_R_CANT_GET_RSA_MGF_MD);
                goto end;
            }
            if (mgfmd == NULL) {
                KMPPPFXerr(KMPPPFX_F_PKEY_RSA_SIGN, KMPPPFX_R_PADDING_NOT_SUPPORTED);
                goto end;
            }
            mgfmdtype = EVP_MD_type(mgfmd);
        }

        flen = sizeof(KEYISO_EVP_PKEY_SIGN) + tbslen;

        from = (unsigned char *) KeyIso_zalloc(flen);
        if(from == NULL){
            KMPPPFXerr(KMPPPFX_F_PKEY_RSA_SIGN, KMPPPFX_R_ALLOC_FAILURE);
            goto end;
        }

        if (sig == NULL){
            // If sig is NULL then the maximum size of the output buffer is written 
            // to the siglen parameter.
            // We will use a dummy buffer for that purpose. 
            getMaxLen = 1;
            siglength = 0;
            tlen = RSA_size(rsa);
            to = (unsigned char *) KeyIso_zalloc(tlen);
            if(to == NULL){
                KMPPPFXerr(KMPPPFX_F_PKEY_RSA_SIGN, KMPPPFX_R_ALLOC_FAILURE);
                goto end;
            }
        } else {
            // If sig is not NULL then before the call the siglen parameter should 
            // contain the length of the sig buffer.
            to = sig;
            getMaxLen = 0;
            siglength = (siglen != NULL) ? *siglen : 0;
            tlen = siglength;
        }

        if (tlen < RSA_size(rsa)) {
            KMPPPFXerr(KMPPPFX_F_PKEY_RSA_SIGN, KMPPPFX_R_INVALID_SIGNATURE_LENGTH);
            goto end;
        }
        
        // write properties to the buffer
        kmpppfx_pkey_rsa_sign_serialization(
            from,
            tbs, 
            tbslen, 
            saltlen, 
            sigmdtype, 
            mgfmdtype,
            siglength,
            getMaxLen);

        ret = KeyIso_CLIENT_pkey_rsa_sign(
            keyCtx,
            (int)flen,       
            from,
	        tlen,
            to,      
            padding);

        if (ret <= 0) {
            goto end;
        }

        if (siglen != NULL) {
            *siglen = ret;
        }
        ret = 1;
         
    } else {

        ////  Passthough  ////
        
        if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
            PFN_PKEY_rsa_sign default_pkey_rsa_sign = NULL;
            if (default_pkey_rsa_meth == NULL) {
                KMPPPFXerr(KMPPPFX_F_PKEY_RSA_SIGN, KMPPPFX_R_CANT_GET_METHOD);
                goto end;
            }
            EVP_PKEY_meth_get_sign(default_pkey_rsa_meth, NULL, &default_pkey_rsa_sign);
            if (default_pkey_rsa_sign == NULL) {
                KMPPPFXerr(KMPPPFX_F_PKEY_RSA_SIGN, KMPPPFX_R_CANT_GET_METHOD);
                goto end;
            }
            ret = default_pkey_rsa_sign(ctx, sig, siglen, tbs, tbslen);
        } else if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA_PSS) {
            PFN_PKEY_rsa_sign default_pkey_rsa_pss_sign = NULL;
            if (default_pkey_rsa_pss_meth == NULL) {
                KMPPPFXerr(KMPPPFX_F_PKEY_RSA_SIGN, KMPPPFX_R_CANT_GET_METHOD);
                goto end;
            }
            EVP_PKEY_meth_get_sign(default_pkey_rsa_pss_meth, NULL, &default_pkey_rsa_pss_sign);
            if (default_pkey_rsa_pss_sign == NULL) {
                KMPPPFXerr(KMPPPFX_F_PKEY_RSA_SIGN, KMPPPFX_R_CANT_GET_METHOD);
                goto end;
            }
            ret = default_pkey_rsa_pss_sign(ctx, sig, siglen, tbs, tbslen);
        }
    }

end:
    if (from != NULL) {
        KeyIso_free(from);
        from = NULL;
    }
    if (to != NULL && sig == NULL) {
        KeyIso_free(to);
        to = NULL;
    }

    STOP_MEASURE_TIME(KeyisoKeyOperation_PkeyRsaSign);

    return ret;
}

static void kmpppfx_pkey_rsa_sign_serialization(unsigned char *from, const unsigned char *tbs, size_t tbsLen, 
                                                    int saltLen, int mdType, int mgfmdType, size_t sigLen, int getMaxLen)
{
    return KeyIso_CLIENT_pkey_rsa_sign_serialization(from, tbs, tbsLen, saltLen, mdType, mgfmdType, sigLen, getMaxLen);
}

/* KMPP PFX EC operations */

static int get_ec_key_ctx(EC_KEY *eckey,
                          KEYISO_KEY_CTX **keyCtx)
{
    KMPPPFX_KEY *kmpppfx_key;

    *keyCtx = NULL;

    kmpppfx_key = EC_KEY_get_ex_data(eckey, eckey_kmpppfx_idx);
    if (!kmpppfx_key || !kmpppfx_key->keyCtx) {
//        KMPPPFXerr(KMPPPFX_F_GET_PRIVATE_EC_KEY, KMPPPFX_R_CANT_GET_KEY);
        return 0;
    }

    *keyCtx = kmpppfx_key->keyCtx;

    return 1;
}

typedef int (*PFN_eckey_sign)(
    int type, const unsigned char *dgst, int dlen,
    unsigned char *sig, unsigned int *siglen,
    const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);

static int kmpppfx_eckey_sign(int type, const unsigned char *dgst, int dlen,
                                 unsigned char *sig, unsigned int *siglen,
                                 const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey)
{
    KEYISO_KEY_CTX *keyCtx = NULL;
    int ret = -1;

    // Start measuring time for metrics
    START_MEASURE_TIME();

    if (get_ec_key_ctx(eckey, &keyCtx)) {
        if (kinv != NULL || r != NULL) {
            // Symcrypt does not support taking kinv or r parameters, nor the provider
            // This parameters could be used by an application to implement deterministic ECDSA via OpenSSL 1.1.1 APIs so ignoring them might break the application hence we return an error here
            KMPPPFXerr(KMPPPFX_F_EC_KEY_SIGN, KMPPPFX_R_UNSUPPORTED_KINV_R_PARAMS);
            goto end;   
        }
	    *siglen = 0;
        ret = KeyIso_CLIENT_ecdsa_sign(
            keyCtx,
            type,
            dgst,
            dlen,
            sig,
            (unsigned int) ECDSA_size(eckey),
            siglen);
    } else {
        const EC_KEY_METHOD *ossl_eckey_method = EC_KEY_get_default_method();
        PFN_eckey_sign pfn_eckey_sign = NULL;

        EC_KEY_METHOD_get_sign(ossl_eckey_method, &pfn_eckey_sign, NULL, NULL);
        if (!pfn_eckey_sign) {
            KMPPPFXerr(KMPPPFX_F_EC_KEY_SIGN, KMPPPFX_R_CANT_GET_METHOD);
            ret = 0;
            goto end;
        }
        ret = pfn_eckey_sign(type, dgst, dlen, sig, siglen, kinv, r, eckey);
    }
end:
    STOP_MEASURE_TIME(KeyisoKeyOperation_EcdsaSign);

    return ret;
}

typedef int (*PFN_eckey_sign_setup)(
    EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
    BIGNUM **rp);

static int kmpppfx_eckey_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                                     BIGNUM **rp)
{
    const EC_KEY_METHOD *ossl_eckey_method = EC_KEY_get_default_method();
    PFN_eckey_sign_setup pfn_eckey_sign_setup = NULL;

    EC_KEY_METHOD_get_sign(ossl_eckey_method, NULL, &pfn_eckey_sign_setup, NULL);
    if (!pfn_eckey_sign_setup) {
        KMPPPFXerr(KMPPPFX_F_EC_KEY_SIGN_SETUP, KMPPPFX_R_CANT_GET_METHOD);
        return 0;
    }

    return pfn_eckey_sign_setup(eckey, ctx_in, kinvp, rp);
}

typedef ECDSA_SIG *(*PFN_eckey_sign_sig)(
    const unsigned char *dgst, int dgst_len,
    const BIGNUM *in_kinv, const BIGNUM *in_r,
    EC_KEY *eckey);

static ECDSA_SIG *kmpppfx_eckey_sign_sig(const unsigned char *dgst, int dgst_len,
                                         const BIGNUM *in_kinv, const BIGNUM *in_r,
                                         EC_KEY *eckey)
{
    KEYISO_KEY_CTX *keyCtx = NULL;

    if (get_ec_key_ctx(eckey, &keyCtx)) {
         if (in_kinv != NULL || in_r != NULL) {
            // Symcrypt does not support taking kinv or r parameters, nor the provider
            // This parameters could be used by an application to implement deterministic ECDSA via OpenSSL 1.1.1 APIs so ignoring them might break the application hence we return an error
            KMPPPFXerr(KMPPPFX_F_EC_KEY_SIGN, KMPPPFX_R_UNSUPPORTED_KINV_R_PARAMS);
            return NULL; 
        }
        unsigned char *sig = NULL;
        unsigned int siglen = (unsigned int) ECDSA_size(eckey);
        ECDSA_SIG *decodedSig = NULL;

        if (siglen > 0) {
            sig = (unsigned char *) KeyIso_zalloc(siglen);
        }
        if (sig == NULL) {
            KMPPPFXerr(KMPPPFX_F_CTX_NEW, KMPPPFX_R_ALLOC_FAILURE);
            return NULL;
        }

        if (KeyIso_CLIENT_ecdsa_sign(
                keyCtx,
                0,              // type
                dgst,
                dgst_len,
                sig,
                siglen,
                &siglen)) {
            const unsigned char *p = sig;
            decodedSig = d2i_ECDSA_SIG(NULL, &p, (long) siglen);

        }
        KeyIso_free(sig);
        if (!decodedSig)
            KMPPPFXerr(KMPPPFX_F_EC_KEY_SIGN_SETUP, KMPPPFX_R_CANT_GET_METHOD);
        return decodedSig;
    } else {
        const EC_KEY_METHOD *ossl_eckey_method = EC_KEY_get_default_method();
        PFN_eckey_sign_sig pfn_eckey_sign_sig = NULL;

        EC_KEY_METHOD_get_sign(ossl_eckey_method, NULL, NULL, &pfn_eckey_sign_sig);
        if (!pfn_eckey_sign_sig) {
            KMPPPFXerr(KMPPPFX_F_EC_KEY_SIGN_SIG, KMPPPFX_R_CANT_GET_METHOD);
            return NULL;
        }

        return pfn_eckey_sign_sig(dgst, dgst_len, in_kinv, in_r, eckey);
    }
}

static void kmpppfx_eckey_free(EC_KEY *eckey)
{
    KMPPPFX_KEY *kmpppfx_key;
    kmpppfx_key = EC_KEY_get_ex_data(eckey, eckey_kmpppfx_idx);
    kmpppfx_free_key(kmpppfx_key);
    EC_KEY_set_ex_data(eckey, eckey_kmpppfx_idx, NULL);
}


static void kmpppfx_vtrace(KMPPPFX_CTX *ctx, int level, char *format,
                        va_list argptr)
{
    BIO *out;

    if (!ctx || (ctx->debug_level < level) || (!ctx->debug_file))
        return;
    out = BIO_new_file(ctx->debug_file, "a+");
    if (out == NULL) {
        KMPPPFXerr(KMPPPFX_F_VTRACE, KMPPPFX_R_FILE_OPEN_ERROR);
        return;
    }
    BIO_vprintf(out, format, argptr);
    BIO_free(out);
}

static void KMPPPFX_trace(KMPPPFX_CTX *ctx, char *format, ...)
{
    va_list args;
    va_start(args, format);
    kmpppfx_vtrace(ctx, KMPPPFX_DBG_TRACE, format, args);
    va_end(args);
}

void kmpppfx_free_key(KMPPPFX_KEY *key)
{
    if (!key)
        return;
    if (key->keyCtx)
        KeyIso_CLIENT_pfx_close(key->keyCtx);
    KeyIso_free(key);
}

/* Initialize a KMPPPFX_CTX structure */

static KMPPPFX_CTX *kmpppfx_ctx_new(void)
{
    KMPPPFX_CTX *ctx = KeyIso_zalloc(sizeof(*ctx));

    if (ctx == NULL) {
        KMPPPFXerr(KMPPPFX_F_CTX_NEW, KMPPPFX_R_ALLOC_FAILURE);
        return NULL;
    }
    return ctx;
}

static void kmpppfx_ctx_free(KMPPPFX_CTX *ctx)
{
    KMPPPFX_trace(ctx, "Calling kmpppfx_ctx_free with %lx\n", ctx);
    if (!ctx)
        return;
    OPENSSL_free(ctx->debug_file);
    KeyIso_free(ctx);
}
