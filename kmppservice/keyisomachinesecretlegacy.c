#include <errno.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/bioerr.h>
#include <openssl/err.h>

#include "keyisolog.h"
#include "keyisocommon.h"
#include "keyisoservicecommon.h"
#include "keyisoutils.h"
#include "keyisomemory.h"

#ifdef KMPP_GENERAL_PURPOSE_TARGET
#ifdef  __cplusplus
extern "C" {
#endif 
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>
#include <dirent.h>
#define TCTI_NAME_DEFAULT "device:/dev/tpmrm0"
#define TPM_DEVICE_PREFIX "tpm"
#define TPM_DEVICE_DIR "/dev"
#ifdef  __cplusplus
}
#endif
#endif //KMPP_GENERAL_PURPOSE_TARGET


#define KEYISO_LEGACY_SECRET_SUB_PATH "private/pfx.0"

static unsigned char KEYISO_pfxSecret[KEYISO_SECRET_FILE_LENGTH];

const uint8_t* KeyIso_get_legacy_machine_secret(void) {
    return KEYISO_pfxSecret;
}

char* KeyIso_get_pfx_secret_filename()
{
    const char *dir = KeyIsoP_get_default_private_area();
     if (dir == NULL) {
        KEYISOP_trace_log_error(NULL, 0, KEYISOP_PFX_SECRET_TITLE, "Get secret directory", "Failed to get default private area");
        return NULL;
    }
    size_t dirLength = strlen(dir);
    const char *subPath = KEYISO_LEGACY_SECRET_SUB_PATH;
    size_t subPathLength = strlen(subPath);
    size_t filenameLength = dirLength + 1 + subPathLength + 1;
    char *filename = (char *) KeyIso_zalloc(filenameLength);

    if (filename != NULL) {
        snprintf(filename, filenameLength, "%s/%s", dir, subPath);
    }

    return filename;
}

static int _write_pfx_secret_file(
    const uuid_t correlationId,
    const char *filename)
{
    const char *title = KEYISOP_PFX_SECRET_TITLE;
    const char *loc = "";
    int ret = 0;
    BIO *out = NULL;
    unsigned char randBytes[KEYISO_SECRET_FILE_LENGTH];
    mode_t prevMask = 0;

    ERR_clear_error();

    if (KeyIso_rand_bytes(randBytes, sizeof(randBytes)) != STATUS_OK) {
        loc = "RAND_bytes";
        goto openSslErr;
    }

    if (randBytes[0] == 0) {
        randBytes[0] = 1;
    }

    prevMask = umask(077);      // Remove permissions for group/other

    out = BIO_new_file(filename, "wb");

    umask(prevMask);

    if (out == NULL) {
        loc = "BIO_new_file";
        goto openSslErr;
    }

    if (BIO_write(out, randBytes, sizeof(randBytes)) != sizeof(randBytes)) {
        loc = "BIO_write";
        goto openSslErr;
    }
    BIO_flush(out);

    ret = 1;

end:
    BIO_free(out);
    KeyIso_cleanse(randBytes, sizeof(randBytes));
    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, loc,
        "filename: %s", filename);
    goto end;
}

static int _read_pfx_secret_file(
    const uuid_t correlationId,
    const char *filename)
{
    const char *title = KEYISOP_PFX_SECRET_TITLE;
    const char *loc = "";
    int ret = 0;
    BIO *in = NULL;

    ERR_clear_error();

    in = BIO_new_file(filename, "rb");
    if (in == NULL) {
        if (ERR_GET_REASON(ERR_peek_last_error()) != BIO_R_NO_SUCH_FILE) {
            loc = "BIO_new_file";
            goto openSslErr;
        }
        goto end;
    }
    
    if (BIO_read(in, KEYISO_pfxSecret, sizeof(KEYISO_pfxSecret)) != sizeof(KEYISO_pfxSecret)) {
        loc = "BIO_read";
        goto openSslErr;
    }
    
    if (KEYISO_pfxSecret[0] == 0) {
        loc = "Invalid Content";
        goto openSslErr;
    }

    ret = 1;

end:
    if (!ret) {
        KeyIso_cleanse(KEYISO_pfxSecret, sizeof(KEYISO_pfxSecret));
    }
    BIO_free(in);
    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, loc,
        "filename: %s", filename);
    goto end;
}


int _create_pfx_secret(
    const uuid_t correlationId, 
    char *filename)
{
    const char *title = KEYISOP_PFX_SECRET_TITLE;
    int ret = 0;

    if (_read_pfx_secret_file(correlationId, filename)) {
        KEYISOP_trace_log_para(correlationId, 0, title, "Using previously generated PFX secret", "secret: %s", filename);
        goto success;
    }

    if (_write_pfx_secret_file(correlationId, filename) && _read_pfx_secret_file(correlationId, filename)) {
        KEYISOP_trace_log_para(correlationId, 0, title, "Generated PFX secret","secret: %s", filename);
        goto success;
    }
    KEYISOP_trace_log_error_para(correlationId, 0, title, "Create PFX secret", "Failed", "secret: %s", filename);
    goto end;

success:
    ret = 1;

end:
    return ret;
}

//////////////////////
// TPM functions
/////////////////////
#ifdef KMPP_GENERAL_PURPOSE_TARGET
static void _print_tpm_error(
    const uuid_t correlationId,
    TSS2_RC ret,
    const char *errStr,
    const char *loc) {

    const char *title = KEYISOP_TPM_SECRET_TITLE;
    const char* tpmErr; 
    tpmErr = Tss2_RC_Decode(ret); 
    KEYISOP_trace_log_error_para(correlationId, 0, title, loc, errStr, "0x%x, TPM Error String: %s", ret, tpmErr); 
}


static TSS2_RC _cleanup_create_secret_tpm(
    const uuid_t correlationId,
    TSS2_RC ret,
    const char *loc,
    const char *message,
    TSS2_TCTI_CONTEXT *pTctiCtx,
    ESYS_CONTEXT *ctx,
    ESYS_TR primaryHandle) 
{
    
    if (ret != TSS2_RC_SUCCESS)
        _print_tpm_error(correlationId, ret, loc, message);

    if (ctx != NULL) {
        Esys_FlushContext(ctx, primaryHandle);
        Esys_Finalize(&ctx);
    }

    if (pTctiCtx != NULL) {
        Tss2_TctiLdr_Finalize(&pTctiCtx);
    }

    return ret;
}

#define _CLEANUP_CREATE_SECRET_TPM(ret, loc, message) \
        _cleanup_create_secret_tpm(correlationId, ret, loc, message, pTctiCtx, ctx, primaryHandle)


static int _create_primary_key_tpm(
    ESYS_CONTEXT *ctx,
    ESYS_TR *primaryHandle)
{
    TSS2_RC ret;
    TPM2B_SENSITIVE_CREATE inSensitivePrim = { .size = 0 };
    TPML_PCR_SELECTION creationPCR = { .count = 0 };
    TPM2B_DATA outsideInfo = { .size = 0 };
    TPM2B_PUBLIC inPublicPrim = {
            .size = sizeof(TPMT_PUBLIC),
            .publicArea = {
                    .type = TPM2_ALG_RSA,
                    .nameAlg = TPM2_ALG_SHA256,
                    .objectAttributes = TPMA_OBJECT_RESTRICTED |
                                        TPMA_OBJECT_DECRYPT |
                                        TPMA_OBJECT_FIXEDTPM |
                                        TPMA_OBJECT_FIXEDPARENT |
                                        TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                        TPMA_OBJECT_USERWITHAUTH,
                    .authPolicy = {

                    },
                    .parameters = {
                            .rsaDetail = {
                                    .symmetric = {
                                                    .algorithm = TPM2_ALG_AES,
                                                    .keyBits = { .sym = 128 },
                                                    .mode = { .sym = TPM2_ALG_CFB }
                                    },
                                    .scheme = { .scheme = TPM2_ALG_NULL },
                                    .keyBits = 2048
                            }
                    },
                    .unique = {
                            .rsa = {
                                        .size = 256
                            }
                    }
            }
    };

    if ((ret = Esys_CreatePrimary(
	        ctx,
	        ESYS_TR_RH_OWNER,
            ESYS_TR_PASSWORD,
	        ESYS_TR_NONE,
	        ESYS_TR_NONE,
	        &inSensitivePrim,
	        &inPublicPrim,
            &outsideInfo,
	        &creationPCR,
	        primaryHandle,
	        NULL,
	        NULL,
            NULL,
	        NULL)) != TSS2_RC_SUCCESS) {
        return ret;  
    }

    return TSS2_RC_SUCCESS;
}


static TSS2_RC _cleanup_create_and_load_key_tpm(
    const uuid_t correlationId,
    TSS2_RC ret,
    const char *loc,
    const char *message,
    TPM2B_PUBLIC *outPublic,
    TPM2B_PRIVATE *outPrivate) 
{
    if(outPrivate)
        Esys_Free(outPrivate);
    if(outPublic)
        Esys_Free(outPublic);

    return ret;
}

#define _CLEANUP_CREATE_AND_LOAD_SECRET_TPM(ret, loc, message) \
        _cleanup_create_and_load_key_tpm(correlationId, ret, loc, message, outPublic, outPrivate)

static TSS2_RC _create_and_load_key_tpm(
    const uuid_t correlationId,
    ESYS_CONTEXT *ctx,
    ESYS_TR primaryHandle,
    ESYS_TR *objectHandleOut,
    const unsigned char *secret)
{
    TSS2_RC ret;
    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_PRIVATE *outPrivate = NULL;
    TPML_PCR_SELECTION creationPCR = { .count = 0 };
    TPM2B_DATA outsideInfo = { .size = 0 };

    TPM2B_PUBLIC inPublic = {
        .size = sizeof(TPMT_PUBLIC),
        .publicArea = {
            .type = TPM2_ALG_KEYEDHASH,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = TPMA_OBJECT_FIXEDTPM |
                                TPMA_OBJECT_FIXEDPARENT |
                                TPMA_OBJECT_USERWITHAUTH,
            .parameters = {
                .keyedHashDetail = {
                .scheme = { TPM2_ALG_NULL }
                }
            },
            .unique = {
                .keyedHash = {
                    .size = 32
                }
            }
        }
    };
    TPM2B_SENSITIVE_CREATE inSensitive = { 
	.size = sizeof(TPM2B_SENSITIVE_CREATE), 
	.sensitive = {
		.data = {
			.size = sizeof(secret),
			}
		}
	};
	memcpy(inSensitive.sensitive.data.buffer, secret, inSensitive.sensitive.data.size);

    if ((ret = Esys_Create(
                ctx,
                primaryHandle,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
			    &inSensitive,
                &inPublic,
                &outsideInfo,
                &creationPCR,
                &outPrivate,
                &outPublic,
                NULL,
                NULL,
                NULL)) != TSS2_RC_SUCCESS) {
        return _CLEANUP_CREATE_AND_LOAD_SECRET_TPM(ret, "Esys_Create", "");
    }

    // Loading sealing key;
    if ((ret = Esys_Load(
            ctx,
            primaryHandle,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            outPrivate,
            outPublic,
            objectHandleOut)) != TSS2_RC_SUCCESS) {
        return _CLEANUP_CREATE_AND_LOAD_SECRET_TPM(ret, "Esys_Load", "");
    }
    
    return _CLEANUP_CREATE_AND_LOAD_SECRET_TPM(TSS2_RC_SUCCESS, "", "");
}

static TSS2_RC _evict_control_tpm(
    const uuid_t correlationId,
    ESYS_CONTEXT* ctx,
    ESYS_TR primaryHandle,
    ESYS_TR inObjectHandle,
    TPMI_DH_PERSISTENT *persistHandle)
{
    TSS2_RC ret = TSS2_TCTI_RC_GENERAL_FAILURE;
    ESYS_TR evictObjectHandleOut;
    const char *title = KEYISOP_TPM_SECRET_TITLE;
    TPMI_DH_PERSISTENT currentHandle = *persistHandle;

    while (currentHandle <= TPM2_PERSISTENT_LAST) {
        // Evict control sealing key
        ret = Esys_EvictControl(
                ctx,
                ESYS_TR_RH_OWNER,
                inObjectHandle,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                currentHandle,
                &evictObjectHandleOut);

        if (ret == TSS2_RC_SUCCESS) {
            return TSS2_RC_SUCCESS;
        } else if (ret != TPM2_RC_NV_DEFINED) {
            break;
        }

        // Increment the persistent handle and try again
        currentHandle++;
        *persistHandle = currentHandle;
    }

    if (currentHandle >= TPM2_PERSISTENT_LAST) {
        KEYISOP_trace_log_error(correlationId, 0, title, NULL, "No available persistent handles");
    } 

    return ret;
}

static TSS2_RC _tpm_init_resources(
    TSS2_TCTI_CONTEXT **pTctiCtx,
    ESYS_CONTEXT **pCtx,
    ESYS_TR *primaryHandle, 
    const char** loc,
    const char** errStr)
{
    TSS2_RC ret = TSS2_RC_SUCCESS;
    TSS2_TCTI_CONTEXT* tctiCtx = NULL;
    ESYS_CONTEXT* ctx = NULL ;

    // Initialize the TCTI context
    // This initialization is required in old versions (below 2.4.0) of the TSS2 stack to avoid errors in the ESAPI initialization.
    if ((ret = Tss2_TctiLdr_Initialize(TCTI_NAME_DEFAULT, &tctiCtx)) != TSS2_RC_SUCCESS) {
        *loc = "Tss2_TctiLdr_Initialize";
        *errStr = "Error initializing TCTI ctx:";
        return ret;
    }

    // Initialize the ESAPI context
    if ((ret = Esys_Initialize(&ctx, tctiCtx, NULL)) != TSS2_RC_SUCCESS) {
        *loc = "Esys_Initialize";
        *errStr = "Error initializing ESAPI:";
        Tss2_TctiLdr_Finalize(&tctiCtx);
        return ret;
    }
 
    // Create primary key
    if ((ret = _create_primary_key_tpm(ctx, primaryHandle)) != TSS2_RC_SUCCESS) {
        *loc = "_create_primary_key_tpm";
        *errStr = "Error creating primary key:";
        Tss2_TctiLdr_Finalize(&tctiCtx);
        Esys_Finalize(&ctx);
        return ret;
    }

    *pTctiCtx = tctiCtx;
    *pCtx = ctx;
    return ret;
}

static TSS2_RC _create_secret_in_tpm(
    const uuid_t correlationId,
    const unsigned char *randBytesSecret,
    TPMI_DH_PERSISTENT *persistHandle)
{
    TSS2_TCTI_CONTEXT *pTctiCtx = NULL;
    ESYS_CONTEXT *ctx = NULL;
    ESYS_TR primaryHandle = ESYS_TR_NONE;
    ESYS_TR objectHandleOut = ESYS_TR_NONE;
    TSS2_RC ret;
    const char *loc = "";
    const char *errStr = "";
    
    // Init TPM resources
    if ((ret = _tpm_init_resources(&pTctiCtx, &ctx, &primaryHandle, &loc, &errStr)) != TSS2_RC_SUCCESS) {
        return _CLEANUP_CREATE_SECRET_TPM(ret, loc, errStr);
    }
   
    // Create and load sealing key
    if ((ret = _create_and_load_key_tpm(correlationId, ctx, primaryHandle, &objectHandleOut, randBytesSecret)) != TSS2_RC_SUCCESS) {
        return _CLEANUP_CREATE_SECRET_TPM(ret, "_create_and_load_key_tpm", "Error loading or sealing the key");
    }
   
    // Storing the object within a persistent handle
    if ((ret = _evict_control_tpm(correlationId, ctx, primaryHandle, objectHandleOut, persistHandle)) != TSS2_RC_SUCCESS) {
        return _CLEANUP_CREATE_SECRET_TPM(ret, "_evict_control_tpm", "Error unsealing data:");
    }

    return _CLEANUP_CREATE_SECRET_TPM(TSS2_RC_SUCCESS, NULL, NULL);
}


static TSS2_RC _cleanup_load_tpm_secret(
    const uuid_t correlationId,
    TSS2_RC ret,
    const char *loc,
    const char *message,
    TSS2_TCTI_CONTEXT *pTctiCtx,
    ESYS_CONTEXT *ctx,
    ESYS_TR primaryHandle,
    ESYS_TR evictObjectHandleOut,
    TPM2B_SENSITIVE_DATA *outData) 
{
    if (ret != TSS2_RC_SUCCESS)
        _print_tpm_error(correlationId, ret, loc, message);

    if (ctx != NULL) {
        Esys_FlushContext(ctx, primaryHandle);
        Esys_Finalize(&ctx);
    }

    if (pTctiCtx != NULL) {
        Tss2_TctiLdr_Finalize(&pTctiCtx);
    }
    Esys_Free(outData);

    return ret;
}

#define _CLEANUP_LOAD_TPM_SECRET(ret, loc, message) \
        _cleanup_load_tpm_secret(correlationId, ret, loc, message, pTctiCtx, ctx, primaryHandle, evictObjectHandleOut, outData)

static TSS2_RC _load_secret_from_tpm(
    const uuid_t correlationId,
    TPMI_DH_PERSISTENT persistHandle)
{
    TSS2_RC ret;
    ESYS_CONTEXT *ctx = NULL;
    ESYS_TR primaryHandle = ESYS_TR_NONE;
    ESYS_TR evictObjectHandleOut = ESYS_TR_NONE;
    TPM2B_SENSITIVE_DATA *outData = NULL;
    TSS2_TCTI_CONTEXT *pTctiCtx = NULL;

    const char *loc = "";
    const char *errStr = "";
    
    // Init TPM resources
    if ((ret = _tpm_init_resources(&pTctiCtx, &ctx, &primaryHandle, &loc, &errStr)) != TSS2_RC_SUCCESS) {
        return _CLEANUP_LOAD_TPM_SECRET(ret, loc, errStr);
    }

    //  Getting the object handle out of the persistent area
    if ((ret = Esys_TR_FromTPMPublic(
                ctx,
                persistHandle,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &evictObjectHandleOut)) != TSS2_RC_SUCCESS) {
        return _CLEANUP_LOAD_TPM_SECRET(ret, "Esys_TR_FromTPMPublic", "Error getting handle from public:");
    }

    // Unseal data using the sealing key
    if ((ret = Esys_Unseal(
                ctx,
                evictObjectHandleOut,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &outData)) != TSS2_RC_SUCCESS) {
        return _CLEANUP_LOAD_TPM_SECRET(ret, "Esys_Unseal", "Error unsealing data");
    }

    // Copy the unsealed data to the KEYISO_pfxSecret 
    if (outData->size <= sizeof(KEYISO_pfxSecret)) {
        memcpy(KEYISO_pfxSecret, outData->buffer, outData->size);
    }
    else {
        return _CLEANUP_LOAD_TPM_SECRET(TSS2_TCTI_RC_INSUFFICIENT_BUFFER, "_load_pfx_secret_from_tpm", "Unsealed data is too large:");
    }

    return _CLEANUP_LOAD_TPM_SECRET(TSS2_RC_SUCCESS, NULL, NULL); 
}

static int _read_tpm_secret_file(
    const uuid_t correlationId,
    const char* filename)
{
    const char *title = KEYISOP_TPM_SECRET_TITLE;
    FILE *in = NULL;
    int ret = STATUS_FAILED;
    TPMI_DH_PERSISTENT persistHandle;

    in = fopen(filename, "rb");
    if (in  == NULL) {
        if (errno != ENOENT) {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "fopen", "Failed to open file", "filename: %s errno:%d", filename, errno);
        }
        return ret;
    }
    
    // Loading the machine secret from TPM   
    if (fread(&persistHandle, sizeof(TPMI_DH_PERSISTENT), 1, in)) {
        if (_load_secret_from_tpm(correlationId, persistHandle) == TSS2_RC_SUCCESS) {
            ret = STATUS_OK;
        }
    }
    else {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "fread", "filename: %s", filename);
    }

    if (ret == STATUS_FAILED) {
        KEYISO_pfxSecret[0] = 0;
    }
    fclose(in);
    return ret;
}

static int _write_tpm_secret_file(
    const uuid_t correlationId,
    const char* filename)
{
    const char* title = KEYISOP_TPM_SECRET_TITLE;
    FILE *out = NULL;
    int ret = STATUS_FAILED;
    TPMI_DH_PERSISTENT persistHandle = TPM2_PERSISTENT_FIRST;
    unsigned char randBytes[KEYISO_SECRET_FILE_LENGTH];
    mode_t prevMask = 0;

    if (KeyIso_rand_bytes(randBytes, sizeof(randBytes)) != STATUS_OK) {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "KeyIso_rand_bytes", "filename: %s", filename);
        return ret;
    }

    // The machine secret should never start with "0" so in case that the random value start with it we set it.
    if (randBytes[0] == 0) {
        randBytes[0] = 1;
    }

    prevMask = umask(077); // Remove permissions for group/other

    out = fopen(filename, "wb");
    if (out == NULL) {
        umask(prevMask);
        KEYISOP_trace_log_error_para(correlationId, 0, title, "fopen", "Failed to open file", "filename: %s", filename);
        KeyIso_cleanse(randBytes, sizeof(randBytes));
        return ret;
    }

    umask(prevMask);

    // Encrypting and storing the machine secret in TPM
    if(_create_secret_in_tpm(correlationId, randBytes, &persistHandle) == TSS2_RC_SUCCESS) {
        // Write the TPMI_DH_PERSISTENT value to the file
        if (fwrite(&persistHandle, sizeof(TPMI_DH_PERSISTENT), 1, out)) {
            ret = STATUS_OK;
        }
        else {
            KEYISOP_trace_log_error_para(correlationId, 0, title, "fwrite", "filename: %s", filename);
        }         
    }

    fflush(out);
    fclose(out);
    KeyIso_cleanse(randBytes, sizeof(randBytes));
    return ret;
}

static int _create_tpm_secret(
    const uuid_t correlationId,
    const char *filename) {

    const char *title = KEYISOP_TPM_SECRET_TITLE;
    int ret = STATUS_FAILED;

    if ((ret = _read_tpm_secret_file(correlationId, filename)) == STATUS_OK) {
        KEYISOP_trace_log_para(correlationId, 0, title, "Using previously generated TPM secret", "secret: %s", filename);
        return STATUS_OK;
    }
    
    ret = _write_tpm_secret_file(correlationId, filename);
    if (ret == STATUS_OK) {
        ret = _read_tpm_secret_file(correlationId, filename);
        if (ret == STATUS_OK) {
            KEYISOP_trace_log_para(correlationId, 0, title, "Generated TPM secret", "secret: %s", filename);
            return STATUS_OK;
        }
    }
    
    KEYISOP_trace_log_error_para(correlationId, 0, title, "Create TPM secret", "Failed", "secret: %s", filename);
    return STATUS_FAILED;
}

static int _check_tpm_device() 
{
    DIR *d;
    struct dirent *dir;
    int tpmExists = 0;

    d = opendir(TPM_DEVICE_DIR);
    if (d) {
        while ((dir = readdir(d)) != NULL) {
        // Check if the directory entry name starts with "tpm"
            if (strncmp(dir->d_name, TPM_DEVICE_PREFIX, sizeof(TPM_DEVICE_PREFIX)-1) == 0) {
                closedir(d);
                return 1;
            }
        }
        closedir(d);
    }
    return tpmExists;
}
#endif //KMPP_GENERAL_PURPOSE_TARGET

int KeyIsoP_create_pfx_secret(
    const uuid_t correlationId) {

   char *filename = NULL;      // KeyIso_free()
   int ret = STATUS_FAILED;

   // Retrieve the secret
   filename = KeyIso_get_pfx_secret_filename();
   if (filename == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_PFX_SECRET_TITLE, "Failed to get PFX secret filename", "KeyIso_get_pfx_secret_filename returned NULL");
        return ret;
   }
   // Additional check to ensure 'filename' contains a valid file path that ends with null terminator
   if (strnlen(filename, PATH_MAX + 1) > PATH_MAX || strchr(filename, '%') != NULL) {
        KEYISOP_trace_log_error(correlationId, 0, KEYISOP_PFX_SECRET_TITLE, "Invalid filename", "Invalid filename");
        KeyIso_free(filename);
        return ret;
    }

#ifdef KMPP_GENERAL_PURPOSE_TARGET
   // Checking if TPM exists in the system
   if (1 == _check_tpm_device()) {
       KEYISOP_trace_log(correlationId, 0, KEYISOP_TPM_SECRET_TITLE, "TPM exists");
       ret = _create_tpm_secret(correlationId, filename);
    }    
    else
       ret = _create_pfx_secret(correlationId, filename);
#else
    ret = _create_pfx_secret(correlationId, filename);
#endif

    
    KeyIso_free(filename);
    return ret;
}