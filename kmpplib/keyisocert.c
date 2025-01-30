/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <ctype.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

#include "keyisolog.h"
#include "keyisoctrl.h"
#include "keyisocertinternal.h"

#include "keyisocert.h"
#include "keyisoutils.h"
#include "keyisomemory.h"

#include <glib.h>
G_LOCK_DEFINE_STATIC(KEYISO_certCtrlLock);
G_LOCK_DEFINE_STATIC(KEYISO_certCtrlDisallowedLock);

// OPENSSLDIR "/" "disallowed"
// KeyIso_free() returned directory name
static char *_get_disallowed_dir()
{
    const char *openSslDir = KeyIsoP_get_default_cert_area();
    size_t openSslDirLength = strlen(openSslDir);
    const char *subDir = "disallowed";
    size_t subDirLength = strlen(subDir);
    size_t disallowedDirLength = openSslDirLength + 1 + subDirLength + 1;
    char *disallowedDir = (char *) KeyIso_zalloc(disallowedDirLength);

    if (disallowedDir != NULL) {
        BIO_snprintf(disallowedDir, disallowedDirLength, "%s/%s",
            openSslDir, subDir);
    }

    return disallowedDir;
}

// For success, returns length of tbs. Otherwise, returns 0 for any error.
int KeyIsoP_X509_extract_tbs(
    int x509Length,
    const unsigned char *x509Bytes,
    const unsigned char **tbsBytes
    )
{
    int ret = 0;
    int inf = 0;
    int tag = 0;
    int class = 0;
    const unsigned char *cur = x509Bytes;
    long rem = (long) x509Length;
    const unsigned char *end = cur + rem;
    long len = 0;
    long hdrLen = 0;
    
    *tbsBytes = NULL;

    // Step into outer X509 SEQUENCE. cur is updated with the start of the SEQUENCE contents.
    inf = ASN1_get_object(
        &cur,
        &len, 
        &tag,
        &class,
        rem);
    if (inf != V_ASN1_CONSTRUCTED || tag != V_ASN1_SEQUENCE ||
            cur > end || len == 0 || 
            (rem = (long) (end - cur), len > rem)) {
        goto end;
    }

    *tbsBytes = cur;

    rem = len;
    end = cur + rem;
    // Step into the inner tbs SEQUENCE. cur is advanced past the tbs SEQUENCE tag/length header octets
    inf = ASN1_get_object(
        &cur,
        &len, 
        &tag,
        &class,
        rem);
    if (inf != V_ASN1_CONSTRUCTED || tag != V_ASN1_SEQUENCE ||
            cur > end || len == 0 ||
            (rem = (long) (end - cur), len > rem)) {
        goto end;
    }

    // total length is the tag/length bytes + the content length
    hdrLen = (long) (cur - *tbsBytes);
    ret = (int) (hdrLen + len);

end:
    return ret;
}
    

// returns -2 for error
int KeyIsoP_X509_tbs_cmp(
    const uuid_t correlationId,
    const char *title,
    X509 *a,
    X509 *b)
{
    int ret;
    int aX509Len = 0;
    unsigned char *aX509Bytes = NULL;   // OPENSSL_free()
    int aTbsLen = 0;
    const unsigned char *aTbsBytes = NULL;

    int bX509Len = 0;
    unsigned char *bX509Bytes = NULL;   // OPENSSL_free()
    int bTbsLen = 0;
    const unsigned char *bTbsBytes = NULL;

    ERR_clear_error();

    aX509Len = i2d_X509(a, &aX509Bytes);
    bX509Len = i2d_X509(b, &bX509Bytes);

    if (aX509Len <= 0 || bX509Len <= 0) {
        KEYISOP_trace_log_openssl_error(correlationId, 0, title, "i2d_X509");
        ret = -2;
        goto end;
    }

    aTbsLen = KeyIsoP_X509_extract_tbs(aX509Len, aX509Bytes, &aTbsBytes);
    bTbsLen = KeyIsoP_X509_extract_tbs(bX509Len, bX509Bytes, &bTbsBytes);

    if (aTbsLen <= 0 || bTbsLen <= 0) {
        KEYISOP_trace_log_openssl_error(correlationId, 0, title, "KeyIsoP_X509_extract_tbs");
        ret = -2;
        goto end;
    }

    ret = aTbsLen - bTbsLen;

    if (ret == 0 && aTbsLen != 0) {
        ret = memcmp(aTbsBytes, bTbsBytes, aTbsLen);
    }

    if (ret < 0) {
        ret = -1;
    }

end:
    OPENSSL_free(aX509Bytes);
    OPENSSL_free(bX509Bytes);

    return ret;
}


#define KEYISOP_MAX_FILENAME_HASH_LENGTH      16
#define KEYISOP_MAX_FILENAME_HEX_HASH_LENGTH  (KEYISOP_MAX_FILENAME_HASH_LENGTH * 2 + 1)

static void _X509_NAME_filename_hex_hash(
    X509_NAME *x,
    char *hexHash)
{
    unsigned long nameHash = X509_NAME_hash(x);
    BIO_snprintf(hexHash, KEYISOP_MAX_FILENAME_HEX_HASH_LENGTH, "%08lx", nameHash);
}

static int _X509_tbs_filename_hex_hash(
    const uuid_t correlationId,
    const char *title,
    X509 *x,
    char *hexHash)
{
    const char *loc = "";
    int ret = 0;
    unsigned char md[SHA256_DIGEST_LENGTH];
    int x509Len = 0;
    unsigned char *x509Bytes = NULL;    // OPENSSL_free()
    int tbsLen = 0;
    const unsigned char *tbsBytes = NULL;
    int fileHashLen;

    ERR_clear_error();

    x509Len = i2d_X509(x, &x509Bytes);
    if (x509Len <= 0) {
        loc = "i2d_X509";
        goto openSslErr;
    }
    tbsLen = KeyIsoP_X509_extract_tbs(x509Len, x509Bytes, &tbsBytes);
    if (tbsLen <= 0) {
        loc = "KeyIsoP_X509_extract_tbs";
        goto openSslErr;
    }

    if (!EVP_Digest(tbsBytes, tbsLen, md, NULL, EVP_sha256(), NULL)) {
        loc = "EVP_Digest";
        goto openSslErr;
    }

    fileHashLen = sizeof(md);
    if (fileHashLen > KEYISOP_MAX_FILENAME_HASH_LENGTH) {
        fileHashLen = KEYISOP_MAX_FILENAME_HASH_LENGTH;
    }

    KeyIsoP_bytes_to_hex(
        fileHashLen,
        md,
        hexHash);
    ret = 1;

end:
    OPENSSL_free(x509Bytes);
    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

static void _X509_sha1_hex_hash(
    X509 *x,
    char *hexHash)
{
    unsigned char md[SHA_DIGEST_LENGTH];

    X509_digest(x, EVP_sha1(), md, NULL);
    KeyIsoP_bytes_to_hex(
        sizeof(md),
        md,
        hexHash);
}

static int _rename_file(
    const uuid_t correlationId,
    const char *title,
    const char *oldFilename,
    const char *newFilename)
{
    int ret = 0;

    // This will fail on windows. Need to remove first
    if (rename(oldFilename, newFilename) == 0) {
        KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Rename",
            "old: %s new: %s", oldFilename, newFilename);
        ret = 1;
    } else {
        int err = errno;
        KEYISOP_trace_log_errno_para(correlationId, 0, title, "Rename", err,
            "old: %s new: %s", oldFilename, newFilename);

        if (err == EEXIST || err == EACCES) {
            if (remove(newFilename) == 0) {
                if (rename(oldFilename, newFilename) == 0) {
                    KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "RenameAfterRemove",
                        "old: %s new: %s", oldFilename, newFilename);
                    ret = 1;
                } else {
                    err = errno;
                    KEYISOP_trace_log_errno_para(correlationId, 0, title, "RenameAfterRemove", err,
                        "old: %s new: %s", oldFilename, newFilename);
                }
            } else {
                err = errno;
                KEYISOP_trace_log_errno_para(correlationId, 0, title, "Remove", err,
                    "new: %s", newFilename);
            }
        }
    }

    return ret;
}

#define KEYISOP_MAX_FILE_SEQ_INDEX    1024

static int _cert_remove(
    const uuid_t correlationId,
    const char *title,
    int removeIndex,
    int isRoot,
    const char *dirName,
    const char *sha1HexHash,
    const char *filenameHexHash,
    int filenameLength,
    const char *removeFilename)
{
    int ret = 0;
    int renameIndex = 0;
    char *renameFilename = NULL;  //  KeyIso_free()

    renameFilename = (char *) KeyIso_zalloc(filenameLength);
    if (renameFilename == NULL) {
        goto end;
    }

    // Find the last entry after the entry being removed
    for (int i = removeIndex + 1; i <= KEYISOP_MAX_FILE_SEQ_INDEX; i++) {
        BIO *in = NULL;
        X509 *fileCert = NULL;
        BIO_snprintf(renameFilename, filenameLength, "%s/%s.%d",
            dirName, filenameHexHash, i);

        in = BIO_new_file(renameFilename, "r");
        if (in == NULL) {
            break;
        }

        fileCert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
        BIO_free(in);
        if (fileCert == NULL) {
            KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, "PEM_read_bio_X509_AUX",
                "filename: %s", renameFilename);
            break;
        }

        X509_free(fileCert);
        renameIndex = i;
        KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "AfterRemove",
            "filename: %s", renameFilename);
    }

    if (renameIndex == 0) {
        if (remove(removeFilename) == 0) {
            KEYISOP_trace_log_para(
                correlationId,
                isRoot ? 0 : KEYISOP_TRACELOG_VERBOSE_FLAG,
                title,
                isRoot ? "RemoveRoot" : "Remove",
                "sha1: %s filename: %s", sha1HexHash, removeFilename);
            ret = 1;
        } else {
            int err = errno;
            KEYISOP_trace_log_errno_para(correlationId, 0, title, "Remove", err,
                "sha1: %s filename: %s", sha1HexHash, removeFilename);
        }
    } else {
        KEYISOP_trace_log_para(
            correlationId,
            isRoot ? 0 : KEYISOP_TRACELOG_VERBOSE_FLAG,
            title,
            isRoot ? "RemoveRoot" : "Remove",
            "sha1: %s filename: %s", sha1HexHash, removeFilename);
        BIO_snprintf(renameFilename, filenameLength, "%s/%s.%d",
            dirName, filenameHexHash, renameIndex);
        ret = _rename_file(correlationId, title, renameFilename, removeFilename);
    }

end:
    KeyIso_free(renameFilename);
    return ret;
}

static int _is_identical_root(
    const uuid_t correlationId,
    const char *title,
    X509 *cert,
    X509 *fileCert)
{
    const char *loc = "";
    int ret = 0;
    BIO *mem = BIO_new(BIO_s_mem());
    BIO *fileMem = BIO_new(BIO_s_mem());
    int memLen = 0;
    const unsigned char *memBytes = NULL;
    int fileMemLen = 0;
    const unsigned char *fileMemBytes = NULL;

    if (mem == NULL || fileMem == NULL) {
        goto openSslErr; 
    }

    if (!PEM_write_bio_X509_AUX(mem, cert) || !PEM_write_bio_X509_AUX(fileMem, fileCert)) {
        loc = "PEM_write_bio_X509_AUX";
        goto openSslErr;
    }

    memLen = (int) BIO_get_mem_data(mem, (char **) &memBytes);
    fileMemLen = (int) BIO_get_mem_data(fileMem, (char **) &fileMemBytes);

    if (memLen == 0 || memLen != fileMemLen || memcmp(memBytes, fileMemBytes, memLen) != 0) {
        KEYISOP_trace_log(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "DifferentNewRootBytes");
        goto end;
    }

    ret = 1;
end:
    BIO_free(mem);
    BIO_free(fileMem);

    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}
const char *KeyIsoP_get_cert_ctrl_title(
    int ctrl,
    int location)
{
    const char *title = "???";
    switch (ctrl) {
        case KEYISO_CERT_CTRL_IMPORT:
            if (location == KEYISO_CERT_LOCATION_ROOT) {
                title = KEYISOP_IMPORT_TRUSTED_TITLE;
            } else if (location == KEYISO_CERT_LOCATION_DISALLOWED) {
                title = KEYISOP_IMPORT_DISALLOWED_TITLE;
            }
            break;
        case KEYISO_CERT_CTRL_REMOVE:
            if (location == KEYISO_CERT_LOCATION_ROOT) {
                title = KEYISOP_REMOVE_TRUSTED_TITLE;
            } else if (location == KEYISO_CERT_LOCATION_DISALLOWED) {
                title = KEYISOP_REMOVE_DISALLOWED_TITLE;
            }
            break;
        case KEYISO_CERT_CTRL_ENUM:
            if (location == KEYISO_CERT_LOCATION_ROOT) {
                title = KEYISOP_ENUM_TRUSTED_TITLE;
            } else if (location == KEYISO_CERT_LOCATION_DISALLOWED) {
                title = KEYISOP_ENUM_DISALLOWED_TITLE;
            }
            break;
        case KEYISO_CERT_CTRL_FIND:
            if (location == KEYISO_CERT_LOCATION_ROOT) {
                title = KEYISOP_IS_TRUSTED_TITLE;
            } else if (location == KEYISO_CERT_LOCATION_DISALLOWED) {
                title = KEYISOP_IS_DISALLOWED_TITLE;
            }
            break;
    }

    return title;
}

static int _cert_ctrl(
    const uuid_t correlationId,
    int ctrl,
    int location,
    X509 *cert)
{
    const char *title = KeyIsoP_get_cert_ctrl_title(ctrl, location);
    const char *loc = "";
    int ret = 0;
    int isRoot = 0;
    char filenameHexHash[KEYISOP_MAX_FILENAME_HEX_HASH_LENGTH];
    char sha1HexHash[SHA_DIGEST_LENGTH * 2 + 1];
    const char *dirName = NULL;                 // Don't free
    char *disallowedDirName = NULL;             // KeyIso_free()
    int filenameLength = 0;
    char *filename = NULL;                      // KeyIso_free()
    int tmpFilenameLength = 0;
    char *tmpFilename = NULL;                   // KeyIso_free()
    char *outFilename = NULL;                   // Don't free
    int i = 0;
    int cmpResult = -1;
    BIO *out = NULL;
    X509 *fileCert = NULL;
    
    _X509_sha1_hex_hash(cert, sha1HexHash);

    if (location == KEYISO_CERT_LOCATION_ROOT && ctrl != KEYISO_CERT_CTRL_FIND) {
        // Check if self-issued root certificate
        if (X509_NAME_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert)) == 0) {
            isRoot = 1;
        }
    }

    if (location == KEYISO_CERT_LOCATION_DISALLOWED) {
        if (!_X509_tbs_filename_hex_hash(correlationId, title, cert, filenameHexHash)) {
            goto end;
        }
        disallowedDirName = _get_disallowed_dir();
        if (disallowedDirName == NULL) {
            loc = "_get_disallowed_dir";
            goto openSslErr;
        }
        dirName = disallowedDirName;
    } else {
        // Certificates are identified via their subject name hash
        _X509_NAME_filename_hex_hash(X509_get_subject_name(cert), filenameHexHash);

        // Certificates are stored in the following directory
        dirName = KeyIsoP_get_default_cert_dir();
    }

    // Here is an example certificate filename
    // "C:\Program Files\Common Files\SSL/certs/c4c48f78.0"

    // "C:\Program Files\Common Files\SSL/certs "/" "c4c48f78" "." "012345" "\0"
    //                                           0   01234567   0   012345   0

    filenameLength = (int) strlen(dirName) + 1 + (int) strlen(filenameHexHash) + 1 + 6 + 1;
    filename = (char *) KeyIso_zalloc(filenameLength);
    if (filename == NULL) {
        goto end;
    }

    for (i = 0; i <= KEYISOP_MAX_FILE_SEQ_INDEX; i++) {
        BIO *in = NULL;
        BIO_snprintf(filename, filenameLength, "%s/%s.%d",
            dirName, filenameHexHash, i);

        in = BIO_new_file(filename, "r");
        if (in == NULL) {
            if (ERR_GET_REASON(ERR_peek_last_error()) != BIO_R_NO_SUCH_FILE) {
                KEYISOP_trace_log_openssl_error_para(correlationId,
                    KEYISOP_TRACELOG_WARNING_FLAG, title, "BIO_new_file",
                    "sha1: %s filename: %s", sha1HexHash, filename);
            }
            break;
        }

        X509_free(fileCert);
        fileCert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
        BIO_free(in);
        if (fileCert == NULL) {
            KEYISOP_trace_log_openssl_error_para(correlationId, 
                KEYISOP_TRACELOG_WARNING_FLAG, title, "PEM_read_bio_X509_AUX",
                "sha1: %s filename: %s", sha1HexHash, filename);
            break;
        }

        if (ctrl == KEYISO_CERT_CTRL_FIND &&
                location == KEYISO_CERT_LOCATION_DISALLOWED) {
            cmpResult = KeyIsoP_X509_tbs_cmp(correlationId, title, cert, fileCert);
        } else {
            cmpResult = X509_cmp(cert, fileCert);
        }

        if (cmpResult == 0) {
            break;
        }

        KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "FilenameHashCollision",
            "sha1: %s filename: %s", sha1HexHash, filename);
    }

    if (i > KEYISOP_MAX_FILE_SEQ_INDEX) {
        KEYISOP_trace_log_error(correlationId, 0, title, "IndexCount", "Exceeded file count with same hash");
        goto end;
    }

    if (ctrl == KEYISO_CERT_CTRL_FIND) {
        if (cmpResult == 0) {
            ret = 1;
        }
        goto end;
    } else if (ctrl == KEYISO_CERT_CTRL_REMOVE) {
        if (cmpResult != 0) {
            KEYISOP_trace_log_error_para(correlationId,
                KEYISOP_TRACELOG_VERBOSE_FLAG | KEYISOP_TRACELOG_WARNING_FLAG,
                title, "Remove", "Certificate already removed",
                "sha1: %s filenameHexHash: %s", sha1HexHash, filenameHexHash);
            ret = 1;
            goto end;
        }

        ret = _cert_remove(
                    correlationId,
                    title,
                    i,
                    isRoot,
                    dirName,
                    sha1HexHash,
                    filenameHexHash,
                    filenameLength,
                    filename);
        goto end;
    }

    if (cmpResult == 0) {
        if (isRoot) {
            if (_is_identical_root(correlationId, title, cert, fileCert)) {
                KEYISOP_trace_log_error_para(correlationId,
                    KEYISOP_TRACELOG_VERBOSE_FLAG | KEYISOP_TRACELOG_WARNING_FLAG,
                    title, "ImportRoot", "Already exists",
                    "sha1: %s filename: %s", sha1HexHash, filename);
                ret = 1;
                goto end;
            }
        } else {
            KEYISOP_trace_log_error_para(correlationId,
                KEYISOP_TRACELOG_VERBOSE_FLAG | KEYISOP_TRACELOG_WARNING_FLAG,
                title, "Import", "Already exists",
                "sha1: %s filename: %s", sha1HexHash, filename);
            ret = 1;
            goto end;
        }

        // filename + ".tmp"
        //             0123
        tmpFilenameLength = filenameLength + 4;
        tmpFilename = (char *) KeyIso_zalloc(tmpFilenameLength);
        if (tmpFilename == NULL) {
            goto openSslErr;
        }

        BIO_snprintf(tmpFilename, tmpFilenameLength, "%s.tmp", filename);
        outFilename = tmpFilename;
        KEYISOP_trace_log_para(correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "TempUpdate",
            "filename: %s", tmpFilename);
    } else {
        outFilename = filename;
    }

    out = BIO_new_file(outFilename, "w");
    if (out == NULL) {
        KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, "BIO_new_file",
            "sha1: %s filename: %s", sha1HexHash, outFilename);
        goto end;
    }

    if (isRoot) {
        ret = PEM_write_bio_X509_AUX(out, cert);
    } else {
        ret = PEM_write_bio_X509(out, cert);
    }

    if (ret) {
        KEYISOP_trace_log_para(correlationId, isRoot ? 0 : KEYISOP_TRACELOG_VERBOSE_FLAG,
            title, isRoot ? "ImportRoot" : "PEM_write_bio_X509",
            "sha1: %s filename: %s", sha1HexHash, outFilename);
    } else {
        KEYISOP_trace_log_openssl_error_para(correlationId, 0,
            title, isRoot ? "ImportRoot" : "PEM_write_bio_X509",
            "sha1: %s filename: %s", sha1HexHash, outFilename);
        goto end;
    }

    BIO_flush(out);

    if (tmpFilename) {
        BIO_free(out);  // To ensure the file is closed before rename.
        out = NULL;

        ret = _rename_file(correlationId, title, tmpFilename, filename);
    }

end:
    X509_free(fileCert);
    KeyIso_free(disallowedDirName);
    KeyIso_free(filename);
    KeyIso_free(tmpFilename);
    BIO_free(out);
    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

static int _der_cert_ctrl(
    const uuid_t correlationId,
    int ctrl,
    int location,
    int length,
    const unsigned char *bytes)
{
    const char *title = KeyIsoP_get_cert_ctrl_title(ctrl, location);
    int ret = 0;
    X509 *cert = d2i_X509(NULL, &bytes, length);

    if (cert == NULL) {
        KEYISOP_trace_log_openssl_error(correlationId, 0, title, "d2i_X509");
        goto end;
    }

    ret = _cert_ctrl(
        correlationId,
        ctrl,
        location,
        cert);

end:
    X509_free(cert);
    return ret;
}

// From onecore\ds\security\cryptoapi\pki\certstor\newstor.cpp

//+-------------------------------------------------------------------------
//  Store file definitions
//
//  The file consist of the FILE_HDR followed by 1 or more FILE_ELEMENTs.
//  Each FILE_ELEMENT has a FILE_ELEMENT_HDR + its value.
//
//  First the CERT elements are written. If a CERT has any properties, then,
//  the PROP elements immediately precede the CERT's element. Next the CRL
//  elements are written. If a CRL has any properties, then, the PROP elements
//  immediately precede the CRL's element. Likewise for CTL elements and its
//  properties. Finally, the END element is written.
//--------------------------------------------------------------------------
typedef struct _FILE_HDR {
    unsigned int               dwVersion;
    unsigned int               dwMagic;
} FILE_HDR, *PFILE_HDR;

#define CERT_FILE_VERSION_0             0
#define CERT_MAGIC ((unsigned int)'C'+((unsigned int)'E'<<8)+((unsigned int)'R'<<16)+((unsigned int)'T'<<24))

// The element's data follows the HDR
typedef struct _FILE_ELEMENT_HDR {
    unsigned int               dwEleType;
    unsigned int               dwEncodingType;
    unsigned int               dwLen;
} FILE_ELEMENT_HDR, *PFILE_ELEMENT_HDR;

#define FILE_ELEMENT_END_TYPE           0
// FILE_ELEMENT_PROP_TYPEs              !(0 | CERT | CRL | CTL | KEYID)
// Note CERT_KEY_CONTEXT_PROP_ID (and CERT_KEY_PROV_HANDLE_PROP_ID)
// isn't written
#define FILE_ELEMENT_CERT_TYPE          32
#define FILE_ELEMENT_CRL_TYPE           33
#define FILE_ELEMENT_CTL_TYPE           34
#define FILE_ELEMENT_KEYID_TYPE         35

//#define MAX_FILE_ELEMENT_DATA_LEN       (4096 * 16)
#define MAX_FILE_ELEMENT_DATA_LEN       0xFFFFFFFF

typedef struct _MEMINFO {
    const unsigned char     *p;
    int                     len;
    int                     offset;
} MEMINFO, *PMEMINFO;

static void _sst_mem_init(
    MEMINFO *memInfo,
    const unsigned char *p,
    int len)
{
    memset(memInfo, 0, sizeof(*memInfo));
    memInfo->p = p;
    memInfo->len = len;
}

static int _sst_mem_read(
    MEMINFO *memInfo,
    void *out,
    int len)
{
    int readCount = len;

    if (memInfo->offset + len > memInfo->len) {
        readCount = memInfo->len - memInfo->offset;
    }

    if (readCount > 0) {
        memcpy(out, memInfo->p + memInfo->offset, readCount);
        memInfo->offset += readCount;
    }

    return readCount;
}

static int _sst_mem_tell(
    MEMINFO *memInfo)
{
    return memInfo->offset;
}

static void _sst_mem_seek(
    MEMINFO *memInfo,
    int offset)
{
    if (offset < memInfo->len) {
        memInfo->offset = offset;
    } else {
        memInfo->offset = memInfo->len;
    }
}
    

// Returns:
//  +1 - BIO *in is pointing to the start of the next certificate.
//       *certOffset - start of certificate
//       *certLength - certificate length
//   0 - sst format error
//  -1 - no more certificates
static int _sst_next_cert(
    const uuid_t correlationId,
    const char *title,
    MEMINFO *memInfo,
    int sstLength,
    int *certOffset,
    int *certLength)
{
    const char *loc = "";
    int ret = 0;
    FILE_ELEMENT_HDR eleHdr;
    int hasProp = 0;

    *certOffset = 0;
    *certLength = 0;

    for (;;) {
        int offset;

        if (_sst_mem_read(memInfo, &eleHdr, sizeof(eleHdr)) != sizeof(eleHdr)) {
            loc = "ReadEleHdr";
            goto sstErr;
        }

        if (eleHdr.dwEleType == FILE_ELEMENT_END_TYPE) {
            if (hasProp) {
                loc = "PrematureEndError";
                goto sstErr;
            }

            ret = -1;
            goto end;
        }

        offset = _sst_mem_tell(memInfo);
        if (offset > sstLength ||
                (int) eleHdr.dwLen > sstLength ||
                offset + (int) eleHdr.dwLen > sstLength) {
            loc = "ExceedEleSizeError";
            goto sstErr;
        }

        switch (eleHdr.dwEleType) {
            case FILE_ELEMENT_CERT_TYPE:
                *certOffset = offset;
                *certLength = eleHdr.dwLen;
                ret = 1;
                goto end;

            case FILE_ELEMENT_CRL_TYPE:
            case FILE_ELEMENT_CTL_TYPE:
                hasProp = 0;
            default:
                hasProp = 1;
        }

        // Skip properties, CRL or CTL
        _sst_mem_seek(memInfo, offset + eleHdr.dwLen);
    }

end:
    return ret;

sstErr:
    KEYISOP_trace_log_error(correlationId, 0, title, loc, "Invalid SST format");
    goto end;
}

static int _sst_cert_ctrl(
    const uuid_t correlationId,
    int ctrl,
    int location,
    int sstLength,
    const unsigned char *sstBytes)
{
    const char *title = KeyIsoP_get_cert_ctrl_title(ctrl, location);
    const char *loc = "";
    int ret = 0;
    int successCount = 0;
    int failedCount = 0;
    MEMINFO memInfo;
    FILE_HDR fileHdr;

    _sst_mem_init(&memInfo, sstBytes, sstLength);

    if (_sst_mem_read(&memInfo, &fileHdr, sizeof(fileHdr)) != sizeof(fileHdr)) {
        loc = "ReadFileHdr";
        goto sstErr;
    }

    if (fileHdr.dwVersion != CERT_FILE_VERSION_0 ||
            fileHdr.dwMagic != CERT_MAGIC) {
        loc = "VerifyFileHdr";
        goto sstErr;
    }

    for (int i = 0; ; i++) {
        int nextRet = 0;
        int certOffset = 0;
        int certLength = 0;

        nextRet = _sst_next_cert(
            correlationId,
            title,
            &memInfo,
            sstLength,
            &certOffset,
            &certLength);
        if (nextRet <= 0) {
            if (nextRet == 0) {
                failedCount++;
            }
            goto end;
        }

        if (_der_cert_ctrl(
                correlationId,
                ctrl,
                location,
                certLength,
                sstBytes + certOffset)) {
            ret = 1;
            successCount++;
        } else { 
            KEYISOP_trace_log_error_para(correlationId, 0, title, "_der_cert_ctrl", "Not updated",
                "entry: %d", i);
            failedCount++;
        }

        _sst_mem_seek(&memInfo, certOffset + certLength);
    }

end:
    if (ret && failedCount) {
        ret = -1;
    }

    if (ret > 0) {
        KEYISOP_trace_log_para(correlationId, 0, title, "Complete",
            "updatedCount: %d", successCount);
    } else {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "Complete", ret < 0 ? "Partial updates" : "No updates",
            "updatedCount: %d failedCount: %d", successCount, failedCount);
    }
    return ret;

sstErr:
    KEYISOP_trace_log_error(correlationId, 0, title, loc, "Invalid SST format");
    goto end;
}

static int _pem_cert_ctrl(
    const uuid_t correlationId,
    int ctrl,
    int location,
    int length,
    const unsigned char *bytes)
{
    const char *title = KeyIsoP_get_cert_ctrl_title(ctrl, location);
    const char *loc = "";
    int ret = 0;
    int successCount = 0;
    int failedCount = 0;
    BIO *in = NULL;
    char *pemName = NULL;               // OPENSSL_free()
    char *pemHeader = NULL;             // OPENSSL_free()
    unsigned char *pemData = NULL;      // OPENSSL_free()
    X509 *cert = NULL;                  // X509_free()

    in = BIO_new_mem_buf(bytes, length);
    if (in == NULL) {
        goto openSslErr;
    }

    for (int i = 0;; i++) {
        long pemLen = 0;

        OPENSSL_free(pemName);
        pemName = NULL;
        OPENSSL_free(pemHeader);
        pemHeader = NULL;
        OPENSSL_free(pemData);
        pemData = NULL;
        X509_free(cert);
        cert = NULL;

        ERR_clear_error();
        if (!PEM_read_bio(in, &pemName, &pemHeader, &pemData, &pemLen)) {
            unsigned long err = ERR_peek_last_error();

            if (ERR_GET_LIB(err) == ERR_LIB_PEM && ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
                break;
            }

            failedCount++;
            loc = "PEM_read_bio";
            goto openSslErr;
        }

        if (strcmp(pemName, PEM_STRING_X509) == 0 ||
                strcmp(pemName, PEM_STRING_X509_TRUSTED) == 0 ||
                strcmp(pemName, PEM_STRING_X509_OLD) == 0) {
            const unsigned char *data = pemData;

            cert = d2i_X509_AUX(NULL, &data, pemLen);
            if (cert == NULL) {
                data = pemData;
                cert = d2i_X509(NULL, &data, pemLen);
            }
        }

        if (cert == NULL) {
            KEYISOP_trace_log_error_para(correlationId, KEYISOP_TRACELOG_WARNING_FLAG,
                title, "IsCertPEM", "Not a certificate",
                "entry: %d name: %s", i, pemName);
            continue;
        }

        if (_cert_ctrl(
                correlationId,
                ctrl,
                location,
                cert)) {
            ret = 1;
            successCount++;
        } else { 
            KEYISOP_trace_log_error_para(correlationId, 0, title, "_cert_ctrl", "Not updated",
                "entry: %d name: %s", i, pemName);
            failedCount++;
        }
    }

end:
    OPENSSL_free(pemName);
    OPENSSL_free(pemHeader);
    OPENSSL_free(pemData);
    X509_free(cert);
    BIO_free(in);

    if (ret && failedCount) {
        ret = -1;
    }

    if (ret > 0) {
        KEYISOP_trace_log_para(correlationId, 0, title, "Complete",
            "updatedCount: %d", successCount);
    } else {
        KEYISOP_trace_log_error_para(correlationId, 0, title, "Complete", ret < 0 ? "Partial updates" : "No updates",
            "updatedCount: %d failedCount: %d", successCount, failedCount);
    }

    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

int KeyIso_SERVER_cert_ctrl(
    const uuid_t correlationId,
    int ctrl,
    int location,
    int format,
    int length,
    const unsigned char *bytes)
{
    const char *title = KeyIsoP_get_cert_ctrl_title(ctrl, location);
    int ret = 0;

    ERR_clear_error();

    // Only one thread at a time can update the certificate directories
    if (location == KEYISO_CERT_LOCATION_DISALLOWED) {
        // Separate lock for disallowed. Don't want to block adding roots
        G_LOCK(KEYISO_certCtrlDisallowedLock);
    } else {
        G_LOCK(KEYISO_certCtrlLock);
    }

    switch (format) {
        case KEYISO_CERT_FORMAT_DER:
            ret = _der_cert_ctrl(
                correlationId,
                ctrl,
                location,
                length,
                bytes);
            break;

        case KEYISO_CERT_FORMAT_PEM:
            ret = _pem_cert_ctrl(
                correlationId,
                ctrl,
                location,
                length,
                bytes);
            break;

        case KEYISO_CERT_FORMAT_SST:
            ret = _sst_cert_ctrl(
                correlationId,
                ctrl,
                location,
                length,
                bytes);
            break;

        default:
            KEYISOP_trace_log_error(correlationId, 0, title, "Format", "Not supported");
    }

    if (location == KEYISO_CERT_LOCATION_DISALLOWED) {
        G_UNLOCK(KEYISO_certCtrlDisallowedLock);
    } else {
        G_UNLOCK(KEYISO_certCtrlLock);
    }

    return ret;
}


static int _read_is_installed_file(
    const uuid_t correlationId,
    const char *filename)
{
    const char *title = KEYISOP_IMPORT_TRUSTED_TITLE;
    const char *loc = "";
    int ret = 0;
    BIO *in = NULL;
    unsigned char buf[1];

    ERR_clear_error();

    in = BIO_new_file(filename, "rb");
    if (in == NULL) {
        if (ERR_GET_REASON(ERR_peek_last_error()) != BIO_R_NO_SUCH_FILE) {
            loc = "BIO_new_file";
            goto openSslErr;
        }
        goto end;
    }

    if (BIO_read(in, buf, sizeof(buf)) != sizeof(buf)) {
        loc = "BIO_read";
        goto openSslErr;
    }

    if (buf[0] == 0) {
        loc = "Invalid Content";
        goto openSslErr;
    }

    ret = 1;

end:
    BIO_free(in);
    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, loc,
        "filename: %s", filename);
    goto end;
}

static int _write_is_installed_file(
    const uuid_t correlationId,
    const char *filename)
{
    const char *title = KEYISOP_IMPORT_TRUSTED_TITLE;
    const char *loc = "";
    int ret = 0;
    BIO *out = NULL;
    unsigned char buf[1] = { 1 };

    ERR_clear_error();

    out = BIO_new_file(filename, "wb");
    if (out == NULL) {
        loc = "BIO_new_file";
        goto openSslErr;
    }

    if (BIO_write(out, buf, sizeof(buf)) != sizeof(buf)) {
        loc = "BIO_write";
        goto openSslErr;
    }
    BIO_flush(out);

    ret = 1;

end:
    BIO_free(out);
    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, loc,
        "filename: %s", filename);
    goto end;
}

static int _write_version_file(
    const uuid_t correlationId,
    const char *filename)
{
    const char *title = KEYISOP_READ_WRITE_VERSION_TITLE;
    const char *loc = "";
    int ret = 0;
    BIO *out = NULL;
    unsigned char version[1] = { KEYISOP_CURRENT_VERSION + '0'};

    ERR_clear_error();

    out = BIO_new_file(filename, "wb");
    if (out == NULL) {
        loc = "BIO_new_file";
        goto openSslErr;
    }

    if (BIO_write(out, version, sizeof(version)) != sizeof(version)) {
        loc = "BIO_write";
        goto openSslErr;
    }
    BIO_flush(out);

    ret = 1;

end:
    BIO_free(out);
    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, loc,
        "filename: %s", filename);
    goto end;
}

#define KEYISOP_INSTALL_CERTS_FILENAME             "certs.pem"
#define KEYISOP_INSTALL_VERSION_FILENAME           "certs.version"
#define KEYISOP_IMAGE_CERTS_INSTALLED_FILENAME     "imagecerts.installed"

// KEYISO_free() returned filename
static char *_get_installed_version_filename(
    const uuid_t correlationId)
{
    const char *title = KEYISOP_IMPORT_TRUSTED_TITLE;
    const char *loc = "";
    char *installedVersionFilename = NULL;
    char *versionPath = NULL;     // KeyIso_free()
    BIO *in = NULL;
    char versionFilename[128];
    int inl = 0;

    versionPath = KeyIsoP_get_path_name(
        KeyIsoP_get_install_image_dir(),
        KEYISOP_INSTALL_VERSION_FILENAME);
    if (versionPath == NULL) {
        goto end;
    }

    ERR_clear_error();

    in = BIO_new_file(versionPath, "rb");
    if (in == NULL) {
        loc = "BIO_new_file";
        goto openSslErr;
    }

    inl = BIO_read(in, versionFilename, sizeof(versionFilename) - 1);
    if (inl <= 0 || inl >= sizeof(versionFilename)) {
        loc = "BIO_read";
        goto openSslErr;
    }

    versionFilename[inl] = '\0';
    for (int i = 0; i < inl; i++) {
        char c = versionFilename[i];
        if (c == '\r' || c == '\n' || c == ' ') {
            versionFilename[i] = '\0';
            break;
        }
    }

    if (versionFilename[0] == '\0') {
        loc = "NoContent";
        goto openSslErr;
    }

    installedVersionFilename = KeyIso_strndup(versionFilename, KEYISO_MAX_FILE_NAME);

end:
    BIO_free(in);
    KeyIso_free(versionPath);

    return installedVersionFilename;

openSslErr:
    KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, loc,
        "filename: %s", versionPath);
    goto end;
}

int KeyIsoP_install_image_certs(
    const uuid_t correlationId)
{
    const char *title = KEYISOP_IMPORT_TRUSTED_TITLE;
    const char *loc = "";
    int ret = 0;
    const char *installedFilename = KEYISOP_IMAGE_CERTS_INSTALLED_FILENAME;
    char *installedVersionFilename = NULL;    // KeyIso_free()
    char *installedPath = NULL; // KeyIso_free()
    char *certsPath = NULL;     // KeyIso_free()
    BIO *in = NULL;
    BIO *mem = NULL;
    int inLength;
    unsigned char *inBytes;       // Don't free

    installedVersionFilename = _get_installed_version_filename(correlationId);
    if (installedVersionFilename != NULL) {
        installedFilename = installedVersionFilename;
    }

    installedPath = KeyIsoP_get_path_name(
        KeyIsoP_get_default_cert_dir(),
        installedFilename);
    if (installedPath == NULL) {
        goto end;
    }

    if (_read_is_installed_file(correlationId, installedPath)) {
        KEYISOP_trace_log_para(correlationId, 0, title, "Certificates already installed",
            "installed: %s", installedPath);
        goto success;
    }

    certsPath = KeyIsoP_get_path_name(
        KeyIsoP_get_install_image_dir(),
        KEYISOP_INSTALL_CERTS_FILENAME);
    if (certsPath == NULL) {
        goto end;
    }

    ERR_clear_error();

    in = BIO_new_file(certsPath, "rb");
    if (in == NULL) {
        loc = "BIO_new_file";
        goto openSslErr;
    }

    mem = BIO_new(BIO_s_mem());
    if (mem == NULL) {
        loc = "BIO_new";
        goto openSslErr;
    }

    for (;;) {
        char buff[512];
        int inl = BIO_read(in, buff, sizeof(buff));

        if (inl <= 0) 
            break;
        if (BIO_write(mem, buff, inl) != inl) {
            loc = "BIO_write";
            goto openSslErr;
        }
    }

    inLength = (int) BIO_get_mem_data(mem, (char **) &inBytes);

    if (KeyIso_SERVER_cert_ctrl(
            correlationId,
            KEYISO_CERT_CTRL_IMPORT,
            KEYISO_CERT_LOCATION_ROOT,
            KEYISO_CERT_FORMAT_PEM,
            inLength,
            inBytes) <= 0) {
        goto end;
    }

    if (!_write_is_installed_file(correlationId, installedPath)) {
        goto end;
    }

    KEYISOP_trace_log_para(correlationId, 0, title, "Certificates successfully installed",
         "certs: %s installed: %s", certsPath, installedPath);

success:
    ret = 1;

end:
    KeyIso_free(installedVersionFilename);
    KeyIso_free(installedPath);
    KeyIso_free(certsPath);
    BIO_free(in);
    BIO_free(mem);
    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error_para(correlationId, 0, title, loc,
        "filename: %s", certsPath);
    goto end;
}

int KeyIsoP_install_service_version(
    const uuid_t correlationId)
{
    const char *title = KEYISOP_SERVICE_TITLE;
    int ret = 0;
    unsigned int installedVersion = KEYISOP_INVALID_VERSION;
    const char *versionFilename = KEYISO_SERVICE_VERSION_FILENAME;
    char *installedPath = NULL; // KeyIso_free()

    installedPath = KeyIsoP_get_path_name(
        KeyIsoP_get_default_cert_dir(),
        versionFilename);
    if (installedPath == NULL) {
        goto end;
    }

    installedVersion = KeyIsoP_read_version_file(NULL, installedPath);
    if (installedVersion != KEYISOP_CURRENT_VERSION) {
        if (!_write_version_file(correlationId, installedPath)) {
            goto end;
        }
        installedVersion = KEYISOP_CURRENT_VERSION;
        KEYISOP_trace_log_para(correlationId, 0, title, "Version file has been successfully installed",
            "version: %u installedPath: %s", installedVersion, installedPath);
    } else {
        KEYISOP_trace_log_para(correlationId, 0, title, "Version file already installed",
            "version: %u installedPath: %s", installedVersion, installedPath);
    }

    ret = 1;

end:
    KeyIso_free(installedPath);
    return ret;
}

// Return:
//  1 - Certificate is disallowed.
//  0 - Certificate not found in the disallowed certificates directory.
int KeyIso_is_disallowed_cert(
    const uuid_t correlationId,
    X509 *cert)
{
    uuid_t randId;
    if (correlationId == NULL) {
        KeyIso_rand_bytes(randId, sizeof(randId));
        correlationId = randId;
    }

    return _cert_ctrl(
        correlationId,
        KEYISO_CERT_CTRL_FIND,
        KEYISO_CERT_LOCATION_DISALLOWED,
        cert);
}

typedef struct KeyIsoP_verify_cert_callback_ctx_st KEYISOP_VERIFY_CERT_CALLBACK_CTX;
struct KeyIsoP_verify_cert_callback_ctx_st {
    KEYISO_PFN_VERIFY_CERT_CALLBACK    callback;
    void                                *arg;
};

DEFINE_STACK_OF(KEYISOP_VERIFY_CERT_CALLBACK_CTX);

struct KeyIso_verify_cert_ctx_st {
    uuid_t                                      correlationId;
    STACK_OF(KEYISOP_VERIFY_CERT_CALLBACK_CTX) *callbackCtx;
    const X509_VERIFY_PARAM                     *param;
};


static void KEYISOP_VERIFY_CERT_CALLBACK_CTX_free(KEYISOP_VERIFY_CERT_CALLBACK_CTX *p) {
    KeyIso_free(p);
}


KEYISO_VERIFY_CERT_CTX *KeyIso_create_verify_cert_ctx(
    const uuid_t correlationId)
{
    KEYISO_VERIFY_CERT_CTX *ctx = NULL;

    ctx = (KEYISO_VERIFY_CERT_CTX *) KeyIso_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        goto end;
    }

    if (correlationId == NULL) {
        KeyIso_rand_bytes(ctx->correlationId, sizeof(ctx->correlationId));
    } else {
        memcpy(ctx->correlationId, correlationId, sizeof(ctx->correlationId));
    }

end:
    return ctx;
}

void KeyIsoP_get_verify_cert_ctx_correlationId(
    KEYISO_VERIFY_CERT_CTX *ctx,
    uuid_t correlationId)
{
    if (ctx) {
        memcpy(correlationId, ctx->correlationId, sizeof(ctx->correlationId));
    } else {
        memset(correlationId, 0, sizeof(ctx->correlationId));
    }
}

void KeyIso_free_verify_cert_ctx(
    KEYISO_VERIFY_CERT_CTX *ctx)
{
    if (ctx == NULL) {
        return;
    }

    sk_KEYISOP_VERIFY_CERT_CALLBACK_CTX_pop_free(
        ctx->callbackCtx,
        KEYISOP_VERIFY_CERT_CALLBACK_CTX_free);

    KeyIso_free(ctx);
}


int KeyIso_register_verify_cert_callback(
    KEYISO_VERIFY_CERT_CTX *ctx,
    KEYISO_PFN_VERIFY_CERT_CALLBACK callback,
    void *arg)
{
    const char *title = KEYISOP_VERIFY_CERT_TITLE;
    const char *loc = "";
    int ret = 0;
    KEYISOP_VERIFY_CERT_CALLBACK_CTX *callbackCtx = NULL;

    if (ctx->callbackCtx == NULL) {
        ctx->callbackCtx = sk_KEYISOP_VERIFY_CERT_CALLBACK_CTX_new_null();
        if (ctx->callbackCtx == NULL) {
            loc = "CALLBACK_CTX_new";
            goto openSslErr;
        }
    }

    callbackCtx = (KEYISOP_VERIFY_CERT_CALLBACK_CTX *) KeyIso_zalloc(sizeof(*callbackCtx));
    if (callbackCtx == NULL) {
        goto end;
    }

    callbackCtx->callback = callback;
    callbackCtx->arg = arg;

    if (!sk_KEYISOP_VERIFY_CERT_CALLBACK_CTX_push(ctx->callbackCtx, callbackCtx)) {
        KeyIso_free(callbackCtx);
        loc = "CALLBACK_CTX_push";
        goto openSslErr;
    }

    ret = 1;
end:
    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error(ctx->correlationId, 0, title, loc);
    goto end;
}

void KeyIso_set_verify_cert_param(
    KEYISO_VERIFY_CERT_CTX *ctx,
    const X509_VERIFY_PARAM *param)
{
    ctx->param = param;
}

int KeyIso_validate_certificate(
    const uuid_t correlationId,
    int keyisoFlags,
    X509 *cert,
    STACK_OF(X509) *ca,             // Optional
    int *verifyChainError,
    STACK_OF(X509) **chain)         // Optional
{
    const char *title = KEYISOP_VERIFY_CERT_TITLE;
    int ret = 0;
    int buildPfxCaRet = 0;

    KEYISO_VERIFY_CERT_CTX *ctx = NULL;    // KeyIso_free_verify_cert_ctx()

    if (cert == NULL) {
        KEYISOP_trace_log_error(correlationId, 0, title, "After PKCS12 parsing", "No end certificate in PFX");
    } else {
        ctx = KeyIso_create_verify_cert_ctx(correlationId);
        if (ctx == NULL) {
            KEYISOP_trace_log_error(correlationId, 0, title, "creating verify ctx", "Failed");
        } else {
            buildPfxCaRet = KeyIso_verify_cert2(
            ctx,
            KEYISO_EXCLUDE_END_FLAG |
                KEYISO_IGNORE_DEPTH_ZERO_SELF_SIGNED_ERROR_FLAG |
                (keyisoFlags & KEYISO_EXCLUDE_EXTRA_CA_FLAG),
            cert,
            ca,
            verifyChainError,
            chain);

            ret = buildPfxCaRet;
        }
    }

    KeyIso_free_verify_cert_ctx(ctx);
    return ret;
}

static int _der_cert_load(
    const uuid_t correlationId,
    int certLength,
    const unsigned char *certBytes,
    X509 **cert)
{
    const char *title = KEYISOP_HELPER_CERT_TITLE;
    int ret = 0;

    *cert = d2i_X509(NULL, &certBytes, certLength);
    if (*cert == NULL) {
        KEYISOP_trace_log_openssl_error(correlationId, 0, title, "d2i_X509");
        goto end;
    }

    ret = 1;
end:
    return ret;
}

int KeyIso_load_pem_cert(
    const uuid_t correlationId,
    int certLength,
    const unsigned char *certBytes,
    EVP_PKEY **pkey,                    // Optional
    X509 **cert,
    STACK_OF(X509) **ca)
{
    const char *title = KEYISOP_HELPER_CERT_TITLE;
    const char *loc = "";
    int ret = 0;
    BIO *in = NULL;
    STACK_OF(X509_INFO) *certInfos = NULL;

    if (cert == NULL || ca == NULL) {
        KEYISOP_trace_log(correlationId, 0, title, "Missing output parameters");
        goto end;
    }

    *cert = NULL;
    *ca = sk_X509_new_null();
    if (*ca == NULL) {
        loc = "sk_X509_new";
        goto openSslErr;
    }

    in = BIO_new_mem_buf(certBytes, certLength);
    if (in == NULL) {
        loc = "new_mem_buf";
        goto openSslErr;
    }

    certInfos = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL);
    if (certInfos == NULL) {
        loc = "PEM_X509_INFO_read_bio";
        goto openSslErr;
    }

    for (int i = 0; i < sk_X509_INFO_num(certInfos); i++) {
        X509_INFO *certInfo = sk_X509_INFO_value(certInfos, i);
        if (certInfo->x509 != NULL) {
            if (*cert == NULL) {
                *cert = certInfo->x509;
            } else {
                if (!sk_X509_push(*ca, certInfo->x509)) {
                    loc = "sk_X509_push";
                    goto openSslErr;
                }
            }

            X509_up_ref(certInfo->x509);
        }
        // Decrypted PKCS1 private key is stored in dec_pkey
        if (certInfo->x_pkey != NULL && certInfo->x_pkey->dec_pkey != NULL) {  
            if (pkey != NULL && *pkey == NULL) {
                *pkey = certInfo->x_pkey->dec_pkey;
            } 
        }
    }

    if (!*cert) {
        KEYISOP_trace_log_error(correlationId, 0, title, loc, "No certificates in PEM");
        goto end;
    }

    ret = 1;

end:
    sk_X509_INFO_pop_free(certInfos, X509_INFO_free);
    BIO_free(in);

    if (!ret) {
        if (cert != NULL) {
            X509_free(*cert);
            *cert = NULL;
        }
        if (ca != NULL) {
            sk_X509_pop_free(*ca, X509_free);
            *ca = NULL;
        }
    }

    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

int KeyIso_load_pem_pubkey(
    const uuid_t correlationId,
    int certLength,
    const unsigned char *certBytes,
    EVP_PKEY **pkey,                    
    X509 **cert,
    STACK_OF(X509) **ca)
{
    const char *title = KEYISOP_HELPER_PFX_TITLE;
    int ret = 0;
    X509 *keyCert = NULL;

    *pkey = NULL;
    if (cert) 
        *cert = NULL;

    if (!KeyIso_load_pem_cert(
            correlationId, 
            certLength, 
            certBytes, 
            NULL, 
            &keyCert, 
            ca)) {
        KEYISOP_trace_log(correlationId, 0, title, "loading public key from PEM failed");
        goto end;
    }

    *pkey = X509_get0_pubkey(keyCert);
    if (!*pkey) {
        KEYISOP_trace_log_openssl_error(correlationId, 0, title, "X509_get0_pubkey");
        goto end;
    }
    EVP_PKEY_up_ref(*pkey);

    if (cert) {
        *cert = keyCert;
        keyCert = NULL;
    }

    ret = 1;

end:
    X509_free(keyCert);
    return ret;
}

int KeyIsoP_pem_from_certs(
    const uuid_t correlationId,
    X509 *cert,                     // Optional
    STACK_OF(X509) *ca,             // Optional
    int *pemCertLength,             // Excludes NULL terminator
    char **pemCert)                 // KeyIso_free()                   
{
    const char *title = KEYISOP_HELPER_CERT_TITLE;
    const char *loc = "";
    int ret = 0;
    BIO *mem = NULL;
    int memLen = 0;
    const unsigned char *memBytes = NULL;   // Don't free

    *pemCertLength = 0;
    *pemCert = NULL;

    mem = BIO_new(BIO_s_mem());
    if (mem == NULL) {
        goto openSslErr;
    }

    if (cert != NULL) {
        if (!PEM_write_bio_X509(mem, cert)) {
            loc = "PEM_write_bio_X509";
            goto openSslErr;
        }
    }

    if (ca != NULL) {
        for (int i = 0; i < sk_X509_num(ca); i++) {
            if (!PEM_write_bio_X509(mem, sk_X509_value(ca, i))) {
                loc = "PEM_write_bio_X509";
                goto openSslErr;
            }
        }
    }

    memLen = (int) BIO_get_mem_data(mem, (char **) &memBytes);
    *pemCert = (char *) KeyIso_zalloc(memLen + 1);
    if (*pemCert == NULL) {
        goto openSslErr;
    }

    memcpy(*pemCert, memBytes, memLen);
    *pemCertLength = memLen;

    ret = 1;
end:
    BIO_free(mem);
    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

static int _parse_bags(
    const STACK_OF(PKCS12_SAFEBAG) *bags, 
    X509 **cert,
    STACK_OF(X509) *ocerts);

static int _parse_bag(
    PKCS12_SAFEBAG *bag, 
    X509 **cert,
    STACK_OF(X509) *ocerts)
{
    X509 *x509 = NULL;
    const ASN1_TYPE *attrib = NULL;
    ASN1_OCTET_STRING *lkid = NULL;

    if ((attrib = PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID)))
        lkid = attrib->value.octet_string;

    switch (PKCS12_SAFEBAG_get_nid(bag)) {
    case NID_certBag:
        if (PKCS12_SAFEBAG_get_bag_nid(bag) != NID_x509Certificate)
            return 1;
        if ((x509 = PKCS12_SAFEBAG_get1_cert(bag)) == NULL)
            return 0;

        if (lkid) {
            if (!*cert) 
                *cert = x509;
            else
                X509_free(x509);

            return 1;
        }

        if (!sk_X509_push(ocerts, x509)) {
            X509_free(x509);
            return 0;
        }

        break;

    case NID_safeContentsBag:
        return _parse_bags(PKCS12_SAFEBAG_get0_safes(bag), cert, ocerts);

    default:
        return 1;
    }
    return 1;
}

static int _parse_bags(
    const STACK_OF(PKCS12_SAFEBAG) *bags, 
    X509 **cert,
    STACK_OF(X509) *ocerts)
{
    for (int i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
        if (!_parse_bag(sk_PKCS12_SAFEBAG_value(bags, i),
                                 cert, ocerts)) {
            return 0;
        }
    }
    return 1;
}

int KeyIsoP_load_pfx_certs(
    const uuid_t correlationId,
    int pfxLength,
    const unsigned char *pfxBytes,
    X509 **cert,
    STACK_OF(X509) **ca)        // Optional
{
    const char *title = KEYISOP_HELPER_PFX_TITLE;
    const char *loc = "";
    int ret = 0;
    BIO *in = NULL;
    PKCS12 *p12 = NULL;

    X509 *x = NULL;
    STACK_OF(X509) *ocerts = NULL;
    STACK_OF(PKCS7) *asafes = NULL;
    int i;

    *cert = NULL;

    ERR_clear_error();
    
    /* Allocate stack for other certificates */
    ocerts = sk_X509_new_null();
    if (!ocerts) {
        goto openSslErr;
    }

    in = BIO_new_mem_buf(pfxBytes, pfxLength);
    if (in == NULL) {
        goto openSslErr;
    }

    p12 = d2i_PKCS12_bio(in, NULL);
    if (p12 == NULL) {
        loc = "d2i_PKCS12_bio";
        goto openSslErr;
    }

    if ((asafes = PKCS12_unpack_authsafes(p12)) == NULL) {
        loc = "PKCS12_unpack_authsafes";
        goto openSslErr;
    }

    for (i = 0; i < sk_PKCS7_num(asafes); i++) {
        STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
        PKCS7 *p7 = sk_PKCS7_value(asafes, i);
        int bagnid = OBJ_obj2nid(p7->type);

        if (bagnid == NID_pkcs7_data) {
            bags = PKCS12_unpack_p7data(p7);
        } else {
            continue;
        }
        if (!bags) {
            loc = "PKCS12_unpack_p7data";
            goto parseErr;
        }
        if (!_parse_bags(bags, cert, ocerts)) {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            loc = "_parse_bags";
            goto parseErr;
        }
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    }

    if (!*cert) {
        loc = "NoCert";
        goto parseErr;
    }

    if (ca) {
        while ((x = sk_X509_pop(ocerts))) {
            if (!*ca) {
                *ca = sk_X509_new_null();
            }
            if (!*ca) {
                goto openSslErr;
            }
            if (!sk_X509_push(*ca, x)) {
                goto openSslErr;
            }
        }
    }

    ret = 1;
end:
    BIO_free(in);
    PKCS12_free(p12);
    sk_PKCS7_pop_free(asafes, PKCS7_free);
    X509_free(x);
    sk_X509_pop_free(ocerts, X509_free);

    if (!ret) {
        X509_free(*cert);
        *cert = NULL;
    }
    return ret;

parseErr:
    KEYISOP_trace_log_error(correlationId, 0, title, loc, "Parse PFX error");
    goto end;

openSslErr:
    KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
    goto end;
}

int KeyIso_load_pfx_pubkey(
    const uuid_t correlationId,
    int pfxLength,
    const unsigned char *pfxBytes,
    EVP_PKEY **pkey,
    X509 **cert,            // Optional
    STACK_OF(X509) **ca)    // Optional
{
    const char *title = KEYISOP_HELPER_PFX_TITLE;
    int ret = 0;
    X509 *keyCert = NULL;

    *pkey = NULL;
    if (cert) 
        *cert = NULL;

    if (!KeyIsoP_load_pfx_certs(
            correlationId,
            pfxLength,
            pfxBytes,
            &keyCert,
            ca)) {
        goto end;
    }

    *pkey = X509_get0_pubkey(keyCert);
    if (!*pkey) {
        KEYISOP_trace_log_openssl_error(correlationId, 0, title, "X509_get0_pubkey");
        goto end;
    }
    EVP_PKEY_up_ref(*pkey);

    if (cert) {
        *cert = keyCert;
        keyCert = NULL;
    }

    ret = 1;

end:
    X509_free(keyCert);
    return ret;
}


static X509_STORE *_setup_verify(
    const uuid_t correlationId)
{
    const char *title = KEYISOP_VERIFY_CERT_TITLE;
    const char *loc = "";
    X509_STORE *store = NULL;
    X509_LOOKUP *lookup = NULL;

    store = X509_STORE_new();
    if (store == NULL) {
        goto openSslErr;
    }

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
    if (lookup == NULL) {
        loc = "add_lookup";
        goto openSslErr;
    }

    if (!X509_LOOKUP_add_dir(lookup, KeyIsoP_get_default_cert_dir(), X509_FILETYPE_PEM)) {
        loc = "add_dir";
        goto openSslErr;
    }

    ERR_clear_error();
    return store;

openSslErr:
    KEYISOP_trace_log_openssl_error(correlationId, 0, title, loc);
    X509_STORE_free(store);
    return NULL;
}

// Cert sha1 hash of untrusted roots. Require trusted CAs.
static const char *KeyIsoP_untrustedRoots[] = {
    // 653b494a.0 - (CN) Baltimore CyberTrust Root
    "d4de20d05e66fc53fe1a50882c78db2852cae474",
    // 3513523f.0 - (CN) DigiCert Global Root CA
    "a8985d3a65e5e5c4b2d7d66d40c6dd2fb19c5436",

    NULL
};

static int KeyIsoP_is_untrusted_root(
    X509 *cert)
{
    int ret = 0;
    char sha1HexHash[SHA_DIGEST_LENGTH * 2 + 1];

    _X509_sha1_hex_hash(cert, sha1HexHash);

    for (int i = 0; KeyIsoP_untrustedRoots[i] != NULL; i++) {
        if (strcmp(sha1HexHash, KeyIsoP_untrustedRoots[i]) == 0) {
            ret = 1;
            break;
        }
    }

    return ret;
}

// Return:
//  1 - Certificate is trusted.
//  0 - Certificate not found in the trusted certificates directory.
static int KeyIsoP_is_trusted_ca(
    const uuid_t correlationId,
    X509 *cert)
{
    return _cert_ctrl(
        correlationId,
        KEYISO_CERT_CTRL_FIND,
        KEYISO_CERT_LOCATION_ROOT,
        cert);
}

//
// Wrapper for openSSL!X509_verify_cert().
//
// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to build chain
int KeyIsoP_X509_verify_cert(
    KEYISO_VERIFY_CERT_CTX *ctx,
    X509_STORE_CTX *storeCtx,
    int keyisoFlags,
    int *verifyChainError)
{
    const char *title = KEYISOP_VERIFY_CERT_TITLE;
    const char *loc = "";
    int ret = 0;
    int chainRet = 0;
    STACK_OF(X509) *storeChain = NULL;
    int chainDepth = 0;
    int hasTrustedCa = 0;
    *verifyChainError = 0;

    ERR_clear_error();

    if (ctx->param != NULL) {
        X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(storeCtx);
        if (param == NULL) {
            KEYISOP_trace_log_error(ctx->correlationId, 0, title, "X509_STORE_CTX_get0_param", "Missing param");
        } else {
            X509_VERIFY_PARAM_inherit(param, ctx->param);
        }
    }

    // Following returns 1 for success;
    chainRet = X509_verify_cert(storeCtx);
    storeChain = X509_STORE_CTX_get1_chain(storeCtx);
    if (storeChain == NULL) {
        loc = "CTX_get1_chain";
        goto openSslErr;
    }

    chainDepth = sk_X509_num(storeChain);
    if (chainDepth <= 0) {
        KEYISOP_trace_log_error(ctx->correlationId, 0, title, "ChainDepth", "No certificates in chain");
        goto end;
    }

    if (chainRet > 0) {
        chainRet = 1;
    } else {
        // These errors are defined in x509_vfy.h
        //  X509_V_ERR_*
        *verifyChainError = X509_STORE_CTX_get_error(storeCtx);

        if ((keyisoFlags & KEYISO_IGNORE_DEPTH_ZERO_SELF_SIGNED_ERROR_FLAG) != 0 &&
                *verifyChainError == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT &&
                chainDepth == 1) {
            chainRet = 1;
            *verifyChainError = 0;
        } else {
            KEYISOP_trace_log_openssl_verify_cert_error_para(ctx->correlationId, 0, title,
                "X509_verify_cert", *verifyChainError, 
                "OpenSSL was unable to verify the provided certificate. Please ensure that the certificate you are using is valid.");
            chainRet = -1;
        }
    }


    for (int i = 0; i < chainDepth; i++) {
        X509 *cert = sk_X509_value(storeChain, i);

        if (KeyIso_is_disallowed_cert(ctx->correlationId, cert)) {
            if (chainRet > 0 && i == chainDepth - 1 && chainDepth >= 2) {
                // Explicitly disallowed root. Check if any CA's in the chain are explicitly trusted.
                // Will also allow an explicitly trusted leaf cert.

                for (int j = chainDepth - 2; j >= 0; j--) {
                    X509* ca = sk_X509_value(storeChain, j);
                    if (KeyIsoP_is_trusted_ca(ctx->correlationId, ca)) {
                        hasTrustedCa = 1;
                        break;
                    }
                }

                if (hasTrustedCa) {
                    break;
                }
            }
			
            *verifyChainError = X509_V_ERR_CERT_REVOKED;
            X509_STORE_CTX_set_error(storeCtx, *verifyChainError);
            KEYISOP_trace_log_openssl_verify_cert_error(ctx->correlationId, 0, title,
                "KeyIso_is_disallowed_cert", *verifyChainError);
            chainRet = -1;
        }
    }

    if (chainDepth >= 2 && !hasTrustedCa) {
        X509 *root = sk_X509_value(storeChain, chainDepth - 1);

        if (KeyIsoP_is_untrusted_root(root)) {
            X509 *ca = sk_X509_value(storeChain, chainDepth - 2);
            const char nullTerminator = 0;

            BIO *rootBio = NULL;
            BIO *caBio = NULL;
            const char *rootName = "";
            const char *caName = "";

            rootBio = BIO_new(BIO_s_mem());
            if (rootBio != NULL) {
                char *name = NULL;
                X509_NAME_print_ex(
                    rootBio,
                    X509_get_subject_name(root),
                    0,                      // indent
                    XN_FLAG_ONELINE | XN_FLAG_DN_REV);
                if (BIO_write(rootBio, &nullTerminator, 1) == 1 &&
                        BIO_get_mem_data(rootBio, &name) > 0 && name != NULL) {
                    rootName = name;
                }
            }

            caBio = BIO_new(BIO_s_mem());
            if (caBio != NULL) {
                char *name = NULL;
                X509_NAME_print_ex(
                    caBio,
                    X509_get_subject_name(ca),
                    0,                      // indent
                    XN_FLAG_ONELINE | XN_FLAG_DN_REV);
                if (BIO_write(caBio, &nullTerminator, 1) == 1 &&
                        BIO_get_mem_data(caBio, &name) > 0 && name != NULL) {
                    caName = name;
                }
            }

            if (!KeyIsoP_is_trusted_ca(ctx->correlationId, ca)) {
                *verifyChainError = X509_V_ERR_CERT_REVOKED;
                X509_STORE_CTX_set_error(storeCtx, *verifyChainError);

                KEYISOP_trace_log_openssl_verify_cert_error_para(ctx->correlationId, 0, title,
                    "KeyIsoP_is_untrusted_root", *verifyChainError,
                    "ROOT: <%s> CA: <%s>", rootName, caName);
                chainRet = -1;

            } else {
                KEYISOP_trace_log_para(ctx->correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title,
                    "KeyIsoP_is_trusted_ca", 
                    "ROOT: <%s> CA: <%s>", rootName, caName);
            }


            BIO_free(rootBio);
            BIO_free(caBio);
        }
    }

    for (int i = 0; i < sk_KEYISOP_VERIFY_CERT_CALLBACK_CTX_num(ctx->callbackCtx); i++) {
        KEYISOP_VERIFY_CERT_CALLBACK_CTX *callbackCtx =
            sk_KEYISOP_VERIFY_CERT_CALLBACK_CTX_value(ctx->callbackCtx, i);

        int callbackRet = callbackCtx->callback(
            ctx->correlationId,
            storeCtx,
            verifyChainError,
            callbackCtx->arg);
        if (callbackRet == 0) {
            KEYISOP_trace_log_error(ctx->correlationId, 0, title, "callback", "Callback verify error");
            goto end;
        }

        if (callbackRet < 0) {
            chainRet = -1;
            KEYISOP_trace_log_openssl_verify_cert_error(ctx->correlationId, 0, title, "callback", *verifyChainError);
        }
    }

    ret = chainRet;
    ERR_clear_error();
end: 
    sk_X509_pop_free(storeChain, X509_free);
    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error(ctx->correlationId, 0, title, loc);
    goto end;
}

// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, unable to build chain
int KeyIso_verify_cert2(
    KEYISO_VERIFY_CERT_CTX *ctx,   // Optional
    int keyisoFlags,
    X509 *cert,
    STACK_OF(X509) *ca,             // Optional
    int *verifyChainError,
    STACK_OF(X509) **chain)         // Optional
{
    const char *title = KEYISOP_VERIFY_CERT_TITLE;
    const char *loc = "";
    int ret = 0;
    int chainRet = 0;
    X509_STORE *store = NULL;
    X509_STORE_CTX *storeCtx = NULL;
    STACK_OF(X509) *storeChain = NULL;
    KEYISO_VERIFY_CERT_CTX *allocCtx = NULL;

    *verifyChainError = 0;
    if (chain) {
        *chain = NULL;
    }

    ERR_clear_error();

    if (ctx == NULL) {
        allocCtx = KeyIso_create_verify_cert_ctx(NULL);
        if (allocCtx == NULL) {
            return 0;
        }

        ctx = allocCtx;
    }

    if (chain) {
        *chain = sk_X509_new_null();
        if (*chain == NULL) {
            goto openSslErr;
        }
    }

    store = _setup_verify(ctx->correlationId);
    if (store == NULL) {
        goto end;
    }

    storeCtx = X509_STORE_CTX_new();
    if (storeCtx == NULL) {
        goto openSslErr;
    }

    if (!X509_STORE_CTX_init(storeCtx, store, cert, ca)) {
        loc = "CTX_init";
        goto openSslErr;
    }

    chainRet = KeyIsoP_X509_verify_cert(
        ctx,
        storeCtx,
        keyisoFlags,
        verifyChainError);
    if (chainRet == 0) {
        goto end;
    }

    if (chain) {
        storeChain = X509_STORE_CTX_get1_chain(storeCtx);
        if (storeChain == NULL) {
            loc = "CTX_get1_chain";
            goto openSslErr;
        }

        for (int i = 0; i < sk_X509_num(storeChain); i++) {
            X509 *cert = sk_X509_value(storeChain, i);
            int isRoot = 0;

            if (X509_NAME_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert)) == 0) {
                isRoot = 1;
            }

            if (i == 0) {
                if (keyisoFlags & KEYISO_EXCLUDE_END_FLAG) {
                    continue;
                }
            } else if (isRoot && (keyisoFlags & KEYISO_EXCLUDE_ROOT_FLAG)) {
                continue;
            }

            if (!sk_X509_push(*chain, cert)) {
                goto openSslErr;
            }
            X509_up_ref(cert);
        }

        if (ca && !(keyisoFlags & KEYISO_EXCLUDE_EXTRA_CA_FLAG)) {
            for (int i = 0; i < sk_X509_num(ca); i++) {
                X509 *caCert = sk_X509_value(ca, i);
                int isOutMatch = 0;

                for (int j = 0; j < sk_X509_num(*chain); j++) {
                    X509 *outCert = sk_X509_value(*chain, j);
                    if (X509_cmp(caCert, outCert) == 0) {
                        isOutMatch = 1;
                        break;
                    }
                }

                if (!isOutMatch) {
                    if ((keyisoFlags & KEYISO_EXCLUDE_ROOT_FLAG) &&
                            X509_NAME_cmp(X509_get_subject_name(caCert),
                                X509_get_issuer_name(caCert)) == 0) {
                            // Exclude the root.
                            continue;
                    }

                    if (!sk_X509_push(*chain, caCert)) {
                        goto openSslErr;
                    }
                    X509_up_ref(caCert);
                }
            }
        }
    }

    ret = chainRet;
    ERR_clear_error();
end: 
    sk_X509_pop_free(storeChain, X509_free);
    X509_STORE_CTX_free(storeCtx);
    X509_STORE_free(store);
    KeyIso_free_verify_cert_ctx(allocCtx);

    if (!ret && chain) {
        sk_X509_pop_free(*chain, X509_free);
        *chain = NULL;
    }
    return ret;

openSslErr:
    KEYISOP_trace_log_openssl_error(ctx->correlationId, 0, title, loc);
    goto end;
}

// Return:
//  +1 - Success with complete chain of certificates to a trusted root
//  -1 - Success with chain error. Might be missing intermediate certs.
//       *verifyChainError is updated with X509_V_ERR_* error defined
//       in x509_vfy.h.
//   0 - Error, other errors, such as, invalid input certificate.
int KeyIso_verify_cert(
    KEYISO_VERIFY_CERT_CTX *ctx,       // Optional
    int keyisoFlags,
    int certFormat,                     // Only DER and PEM
    int certLength,
    const unsigned char *certBytes,
    int *verifyChainError,
    int *pemChainLength,                // Optional, excludes NULL terminator
    char **pemChain)                    // Optional, KeyIso_free()
{
    const char *title = KEYISOP_VERIFY_CERT_TITLE;
    int ret = 0;
    int chainRet = 0;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    STACK_OF(X509) *chain = NULL;
    KEYISO_VERIFY_CERT_CTX *allocCtx = NULL;
    int pemRet = 1;

    *verifyChainError = 0;
    if (pemChainLength) {
        *pemChainLength = 0;
    } else {
        pemRet = 0;
    }
    if (pemChain) {
        *pemChain = NULL;
    } else {
        pemRet = 0;
    }

    ERR_clear_error();

    if (ctx == NULL) {
        allocCtx = KeyIso_create_verify_cert_ctx(NULL);
        if (allocCtx == NULL) {
            return 0;
        }

        ctx = allocCtx;
    }

    switch (certFormat) {
        case KEYISO_CERT_FORMAT_DER:
            ret = _der_cert_load(
                ctx->correlationId,
                certLength,
                certBytes,
                &cert);
            break;

        case KEYISO_CERT_FORMAT_PEM:
            ret = KeyIso_load_pem_cert(
                ctx->correlationId,
                certLength,
                certBytes,
                NULL,     // pkey
                &cert,
                &ca);
            break;

        default:
            KEYISOP_trace_log_error(ctx->correlationId, 0, title, "CertFormat", "Not supported certificate format");
    }

    if (!ret) {
        goto end;
    }

    chainRet = KeyIso_verify_cert2(
        ctx,
        keyisoFlags,
        cert,
        ca,
        verifyChainError,
        pemRet ? &chain : NULL);
    if (chainRet == 0) {
        goto end;
    }

    if (pemRet) {
        ret = KeyIsoP_pem_from_certs(
            ctx->correlationId,
            NULL,                   // X509 *cert
            chain,
            pemChainLength,
            pemChain);
    }

    if (ret) {
        ret = chainRet;
    }

end:
    X509_free(cert);
    sk_X509_pop_free(ca, X509_free);
    sk_X509_pop_free(chain, X509_free);
    KeyIso_free_verify_cert_ctx(allocCtx);
    return ret;
}


struct KeyIso_cert_dir_st {
    uuid_t      correlationId;
    DIR         *dir;               // closedir()
    char        *dirName;           // KeyIso_free()
    int         location;
};

static KEYISO_CERT_DIR*_open_trusted_cert_dir(
    const uuid_t correlationId,
    int keyisoFlags,
    int location)
{
    const char *title = KeyIsoP_get_cert_ctrl_title(KEYISO_CERT_CTRL_ENUM, location);
    int ret = 0;
    KEYISO_CERT_DIR *certDir = NULL;           
    const char *dirName = NULL;                 // Don't free
    char *disallowedDirName = NULL;             // KeyIso_free()

    certDir = (KEYISO_CERT_DIR *) KeyIso_zalloc(sizeof(*certDir));
    if (certDir == NULL) {
        goto end;
    }

    if (correlationId == NULL) {
        KeyIso_rand_bytes(certDir->correlationId, sizeof(certDir->correlationId));
    } else {
        memcpy(certDir->correlationId, correlationId, sizeof(certDir->correlationId));
    }

    certDir->location = location;

    if (location == KEYISO_CERT_LOCATION_DISALLOWED) {
        disallowedDirName = _get_disallowed_dir();
        if (disallowedDirName == NULL) {
            KEYISOP_trace_log_openssl_error(certDir->correlationId, 0, title, "_get_disallowed_dir");
            goto end;
        }
        dirName = disallowedDirName;
    } else {
        dirName = KeyIsoP_get_default_cert_dir();
    }

    certDir->dirName = KeyIso_strndup(dirName, KEYISO_MAX_PATH_LEN); // KEYISO_MAX_PATH_LEN includes NULL terminator
    if (certDir->dirName == NULL) {
        goto end;
    }

    certDir->dir = opendir(dirName);
    if (certDir->dir == NULL) {
        int err = errno;
        KEYISOP_trace_log_errno_para(certDir->correlationId, 0, title, "opendir", err,
            "certDir: %s", dirName);
        goto end;
    }

    ret = 1;

end:
    KeyIso_free(disallowedDirName);
    if (!ret) {
        KeyIso_close_cert_dir(certDir);
        certDir = NULL;
    }
    return certDir;
}

// Returns directory handle or NULL on error.
KEYISO_CERT_DIR *KeyIso_open_trusted_cert_dir(
    const uuid_t correlationId,
    int keyisoFlags)
{
    return _open_trusted_cert_dir(correlationId, keyisoFlags, KEYISO_CERT_LOCATION_ROOT);
}

KEYISO_CERT_DIR *KeyIso_open_disallowed_cert_dir(
    const uuid_t correlationId,
    int keyisoFlags)
{
    return _open_trusted_cert_dir(correlationId, keyisoFlags, KEYISO_CERT_LOCATION_DISALLOWED);
}

// Return:
//  +1 - Success with *cert updated
//  -1 - No more certs. *cert is set to NULL.
//   0 - Error
int KeyIso_read_cert_dir(
    KEYISO_CERT_DIR *certDir,
    X509 **cert)                // X509_free()
{
    const char *title = KeyIsoP_get_cert_ctrl_title(KEYISO_CERT_CTRL_ENUM, certDir->location);
    int ret = 0;
    const int asciiHexLength =
        certDir->location == KEYISO_CERT_LOCATION_DISALLOWED ? KEYISOP_MAX_FILENAME_HASH_LENGTH * 2 : 4 * 2;
    char *certPath = NULL;  // KeyIso_free()
    
    *cert = NULL;

    for(;;) {
        int nameLength = 0;
        int certPathLength = 0;
        int validName = 1;
        struct dirent *dp = NULL;
        BIO *in = NULL;

        errno = 0;
        dp = readdir(certDir->dir);

        if (dp == NULL) {
            int err = errno;

            if (err == 0) {
                ret = -1;
            } else {
                KEYISOP_trace_log_errno_para(certDir->correlationId, 0, title, "readdir", err,
                    "certDir: %s", certDir->dirName);
            }

            break;
        }

        // Skip "." and ".."
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0) {
            continue;
        }

        nameLength = (int) strlen(dp->d_name);
        certPathLength = (int) strlen(certDir->dirName) + 1 + nameLength + 1;
                
        KeyIso_free(certPath);
        certPath = (char *) KeyIso_zalloc(certPathLength);
        if (certPath == NULL) {
            break;
        }

        BIO_snprintf(certPath, certPathLength, "%s/%s",
            certDir->dirName, dp->d_name);

        // Skip files not matching 
        //  Trusted:      0b9a1734.0                            8 asciiHex "." digits "\0"
        //  Disallowed:   514be7009413c5cd96e99a33dc499f5d.0   32 asciiHex "." digits "\0"

        if (nameLength < asciiHexLength + 2 || dp->d_name[asciiHexLength] != '.') {
            validName = 0;
        } else {
            for (int i = 0; i < asciiHexLength; i++) {
                int c = dp->d_name[i];
                if (isdigit(c) || (c >= 'a' && c <= 'f')) {
                    continue;
                }

                validName = 0;
                break;
            }

            for (int i = asciiHexLength + 1; i < nameLength; i++) {
                int c = dp->d_name[i];
                if (isdigit(c)) {
                    continue;
                }

                validName = 0;
                break;
            }
        }

        if (!validName) {
            KEYISOP_trace_log_para(certDir->correlationId, KEYISOP_TRACELOG_VERBOSE_FLAG, title, "Skipping file",
                "filename: %s", certPath);
            continue;
        }

        ERR_clear_error();

        in = BIO_new_file(certPath, "r");
        if (in == NULL) {
            KEYISOP_trace_log_openssl_error_para(certDir->correlationId, 0, title, "BIO_new_file",
                    "filename: %s", certPath);
            continue;
        }

        *cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
        BIO_free(in);

        if (*cert != NULL) {
            ret = 1;
            break;
        }

        KEYISOP_trace_log_openssl_error_para(certDir->correlationId, 0, title, "PEM_read_bio_X509_AUX",
            "filename: %s", certPath);
    }

    KeyIso_free(certPath);

    return ret;
}

void KeyIso_close_cert_dir(
    KEYISO_CERT_DIR *certDir)
{
    if (certDir != NULL) {
        if (certDir->dir != NULL) {
            closedir(certDir->dir);
        }
        KeyIso_free(certDir->dirName);
        KeyIso_free(certDir);
    }
}
