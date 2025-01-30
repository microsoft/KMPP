/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <openssl/buffer.h>

#include "keyiso.h"
#include "keyisoutils.h"

static int _read_file_bio(
    BIO **in,
    BIO **mem,
    const char *filename, 
    unsigned char **inBytes)
{
    *in = BIO_new_file(filename, "rb");
    if (*in == NULL) {
        printf("Failed BIO_new_file: %s\n", filename);
        return 0;
    }
    *mem = BIO_new(BIO_s_mem());
    if (*mem == NULL) {
        printf("Out of Memory\n");
        BIO_free(*in);
        return 0;
    }

    for (;;) {
        char buff[512];
        int inl = BIO_read(*in, buff, sizeof(buff));

        if (inl <= 0)
            break;
        if (BIO_write(*mem, buff, inl) != inl) {
            printf("Out of Memory\n");
            BIO_free(*in);
            BIO_free(*mem);
            return 0;
        }
    }

    int inLength = (int) BIO_get_mem_data(*mem, (char **) inBytes);
    printf("filename: %s Length: %d\n", filename, inLength);

    return inLength;
}

int test_KeyIso_import_pfx_to_key_id() 
{
    // Set keyisoFlags (example value, adjust as needed)
    int keyisoFlags = 0;
    const char *password = "example";     // Optional
    int verifyChainError = 0;
    const char *outFilename = "output.id"; // Set to a valid file path
    int ret = 0;
    char *keyId = NULL;                 // KeyIso_clear_free_string()
    int keyIdLength = 0;
    BIO *out = NULL;

    uuid_t correlationId;
    KeyIso_rand_bytes(correlationId, sizeof(correlationId));

    // Read files
    BIO *in = NULL;
    BIO *mem = NULL;
    unsigned char *inBytes = NULL;

    int inLength = _read_file_bio(&in, &mem, "certificate.pfx", &inBytes);
    if (inLength == 0) {
        printf("Failed to read PFX file\n");
        return 1;
    }

    ret = KeyIso_import_pfx_to_key_id(
        correlationId,
        keyisoFlags,
        inLength,
        inBytes,
        password,
        &verifyChainError,
        &keyId);

    if (keyId != NULL) {
        keyIdLength = (int)strlen(keyId);
    } else {
        printf("Failed to import PFX to key ID\n");
        ret = 0;
    }

    if (ret) {
        out = BIO_new_file(outFilename, "wb");
        if (out != NULL) {
            BIO_write(out, keyId, keyIdLength);
            BIO_flush(out);
            BIO_free(out);
        } else {
            printf("Failed to open output file: %s\n", outFilename);
            ret = 0;
        }
    }

    printf("import_pfx_to_key_id: %d\n", ret);

    // Clean up
    KeyIso_clear_free_string(keyId);
    BIO_free(in);
    BIO_free(mem);
    return ret;
}

int main()
{
   return test_KeyIso_import_pfx_to_key_id() ? 0 : 1;
}