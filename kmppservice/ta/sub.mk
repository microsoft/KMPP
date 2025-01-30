# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

KMPP_SERVICE_DIR = ..
KMPP_SERVICE_INC_DIR = $(KMPP_SERVICE_DIR)/include/internal

MSCRYPT_DIR = $(KMPP_SERVICE_DIR)/..
MSCRYPT_INC_DIR = $(MSCRYPT_DIR)/include

# Add the TA include directory to the include path
global-incdirs-y += include
global-incdirs-y += include/internal
global-incdirs-y += $(MSCRYPT_INC_DIR)
global-incdirs-y += $(MSCRYPT_INC_DIR)/internal/clientservice
global-incdirs-y += $(KMPP_SERVICE_INC_DIR)

# Add the Symcrypt include directory to the include path
SYMCRYPT_DIR = $(MSCRYPT_DIR)/external/SymCrypt
global-incdirs-y += $(SYMCRYPT_DIR)/inc/

# Link Symcrypt lib to kmpp TA compilation
libdirs += $(SYMCRYPT_DIR)/bin/lib

# Typically, the linker only includes the needed object files from the library to resolve undefined references,
# However, since SymCrypt is statically linked to KMPP OP-TEE, the `--whole-archive` flag is necessary.
# This flag ensures that the linker includes all object files from the SymCrypt library.
# This is crucial for static constructors, which are used as part of the SymCrypt self-test.
# The `--no-whole-archive` flag is used to disable the `--whole-archive` flag for the following libraries.
user-ta-ldadd += --whole-archive -lsymcrypt_optee --no-whole-archive

# File in this directory
TA_SRCS := keyisoservicekeylistta.c \
		   keyisologta.c \
           kmppta.c \
           kmpptamsghandler.c \
           uuid.c

# Files in the kmppservice directory
KMPP_SERVICE_DIR_SRCS := keyisoipcserviceadapter.c \
                         keyisoserviceapi.c \
                         keyisoservicecommon.c \
                         keyisoservicecrypto.c \
                         keyisoservicekeygen.c \
                         keylist/keyisoservicekeylist.c \
                         keyisoservicemsghandler.c \
                         keyisoservicesymmetrickey.c

# Files in the root directory (mscrypt)
MSCRYPT_DIR_SRCS := kmpplib/keyisomemory.c \
                    kmpplib/keyisosymcryptcommon.c \
                    kmpplib/keyisoutils.c \
                    kmpplib/keyisobaselog.c

# Add the source files to the build
srcs-y += $(TA_SRCS)
srcs-y += $(addprefix $(KMPP_SERVICE_DIR)/, $(KMPP_SERVICE_DIR_SRCS))
srcs-y += $(addprefix $(MSCRYPT_DIR)/, $(MSCRYPT_DIR_SRCS))

# Flags for this directory
# Treat warnings as errors to ensure that the code does not contain any warnings
cflags-y += -Wall -Werror

# Disable warnings for function declarations without arguments to avoid warnings for emty parameter
cflags-y += -Wno-strict-prototypes -Wno-old-style-definition

# Avoid compiling Inproc code in TA 
cflags-y += -DKMPP_TA_COMPILATION

# Disable telemetry for TA
cflags-y += -DKMPP_TELEMETRY_DISABLED

# To ignore format warnings
cflags-y += -Wno-suggest-attribute=format

# To ignore optee_ta_dev_kit warnings
CPPFLAGS += -Wno-missing-braces

# Set the output directory for the compiled files
out-dir := out/lib