# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Specify the minimum version of CMake
cmake_minimum_required(VERSION 3.12)

# Define the project name
project(kmppprovider)

# Detecting memory errors with AddressSanitizer and UndefinedBehaviorSanitizer
message(STATUS "The build type is ${CMAKE_BUILD_TYPE}")
string(TOLOWER "${CMAKE_BUILD_TYPE}" cmake_build_type_lower)
if(cmake_build_type_lower MATCHES debug)
   message("Adding AddressSanitizer and UndefinedBehaviorSanitizer for Debug build")
   set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer")
   set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fsanitize=address -fsanitize=undefined")
endif()

# Set library names
set(LIBRARY_NAME "kmppprovider")
set(DEFAULT_LIBRARY_NAME "kmppprovider_dflt")

# Find the OpenSSL package
find_package(OpenSSL REQUIRED)

# Update openSSL directory according to version
execute_process(
  COMMAND ${OPENSSL_CLI} version -m
  OUTPUT_VARIABLE OPENSSL_MODULESDIR_OUTPUT
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET # suppress error message, it will be handled by result
  RESULT_VARIABLE result
)

if(KMPP_GENERAL_PURPOSE_TARGET)
  # Extract modules directory
  if(result EQUAL 0 AND NOT "${OPENSSL_MODULESDIR_OUTPUT}" STREQUAL "")
    string(REGEX MATCH "MODULESDIR: \"([^\"]+)\"" _ ${OPENSSL_MODULESDIR_OUTPUT})
    if(DEFINED CMAKE_MATCH_1)
      set(OPENSSL_MODULESDIR_DIR "${CMAKE_MATCH_1}")
    else()
      message(FATAL_ERROR "Failed to extract OPENSSL_MODULESDIR_DIR from OpenSSL output")
    endif()
  else()
    message(FATAL_ERROR "Failed to get OpenSSL version -m output")
  endif()
else()
  # Override the default OpenSSL module directory
  set(OPENSSL_MODULESDIR_DIR "${CMAKE_INSTALL_LIBDIR}/ossl-modules")
endif()

message(STATUS "OpenSSl modules (providers) directory: ${OPENSSL_MODULESDIR_DIR}")

# Set openSSL configuration directory variable
execute_process(
  COMMAND ${OPENSSL_CLI} info -configdir
  OUTPUT_VARIABLE OPENSSL_CONFIG_DIR
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET
  RESULT_VARIABLE result_configdir
)

# Extract config directory
if(result_configdir EQUAL 0 AND NOT "${OPENSSL_CONFIG_DIR}" STREQUAL "")
  message(STATUS "OpenSSL configuration directory: ${OPENSSL_CONFIG_DIR}")
else()
  message(FATAL_ERROR "Failed to extract OPENSSL_CONFIG_DIR from OpenSSL output")
endif()


# Add source files
set(COMMON_SOURCE_FILES
    p_keyiso_base.c
    p_keyiso_crypto.c
    p_keyiso_decoder.c
    p_keyiso_encoder.c
    p_keyiso_err.c
    p_keyiso_keymgmt.c
    p_keyiso_rsa_cipher.c
    p_keyiso_rsa_common.c
    p_keyiso_rsa_signature.c
    p_keyiso_store.c
    p_keyiso_common.c
)

set(SOURCE_FILES
    ${COMMON_SOURCE_FILES}
    p_keyiso.c
)

set(SOURCE_FILES_DFLT
    ${COMMON_SOURCE_FILES}
    p_keyiso_dflt.c
)

add_compile_options(
    -Wall -Wextra -Werror
    -fstack-protector-strong -Wstack-protector --param=ssp-buffer-size=4
    -fstack-clash-protection
    -fPIC
    -z noexecstack
    -Wformat
)

find_library(SYMCRYPT_LIB libsymcrypt.so REQUIRED)
find_library(SYMCRYPT_PROVIDER_LIB symcryptprovider.so PATHS ${OPENSSL_MODULESDIR_DIR})

# Function to create and configure a provider library
function(add_provider_library name source_files)
    # Create the shared library
    add_library(${name} SHARED ${source_files})
    set_target_properties(${name} PROPERTIES OUTPUT_NAME ${name} PREFIX "" SUFFIX ".so")

    # Include directories
    target_include_directories(${name} PRIVATE include)

    # Add the definition for OpenSSL support
    target_compile_definitions(${name} PRIVATE -DKMPP_OPENSSL_SUPPORT)  

    # Link libraries
    target_link_libraries(${name} kmpp_shared)

    # Check if the library was found
    if (SYMCRYPT_PROVIDER_LIB)
      message(STATUS "symcryptprovider.so Found: ${SYMCRYPT_PROVIDER_LIB}")
      target_link_libraries(${LIBRARY_NAME} ${SYMCRYPT_PROVIDER_LIB})      
      target_compile_definitions(${LIBRARY_NAME} PRIVATE -DKEYS_IN_USE_AVAILABLE)
    else()
      message(STATUS "symcryptprovider.so not found in ${MODULESDIR}. Required for KeysInUse - Continuing without it.")      
    endif()

    # Install libraries
    install(TARGETS ${name} 
		    DESTINATION "${OPENSSL_MODULESDIR_DIR}"
		    COMPONENT Runtime)
    install(TARGETS ${name} 
		    DESTINATION "${OPENSSL_MODULESDIR_DIR}"
		    COMPONENT Client)
endfunction()

############## Creating shared objects ##############

# Create standard provider
add_provider_library(${LIBRARY_NAME} "${SOURCE_FILES}")

# Create default provider only if KMPP_GENERAL_PURPOSE_TARGET is enabled
if(KMPP_GENERAL_PURPOSE_TARGET)
    message(STATUS "Building default provider library: ${DEFAULT_LIBRARY_NAME}")
    add_provider_library(${DEFAULT_LIBRARY_NAME} "${SOURCE_FILES_DFLT}")
endif()


############## Installing configuration files  ##############

if(KMPP_GENERAL_PURPOSE_TARGET)
    # Add Provider configuration files only if KMPP_GENERAL_PURPOSE_TARGET is enabled
    set(kmpp_provider_config_files
      ${CMAKE_CURRENT_SOURCE_DIR}/conf/kmpp_prov.cnf
      ${CMAKE_CURRENT_SOURCE_DIR}/conf/kmpp_dflt_prov.cnf
    )

    # Install provider configuration files
    install(
      FILES ${kmpp_provider_config_files}
      DESTINATION ${OPENSSL_CONFIG_DIR}
      PERMISSIONS 
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE
      COMPONENT Runtime
    )

    install(
      FILES ${kmpp_provider_config_files}
      DESTINATION ${OPENSSL_CONFIG_DIR}
      PERMISSIONS 
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE
      COMPONENT Client
    )

    ############## Installing script for postinst ##############

    set(KMPP_DEFAULT_PROVIDER_CNF_SCRIPT_PATH "${KMPP_INSTALL_IMAGE_DIR}/scripts")
    set(KMPP_DEFAULT_PROVIDER_CNF_SCRIPT_PATH "${KMPP_DEFAULT_PROVIDER_CNF_SCRIPT_PATH}" PARENT_SCOPE)
    message(STATUS "KMPP_DEFAULT_PROVIDER_CNF_SCRIPT_PATH: ${KMPP_DEFAULT_PROVIDER_CNF_SCRIPT_PATH}")


    install(
        FILES 
            ${CMAKE_SOURCE_DIR}/scripts/
        DESTINATION ${KMPP_DEFAULT_PROVIDER_CNF_SCRIPT_PATH}
        PERMISSIONS 
            OWNER_READ OWNER_WRITE OWNER_EXECUTE
            GROUP_READ GROUP_EXECUTE
            WORLD_READ WORLD_EXECUTE
        COMPONENT Client
    )
endif() # KMPP_GENERAL_PURPOSE_TARGET
