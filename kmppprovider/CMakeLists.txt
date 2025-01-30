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

# Set the output library name
set(LIBRARY_NAME "kmppprovider")

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

if(result EQUAL 0 AND NOT "${OPENSSL_MODULESDIR_OUTPUT}" STREQUAL "")
  # Extract the MODULESDIR path using a regular expression
  string(REGEX MATCH "MODULESDIR: \"([^\"]+)\"" _ ${OPENSSL_MODULESDIR_OUTPUT})
  if(DEFINED CMAKE_MATCH_1)
    set(MODULESDIR "${CMAKE_MATCH_1}")
    message(STATUS "OpenSSL MODULESDIR: ${MODULESDIR}")
  else()
    message(FATAL_ERROR "Failed to extract MODULESDIR from OpenSSL output")
  endif()
else()
  message(FATAL_ERROR "Failed to get OpenSSL version -m output")
endif()

message(STATUS "OpenSSl providers directory: ${MODULESDIR}")

# Add source files
set(SOURCE_FILES
    p_keyiso.c
    p_keyiso_keymgmt.c
    p_keyiso_rsa_signature.c
    p_keyiso_store.c
    p_keyiso_rsa_common.c
    p_keyiso_rsa_cipher.c
    p_keyiso_crypto.c
    p_keyiso_err.c
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

# Create the shared library
add_library(${LIBRARY_NAME} SHARED ${SOURCE_FILES})

set_target_properties(${LIBRARY_NAME}
  PROPERTIES OUTPUT_NAME ${LIBRARY_NAME} PREFIX "" SUFFIX ".so"
  )

# Include directories
target_include_directories(${LIBRARY_NAME} PRIVATE include)

# Link libraries
target_link_libraries(${LIBRARY_NAME} kmpp_shared)
install(TARGETS kmppprovider 
		DESTINATION "${MODULESDIR}"
		COMPONENT Runtime)
install(TARGETS kmppprovider 
		DESTINATION "${MODULESDIR}"
		COMPONENT Client)
