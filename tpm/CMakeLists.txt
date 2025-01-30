# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.10)
project(kmpp_tpm)

message(STATUS "The build type is ${CMAKE_BUILD_TYPE}")

string(TOLOWER "${CMAKE_BUILD_TYPE}" cmake_build_type_lower)

if(cmake_build_type_lower MATCHES debug)
   message("Adding AddressSanitizer and UndefinedBehaviorSanitizer for Debug build")
   set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer")
   set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fsanitize=address -fsanitize=undefined")
endif()

# Find the OpenSSL package
find_package(OpenSSL REQUIRED)

# OpenSSL include directory
include_directories(${OPENSSL_INCLUDE_DIR})

# TPM libraries
find_library(ESYS_LIB libtss2-esys.so.0 REQUIRED)
find_library(TSSMRC_LIB libtss2-rc.so.0 REQUIRED)
find_library(TCTILDR_LIB libtss2-tctildr.so REQUIRED)
find_library(UUID_LIB libuuid.so REQUIRED)

set(TSS2_LIBRARIES ${ESYS_LIB} ${TSSMRC_LIB} ${TCTILDR_LIB})

# Add the library
add_library(kmpp_tpm SHARED)
target_sources(kmpp_tpm PRIVATE 
   ../kmpplib/keyisobaselog.c
   ../kmpplib/keyisolog.c
   ../kmpplib/ossl/keyisomemory.c
   keyisotpmsetup.c
   keyisotpmcrypto.c
   keyisotpmkeymanagement.c
)

add_compile_options(
    -Wall -Wextra -Werror
    -fstack-protector-strong -Wstack-protector --param=ssp-buffer-size=4
    -fstack-clash-protection
    -fPIC
    -z noexecstack
    -Wformat
)

if(KMPP_OPENSSL_SUPPORT)
  target_compile_definitions(kmpp_tpm PRIVATE -DKMPP_OPENSSL_SUPPORT
)
endif()

target_link_libraries(kmpp_tpm PRIVATE ${TSS2_LIBRARIES} ${UUID_LIB})
target_include_directories(kmpp_tpm PRIVATE 
   /usr/include/tss2
   # For logging and memory management
   ../include/
   ../include/internal/clientservice
   # TPM include directory
   include
   include/internal/
)

# Add a custom target for clang static analyzer
add_custom_target(clang-analyze
COMMAND clang --analyze ${CMAKE_C_FLAGS} ${SOURCES})

# Install and package the library
install(TARGETS kmpp_tpm LIBRARY 
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        COMPONENT Client)

install(TARGETS kmpp_tpm LIBRARY 
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        COMPONENT Runtime)
        
if(KMPP_TEST)

# Google Test Unit Test
# Find the Google Test package
find_package(GTest REQUIRED)

# Add the test source file
add_executable(tpmUnittest tpmUnittest.cpp)

# Link the Google Test libraries
target_link_libraries(tpmUnittest 
                     ${GTEST_LIBRARIES}
                     ${OPENSSL_LIBRARIES}
                     pthread
                     kmpp_tpm)

target_include_directories(tpmUnittest PRIVATE 
                          ${GTEST_INCLUDE_DIRS}
                          include
                          # For free mem API's
                          ../include/)
endif()
