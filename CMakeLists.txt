# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.12)
project(kmpp)

###########################################################################################
####################################### COMPILATION #######################################
###########################################################################################
option(KMPP_NGINX "Build nginx example." ON)
option(KMPP_GENERAL_PURPOSE_TARGET "Build under general purpose Linux build system." ON)
option(KMPP_INSTALL_FROM_SOURCES "Install KMPP from sources." OFF)
option(KMPP_DEBUG "Build with Debug options." OFF)
option(KMPP_COVERAGE "Build with coverage information for tests." OFF)
# Turn on containers option if runing on any type of containers (not specifically AKS)
option(KMPP_RUNNING_ON_CONTAINERS "Running on containers." OFF)
option(KMPP_OPENSSL_SUPPORT "Build with a dependency on OpenSSL" ON)
option(KMPP_SYMMETRIC_KEY_SUPPORT  "Build with support in symmetric key" ON)

# Turn off and let recipe install systemd service unit
# because the systemd path maybe outside of CMAKE_INSTALL_PREFIX.
option(KMPP_INSTALL_SERVICE "Install Systemd service." ON)

# Initialize the OS_RELEASE variable
set(OS_RELEASE "")

# Check if the file exists
if(EXISTS "/etc/os-release")
    # Read the contents of the file
    file(READ "/etc/os-release" OS_RELEASE)    
endif()

if(KMPP_GENERAL_PURPOSE_TARGET)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DKMPP_GENERAL_PURPOSE_TARGET")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DKMPP_GENERAL_PURPOSE_TARGET")
endif()

if(KMPP_RUNNING_ON_CONTAINERS)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DKMPP_RUNNING_ON_CONTAINERS")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DKMPP_RUNNING_ON_CONTAINERS")
endif()

if (KMPP_COVERAGE)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs -ftest-coverage")
endif()


if(KMPP_SYMMETRIC_KEY_SUPPORT)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DKMPP_SYMMETRIC_KEY_SUPPORT")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DKMPP_SYMMETRIC_KEY_SUPPORT")
endif()

set(CMAKE_SKIP_INSTALL_RPATH TRUE)
set(CMAKE_SKIP_RPATH TRUE)

if (KMPP_INSTALL_FROM_SOURCES)
  set(KMPP_INSTALL_SERVICE OFF)
endif()

if(KMPP_GENERAL_PURPOSE_TARGET)
  set(KMPP_NGINX OFF)
  set(KMPP_INSTALL_UNITTEST OFF)
  set(CMAKE_INSTALL_PREFIX "/usr")
  set(KMPP_USER_NAME "kmpp")
else()
  if(NOT KMPP_USER_NAME)
    set(KMPP_USER_NAME "kmpp")
  endif()
endif()


set(KMPP_USER_NAME "kmpp")
if(NOT KMPP_INSTALL_IMAGE_DIR)
  set(KMPP_INSTALL_IMAGE_DIR "/var/msft/kmpp")
endif()
if(NOT KMPP_ROOT_DIR)
  set(KMPP_ROOT_DIR "/var/opt/msft/kmpp")
endif()
if(NOT KMPP_PRIVATE_ROOT_DIR)
  set(KMPP_PRIVATE_ROOT_DIR "/var/opt/msft/kmpp-private")
endif()


set(KMPPCTRL_ALLOW_GROUP "${KMPP_USER_NAME}cert")
set(KMPP_BUS_NAME "com.microsoft.${KMPP_USER_NAME}")
set(KMPPCTRL_BUS_NAME "com.microsoft.${KMPP_USER_NAME}ctrl")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DKMPP_USER_NAME=\\\"${KMPP_USER_NAME}\\\"")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DKMPP_USER_NAME=\\\"${KMPP_USER_NAME}\\\"")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DKMPP_BUS_NAME=\\\"${KMPP_BUS_NAME}\\\"")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DKMPP_BUS_NAME=\\\"${KMPP_BUS_NAME}\\\"")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DKMPPCTRL_BUS_NAME=\\\"${KMPPCTRL_BUS_NAME}\\\"")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DKMPPCTRL_BUS_NAME=\\\"${KMPPCTRL_BUS_NAME}\\\"")

set(KMPP_DEFAULT_CONFIG_PATH "${CMAKE_INSTALL_PREFIX}/share/${KMPP_USER_NAME}/config.cnf")
set(KMPP_CUSTOM_CONFIG_PATH "${KMPP_ROOT_DIR}/config.cnf")
set(KMPP_ALLOWED_APPS_JSON_CONFIG "${KMPP_ROOT_DIR}/kmpp_apps.json")

message(STATUS "KMPP_USER_NAME: ${KMPP_USER_NAME}")
message(STATUS "KMPPCTRL_ALLOW_GROUP: ${KMPPCTRL_ALLOW_GROUP}")
message(STATUS "KMPP_BUS_NAME: ${KMPP_BUS_NAME}")
message(STATUS "KMPPCTRL_BUS_NAME: ${KMPPCTRL_BUS_NAME}")

message(STATUS "KMPP_ROOT_DIR: ${KMPP_ROOT_DIR}")
message(STATUS "KMPP_PRIVATE_ROOT_DIR: ${KMPP_PRIVATE_ROOT_DIR}")
message(STATUS "KMPP_INSTALL_IMAGE_DIR: ${KMPP_INSTALL_IMAGE_DIR}")
message(STATUS "KMPP_DEFAULT_CONFIG_PATH: ${KMPP_DEFAULT_CONFIG_PATH}")

add_definitions(-DKMPP_ROOT_DIR="${KMPP_ROOT_DIR}")
add_definitions(-DKMPP_PRIVATE_ROOT_DIR="${KMPP_PRIVATE_ROOT_DIR}")
add_definitions(-DKMPP_INSTALL_IMAGE_DIR="${KMPP_INSTALL_IMAGE_DIR}")
add_definitions(-DKMPP_CUSTOM_CONFIG_PATH="${KMPP_CUSTOM_CONFIG_PATH}")


# get version
set(ENV_PACKAGE_VERSION "$ENV{PKG_VER}")

if (ENV_PACKAGE_VERSION STREQUAL "")
  # use verion from makeenv file
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/scripts/makeenv")
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/scripts/makeenv" envvars)

    # Extract the package using regular expressions
    string(REGEX MATCH "PACKAGE=([^;]+)" package_match ${envvars})
    string(FIND ${package_match} "VERSION" version_pos)
    string(REPLACE "PACKAGE=" "" package_string ${package_match})
    string(FIND ${package_string} "VERSION" version_pos)
    string(SUBSTRING ${package_string} 0 ${version_pos} package_name)
    
    # Remove the "VERSION=" prefix
    string(REGEX MATCH "VERSION=(.+)" version_match ${envvars})
    string(REPLACE "VERSION=" "" version_name ${version_match})
    
    message(STATUS "Package: ${package_name}")
    message(STATUS "Version: ${version_name}")
    set(ENV_PACKAGE_VERSION ${version_name})
  endif()
endif()

message(STATUS "Env-Package-Version: ${ENV_PACKAGE_VERSION}")

add_definitions(-DPKG_VERSION="${ENV_PACKAGE_VERSION}")

if(KMPP_GENERAL_PURPOSE_TARGET)
  set(KEY_VERBOSITY_FLAG true)
else()
  set(KEY_VERBOSITY_FLAG false)
endif()

add_definitions(-DKEY_VERBOSITY_FLAG=${KEY_VERBOSITY_FLAG})

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_compile_options(-O2 -pipe -feliminate-unused-debug-types)
add_compile_options(-DFortify_Source=2)
add_compile_options(-Wunused-variable)

# Enable treating warnings as errors
add_compile_options(-Werror -Wall)
# Exclude -Wdeprecated-declarations from treating as an error
add_compile_options(-Wno-error=deprecated-declarations)

# Liquide compliance flags
link_libraries(-Wl,-z,now)
link_libraries(-Wl,-z,relro)
link_libraries(-Wl,-z,noexecstack)

add_compile_options(-fstack-protector-strong -Wstack-protector --param=ssp-buffer-size=4)
add_compile_options(-fstack-clash-protection)
add_compile_options(-fPIC)
add_compile_options(-Wformat -Wformat-security -Werror=format-security)

if(OS_RELEASE MATCHES "Ubuntu")
  # For Ubuntu, use -D_FORTIFY_SOURCE=3
  add_compile_options(-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3)
else()
  # For other distributions, use -D_FORTIFY_SOURCE=2
  add_compile_options(-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2)
endif()
if (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
  add_compile_options(-fcf-protection)
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
  # Add comprehensive control-flow protection for ARM64.
  add_compile_options(-mbranch-protection=standard)
endif()
# End of liquide compliance flags

if (KMPP_GENERAL_PURPOSE_TARGET)
  if (KMPP_DEBUG)
    set(CMAKE_BUILD_TYPE Debug)
  endif() 
  add_subdirectory(tpm)
endif()


# Old cmake doesn't support add_link_options.
link_libraries(-Wl,--no-undefined)

if("$ENV{SDKROOT}" STREQUAL "c:\\winsdk")
  set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/usr)
  # For release, do cmake -DCMAKE_BUILD_TYPE Release
  set(CMAKE_BUILD_TYPE Debug)
endif()

message(STATUS "Build type ${CMAKE_BUILD_TYPE}")

include(GNUInstallDirs)
set(CMAKE_INSTALL_DEFAULT_DIRECTORY_PERMISSIONS
  OWNER_READ
  OWNER_WRITE
  OWNER_EXECUTE
  GROUP_READ
  GROUP_EXECUTE
  WORLD_READ
  WORLD_EXECUTE
  )
  
if(KMPP_GENERAL_PURPOSE_TARGET)
  # Define the path to the TinyCBOR third-party library directory
  set(TINYCBOR_LIB_DIR ${CMAKE_SOURCE_DIR}/thirdparty/tinycbor)

  # Build and install the library using 'make' and 'make install'
  execute_process(
      COMMAND make
      WORKING_DIRECTORY ${TINYCBOR_LIB_DIR}
  )

  find_library(TINYCBOR_LIB libtinycbor.a REQUIRED PATHS ${TINYCBOR_LIB_DIR}/lib NO_DEFAULT_PATH)
else()
  find_library(TINYCBOR_LIB libtinycbor.a REQUIRED)
endif()
find_library(SYMCRYPT_LIB libsymcrypt.so REQUIRED)
find_package(PkgConfig REQUIRED)
find_library(SSL_LIB libssl.so REQUIRED)
find_library(CRYPTO_LIB libcrypto.so REQUIRED)
find_library(CURL_LIB libcurl.so REQUIRED)
find_library(UUID_LIB libuuid.so REQUIRED)


if (KMPP_GENERAL_PURPOSE_TARGET)
 # TPM libraries
 find_library(ESYS_LIB libtss2-esys.so.0 REQUIRED)
 find_library(TSSMRC_LIB libtss2-rc.so.0 REQUIRED)
 find_library(TCTILDR_LIB libtss2-tctildr.so REQUIRED)
 find_library(MU_LIB libtss2-mu.so REQUIRED)
 
 set(TSS2_LIBRARIES
     ${ESYS_LIB}
     ${TSSMRC_LIB}
     ${TCTILDR_LIB}
     ${MU_LIB}
 )
endif() 

find_program(OPENSSL_CLI NAMES openssl)

# Query the OpenSSL version
execute_process(
  COMMAND ${OPENSSL_CLI} version
  OUTPUT_VARIABLE OPENSSL_VERSION_OUTPUT
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Check the OpenSSL version
string(REGEX MATCH "OpenSSL ([0-9]+\\.[0-9]+\\.[0-9]+)" _ ${OPENSSL_VERSION_OUTPUT})
if(DEFINED CMAKE_MATCH_1)
  set(OPENSSL_VERSION ${CMAKE_MATCH_1})
else()
  message(WARNING "Failed to extract OpenSSL version from output: ${OPENSSL_VERSION_OUTPUT}")
endif()

# Set openssl 3 flag for version 3.0.0 or higher
if(OPENSSL_VERSION VERSION_GREATER_EQUAL 3)
  message(STATUS "Using OpenSSL version ${OPENSSL_VERSION} (3.0.0 or higher)")
  set(KMPP_OPENSSL_3 ON)
else()
  message(STATUS "Using OpenSSL version ${OPENSSL_VERSION} (older than 3.0.0)")
  set(KMPP_OPENSSL_3 OFF)
endif()

if(KMPP_OPENSSL_3)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DKMPP_OPENSSL_3")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DKMPP_OPENSSL_3")
endif()

set(KMPP_OPENSSL_ENGINE_DIR "${CMAKE_INSTALL_LIBDIR}/engines-1.1")
# Update openSSL engine directory according to version
execute_process(
  COMMAND ${OPENSSL_CLI} version -e
  OUTPUT_VARIABLE OPENSSL_VERSION_OUTPUT
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET # suppress error message, it will be handled by result
  RESULT_VARIABLE result
)
if(result EQUAL 0 AND NOT "${OPENSSL_VERSION_OUTPUT}" STREQUAL "")
  string(REGEX REPLACE ".*\\/([^/]+)$" "\\1" OPENSSL_VERSION ${OPENSSL_VERSION_OUTPUT})
  string(REGEX REPLACE "[^-.^A-Za-z0-9]" "" OPENSSL_VERSION ${OPENSSL_VERSION})
  message(STATUS "Detected OpenSSL version: ${OPENSSL_VERSION}")
  set(KMPP_OPENSSL_ENGINE_DIR ${CMAKE_INSTALL_LIBDIR}/${OPENSSL_VERSION})
else()
  message(STATUS "Failed to detect OpenSSL version, using default")
endif()
message(STATUS "OpenSSl engine directory: ${KMPP_OPENSSL_ENGINE_DIR}")

pkg_check_modules(GLIB2 REQUIRED glib-2.0 gio-2.0 gio-unix-2.0 gobject-2.0)
pkg_check_modules(DBUS REQUIRED dbus-1)

if (KMPP_GENERAL_PURPOSE_TARGET)
  pkg_check_modules(JANSSON REQUIRED jansson)
endif()

# Base Include Directories
set(BASE_INCLUDE_DIRS
  include
  include/datastructures/
  include/gdbus/ctrlclient
  include/internal
  include/internal/clientservice
  kmppclient/include
  kmppclient/include/internal
  ${GLIB2_INCLUDE_DIRS}
  ${DBUS_INCLUDE_DIRS}
)

# GDBus Include Directories
set(GDBUS_INCLUDE_DIRS
  include/gdbus
  include/internal/gdbus
)

# OP-TEE Client Include Directories
set(OPTEE_CLIENT_INCLUDE_DIRS
  kmppservice/ta/include
)

# TPM Client Include Directories
set(TPM_CLIENT_INCLUDE_DIRS
  kmppclient/tpm_client/include/internal
  tpm/include
)

# Service Include Directories
set(SERVICE_INCLUDE_DIRS
  kmppservice/include/internal
  kmppservice/include/internal/ossl
  kmppservice/include/internal/gdbus
)

if(KMPP_OPENSSL_3)
set(PROVIDER_INCLUDE_DIRS
    kmppprovider/include
)
endif()

include_directories(
  ${BASE_INCLUDE_DIRS}
  ${GDBUS_INCLUDE_DIRS}
  ${SERVICE_INCLUDE_DIRS} # Remove if in-process code is no longer needed
  ${PROVIDER_INCLUDE_DIRS}
)

# Add TPM or OP-TEE includes based on target
if(KMPP_GENERAL_PURPOSE_TARGET)
  include_directories(${TPM_CLIENT_INCLUDE_DIRS})
else()
  include_directories(${OPTEE_CLIENT_INCLUDE_DIRS})
endif()

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
  if(KMPP_GENERAL_PURPOSE_TARGET)  
    include_directories(
      /usr/include
      /usr/local/include)
  else()
    include_directories(
      /usr/include)
  endif()
endif()

set(kmpp_headers
  include/keyiso.h
  include/keyisomemory.h
  include/keyisocert.h
  include/keyisocurl.h
  include/keyisoutils.h
  kmppclient/include/keyisoclient.h
  kmppclient/include/keyisoctrlclient.h
  kmppclient/include/keyisopfxclient.h
  kmppclient/include/keyisosymmetrickeyclient.h
)

if(KMPP_OPENSSL_3)
  list(APPEND kmpp_headers kmppclient/include/keyisoclientprov.h)
endif()

install(
  FILES
    ${kmpp_headers}


  PERMISSIONS
    OWNER_READ
    OWNER_WRITE
    GROUP_READ
    WORLD_READ
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  COMPONENT Development)

# Common source files both for client and service side kmpp shared libs
set(common_src
  kmpplib/keyisobaselog.c
  kmpplib/keyisolog.c
  kmpplib/keyisosymcryptcommon.c
  kmpplib/keyisotelemetry.c
  kmpplib/keyisoutils.c
  kmpplib/kmppgdbusclientcommon.c
  kmpplib/kmppgdbusgenerated.c
  kmpplib/serialization/keyisoipccommonserialize.c
  kmpplib/serialization/keyisoipcprivatekeyserialization.c
)

if(KMPP_GENERAL_PURPOSE_TARGET)
  list(APPEND common_src
    kmpplib/keyisojsonutils.c
  )
endif()

set(ossl_src
  ${common_src} 
  kmpplib/ossl/keyisomemory.c 
  kmpplib/keyisocommonossl.c
  kmpplib/keyisocert.c
  kmpplib/keyisopbe.c
  kmpplib/keyisopkcs12.c
)

# Client side sources
set(kmpp_src
  ${ossl_src} 
  kmppclient/keyisoclientinit.c
  kmppclient/keyisoclient.c
  kmppclient/keyisoclientmsghandler.c
  kmppclient/keyisoclientpkcs8.c
  kmppclient/keyisoctrlclient.c
  kmppclient/keyisoipcclientadapter.c
  kmppclient/kmppipcutils.c
  kmpplib/kmppctrlgdbusgenerated.c
  kmpplib/kmppgdbusctrlclient.c
  kmpplib/keyisocurl.c   
  kmpplib/kmppgdbusclient.c
  kmpplib/kmppgdbuspfxclient.c
)

if(KMPP_GENERAL_PURPOSE_TARGET)
  list(APPEND kmpp_src  
    kmppclient/tpm_client/keyisotpmclientconfig.c
    kmppclient/tpm_client/keyisotpmclientpbe.c
    kmppclient/tpm_client/keyisotpmclientmsghandler.c)
else()
  list(APPEND kmpp_src
    kmppclient/optee_client/kmppopteeclient.c
    kmppclient/optee_client/keyisoopteeclientconfig.c
  )
endif()


if(KMPP_OPENSSL_3)
  list(APPEND kmpp_src kmppclient/keyisoclientprov.c)
else()
  list(APPEND kmpp_src kmppclient/keyisoclienteng.c)
endif()
# Service side sources
# The following files are required for inproc. 
# In-proc implementation involves IPC components.
set(kmpp_service_common_src
  # KeyIso_SERVER_* functions
  kmppservice/keyisoserviceapi.c
  kmppservice/keyisoservicecommon.c
  kmppservice/keyisoservicecrypto.c
  kmppservice/keyisoservicecryptosymcrypt.c
  kmppservice/keyisoservicekeygen.c
  kmppservice/keyisoservicesymmetrickey.c
  # IPC
  kmppservice/keyisoipcserviceadapter.c
  kmppservice/keyisoservicemsghandler.c
  kmppservice/keyisoserviceinprocmsghandler.c
  kmppservice/kmppgdbusmsghandler.c       # KeyIso_gdbus_handle_client_message
  kmppservice/keyisoservicekeylistgdbus.c # KeyIso_add_gdbus_sender_to_list

)

if (KMPP_GENERAL_PURPOSE_TARGET)
  list(APPEND kmpp_service_common_src
  kmppservice/keyisolrucache.c
  kmppservice/keyisoservicekeycache.c
  )
else()
  list(APPEND kmpp_service_common_src
  kmppservice/keylist/keyisoservicekeylist.c
)
endif()

set(kmpp_service_ossl_src
  ${ossl_src}
  ${kmpp_service_common_src}
  kmppservice/ossl/deprecatedServiceMessageHandler.c
  kmppservice/ossl/keyisoserviceapiossl.c 
)

macro(CreateLib lib_name obj shared_lib ossl_support)
  # message(" lib_name:${lib_name}\n obj:${obj}\n shared_lib:${shared_lib}\n ossl_support:${ossl_support}")
  set(lib_list ${ARGN})
  # message(" lib_list:${lib_list}\n")
  if(${ossl_support})
    target_compile_definitions(${obj} PRIVATE -DKMPP_OPENSSL_SUPPORT)
    
  endif()
  set_property(TARGET ${obj} PROPERTY POSITION_INDEPENDENT_CODE 1)
  add_library(${shared_lib} SHARED $<TARGET_OBJECTS:${obj}>)
  set_target_properties(${shared_lib} PROPERTIES OUTPUT_NAME ${lib_name} PREFIX "lib" SUFFIX ".so")
  target_link_libraries(${shared_lib} ${lib_list})
  if(NOT KMPP_GENERAL_PURPOSE_TARGET)
    target_link_libraries(${shared_lib} ${lib_list} teec)
  endif()
  set_target_properties(${shared_lib} PROPERTIES SOVERSION 1)
endmacro()

set(common_lib_list
  ${GLIB2_LIBRARIES}
  ${UUID_LIB}
  ${TINYCBOR_LIB}
  rt
)

if (KMPP_GENERAL_PURPOSE_TARGET)
  list(APPEND common_lib_list ${TSS2_LIBRARIES})
  list(APPEND common_lib_list ${JANSSON_LIBRARIES})
endif()

set(ossl_lib_list 
  ${common_lib_list}
  ${CRYPTO_LIB}
  ${SSL_LIB}
  ${CURL_LIB}
)

set(service_ossl_lib_list
  ${SYMCRYPT_LIB}
  ${ossl_lib_list}
)

set(service_lib_list
  ${SYMCRYPT_LIB}
  ${common_lib_list}
)

set(client_lib_list
  ${ossl_lib_list}
  ${DBUS_LIBRARIES}
)

if (KMPP_GENERAL_PURPOSE_TARGET)
  list(APPEND client_lib_list kmpp_tpm)
endif()

set(FUZZING_FLAGS "-g3 -fsanitize=fuzzer -fsanitize=address \
                  -fsanitize-coverage=inline-8bit-counters -fsanitize-coverage=trace-cmp -fsanitize-coverage=trace-div")

# Service side lib
add_library(kmpp_service_obj OBJECT ${kmpp_service_ossl_src})
CreateLib(kmppsrv kmpp_service_obj kmpp_service_shared TRUE ${service_ossl_lib_list})

if (KMPP_GENERAL_PURPOSE_TARGET AND KMPP_DEBUG)
  set_target_properties(kmpp_service_shared PROPERTIES COMPILE_FLAGS ${FUZZING_FLAGS})
 endif()
list(APPEND client_lib_list kmpp_service_shared)

# Client side lib - currently the client code is always dependend on OpenSSL 
add_library(kmpp_obj OBJECT ${kmpp_src})
CreateLib(kmpp kmpp_obj kmpp_shared TRUE ${client_lib_list})
if (KMPP_GENERAL_PURPOSE_TARGET AND KMPP_DEBUG)
  set_target_properties(kmpp_shared PROPERTIES COMPILE_FLAGS ${FUZZING_FLAGS})
endif()

# Create the shared library for the PFX engine
set(TARGETS_LIST
  kmpp_shared
  kmpp_service_shared
  )

install(TARGETS 
  ${TARGETS_LIST}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT Runtime
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT Runtime
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} COMPONENT Runtime
)

install(TARGETS 
  ${TARGETS_LIST}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT Client
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT Client
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} COMPONENT Client
)
add_library(kmpppfx SHARED
  kmpppfx/e_keyisopfx.c
  kmpppfx/e_keyisopfx_err.c
  kmpppfx/e_keyisosymmetric.c
  )
set_target_properties(kmpppfx
  PROPERTIES OUTPUT_NAME kmpppfx PREFIX "" SUFFIX ".so"
  )

target_link_libraries(kmpppfx kmpp_shared)
install(TARGETS kmpppfx 
		DESTINATION "${KMPP_OPENSSL_ENGINE_DIR}"
		COMPONENT Runtime)
install(TARGETS kmpppfx 
		DESTINATION "${KMPP_OPENSSL_ENGINE_DIR}"
		COMPONENT Client)

add_custom_target(list_engines
  COMMAND
    LD_LIBRARY_PATH=${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
    OPENSSL_ENGINES=${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
    ${OPENSSL_CLI} engine -tt -vvvv -c kmpppfx
  DEPENDS kmpppfx
  )

add_custom_target(simple_test
  DEPENDS list_engines
  )

add_executable(kmppexample
  example/test.c
  )

find_package(Threads REQUIRED) 
target_compile_definitions(kmppexample PRIVATE -DKMPP_OPENSSL_SUPPORT)
target_include_directories(kmppexample PRIVATE ${CMAKE_SOURCE_DIR}/example)
target_link_libraries(kmppexample Threads::Threads kmpp_shared)
install(TARGETS kmppexample 
		        DESTINATION ${CMAKE_INSTALL_BINDIR}
		        COMPONENT Test)



set(COVERAGE_EXCLUDES '*/bits/*' '*/openssl/*' '/usr/*' '*/tpm/*' '*gtest*' '*kmppgdbusservice*' '*deprecatedServiceMessageHandler*' '*keyisotpmclientmsghandler*' '*keyisotpmclientpbe*')
 add_custom_target(coverage
    COMMAND lcov --directory . --capture --output-file coverage.info 
    COMMAND lcov --remove coverage.info ${COVERAGE_EXCLUDES} --output-file coverage.info.cleaned
    COMMAND genhtml coverage.info.cleaned --output-directory coverage-report
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_subdirectory(kmppservice)
add_subdirectory(kmppctrlservice)
if(KMPP_OPENSSL_3)
    add_subdirectory(kmppprovider)
endif()


configure_file(scripts/kmpp.pc.in ${KMPP_USER_NAME}.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/${KMPP_USER_NAME}.pc 
		DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
		COMPONENT Runtime)
install(FILES ${CMAKE_BINARY_DIR}/${KMPP_USER_NAME}.pc 
		DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
		COMPONENT Client)

  # Initial set of certs in certs.pem.
install(FILES certs/certs.pem certs/certs.version 
		DESTINATION ${KMPP_INSTALL_IMAGE_DIR}
		COMPONENT Runtime)
install(FILES certs/certs.pem certs/certs.version 
		DESTINATION ${KMPP_INSTALL_IMAGE_DIR}
		COMPONENT Client)
install(FILES config.cnf
		DESTINATION ${CMAKE_INSTALL_PREFIX}/share/${KMPP_USER_NAME}
		COMPONENT Runtime)
install(FILES config.cnf 
		DESTINATION ${CMAKE_INSTALL_PREFIX}/share/${KMPP_USER_NAME}
		COMPONENT Client)

install(FILES NOTICE.txt DESTINATION ${CMAKE_INSTALL_PREFIX}/share/ COMPONENT Client)
install(FILES NOTICE.txt DESTINATION ${CMAKE_INSTALL_PREFIX}/share/ COMPONENT Runtime)

if (KMPP_GENERAL_PURPOSE_TARGET AND KMPP_INSTALL_FROM_SOURCES)
configure_file(scripts/install.sh.in install.sh)
install(CODE "execute_process(COMMAND /usr/bin/bash install.sh)")
endif()

# uninstall target
if(NOT TARGET uninstall AND KMPP_INSTALL_FROM_SOURCES)
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

  configure_file(scripts/uninstall.sh.in uninstall.sh)

  add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif() 


###########################################################################################
######################################## PACKAGING ########################################
###########################################################################################

#------------------------------------------------------------------------------------------
# Generic Package Settings
#------------------------------------------------------------------------------------------
set(CPACK_PACKAGE_NAME "kmpp")
if(KMPP_RUNNING_ON_CONTAINERS)
  set(CPACK_PACKAGE_NAME "kmpp-containers")
endif()
set(CPACK_PACKAGE_VENDOR "Microsoft Corp")
set(CPACK_PACKAGE_CONTACT "Microsoft Corp")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Key Material and Protection Platform")
set(CPACK_PACKAGE_DESCRIPTION "Private Key Material and Protection Platform for Key Isolation in general purpose Linux environments")

set(PACKAGE_VERSION "${ENV_PACKAGE_VERSION}")

set(CPACK_PACKAGE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/Packaging")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")


set(AGENT_ROOT_DIR "/var/msft")

set(SYSTEMD_UNITS_DIR "${CMAKE_INSTALL_PREFIX}/lib/systemd")
set(SYSTEMD_SYSTEM_DIR "${SYSTEMD_UNITS_DIR}/system")
set(SYSTEMD_PRESET_DIR "${SYSTEMD_UNITS_DIR}/system-preset")

set(CPACK_COMPONENTS_ALL Runtime Development Test Client)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/scripts/preinst.in ${CMAKE_CURRENT_SOURCE_DIR}/scripts/preinst @ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/scripts/postinst.in ${CMAKE_CURRENT_SOURCE_DIR}/scripts/postinst @ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/scripts/prerm.in ${CMAKE_CURRENT_SOURCE_DIR}/scripts/prerm @ONLY)

#------------------------------------------------------------------------------------------
# RPM Package
#------------------------------------------------------------------------------------------

#set(CPACK_RPM_PACKAGE_REQUIRES "openssl (>= 1.1.1), curl, glib-2.0, dbus, systemd, uuid")
set(CPACK_RPM_PACKAGE_VERSION "${ENV_PACKAGE_VERSION}")

set(CPACK_RPM_COMPONENT_INSTALL ON)
set(CPACK_RPM_MAIN_COMPONENT Runtime)

set(CPACK_RPM_Development_PACKAGE_NAME "${CPACK_PACKAGE_NAME}-devel")
set(CPACK_RPM_Development_PACKAGE_SUMMARY
    "Development files for ${CPACK_PACKAGE_NAME}")

set(CPACK_RPM_Test_PACKAGE_NAME "${CPACK_PACKAGE_NAME}-test")
set(CPACK_RPM_Test_PACKAGE_SUMMARY
    "Test files for ${CPACK_PACKAGE_NAME}")

set(CPACK_RPM_Telemetry_PACKAGE_NAME "${CPACK_PACKAGE_NAME}-telemetry")
set(CPACK_RPM_Telemetry_PACKAGE_SUMMARY
    "Configuration files for ${CPACK_PACKAGE_NAME}")

set(CPACK_RPM_Client_PACKAGE_NAME "${CPACK_PACKAGE_NAME}-client")
set(CPACK_RPM_Client_PACKAGE_SUMMARY
    "Client files for ${CPACK_PACKAGE_NAME}")
	
set(CPACK_RPM_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_RPM_PACKAGE_VERSION}.${CMAKE_SYSTEM_PROCESSOR}.rpm")
set(CPACK_RPM_Development_FILE_NAME "${CPACK_RPM_Development_PACKAGE_NAME}-${CPACK_RPM_PACKAGE_VERSION}.${CMAKE_SYSTEM_PROCESSOR}.rpm")
set(CPACK_RPM_Test_FILE_NAME "${CPACK_RPM_Test_PACKAGE_NAME}-${CPACK_RPM_PACKAGE_VERSION}.${CMAKE_SYSTEM_PROCESSOR}.rpm")
set(CPACK_RPM_Client_FILE_NAME "${CPACK_RPM_Client_PACKAGE_NAME}-${CPACK_RPM_PACKAGE_VERSION}.${CMAKE_SYSTEM_PROCESSOR}.rpm")
set(CPACK_RPM_Telemetry_FILE_NAME "${CPACK_RPM_Telemetry_PACKAGE_NAME}-${CPACK_RPM_PACKAGE_VERSION}.${CMAKE_SYSTEM_PROCESSOR}.rpm")

set(CPACK_RPM_Runtime_USER_FILELIST
	"%attr(755,root,root) ${AGENT_ROOT_DIR}"
	"%attr(755,root,root) ${AGENT_ROOT_DIR}/kmpp"
	"%attr(755,root,root) ${SYSTEMD_UNITS_DIR}"
	"%attr(755,root,root) ${SYSTEMD_PRESET_DIR}"
	"%attr(755,root,root) ${KMPP_INSTALL_IMAGE_DIR}"
	"%attr(644,root,root) ${KMPP_INSTALL_IMAGE_DIR}/certs.version"
	"%attr(444,root,root) ${KMPP_INSTALL_IMAGE_DIR}/certs.pem"
  "%attr(444,root,root) ${CMAKE_INSTALL_PREFIX}/share/${KMPP_USER_NAME}/config.cnf"
  "%attr(444,root,root) ${SYSTEMD_SYSTEM_DIR}/${KMPP_USER_NAME}.slice"
	"%attr(444,root,root) ${SYSTEMD_SYSTEM_DIR}/dbus-com.microsoft.kmpp.service"
	"%attr(444,root,root) ${SYSTEMD_SYSTEM_DIR}/dbus-com.microsoft.kmppctrl.service"
	"%config ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/pkgconfig/${KMPP_USER_NAME}.pc")

if(KMPP_GENERAL_PURPOSE_TARGET)
	list(APPEND CPACK_RPM_Runtime_USER_FILELIST "%attr(444,root,root) ${SYSTEMD_SYSTEM_DIR}/dbus-com.microsoft.kmpp.service.tpm")
endif()

set(CPACK_RPM_Runtime_PRE_INSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/scripts/preinst")
set(CPACK_RPM_Runtime_POST_INSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/scripts/postinst")
set(CPACK_RPM_Runtime_PRE_UNINSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/scripts/prerm")

list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "/var")

list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${SYSTEMD_SYSTEM_DIR}")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${SYSTEMD_PRESET_DIR}")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CMAKE_INSTALL_PREFIX}/share/dbus-1")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CMAKE_INSTALL_PREFIX}/share/dbus-1/services")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CMAKE_INSTALL_PREFIX}/share/dbus-1/system-services")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CMAKE_INSTALL_PREFIX}/share/dbus-1/system.d")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/pkgconfig")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/${OPENSSL_VERSION}")

#------------------------------------------------------------------------------------------
# Deb Package
#------------------------------------------------------------------------------------------

set(CPACK_DEBIAN_PACKAGE_RELEASE 1)
set(CPACK_DEBIAN_PACKAGE_VERSION "${ENV_PACKAGE_VERSION}")
set(CPACK_DEBIAN_RUNTIME_PACKAGE_CONTROL_EXTRA
    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/preinst;${CMAKE_CURRENT_SOURCE_DIR}/scripts/postinst;${CMAKE_CURRENT_SOURCE_DIR}/scripts/prerm")
	
set(CPACK_DEB_COMPONENT_INSTALL ON)

    
if(OS_RELEASE MATCHES "Ubuntu")
    # Extract version ID (e.g., "20.04", "22.04")
    string(REGEX MATCH "VERSION_ID=\"([0-9]+)\\.([0-9]+)\"" _ ${OS_RELEASE})
    set(OS_VERSION "${CMAKE_MATCH_1}.${CMAKE_MATCH_2}")

    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libatomic1, symcrypt, libjansson4")
    # Ubuntu 22.x specific dependencies
    if(OS_VERSION VERSION_GREATER_EQUAL "22.04")
      set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libtss2-esys-3.0.2-0, libtss2-rc0, libtss2-fapi1")
    endif()
endif()
      
#Note that <COMPONENT> in CPACK_DEBIAN_<COMPONENT>_XXXX variables refers to the grouping name written in upper case.
set(CPACK_DEBIAN_RUNTIME_PACKAGE_NAME "lib${CPACK_PACKAGE_NAME}")
set(CPACK_DEBIAN_RUNTIME_DESCRIPTION "Development files for ${CPACK_PACKAGE_NAME}")
set(CPACK_DEBIAN_RUNTIME_FILE_NAME "${CPACK_DEBIAN_RUNTIME_PACKAGE_NAME}-${CPACK_DEBIAN_PACKAGE_VERSION}.${CMAKE_SYSTEM_PROCESSOR}.deb")
set(CPACK_DEBIAN_DEVELOPMENT_PACKAGE_NAME "lib${CPACK_PACKAGE_NAME}-dev")
set(CPACK_DEBIAN_DEVELOPMENT_DESCRIPTION "Development files for ${CPACK_PACKAGE_NAME}")
set(CPACK_DEBIAN_DEVELOPMENT_FILE_NAME "${CPACK_DEBIAN_DEVELOPMENT_PACKAGE_NAME}-${CPACK_DEBIAN_PACKAGE_VERSION}.${CMAKE_SYSTEM_PROCESSOR}.deb")
set(CPACK_DEBIAN_TEST_PACKAGE_NAME "lib${CPACK_PACKAGE_NAME}-test")
set(CPACK_DEBIAN_TEST_DESCRIPTION "Test files for ${CPACK_PACKAGE_NAME}")
set(CPACK_DEBIAN_TEST_FILE_NAME "${CPACK_DEBIAN_TEST_PACKAGE_NAME}-${CPACK_DEBIAN_PACKAGE_VERSION}.${CMAKE_SYSTEM_PROCESSOR}.deb")
set(CPACK_DEBIAN_CLIENT_PACKAGE_NAME "lib${CPACK_PACKAGE_NAME}-client")
set(CPACK_DEBIAN_CLIENT_DESCRIPTION "${CPACK_PACKAGE_NAME} client components")
set(CPACK_DEBIAN_CLIENT_FILE_NAME "${CPACK_DEBIAN_CLIENT_PACKAGE_NAME}-${CPACK_DEBIAN_PACKAGE_VERSION}.${CMAKE_SYSTEM_PROCESSOR}.deb")
set(CPACK_DEBIAN_TELEMETRY_PACKAGE_NAME "lib${CPACK_PACKAGE_NAME}-telemetry")
set(CPACK_DEBIAN_TELEMETRY_DESCRIPTION "Telemetry files for ${CPACK_PACKAGE_NAME}")
set(CPACK_DEBIAN_TELEMETRY_FILE_NAME "${CPACK_DEBIAN_TELEMETRY_PACKAGE_NAME}-${CPACK_DEBIAN_PACKAGE_VERSION}.${CMAKE_SYSTEM_PROCESSOR}.deb")


#------------------------------------------------------------------------------------------
# Include Package
#------------------------------------------------------------------------------------------
include(CPack)
