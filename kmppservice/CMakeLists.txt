# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/service)


set(kmpp_service_exe_src
    kmppgdbusservice.c
)

if(KMPP_OPENSSL_SUPPORT)
  list(APPEND kmpp_service_exe_src ossl/deprecatedServiceMessageHandler.c)
endif()

add_executable(${KMPP_USER_NAME}service ${kmpp_service_exe_src})

if(KMPP_OPENSSL_SUPPORT)
  target_compile_definitions(${KMPP_USER_NAME}service PRIVATE
     -DKMPP_OPENSSL_SUPPORT
)
endif()

target_link_libraries(${KMPP_USER_NAME}service
  kmpp_service_shared
  )

configure_file(
  com.microsoft.kmpp.conf.in
  ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${KMPP_BUS_NAME}.conf
  @ONLY)

configure_file(
  com.microsoft.kmpp.service.in
  ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${KMPP_BUS_NAME}.service
  @ONLY)

configure_file(
  kmpp.slice.in
  ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${KMPP_USER_NAME}.slice
  @ONLY)

if(KMPP_GENERAL_PURPOSE_TARGET)
  set(KMPP_SYSTEMD_WANTEDBY "multi-user.target")
else()
  set(KMPP_SYSTEMD_WANTEDBY "agents.target")
endif()

if(KMPP_IS_SOC)
  configure_file(
    dbus-com.microsoft.kmpp.service.soc.in
    ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/dbus-${KMPP_BUS_NAME}.service
    @ONLY)
else()
  configure_file(
    dbus-com.microsoft.kmpp.service.in
    ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/dbus-${KMPP_BUS_NAME}.service
    @ONLY)
    if(KMPP_GENERAL_PURPOSE_TARGET)
       configure_file(
        dbus-com.microsoft.kmpp.service.tpm.in
        ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/dbus-${KMPP_BUS_NAME}.service.tpm
        @ONLY)
    endif()
endif()

target_compile_options(${KMPP_USER_NAME}service PRIVATE -fPIE)
set_target_properties(${KMPP_USER_NAME}service PROPERTIES LINK_FLAGS "-Wl,-pie")

include_directories(
  kmppservice/include
  kmppservice/include/internal
  kmppservice/include/internal/ossl
  kmppservice/include/internal/gdbus
  )

install(
  TARGETS ${KMPP_USER_NAME}service 
  DESTINATION ${CMAKE_INSTALL_BINDIR}
  COMPONENT Runtime
  )
install(
  FILES ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${KMPP_BUS_NAME}.service
  DESTINATION share/dbus-1/services
  COMPONENT Runtime
  )
install(
  FILES ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${KMPP_BUS_NAME}.service
  DESTINATION share/dbus-1/system-services
  COMPONENT Runtime
  )
install(
  FILES ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${KMPP_BUS_NAME}.conf
  DESTINATION share/dbus-1/system.d
  COMPONENT Runtime
  )
if(KMPP_INSTALL_SERVICE)
  install(
    FILES ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/dbus-${KMPP_BUS_NAME}.service
    DESTINATION lib/systemd/system/
	  COMPONENT Runtime
    )
    if(KMPP_GENERAL_PURPOSE_TARGET)
      install(
        FILES ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/dbus-${KMPP_BUS_NAME}.service.tpm
        DESTINATION lib/systemd/system/
	      COMPONENT Runtime
      )
    endif()
  install(
    FILES ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${KMPP_USER_NAME}.slice
    DESTINATION lib/systemd/system/
	  COMPONENT Runtime
    )

  # Install the preset file as part of the service installation only for general purpose targets
  # Not general purpose targets are expected to have their own preset file
  if(KMPP_GENERAL_PURPOSE_TARGET)
    install(
      FILES 50-dbus-com.microsoft.kmpp.preset
      DESTINATION lib/systemd/system-preset
      COMPONENT Runtime
      )
  endif()
endif()