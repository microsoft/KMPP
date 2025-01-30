# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/service)

add_executable(${KMPP_USER_NAME}ctrlservice
  keyisoctrlservice.c
  )
target_link_libraries(${KMPP_USER_NAME}ctrlservice
  kmpp_shared
  )

configure_file(
  com.microsoft.kmppctrl.service.in
  ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${KMPPCTRL_BUS_NAME}.service
  @ONLY)

configure_file(
  dbus-com.microsoft.kmppctrl.service.in
  ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/dbus-${KMPPCTRL_BUS_NAME}.service
  @ONLY)

if(NOT KMPPCTRL_DEFAULT_POLICY)
  set(KMPPCTRL_DEFAULT_POLICY "deny")
endif()
configure_file(
  com.microsoft.kmppctrl.conf.in
  ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${KMPPCTRL_BUS_NAME}.conf
  @ONLY)

target_compile_options(${KMPP_USER_NAME}ctrlservice PRIVATE -fPIE)
set_target_properties(${KMPP_USER_NAME}ctrlservice PROPERTIES LINK_FLAGS "-Wl,-pie")

install(
  TARGETS ${KMPP_USER_NAME}ctrlservice 
  DESTINATION ${CMAKE_INSTALL_BINDIR}
  COMPONENT Runtime
  )
install(
  FILES ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${KMPPCTRL_BUS_NAME}.service
  DESTINATION share/dbus-1/services
  COMPONENT Runtime
  )
install(
  FILES ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${KMPPCTRL_BUS_NAME}.service
  DESTINATION share/dbus-1/system-services
  COMPONENT Runtime
  )
install(
  FILES ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${KMPPCTRL_BUS_NAME}.conf
  DESTINATION share/dbus-1/system.d
  COMPONENT Runtime
  )

if(KMPP_INSTALL_SERVICE)
  install(
    FILES ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/dbus-${KMPPCTRL_BUS_NAME}.service
    DESTINATION lib/systemd/system/
	COMPONENT Runtime
    )

  # Install the preset file as part of the service installation only for general purpose targets
  # Not general purpose targets are expected to have their own preset file
  if(KMPP_GENERAL_PURPOSE_TARGET)
    install(
      FILES 50-dbus-com.microsoft.kmppctrl.preset
      DESTINATION lib/systemd/system-preset
      COMPONENT Runtime
      )
  endif()   
endif()
