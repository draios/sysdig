option(BUILD_DRIVER "Build the driver on Linux" ON)
option(ENABLE_DKMS "Enable DKMS on Linux" ON)

configure_file(dkms.conf.in dkms.conf)
configure_file(Makefile.in Makefile.dkms)
configure_file(driver_config.h.in driver_config.h)
configure_file(driver_config.h.in "${CMAKE_CURRENT_SOURCE_DIR}/driver_config.h")

set(CLEAN_FILES
	"${CMAKE_CURRENT_SOURCE_DIR}/Makefile"
	"${CMAKE_CURRENT_SOURCE_DIR}/driver_config.h")

set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${CLEAN_FILES}")

add_custom_target(configure_driver ALL
	COMMAND "${CMAKE_COMMAND}" -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/driver_config.h driver_config.h
	WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
	VERBATIM)

# make can be self-referenced as $(MAKE) only from Makefiles but this
# triggers syntax errors with other generators such as Ninja
if(${CMAKE_GENERATOR} STREQUAL "Unix Makefiles")
	set(MAKE_COMMAND "$(MAKE)")
else()
	set(MAKE_COMMAND "make")
endif()

# This if/else is needed because you currently cannot manipulate dependencies
# of built-in targets like "all" in CMake:
# http://public.kitware.com/Bug/view.php?id=8438
if(BUILD_DRIVER)
	add_custom_target(driver ALL
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/Makefile.dkms Makefile
		COMMAND ${MAKE_COMMAND}
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different ${PROBE_NAME}.ko "${CMAKE_CURRENT_BINARY_DIR}"
		DEPENDS configure_driver
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
		VERBATIM)
else()
	add_custom_target(driver
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/Makefile.dkms Makefile
		COMMAND ${MAKE_COMMAND}
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different ${PROBE_NAME}.ko "${CMAKE_CURRENT_BINARY_DIR}"
		DEPENDS configure_driver
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
		VERBATIM)
endif()

add_custom_target(install_driver
	COMMAND ${MAKE_COMMAND} install
	DEPENDS driver
	WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
	VERBATIM)

if(ENABLE_DKMS)
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/Makefile.dkms
		RENAME Makefile
		DESTINATION "src/${PACKAGE_NAME}-${PROBE_VERSION}"
		COMPONENT agent)

	install(FILES
		${CMAKE_CURRENT_BINARY_DIR}/dkms.conf
		dynamic_params_table.c
		driver_config.h
		event_table.c
		flags_table.c
		main.c
		ppm.h
		ppm_events.c
		ppm_events.h
		ppm_events_public.h
		ppm_fillers.c
		ppm_ringbuffer.h
		ppm_syscall.h
		syscall_table.c
		ppm_cputime.c
		ppm_compat_unistd_32.h
		DESTINATION "src/${PACKAGE_NAME}-${PROBE_VERSION}"
		COMPONENT agent)
endif()
