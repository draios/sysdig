option(BUILD_DRIVER "Build the driver on Linux" ON)
option(ENABLE_DKMS "Enable DKMS on Linux" ON)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(KBUILD_FLAGS "${SYSDIG_DEBUG_FLAGS} ${SYSDIG_FEATURE_FLAGS}")
else()
	set(KBUILD_FLAGS "${SYSDIG_FEATURE_FLAGS}")
endif()

configure_file(dkms.conf.in dkms.conf)
configure_file(Makefile.in Makefile.dkms)

set(CLEAN_FILES
	"${CMAKE_CURRENT_SOURCE_DIR}/Makefile")

set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${CLEAN_FILES}")

# This if/else is needed because you currently cannot manipulate dependencies
# of built-in targets like "all" in CMake:
# http://public.kitware.com/Bug/view.php?id=8438
if(BUILD_DRIVER)
	add_custom_target(driver ALL
		COMMAND cp -f ${CMAKE_CURRENT_BINARY_DIR}/Makefile.dkms Makefile
		COMMAND $(MAKE)
		COMMAND cp -f sysdig-probe.ko "${CMAKE_CURRENT_BINARY_DIR}"
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
		VERBATIM)
else()
	add_custom_target(driver
		COMMAND cp -f ${CMAKE_CURRENT_BINARY_DIR}/Makefile.dkms Makefile
		COMMAND $(MAKE)
		COMMAND cp -f sysdig-probe.ko "${CMAKE_CURRENT_BINARY_DIR}"
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
		VERBATIM)
endif()

add_custom_target(install_driver
	COMMAND $(MAKE) install
	DEPENDS driver
	WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
	VERBATIM)

if(ENABLE_DKMS)
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/Makefile.dkms
		RENAME Makefile
		DESTINATION "src/sysdig-${SYSDIG_VERSION}")

	install(FILES
		${CMAKE_CURRENT_BINARY_DIR}/dkms.conf
		dynamic_params_table.c
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
		DESTINATION "src/sysdig-${SYSDIG_VERSION}")
endif()
