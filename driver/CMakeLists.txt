option(BUILD_DRIVER "Build the driver on Linux" ON)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(KBUILD_FLAGS "${SYSDIG_DEBUG_FLAGS} ${SYSDIG_FEATURE_FLAGS}")
else()
	set(KBUILD_FLAGS "${SYSDIG_FEATURE_FLAGS}")
endif()

configure_file(dkms.conf.in dkms.conf)
configure_file(Makefile.in Makefile.dkms)

set(GENERATED_FILES
	event_info.inc
	event_type.inc
	flags.inc
	flags.h
	ppm_events.inc
	syscall_table.inc
)

set(CLEAN_FILES
	"${CMAKE_CURRENT_SOURCE_DIR}/Makefile")

foreach(generated_file ${GENERATED_FILES})
	set(CLEAN_FILES "${CLEAN_FILES} ${CMAKE_CURRENT_SOURCE_DIR}/${generated_file}")
endforeach()

set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${CLEAN_FILES}")

# This if/else is needed because you currently cannot manipulate dependencies
# of built-in targets like "all" in CMake:
# http://public.kitware.com/Bug/view.php?id=8438
if(BUILD_DRIVER)
	add_custom_target(driver ALL
		DEPENDS generate_event_files
		COMMAND cp -f ${CMAKE_CURRENT_BINARY_DIR}/Makefile.dkms Makefile
		COMMAND $(MAKE)
		COMMAND cp -f sysdig-probe.ko "${CMAKE_CURRENT_BINARY_DIR}"
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
		VERBATIM)
else()
	add_custom_target(driver
		DEPENDS generate_event_files
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

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/Makefile.dkms
	RENAME Makefile
	DESTINATION "src/sysdig-${SYSDIG_VERSION}")

install(FILES
	${CMAKE_CURRENT_BINARY_DIR}/dkms.conf
	event_table.c
	flags_table.c
	main.c
	ppm.h
	ppm_events.c
	ppm_events.h
	ppm_events_public.h
	ppm_fillers.c
	ppm_ringbuffer.h
	syscall_table.c
	${GENERATED_FILES}
	DESTINATION "src/sysdig-${SYSDIG_VERSION}")
