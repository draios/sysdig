if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(KBUILD_FLAGS "${SYSDIG_DEBUG_FLAGS} ${SYSDIG_FEATURE_FLAGS}")
else()
	set(KBUILD_FLAGS "${SYSDIG_FEATURE_FLAGS}")
endif()

add_custom_target(driver ALL
	COMMAND sed -i 's/^PACKAGE_VERSION=.*/PACKAGE_VERSION="${SYSDIG_VERSION}"/g' dkms.conf
	COMMAND sed -i 's/^DKMS_VERSION=.*/DKMS_VERSION="${SYSDIG_VERSION}"/g' ${PROJECT_SOURCE_DIR}/scripts/debian/postinst
	COMMAND sed -i 's/^DKMS_VERSION=.*/DKMS_VERSION="${SYSDIG_VERSION}"/g' ${PROJECT_SOURCE_DIR}/scripts/debian/prerm
	COMMAND sed -i 's/^ccflags-y := .*/ccflags-y := ${KBUILD_FLAGS}/g' Makefile
	COMMAND make
	WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/driver)

install(FILES
	Makefile
	dkms.conf
	event_table.c
	main.c
	ppm.h
	ppm_events.c
	ppm_events.h
	ppm_events_public.h
	ppm_fillers.c
	ppm_ringbuffer.h
	ppm_types.h
	syscall_info_table.c
	syscall_table.c
	DESTINATION ${SYSDIG_SRC_PREFIX}/
	COMPONENT agent)
