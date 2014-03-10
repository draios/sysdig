if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(KBUILD_FLAGS "${SYSDIG_DEBUG_FLAGS} ${SYSDIG_FEATURE_FLAGS}")
else()
	set(KBUILD_FLAGS "${SYSDIG_FEATURE_FLAGS}")
endif()

add_custom_target(driver ALL
	COMMAND sed -i 's/^PACKAGE_VERSION=.*/PACKAGE_VERSION="${SYSDIG_VERSION}"/g' dkms.conf
	COMMAND sed -i 's/^DKMS_VERSION=.*/DKMS_VERSION="${SYSDIG_VERSION}"/g' ../scripts/debian/postinst
	COMMAND sed -i 's/^DKMS_VERSION=.*/DKMS_VERSION="${SYSDIG_VERSION}"/g' ../scripts/debian/prerm
	COMMAND sed -i 's/^ccflags-y := .*/ccflags-y := ${KBUILD_FLAGS}/g' Makefile
	COMMAND make
	COMMAND cp -f sysdig-probe.ko ${CMAKE_CURRENT_BINARY_DIR}
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

install(FILES
	Makefile
	dkms.conf
	event_table.c
	flags_table.c
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
	DESTINATION "src/sysdig-${SYSDIG_VERSION}")
