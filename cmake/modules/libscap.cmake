include(CompilerFlags)

if(NOT LIBSCAP_DIR)
	get_filename_component(LIBSCAP_DIR ${CMAKE_CURRENT_LIST_DIR}/../.. ABSOLUTE)
endif()

include(ExternalProject)

option(USE_BUNDLED_DEPS "Enable bundled dependencies instead of using the system ones" ON)

if(NOT MINIMAL_BUILD)
	include(zlib)
endif() # MINIMAL_BUILD

add_definitions(-DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")

get_filename_component(DRIVER_CONFIG_DIR ${CMAKE_BINARY_DIR}/driver/src ABSOLUTE)
get_filename_component(LIBSCAP_INCLUDE_DIR ${LIBSCAP_DIR}/userspace/libscap ABSOLUTE)
set(LIBSCAP_INCLUDE_DIRS ${LIBSCAP_INCLUDE_DIR} ${DRIVER_CONFIG_DIR})

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	if(CMAKE_BUILD_TYPE STREQUAL "Debug")
		set(KBUILD_FLAGS "${SYSDIG_DEBUG_FLAGS}")
	else()
		set(KBUILD_FLAGS "")
	endif()

	if(NOT DEFINED PROBE_VERSION)
		set(PROBE_VERSION "${SYSDIG_VERSION}")
	endif()
	if(NOT DEFINED PROBE_NAME)
		set(PROBE_NAME "sysdig-probe")
	endif()

	if(NOT DEFINED PROBE_DEVICE_NAME)
		set(PROBE_DEVICE_NAME "sysdig")
	endif()

	add_definitions(-DHAS_CAPTURE)
	add_subdirectory(${LIBSCAP_DIR}/driver ${CMAKE_BINARY_DIR}/driver)
endif()

add_subdirectory(${LIBSCAP_DIR}/userspace/libscap ${CMAKE_BINARY_DIR}/libscap)

get_directory_property(hasParent PARENT_DIRECTORY)
if(hasParent)
	set(LIBSCAP_INCLUDE_DIRS ${LIBSCAP_INCLUDE_DIRS} PARENT_SCOPE)
	set(DRIVER_CONFIG_DIR ${DRIVER_CONFIG_DIR} PARENT_SCOPE)
endif()
