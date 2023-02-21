#
# Copyright (C) 2013-2018 Draios Inc dba Sysdig.
#
# This file is part of sysdig .
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Prior to doing anything, we make sure that we aren't trying to
# run cmake in-tree. (see Issue 71: https://github.com/draios/sysdig/issues/71)
if(EXISTS ${CMAKE_CURRENT_BINARY_DIR}/CMakeLists.txt)
	message(FATAL_ERROR
		"Looks like you are trying to run cmake from the base sysdig source directory.\n"
		"** RUNNING CMAKE FROM THE BASE SYSDIG DIRECTORY WILL NOT WORK **\n"
		"To Fix:\n"
		" 1. Remove the CMakeCache.txt file in this directory. ex: rm CMakeCache.txt\n"
		" 2. Create a build directory from here. ex: mkdir build\n"
		" 3. cd into that directory. ex: cd build\n"
		" 4. Run cmake from the build directory. ex: cmake ..\n"
		" 5. Run make from the build directory. ex: make\n"
		"Full paste-able example:\n"
		"( rm -f CMakeCache.txt; mkdir build; cd build; cmake ..; make )\n"
		"The following wiki page has more information on manually building sysdig: http://bit.ly/1oJ84UI")
endif()

cmake_minimum_required(VERSION 2.8.2)

project(sysdig)

option(MINIMAL_BUILD "Produce a minimal sysdig binary with only the essential features (no eBPF probe driver, no kubernetes, no mesos, no marathon and no container metadata)" OFF)
option(MUSL_OPTIMIZED_BUILD "Enable if you want a musl optimized build" OFF)
option(USE_BUNDLED_DEPS "Enable bundled dependencies instead of using the system ones" ON)

# Add path for custom CMake modules.
list(APPEND CMAKE_MODULE_PATH
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

if(NOT DEFINED SYSDIG_VERSION)
	set(SYSDIG_VERSION "0.0.0-dev")
endif()

if(${SYSDIG_VERSION} STREQUAL "dev")
	set(SYSDIG_VERSION "0.0.0-dev")
endif()

if(NOT DEFINED DIR_ETC)
	set(DIR_ETC "${CMAKE_INSTALL_PREFIX}/etc")
endif()

if(NOT CMAKE_BUILD_TYPE)
	SET(CMAKE_BUILD_TYPE Release)
endif()

set(PACKAGE_NAME "sysdig")

add_definitions(-DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")

option(BUILD_WARNINGS_AS_ERRORS "Enable building with -Wextra -Werror flags")

if(APPLE)
	set(MINIMAL_BUILD ON)
endif()

if(MINIMAL_BUILD)
  set(MINIMAL_BUILD_FLAGS "-DMINIMAL_BUILD")
endif()

if(MUSL_OPTIMIZED_BUILD)
	set(SYSDIG_MUSL_FLAGS "-static -Os")
endif()

if(NOT WIN32)

	set(SYSDIG_DEBUG_FLAGS "-D_DEBUG")
	set(CMAKE_COMMON_FLAGS "-Wall -ggdb ${MINIMAL_BUILD_FLAGS} ${SYSDIG_MUSL_FLAGS}")

	if(BUILD_WARNINGS_AS_ERRORS)
		set(CMAKE_SUPPRESSED_WARNINGS "-Wno-unused-parameter -Wno-missing-field-initializers -Wno-sign-compare -Wno-type-limits -Wno-implicit-fallthrough -Wno-format-truncation")
		set(CMAKE_COMMON_FLAGS "${CMAKE_COMMON_FLAGS} -Wextra -Werror ${CMAKE_SUPPRESSED_WARNINGS}")
	endif()

	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_COMMON_FLAGS}")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_COMMON_FLAGS} -std=c++0x")

	set(CMAKE_C_FLAGS_DEBUG "${SYSDIG_DEBUG_FLAGS}")
	set(CMAKE_CXX_FLAGS_DEBUG "${SYSDIG_DEBUG_FLAGS}")

	set(CMAKE_C_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")
	set(CMAKE_CXX_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")

	if(CMAKE_SYSTEM_NAME MATCHES "Linux")
		if(CMAKE_BUILD_TYPE STREQUAL "Debug")
			set(KBUILD_FLAGS "${SYSDIG_DEBUG_FLAGS} ${SYSDIG_FEATURE_FLAGS}")
		else()
			set(KBUILD_FLAGS "${SYSDIG_FEATURE_FLAGS}")
		endif()

		set(SCAP_HOST_ROOT_ENV_VAR_NAME "HOST_ROOT")
		set(DRIVER_PACKAGE_NAME "scap")

		add_definitions(-DHAS_CAPTURE)
	endif()

	if(CMAKE_SYSTEM_NAME MATCHES "SunOS")
		set(CMD_MAKE gmake)
	else()
		set(CMD_MAKE make)
	endif()

else()
	set(MINIMAL_BUILD ON)

	set(SYSDIG_FLAGS_WIN "-D_CRT_SECURE_NO_WARNINGS -DWIN32 -DMINIMAL_BUILD /EHsc /W3 /Zi")
	set(SYSDIG_FLAGS_WIN_DEBUG "/MTd /Od")
	set(SYSDIG_FLAGS_WIN_RELEASE "/MT")

	set(CMAKE_C_FLAGS "${SYSDIG_FLAGS_WIN}")
	set(CMAKE_CXX_FLAGS "${SYSDIG_FLAGS_WIN}")

	set(CMAKE_C_FLAGS_DEBUG "${SYSDIG_FLAGS_WIN_DEBUG}")
	set(CMAKE_CXX_FLAGS_DEBUG "${SYSDIG_FLAGS_WIN_DEBUG}")

	set(CMAKE_C_FLAGS_RELEASE "${SYSDIG_FLAGS_WIN_RELEASE}")
	set(CMAKE_CXX_FLAGS_RELEASE "${SYSDIG_FLAGS_WIN_RELEASE}")
endif()

# Modern BPF is not supported on not Linux systems and in MINIMAL_BUILD
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	option(BUILD_SYSDIG_MODERN_BPF "Build modern BPF support for Sysdig" OFF)
	if(BUILD_SYSDIG_MODERN_BPF)
		add_definitions(-DHAS_MODERN_BPF)
	endif()
endif()

if(NOT DEFINED SYSDIG_COMPONENT_NAME)
    set(SYSDIG_COMPONENT_NAME "${CMAKE_PROJECT_NAME}")
endif()

include(falcosecurity-libs)
include(yaml-cpp)
include(nlohmann-json)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	if(NOT DEFINED DRIVER_VERSION)
		set(DRIVER_VERSION "${FALCOSECURITY_LIBS_VERSION}")
	endif()

	if(NOT DEFINED DRIVER_NAME)
		set(DRIVER_NAME "scap")
	endif()

	set(DRIVERS_REPO "https://download.sysdig.com/scap-drivers")
	
	# If no path is provided, try to search the BPF probe in: `home/.falco/falco-bpf.o`
	# This is the same fallback that we had in the libraries: `SCAP_PROBE_BPF_FILEPATH`.
	set(SYSDIG_PROBE_BPF_FILEPATH ".${DRIVER_NAME}/${DRIVER_NAME}-bpf.o")
	add_definitions(-DSYSDIG_PROBE_BPF_FILEPATH="${SYSDIG_PROBE_BPF_FILEPATH}")

	add_subdirectory(scripts)
endif()

add_subdirectory(userspace/sysdig)

set(CPACK_PACKAGE_NAME "${PACKAGE_NAME}")
set(CPACK_PACKAGE_VENDOR "Sysdig Inc.")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "sysdig, a system-level exploration and troubleshooting tool")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/scripts/description.txt")
set(CPACK_PACKAGE_VERSION "${SYSDIG_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_PROJECT_CONFIG_FILE "${PROJECT_SOURCE_DIR}/CMakeCPackOptions.cmake")
set(CPACK_STRIP_FILES "ON")

if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
	set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
endif()
if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
	set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "arm64")
endif()

if(WIN32)
	set(CPACK_GENERATOR "NSIS") # this needs NSIS installed, and available
elseif (APPLE)
	set(CPACK_GENERATOR "DragNDrop")
else()
	set(CPACK_GENERATOR DEB RPM TGZ)
endif()

# Built packages will include only the following components
set(CPACK_INSTALL_CMAKE_PROJECTS
  "${CMAKE_CURRENT_BINARY_DIR};${SYSDIG_COMPONENT_NAME};${SYSDIG_COMPONENT_NAME};/"
)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	list(APPEND CPACK_INSTALL_CMAKE_PROJECTS "${CMAKE_CURRENT_BINARY_DIR};${DRIVER_COMPONENT_NAME};${DRIVER_COMPONENT_NAME};/")
	set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Sysdig <support@sysdig.com>")
	set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
	set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "http://www.sysdig.com")
	set(CPACK_DEBIAN_PACKAGE_DEPENDS "dkms (>= 2.1.0.0)")
	set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_BINARY_DIR}/scripts/debian/postinst;${CMAKE_BINARY_DIR}/scripts/debian/prerm")

	set(CPACK_RPM_PACKAGE_LICENSE "Apache v2.0")
	set(CPACK_RPM_PACKAGE_URL "http://www.sysdig.com")
	set(CPACK_RPM_PACKAGE_REQUIRES "dkms, gcc, make, kernel-devel, perl")
	set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_BINARY_DIR}/scripts/rpm/postinstall")
	set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${CMAKE_BINARY_DIR}/scripts/rpm/preuninstall")
	set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION /usr/src /usr/share/man /usr/share/man/man8)
endif()

include(CPack)
