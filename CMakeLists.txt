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

# Add path for custom CMake modules.
list(APPEND CMAKE_MODULE_PATH
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

if(NOT DEFINED SYSDIG_VERSION)
	set(SYSDIG_VERSION "0.1.1dev")
endif()

if(NOT DEFINED DIR_ETC)
	set(DIR_ETC "${CMAKE_INSTALL_PREFIX}/etc")
endif()

if(NOT CMAKE_BUILD_TYPE)
	SET(CMAKE_BUILD_TYPE Release)
endif()

set(PACKAGE_NAME "sysdig")

add_definitions(-DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")
add_definitions(-DK8S_DISABLE_THREAD)

option(BUILD_WARNINGS_AS_ERRORS "Enable building with -Wextra -Werror flags")

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

		if(NOT DEFINED PROBE_VERSION)
			set(PROBE_VERSION "${SYSDIG_VERSION}")
		endif()
		if(NOT DEFINED PROBE_NAME)
			set(PROBE_NAME "sysdig-probe")
		endif()

		if(NOT DEFINED PROBE_DEVICE_NAME)
			set(PROBE_DEVICE_NAME "sysdig")
		endif()

		add_subdirectory(driver)
		add_definitions(-DHAS_CAPTURE)
	endif()

	add_subdirectory(scripts)

	if(CMAKE_SYSTEM_NAME MATCHES "SunOS")
		set(CMD_MAKE gmake)
	else()
		set(CMD_MAKE make)
	endif()

else()

	set(SYSDIG_FLAGS_WIN "-D_CRT_SECURE_NO_WARNINGS -DWIN32 /EHsc /W3 /Zi")
	set(SYSDIG_FLAGS_WIN_DEBUG "/MTd /Od")
	set(SYSDIG_FLAGS_WIN_RELEASE "/MT")

	set(CMAKE_C_FLAGS "${SYSDIG_FLAGS_WIN}")
	set(CMAKE_CXX_FLAGS "${SYSDIG_FLAGS_WIN}")

	set(CMAKE_C_FLAGS_DEBUG "${SYSDIG_FLAGS_WIN_DEBUG}")
	set(CMAKE_CXX_FLAGS_DEBUG "${SYSDIG_FLAGS_WIN_DEBUG}")

	set(CMAKE_C_FLAGS_RELEASE "${SYSDIG_FLAGS_WIN_RELEASE}")
	set(CMAKE_CXX_FLAGS_RELEASE "${SYSDIG_FLAGS_WIN_RELEASE}")

endif()

if(APPLE)
	set(CMAKE_EXE_LINKER_FLAGS "-pagezero_size 10000 -image_base 100000000")
endif()

include(ExternalProject)

option(USE_BUNDLED_DEPS "Enable bundled dependencies instead of using the system ones" ON)

include(luajit)
include(jsoncpp)

if(NOT MINIMAL_BUILD)
	include(zlib)
endif() # MINIMAL_BUILD

include(tbb)

if(NOT WIN32 AND NOT APPLE)
	include(jq)
endif()

if(NOT WIN32)
	include(ncurses)
endif()

if(NOT WIN32 AND NOT APPLE)
	include(b64)
endif()

if(NOT WIN32 AND NOT MINIMAL_BUILD)
	include(openssl)
	include(curl)
endif() # NOT WIN32 AND NOT MINIMAL_BUILD

if(NOT MINIMAL_BUILD)
	include(cares)
endif() # NOT MINIMAL_BUILD

if(NOT WIN32 AND NOT APPLE)
	if(NOT MINIMAL_BUILD)
		include(protobuf)
		include(grpc)
	endif() # NOT WIN32 AND NOT APPLE
endif() # MINIMAL_BUILD

option(CREATE_TEST_TARGETS "Enable make-targets for unit testing" ON)
if(CREATE_TEST_TARGETS AND NOT WIN32)
	option(USE_BUNDLED_GTEST "Enable building of the bundled gtest" ${USE_BUNDLED_DEPS})
	if(NOT USE_BUNDLED_GTEST)
		find_path(GTEST_INCLUDE_DIR PATH_SUFFIXES gtest NAMES gtest.h)
		find_library(GTEST_LIB NAMES gtest)
		find_library(GTEST_MAIN_LIB NAMES gtest_main)
		if(GTEST_INCLUDE_DIR AND GTEST_LIB AND GTEST_MAIN_LIB)
			message(STATUS "Found gtest: include: ${GTEST_INCLUDE_DIR}, lib: ${GTEST_LIB}, main lib: ${GTEST_MAIN_LIB}")
		else()
			message(FATAL_ERROR "Couldn't find system gtest")
		endif()
	else()
		# https://github.com/google/googletest/tree/master/googletest#incorporating-into-an-existing-cmake-project
		# Download and unpack googletest at configure time
		configure_file(CMakeListsGtestInclude.cmake googletest-download/CMakeLists.txt)
		execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
			RESULT_VARIABLE result
			WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
		if(result)
			message(FATAL_ERROR "CMake step for googletest failed: ${result}")
		endif()
		execute_process(COMMAND ${CMAKE_COMMAND} --build .
			RESULT_VARIABLE result
			WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
		if(result)
			message(FATAL_ERROR "Build step for googletest failed: ${result}")
		endif()

		# Add googletest directly to our build. This defines
		# the gtest and gtest_main targets.
		add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/googletest-src
		                 ${CMAKE_CURRENT_BINARY_DIR}/googletest-build
		                 EXCLUDE_FROM_ALL)

		set(GTEST_INCLUDE_DIR "${gtest_SOURCE_DIR}/include/gtest")
		set(GTEST_MAIN_LIB "gtest_main")
	endif()
endif() # NOT WIN32

add_subdirectory(userspace/sysdig)
add_subdirectory(userspace/libscap)
add_subdirectory(userspace/libsinsp)

if(CREATE_TEST_TARGETS AND NOT WIN32)
		# Add unit test directories
		add_subdirectory(userspace/libsinsp/test)

		# Add command to run all unit tests at once via the make system.
		# This is preferred vs using ctest's add_test because it will build
		# the code and output to stdout.
		add_custom_target(run-unit-tests
			COMMAND ${CMAKE_MAKE_PROGRAM} run-unit-test-libsinsp
		)
endif()

set(CPACK_PACKAGE_NAME "${PACKAGE_NAME}")
set(CPACK_PACKAGE_VENDOR "Sysdig Inc.")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "sysdig, a system-level exploration and troubleshooting tool")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/scripts/description.txt")
set(CPACK_PACKAGE_VERSION "${SYSDIG_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_PROJECT_CONFIG_FILE "${PROJECT_SOURCE_DIR}/CMakeCPackOptions.cmake")
set(CPACK_STRIP_FILES "ON")

set(CPACK_GENERATOR DEB RPM TGZ)

set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Sysdig <support@sysdig.com>")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "http://www.sysdig.com")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "dkms (>= 2.1.0.0)")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_BINARY_DIR}/scripts/debian/postinst;${CMAKE_BINARY_DIR}/scripts/debian/prerm")

set(CPACK_RPM_PACKAGE_LICENSE "Apache v2.0")
set(CPACK_RPM_PACKAGE_URL "http://www.sysdig.com")
set(CPACK_RPM_PACKAGE_REQUIRES "dkms, gcc, make, kernel-devel, perl")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/postinstall")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/preuninstall")
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION /usr/src /usr/share/man /usr/share/man/man8)

include(CPack)
