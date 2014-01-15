cmake_minimum_required(VERSION 2.6)

project(sysdig) 

set(SYSDIG_DEBUG_FLAGS "-D_DEBUG")

set(CMAKE_C_FLAGS "-Wall -ggdb")
set(CMAKE_CXX_FLAGS "-Wall -ggdb --std=c++0x")
set(CMAKE_C_FLAGS_DEBUG "${SYSDIG_DEBUG_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "${SYSDIG_DEBUG_FLAGS}")
set(CMAKE_C_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")

set(SYSDIG_VERSION "0.1.${SYSDIG_BUILD_NUMBER}")
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(SYSDIG_PACKAGE_NAME "sysdig-debug")
else()
	set(SYSDIG_PACKAGE_NAME "sysdig")
endif()
set(SYSDIG_BIN_PREFIX "/opt/sysdig")
set(SYSDIG_SRC_PREFIX "/usr/src/sysdig-${SYSDIG_VERSION}")

add_subdirectory(driver)
add_subdirectory(userspace/sysdig)
add_subdirectory(userspace/libscap)
add_subdirectory(userspace/libsinsp)
