# Prior to doing anything, we make sure that we aren't trying to 
# run cmake in-tree. (see Issue 71: https://github.com/draios/sysdig/issues/71)
if(EXISTS CMakeLists.txt)
	message( FATAL_ERROR 
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

include(ExternalProject)

if(NOT DEFINED SYSDIG_VERSION)
	set(SYSDIG_VERSION "0.1.1-dev")
endif()

add_definitions(-DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")

option(USE_BUNDLED_LUAJIT "Enable building of the bundled LuaJIT" ON)
option(LUAJIT_PREFIX "Build with LuaJIT at the given path" "")

if (LUAJIT_PREFIX AND USE_BUNDLED_LUAJIT)
    message (FATAL_ERROR "You must set either LUAJIT_PREFIX or USE_BUNDLED_LUAJIT "
                         "not both.")
endif()

set (LUAJIT_SRC "${PROJECT_SOURCE_DIR}/third-party/LuaJIT-2.0.2")

option(USE_BUNDLED_JSONCPP "Enable building of the bundled jsoncpp" ON)
option(JSONCPP_PREFIX "Build with jsoncpp at the given path" "")

if (JSONCPP_PREFIX AND USE_BUNDLED_JSONCPP)
	message (FATAL_ERROR "You must set either JSONCPP_PREFIX or USE_BUNDLED_JSONCPP "
			     "not both.")
endif()

set (JSONCPP_SRC "${PROJECT_SOURCE_DIR}/userspace/libsinsp/third-party/jsoncpp")

if (JSONCPP_PREFIX)
	find_path (JSONCPP_INCLUDE json/json.h "${JSONCPP_PREFIX}" NO_DEFAULT_PATH)
	find_library (JSONCPP_LIB NAMES jsoncpp PATHS "${JSONCPP_PREFIX}" NO_DEFAULT_PATH)
	if (JSONCPP_INCLUDE AND JSONCPP_LIB)
		message (STATUS "Found jsoncpp: include: ${JSONCPP_INCLUDE}, lib: ${JSONCPP_LIB}")
	else()
		message (FATAL_ERROR "Couldn't find jsoncpp in '${JSONCPP_PREFIX}'")
	endif()
elseif (NOT USE_BUNDLED_JSONCPP)
	find_path (JSONCPP_INCLUDE json/json.h PATH_SUFFIXES jsoncpp)
	find_library (JSONCPP_LIB NAMES jsoncpp)
	if (JSONCPP_INCLUDE AND JSONCPP_LIB)
		message (STATUS "Found jsoncpp: include: ${JSONCPP_INCLUDE}, lib: ${JSONCPP_LIB}")
	else()
		message (FATAL_ERROR "Couldn't find system jsoncpp")
	endif()
else()
	set (JSONCPP_INCLUDE "${JSONCPP_SRC}")
	set (JSONCPP_LIB_SRC "${JSONCPP_SRC}/jsoncpp.cpp")
	message (STATUS "Using bundled jsoncpp in '${JSONCPP_SRC}'")
endif()

if(NOT WIN32)

	set(SYSDIG_DEBUG_FLAGS "-D_DEBUG")

	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -ggdb")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -ggdb --std=c++0x")

	set(CMAKE_C_FLAGS_DEBUG "${SYSDIG_DEBUG_FLAGS}")
	set(CMAKE_CXX_FLAGS_DEBUG "${SYSDIG_DEBUG_FLAGS}")

	set(CMAKE_C_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")
	set(CMAKE_CXX_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")

	if(CMAKE_SYSTEM_NAME MATCHES "Linux")
		add_subdirectory(driver)
		add_subdirectory(scripts)
		add_definitions(-DHAS_CAPTURE)
	endif()

	if(CMAKE_SYSTEM_NAME MATCHES "SunOS")
		set(CMD_MAKE gmake)
	else()
		set(CMD_MAKE make)
	endif()

	if (LUAJIT_PREFIX)
		find_path (LUAJIT_INCLUDE luajit.h "${LUAJIT_PREFIX}" NO_DEFAULT_PATH)
		find_library (LUAJIT_LIB NAMES luajit luajit-5.1 PATHS "${LUAJIT_PREFIX}" NO_DEFAULT_PATH)
		if (LUAJIT_INCLUDE AND LUAJIT_LIB)
			message (STATUS "Found LuaJIT: include: ${LUAJIT_INCLUDE}, lib: ${LUAJIT_LIB}")
		else()
			message (FATAL_ERROR "Couldn't find LuaJIT in '${LUAJIT_PREFIX}'")
		endif()
	elseif (NOT USE_BUNDLED_LUAJIT)
		find_path (LUAJIT_INCLUDE luajit.h PATH_SUFFIXES luajit-2.0 luajit)
		find_library (LUAJIT_LIB NAMES luajit luajit-5.1)
		if (LUAJIT_INCLUDE AND LUAJIT_LIB)
			message (STATUS "Found LuaJIT: include: ${LUAJIT_INCLUDE}, lib: ${LUAJIT_LIB}")
		else()
			message (FATAL_ERROR "Couldn't find system LuaJIT")
		endif()
	else()
		set (LUAJIT_INCLUDE "${LUAJIT_SRC}/src")
		set (LUAJIT_LIB "${LUAJIT_SRC}/src/libluajit.a")
		message (STATUS "Using bundled LuaJIT in '${LUAJIT_SRC}'")
		ExternalProject_Add(luajit
			SOURCE_DIR "${LUAJIT_SRC}"
			CONFIGURE_COMMAND ""
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			INSTALL_COMMAND "")
	endif()

	set(ZLIB_INCLUDE "${PROJECT_BINARY_DIR}/zlib-prefix/src/zlib")
	set(ZLIB_LIB "${PROJECT_BINARY_DIR}/zlib-prefix/src/zlib/libz.a")
	ExternalProject_Add(zlib
		URL "http://download.draios.com/dependencies/zlib-1.2.8.tar.gz"
		URL_MD5 "44d667c142d7cda120332623eab69f40"
		CONFIGURE_COMMAND "./configure"
		BUILD_COMMAND ${CMD_MAKE}
		BUILD_IN_SOURCE 1
		INSTALL_COMMAND "")

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

	set (LUAJIT_INCLUDE "${LUAJIT_SRC}/src")
	set (LUAJIT_LIB "${LUAJIT_SRC}/src/lua51.lib")
	ExternalProject_Add(luajit
		SOURCE_DIR ${LUAJIT_SRC}
		CONFIGURE_COMMAND ""
		BUILD_COMMAND msvcbuild.bat
		BINARY_DIR "${LUAJIT_INCLUDE}"
		INSTALL_COMMAND "")

	set(ZLIB_INCLUDE "${PROJECT_BINARY_DIR}/zlib-prefix/src/zlib")
	set(ZLIB_LIB "${PROJECT_BINARY_DIR}/zlib-prefix/src/zlib/zdll.lib")
	ExternalProject_Add(zlib
		URL "http://download.draios.com/dependencies/zlib-1.2.8.tar.gz"
		URL_MD5 "44d667c142d7cda120332623eab69f40"
		CONFIGURE_COMMAND ""
		BUILD_COMMAND nmake -f win32/Makefile.msc
		BINARY_DIR "${ZLIB_INCLUDE}"
		INSTALL_COMMAND "")

endif()

if(APPLE)
	set(CMAKE_EXE_LINKER_FLAGS "-pagezero_size 10000 -image_base 100000000")
endif()

add_subdirectory(userspace/sysdig)
add_subdirectory(userspace/libscap)
add_subdirectory(userspace/libsinsp)

set(CPACK_PACKAGE_NAME "sysdig")
set(CPACK_PACKAGE_VENDOR "Draios Inc.")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "A system exploration and troubleshooting tool")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/scripts/description.txt")
set(CPACK_PACKAGE_VERSION "${SYSDIG_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_STRIP_FILES "ON")

set(CPACK_GENERATOR DEB RPM)

set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Draios Inc. <support@draios.com>")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "http://www.draios.com")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "dkms (>= 2.1.0.0)")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_BINARY_DIR}/scripts/debian/postinst;${CMAKE_BINARY_DIR}/scripts/debian/prerm")

set(CPACK_RPM_PACKAGE_LICENSE "GPLv2")
set(CPACK_RPM_PACKAGE_URL "http://www.draios.com")
set(CPACK_RPM_PACKAGE_REQUIRES "dkms, gcc, make, kernel-devel, perl")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/postinstall")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/preuninstall")
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION /usr/src)

include(CPack)
