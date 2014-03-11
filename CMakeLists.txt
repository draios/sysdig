cmake_minimum_required(VERSION 2.8)

project(sysdig) 

if(NOT WIN32)

	set(SYSDIG_DEBUG_FLAGS "-D_DEBUG")

	set(CMAKE_C_FLAGS "-Wall -ggdb")
	set(CMAKE_CXX_FLAGS "-Wall -ggdb --std=c++0x")

	set(CMAKE_C_FLAGS_DEBUG "${SYSDIG_DEBUG_FLAGS}")
	set(CMAKE_CXX_FLAGS_DEBUG "${SYSDIG_DEBUG_FLAGS}")

	set(CMAKE_C_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")
	set(CMAKE_CXX_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")

	set(SYSDIG_SRC_PREFIX "/usr/src/sysdig-${SYSDIG_VERSION}")

	if(CMAKE_SYSTEM_NAME MATCHES "Linux")
		add_subdirectory(driver)
	endif()

	include(ExternalProject)
	ExternalProject_Add(luajit
		SOURCE_DIR ${PROJECT_SOURCE_DIR}/third-party/LuaJIT-2.0.2
		CONFIGURE_COMMAND ""
		BUILD_COMMAND make
		BUILD_IN_SOURCE 1
		INSTALL_COMMAND "")

else()

	set(SYSDIG_FLAGS_WIN "-D_CRT_SECURE_NO_WARNINGS -DWIN32 /EHsc /W3")
	set(SYSDIG_FLAGS_WIN_DEBUG "/MTd")
	set(SYSDIG_FLAGS_WIN_RELEASE "/MT")

	set(CMAKE_C_FLAGS "${SYSDIG_FLAGS_WIN}")
	set(CMAKE_CXX_FLAGS "${SYSDIG_FLAGS_WIN}")

	set(CMAKE_C_FLAGS_DEBUG "${SYSDIG_FLAGS_WIN_DEBUG}")
	set(CMAKE_CXX_FLAGS_DEBUG "${SYSDIG_FLAGS_WIN_DEBUG}")

	set(CMAKE_C_FLAGS_RELEASE "${SYSDIG_FLAGS_WIN_RELEASE}")
	set(CMAKE_CXX_FLAGS_RELEASE "${SYSDIG_FLAGS_WIN_RELEASE}")

	include(ExternalProject)
	ExternalProject_Add(luajit
		SOURCE_DIR ${PROJECT_SOURCE_DIR}/third-party/LuaJIT-2.0.2
		CONFIGURE_COMMAND ""
		BUILD_COMMAND msvcbuild.bat
		BINARY_DIR ${PROJECT_SOURCE_DIR}/third-party/LuaJIT-2.0.2/src
		INSTALL_COMMAND "")

endif()

if(APPLE)
	set(CMAKE_EXE_LINKER_FLAGS "-pagezero_size 10000 -image_base 100000000")
endif()

add_subdirectory(userspace/sysdig)
add_subdirectory(userspace/libscap)
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
   add_subdirectory(userspace/libscap/examples/01-open)
   add_subdirectory(userspace/libscap/examples/02-validatebuffer)
endif()
add_subdirectory(userspace/libsinsp)

set(CPACK_PACKAGE_NAME "sysdig")
set(CPACK_PACKAGE_VENDOR "Draios Inc.")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Sysdig system exploration and troubleshooting tool")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/scripts/description.txt")
set(CPACK_PACKAGE_VERSION "${SYSDIG_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_STRIP_FILES "ON")

set(CPACK_GENERATOR DEB RPM)

set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Draios Inc. <support@draios.com>")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "http://www.draios.com")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "dkms (>= 2.1.0.0)")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${PROJECT_SOURCE_DIR}/scripts/debian/postinst;${PROJECT_SOURCE_DIR}/scripts/debian/prerm")

set(CPACK_RPM_PACKAGE_URL "http://www.draios.com")
set(CPACK_RPM_PACKAGE_REQUIRES "dkms, gcc, make, kernel-devel, perl")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/postinstall")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/preuninstall")
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION /usr/src)

include(CPack)
