cmake_minimum_required(VERSION 2.6)

project(sysdig) 

set(SYSDIG_DEBUG_FLAGS "-D_DEBUG")

set(CMAKE_C_FLAGS "-Wall -ggdb")
set(CMAKE_CXX_FLAGS "-Wall -ggdb --std=c++0x")
set(CMAKE_C_FLAGS_DEBUG "${SYSDIG_DEBUG_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "${SYSDIG_DEBUG_FLAGS}")
set(CMAKE_C_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")

set(SYSDIG_VERSION "0.1.1")
set(SYSDIG_SRC_PREFIX "/usr/src/sysdig-${SYSDIG_VERSION}")

add_subdirectory(driver)
add_subdirectory(userspace/sysdig)
add_subdirectory(userspace/libscap)
add_subdirectory(userspace/libsinsp)

set(CPACK_PACKAGE_NAME "sysdig")
set(CPACK_PACKAGE_VENDOR "Draios Inc.")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Sysdig system exploration and troubleshooting tool")
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

include(CPack)
