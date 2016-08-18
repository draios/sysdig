# Prior to doing anything, we make sure that we aren't trying to
# run cmake in-tree. (see Issue 71: https://github.com/draios/sysdig/issues/71)
if(EXISTS CMakeLists.txt)
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

if(NOT WIN32)

	set(SYSDIG_DEBUG_FLAGS "-D_DEBUG")

	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -ggdb")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -ggdb --std=c++0x")

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

		set(PROBE_VERSION "${SYSDIG_VERSION}")
		set(PROBE_NAME "sysdig-probe")
		set(PROBE_DEVICE_NAME "sysdig")

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

#
# LuaJIT
#
option(USE_BUNDLED_LUAJIT "Enable building of the bundled LuaJIT" ${USE_BUNDLED_DEPS})

if(NOT USE_BUNDLED_LUAJIT)
	find_path(LUAJIT_INCLUDE luajit.h PATH_SUFFIXES luajit-2.0 luajit)
	find_library(LUAJIT_LIB NAMES luajit luajit-5.1)
	if(LUAJIT_INCLUDE AND LUAJIT_LIB)
		message(STATUS "Found LuaJIT: include: ${LUAJIT_INCLUDE}, lib: ${LUAJIT_LIB}")
	else()
		# alternatively try stock Lua
		find_package(Lua51)
		set(LUAJIT_LIB ${LUA_LIBRARY})
		set(LUAJIT_INCLUDE ${LUA_INCLUDE_DIR})

		if(NOT ${LUA51_FOUND})
			message(FATAL_ERROR "Couldn't find system LuaJIT or Lua")
		endif()
	endif()
else()
	set(LUAJIT_SRC "${PROJECT_BINARY_DIR}/luajit-prefix/src/luajit/src")
	message(STATUS "Using bundled LuaJIT in '${LUAJIT_SRC}'")
	set(LUAJIT_INCLUDE "${LUAJIT_SRC}")
	if(NOT WIN32)
		set(LUAJIT_LIB "${LUAJIT_SRC}/libluajit.a")
		ExternalProject_Add(luajit
			URL "http://download.draios.com/dependencies/LuaJIT-2.0.3.tar.gz"
			URL_MD5 "f14e9104be513913810cd59c8c658dc0"
			CONFIGURE_COMMAND ""
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			INSTALL_COMMAND "")
	else()
		set(LUAJIT_LIB "${LUAJIT_SRC}/lua51.lib")
		ExternalProject_Add(luajit
			URL "http://download.draios.com/dependencies/LuaJIT-2.0.3.tar.gz"
			URL_MD5 "f14e9104be513913810cd59c8c658dc0"
			CONFIGURE_COMMAND ""
			BUILD_COMMAND msvcbuild.bat
			BINARY_DIR "${LUAJIT_SRC}"
			INSTALL_COMMAND "")
	endif()
endif()

#
# JsonCpp
#
option(USE_BUNDLED_JSONCPP "Enable building of the bundled jsoncpp" ${USE_BUNDLED_DEPS})

set(JSONCPP_SRC "${PROJECT_SOURCE_DIR}/userspace/libsinsp/third-party/jsoncpp")

if(NOT USE_BUNDLED_JSONCPP)
	find_path(JSONCPP_INCLUDE json/json.h PATH_SUFFIXES jsoncpp)
	find_library(JSONCPP_LIB NAMES jsoncpp)
	if(JSONCPP_INCLUDE AND JSONCPP_LIB)
		message(STATUS "Found jsoncpp: include: ${JSONCPP_INCLUDE}, lib: ${JSONCPP_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system jsoncpp")
	endif()
else()
	set(JSONCPP_INCLUDE "${JSONCPP_SRC}")
	set(JSONCPP_LIB_SRC "${JSONCPP_SRC}/jsoncpp.cpp")
	message(STATUS "Using bundled jsoncpp in '${JSONCPP_SRC}'")
endif()

#
# zlib
#
option(USE_BUNDLED_ZLIB "Enable building of the bundled zlib" ${USE_BUNDLED_DEPS})

if(NOT USE_BUNDLED_ZLIB)
	find_path(ZLIB_INCLUDE zlib.h PATH_SUFFIXES zlib)
	find_library(ZLIB_LIB NAMES z)
	if(ZLIB_INCLUDE AND ZLIB_LIB)
		message(STATUS "Found zlib: include: ${ZLIB_INCLUDE}, lib: ${ZLIB_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system zlib")
	endif()
else()
	set(ZLIB_SRC "${PROJECT_BINARY_DIR}/zlib-prefix/src/zlib")
	message(STATUS "Using bundled zlib in '${ZLIB_SRC}'")
	set(ZLIB_INCLUDE "${ZLIB_SRC}")
	if(NOT WIN32)
		set(ZLIB_LIB "${ZLIB_SRC}/libz.a")
		ExternalProject_Add(zlib
			URL "http://download.draios.com/dependencies/zlib-1.2.8.tar.gz"
			URL_MD5 "44d667c142d7cda120332623eab69f40"
			CONFIGURE_COMMAND "./configure"
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			INSTALL_COMMAND "")
	else()
		set(ZLIB_LIB "${ZLIB_SRC}/zdll.lib")
		ExternalProject_Add(zlib
			URL "http://download.draios.com/dependencies/zlib-1.2.8.tar.gz"
			URL_MD5 "44d667c142d7cda120332623eab69f40"
			CONFIGURE_COMMAND ""
			BUILD_COMMAND nmake -f win32/Makefile.msc
			BUILD_IN_SOURCE 1
			INSTALL_COMMAND "")
	endif()
endif()

#
# jq
#
if(NOT WIN32 AND NOT APPLE)
	option(USE_BUNDLED_JQ "Enable building of the bundled jq" ${USE_BUNDLED_DEPS})
	if(NOT USE_BUNDLED_JQ)
		find_path(JQ_INCLUDE jq.h PATH_SUFFIXES jq)
		find_library(JQ_LIB NAMES jq)
		if(JQ_INCLUDE AND JQ_LIB)
			message(STATUS "Found jq: include: ${JQ_INCLUDE}, lib: ${JQ_LIB}")
		else()
			message(FATAL_ERROR "Couldn't find system jq")
		endif()
	else()
		set(JQ_SRC "${PROJECT_BINARY_DIR}/jq-prefix/src/jq")
		message(STATUS "Using bundled jq in '${JQ_SRC}'")
		set(JQ_INCLUDE "${JQ_SRC}")
		set(JQ_LIB "${JQ_SRC}/.libs/libjq.a")
		ExternalProject_Add(jq
		URL "http://download.draios.com/dependencies/jq-1.5.tar.gz"
		URL_MD5 "0933532b086bd8b6a41c1b162b1731f9"
		CONFIGURE_COMMAND ./configure --disable-maintainer-mode --enable-all-static --disable-dependency-tracking
		BUILD_COMMAND ${CMD_MAKE} LDFLAGS=-all-static
		BUILD_IN_SOURCE 1
		INSTALL_COMMAND "")
	endif()
endif()

#
# ncurses, keep it simple for the moment
#
if(NOT WIN32)
	option(USE_BUNDLED_NCURSES "Enable building of the bundled ncurses" ${USE_BUNDLED_DEPS})

	if(NOT USE_BUNDLED_NCURSES)
		set(CURSES_NEED_NCURSES TRUE)
		find_package(Curses REQUIRED)
		message(STATUS "Found ncurses: include: ${CURSES_INCLUDE_DIR}, lib: ${CURSES_LIBRARIES}")
	else()
		set(CURSES_BUNDLE_DIR "${PROJECT_BINARY_DIR}/ncurses-prefix/src/ncurses")
		set(CURSES_INCLUDE_DIR "${CURSES_BUNDLE_DIR}/include/")
		set(CURSES_LIBRARIES "${CURSES_BUNDLE_DIR}/lib/libncurses.a")

		message(STATUS "Using bundled ncurses in '${CURSES_BUNDLE_DIR}'")

		ExternalProject_Add(ncurses
			URL "http://download.draios.com/dependencies/ncurses-6.0-20150725.tgz"
			URL_MD5 "32b8913312e738d707ae68da439ca1f4"
			CONFIGURE_COMMAND ./configure --without-cxx --without-cxx-binding --without-ada --without-manpages --without-progs --without-tests --with-terminfo-dirs=/etc/terminfo:/lib/terminfo:/usr/share/terminfo
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			INSTALL_COMMAND "")
	endif()
endif()

if(NOT WIN32 AND NOT APPLE)
	#
	# libb64
	#
	option(USE_BUNDLED_B64 "Enable building of the bundled b64" ${USE_BUNDLED_DEPS})

	if(NOT USE_BUNDLED_B64)
		find_path(B64_INCLUDE NAMES b64/encode.h)
		find_library(B64_LIB NAMES b64)
		if(B64_INCLUDE AND B64_LIB)
			message(STATUS "Found b64: include: ${B64_INCLUDE}, lib: ${B64_LIB}")
		else()
			message(FATAL_ERROR "Couldn't find system b64")
		endif()
	else()
		set(B64_SRC "${PROJECT_BINARY_DIR}/b64-prefix/src/b64")
		message(STATUS "Using bundled b64 in '${B64_SRC}'")
		set(B64_INCLUDE "${B64_SRC}/include")
		set(B64_LIB "${B64_SRC}/src/libb64.a")
		ExternalProject_Add(b64
			URL "http://download.draios.com/dependencies/libb64-1.2.src.zip"
			URL_MD5 "a609809408327117e2c643bed91b76c5"
			CONFIGURE_COMMAND ""
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			INSTALL_COMMAND "")
	endif()

	#
	# OpenSSL
	#
	option(USE_BUNDLED_OPENSSL "Enable building of the bundled OpenSSL" ${USE_BUNDLED_DEPS})

	if(NOT USE_BUNDLED_OPENSSL)
		find_package(OpenSSL REQUIRED)
		message(STATUS "Found OpenSSL: include: ${OPENSSL_INCLUDE_DIR}, lib: ${OPENSSL_LIBRARIES}")
	else()
		set(OPENSSL_BUNDLE_DIR "${PROJECT_BINARY_DIR}/openssl-prefix/src/openssl")
		set(OPENSSL_INSTALL_DIR "${OPENSSL_BUNDLE_DIR}/target")
		set(OPENSSL_INCLUDE_DIR "${PROJECT_BINARY_DIR}/openssl-prefix/src/openssl/include")
		set(OPENSSL_LIBRARY_SSL "${OPENSSL_INSTALL_DIR}/lib/libssl.a")
		set(OPENSSL_LIBRARY_CRYPTO "${OPENSSL_INSTALL_DIR}/lib/libcrypto.a")

		message(STATUS "Using bundled openssl in '${OPENSSL_BUNDLE_DIR}'")

		ExternalProject_Add(openssl
			URL "http://download.draios.com/dependencies/openssl-1.0.2d.tar.gz"
			URL_MD5 "38dd619b2e77cbac69b99f52a053d25a"
			CONFIGURE_COMMAND ./config shared --prefix=${OPENSSL_INSTALL_DIR}
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			INSTALL_COMMAND ${CMD_MAKE} install)
	endif()

	#
	# libcurl
	#
	option(USE_BUNDLED_CURL "Enable building of the bundled curl" ${USE_BUNDLED_DEPS})

	if(NOT USE_BUNDLED_CURL)
		find_package(CURL REQUIRED)
		message(STATUS "Found CURL: include: ${CURL_INCLUDE_DIR}, lib: ${CURL_LIBRARIES}")
	else()
		set(CURL_BUNDLE_DIR "${PROJECT_BINARY_DIR}/curl-prefix/src/curl")
		set(CURL_INCLUDE_DIR "${CURL_BUNDLE_DIR}/include/")
		set(CURL_LIBRARIES "${CURL_BUNDLE_DIR}/lib/.libs/libcurl.a")

		if(NOT USE_BUNDLED_OPENSSL)
			set(CURL_SSL_OPTION "")
		else()
			set(CURL_SSL_OPTION "--with-ssl=${OPENSSL_INSTALL_DIR}")
		endif()

		message(STATUS "Using bundled curl in '${CURL_BUNDLE_DIR}'")
		message(STATUS "Using SSL for curl in '${CURL_SSL_OPTION}'")

		ExternalProject_Add(curl
			DEPENDS openssl
			URL "http://download.draios.com/dependencies/curl-7.45.0.tar.bz2"
			URL_MD5 "62c1a352b28558f25ba6209214beadc8"
			CONFIGURE_COMMAND ./configure ${CURL_SSL_OPTION} --disable-shared --enable-optimize --disable-curldebug --disable-rt --enable-http --disable-ftp --disable-file --disable-ldap --disable-ldaps --disable-rtsp --disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smb --disable-smtp --disable-gopher --disable-sspi --disable-ntlm-wb --disable-tls-srp --without-winssl --without-darwinssl --without-polarssl --without-cyassl --without-nss --without-axtls --without-ca-path --without-ca-bundle --without-libmetalink --without-librtmp --without-winidn --without-libidn --without-nghttp2 --without-libssh2
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			INSTALL_COMMAND "")
	endif()
endif() # NOT WIN32 AND NOT APPLE

add_subdirectory(userspace/sysdig)
add_subdirectory(userspace/libscap)
add_subdirectory(userspace/libsinsp)

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
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "http://www.sysdig.org")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "dkms (>= 2.1.0.0)")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_BINARY_DIR}/scripts/debian/postinst;${CMAKE_BINARY_DIR}/scripts/debian/prerm")

set(CPACK_RPM_PACKAGE_LICENSE "GPLv2")
set(CPACK_RPM_PACKAGE_URL "http://www.sysdig.org")
set(CPACK_RPM_PACKAGE_REQUIRES "dkms, gcc, make, kernel-devel, perl")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/postinstall")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/preuninstall")
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION /usr/src /usr/share/man /usr/share/man/man8)

include(CPack)
