#
# zlib
#
option(USE_BUNDLED_ZLIB "Enable building of the bundled zlib" ${USE_BUNDLED_DEPS})

if(TARGET zlib)
elseif(NOT USE_BUNDLED_ZLIB)
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
			URL "http://download.draios.com/dependencies/zlib-1.2.11.tar.gz"
			URL_MD5 "1c9f62f0778697a09d36121ead88e08e"
			CONFIGURE_COMMAND "./configure"
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${ZLIB_LIB}
			INSTALL_COMMAND "")
	else()
		set(ZLIB_LIB "${ZLIB_SRC}/zdll.lib")
		ExternalProject_Add(zlib
			URL "http://download.draios.com/dependencies/zlib-1.2.11.tar.gz"
			URL_MD5 "1c9f62f0778697a09d36121ead88e08e"
			CONFIGURE_COMMAND ""
			BUILD_COMMAND nmake -f win32/Makefile.msc
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${ZLIB_LIB}
			INSTALL_COMMAND "")
	endif()
endif()
include_directories("${ZLIB_INCLUDE}")
