#
# c-ares
#
option(USE_BUNDLED_CARES "Enable building of the bundled c-ares" ${USE_BUNDLED_DEPS})
if(TARGET cares)
elseif(NOT USE_BUNDLED_CARES)
	find_path(CARES_INCLUDE NAMES cares/ares.h ares.h)
	find_library(CARES_LIB NAMES cares)
	if(CARES_INCLUDE AND CARES_LIB)
		message(STATUS "Found c-ares: include: ${CARES_INCLUDE}, lib: ${CARES_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system c-ares")
	endif()
else()
	set(CARES_SRC "${PROJECT_BINARY_DIR}/c-ares-prefix/src/c-ares")
	message(STATUS "Using bundled c-ares in '${CARES_SRC}'")
	set(CARES_INCLUDE "${CARES_SRC}/target/include")
	set(CARES_LIB "${CARES_SRC}/target/lib/libcares.a")
	ExternalProject_Add(c-ares
		URL "http://download.sysdig.com/dependencies/c-ares-1.13.0.tar.gz"
		URL_MD5 "d2e010b43537794d8bedfb562ae6bba2"
		CONFIGURE_COMMAND ./configure --prefix=${CARES_SRC}/target
		BUILD_COMMAND ${CMD_MAKE}
		BUILD_IN_SOURCE 1
		BUILD_BYPRODUCTS ${CARES_INCLUDE} ${CARES_LIB}
		INSTALL_COMMAND ${CMD_MAKE} install)
endif()

include_directories("${CARES_INCLUDE}")
