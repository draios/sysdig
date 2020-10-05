option(USE_BUNDLED_PROTOBUF "Enable building of the bundled protobuf" ${USE_BUNDLED_DEPS})
if(TARGET protobuf)
elseif(NOT USE_BUNDLED_PROTOBUF)
	find_program(PROTOC NAMES protoc)
	find_path(PROTOBUF_INCLUDE NAMES google/protobuf/message.h)
	find_library(PROTOBUF_LIB NAMES protobuf)
	if(PROTOC AND PROTOBUF_INCLUDE AND PROTOBUF_LIB)
		message(STATUS "Found protobuf: compiler: ${PROTOC}, include: ${PROTOBUF_INCLUDE}, lib: ${PROTOBUF_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system protobuf")
	endif()
else()
	set(PROTOBUF_SRC "${PROJECT_BINARY_DIR}/protobuf-prefix/src/protobuf")
	message(STATUS "Using bundled protobuf in '${PROTOBUF_SRC}'")
	set(PROTOC "${PROTOBUF_SRC}/target/bin/protoc")
	set(PROTOBUF_INCLUDE "${PROTOBUF_SRC}/target/include")
	set(PROTOBUF_LIB "${PROTOBUF_SRC}/target/lib/libprotobuf.a")
	if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "s390x")
		ExternalProject_Add(protobuf
			DEPENDS openssl zlib
			URL "http://download.sysdig.com/dependencies/protobuf-cpp-3.5.0.tar.gz"
			URL_MD5 "e4ba8284a407712168593e79e6555eb2"
			PATCH_COMMAND wget http://download.sysdig.com/dependencies/protobuf-3.5.0-s390x.patch && patch -p1 -i protobuf-3.5.0-s390x.patch
			# TODO what if using system zlib?
			CONFIGURE_COMMAND /usr/bin/env CPPFLAGS=-I${ZLIB_INCLUDE} LDFLAGS=-L${ZLIB_SRC} ./configure --with-zlib --prefix=${PROTOBUF_SRC}/target
			COMMAND aclocal && automake
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${PROTOC} ${PROTOBUF_INCLUDE} ${PROTOBUF_LIB}
			INSTALL_COMMAND make install)
	else()
		ExternalProject_Add(protobuf
			DEPENDS openssl zlib
			URL "http://download.sysdig.com/dependencies/protobuf-cpp-3.5.0.tar.gz"
			URL_MD5 "e4ba8284a407712168593e79e6555eb2"
			# TODO what if using system zlib?
			CONFIGURE_COMMAND /usr/bin/env CPPFLAGS=-I${ZLIB_INCLUDE} LDFLAGS=-L${ZLIB_SRC} ./configure --with-zlib --prefix=${PROTOBUF_SRC}/target
			BUILD_COMMAND ${CMD_MAKE}
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${PROTOC} ${PROTOBUF_INCLUDE} ${PROTOBUF_LIB}
			INSTALL_COMMAND make install)
	endif()
endif()
include_directories("${PROTOBUF_INCLUDE}")
