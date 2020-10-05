option(USE_BUNDLED_GRPC "Enable building of the bundled grpc" ${USE_BUNDLED_DEPS})
if(TARGET grpc)
elseif(NOT USE_BUNDLED_GRPC)
	find_path(GRPCXX_INCLUDE NAMES grpc++/grpc++.h)
	if(GRPCXX_INCLUDE)
		set(GRPC_INCLUDE ${GRPCXX_INCLUDE})
	else()
		find_path(GRPCPP_INCLUDE NAMES grpcpp/grpcpp.h)
		set(GRPC_INCLUDE ${GRPCPP_INCLUDE})
		add_definitions(-DGRPC_INCLUDE_IS_GRPCPP=1)
	endif()
	find_library(GRPC_LIB NAMES grpc_unsecure)
	find_library(GRPCPP_LIB NAMES grpc++_unsecure)
	if(GRPC_INCLUDE AND GRPC_LIB AND GRPCPP_LIB)
		message(STATUS "Found grpc: include: ${GRPC_INCLUDE}, C lib: ${GRPC_LIB}, C++ lib: ${GRPCPP_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system grpc")
	endif()
	find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin)
	if(NOT GRPC_CPP_PLUGIN)
		message(FATAL_ERROR "System grpc_cpp_plugin not found")
	endif()
else()
	find_package(PkgConfig)
	if(NOT PKG_CONFIG_FOUND)
		message(FATAL_ERROR "pkg-config binary not found")
	endif()
	message(STATUS "Found pkg-config executable: ${PKG_CONFIG_EXECUTABLE}")
	set(GRPC_SRC "${PROJECT_BINARY_DIR}/grpc-prefix/src/grpc")
	message(STATUS "Using bundled grpc in '${GRPC_SRC}'")
	set(GRPC_INCLUDE "${GRPC_SRC}/include")
	set(GRPC_LIB "${GRPC_SRC}/libs/opt/libgrpc_unsecure.a")
	set(GRPCPP_LIB "${GRPC_SRC}/libs/opt/libgrpc++_unsecure.a")
	set(GRPC_CPP_PLUGIN "${GRPC_SRC}/bins/opt/grpc_cpp_plugin")

	get_filename_component(PROTOC_DIR ${PROTOC} PATH)

	ExternalProject_Add(grpc
		DEPENDS protobuf zlib c-ares
		URL "http://download.draios.com/dependencies/grpc-1.8.1.tar.gz"
		URL_MD5 "2fc42c182a0ed1b48ad77397f76bb3bc"
		CONFIGURE_COMMAND ""
		# TODO what if using system openssl, protobuf or cares?
		BUILD_COMMAND CFLAGS=-Wno-implicit-fallthrough HAS_SYSTEM_ZLIB=false LDFLAGS=-static PATH=${PROTOC_DIR}:$ENV{PATH} PKG_CONFIG_PATH=${OPENSSL_BUNDLE_DIR}:${PROTOBUF_SRC}:${CARES_SRC} PKG_CONFIG=${PKG_CONFIG_EXECUTABLE} make grpc_cpp_plugin static_cxx static_c
		BUILD_IN_SOURCE 1
		BUILD_BYPRODUCTS ${GRPC_LIB} ${GRPCPP_LIB}
		# TODO s390x support
		# TODO what if using system zlib
		PATCH_COMMAND rm -rf third_party/zlib && ln -s ${ZLIB_SRC} third_party/zlib && wget https://download.sysdig.com/dependencies/grpc-1.8.1-Makefile.patch && patch < grpc-1.8.1-Makefile.patch
		INSTALL_COMMAND "")
endif()
include_directories("${GRPC_INCLUDE}")
