#
# OpenSSL
#
option(USE_BUNDLED_OPENSSL "Enable building of the bundled OpenSSL" ${USE_BUNDLED_DEPS})

if(TARGET openssl)
elseif(NOT USE_BUNDLED_OPENSSL)
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
		URL "http://download.draios.com/dependencies/openssl-1.0.2n.tar.gz"
		URL_MD5 "13bdc1b1d1ff39b6fd42a255e74676a4"
		CONFIGURE_COMMAND ./config shared --prefix=${OPENSSL_INSTALL_DIR}
		BUILD_COMMAND ${CMD_MAKE}
		BUILD_IN_SOURCE 1
		BUILD_BYPRODUCTS ${OPENSSL_LIBRARY_SSL} ${OPENSSL_LIBRARY_CRYPTO}
		INSTALL_COMMAND ${CMD_MAKE} install)
endif()
include_directories("${OPENSSL_INCLUDE_DIR}")
