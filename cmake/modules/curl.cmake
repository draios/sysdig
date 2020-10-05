#
# libcurl
#
option(USE_BUNDLED_CURL "Enable building of the bundled curl" ${USE_BUNDLED_DEPS})

if(TARGET curl)
elseif(NOT USE_BUNDLED_CURL)
	find_package(CURL REQUIRED)
	message(STATUS "Found CURL: include: ${CURL_INCLUDE_DIR}, lib: ${CURL_LIBRARIES}")
else()
	set(CURL_BUNDLE_DIR "${PROJECT_BINARY_DIR}/curl-prefix/src/curl")
	set(CURL_INCLUDE_DIR "${CURL_BUNDLE_DIR}/include/")
	set(CURL_LIBRARIES "${CURL_BUNDLE_DIR}/lib/.libs/libcurl.a")

	if(NOT USE_BUNDLED_OPENSSL)
		set(CURL_SSL_OPTION "--with-ssl")
	else()
		set(CURL_SSL_OPTION "--with-ssl=${OPENSSL_INSTALL_DIR}")
		message(STATUS "Using bundled curl in '${CURL_BUNDLE_DIR}'")
		message(STATUS "Using SSL for curl in '${CURL_SSL_OPTION}'")
	endif()


	ExternalProject_Add(curl
		DEPENDS openssl
		URL "http://download.draios.com/dependencies/curl-7.61.0.tar.bz2"
		URL_MD5 "31d0a9f48dc796a7db351898a1e5058a"
		CONFIGURE_COMMAND ./configure ${CURL_SSL_OPTION} --disable-threaded-resolver --disable-shared --enable-optimize --disable-curldebug --disable-rt --enable-http --disable-ftp --disable-file --disable-ldap --disable-ldaps --disable-rtsp --disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smb --disable-smtp --disable-gopher --disable-sspi --disable-ntlm-wb --disable-tls-srp --without-winssl --without-darwinssl --without-polarssl --without-cyassl --without-nss --without-axtls --without-ca-path --without-ca-bundle --without-libmetalink --without-librtmp --without-winidn --without-libidn --without-libidn2 --without-nghttp2 --without-libssh2  --without-libpsl
		BUILD_COMMAND ${CMD_MAKE}
		BUILD_IN_SOURCE 1
		BUILD_BYPRODUCTS ${CURL_LIBRARIES}
		INSTALL_COMMAND "")
endif()
include_directories("${CURL_INCLUDE_DIR}")
