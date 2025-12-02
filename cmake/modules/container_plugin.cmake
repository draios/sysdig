# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2025 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under
# the License.
#

include(ExternalProject)

string(TOLOWER ${CMAKE_HOST_SYSTEM_NAME} PLUGINS_SYSTEM_NAME)

set(CONTAINER_VERSION "0.5.0")

if(UNIX AND NOT APPLE)

	set(CONTAINER_LIBRARY
		"${CMAKE_BINARY_DIR}/container_plugin-prefix/src/container_plugin/libcontainer.so"
	)
	if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
		set(CONTAINER_HASH "717020a51d2c0a58a777fef724be53cb802d687815e336f17d9cb0bbdb79fcb1")
	else() # arm64
		set(CONTAINER_HASH "2de25ef29eaadd719507441dbf1610bf094e9c41e9aa8cdb5f6a70c4ec8bba75")
	endif()

	if(NOT TARGET container_plugin)
		message(STATUS "Fetching container plugin ${CONTAINER_VERSION} in '${CONTAINER_LIBRARY}'")
		ExternalProject_Add(
			container_plugin
			URL "https://download.falco.org/plugins/stable/container-${CONTAINER_VERSION}-${PLUGINS_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz"
			URL_HASH "SHA256=${CONTAINER_HASH}"
			BUILD_BYPRODUCTS "${CONTAINER_LIBRARY}"
			CONFIGURE_COMMAND ""
			BUILD_COMMAND ""
			INSTALL_COMMAND ""
		)

		install(
			FILES "${CONTAINER_LIBRARY}"
			DESTINATION share/sysdig/plugins
			COMPONENT "${SYSDIG_COMPONENT_NAME}"
		)
	endif()
else()

	# Determine the correct library extension for the platform
	if(APPLE)
		set(CONTAINER_LIB_EXT "dylib")
	elseif(WIN32)
		set(CONTAINER_LIB_EXT "dll")
	else()
		set(CONTAINER_LIB_EXT "so")
	endif()

	# On Windows, shared libraries don't have the "lib" prefix
	# and multi-config generators place outputs in config subdirectories
	if(WIN32)
		set(CONTAINER_LIBRARY
			"${CMAKE_BINARY_DIR}/container_plugin-prefix/src/container_plugin/plugins/container/${CMAKE_BUILD_TYPE}/container.${CONTAINER_LIB_EXT}"
		)
	else()
		set(CONTAINER_LIBRARY
			"${CMAKE_BINARY_DIR}/container_plugin-prefix/src/container_plugin/plugins/container/libcontainer.${CONTAINER_LIB_EXT}"
		)
	endif()
	if(NOT TARGET container_plugin)
		message(STATUS "Fetching container plugin source ${CONTAINER_VERSION} in '${CONTAINER_LIBRARY}'")
		ExternalProject_Add(
			container_plugin
			URL "https://github.com/falcosecurity/plugins/archive/refs/tags/plugins/container/v${CONTAINER_VERSION}.tar.gz"
			URL_HASH "SHA256=b3e3fc3f26bf405c3332a8d75377fbbdd298066d46c21813a4a2bbb0f352f7fb"
			SOURCE_SUBDIR plugins/container
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS "${CONTAINER_LIBRARY}"
			CONFIGURE_COMMAND
			${CMAKE_COMMAND} . -DENABLE_ASYNC=OFF -G "${CMAKE_GENERATOR}"
			BUILD_COMMAND ${CMAKE_COMMAND} --build . --config ${CMAKE_BUILD_TYPE}
			INSTALL_COMMAND ""
		)

		install(
			FILES "${CONTAINER_LIBRARY}"
			DESTINATION share/plugins
			COMPONENT "${SYSDIG_COMPONENT_NAME}"
		)
	endif()

endif()
