# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# The following file was originally developed in the sysdig cli
# project and then contributed to the falcosecurity/libs project
# (https://github.com/draios/sysdig/commit/abf90f39f8e5ea6eb4276cc3f980dbd878816ecd
# with the #1737 PR). At the end, given its removal from the
# falcosecurity/libs project, has been reintroduced to the
# draios/sysdig project.
#

option(USE_BUNDLED_LUAJIT "Enable building of the bundled LuaJIT" ${USE_BUNDLED_DEPS})

if(LUAJIT_INCLUDE)
	# we already have luajit
elseif(NOT USE_BUNDLED_LUAJIT)
	find_path(LUAJIT_INCLUDE luajit.h PATH_SUFFIXES luajit-2.0 luajit-2.1 luajit)
	find_library(LUAJIT_LIB NAMES luajit luajit-5.1)
	if(LUAJIT_INCLUDE AND LUAJIT_LIB)
		message(STATUS "Found LuaJIT: include: ${LUAJIT_INCLUDE}, lib: ${LUAJIT_LIB}")
	else()
		# alternatively try stock Lua
		find_package(Lua REQUIRED)
		set(LUAJIT_LIB ${LUA_LIBRARY})
		set(LUAJIT_INCLUDE ${LUA_INCLUDE_DIR})
	endif()
else()
	set(LUAJIT_SRC "${PROJECT_BINARY_DIR}/luajit-prefix/src/luajit/src")
	set(LUAJIT_INCLUDE "${LUAJIT_SRC}/")

	if(NOT WIN32)
		set(LUAJIT_LIB "${LUAJIT_SRC}/libluajit.a")
	else()
		set(LUAJIT_LIB "${LUAJIT_SRC}/lua51.lib")
	endif()

	if(NOT TARGET luajit)
		message(STATUS "Using bundled LuaJIT in '${LUAJIT_SRC}'")
		if(NOT WIN32)
			if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "ppc64le")
				ExternalProject_Add(luajit
					PREFIX "${PROJECT_BINARY_DIR}/luajit-prefix"
					GIT_REPOSITORY "https://github.com/moonjit/moonjit"
					GIT_TAG "2.1.2"
					CONFIGURE_COMMAND ""
					BUILD_COMMAND make
					BUILD_IN_SOURCE 1
					BUILD_BYPRODUCTS ${LUAJIT_LIB}
					UPDATE_COMMAND ""
					INSTALL_COMMAND "")
			elseif("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "s390x")
				ExternalProject_Add(luajit
					PREFIX "${PROJECT_BINARY_DIR}/luajit-prefix"
					GIT_REPOSITORY "https://github.com/linux-on-ibm-z/LuaJIT.git"
					GIT_TAG "v2.1"
					CONFIGURE_COMMAND ""
					BUILD_COMMAND make
					BUILD_IN_SOURCE 1
					BUILD_BYPRODUCTS ${LUAJIT_LIB}
					UPDATE_COMMAND ""
					INSTALL_COMMAND "")
			elseif(APPLE)
				ExternalProject_Add(luajit
					PREFIX "${PROJECT_BINARY_DIR}/luajit-prefix"
					URL "https://github.com/LuaJIT/LuaJIT/archive/8e6520a7aecd0517e792b359afbbfd7274791f5f.tar.gz"
					URL_HASH "SHA256=9c4c370559352e0622231d5a1f28e95ff56e2dce6308238e6588b0943aac5e63"
					CONFIGURE_COMMAND ""
					BUILD_COMMAND make MACOSX_DEPLOYMENT_TARGET=10.14
					BUILD_IN_SOURCE 1
					BUILD_BYPRODUCTS ${LUAJIT_LIB}
					INSTALL_COMMAND "")
			else()
				ExternalProject_Add(luajit
					PREFIX "${PROJECT_BINARY_DIR}/luajit-prefix"
					GIT_REPOSITORY "https://github.com/LuaJIT/LuaJIT"
					GIT_TAG "8e6520a7aecd0517e792b359afbbfd7274791f5f"
					CONFIGURE_COMMAND ""
					BUILD_COMMAND make
					BUILD_IN_SOURCE 1
					BUILD_BYPRODUCTS ${LUAJIT_LIB}
					UPDATE_COMMAND ""
					INSTALL_COMMAND "")
			endif()
			install(FILES "${LUAJIT_LIB}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
					COMPONENT "libs-deps")
			install(DIRECTORY "${LUAJIT_INCLUDE}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
					COMPONENT "libs-deps"
					FILES_MATCHING PATTERN "*.h")
		else()
			# msvcbuild.bat selects its DynASM target from %VSCMD_ARG_TGT_ARCH%,
			# which a VS dev prompt sets but which is absent inside CMake's MSBuild
			# custom build step. Without it the script defaults to the x64 source
			# (vm_x64.dasc) regardless of the real compiler, so on arm64 the
			# generated buildvm_arch.h references CCallState.nfpr (an x64-only
			# field) and the arm64 build fails with C2039. Pass the actual VS
			# target platform through so the DynASM source matches the compiler.
			if(CMAKE_VS_PLATFORM_NAME STREQUAL "ARM64")
				set(LUAJIT_MSVC_TGT_ARCH "arm64")
			elseif(CMAKE_VS_PLATFORM_NAME STREQUAL "Win32")
				set(LUAJIT_MSVC_TGT_ARCH "x86")
			else()
				set(LUAJIT_MSVC_TGT_ARCH "x64")
			endif()
			ExternalProject_Add(luajit
				PREFIX "${PROJECT_BINARY_DIR}/luajit-prefix"
					GIT_REPOSITORY "https://github.com/LuaJIT/LuaJIT"
					GIT_TAG "8e6520a7aecd0517e792b359afbbfd7274791f5f"
				CONFIGURE_COMMAND ""
				BUILD_COMMAND cmd /c "set VSCMD_ARG_TGT_ARCH=${LUAJIT_MSVC_TGT_ARCH}&& msvcbuild.bat static"
				BUILD_BYPRODUCTS ${LUAJIT_LIB}
				BINARY_DIR "${LUAJIT_SRC}"
				INSTALL_COMMAND "")
		endif()
	endif()
endif()

if(NOT TARGET luajit)
	add_custom_target(luajit)
endif()

include_directories("${LUAJIT_INCLUDE}")
