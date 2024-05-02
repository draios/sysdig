#
# Copyright (C) 2013-2018 Draios Inc dba Sysdig.
#
# This file is part of sysdig .
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

if(NOT WIN32)
	include(ncurses)
endif() # NOT WIN32

include(zlib)
include(luajit)

include_directories("${PROJECT_BINARY_DIR}/userspace/sinspui")
include_directories(../sinspui)
include_directories("${PROJECT_BINARY_DIR}/userspace/sysdig")
include_directories(.)

if(NOT WIN32)
	set(SOURCE_FILES
		sysdig.cpp)

	set(SOURCE_FILES_CSYSDIG
		csysdig.cpp)
else()
	set(SOURCE_FILES
		sysdig.cpp
		win32/getopt.c)

	set(SOURCE_FILES_CSYSDIG
		csysdig.cpp
		win32/getopt.c)
endif()

list(APPEND SOURCE_FILES
	utils/sinsp_opener.cpp
	utils/plugin_utils.cpp
	utils/supported_events.cpp
	utils/supported_fields.cpp)

list(APPEND SOURCE_FILES_CSYSDIG
	utils/sinsp_opener.cpp
	utils/plugin_utils.cpp
	utils/supported_events.cpp
	utils/supported_fields.cpp
	../sinspui/ctext.cpp
	../sinspui/cursescomponents.cpp
	../sinspui/cursesspectro.cpp
	../sinspui/cursestable.cpp
	../sinspui/cursesui.cpp)

list(APPEND CHISEL_SOURCES
	../chisel/chisel_api.cpp
	../chisel/chisel_fields_info.cpp
	../chisel/chisel_utils.cpp
	../chisel/chisel.cpp
	../chisel/chisel_viewinfo.cpp
	../chisel/chisel_table.cpp)

list(APPEND SOURCE_FILES ${CHISEL_SOURCES})
list(APPEND SOURCE_FILES_CSYSDIG ${CHISEL_SOURCES})

add_executable(sysdig ${SOURCE_FILES})
add_executable(csysdig ${SOURCE_FILES_CSYSDIG})

if(USE_BUNDLED_DEPS)
	add_dependencies(sysdig njson)
	add_dependencies(csysdig njson)
	add_dependencies(sysdig yaml-cpp)
	add_dependencies(csysdig yaml-cpp)
	add_dependencies(sysdig luajit)
	add_dependencies(csysdig luajit)
endif()

if(USE_BUNDLED_FALCOSECURITY_LIBS)
    set(SINSP_LIB sinsp)
else()
    set(SINSP_LIB PkgConfig::LIBSINSP)
endif()

target_include_directories(
	sysdig
	PUBLIC
		"${NJSON_INCLUDE_DIR}"
		"${LUAJIT_INCLUDE}"
		../chisel
		..
	)

target_include_directories(
	csysdig
	PUBLIC
		"${NJSON_INCLUDE_DIR}"
		"${LUAJIT_INCLUDE}"
		../chisel
		..
	)

if(NOT WIN32)
	include_directories(${PROJECT_BINARY_DIR}/driver/src)

	target_link_libraries(sysdig
		"${SINSP_LIB}"
		"${LUAJIT_LIB}"
		yaml-cpp)

	if(USE_BUNDLED_NCURSES)
		add_dependencies(csysdig ncurses)
	endif()

	target_link_libraries(csysdig
		"${SINSP_LIB}"
		"${LUAJIT_LIB}"
		"${CURSES_LIBRARIES}"
		yaml-cpp)

	add_subdirectory(man)

	install(TARGETS sysdig 
		DESTINATION bin COMPONENT "${SYSDIG_COMPONENT_NAME}")

	install(TARGETS csysdig 
		DESTINATION bin COMPONENT "${SYSDIG_COMPONENT_NAME}")

	install(DIRECTORY chisels
		DESTINATION share/sysdig COMPONENT "${SYSDIG_COMPONENT_NAME}")

	file(COPY chisels
		DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")

else()
	add_definitions(-DNOCURSESUI)

	target_link_libraries(sysdig
		"${SINSP_LIB}"
		"${LUAJIT_LIB}"
		yaml-cpp)

	target_link_libraries(csysdig
		"${SINSP_LIB}"
		"${LUAJIT_LIB}"
		yaml-cpp)

	target_link_libraries(sysdig odbc32.lib odbccp32.lib Netapi32.lib Iphlpapi.lib)

	target_link_libraries(csysdig odbc32.lib odbccp32.lib Netapi32.lib Iphlpapi.lib)

	add_custom_command(TARGET sysdig POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E copy_directory
			"${PROJECT_SOURCE_DIR}/userspace/sysdig/chisels"
			"${PROJECT_BINARY_DIR}/$(Configuration)/chisels")

	add_custom_command(TARGET sysdig POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different
			$<TARGET_FILE:sysdig>
			"${PROJECT_BINARY_DIR}/$(Configuration)/sysdig.exe")

	add_custom_command(TARGET csysdig POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different
			$<TARGET_FILE:csysdig>
			"${PROJECT_BINARY_DIR}/$(Configuration)/csysdig.exe")

	install(TARGETS sysdig
			DESTINATION programs
			COMPONENT "${SYSDIG_COMPONENT_NAME}")

	install(TARGETS csysdig
			DESTINATION programs
			COMPONENT "${SYSDIG_COMPONENT_NAME}")

	install(DIRECTORY chisels
			DESTINATION programs
			COMPONENT "${SYSDIG_COMPONENT_NAME}")

endif()

configure_file(config_sysdig.h.in config_sysdig.h)
