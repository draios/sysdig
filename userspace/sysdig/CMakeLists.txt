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

include(libscap)
include(libsinsp)

include_directories("${LIBSINSP_INCLUDE_DIRS}")
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

add_executable(sysdig ${SOURCE_FILES})
add_executable(csysdig ${SOURCE_FILES_CSYSDIG})

add_dependencies(sysdig njson)
add_dependencies(csysdig njson)

if(USE_BUNDLED_DEPS)
	add_dependencies(sysdig yaml-cpp)
	add_dependencies(csysdig yaml-cpp)
endif()

target_include_directories(
	sysdig
	PUBLIC
        "${LIBSCAP_INCLUDE_DIRS}"
        "${LIBSINSP_INCLUDE_DIRS}"
		"${YAMLCPP_INCLUDE_DIR}"
		"${NJSON_INCLUDE_DIR}")

target_include_directories(
	csysdig
	PUBLIC
        "${LIBSCAP_INCLUDE_DIRS}"
        "${LIBSINSP_INCLUDE_DIRS}"
		"${YAMLCPP_INCLUDE_DIR}"
		"${NJSON_INCLUDE_DIR}")

if(NOT WIN32)
	include_directories(${PROJECT_BINARY_DIR}/driver/src)

	target_link_libraries(sysdig
		sinsp
		"${YAMLCPP_LIB}")

	if(USE_BUNDLED_NCURSES)
		add_dependencies(csysdig ncurses)
	endif()

	target_link_libraries(csysdig
		sinsp
		"${CURSES_LIBRARIES}"
		"${YAMLCPP_LIB}")

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
	include(luajit)

	target_link_libraries(sysdig
		sinsp
		"${YAMLCPP_LIB}")

	target_link_libraries(csysdig
		sinsp
		"${YAMLCPP_LIB}")

	target_link_libraries(sysdig odbc32.lib odbccp32.lib Netapi32.lib Iphlpapi.lib)

	target_link_libraries(csysdig odbc32.lib odbccp32.lib Netapi32.lib Iphlpapi.lib)

	add_custom_command(TARGET sysdig POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different
			"${LUAJIT_SRC}/lua51.dll"
			"${PROJECT_BINARY_DIR}/$(Configuration)/lua51.dll")

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

	install(FILES "${LUAJIT_SRC}/lua51.dll"
			DESTINATION programs
			COMPONENT "${SYSDIG_COMPONENT_NAME}")

endif()

configure_file(config_sysdig.h.in config_sysdig.h)
