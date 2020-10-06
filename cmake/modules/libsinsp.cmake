include(CompilerFlags)

if(NOT LIBSINSP_DIR)
	get_filename_component(LIBSINSP_DIR ${CMAKE_CURRENT_LIST_DIR}/../.. ABSOLUTE)
endif()

if(LIBSCAP_DIR)
	list(APPEND CMAKE_MODULE_PATH ${LIBSCAP_DIR}/cmake/modules)
endif()

include(ExternalProject)

include(luajit)
include(jsoncpp)
include(tbb)

if(NOT MINIMAL_BUILD)
	include(zlib)
	include(cares)
endif() # NOT MINIMAL_BUILD

if(NOT WIN32 AND NOT MINIMAL_BUILD)
	include(openssl)
	include(curl)
endif() # NOT WIN32 AND NOT MINIMAL_BUILD

if(NOT WIN32 AND NOT APPLE)
	include(jq)
	include(b64)
	if(NOT MINIMAL_BUILD)
		include(protobuf)
		include(grpc)
	endif() # MINIMAL_BUILD
endif()

if(NOT WIN32)
	include(ncurses)
endif()

include(libscap)

set(LIBSINSP_INCLUDE_DIRS ${LIBSINSP_DIR}/userspace/libsinsp ${LIBSCAP_INCLUDE_DIRS} ${DRIVER_CONFIG_DIR})
get_filename_component(TBB_ABSOLUTE_INCLUDE_DIR ${TBB_INCLUDE_DIR} ABSOLUTE)
list(APPEND LIBSINSP_INCLUDE_DIRS ${TBB_ABSOLUTE_INCLUDE_DIR})
get_filename_component(JSONCPP_ABSOLUTE_INCLUDE_DIR ${JSONCPP_INCLUDE} ABSOLUTE)
list(APPEND LIBSINSP_INCLUDE_DIRS ${JSONCPP_ABSOLUTE_INCLUDE_DIR})

get_directory_property(hasParent PARENT_DIRECTORY)
if(hasParent)
	set(LIBSINSP_INCLUDE_DIRS ${LIBSINSP_INCLUDE_DIRS} PARENT_SCOPE)
	set(CURSES_LIBRARIES ${CURSES_LIBRARIES} PARENT_SCOPE)
endif()
add_subdirectory(${LIBSINSP_DIR}/userspace/libsinsp ${CMAKE_BINARY_DIR}/libsinsp)
