#
# JsonCpp
#
option(USE_BUNDLED_JSONCPP "Enable building of the bundled jsoncpp" ${USE_BUNDLED_DEPS})

if(JSONCPP_INCLUDE AND JSONCPP_LIB)
	message(STATUS "Using jsoncpp: include: ${JSONCPP_INCLUDE}, lib: ${JSONCPP_LIB}")
elseif(NOT USE_BUNDLED_JSONCPP)
	find_path(JSONCPP_INCLUDE json/json.h PATH_SUFFIXES jsoncpp)
	find_library(JSONCPP_LIB NAMES jsoncpp)
	if(JSONCPP_INCLUDE AND JSONCPP_LIB)
		message(STATUS "Found jsoncpp: include: ${JSONCPP_INCLUDE}, lib: ${JSONCPP_LIB}")
	else()
		message(FATAL_ERROR "Couldn't find system jsoncpp")
	endif()
else()
	set(JSONCPP_SRC "${CMAKE_CURRENT_LIST_DIR}/../../userspace/libsinsp/third-party/jsoncpp")
	set(JSONCPP_INCLUDE "${JSONCPP_SRC}")
	set(JSONCPP_LIB_SRC "${JSONCPP_SRC}/jsoncpp.cpp")
	message(STATUS "Using bundled jsoncpp in '${JSONCPP_SRC}'")
endif()
include_directories("${JSONCPP_INCLUDE}")
