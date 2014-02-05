include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsinsp)
include_directories(${PROJECT_BINARY_DIR}/userspace/sysdig)
include_directories(.)

if(NOT WIN32)
	set(SOURCE_FILES
		sysdig.cpp)
else()
	set(SOURCE_FILES
		fields_info.cpp
		sysdig.cpp
		win32/getopt.c)
endif()

add_executable(sysdig ${SOURCE_FILES})

target_link_libraries(sysdig
	sinsp)

if(WIN32)
	target_link_libraries(sysdig odbc32.lib odbccp32.lib)
endif()

install(TARGETS sysdig 
	DESTINATION bin)

install(DIRECTORY chisels
	DESTINATION share/sysdig)

file(COPY chisels
	DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

configure_file(config.h.in config.h)
