include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsinsp)
include_directories(${PROJECT_BINARY_DIR}/userspace/sysdig)
include_directories(.)

if(NOT WIN32)
	set(SOURCE_FILES
		fields_info.cpp
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

if(NOT WIN32)

	install(TARGETS sysdig 
		DESTINATION bin)

	install(DIRECTORY chisels
		DESTINATION share/sysdig)

	file(COPY chisels
		DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

else()

	target_link_libraries(sysdig odbc32.lib odbccp32.lib)

	add_custom_command(TARGET sysdig POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
			"${PROJECT_SOURCE_DIR}/third-party/LuaJIT-2.0.2/src/lua51.dll"
			$<TARGET_FILE_DIR:sysdig>)

	add_custom_command(TARGET sysdig POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy_directory
			"${PROJECT_SOURCE_DIR}/userspace/sysdig/chisels"
			$<TARGET_FILE_DIR:sysdig>/chisels)

endif()

configure_file(config.h.in config.h)
