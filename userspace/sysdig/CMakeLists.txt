include_directories("${JSONCPP_INCLUDE}")
include_directories("${PROJECT_SOURCE_DIR}/common")
include_directories("${PROJECT_SOURCE_DIR}/userspace/libscap")
include_directories("${PROJECT_SOURCE_DIR}/userspace/libsinsp")
include_directories("${PROJECT_BINARY_DIR}/userspace/sysdig")
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

	install(FILES man/sysdig.8
		DESTINATION share/man/man8)

	install(DIRECTORY chisels
		DESTINATION share/sysdig)

	file(COPY chisels
		DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")

else()

	target_link_libraries(sysdig odbc32.lib odbccp32.lib)

	add_custom_command(TARGET sysdig POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different
			"${LUAJIT_SRC}/lua51.dll"
			"${PROJECT_BINARY_DIR}/$(Configuration)/lua51.dll")

	add_custom_command(TARGET sysdig POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different
			"${ZLIB_INCLUDE}/zlib1.dll"
			"${PROJECT_BINARY_DIR}/$(Configuration)/")

	add_custom_command(TARGET sysdig POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E copy_directory
			"${PROJECT_SOURCE_DIR}/userspace/sysdig/chisels"
			"${PROJECT_BINARY_DIR}/$(Configuration)/chisels")

	add_custom_command(TARGET sysdig POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different
			$<TARGET_FILE:sysdig>
			"${PROJECT_BINARY_DIR}/$(Configuration)/sysdig.exe")

endif()

configure_file(config.h.in config.h)
