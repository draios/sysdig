include_directories("${PROJECT_SOURCE_DIR}/common")

add_library(scap STATIC 
	scap.c 
	scap_event.c 
	scap_fds.c 
	scap_iflist.c 
	scap_savefile.c 
	scap_procs.c 
	scap_userlist.c 
	flags_table.c
	event_table.c
	syscall_info_table.c)

if (CMAKE_SYSTEM_NAME MATCHES "SunOS")
	target_link_libraries(scap
		socket nsl)

elseif (WIN32)
	target_link_libraries(scap
		Ws2_32.lib)
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    option(BUILD_LIBSCAP_EXAMPLES "Build libscap examples" ON)

    if (BUILD_LIBSCAP_EXAMPLES)
        add_subdirectory(examples/01-open)
        add_subdirectory(examples/02-validatebuffer)
    endif()
endif()
