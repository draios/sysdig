include_directories(${PROJECT_SOURCE_DIR}/common)

add_library(scap STATIC 
	scap.c 
	scap_event.c 
	scap_fds.c 
	scap_iflist.c 
	scap_savefile.c 
	scap_procs.c 
	scap_userlist.c 
	../../driver/flags_table.c
	../../driver/event_table.c
	../../driver/syscall_info_table.c)

if (WIN32)
	target_link_libraries(scap
		Ws2_32.lib)
endif()
