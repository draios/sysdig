include_directories(${PROJECT_SOURCE_DIR}/common)

add_library(scap STATIC 
	scap.c 
	scap_event.c 
	scap_fds.c 
	scap_iflist.c 
	scap_savefile.c 
	scap_event.c 
	scap_procs.c 
	scap_userlist.c 
	${PROJECT_SOURCE_DIR}/driver/event_table.c
	${PROJECT_SOURCE_DIR}/driver/syscall_info_table.c)
