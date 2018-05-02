include_directories("${PROJECT_SOURCE_DIR}/common")
include_directories("${ZLIB_INCLUDE}")
if(CYGWIN)
include_directories("${WIN_HAL_INCLUDE}")
endif()

list(APPEND targetfiles
	scap.c
	scap_bpf.c
	scap_event.c
	scap_fds.c
	scap_iflist.c
	scap_savefile.c
	scap_procs.c
	scap_userlist.c
	syscall_info_table.c
	../../driver/dynamic_params_table.c
	../../driver/event_table.c
	../../driver/fillers_table.c
	../../driver/flags_table.c
	../../driver/syscall_table.c)

if(CYGWIN)
	list(APPEND targetfiles
		windows_hal.c)
endif()

add_library(scap STATIC
	${targetfiles})

if(USE_BUNDLED_ZLIB)
	add_dependencies(scap zlib)
endif()

if (CMAKE_SYSTEM_NAME MATCHES "SunOS")
	target_link_libraries(scap
		socket nsl)
elseif (WIN32)
	target_link_libraries(scap
		Ws2_32.lib)
elseif (CYGWIN)
	target_link_libraries(scap
		/lib/w32api/libpsapi.a
		${WIN_HAL_LIB}/dragent_win_hal.lib
		)
endif()

target_link_libraries(scap
	"${ZLIB_LIB}"
	elf
	rt)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    option(BUILD_LIBSCAP_EXAMPLES "Build libscap examples" ON)

    if (BUILD_LIBSCAP_EXAMPLES)
        add_subdirectory(examples/01-open)
        add_subdirectory(examples/02-validatebuffer)
    endif()
endif()
