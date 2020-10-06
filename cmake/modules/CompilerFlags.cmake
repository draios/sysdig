option(BUILD_WARNINGS_AS_ERRORS "Enable building with -Wextra -Werror flags")

option(MINIMAL_BUILD "Produce a minimal sysdig binary with only the essential features (no eBPF probe driver, no kubernetes, no mesos, no marathon and no container metadata)" OFF)
if(MINIMAL_BUILD)
	set(MINIMAL_BUILD_FLAGS "-DMINIMAL_BUILD")
endif()

option(MUSL_OPTIMIZED_BUILD "Enable if you want a musl optimized build" OFF)
if(MUSL_OPTIMIZED_BUILD)
	set(SYSDIG_MUSL_FLAGS "-static -Os")
endif()

add_definitions(-DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")

if(NOT WIN32)

	set(DEBUG_FLAGS "-D_DEBUG")
	set(CMAKE_COMMON_FLAGS "-Wall -ggdb ${MINIMAL_BUILD_FLAGS} ${SYSDIG_MUSL_FLAGS}")

	if(BUILD_WARNINGS_AS_ERRORS)
		set(CMAKE_SUPPRESSED_WARNINGS "-Wno-unused-parameter -Wno-missing-field-initializers -Wno-sign-compare -Wno-type-limits -Wno-implicit-fallthrough -Wno-format-truncation -Wno-unused-function")
		set(CMAKE_COMMON_FLAGS "${CMAKE_COMMON_FLAGS} -Wextra -Werror ${CMAKE_SUPPRESSED_WARNINGS}")
	endif()

	if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
	endif()

	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_COMMON_FLAGS}")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_COMMON_FLAGS} -std=c++0x")

	set(CMAKE_C_FLAGS_DEBUG "${DEBUG_FLAGS}")
	set(CMAKE_CXX_FLAGS_DEBUG "${DEBUG_FLAGS}")

	set(CMAKE_C_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")
	set(CMAKE_CXX_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")

	if(CMAKE_SYSTEM_NAME MATCHES "Linux")
		add_definitions(-DHAS_CAPTURE)
	endif()

	if(CMAKE_SYSTEM_NAME MATCHES "SunOS")
		set(CMD_MAKE gmake)
	else()
		set(CMD_MAKE make)
	endif()

else()

	set(SYSDIG_FLAGS_WIN "-D_CRT_SECURE_NO_WARNINGS -DWIN32 /EHsc /W3 /Zi")
	set(SYSDIG_FLAGS_WIN_DEBUG "/MTd /Od")
	set(SYSDIG_FLAGS_WIN_RELEASE "/MT")

	set(CMAKE_C_FLAGS "${SYSDIG_FLAGS_WIN}")
	set(CMAKE_CXX_FLAGS "${SYSDIG_FLAGS_WIN}")

	set(CMAKE_C_FLAGS_DEBUG "${SYSDIG_FLAGS_WIN_DEBUG}")
	set(CMAKE_CXX_FLAGS_DEBUG "${SYSDIG_FLAGS_WIN_DEBUG}")

	set(CMAKE_C_FLAGS_RELEASE "${SYSDIG_FLAGS_WIN_RELEASE}")
	set(CMAKE_CXX_FLAGS_RELEASE "${SYSDIG_FLAGS_WIN_RELEASE}")

endif()

if(APPLE)
	set(CMAKE_EXE_LINKER_FLAGS "-pagezero_size 10000 -image_base 100000000")
endif()

