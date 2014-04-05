include_directories(./)
include_directories(../../common)
include_directories(../libscap)
include_directories(third-party/jsoncpp)
include_directories(third-party/jsoncpp)
include_directories(${LUAJIT_INCLUDE})

add_library(sinsp STATIC
	chisel.cpp
	event.cpp
	eventformatter.cpp
	dumper.cpp
	fdinfo.cpp
	filter.cpp
	filterchecks.cpp
	ifinfo.cpp
	internal_metrics.cpp
	third-party/jsoncpp/jsoncpp.cpp
	logger.cpp
	parsers.cpp
	threadinfo.cpp
	sinsp.cpp
	stats.cpp
	utils.cpp)

target_link_libraries(sinsp 
	scap)

if(NOT WIN32)
	add_dependencies(sinsp luajit)
	
	target_link_libraries(sinsp
		${LUAJIT_LIB}
		dl)
else()
	target_link_libraries(sinsp
		${LUAJIT_LIB})
endif()
