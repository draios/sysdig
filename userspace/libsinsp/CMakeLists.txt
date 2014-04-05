include_directories(./)
include_directories(../../common)
include_directories(../libscap)
include_directories(third-party/jsoncpp)
include_directories(third-party/jsoncpp)
include_directories(${PROJECT_SOURCE_DIR}/third-party/LuaJIT-2.0.2/src)

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
		${PROJECT_SOURCE_DIR}/third-party/LuaJIT-2.0.2/src/libluajit.a
		dl)
else()
	target_link_libraries(sinsp
		${PROJECT_SOURCE_DIR}/third-party/LuaJIT-2.0.2/src/lua51.lib)
endif()