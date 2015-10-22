include_directories(./)
include_directories(../../common)
include_directories(../libscap)
include_directories("${JSONCPP_INCLUDE}")
include_directories("${LUAJIT_INCLUDE}")
include_directories("${B64_INCLUDE}")
include_directories("${CURL_INCLUDE_DIR}")

if(NOT WIN32)
	include_directories("${CURSES_INCLUDE_DIR}")
endif()

add_library(sinsp STATIC
	chisel.cpp
	chisel_api.cpp
	container.cpp
	ctext.cpp
	cyclewriter.cpp
	cursescomponents.cpp
	cursestable.cpp
	cursesui.cpp
	event.cpp
	eventformatter.cpp
	dumper.cpp
	fdinfo.cpp
	filter.cpp
	filterchecks.cpp
	ifinfo.cpp
	k8s.cpp
	k8s_component.cpp
	k8s_dispatcher.cpp
	k8s_event_data.cpp
	k8s_http.cpp
	k8s_net.cpp
	k8s_poller.cpp
	memmem.cpp
	internal_metrics.cpp
	"${JSONCPP_LIB_SRC}"
	logger.cpp
	parsers.cpp
	protodecoder.cpp
	threadinfo.cpp
	sinsp.cpp
	stats.cpp
	table.cpp
	uri.cpp
	utils.cpp
	viewinfo.cpp)

target_link_libraries(sinsp 
	scap
	"${JSONCPP_LIB}"
	"${B64_LIB}"
	"${CURL_LIBRARIES}"
	pthread)

if(NOT WIN32)
	if(USE_BUNDLED_LUAJIT)
		add_dependencies(sinsp luajit)
	endif()

	target_link_libraries(sinsp
		"${LUAJIT_LIB}"
		dl)
else()
	target_link_libraries(sinsp
		"${LUAJIT_LIB}")
endif()
