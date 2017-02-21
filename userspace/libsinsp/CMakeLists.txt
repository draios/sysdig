include_directories(./)
include_directories(../../common)
include_directories(../libscap)
include_directories("${JSONCPP_INCLUDE}")
include_directories("${LUAJIT_INCLUDE}")

if(NOT WIN32 AND NOT APPLE)
	include_directories("${B64_INCLUDE}")
	include_directories("${CURL_INCLUDE_DIR}")
	include_directories("${CURSES_INCLUDE_DIR}")
	include_directories("${JQ_INCLUDE}")
	include_directories("${OPENSSL_INCLUDE_DIR}")
endif()

add_library(sinsp STATIC
	chisel.cpp
	chisel_api.cpp
	container.cpp
	ctext.cpp
	cyclewriter.cpp
	cursescomponents.cpp
	cursestable.cpp
	cursesspectro.cpp
	cursesui.cpp
	event.cpp
	eventformatter.cpp
	docker.cpp
	dumper.cpp
	fdinfo.cpp
	filter.cpp
	filterchecks.cpp
	http_parser.c
	ifinfo.cpp
	json_query.cpp
	k8s.cpp
	k8s_api_error.cpp
	k8s_api_handler.cpp
	k8s_component.cpp
	k8s_daemonset_handler.cpp
	k8s_deployment_handler.cpp
	k8s_dispatcher.cpp
	k8s_event_data.cpp
	k8s_event_handler.cpp
	k8s_handler.cpp
	k8s_namespace_handler.cpp
	k8s_net.cpp
	k8s_node_handler.cpp
	k8s_pod_handler.cpp
	k8s_pod_handler.cpp
	k8s_replicationcontroller_handler.cpp
	k8s_replicaset_handler.cpp
	k8s_service_handler.cpp
	k8s_state.cpp
	lua_parser.cpp
	lua_parser_api.cpp
	marathon_component.cpp
	marathon_http.cpp
	memmem.cpp
	tracers.cpp
	mesos_auth.cpp
	mesos.cpp
	mesos_collector.cpp
	mesos_component.cpp
	mesos_http.cpp
	mesos_state.cpp
	internal_metrics.cpp
	"${JSONCPP_LIB_SRC}"
	logger.cpp
	parsers.cpp
	prefix_search.cpp
	protodecoder.cpp
	threadinfo.cpp
	sinsp.cpp
	stats.cpp
	table.cpp
	sinsp_auth.cpp
	sinsp_curl.cpp
	stopwatch.cpp
	uri_parser.c
	uri.cpp
	utils.cpp
	user_event.cpp
	value_parser.cpp
	viewinfo.cpp)

target_link_libraries(sinsp 
	scap
	"${JSONCPP_LIB}")

if(NOT WIN32)
	if(USE_BUNDLED_LUAJIT)
		add_dependencies(sinsp luajit)
	endif()

	if(NOT APPLE)
		target_link_libraries(sinsp
			"${JQ_LIB}"
			"${B64_LIB}"
			"${CURL_LIBRARIES}"
			rt
			anl)
	endif()

        if(USE_BUNDLED_OPENSSL)
		target_link_libraries(sinsp
			"${OPENSSL_LIBRARY_SSL}"
			"${OPENSSL_LIBRARY_CRYPTO}")
        else()
		target_link_libraries(sinsp
                    "${OPENSSL_LIBRARIES}")
        endif()

	target_link_libraries(sinsp
		"${LUAJIT_LIB}"
		dl
		pthread)
else()
	target_link_libraries(sinsp
		"${LUAJIT_LIB}")
endif()
