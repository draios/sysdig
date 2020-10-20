#
# Copyright (C) 2013-2018 Draios Inc dba Sysdig.
#
# This file is part of sysdig .
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
include_directories(./)
include_directories(../../common)
include_directories(../libscap)
include_directories(../async)
include_directories(./include)
include_directories("${JSONCPP_INCLUDE}")
include_directories("${LUAJIT_INCLUDE}")

if(NOT MINIMAL_BUILD)
	include_directories("${CARES_INCLUDE}")
endif()

if(NOT WIN32 AND NOT APPLE)
	include_directories("${B64_INCLUDE}")
	include_directories("${CURSES_INCLUDE_DIR}")
	if(NOT MINIMAL_BUILD)
		include_directories("${GRPC_INCLUDE}")
		include_directories("${PROTOBUF_INCLUDE}")
		include_directories("${OPENSSL_INCLUDE_DIR}")
		include_directories("${CURL_INCLUDE_DIR}")
	endif() # NOT MINIMAL_BUILD
	include_directories("${JQ_INCLUDE}")
	include_directories("${CMAKE_CURRENT_BINARY_DIR}")
endif()

if(NOT WIN32)
	include_directories("${TBB_INCLUDE_DIR}")
endif() # NOT WIN32

set(SINSP_SOURCES
	chisel.cpp
	chisel_api.cpp
	container.cpp
	container_engine/container_engine_base.cpp
	container_info.cpp
	ctext.cpp
	cyclewriter.cpp
	cursescomponents.cpp
	cursestable.cpp
	cursesspectro.cpp
	cursesui.cpp
	event.cpp
	eventformatter.cpp
	dns_manager.cpp
	dumper.cpp
	fdinfo.cpp
	filter.cpp
	fields_info.cpp
	filterchecks.cpp
	gen_filter.cpp
	http_parser.c
	http_reason.cpp
	ifinfo.cpp
	json_query.cpp
	json_error_log.cpp
	lua_parser.cpp
	lua_parser_api.cpp
	memmem.cpp
	tracers.cpp
	internal_metrics.cpp
	"${JSONCPP_LIB_SRC}"
	logger.cpp
	parsers.cpp
	prefix_search.cpp
	protodecoder.cpp
	threadinfo.cpp
	tuples.cpp
	sinsp.cpp
	stats.cpp
	table.cpp
	token_bucket.cpp
	stopwatch.cpp
	uri_parser.c
	uri.cpp
	user_event_logger.cpp
	utils.cpp
	user_event.cpp
	value_parser.cpp
	viewinfo.cpp
)

if(NOT MINIMAL_BUILD)
	list(APPEND SINSP_SOURCES
		addrinfo.cpp
		sinsp_auth.cpp
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
		k8s_replicationcontroller_handler.cpp
		k8s_replicaset_handler.cpp
		k8s_service_handler.cpp
		k8s_state.cpp
		marathon_component.cpp
		marathon_http.cpp
		mesos_auth.cpp
		mesos.cpp
		mesos_collector.cpp
		mesos_component.cpp
		mesos_http.cpp
		mesos_state.cpp
		sinsp_curl.cpp
		container_engine/docker_common.cpp)
	if(WIN32)
	list(APPEND SINSP_SOURCES
		container_engine/docker_win.cpp)
	else()
	list(APPEND SINSP_SOURCES
		container_engine/docker_linux.cpp
		container_engine/libvirt_lxc.cpp
		container_engine/lxc.cpp
		container_engine/mesos.cpp
		container_engine/rkt.cpp
		container_engine/bpm.cpp
		runc.cpp)
	endif()

	if(NOT WIN32 AND NOT APPLE)
		list(APPEND SINSP_SOURCES
			cgroup_limits.cpp
			cri.cpp
			container_engine/cri.cpp
			${CMAKE_CURRENT_BINARY_DIR}/cri.grpc.pb.cc
			${CMAKE_CURRENT_BINARY_DIR}/cri.pb.cc
			grpc_channel_registry.cpp
		)
	endif()
endif()

add_library(sinsp STATIC ${SINSP_SOURCES})

target_link_libraries(sinsp
	scap
	"${CURL_LIBRARIES}"
	"${JSONCPP_LIB}"
	"${TBB_LIB}"
	"${CARES_LIB}")

if(USE_BUNDLED_LUAJIT)
	add_dependencies(sinsp luajit)
endif()

if(NOT WIN32)
	if(USE_BUNDLED_OPENSSL AND NOT MINIMAL_BUILD)
		add_dependencies(sinsp openssl)
	endif() # USE_BUNDLED_OPENSSL
	if(USE_BUNDLED_CURL AND NOT MINIMAL_BUILD)
		add_dependencies(sinsp curl)
	endif() # USE_BUNDLED_CURL
	if(USE_BUNDLED_TBB)
		add_dependencies(sinsp tbb)
	endif() # USE_BUNDLED_TBB


	if(NOT APPLE)
		if(NOT MINIMAL_BUILD)
			configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cri.proto ${CMAKE_CURRENT_BINARY_DIR}/cri.proto COPYONLY)
			set(CRI_PROTO_PATCH_MUSL_COMMAND "")
			if (MUSL_OPTIMIZED_BUILD)
				# We need to patch the CRI proto while under musl because musl
				# does not fully respect the standard and defines stdin, stdout and stderr
				# as compile time constants. However, those are already defined in cri.proto and that is a reference collision.
				# see: https://git.musl-libc.org/cgit/musl/tree/include/stdio.h?id=0b0640219338b80cf47026d1970b5503414ed7f3#n60
				configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/patch/musl-cri.proto.patch ${CMAKE_CURRENT_BINARY_DIR}/cmake/patch/musl-cri.proto.patch COPYONLY)
				set(CRI_PROTO_PATCH_MUSL_COMMAND patch -d ${CMAKE_CURRENT_BINARY_DIR}  -p3 -i ${CMAKE_CURRENT_BINARY_DIR}/cmake/patch/musl-cri.proto.patch)
			endif()

			add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/cri.grpc.pb.cc
						${CMAKE_CURRENT_BINARY_DIR}/cri.grpc.pb.h
						${CMAKE_CURRENT_BINARY_DIR}/cri.pb.cc
						${CMAKE_CURRENT_BINARY_DIR}/cri.pb.h
					COMMENT "Generate CRI grpc code"
					DEPENDS
					COMMAND ${CRI_PROTO_PATCH_MUSL_COMMAND}
					COMMAND ${PROTOC} -I ${CMAKE_CURRENT_BINARY_DIR} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/cri.proto
					COMMAND ${PROTOC} -I ${CMAKE_CURRENT_BINARY_DIR} --grpc_out=. --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN} ${CMAKE_CURRENT_BINARY_DIR}/cri.proto
					WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

			if(USE_BUNDLED_GRPC)
				add_dependencies(sinsp grpc)
			endif() # USE_BUNDLED_GRPC

			target_link_libraries(sinsp
				"${GRPCPP_LIB}"
				"${GRPC_LIB}"
				"${PROTOBUF_LIB}"
				"${CARES_LIB}"
				"${JQ_LIB}"
				"${B64_LIB}")

			if(NOT MUSL_OPTIMIZED_BUILD)
			target_link_libraries(sinsp
				rt
				anl)
			endif()

		else()
			target_link_libraries(sinsp
				"${JQ_LIB}"
				"${B64_LIB}"
				rt)
		endif() # NOT MINIMAL_BUILD
		# when JQ is compiled statically, it will
		# also compile a static object for oniguruma we need to link
		if(USE_BUNDLED_JQ)
			target_link_libraries(sinsp
			"${ONIGURUMA_LIB}")
		endif()
	endif() # NOT APPLE

        if(USE_BUNDLED_OPENSSL AND NOT MINIMAL_BUILD)
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
endif() # NOT WIN32
