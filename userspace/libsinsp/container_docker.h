/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "json/json.h"

#include "container_info.h"

class sinsp_container_manager;
class sinsp_container_info;
class sinsp_threadinfo;

#if !defined(_WIN32) && !defined(CYGWING_AGENT) && defined(HAS_CAPTURE)
#include <curl/curl.h>
#include <curl/easy.h>
#include <curl/multi.h>

namespace runtime {
namespace v1alpha2 {
class ContainerStatus;
}
}

#ifndef CONTAINER_CPP
// a class that no-op extends RuntimeService::Stub from the CRI GRPC header
// we can't include the header due to conflicts with ncurses in table.cc
// and  we can't forward-declare a nested class
class RuntimeService_Stub;
#endif
#endif

enum sinsp_docker_response
{
	RESP_OK = 0,
	RESP_BAD_REQUEST = 1,
	RESP_ERROR = 2
};

class sinsp_container_engine_docker
{
public:
	sinsp_container_engine_docker();

	bool resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info);
	static void cleanup();
	static void set_query_image_info(bool query_image_info);
	static void set_cri_socket_path(const std::string& path) {
#if !defined(CYGWING_AGENT) && defined(HAS_CAPTURE)
		m_cri_unix_socket_path = path;
#endif
	}
	static void parse_json_mounts(const Json::Value &mnt_obj, std::vector<sinsp_container_info::container_mount_info> &mounts);

protected:
#if !defined(CYGWING_AGENT) && defined(HAS_CAPTURE)
	static size_t curl_write_callback(const char* ptr, size_t size, size_t nmemb, std::string* json);
	inline bool parse_cri_mounts(const runtime::v1alpha2::ContainerStatus& status, sinsp_container_info *container);
	inline bool parse_cri_image(const runtime::v1alpha2::ContainerStatus& status, sinsp_container_info *container);
	inline bool parse_cri_env(const Json::Value& info, sinsp_container_info *container);
	inline bool parse_cri_runtime_spec(const Json::Value& info, sinsp_container_info *container);
	inline uint32_t get_pod_sandbox_ip(const std::string& pod_sandbox_id);
#endif
	sinsp_docker_response get_docker(sinsp_container_manager* manager, const std::string& url, std::string &json);
	std::string build_request(const std::string& url);
	bool parse_docker(sinsp_container_manager* manager, sinsp_container_info *container, sinsp_threadinfo* tinfo);
	bool parse_containerd(sinsp_container_manager* manager, sinsp_container_info *container, sinsp_threadinfo* tinfo);
	std::string m_api_version;

	static bool m_query_image_info;
#if !defined(CYGWING_AGENT) && defined(HAS_CAPTURE)
	static std::string m_unix_socket_path;
	static std::string m_cri_unix_socket_path;
	static CURLM *m_curlm;
	static CURL *m_curl;

	static std::unique_ptr<RuntimeService_Stub> m_cri;
#endif
};

