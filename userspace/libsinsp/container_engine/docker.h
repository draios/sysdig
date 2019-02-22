/*
Copyright (C) 2013-2019 Draios Inc dba Sysdig.

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
#include <atomic>

#include "json/json.h"

#include "async_key_value_source.h"

#include "sinsp.h"

#include "container_info.h"

class sinsp_container_manager;
class sinsp_container_info;
class sinsp_threadinfo;

namespace libsinsp {
namespace container_engine {

class docker_async_source : public sysdig::async_key_value_source<std::string, std::string>
{
	enum docker_response
	{
		RESP_OK = 0,
		RESP_BAD_REQUEST = 1,
		RESP_ERROR = 2
	};

public:
	docker_async_source(uint64_t max_wait_ms, uint64_t ttl_ms);
	virtual ~docker_async_source();

	void set_inspector(sinsp *inspector);
	static void set_query_image_info(bool query_image_info);

protected:
	void run_impl();

	std::string build_request(const std::string& url);

	docker_response get_docker(const std::string& url, std::string &json);
	bool parse_docker(std::string &container_id, std::string &json);

	static std::string m_api_version;
	sinsp *m_inspector;

	static bool m_query_image_info;
};

class docker
{
public:
	docker();

	bool resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info);
	static void cleanup();
	static void parse_json_mounts(const Json::Value &mnt_obj, std::vector<sinsp_container_info::container_mount_info> &mounts);
	static void set_enabled(bool enabled);

protected:
	void parse_docker_async(sinsp *inspector, std::string &container_id, sinsp_container_manager *manager);

	docker_async_source m_docker_info_source;
	static atomic<bool> m_enabled;
};
}
}
