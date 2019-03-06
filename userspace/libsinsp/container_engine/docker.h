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

#include "tbb/concurrent_hash_map.h"

#include "json/json.h"

#include "async_key_value_source.h"

#include "sinsp.h"

#include "container_info.h"

class sinsp_container_manager;
class sinsp_container_info;
class sinsp_threadinfo;

namespace libsinsp {
namespace container_engine {

class docker_async_source : public sysdig::async_key_value_source<std::string, sinsp_container_info>
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

	// Note that this tid is the current top tid for this container
	void set_top_tid(const std::string &container_id, sinsp_threadinfo *tinfo);

	// Update the mapping from container id to top running tid for
	// that container.
	void update_top_tid(std::string &container_id, sinsp_threadinfo *tinfo);

	// Get the thread id of the top thread running in this container.
	int64_t get_top_tid(const std::string &container_id);

        bool pending_lookup(std::string &container_id);

protected:
	void run_impl();

	std::string build_request(const std::string& url);

	docker_response get_docker(const std::string& url, std::string &json);
	bool parse_docker(std::string &container_id, sinsp_container_info *container);

	static std::string m_api_version;
	sinsp *m_inspector;

	static bool m_query_image_info;

	// Maps from container id to the "top" threadinfo in the
	// process heirarchy having that container id that
	// exists. These associations are only maintained while an
	// async lookup of container information is in progress. We
	// use this to ensure that the tid of the CONTAINER_JSON event
	// we eventually emit is the top running thread in the
	// container.
	typedef tbb::concurrent_hash_map<std::string, int64_t> top_tid_table;
	top_tid_table m_top_tids;
};

class docker
{
public:
	docker();

	bool resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info);
	static void cleanup();
	static void parse_json_mounts(const Json::Value &mnt_obj, std::vector<sinsp_container_info::container_mount_info> &mounts);
	static void set_enabled(bool enabled);

	// Container name only set for windows. For linux name must be fetched via lookup
	static bool detect_docker(const sinsp_threadinfo* tinfo, std::string& container_id, std::string &container_name);
protected:
	void parse_docker_async(sinsp *inspector, std::string &container_id, sinsp_container_manager *manager);

	static std::unique_ptr<docker_async_source> g_docker_info_source;
	static bool m_enabled;
};
}
}
