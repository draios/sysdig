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

class sinsp_container_engine_docker
{
	enum docker_response
	{
		RESP_OK = 0,
		RESP_BAD_REQUEST = 1,
		RESP_ERROR = 2
	};

public:
	sinsp_container_engine_docker();

	bool resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info);
	static void cleanup();
	static void set_query_image_info(bool query_image_info);
	static void parse_json_mounts(const Json::Value &mnt_obj, std::vector<sinsp_container_info::container_mount_info> &mounts);

#if !defined(_WIN32)
	enum engine_mode
	{
		DISABLED = 0,
		ENABLED = 1,
		WEAK = 2, // only report container when metadata is found, for Docker-then-CRI mode
	};
	static void set_mode(engine_mode mode);
	static bool detect_docker(const sinsp_threadinfo* tinfo, std::string& container_id);
#endif

protected:
	docker_response get_docker(sinsp_container_manager* manager, const std::string& url, std::string &json);
	std::string build_request(const std::string& url);
	bool parse_docker(sinsp_container_manager* manager, sinsp_container_info *container, sinsp_threadinfo* tinfo);

	static std::string m_api_version;
	static bool m_query_image_info;
#if !defined(_WIN32)
	static engine_mode m_engine_mode;
#endif
};
