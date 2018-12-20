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

#include "container_docker.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "dragent_win_hal_public.h"

std::string sinsp_container_engine_docker::m_api_version = "/v1.30";

sinsp_container_engine_docker::sinsp_container_engine_docker()
{
}

void sinsp_container_engine_docker::cleanup()
{
}

std::string sinsp_container_engine_docker::build_request(const std::string &url)
{
	return "GET " + m_api_version + url + " HTTP/1.1\r\nHost: docker\r\n\r\n";
}

bool sinsp_container_engine_docker::resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
	wh_docker_container_info wcinfo = wh_docker_resolve_pid(manager->get_inspector()->get_wmi_handle(), tinfo->m_pid);
	if(!wcinfo.m_res)
	{
		return false;
	}

	sinsp_container_info container_info;
	container_info.m_type = CT_DOCKER;
	container_info.m_id = wcinfo.m_container_id;
	container_info.m_name = wcinfo.m_container_name;

	tinfo->m_container_id = container_info.m_id;
	if (!manager->container_exists(container_info.m_id))
	{
		if (query_os_for_missing_info)
		{
			parse_docker(manager, &container_info, tinfo);
		}
		manager->add_container(container_info, tinfo);
		manager->notify_new_container(container_info);
	}
	return true;
}

sinsp_container_engine_docker::docker_response sinsp_container_engine_docker::get_docker(sinsp_container_manager* manager, const string& url, string &json)
{
	const char* response = NULL;
	bool qdres = wh_query_docker(manager->get_inspector()->get_wmi_handle(),
				     (char*)url.c_str(),
				     &response);
	if(qdres == false)
	{
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}

	json = response;
	if(strncmp(json.c_str(), "HTTP/1.0 200 OK", sizeof("HTTP/1.0 200 OK") -1))
	{
		return docker_response::RESP_BAD_REQUEST;
	}

	size_t pos = json.find("{");
	if(pos == string::npos)
	{
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}
	json = json.substr(pos);

	return docker_response::RESP_OK;
}
