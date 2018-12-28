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

#include "container_mesos.h"
#include "sinsp.h"
#include "sinsp_int.h"

#if defined(HAS_CAPTURE)
namespace {
string docker_unix_socket_path = "/var/run/docker.sock";
CURLM *m_curlm = NULL;
CURL *m_curl = NULL;

size_t docker_curl_write_callback(const char* ptr, size_t size, size_t nmemb, string* json)
{
	const std::size_t total = size * nmemb;
	json->append(ptr, total);
	return total;
}

}
#endif

std::string sinsp_container_engine_docker::m_api_version = "/v1.24";

sinsp_container_engine_docker::sinsp_container_engine_docker()
{
#if defined(HAS_CAPTURE)
	if(!m_curlm)
	{
		m_curl = curl_easy_init();
		m_curlm = curl_multi_init();

		if(m_curlm)
		{
			curl_multi_setopt(m_curlm, CURLMOPT_PIPELINING, CURLPIPE_HTTP1|CURLPIPE_MULTIPLEX);
		}

		if(m_curl)
		{
			auto docker_path = scap_get_host_root() + docker_unix_socket_path;
			curl_easy_setopt(m_curl, CURLOPT_UNIX_SOCKET_PATH, docker_path.c_str());
			curl_easy_setopt(m_curl, CURLOPT_HTTPGET, 1);
			curl_easy_setopt(m_curl, CURLOPT_FOLLOWLOCATION, 1);
			curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, docker_curl_write_callback);
		}
	}
#endif
}

void sinsp_container_engine_docker::cleanup()
{
#if defined(HAS_CAPTURE)
	curl_easy_cleanup(m_curl);
	m_curl = NULL;
	curl_multi_cleanup(m_curlm);
	m_curlm = NULL;
#endif
}

std::string sinsp_container_engine_docker::build_request(const std::string &url)
{
	return "http://localhost" + m_api_version + url;
}

bool sinsp_container_engine_docker::resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
	sinsp_container_info container_info;

	if(detect_docker(tinfo, container_info.m_id))
	{
		container_info.m_type = CT_DOCKER;
	}
	else
	{
		return false;
	}
	tinfo->m_container_id = container_info.m_id;
	if (!manager->container_exists(container_info.m_id))
	{
		if (query_os_for_missing_info)
		{
			parse_docker(manager, &container_info, tinfo);
		}
		if (sinsp_container_engine_mesos::set_mesos_task_id(&container_info, tinfo))
		{
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"Mesos Docker container: [%s], Mesos task ID: [%s]",
					container_info.m_id.c_str(), container_info.m_mesos_task_id.c_str());
		}
		manager->add_container(container_info, tinfo);
		manager->notify_new_container(container_info);
	}
	return true;
}

sinsp_container_engine_docker::docker_response sinsp_container_engine_docker::get_docker(sinsp_container_manager* manager, const string& url, string &json)
{
#ifdef HAS_CAPTURE
	if(curl_easy_setopt(m_curl, CURLOPT_URL, url.c_str()) != CURLE_OK)
	{
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}
	if(curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &json) != CURLE_OK)
	{
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}

	if(curl_multi_add_handle(m_curlm, m_curl) != CURLM_OK)
	{
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}

	while(true)
	{
		int still_running;
		CURLMcode res = curl_multi_perform(m_curlm, &still_running);
		if(res != CURLM_OK)
		{
			ASSERT(false);
			return docker_response::RESP_ERROR;
		}

		if(still_running == 0)
		{
			break;
		}

		int numfds;
		res = curl_multi_wait(m_curlm, NULL, 0, -1, &numfds);
		if(res != CURLM_OK)
		{
			ASSERT(false);
			return docker_response::RESP_ERROR;
		}
	}

	if(curl_multi_remove_handle(m_curlm, m_curl) != CURLM_OK)
	{
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}

	long http_code = 0;
	if(curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &http_code) != CURLE_OK)
	{
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}
	switch(http_code)
	{
		case 0: /* connection failed, apparently */
			return docker_response::RESP_ERROR;
		case 200:
			return docker_response::RESP_OK;
		default:
			return docker_response::RESP_BAD_REQUEST;
	}

	return docker_response::RESP_OK;
#else
	return docker_response::RESP_ERROR;
#endif
}

bool sinsp_container_engine_docker::detect_docker(const sinsp_threadinfo *tinfo, std::string &container_id)
{
	for(auto it = tinfo->m_cgroups.begin(); it != tinfo->m_cgroups.end(); ++it)
	{
		string cgroup = it->second;
		size_t pos;

		//
		// Non-systemd Docker
		//
		pos = cgroup.find_last_of("/");
		if(pos != string::npos)
		{
			if(cgroup.length() - pos - 1 == 64 &&
			   cgroup.find_first_not_of("0123456789abcdefABCDEF", pos + 1) == string::npos)
			{
				container_id = cgroup.substr(pos + 1, 12);
				return true;
			}
		}

		//
		// systemd Docker
		//
		pos = cgroup.find("docker-");
		if(pos != string::npos)
		{
			size_t pos2 = cgroup.find(".scope");
			if(pos2 != string::npos &&
			   pos2 - pos - sizeof("docker-") + 1 == 64)
			{
				container_id = cgroup.substr(pos + sizeof("docker-") - 1, 12);
				return true;
			}
		}
	}

	return false;
}