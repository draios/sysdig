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

#include "container_engine/docker.h"

#include "container_engine/mesos.h"
#include "sinsp.h"
#include "sinsp_int.h"

using namespace libsinsp::container_engine;

#if defined(HAS_CAPTURE)
namespace {
std::string s_docker_unix_socket_path = "/var/run/docker.sock";
CURLM *s_curlm = NULL;
CURL *s_curl = NULL;

size_t docker_curl_write_callback(const char* ptr, size_t size, size_t nmemb, string* json)
{
	const std::size_t total = size * nmemb;
	json->append(ptr, total);
	return total;
}

}
#endif

std::string docker::m_api_version = "/v1.24";
bool libsinsp::container_engine::docker::m_enabled = true;

docker::docker()
{
#if defined(HAS_CAPTURE)
	if(!s_curlm)
	{
		s_curl = curl_easy_init();
		s_curlm = curl_multi_init();

		if(s_curlm)
		{
			curl_multi_setopt(s_curlm, CURLMOPT_PIPELINING, CURLPIPE_HTTP1|CURLPIPE_MULTIPLEX);
		}

		if(s_curl)
		{
			auto docker_path = scap_get_host_root() + s_docker_unix_socket_path;
			curl_easy_setopt(s_curl, CURLOPT_UNIX_SOCKET_PATH, docker_path.c_str());
			curl_easy_setopt(s_curl, CURLOPT_HTTPGET, 1);
			curl_easy_setopt(s_curl, CURLOPT_FOLLOWLOCATION, 1);
			curl_easy_setopt(s_curl, CURLOPT_WRITEFUNCTION, docker_curl_write_callback);
		}
	}
#endif
}

void docker::cleanup()
{
#if defined(HAS_CAPTURE)
	curl_easy_cleanup(s_curl);
	s_curl = NULL;
	curl_multi_cleanup(s_curlm);
	s_curlm = NULL;

	m_enabled = true;
#endif
}

std::string docker::build_request(const std::string &url)
{
	return "http://localhost" + m_api_version + url;
}

bool docker::resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
	sinsp_container_info container_info;

	if (!m_enabled)
	{
		return false;
	}

	if(detect_docker(tinfo, container_info.m_id))
	{
		container_info.m_type = CT_DOCKER;
		tinfo->m_container_id = container_info.m_id;
	}
	else
	{
		return false;
	}
	if (!manager->container_exists(container_info.m_id))
	{
		if (query_os_for_missing_info)
		{
			if (!parse_docker(manager, &container_info, tinfo))
			{
				// give CRI a chance to return metadata for this container
				g_logger.format(sinsp_logger::SEV_DEBUG, "Failed to get Docker metadata for container %s",
					container_info.m_id.c_str());
				return false;
			}
		}
		if (mesos::set_mesos_task_id(&container_info, tinfo))
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

docker::docker_response libsinsp::container_engine::docker::get_docker(sinsp_container_manager* manager, const std::string& url, std::string &json)
{
#ifdef HAS_CAPTURE
	if(curl_easy_setopt(s_curl, CURLOPT_URL, url.c_str()) != CURLE_OK)
	{
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}
	if(curl_easy_setopt(s_curl, CURLOPT_WRITEDATA, &json) != CURLE_OK)
	{
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}

	if(curl_multi_add_handle(s_curlm, s_curl) != CURLM_OK)
	{
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}

	while(true)
	{
		int still_running;
		CURLMcode res = curl_multi_perform(s_curlm, &still_running);
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
		res = curl_multi_wait(s_curlm, NULL, 0, -1, &numfds);
		if(res != CURLM_OK)
		{
			ASSERT(false);
			return docker_response::RESP_ERROR;
		}
	}

	if(curl_multi_remove_handle(s_curlm, s_curl) != CURLM_OK)
	{
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}

	long http_code = 0;
	if(curl_easy_getinfo(s_curl, CURLINFO_RESPONSE_CODE, &http_code) != CURLE_OK)
	{
		ASSERT(false);
		return docker_response::RESP_ERROR;
	}
	switch(http_code)
	{
		case 0: /* connection failed, apparently */
			g_logger.format(sinsp_logger::SEV_NOTICE, "Docker connection failed, disabling Docker container engine");
			m_enabled = false;
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

bool docker::detect_docker(const sinsp_threadinfo *tinfo, std::string &container_id)
{
	for(auto it = tinfo->m_cgroups.begin(); it != tinfo->m_cgroups.end(); ++it)
	{
		std::string cgroup = it->second;
		size_t pos;

		//
		// Non-systemd Docker
		//
		pos = cgroup.find_last_of("/");
		if(pos != std::string::npos)
		{
			if(cgroup.length() - pos - 1 == 64 &&
			   cgroup.find_first_not_of("0123456789abcdefABCDEF", pos + 1) == std::string::npos)
			{
				container_id = cgroup.substr(pos + 1, 12);
				return true;
			}
		}

		//
		// systemd Docker
		//
		pos = cgroup.find("docker-");
		if(pos != std::string::npos)
		{
			size_t pos2 = cgroup.find(".scope");
			if(pos2 != std::string::npos &&
			   pos2 - pos - sizeof("docker-") + 1 == 64)
			{
				container_id = cgroup.substr(pos + sizeof("docker-") - 1, 12);
				return true;
			}
		}

		if(cgroup.length() > 64) {
			g_logger.format(sinsp_logger::SEV_INFO, "GS_DEBUG_MSG: Container cgroup with id %s (tid %lu, comm %s) of l > 64 did not have a valid container id.",
					cgroup.c_str(), tinfo->m_tid, tinfo->m_comm.c_str());
		}
	}

	return false;
}
