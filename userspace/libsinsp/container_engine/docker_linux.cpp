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

#include "runc.h"
#include "container_engine/mesos.h"
#include "sinsp.h"
#include "sinsp_int.h"

using namespace libsinsp::container_engine;
using namespace libsinsp::runc;

namespace {
std::string s_docker_unix_socket_path = "/var/run/docker.sock";
#if defined(HAS_CAPTURE)
CURLM *s_curlm = NULL;
CURL *s_curl = NULL;

size_t docker_curl_write_callback(const char* ptr, size_t size, size_t nmemb, string* json)
{
	const std::size_t total = size * nmemb;
	json->append(ptr, total);
	return total;
}
#endif

constexpr const cgroup_layout DOCKER_CGROUP_LAYOUT[] = {
	{"/", ""}, // non-systemd docker
	{"/docker-", ".scope"}, // systemd docker
	{nullptr, nullptr}
};
}

std::string docker_async_source::m_api_version = "/v1.24";
bool docker::m_enabled = true;
std::unique_ptr<docker_async_source> docker::g_docker_info_source;

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

	g_docker_info_source.reset(NULL);
	m_enabled = true;
#endif
}

std::string docker_async_source::build_request(const std::string &url)
{
	return "http://localhost" + m_api_version + url;
}

docker_async_source::docker_response docker_async_source::get_docker(const std::string& url, std::string &json)
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
			docker::set_enabled(false);
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

bool docker::detect_docker(const sinsp_threadinfo *tinfo, std::string &container_id, std::string &container_name)
{
	if(matches_runc_cgroups(tinfo, DOCKER_CGROUP_LAYOUT, container_id))
	{
		// The container name is only available in windows
		container_name = "incomplete";

		return true;
	}

	return false;
}
