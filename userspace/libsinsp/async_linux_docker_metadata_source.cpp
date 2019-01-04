/*
Copyright (C) 2018 Sysdig, Inc.

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
#include "async_linux_docker_metadata_source.h"
#include "sinsp_int.h"
#include "logger.h"

using namespace sysdig;

namespace
{

const std::string s_docker_socket_path = "/var/run/docker.sock";

#if defined(HAS_CAPTURE)
/**
 * Handles callbacks from libcurl to build a string representation of the
 * document that its fetching.
 */
size_t docker_curl_write_callback(const char* const ptr,
                                  const size_t size,
                                  const size_t nmemb,
                                  std::string* const json)
{
	const std::size_t total = size * nmemb;

	json->append(ptr, total);

	return total;
}
#endif

} // end namespace

const std::string async_linux_docker_metadata_source::DEFAULT_API_VERSION = "/v1.24";

async_linux_docker_metadata_source::async_linux_docker_metadata_source(
		const std::string& api_version,
		const uint16_t port):
	  async_docker_metadata_source(api_version, port)
	, m_unix_socket_path(scap_get_host_root() + s_docker_socket_path)
#if defined(HAS_CAPTURE)
	, m_curl(curl_easy_init())
	, m_curlm(curl_multi_init())
#endif
{
#if defined(HAS_CAPTURE)
	if(m_curlm != nullptr)
	{
		curl_multi_setopt(m_curlm,
		                  CURLMOPT_PIPELINING,
		                  CURLPIPE_HTTP1 | CURLPIPE_MULTIPLEX);
	}

	if(m_curl != nullptr)
	{
		curl_easy_setopt(m_curl, CURLOPT_UNIX_SOCKET_PATH, m_unix_socket_path.c_str());
		curl_easy_setopt(m_curl, CURLOPT_HTTPGET, 1);
		curl_easy_setopt(m_curl, CURLOPT_FOLLOWLOCATION, 1);
		curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, docker_curl_write_callback);
	}
#endif
}

async_linux_docker_metadata_source::~async_linux_docker_metadata_source()
{
#if defined(HAS_CAPTURE)
	curl_easy_cleanup(m_curl);
	curl_multi_cleanup(m_curlm);
#endif
}

std::string async_linux_docker_metadata_source::build_request(const std::string& path)
{
	return "http://localhost" + get_api_version() + path;
}

sinsp_docker_response async_linux_docker_metadata_source::get_docker(
		sinsp_container_manager* const,
                const std::string& url,
                std::string &json)
{
#if defined(HAS_CAPTURE)

	if(curl_easy_setopt(m_curl, CURLOPT_URL, url.c_str()) != CURLE_OK)
	{
		ASSERT(false);
		return sinsp_docker_response::RESP_ERROR;
	}

	if(curl_easy_setopt(m_curl, CURLOPT_PORT, get_port()) != CURLE_OK)
	{
		ASSERT(false);
		return sinsp_docker_response::RESP_ERROR;
	}

	if(curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &json) != CURLE_OK)
	{
		ASSERT(false);
		return sinsp_docker_response::RESP_ERROR;
	}

	if(curl_multi_add_handle(m_curlm, m_curl) != CURLM_OK)
	{
		ASSERT(false);
		return sinsp_docker_response::RESP_ERROR;
	}

	while(true)
	{
		int still_running = 42;
		CURLMcode res = curl_multi_perform(m_curlm, &still_running);

		if(res != CURLM_OK)
		{
			ASSERT(false);
			return sinsp_docker_response::RESP_ERROR;
		}

		if(still_running == 0)
		{
			break;
		}

		int numfds = 0;
		res = curl_multi_wait(m_curlm, NULL, 0, -1, &numfds);
		if(res != CURLM_OK)
		{
			ASSERT(false);
			return sinsp_docker_response::RESP_ERROR;
		}
	}

	if(curl_multi_remove_handle(m_curlm, m_curl) != CURLM_OK)
	{
		ASSERT(false);
		return sinsp_docker_response::RESP_ERROR;
	}

	long http_code = 0;
	if(curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &http_code) != CURLE_OK)
	{
		ASSERT(false);
		return sinsp_docker_response::RESP_ERROR;
	}

	if(http_code != 200)
	{
		g_logger.log("http_code: " + std::to_string(http_code),
		             sinsp_logger::SEV_WARNING);
		return sinsp_docker_response::RESP_BAD_REQUEST;
	}

	return sinsp_docker_response::RESP_OK;
#else /* HAS_CAPTURE */
	return sinsp_docker_response::RESP_ERROR;
#endif /* HAS_CAPTURE */
}

