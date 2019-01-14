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

#if defined(LOCAL_DEBUG)
#       include<cstdio>
#       define LOG(fmt, ...) fprintf(stderr, "[%s]:%d: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#       define LOG(fmt, ...) do { } while(false)
#endif

using namespace sysdig;

const std::string async_linux_docker_metadata_source::DEFAULT_DOCKER_SOCKET_PATH = "/var/run/docker.sock";
const std::string async_linux_docker_metadata_source::DEFAULT_API_VERSION = "/v1.24";

async_linux_docker_metadata_source::async_linux_docker_metadata_source(
		const bool query_image_info,
		const std::string& socket_path,
		const std::string& api_version):
	  async_docker_metadata_source(api_version, query_image_info)
	, m_unix_socket_path(scap_get_host_root() + socket_path)
#if defined(HAS_CAPTURE)
        , m_url_fetcher(url_fetcher::new_fetcher(m_unix_socket_path))
#endif
{ }

async_linux_docker_metadata_source::~async_linux_docker_metadata_source()
{
	stop();
}

const std::string& async_linux_docker_metadata_source::get_socket_path() const
{
	return m_unix_socket_path;
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
	sinsp_docker_response response = sinsp_docker_response::RESP_ERROR;

#if defined(HAS_CAPTURE)
	try
	{
		LOG("url: %s", url.c_str());

		const int http_code = m_url_fetcher->fetch(url, json);

		if(http_code == 200)
		{
			response = sinsp_docker_response::RESP_OK;
		}
		else
		{
			g_logger.log("http_code: " + std::to_string(http_code),
				     sinsp_logger::SEV_WARNING);
			response = sinsp_docker_response::RESP_BAD_REQUEST;
		}
	}
	catch(const std::exception& ex)
	{
		g_logger.log(std::string("Failed to fetch URL: ") + ex.what(),
		             sinsp_logger::SEV_WARNING);
		ASSERT(false);
		response = sinsp_docker_response::RESP_ERROR;
	}
#endif // HAS_CAPTURE

	return response;
}
