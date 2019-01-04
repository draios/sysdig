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
#include "async_windows_docker_metadata_source.h"
#include "sinsp_int.h"
#include "logger.h"

using namespace sysdig;

const std::string async_windows_docker_metadata_source::DEFAULT_API_VERSION = "/v1.30";

async_windows_docker_metadata_source::async_windows_docker_metadata_source(
		const std::string& api_version,
		const uint16_t port):
	  async_docker_metadata_source(api_version, port)
{
}

std::string async_windows_docker_metadata_source::build_request(const std::string& path)
{
	return "GET " + get_api_version() + path + " HTTP/1.1\r\nHost: docker\r\n\r\n";
}

sinsp_docker_response async_windows_docker_metadata_source::get_docker(
		sinsp_container_manager* const manager,
                const std::string& url,
                std::string &json)
{
 	const char* response = nullptr;

 	const bool qdres = wh_query_docker(manager->get_inspector()->get_wmi_handle(),
	                             const_cast<char*>(url.c_str()),
	                             &response);

 	if(!qdres)
 	{
 		ASSERT(false);
 		return sinsp_docker_response::RESP_ERROR;
 	}
 
 	json = response;
 	if(strncmp(json.c_str(), "HTTP/1.0 200 OK", sizeof("HTTP/1.0 200 OK") - 1))
 	{
 		return sinsp_docker_response::RESP_BAD_REQUEST;
 	}
 
 	size_t pos = json.find("{");
 	if(pos == std::string::npos)
 	{
 		ASSERT(false);
 		return sinsp_docker_response::RESP_ERROR;
 	}
 	json = json.substr(pos);
 
 	return sinsp_docker_response::RESP_OK;
}
