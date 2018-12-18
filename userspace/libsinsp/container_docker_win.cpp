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

sinsp_container_engine_docker::sinsp_container_engine_docker() :
	m_api_version("/v1.30")
{
}

void sinsp_container_engine_docker::cleanup()
{
}

std::string sinsp_container_engine_docker::build_request(const std::string &url)
{
	return "GET " + m_api_version + url + " HTTP/1.1\r\nHost: docker\r\n\r\n";
}
