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

#include <string>
#include <stdint.h>

class sinsp_container_manager;
class sinsp_container_info;
class sinsp_threadinfo;

class sinsp_container_engine_cri
{
public:
	sinsp_container_engine_cri();

	bool resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info);
	static void cleanup();
	static void set_cri_socket_path(const std::string& path);
	static void set_cri_timeout(int64_t timeout_ms);
};

