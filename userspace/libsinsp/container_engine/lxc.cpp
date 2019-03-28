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

#include "container_engine/lxc.h"
#include "sinsp.h"

using namespace libsinsp::container_engine;

bool lxc::resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
	sinsp_container_info container_info;
	bool matches = false;

	for(const auto& it : tinfo->m_cgroups)
	{
		//
		// Non-systemd LXC
		//
		const auto& cgroup = it.second;
		size_t pos = cgroup.find("/lxc/");
		if(pos != std::string::npos)
		{
			auto id_start = pos + sizeof("/lxc/") - 1;
			auto id_end = cgroup.find('/', id_start);
			container_info.m_type = CT_LXC;
			container_info.m_id = cgroup.substr(id_start, id_end - id_start);
			matches = true;
			break;
		}
	}

	if (!matches)
	{
		return false;
	}

	tinfo->m_container_id = container_info.m_id;
	if (!manager->container_exists(container_info.m_id))
	{
		container_info.m_name = container_info.m_id;
		manager->add_container(container_info, tinfo);
		manager->notify_new_container(container_info, tinfo->m_tid);
	}
	return true;
}
