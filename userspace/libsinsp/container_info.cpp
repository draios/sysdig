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

#include "container_info.h"
#include "sinsp.h"
#include "sinsp_int.h"

const sinsp_container_info::container_mount_info *sinsp_container_info::mount_by_idx(uint32_t idx) const
{
	if (idx >= m_mounts.size())
	{
		return NULL;
	}

	return &(m_mounts[idx]);
}

const sinsp_container_info::container_mount_info *sinsp_container_info::mount_by_source(std::string &source) const
{
	// note: linear search
	for (auto &mntinfo :m_mounts)
	{
		if(sinsp_utils::glob_match(source.c_str(), mntinfo.m_source.c_str()))
		{
			return &mntinfo;
		}
	}

	return NULL;
}

const sinsp_container_info::container_mount_info *sinsp_container_info::mount_by_dest(std::string &dest) const
{
	// note: linear search
	for (auto &mntinfo :m_mounts)
	{
		if(sinsp_utils::glob_match(dest.c_str(), mntinfo.m_dest.c_str()))
		{
			return &mntinfo;
		}
	}

	return NULL;
}

bool sinsp_container_info::is_pod_sandbox() const
{
	return m_is_pod_sandbox || m_name.find("k8s_POD") != std::string::npos;
}

std::string sinsp_container_info::normalize_healthcheck_arg(const std::string &arg)
{
	std::string ret = arg;

	if(ret.empty())
	{
		return ret;
	}

	// Remove pairs of leading/trailing " or ' chars, if present
	while(ret.front() == '"' || ret.front() == '\'')
	{
		if(ret.back() == ret.front())
		{
			ret.pop_back();
			ret.erase(0, 1);
		}
	}

	return ret;
}

void sinsp_container_info::parse_healthcheck(const Json::Value &healthcheck_obj)
{
	if(!healthcheck_obj.isNull())
	{
		const Json::Value &test_obj = healthcheck_obj["Test"];

		if(!test_obj.isNull() && test_obj.isArray() && test_obj.size() >= 2)
		{
			if(test_obj[0].asString() == "CMD")
			{
				m_has_healthcheck = true;
				m_healthcheck_exe = normalize_healthcheck_arg(test_obj[1].asString());

				for(uint32_t i = 2; i < test_obj.size(); i++)
				{
					m_healthcheck_args.push_back(normalize_healthcheck_arg(test_obj[i].asString()));
				}
			}
			else if(test_obj[0].asString() == "CMD-SHELL")
			{
				m_has_healthcheck = true;
				m_healthcheck_exe = "/bin/sh";
				m_healthcheck_args.push_back("-c");
				m_healthcheck_args.push_back(test_obj[1].asString());
			}
		}
	}
}
