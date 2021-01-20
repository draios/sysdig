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

#include "sinsp.h"

#include "container_engine/static_container.h"

using namespace libsinsp::container_engine;

static_container::static_container(container_cache_interface& cache,
                                   const std::string& id,
                                   const std::string& name,
                                   const std::string& image)
    : container_engine_base(cache)
{
	m_static_container_info = std::make_shared<sinsp_container_info>();
	m_static_container_info->m_id = id;
	m_static_container_info->m_type = CT_STATIC;
	m_static_container_info->m_name = name;
	m_static_container_info->m_image = image;

	cache.add_container(m_static_container_info, nullptr);
}

bool static_container::resolve(sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
	tinfo->m_container_id = m_static_container_info->m_id;
	return true;
}
