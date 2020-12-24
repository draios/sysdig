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

#include "sinsp.h"
#include "sinsp_int.h"
#include "filter.h"
#include "filterchecks.h"
#include "scap_source_interface.h"
#include "source_plugin.h"

sinsp_source_plugin::sinsp_source_plugin(sinsp* inspector)
{
	m_inspector = inspector;
}

sinsp_source_plugin::~sinsp_source_plugin()
{
	if(m_plugin_info.destroy != NULL)
	{
		m_plugin_info.destroy(m_plugin_info.scap_src.state);
	}
}

void sinsp_source_plugin::configure(sinsp_src_interface* plugin_info, char* config)
{
	char error[SCAP_LASTERR_SIZE];
	int init_res;

	ASSERT(m_inspector != NULL);
	ASSERT(plugin_info != NULL);

	m_plugin_info = *plugin_info;

	if(m_plugin_info.get_id == NULL)
	{
		throw sinsp_exception("invalid source plugin: 'get_id' method missing");
	}

	if(m_plugin_info.scap_src.open == NULL)
	{
		throw sinsp_exception("invalid source plugin: 'open' method missing");
	}

	if(m_plugin_info.scap_src.close == NULL)
	{
		throw sinsp_exception("invalid source plugin: 'close' method missing");
	}

	if(m_plugin_info.scap_src.next == NULL)
	{
		throw sinsp_exception("invalid source plugin: 'next' method missing");
	}

	if(m_plugin_info.event_to_string == NULL)
	{
		throw sinsp_exception("invalid source plugin: 'event_to_string' method missing");
	}

	if(m_plugin_info.get_name == NULL)
	{
		throw sinsp_exception("invalid source plugin: 'get_name' method missing");
	}

	//
	// Initialize the plugin
	//
	if(m_plugin_info.init != NULL)
	{
		m_plugin_info.scap_src.state = m_plugin_info.init(config, error, &init_res);
		if(init_res != SCAP_SUCCESS)
		{
			throw sinsp_exception(error);
		}
	}

	m_id = m_plugin_info.get_id();
	m_plugin_info.scap_src.id = m_id;
}

uint32_t sinsp_source_plugin::get_id()
{
	return m_id;
}
