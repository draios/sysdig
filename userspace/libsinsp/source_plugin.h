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

#include "filterchecks.h"

//
// Events in tracers checks
//
class sinsp_filter_check_plugin : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_CNT = 0,
	};

	sinsp_filter_check_plugin();
//	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering);
	sinsp_filter_check* allocate_new();
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

	void set_name(string name);
	void set_fields(filtercheck_field_info* fields, uint32_t nfields);

	uint64_t m_cnt;
	uint32_t m_id;
	source_plugin_info* m_source_info;
};

class sinsp_source_plugin
{
public:
	sinsp_source_plugin(sinsp* inspector);
	~sinsp_source_plugin();
	void configure(source_plugin_info* plugin_info, char* config);
	uint32_t get_id();

	source_plugin_info m_source_info;

private:
	sinsp* m_inspector;
	uint32_t m_id;
	vector<filtercheck_field_info> m_fields;
};
