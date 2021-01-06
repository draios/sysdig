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
class sinsp_filter_check_plugin;

class sinsp_plugin_desc
{
public:
	string m_name;
	string m_description;
	uint32_t m_id;
};

class sinsp_source_plugin
{
public:
	sinsp_source_plugin(sinsp* inspector);
	~sinsp_source_plugin();
	void configure(ss_plugin_info* plugin_info, char* config);
	uint32_t get_id();
	ss_plugin_type get_type();
	static void register_source_plugins(sinsp* inspector, string sysdig_installation_dir);
	static void list_plugins(sinsp* inspector);

	ss_plugin_info m_source_info;

private:
	static void add_plugin_dirs(sinsp* inspector, string sysdig_installation_dir);
	static void* getsym(void* handle, const char* name);
	static bool create_dynlib_source(string libname, OUT ss_plugin_info* info, OUT string* error);
	static void load_dynlib_plugins(sinsp* inspector);

	sinsp* m_inspector;
	uint32_t m_id;
	vector<filtercheck_field_info> m_fields;
	sinsp_filter_check_plugin* m_filtercheck = NULL;
	ss_plugin_type m_type;
};
