/*
Copyright (C) 2013-2022 Sysdig Inc.

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

#include <vector>
#include <string>
#include <memory>
#include <unordered_set>
#include <sinsp.h>
#include <plugin.h>

class plugin_utils
{
public:
	plugin_utils();

	void add_directory(const std::string& plugins_dir);

	void load_plugin(sinsp *inspector, const std::string& name);
	void read_plugins_from_dirs(sinsp *inspector);
	void load_plugins_from_conf_file(sinsp *inspector, filter_check_list* flist, const std::string& config_filename, bool set_input);

	void config_plugin(sinsp *inspector, const std::string& name, const std::string& conf);

	void select_input_plugin(sinsp *inspector, filter_check_list* flist, const std::string& name, const std::string& params);
	void clear_input_plugin();

	void print_plugin_info(sinsp* inspector, filter_check_list* flist, const std::string& name);
	void print_plugin_info_list(sinsp* inspector);
	void print_field_extraction_support(sinsp* inspector, const std::string& field);

	bool has_plugins() const;
	bool has_input_plugin() const;
	const std::string& input_plugin_name() const;
	const std::string& input_plugin_params() const;

	void init_loaded_plugins(sinsp* inspector, filter_check_list* flist);
	std::vector<std::string> get_event_sources(sinsp *inspector);
	std::vector<std::unique_ptr<sinsp_filter_check>> get_filterchecks(sinsp *inspector, const std::string& source);

private:
	struct plugin_entry
	{
		bool used = false;
		bool inited = false;
		std::string libpath;
		std::string init_config;
		std::unordered_set<std::string> names;
		
		void init(sinsp *inspector, filter_check_list* flist);
		void print_info(sinsp* inspector, std::ostringstream& os) const;
		std::shared_ptr<sinsp_plugin> get_plugin(sinsp *inspector) const;
	};

	void add_dir(std::string dirname, bool front_add);
	plugin_entry& find_plugin(const std::string name);
	const plugin_entry& find_plugin(const std::string name) const;

	std::string m_input_plugin_name;
	std::string m_input_plugin_params;
	std::vector<std::string> m_dirs;
	std::vector<plugin_entry> m_plugins;
};

