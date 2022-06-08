/*
Copyright (C) 2013-2021 Sysdig Inc.

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

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <sys/stat.h>

#include <sinsp.h>
#include <plugin.h>
#include "sysdig.h"

#include <yaml-cpp/yaml.h>
#include <nlohmann/json.hpp>

class plugin_utils
{
public:
	plugin_utils();

	void add_directory(const std::string& plugins_dir);

	void load_plugin(sinsp *inspector, const string& name);
	void load_plugins_from_dirs(sinsp *inspector);
	void load_plugins_from_conf_file(sinsp *inspector, const std::string& config_filename);

	void init_plugin(sinsp *inspector, const string& name, const string& conf);

	void set_input_plugin(sinsp *inspector, const string& name, const string& params);

	void print_plugins_list(sinsp* inspector, std::ostringstream& os) const;
	void print_plugin_init_schema(sinsp* inspector, const string& name, std::ostringstream& os) const;
	void print_plugin_open_params(sinsp* inspector, const string& name, std::ostringstream& os) const;

	bool has_plugins() const;
	bool has_input_plugin() const;

private:
	struct plugin_entry {
		bool inited;
		std::set<std::string> names;
		std::shared_ptr<sinsp_plugin> plugin;
		
		void init(const std::string& conf);
	};

	void add_dir(std::string dirname, bool front_add);
	plugin_entry& find_plugin(const std::string name);
	const plugin_entry& find_plugin(const std::string name) const;

	bool m_has_input_plugin;
	std::vector<std::string> m_dirs;
	std::vector<plugin_entry> m_plugins;
};

namespace YAML {
	template<>
	struct convert<nlohmann::json> {
		static bool decode(const Node& node, nlohmann::json& res)
		{
			int int_val;
			double double_val;
			bool bool_val;
			std::string str_val;

			switch (node.Type()) {
				case YAML::NodeType::Map:
					for (auto &&it: node)
					{
						nlohmann::json sub{};
						YAML::convert<nlohmann::json>::decode(it.second, sub);
						res[it.first.as<std::string>()] = sub;
					}
					break;
				case YAML::NodeType::Sequence:
					for (auto &&it : node)
					{
						nlohmann::json sub{};
						YAML::convert<nlohmann::json>::decode(it, sub);
						res.emplace_back(sub);
					}
					break;
				case YAML::NodeType::Scalar:
					if (YAML::convert<int>::decode(node, int_val))
					{
						res = int_val;
					}
					else if (YAML::convert<double>::decode(node, double_val))
					{
						res = double_val;
					}
					else if (YAML::convert<bool>::decode(node, bool_val))
					{
						res = bool_val;
					}
					else if (YAML::convert<std::string>::decode(node, str_val))
					{
						res = str_val;
					}
				default:
					break;
			}
			
			return true;
		}
	};
}

