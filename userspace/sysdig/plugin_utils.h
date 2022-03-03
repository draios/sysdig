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
#include "sysdig.h"
#include "plugin.h"

#include <yaml-cpp/yaml.h>
#include <nlohmann/json.hpp>
#include <third-party/tinydir.h>

//
// Plugin Directory info
//
typedef struct plugin_dir_info
{
    std::string m_dir;
} plugin_dir_info;

typedef struct
{
	std::string path;
	std::string init_config;
} plugin_selected_init;

void add_plugin_dir(string dirname, bool front_add);
void add_plugin_dirs(string sysdig_installation_dir);
std::vector<plugin_dir_info> get_plugin_dirs();
// Select a plugin for initialization. Name can be either a name or a path.
void select_plugin_init(string& name, const string& init_config);
// Select a plugin for use. In case of a source plugin, it will be opened (optionally with parameters) and used.
void select_plugin_enable(string& name, const string& open_params);
void init_plugins(sinsp *inspector);
bool enable_source_plugin(sinsp *inspector);
void parse_plugin_configuration_file(std::string config_filename);

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
