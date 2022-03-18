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

#include "plugin_utils.h"

#include <utility>

vector<plugin_dir_info> g_plugin_dirs;

// Stores user-selected plugins (via '-H' flag)
std::map<std::string, plugin_selected_init> g_selected_plugins_init;
/*
 * Stores actually registered plugins; it can be either:
 *      a map between plugin name and plugin when user did not select any plugin
 *      a map between selected plugin name and plugin.
 *      NOTE: selected plugin name may differ from plugin name (it can be a path to the plugin)
 */
std::map<std::string, std::shared_ptr<sinsp_plugin>> g_selected_plugins_registered;
// Stores user-enabled plugins ('-I' flag)
std::map<std::string, std::string> g_selected_plugins_enable;

void add_plugin_dir(string dirname, bool front_add)
{
    trim(dirname);

    if (dirname[dirname.size() - 1] != '/')
    {
        dirname += "/";
    }

    plugin_dir_info di;
    di.m_dir = std::move(dirname);

    if (front_add)
    {
        g_plugin_dirs.insert(g_plugin_dirs.begin(), di);
    }
    else
    {
        g_plugin_dirs.push_back(di);
    }
}

void add_plugin_dirs(string sysdig_installation_dir)
{
    //
    // Add the default plugin directory statically configured by the build system
    //
    add_plugin_dir(sysdig_installation_dir + PLUGINS_INSTALLATION_DIR, false);

    //
    // Add the directories configured in the SYSDIG_PLUGIN_DIR environment variable
    //
    char *s_user_cdirs = getenv("SYSDIG_PLUGIN_DIR");

    if (s_user_cdirs != NULL)
    {
        vector<string> user_cdirs = sinsp_split(s_user_cdirs, ';');

        for (uint32_t j = 0; j < user_cdirs.size(); j++)
        {
            add_plugin_dir(user_cdirs[j], true);
        }
    }
}

void init_plugins(sinsp *inspector)
{
	// If any plugin was requested to be loaded,
	// only register them
	if (!g_selected_plugins_init.empty())
	{
		for (const auto &pl : g_selected_plugins_init)
		{
			auto plugin = sinsp_plugin::register_plugin(inspector, pl.second.path, pl.second.init_config.c_str());
			g_selected_plugins_registered.emplace(pl.second.path, plugin);
		}
		return;
	}

	// Otherwise, register any available plugin and mark it as selected
    for (const auto & plugin_dir : g_plugin_dirs)
    {
        if (string(plugin_dir.m_dir).empty())
        {
            continue;
        }

        tinydir_dir dir = {};

        for (tinydir_open(&dir, plugin_dir.m_dir.c_str()); dir.has_next; tinydir_next(&dir))
        {
            tinydir_file file;
            tinydir_readfile(&dir, &file);

            string fname(file.name);
            string fpath(file.path);
            string error;

            if (fname == "." || fname == "..")
            {
                continue;
            }

            auto plugin = sinsp_plugin::register_plugin(inspector, file.path, NULL);
	        g_selected_plugins_registered.emplace(plugin->name(), plugin);
        }

        tinydir_close(&dir);
    }
}

void select_plugin_init(string& name, const string& init_config)
{
	// If it is a path, store it!
	if (name.find('/') != string::npos)
	{
		g_selected_plugins_init.emplace(name, plugin_selected_init{name, init_config});
		return;
	}

	// In case users passed "dummy" in place of "libdummy.so"
	string soname = "lib" + name + ".so";

	bool found = false;
	for (const auto & plugin_dir : g_plugin_dirs)
	{
		if (string(plugin_dir.m_dir).empty())
		{
			continue;
		}

		tinydir_dir dir = {};

		tinydir_open(&dir, plugin_dir.m_dir.c_str());

		while (dir.has_next)
		{
			tinydir_file file;
			tinydir_readfile(&dir, &file);

			string fname(file.name);
			string fpath(file.path);
			string error;

			if (fname == name || fname == soname)
			{
				g_selected_plugins_init.emplace(name, plugin_selected_init{fpath, init_config});
				found = true;
				break;
			}

			tinydir_next(&dir);
		}

		if (!found)
		{
			tinydir_close(&dir);
		}
		else
		{
			break;
		}
	}

	if (!found)
	{
		throw sinsp_exception("plugin " + name + " not found. Use -Il to list all installed plugins.");
	}
}

void select_plugin_enable(string& name, const string& open_params)
{
    g_selected_plugins_enable.emplace(name, open_params);
}

bool enable_source_plugin(sinsp *inspector)
{
    bool source_plugin_enabled = false;

    for(const auto& pginfo : g_selected_plugins_enable)
    {
        std::string name = pginfo.first;
        std::string open_params = pginfo.second;

	    auto itr = g_selected_plugins_registered.find(name);
	    if (itr == g_selected_plugins_registered.end())
        {
            throw sinsp_exception("plugin " + name + " not loaded. Use -H to load it.");
        }

        auto plugin = itr->second;
        if (plugin->type() == TYPE_SOURCE_PLUGIN)
        {
            if(source_plugin_enabled)
            {
                throw sinsp_exception("only one source plugin can be enabled at a time.");
            }
            inspector->set_input_plugin(plugin->name());
            inspector->set_input_plugin_open_params(open_params);
            source_plugin_enabled = true;
        }
    }

    return source_plugin_enabled;
}

vector<plugin_dir_info> get_plugin_dirs()
{
    return g_plugin_dirs;
}

void parse_plugin_configuration_file(const std::string config_filename)
{
    YAML::Node config;
    std::string config_explanation = ". See https://falco.org/docs/plugins/#loading-plugins-in-falco for additional information.";
    try {
        config = YAML::LoadFile(config_filename);
    } catch (exception &e)
    {
        throw sinsp_exception("could not read or find configuration file " + config_filename + ": " + e.what());
    }

    if(config.IsNull())
    {
        throw sinsp_exception("could not parse configuration file " + config_filename + ": configuration is empty");
    }

    auto plugins = config["plugins"];

    if(!plugins)
    {
        throw sinsp_exception("could not find \"plugins\" entry in configuration file " + config_filename + config_explanation);
    }

    if(plugins.Type() != YAML::NodeType::Sequence)
    {
        throw sinsp_exception("\"plugins\" must be a list of objects" + config_explanation);
    }

    std::set<std::string> load_plugins;
    bool filter_load_plugins = false;
    if(config["load_plugins"].Type() == YAML::NodeType::Sequence)
    {
        filter_load_plugins = true;
        for(auto plugin_to_load : config["load_plugins"])
        {
            load_plugins.emplace(plugin_to_load.as<std::string>());
        }
    }

    for(auto plugin : plugins) {
        if(!plugin["name"].IsScalar()) {
            throw sinsp_exception("every plugin entry must have a name" + config_explanation);
        }

        if(!plugin["library_path"].IsScalar()) {
            throw sinsp_exception("every plugin entry must have a library_path" + config_explanation);
        }

        std::string name = plugin["name"].as<std::string>();
        std::string library_path = plugin["library_path"].as<std::string>();

        std::string init_config = "";
        std::string open_params = "";

        if(plugin["init_config"].IsMap())
        {
            nlohmann::json json;
            YAML::convert<nlohmann::json>::decode(plugin["init_config"], json);
            init_config = json.dump();
        }
        else if(plugin["init_config"].IsScalar())
        {
            init_config = plugin["init_config"].as<std::string>();
        }

        if(plugin["open_params"]) {
            open_params = plugin["open_params"].as<std::string>();
        }

        if(filter_load_plugins == false || load_plugins.find(name) != load_plugins.end())
        {
            select_plugin_init(library_path, init_config);
            select_plugin_enable(name, open_params);
        }
    }

    return;
}
