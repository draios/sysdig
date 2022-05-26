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

#ifdef _WIN32
#define SHAREDOBJ_EXT ".dll"
#else
#define SHAREDOBJ_EXT ".so"
#endif

vector<plugin_dir_info> g_plugin_dirs;

/*
 * Stores actually registered plugins; it can be either:
 *      a map between plugin name and plugin when user did not select any plugin (therefore plugins are loaded from system folders)
 *      a map between selected plugin name and plugin (selected through "-H" or conf file)
 *      NOTE: selected plugin name may differ from plugin name (it can be a path to the plugin)
 */
std::map<std::string, std::shared_ptr<sinsp_plugin>> g_selected_plugins_registered;
/*
 * Stores user-enabled plugins ('-I' flag) to be used as input plugins
 * (we only support one input, but conf file mandates the use of multiple ones)
 */
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

void add_plugin_dirs(string sysdig_plugins_dir)
{
    //
    // Add the default plugin directory statically configured by the build system
    //
    add_plugin_dir(std::move(sysdig_plugins_dir), false);

    //
    // Add the directories configured in the SYSDIG_PLUGIN_DIR environment variable
    //
    char *s_user_cdirs = getenv("SYSDIG_PLUGIN_DIR");

    if (s_user_cdirs != nullptr)
    {
        vector<string> user_cdirs = sinsp_split(s_user_cdirs, ';');

        for (auto & user_cdir : user_cdirs)
        {
            add_plugin_dir(user_cdir, true);
        }
    }
}

static bool iterate_plugins_dirs(const std::function<bool(const tinydir_file &)>& predicate)
{
	bool breakout = false;
	for (const auto & plugin_dir : g_plugin_dirs)
	{
		if (string(plugin_dir.m_dir).empty())
		{
			continue;
		}

		tinydir_dir dir = {};

		for (tinydir_open(&dir, plugin_dir.m_dir.c_str()); dir.has_next && !breakout; tinydir_next(&dir))
		{
			tinydir_file file;
			tinydir_readfile(&dir, &file);

			auto namelen = strlen(file.name);
			auto extlen = strlen(SHAREDOBJ_EXT);
			if (file.is_dir
                || strcmp(file.name, ".") == 0
				|| strcmp(file.name, "..") == 0
				|| (namelen > extlen
				    && strcmp(file.name + namelen -extlen, SHAREDOBJ_EXT) != 0))
			{
				continue;
			}

			breakout = predicate(file);
		}

		tinydir_close(&dir);
		if (breakout)
		{
			break;
		}
	}
	return breakout;
}

void init_plugins(sinsp *inspector)
{
	// If any plugin was already registered, it means we are in the
	// "-H"/conf file use case; we already registered any desired plugin!
	if (!g_selected_plugins_registered.empty())
	{
		return;
	}

	iterate_plugins_dirs([&inspector] (const tinydir_file file) -> bool {
		auto plugin = inspector->register_plugin(file.path, "");
		g_selected_plugins_registered.emplace(plugin->name(), plugin);
		return false;
	});
}

void select_plugin_init(sinsp *inspector, string& name, const string& init_config)
{
	// If it is a path, register it
	if (name.find('/') != string::npos)
	{
		auto p = inspector->register_plugin(name, init_config);
		g_selected_plugins_registered.emplace(name, p);
		return;
	}

	// Otherwise, try to find it from system folders

	// In case users passed "dummy" in place of "libdummy.so"
	string soname = "lib" + name + ".so";

	bool found = iterate_plugins_dirs([&inspector, &name, &soname, &init_config] (const tinydir_file file) -> bool {
		if (file.name == name || file.name == soname)
		{
			auto p = inspector->register_plugin(file.path, init_config);
			g_selected_plugins_registered.emplace(name, p);
			return true; // break-out
		}
		return false;
	});
	if (!found)
	{
		throw sinsp_exception("plugin " + name + " not found. Use -Il to list all installed plugins.");
	}
}

// "-I" or config file
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
        if (plugin->caps() & CAP_SOURCING)
        {
            if(source_plugin_enabled)
            {
                throw sinsp_exception("only one source plugin can be enabled at a time.");
            }
            inspector->set_input_plugin(plugin->name(), open_params);
            source_plugin_enabled = true;
        }
    }

    return source_plugin_enabled;
}

vector<plugin_dir_info> get_plugin_dirs()
{
    return g_plugin_dirs;
}

bool parse_plugin_configuration_file(sinsp *inspector, const std::string& config_filename)
{
	bool input_plugin = false;
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

    for (auto plugin : plugins) {
        if (!plugin["name"].IsScalar()) {
            throw sinsp_exception("every plugin entry must have a name" + config_explanation);
        }

        if (!plugin["library_path"].IsScalar()) {
            throw sinsp_exception("every plugin entry must have a library_path" + config_explanation);
        }

        std::string name = plugin["name"].as<std::string>();
        std::string library_path = plugin["library_path"].as<std::string>();

        std::string init_config;
        std::string open_params;

        if (plugin["init_config"].IsMap())
        {
            nlohmann::json json;
            YAML::convert<nlohmann::json>::decode(plugin["init_config"], json);
            init_config = json.dump();
        }
        else if (plugin["init_config"].IsScalar())
        {
            init_config = plugin["init_config"].as<std::string>();
        }

        if (plugin["open_params"]) {
            open_params = plugin["open_params"].as<std::string>();
        }

	    if (!filter_load_plugins || load_plugins.find(name) != load_plugins.end())
        {
	        select_plugin_init(inspector, library_path, init_config);
			// This is always existent, otherwise select_plugin_init() throws an exception
	        auto itr = g_selected_plugins_registered.find(library_path);
	        auto p = itr->second;
	        if (p->caps() & CAP_SOURCING)
	        {
		        select_plugin_enable(library_path, open_params);
		        input_plugin = true;
			}
        }
    }
	return input_plugin;
}
