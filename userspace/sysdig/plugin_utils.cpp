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

struct PluginLoaded
{
	PluginLoaded(string& path, string& init_conf) : path(path), init_config(init_conf)
	{}
	string path;
	string init_config;
};

vector<plugin_dir_info> g_plugin_dirs;
map<string, PluginLoaded> g_loaded_plugins;

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

void register_plugins(sinsp *inspector)
{
	// If any plugin was requested to be loaded,
	// only register them
	if (!g_loaded_plugins.empty())
	{
		for (const auto &pl : g_loaded_plugins)
		{
			sinsp_plugin::register_plugin(inspector, pl.second.path, pl.second.init_config.c_str());
		}
		return;
	}

	// Otherwise, register any available plugin
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

            if (fname == "." || fname == "..")
            {
                goto nextfile;
            }

            sinsp_plugin::register_plugin(inspector, file.path, NULL);

        nextfile:
            tinydir_next(&dir);
        }

        tinydir_close(&dir);
    }
}

void load_plugin(string& name, string& init_config)
{
	// If it is a path, store it!
	if (name.find('/') != string::npos)
	{
		g_loaded_plugins.emplace(name, PluginLoaded(name, init_config));
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
				g_loaded_plugins.emplace(name, PluginLoaded(fpath, init_config));
				found = true;
				break;
			}

			tinydir_next(&dir);
		}

		tinydir_close(&dir);
	}
	if (!found)
	{
		throw sinsp_exception("plugin " + name + " not found. Use -Il to list all installed plugins.");
	}
}

shared_ptr<sinsp_plugin> enable_plugin(sinsp *inspector, string& name)
{
	auto itr = g_loaded_plugins.find(name);
	if (itr == g_loaded_plugins.end())
	{
		throw sinsp_exception("plugin " + name + " not loaded. Use -H to load it.");
	}
	auto plugin = sinsp_plugin::register_plugin(inspector, itr->second.path, itr->second.init_config.c_str());
	return plugin;
}

const std::vector<plugin_dir_info> get_plugin_dirs() {
    return g_plugin_dirs;
}