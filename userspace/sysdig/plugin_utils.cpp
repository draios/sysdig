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
#include <third-party/tinydir.h>

#ifdef _WIN32
#define SHAREDOBJ_EXT ".dll"
#else
#define SHAREDOBJ_EXT ".so"
#endif

static inline void throw_not_found(std::string name)
{
    throw sinsp_exception("plugin not found, use -Il to list all the installed plugins: " + name);
}

static inline void throw_no_source_cap(std::string name)
{
    throw sinsp_exception("plugin does not support the event sourcing capability: " + name);
}

static bool iterate_plugins_dirs(
    const std::vector<std::string>& dirs,
    const std::function<bool(const tinydir_file &)>& predicate)
{
	bool breakout = false;
	for (const auto & plugin_dir : dirs)
	{
		if (plugin_dir.empty())
		{
			continue;
		}

		tinydir_dir dir = {};

		for (tinydir_open(&dir, plugin_dir.c_str()); dir.has_next && !breakout; tinydir_next(&dir))
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

void plugin_utils::plugin_entry::init(const std::string& conf)
{
    if (!inited)
    {
        std::string err;
        if (!plugin->init(conf, err))
        {
            throw sinsp_exception(err.c_str());
        }
        if (plugin->caps() & CAP_EXTRACTION)
        {
            g_filterlist.add_filter_check(sinsp_plugin::new_filtercheck(plugin));
        }
        inited = true;
    }
}

void plugin_utils::add_dir(std::string dirname, bool front_add)
{
    trim(dirname);

    if (dirname[dirname.size() - 1] != '/')
    {
        dirname += "/";
    }

    if (front_add)
    {
        m_dirs.insert(m_dirs.begin(), std::move(dirname));
    }
    else
    {
        m_dirs.push_back(std::move(dirname));
    }
}

plugin_utils::plugin_utils()
    : m_has_input_plugin(false)
{
    //
    // Add the directories configured in the SYSDIG_PLUGIN_DIR environment variable
    //
    char *s_user_cdirs = getenv("SYSDIG_PLUGIN_DIR");

    if (s_user_cdirs != nullptr)
    {
        vector<string> user_cdirs = sinsp_split(s_user_cdirs, ';');

        for (auto & user_cdir : user_cdirs)
        {
            add_dir(user_cdir, true);
        }
    }
}

bool plugin_utils::has_plugins() const
{
    return !m_plugins.empty();
}

bool plugin_utils::has_input_plugin() const
{
    return m_has_input_plugin;
}

void plugin_utils::add_directory(const std::string& plugins_dir)
{
    add_dir(plugins_dir, false);
}

void plugin_utils::load_plugin(sinsp *inspector, const string& name)
{
    // If it is a path, register it
	if (name.find('/') != string::npos)
	{
        plugin_entry p;
        p.inited = false;
		p.plugin = inspector->register_plugin(name);
        p.names.insert(name);
        p.names.insert(p.plugin->name());
        m_plugins.push_back(p);
		return;
	}

	// Otherwise, try to find it from system folders

	// In case users passed "dummy" in place of "libdummy.so"
	string soname = "lib" + name + ".so";
    auto& plugins = m_plugins;
	bool found = iterate_plugins_dirs(m_dirs, [&inspector, &name, &soname, &plugins] (const tinydir_file file) -> bool {
		if (file.name == name || file.name == soname)
		{
            plugin_entry p;
            p.inited = false;
            p.plugin = inspector->register_plugin(file.path);
            p.names.insert(file.path);
            p.names.insert(file.name);
            p.names.insert(p.plugin->name());
            plugins.push_back(p);
			return true; // break-out
		}
		return false;
	});
	if (!found)
	{
		throw_not_found(name);
	}
}

void plugin_utils::load_plugins_from_dirs(sinsp *inspector)
{
    auto& plugins = m_plugins;
    iterate_plugins_dirs(m_dirs, [&inspector, &plugins] (const tinydir_file file) -> bool {
        plugin_entry p;
        p.inited = false;
        p.plugin = inspector->register_plugin(file.path);
        p.names.insert(file.path);
        p.names.insert(file.name);
        p.names.insert(p.plugin->name());
        p.init("");
        plugins.push_back(p);
        return false;
	});
}

plugin_utils::plugin_entry& plugin_utils::find_plugin(const std::string name)
{
    for (auto &p : m_plugins)
    {
        if (p.names.find(name) != p.names.end())
        {
            return p;
        }
    }
    throw_not_found(name);
}

const plugin_utils::plugin_entry& plugin_utils::find_plugin(const std::string name) const
{
    for (auto &p : m_plugins)
    {
        if (p.names.find(name) != p.names.end())
        {
            return p;
        }
    }
    throw_not_found(name);
}

void plugin_utils::init_plugin(sinsp *inspector, const string& name, const string& conf)
{
    auto& p = find_plugin(name);
    p.init(conf);
}

void plugin_utils::set_input_plugin(sinsp *inspector, const string& name, const string& params)
{
    auto& p = find_plugin(name);
    if (p.plugin->caps() & CAP_SOURCING)
    {
        if (m_has_input_plugin)
        {
            throw sinsp_exception("using more than one plugin as input is not supported");
        }
        inspector->set_input_plugin(p.plugin->name(), params);
        g_filterlist.add_filter_check(inspector->new_generic_filtercheck());
        m_has_input_plugin = true;
        return;
    }
    throw_no_source_cap(name);
}

void plugin_utils::print_plugins_list(sinsp* inspector, std::ostringstream& os) const
{
	std::ostringstream os_dirs, os_info;

	for(const auto& path : m_dirs)
	{
		os_dirs << path << " ";
	}

	for (auto &pl : m_plugins)
	{
        auto p = pl.plugin;
		os_info << "Name: " << p->name() << std::endl;
		os_info << "Description: " << p->description() << std::endl;
		os_info << "Contact: " << p->contact() << std::endl;
		os_info << "Version: " << p->plugin_version().as_string() << std::endl;
		os_info << "Capabilities: " << std::endl;
		if(p->caps() & CAP_SOURCING)
		{
			os_info << "  - Event Sourcing (ID=" << p->id();
			os_info << ", source='" << p->event_source() << "')" << std::endl;
		}
		if(p->caps() & CAP_EXTRACTION)
		{
			os_info << "  - Field Extraction" << std::endl;
		}
		os_info << std::endl;
	}

	os << "Plugin search paths are: " << os_dirs.str() << std::endl;
	os << m_plugins.size() << " Plugins Loaded:" << std::endl << std::endl << os_info.str() << std::endl;
}

void plugin_utils::print_plugin_init_schema(sinsp* inspector, const string& name, std::ostringstream& os) const
{
    auto& p = find_plugin(name);
    ss_plugin_schema_type type;
    auto schema = p.plugin->get_init_schema(type);
    os << "Plugin: " << p.plugin->name() << std::endl;
    switch (type)
    {
        case SS_PLUGIN_SCHEMA_JSON:
            os << "Schema type: JSON" << std::endl;
            break;
        case SS_PLUGIN_SCHEMA_NONE:
        default:
            os << "No init config schema available" << std::endl;
            break;
    }
    os << schema << std::endl;
}

void plugin_utils::print_plugin_open_params(sinsp* inspector, const string& name, std::ostringstream& os) const
{
    auto& p = find_plugin(name);
    if (p.plugin->caps() & CAP_SOURCING)
    {
        auto params = p.plugin->list_open_params();
        os << "Plugin: " << p.plugin->name() << std::endl;
        if (params.empty())
        {
            os << "No suggested open params available" << std::endl;
        }
        else
        {
            os << "Suggested open params:" << std::endl;
            for(auto &oparam : p.plugin->list_open_params())
            {
                if(oparam.desc == "")
                {
                    os << oparam.value << std::endl;
                }
                else
                {
                    os << oparam.value << ": " << oparam.desc << std::endl;
                }
            }
        }
        return;
    }
    throw_no_source_cap(name);
}

void plugin_utils::load_plugins_from_conf_file(sinsp *inspector, const std::string& config_filename)
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
            load_plugin(inspector, library_path);
            init_plugin(inspector, library_path, init_config);
            auto& p = find_plugin(library_path);
            if (p.plugin->caps() & CAP_SOURCING)
            {
                set_input_plugin(inspector, library_path, open_params);
            }
        }
    }
}