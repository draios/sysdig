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

#include "common.h"
#include "plugin_utils.h"

#include <unordered_set>

#include <utility>
#include <tinydir.h>
#include <yaml-cpp/yaml.h>
#include <nlohmann/json.hpp>

#include <filterchecks.h>
#include <plugin_manager.h>

#ifdef _WIN32
#define SHAREDOBJ_PREFIX ""
#define SHAREDOBJ_EXT    ".dll"
#else
#define SHAREDOBJ_PREFIX "lib"
#define SHAREDOBJ_EXT    ".so"
#endif

static const char* err_plugin_not_found = "plugin not found, use -Il to list all the installed plugins: ";
static const char* err_plugin_no_source_cap = "plugin does not support the event sourcing capability: ";

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

void plugin_utils::plugin_entry::init(sinsp *inspector, filter_check_list* flist)
{
    std::string err;
    auto plugin = get_plugin(inspector);
    if (!plugin->init(init_config, err))
    {
        throw sinsp_exception(err.c_str());
    }
    if (plugin->caps() & CAP_EXTRACTION)
    {
        // todo(jasondellaluce): manage field name conflicts
        flist->add_filter_check(sinsp_plugin::new_filtercheck(plugin));
    }
    inited = true;
}

std::shared_ptr<sinsp_plugin> plugin_utils::plugin_entry::get_plugin(sinsp *inspector) const
{
    for (auto& p : inspector->get_plugin_manager()->plugins())
    {
        const auto& name = p->name();
        if (names.find(name) != names.end())
        {
            return p;
        }
    }
    return inspector->register_plugin(libpath);
}

void plugin_utils::init_loaded_plugins(sinsp* inspector, filter_check_list* flist)
{
    for (auto &p : m_plugins)
    {
        if (p.used && !p.inited)
        {
            p.init(inspector, flist);
        }
    }
}

void plugin_utils::plugin_entry::print_info(sinsp* inspector, std::ostringstream& os) const
{
    auto plugin = get_plugin(inspector);
    os << "Name: " << plugin->name() << std::endl;
    os << "Description: " << plugin->description() << std::endl;
    os << "Contact: " << plugin->contact() << std::endl;
    os << "Version: " << plugin->plugin_version().as_string() << std::endl;
    os << "Capabilities: " << std::endl;
    if(plugin->caps() & CAP_SOURCING)
    {
        os << "  - Event Sourcing";
        if (plugin->id() != 0)
        {
            os << " (ID=" << plugin->id();
            os << ", source='" << plugin->event_source() << "')";
        }
        else
        {
            os << " (system events)";
        }
        os << std::endl;
    }
    if(plugin->caps() & CAP_EXTRACTION)
    {
        os << "  - Field Extraction" << std::endl;
    }
    if(plugin->caps() & CAP_PARSING)
    {
        os << "  - Event Parsing" << std::endl;
    }
    if(plugin->caps() & CAP_ASYNC)
    {
        os << "  - Async Events" << std::endl;
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
{
    //
    // Add the directories configured in the SYSDIG_PLUGIN_DIR environment variable
    //
    char *s_user_cdirs = getenv("SYSDIG_PLUGIN_DIR");

    if (s_user_cdirs != nullptr)
    {
        std::vector<std::string> user_cdirs = sinsp_split(s_user_cdirs, ';');

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
    return !m_input_plugin_name.empty();
}

const std::string& plugin_utils::input_plugin_name() const
{
    return m_input_plugin_name;
}

const std::string& plugin_utils::input_plugin_params() const
{
    return m_input_plugin_params;
}

void plugin_utils::add_directory(const std::string& plugins_dir)
{
    add_dir(plugins_dir, false);
}

void plugin_utils::load_plugin(sinsp *inspector, const std::string& name)
{
    // avoid duplicate loads
    for (auto &p : m_plugins)
    {
        if (p.names.find(name) != p.names.end())
        {
            p.used = true;
            return;
        }
    }

    // If it is a path, register it
	if (name.find('/') != std::string::npos)
	{
        plugin_entry p;
        p.used = true;
        p.inited = false;
        p.libpath = name;
        p.names.insert(name);
        p.names.insert(p.get_plugin(inspector)->name());
        m_plugins.push_back(p);
		return;
	}

	// Otherwise, try to find it from system folders

	// In case users passed "dummy" in place of "libdummy.so"
    std::string soname = name;
    if (!sinsp_utils::endswith(soname, SHAREDOBJ_EXT))
    {
        soname = SHAREDOBJ_PREFIX + name + SHAREDOBJ_EXT;
    }
    auto& plugins = m_plugins;
    bool found = iterate_plugins_dirs(m_dirs, [&inspector, &name, &soname, &plugins] (const tinydir_file file) -> bool {
        if (file.name == name || file.name == soname)
        {
            plugin_entry p;
            p.used = true;
            p.inited = false;
            p.libpath = file.path;
            p.names.insert(soname);
            p.names.insert(file.path);
            p.names.insert(file.name);
            p.names.insert(p.get_plugin(inspector)->name());
            plugins.push_back(p);
            return true; // break-out
        }
        return false;
    });
    if (!found)
    {
        throw sinsp_exception(err_plugin_not_found + name);
    }
}

void plugin_utils::read_plugins_from_dirs(sinsp *inspector)
{
    auto& plugins = m_plugins;
    auto tmpinsp = std::unique_ptr<sinsp>(new sinsp());
    iterate_plugins_dirs(m_dirs, [&inspector, &plugins, &tmpinsp] (const tinydir_file file) -> bool {
        // we temporarily load the plugin just to read its info,
        // but we don't actually load it in our inspector
        auto plugin = tmpinsp->register_plugin(file.path);

        plugin_entry p;
        p.used = false;
        p.inited = false;
        p.libpath = file.path;
        p.names.insert(file.path);
        p.names.insert(file.name);
        p.names.insert(plugin->name());
        plugins.push_back(p);
        return false;
	});
}

plugin_utils::plugin_entry& plugin_utils::find_plugin(const std::string name)
{
    for (auto &p : m_plugins)
    {
        if (p.names.find(name) != p.names.end() && p.used)
        {
            return p;
        }
    }
    throw sinsp_exception(err_plugin_not_found + name);
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
    throw sinsp_exception(err_plugin_not_found + name);
}

void plugin_utils::config_plugin(sinsp *inspector, const std::string& name, const std::string& conf)
{
    auto& p = find_plugin(name);
    p.init_config = conf;
}

void plugin_utils::select_input_plugin(sinsp *inspector, filter_check_list* flist, const std::string& name, const std::string& params)
{
    load_plugin(inspector, name);
    auto& p = find_plugin(name);
    auto plugin = p.get_plugin(inspector);
    if (plugin->caps() & CAP_SOURCING)
    {
        // we need to add the generic evt.* filtercheck class only once
        if (has_input_plugin())
        {
            throw sinsp_exception("using more than one plugin as input is not supported");
        }
        flist->add_filter_check(inspector->new_generic_filtercheck());
        m_input_plugin_name = plugin->name();
        m_input_plugin_params = params;
        return;
    }
    throw sinsp_exception(err_plugin_no_source_cap + name);
}

void plugin_utils::clear_input_plugin()
{
    m_input_plugin_name.clear();
    m_input_plugin_params.clear();
}

void plugin_utils::print_plugin_info_list(sinsp* inspector)
{
	std::ostringstream os, os_dirs, os_info;

	for(const auto& path : m_dirs)
	{
		os_dirs << path << " ";
	}

	for (auto &pl : m_plugins)
	{
        pl.print_info(inspector, os_info);
        os_info << std::endl;
	}

	os << "Plugin search paths are: " << os_dirs.str() << std::endl;
	os << m_plugins.size() << " Plugins Loaded:" << std::endl << std::endl << os_info.str() << std::endl;
    printf("%s", os.str().c_str());
}

void plugin_utils::print_plugin_info(sinsp* inspector, filter_check_list* flist, const std::string& name)
{
    std::ostringstream os;

    // try loading the plugin (if already loaded, this has no effect)
    load_plugin(inspector, name);
    auto& p = find_plugin(name);
    auto plugin = p.get_plugin(inspector);
    
    // print plugin static info
    p.print_info(inspector, os);
    os << std::endl;
    printf("%s", os.str().c_str());

    // print plugin init schema
    os.str("");
    os.clear();
    ss_plugin_schema_type type;
    auto schema = plugin->get_init_schema(type);
    os << "Init config schema type: ";
    switch (type)
    {
        case SS_PLUGIN_SCHEMA_JSON:
            os << "JSON" << std::endl;
            break;
        case SS_PLUGIN_SCHEMA_NONE:
        default:
            os << "Not available, plugin does not implement the init config schema functionality" << std::endl;
            break;
    }
    os << schema << std::endl;
    os << std::endl;
    printf("%s", os.str().c_str());

    // init the plugin with empty config (ignored if already inited)
    if (!p.inited)
    {
        p.init(inspector, flist);
    }

    // print plugin suggested open parameters
    if (plugin->caps() & CAP_SOURCING)
    {
        os.str("");
        os.clear();
        auto params = plugin->list_open_params();
        if (params.empty())
        {
            os << "No suggested open params available: ";
            os << "plugin has not been configured, or it does not implement the open params suggestion functionality" << std::endl;
        }
        else
        {
            os << "Suggested open params:" << std::endl;
            for(auto &oparam : plugin->list_open_params())
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
        os << std::endl;
        printf("%s", os.str().c_str());
    }
}

void plugin_utils::load_plugins_from_conf_file(sinsp *inspector, filter_check_list* flist, const std::string& config_filename, bool set_input)
{
    YAML::Node config;
    std::string config_explanation = ". See https://falco.org/docs/plugins/#loading-plugins-in-falco for additional information.";
    try {
        config = YAML::LoadFile(config_filename);
    } catch (std::exception &e)
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
            config_plugin(inspector, library_path, init_config);
            auto& p = find_plugin(library_path);
            if (set_input && p.get_plugin(inspector)->caps() & CAP_SOURCING)
            {
                select_input_plugin(inspector, flist, name, open_params);
            }
        }
    }
}

void plugin_utils::print_field_extraction_support(sinsp* inspector, const std::string& field)
{
    std::string field_name = field;
    size_t field_arg_pos = field.find_first_of('[');
    if (field_arg_pos != std::string::npos)
    {
        field_name = field.substr(0, field_arg_pos);
    }
    auto err = "filter contains an unknown field '" + field_name + "'";
    std::unordered_set<std::string> compatible_plugins;
    for (auto &p : m_plugins)
    {
        auto plugin = p.get_plugin(inspector);
        if (plugin->caps() & CAP_EXTRACTION)
        {
            const auto &fields = plugin->fields();
            for (const auto& f : fields)
            {
                std::string fname = f.m_name;
                if (fname == field_name)
                {
                    compatible_plugins.insert(plugin->name());
                }
            }
        }
    }
    if (!compatible_plugins.empty())
    {
        std::string fmt;
        for (const auto& pname : compatible_plugins)
        {
            fmt += fmt.empty() ? "" : ", ";
            fmt += pname;
        }
        throw sinsp_exception(err + ", but it can be supported by loading one of these plugins: " + fmt);
    }
    throw sinsp_exception(err + ", and none of the loaded plugins is capable of extracting it");
}

std::vector<std::string> plugin_utils::get_event_sources(sinsp *inspector)
{
    for (auto &pl : m_plugins)
    {
        // note: this triggers the inspector to register
        // the plugin, in case it was not registered already
        pl.get_plugin(inspector);
    }
    return inspector->event_sources();
}

std::vector<std::unique_ptr<sinsp_filter_check>> plugin_utils::get_filterchecks(sinsp *inspector, const std::string& source)
{
    std::vector<std::unique_ptr<sinsp_filter_check>> list;
    list.push_back(std::unique_ptr<sinsp_filter_check>(inspector->new_generic_filtercheck()));

    for (auto &pl : m_plugins)
    {
        auto plugin = pl.get_plugin(inspector);
        if (plugin->caps() & CAP_EXTRACTION
            && sinsp_plugin::is_source_compatible(plugin->extract_event_sources(), source))
        {
            list.push_back(std::unique_ptr<sinsp_filter_check>(sinsp_plugin::new_filtercheck(plugin)));
        }
    }
    return list;
}
