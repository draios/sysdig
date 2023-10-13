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
#include "supported_fields.h"
#include <filterchecks.h>

#include <map>
#include <set>
#include <unordered_set>

struct fields_info
{
    std::set<std::string> compatible_sources;
    gen_event_filter_factory::filter_fieldclass_info class_info;
};

void print_supported_fields(sinsp* inspector, plugin_utils& plugins, const std::string &source, bool verbose, bool markdown)
{
    std::vector<fields_info> field_infos;
    std::vector<std::unique_ptr<const sinsp_filter_check>> filtecheck_lists; // only used to retain memory until we finish
    std::vector<std::string> sources = plugins.get_event_sources(inspector);

    // add event sources defined by the loaded plugins
    if (!source.empty())
    {
        bool found = false;
        for (const auto& s : sources)
        {
            if (s == source)
            {
                found = true;
            }
        }
        if (!found)
        {
            throw sinsp_exception("value for --list must be a valid source type");
        }
    }

    // Do a first pass to group together classes that are
    // applicable to multiple event sources.
    for(const auto &src : sources)
    {
        if(source != "" && source != src)
        {
            continue;
        }

        sinsp_filter_check_list sinsp_filterchecks;
        std::vector<const filter_check_info*> filterchecks;
        if (src == s_syscall_source)
        {
            std::vector<const filter_check_info*> all_checks;
            sinsp_filterchecks.get_all_fields(all_checks);
            for (const auto& check : all_checks)
            {   
                // todo: we need to polish this logic in libsinsp, it's not ok to
                // leak this implementation detail
                if (check->m_name.find(" (plugin)") == std::string::npos)
                {
                    filterchecks.push_back(check);
                }
            }
        }

        for (auto& check: plugins.get_filterchecks(inspector, src))
        {
            filterchecks.push_back(check->get_fields());
            filtecheck_lists.push_back(std::move(check));
        }
        
        const auto classes = sinsp_filter_factory::check_infos_to_fieldclass_infos(filterchecks);
        for(const auto &fld_class : classes)
        {
            bool found = false;
            for (auto &info : field_infos)
            {
                if (info.class_info.name == fld_class.name)
                {
                    found = true;
                    info.compatible_sources.insert(src);
                }
            }
            if (!found)
            {
                field_infos.emplace_back();
                field_infos[field_infos.size() - 1].class_info = fld_class;
                field_infos[field_infos.size() - 1].compatible_sources.insert(src);
            }
        }
    }

    for(auto &info : field_infos)
    {
        if (markdown)
        {
            printf("%s\n", info.class_info.as_markdown(info.compatible_sources).c_str());
        }
        else
        {
            printf("%s\n", info.class_info.as_string(verbose, info.compatible_sources).c_str());
        }
    }
}
