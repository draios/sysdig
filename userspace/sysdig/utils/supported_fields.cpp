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
    std::vector<std::string> sources = plugins.get_event_sources(inspector);
    sources.push_back(s_syscall_source);

	// Do a first pass to group together classes that are
	// applicable to multiple event sources.
	for(const auto &src : sources)
	{
		if(source != "" && source != src)
		{
			continue;
		}

        std::vector<const filter_check_info*> filterchecks;
        if (src == s_syscall_source)
        {
            sinsp::get_filtercheck_fields_info(filterchecks);
        }
        else
        {
            auto filterchecks_list = plugins.get_filterchecks(inspector, src);
            filterchecks_list.get_all_fields(filterchecks);
        }
        const auto classes = sinsp_filter_factory::check_infos_to_fieldclass_infos(filterchecks);
        
		for(const auto &fld_class : classes)
		{
            bool found = false;
            for (auto &info : field_infos)
            {
                if (info.class_info.name == fld_class.name
                        && info.class_info.desc == fld_class.desc)
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

	// In the second pass, actually print info, skipping duplicate
	// field classes and also printing info on supported sources.
	for(const auto &src : sources)
	{
		if(source != "" && source != src)
		{
			continue;
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
}
