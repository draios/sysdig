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

#include "supported_events.h"

#include <vector>
#include <string>
#include <memory>

struct event_entry
{
    bool is_enter;
    std::string name;
    const ppm_event_info* info;
};

static std::vector<event_entry> get_event_entries(bool include_generics)
{
    event_entry entry;
    std::vector<event_entry> events;

    // skip generic events
    for(const auto& evt : libsinsp::events::all_event_set())
    {
        if (!libsinsp::events::is_generic(evt)
            && !libsinsp::events::is_old_version_event(evt)
            && !libsinsp::events::is_unused_event(evt)
            && !libsinsp::events::is_unknown_event(evt))
        {
            entry.is_enter = PPME_IS_ENTER(evt);
            entry.info = libsinsp::events::info(evt);
			entry.name = entry.info->name;
            events.push_back(entry);
        }
    }

    if (include_generics)
    {
        // append generic events
		const auto names = libsinsp::events::event_set_to_names({ppm_event_code::PPME_GENERIC_E});
		for (const auto& name : names)
		{
			entry.is_enter = PPME_IS_ENTER(ppm_event_code::PPME_GENERIC_E);
			entry.info = libsinsp::events::info(ppm_event_code::PPME_GENERIC_E);
			entry.name = name;
			events.push_back(entry);

			entry.is_enter = PPME_IS_ENTER(ppm_event_code::PPME_GENERIC_X);
			entry.info = libsinsp::events::info(ppm_event_code::PPME_GENERIC_X);
			entry.name = name;
			events.push_back(entry);
		}
    }

    return events;
}

void print_supported_events(sinsp* inspector, bool markdown)
{
    const auto events = get_event_entries(true);

    if(markdown)
    {
        printf("Dir | Event\n");
        printf(":---|:-----\n");
    }

    for (const auto& e : events)
    {
        char dir = e.is_enter ? '>' : '<';
        if (markdown)
        {
            printf("%c | **%s**(", dir, e.name.c_str());
        }
        else
        {
            printf("%c %s(", dir, e.name.c_str());
        }

        for(uint32_t k = 0; k < e.info->nparams; k++)
        {
            if(k != 0)
            {
                printf(", ");
            }

            printf("%s %s", param_type_to_string(e.info->params[k].type),
                e.info->params[k].name);
        }
        printf(")\n");
    }
}
