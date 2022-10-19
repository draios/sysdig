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
    struct ppm_event_info info;
};

static std::vector<event_entry> get_event_entries(sinsp* inspector, bool include_generics)
{
    event_entry entry;
    std::vector<event_entry> events;
    const struct ppm_event_info* etable = inspector->get_event_info_tables()->m_event_info;

    // skip generic events
    for(uint32_t evt = PPME_GENERIC_X + 1; evt < PPM_EVENT_MAX; evt++)
    {
        if (!sinsp::is_old_version_event(evt)
                && !sinsp::is_unused_event(evt)
                && !sinsp::is_unknown_event(evt))
        {
            entry.is_enter = PPME_IS_ENTER(evt);
            entry.name = etable[evt].name;
            entry.info = etable[evt];
            events.push_back(entry);
        }
    }

    if (include_generics)
    {
        // append generic events
        const auto generic_syscalls = inspector->get_events_names({PPME_GENERIC_E});
        for (const auto& name : generic_syscalls)
        {
            for(uint32_t evt = PPME_GENERIC_E; evt <= PPME_GENERIC_X; evt++)
            {
                entry.is_enter = PPME_IS_ENTER(evt);
                entry.name = name;
                entry.info = etable[evt];
                events.push_back(entry);
            }
        }
    }

    return events;
}

void print_supported_events(sinsp* inspector, bool markdown)
{
    const auto events = get_event_entries(inspector, true);

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

        for(uint32_t k = 0; k < e.info.nparams; k++)
        {
            if(k != 0)
            {
                printf(", ");
            }

            printf("%s %s", param_type_to_string(e.info.params[k].type),
                e.info.params[k].name);
        }
        printf(")\n");
    }
}
