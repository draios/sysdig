/*
Copyright (C) 2013-2022 Sysdig Inc.

This file is part of sysdig.

Licensed under the Apache License,
Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include "sinsp_opener.h"

#include <sinsp_exception.h>
#ifdef HAS_CAPTURE
#ifndef WIN32
#include "driver_config.h"
#endif // WIN32
#endif // HAS_CAPTURE

void sinsp_opener::open(sinsp* inspector) const
{
    if(options.print_progress && !(plugin.enabled || savefile.enabled))
    {
        throw sinsp_exception("the -P flag cannot be used with live captures.");
    }

    if(savefile.enabled)
    {
        inspector->open_savefile(savefile.path);
        return;
    }

    if (plugin.enabled)
    {
        inspector->open_plugin(plugin.name, plugin.params, sinsp_plugin_platform::SINSP_PLATFORM_HOSTINFO);
        return;
    }

#if defined(HAS_CAPTURE)
    /* Populate syscalls of interest */
    auto sc_of_interest = libsinsp::events::all_sc_set();

    if(!options.page_faults)
    {
        sc_of_interest.remove(ppm_sc_code::PPM_SC_PAGE_FAULT_USER);
        sc_of_interest.remove(ppm_sc_code::PPM_SC_PAGE_FAULT_KERNEL);
    }

    if(gvisor.enabled)
    {
        inspector->open_gvisor(gvisor.config, gvisor.root);
        return;
    }

    if(bpf.enabled)
    {
#ifdef HAS_MODERN_BPF
		if(bpf.modern)
		{
			inspector->open_modern_bpf(DEFAULT_DRIVER_BUFFER_BYTES_DIM, bpf.cpus_for_each_syscall_buffer, true, sc_of_interest);
			inspector->set_get_procs_cpu_from_driver(true);
			return;
		}
#endif

        auto probe = bpf.probe;
        if (probe.empty())
        {
            const char *home = std::getenv("HOME");
            if(!home)
            {
                throw sinsp_exception("Cannot get the env variable 'HOME'");
            }
            probe = std::string(home) + "/" + SYSDIG_PROBE_BPF_FILEPATH;
        }

        try
        {
            inspector->open_bpf(probe, DEFAULT_DRIVER_BUFFER_BYTES_DIM, sc_of_interest);
        }
        catch(const sinsp_exception& e)
        {
            if(system("scap-driver-loader bpf"))
            {
                fprintf(stderr, "Unable to load the BPF probe\n");
            }
            inspector->open_bpf(probe, DEFAULT_DRIVER_BUFFER_BYTES_DIM, sc_of_interest);
        }

        // Enable gathering the CPU from the kernel module
        inspector->set_get_procs_cpu_from_driver(true);
        return;
    }
    
    // default to kernel module if no other option is specified
    try
    {
        inspector->open_kmod(DEFAULT_DRIVER_BUFFER_BYTES_DIM, sc_of_interest);
    }
    catch(const sinsp_exception& e)
    {
        // if we are opening the syscall source, we retry later
        // by loading the driver with modprobe
        if(system("modprobe " DRIVER_NAME " > /dev/null 2> /dev/null"))
        {
            fprintf(stderr, "Unable to load the driver\n");
        }
        inspector->open_kmod(DEFAULT_DRIVER_BUFFER_BYTES_DIM, sc_of_interest);
    }

    // Enable gathering the CPU from the kernel module
    inspector->set_get_procs_cpu_from_driver(true);
#else // HAS_CAPTURE
    throw sinsp_exception("can't open inspector");
#endif // HAS_CAPTURE
}
