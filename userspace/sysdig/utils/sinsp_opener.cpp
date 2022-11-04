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
    if(enable_print_progress && !(mode_plugin || mode_savefile))
    {
        throw sinsp_exception("the -P flag cannot be used with live captures.");
    }

    if(mode_savefile)
    {
        inspector->open_savefile(savefile_path);
        return;
    }

    if (mode_plugin)
    {
        inspector->open_plugin(plugin_name, plugin_params);
        return;
    }

#if defined(HAS_CAPTURE)
    /* Populate syscalls of interest */
    std::unordered_set<uint32_t> sc_of_interest = inspector->get_all_ppm_sc();

    /* Populate tracepoints of interest */
    std::unordered_set<uint32_t> tp_of_interest = inspector->get_all_tp();
    if(!enable_page_faults)
    {
        tp_of_interest.erase(PAGE_FAULT_USER);
        tp_of_interest.erase(PAGE_FAULT_KERN);
    }

    if(mode_udig)
    {
        inspector->open_udig();
        return;
    }

    if(mode_gvisor)
    {
        inspector->open_gvisor(gvisor_config, gvisor_root);
        return;
    }

#ifndef _WIN32
    if(mode_bpf)
    {
        auto probe = bpf_probe;
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
            inspector->open_bpf(probe, DEFAULT_DRIVER_BUFFER_BYTES_DIM, sc_of_interest, tp_of_interest);
        }
        catch(const sinsp_exception& e)
        {
            if(system("scap-driver-loader bpf"))
            {
                fprintf(stderr, "Unable to load the BPF probe\n");
            }
            inspector->open_bpf(probe, DEFAULT_DRIVER_BUFFER_BYTES_DIM, sc_of_interest, tp_of_interest);
        }

        // Enable gathering the CPU from the kernel module
        inspector->set_get_procs_cpu_from_driver(true);
        return;
    }
    
    try
    {
        inspector->open_kmod(DEFAULT_DRIVER_BUFFER_BYTES_DIM, sc_of_interest, tp_of_interest);
    }
    catch(const sinsp_exception& e)
    {
        // if we are opening the syscall source, we retry later
        // by loading the driver with modprobe
        if(system("modprobe " DRIVER_NAME " > /dev/null 2> /dev/null"))
        {
            fprintf(stderr, "Unable to load the driver\n");
        }
        inspector->open_kmod(DEFAULT_DRIVER_BUFFER_BYTES_DIM, sc_of_interest, tp_of_interest);
    }

    // Enable gathering the CPU from the kernel module
    inspector->set_get_procs_cpu_from_driver(true);
#elif // _WIN32
    throw sinsp_exception("can't open inspector");
#endif // _WIN32
#endif // HAS_CAPTURE
}
