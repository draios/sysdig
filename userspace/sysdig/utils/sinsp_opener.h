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
#pragma once

#include <sinsp.h>

#include <string>

struct sinsp_opener
{
    sinsp_opener() = default;
    virtual ~sinsp_opener() = default;
    sinsp_opener(sinsp_opener&&) = default;
    sinsp_opener& operator = (sinsp_opener&&) = default;
    sinsp_opener(const sinsp_opener&) = default;
    sinsp_opener& operator = (const sinsp_opener&) = default;
    
    void open(sinsp* inspector) const;

    struct 
    {
        bool print_progress = false;
        bool page_faults = false;
    } options;

    struct
    {
        bool enabled = false;
    } udig;

    struct
    {
        bool enabled = false;
#ifdef HAS_MODERN_BPF
        bool modern  = false;
		uint16_t cpus_for_each_syscall_buffer = 2;
#endif
        std::string probe;
    } bpf;

    struct
    {
        bool enabled = false;
        std::string config;
        std::string root;
    } gvisor;

    struct
    {
        bool enabled = false;
        std::string name;
        std::string params;
    } plugin;

    struct
    {
        bool enabled = false;
        std::string path;
    } savefile;    
};
