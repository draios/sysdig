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

#include <stdio.h>
#include <sys/stat.h>

#include <sinsp.h>
#include "sysdig.h"
#include "plugin.h"

#include <third-party/tinydir.h>

//
// Plugin Directory info
//
typedef struct plugin_dir_info
{
    std::string m_dir;
} plugin_dir_info;

void add_plugin_dir(string dirname, bool front_add);
void add_plugin_dirs(string sysdig_installation_dir);
void register_plugins(sinsp *inspector);