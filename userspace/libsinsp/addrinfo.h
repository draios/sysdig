/*
Copyright (C) 2020 Sysdig Inc.

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

#ifndef MINIMAL_BUILD
#pragma once

#include <netinet/in.h>
#include <string>

struct ares_cb_result
{
    std::string address;
    in_addr addr;
    bool done = false;
    bool call = false;
};

void ares_cb(void *arg, int status, int timeouts, struct hostent *host);

#endif // MINIMAL_BUILD
