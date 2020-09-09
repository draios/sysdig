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
#include "addrinfo.h"

#include <ares.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>

void ares_cb(void *arg, int status, int timeouts, struct hostent *host)
{
    if (status == ARES_SUCCESS)
    {
        struct in_addr addr;
        char *p;
        p = host->h_addr_list[0];
        memcpy(&addr, p, sizeof(struct in_addr));
        ares_cb_result *res = reinterpret_cast<ares_cb_result *>(arg);
        auto addr_str = std::string(inet_ntoa(addr));
        res->address = addr_str;
        res->addr = addr;
        res->done = true;
    }
}
