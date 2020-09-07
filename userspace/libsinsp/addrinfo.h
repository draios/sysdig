
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
