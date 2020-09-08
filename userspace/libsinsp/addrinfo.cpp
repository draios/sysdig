#include "addrinfo.h"

#include <ares.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>

void ares_cb(void *arg, int status, int timeouts, struct hostent *host)
{
    if (status == ARES_EDESTRUCTION)
    {
        return;
    }

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

        // todo(leodido, fntlnz) > cleanup? ares_destroy?
    }
}
