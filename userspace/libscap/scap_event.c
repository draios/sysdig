/*
Copyright (C) 2013-2014 Draios inc.
 
This file is part of sysdig.

sysdig is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif // _WIN32

#include "scap.h"
#include "scap-int.h"

// This is defined in the driver
extern const struct ppm_event_info g_event_info[];
extern const struct ppm_syscall_desc g_syscall_info_table[];

//
// Get the event info table
//
const struct ppm_event_info* scap_get_event_info_table()
{
	return g_event_info;
}

//
// Get the syscall info table
//
const struct ppm_syscall_desc* scap_get_syscall_info_table()
{
	return g_syscall_info_table;
}

uint32_t scap_event_compute_len(scap_evt* e)
{
	uint32_t j;
	uint32_t res = 0;
	uint16_t* lens = (uint16_t*)((char*)e + sizeof(struct ppm_evt_hdr));

	ASSERT(e->type < PPM_EVENT_MAX);

	for(j = 0; j < g_event_info[e->type].nparams; j++)
	{
		res += lens[j];
	}

	res += g_event_info[e->type].nparams * sizeof(uint16_t) + sizeof(struct ppm_evt_hdr);

#ifdef PPM_ENABLE_SENTINEL
	res += sizeof(uint32_t);
#endif

	return res;
}

uint32_t scap_event_getlen(scap_evt* e)
{
	return e->len;
}

uint64_t scap_event_get_num(scap_t* handle)
{
	return handle->m_evtcnt;
}

uint64_t scap_event_get_ts(scap_evt* e)
{
	return e->ts;
}

#ifdef PPM_ENABLE_SENTINEL
uint32_t scap_event_get_sentinel_begin(scap_evt* e)
{
	return e->sentinel_begin;
}
#endif

const struct ppm_event_info* scap_event_getinfo(scap_evt* e)
{
	return &(g_event_info[e->type]);
}
