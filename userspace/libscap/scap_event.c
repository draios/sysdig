/*
Copyright (C) 2013-2014 Draios inc.

This file is part of sysdig.

sysdig is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

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
extern bool validate_info_table_size();

//
// Get the event info table
//
const struct ppm_event_info* scap_get_event_info_table()
{
	ASSERT(validate_info_table_size());
	return g_event_info;
}

//
// Get the syscall info table
//
const struct ppm_syscall_desc* scap_get_syscall_info_table()
{
	return g_syscall_info_table;
}

uint32_t scap_event_getlen(scap_evt* e)
{
	return e->len;
}

uint64_t scap_event_get_num(scap_t* handle)
{
	return handle->m_evtcnt;
}

void scap_event_reset_count(scap_t* handle)
{
	handle->m_evtcnt = 0;
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
