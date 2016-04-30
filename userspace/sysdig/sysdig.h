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

#pragma once

#include <config_sysdig.h>
#ifdef HAS_CAPTURE
#include "../../driver/driver_config.h"
#endif // HAS_CAPTURE

//
// ASSERT implementation
//
#ifdef _DEBUG
#define ASSERT(X) assert(X)
#else // _DEBUG
#define ASSERT(X)
#endif // _DEBUG

//
// Capture results
//
class sysdig_init_res
{
public:
	sysdig_init_res()
	{
		m_res = EXIT_SUCCESS;
	}

	sysdig_init_res(int res)
	{
		m_res = res;
	}

	int m_res;
	vector<string> m_next_run_args;
};

//
// Capture results
//
class captureinfo
{
public:
	captureinfo()
	{
		m_nevts = 0;
		m_time = 0;
	}

	uint64_t m_nevts;
	uint64_t m_time;
};

//
// Summary table entry
//
class summary_table_entry
{
public:
	summary_table_entry(uint16_t id, bool is_unsupported_syscall)
	{
		m_id = id;
		m_ncalls = 0;
		m_is_unsupported_syscall = is_unsupported_syscall;
	}

	uint16_t m_id;
	uint64_t m_ncalls;
	bool m_is_unsupported_syscall;
};

struct summary_table_entry_rsort_comparer
{
    bool operator() (const summary_table_entry& first, const summary_table_entry& second) const 
	{
		return first.m_ncalls > second.m_ncalls;
	}
};

//
// Printer functions
//
void list_fields(bool verbose, bool markdown);
const char* param_type_to_string(ppm_param_type pt);
void list_events(sinsp* inspector);

#ifdef HAS_CHISELS
void print_chisel_info(chisel_desc* cd);
void list_chisels(vector<chisel_desc>* chlist, bool verbose);
#endif



