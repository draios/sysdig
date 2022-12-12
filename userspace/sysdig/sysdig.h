/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

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

#ifdef _WIN32
#define NOCURSESUI
#endif

//
// Enables Lua chisel scripts support
//
#define HAS_CHISELS

//
// Relative path to chisels
//
#define CHISELS_INSTALLATION_DIR "/share/sysdig/chisels"

//
// Relative path to plugins
//
#define PLUGINS_INSTALLATION_DIR "/share/sysdig/plugins"

#include <config_sysdig.h>

//
// ASSERT implementation
//
#ifndef ASSERT
#ifdef _DEBUG
#define ASSERT(X) assert(X)
#else // _DEBUG
#define ASSERT(X)
#endif // _DEBUG
#endif // ASSERT
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
	std::vector<std::string> m_next_run_args;
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
	summary_table_entry(uint16_t id, bool is_unsupported_syscall) : m_ncalls(0), m_id(id), m_is_unsupported_syscall(is_unsupported_syscall)
	{
	}

	uint64_t m_ncalls;
	uint16_t m_id;
	bool m_is_unsupported_syscall;	
};

struct summary_table_entry_rsort_comparer
{
    bool operator() (const summary_table_entry& first, const summary_table_entry& second) const 
	{
		return first.m_ncalls > second.m_ncalls;
	}
};
