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

////////////////////////////////////////////////////////////////////////////
// Public definitions for the scap library
////////////////////////////////////////////////////////////////////////////
#pragma once

#ifdef _WIN32
#include <Windows.h>
#else
#include <csignal>
#endif
#include <assert.h>

#include <string>
#include <memory>
#include <iostream>
#include <fstream>
#include <exception>
#include <sstream>
#include <deque>
#include <queue>
#include <list>
#include <vector>
#include <iostream>
#include <limits>

using namespace std;

#include "../libscap/scap.h"
#include "settings.h"
#include "utils.h"
#include "../libscap/scap.h"
#include "parsers.h"
#include "ifinfo.h"
#include "internal_metrics.h"

#ifndef MIN
#define MIN(X,Y) ((X) < (Y)? (X):(Y))
#define MAX(X,Y) ((X) > (Y)? (X):(Y))
#endif

//
// ASSERT implementation
//
#ifdef _DEBUG
#ifdef ASSERT_TO_LOG
#define ASSERT(X) \
	if(!(X)) \
	{ \
		g_logger.format(sinsp_logger::SEV_ERROR, "ASSERTION %s at %s:%d", #X , __FILE__, __LINE__); \
		assert(X); \
	} 
#else
#define ASSERT(X) assert(X)
#endif // ASSERT_TO_LOG
#else // _DEBUG
#define ASSERT(X)
#endif // _DEBUG

//
// Public export macro
//
#ifdef _WIN32
#define SINSP_PUBLIC __declspec(dllexport)
#define BRK(X) {if(evt != NULL && evt->get_num() == X)__debugbreak();}
#else
#define SINSP_PUBLIC
#define BRK(X)
#endif

//
// Path separator
//
#ifdef _WIN32
#define DIR_PATH_SEPARATOR '\\'
#else
#define DIR_PATH_SEPARATOR '/'
#endif

//
// The logger
//
extern sinsp_logger g_logger;
#define glogf g_logger.format

//
// Prototype of the callback invoked by the thread table when a thread is 
// created or destroyed
//
class sinsp_threadtable_listener
{
public:
	virtual ~sinsp_threadtable_listener()
	{
	}
	virtual void on_thread_created(sinsp_threadinfo* tinfo) = 0;
	virtual void on_thread_destroyed(sinsp_threadinfo* tinfo) = 0;
};

//
// Prototype of the callback invoked by the thread table when a thread is 
// created or destroyed
//
class sinsp_fd_listener
{
public:
	virtual ~sinsp_fd_listener()
	{
	}
	virtual void on_read(sinsp_evt* evt, int64_t tid, int64_t fd, sinsp_fdinfo_t* fdinfo, char *data, uint32_t original_len, uint32_t len) = 0;
	virtual void on_write(sinsp_evt* evt, int64_t tid, int64_t fd, sinsp_fdinfo_t* fdinfo, char *data, uint32_t original_len, uint32_t len) = 0;
	virtual void on_sendfile(sinsp_evt* evt, int64_t fdin, uint32_t len) = 0;
	virtual void on_connect(sinsp_evt* evt, uint8_t* packed_data) = 0;
	virtual void on_accept(sinsp_evt* evt, int64_t newfd, uint8_t* packed_data, sinsp_fdinfo_t* new_fdinfo) = 0;
	virtual void on_file_open(sinsp_evt* evt, const string& fullpath, uint32_t flags) = 0;
	virtual void on_error(sinsp_evt* evt) = 0;
	virtual void on_erase_fd(erase_fd_params* params) = 0;
	virtual void on_socket_shutdown(sinsp_evt *evt) = 0;
	virtual void on_execve(sinsp_evt* evt) = 0;
	virtual void on_clone(sinsp_evt* evt, sinsp_threadinfo* newtinfo) = 0;
	virtual void on_bind(sinsp_evt* evt) = 0;
	virtual bool on_resolve_container(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info, resolve_container_context ctx) = 0;
};
