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
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>

#include "../common/sysdig_types.h"
#define DRAGENT_WIN_HAL_C_ONLY
#include "windows/dragent_win_hal_public.h"
#include "scap.h"
#include "scap-int.h"
#include "windows_hal.h"

typedef char* (*fwh_getlasterror)(wh_t* handle);
typedef wh_t* (*fwh_open)(char* error);
typedef void (*fwh_close)(wh_t* handle);
typedef wh_proclist (*fwh_wmi_get_procs)(wh_t* handle);
typedef int (*fwh_is_docker_present)(wh_t* handle);
typedef int (*fwh_docker_refresh)(wh_t* handle);
typedef int (*fwh_wmi_update_procs_perf)(wh_t* handle);
typedef wh_proc_perf_info (*fwh_wmi_get_proc_perf_info)(wh_t* handle, uint64_t pid);
typedef bool (*fwh_create_fd_list)(wh_t* handle);
typedef void (*fwh_free_fd_list)(wh_t* handle);
typedef wh_fdlist (*fwh_get_pid_fds)(wh_t* handle, uint32_t pid);
typedef bool (*fwh_create_tid_list)(wh_t* handle);
typedef void (*fwh_free_tid_list)(wh_t* handle);
typedef wh_tidlist (*fwh_get_pid_tids)(wh_t* handle, uint32_t pid);

fwh_getlasterror p_wh_getlasterror;
fwh_open p_wh_open;
fwh_close p_wh_close;
fwh_wmi_get_procs p_wh_wmi_get_procs;
fwh_is_docker_present p_wh_is_docker_present;
fwh_docker_refresh p_wh_docker_refresh;
fwh_wmi_update_procs_perf p_wh_wmi_update_procs_perf;
fwh_wmi_get_proc_perf_info p_wh_wmi_get_proc_perf_info;
fwh_create_fd_list p_wh_create_fd_list;
fwh_free_fd_list p_wh_free_fd_list;
fwh_get_pid_fds p_wh_get_pid_fds;
fwh_create_tid_list p_wh_create_tid_list;
fwh_free_tid_list p_wh_free_tid_list;
fwh_get_pid_tids p_wh_get_pid_tids;

int32_t scap_windows_hal_import(char* error)
{
	HINSTANCE pdll = LoadLibrary("dragent_win_hal.dll");
	if(pdll == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "dragent_win_hal.dll not found. Make sure the the windows HAL is installed.");
		return SCAP_FAILURE;
	}

	p_wh_getlasterror = (fwh_getlasterror)GetProcAddress(pdll, "wh_getlasterror");
	if(p_wh_getlasterror == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "win hal symbol wh_getlasterror not found");
		return SCAP_FAILURE;
	}

	p_wh_open = (fwh_open)GetProcAddress(pdll, "wh_open");
	if(p_wh_open == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "win hal symbol wh_open not found");
		return SCAP_FAILURE;
	}

	p_wh_close = (fwh_close)GetProcAddress(pdll, "wh_close");
	if(p_wh_close == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "win hal symbol wh_close not found");
		return SCAP_FAILURE;
	}

	p_wh_wmi_get_procs = (fwh_wmi_get_procs)GetProcAddress(pdll, "wh_wmi_get_procs");
	if(p_wh_wmi_get_procs == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "win hal symbol wh_wmi_get_procs not found");
		return SCAP_FAILURE;
	}

	p_wh_is_docker_present = (fwh_is_docker_present)GetProcAddress(pdll, "wh_is_docker_present");
	if(p_wh_is_docker_present == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "win hal symbol wh_is_docker_present not found");
		return SCAP_FAILURE;
	}

	p_wh_docker_refresh = (fwh_docker_refresh)GetProcAddress(pdll, "wh_docker_refresh");
	if(p_wh_docker_refresh == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "win hal symbol wh_docker_refresh not found");
		return SCAP_FAILURE;
	}

	p_wh_wmi_update_procs_perf = (fwh_wmi_update_procs_perf)GetProcAddress(pdll, "wh_wmi_update_procs_perf");
	if(p_wh_wmi_update_procs_perf == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "win hal symbol wh_wmi_update_procs_perf not found");
		return SCAP_FAILURE;
	}

	p_wh_wmi_get_proc_perf_info = (fwh_wmi_get_proc_perf_info)GetProcAddress(pdll, "wh_wmi_get_proc_perf_info");
	if(p_wh_wmi_get_proc_perf_info == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "win hal symbol wh_wmi_get_proc_perf_info not found");
		return SCAP_FAILURE;
	}

	p_wh_create_fd_list = (fwh_create_fd_list)GetProcAddress(pdll, "wh_create_fd_list");
	if(p_wh_create_fd_list == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "win hal symbol wh_create_fd_list not found");
		return SCAP_FAILURE;
	}

	p_wh_free_fd_list = (fwh_free_fd_list)GetProcAddress(pdll, "wh_free_fd_list");
	if(p_wh_free_fd_list == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "win hal symbol wh_free_fd_list not found");
		return SCAP_FAILURE;
	}

	p_wh_get_pid_fds = (fwh_get_pid_fds)GetProcAddress(pdll, "wh_get_pid_fds");
	if(p_wh_get_pid_fds == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "win hal symbol wh_get_pid_fds not found");
		return SCAP_FAILURE;
	}

	p_wh_create_tid_list = (fwh_create_tid_list)GetProcAddress(pdll, "wh_create_tid_list");
	if(p_wh_create_tid_list == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "win hal symbol wh_create_tid_list not found");
		return SCAP_FAILURE;
	}

	p_wh_free_tid_list = (fwh_free_tid_list)GetProcAddress(pdll, "wh_free_tid_list");
	if(p_wh_free_tid_list == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "win hal symbol wh_free_tid_list not found");
		return SCAP_FAILURE;
	}

	p_wh_get_pid_tids = (fwh_get_pid_tids)GetProcAddress(pdll, "wh_get_pid_tids");
	if(p_wh_get_pid_tids == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "win hal symbol wh_get_pid_tids not found");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

wh_t* scap_windows_hal_open(char* error)
{
	if(p_wh_getlasterror == NULL)
	{
		if(scap_windows_hal_import(error) != SCAP_SUCCESS)
		{
			return NULL;
		}
	}

	return p_wh_open(error);
}

void scap_windows_hal_close(wh_t* handle)
{
	p_wh_close(handle);
}

void scap_get_machine_info_windows(OUT uint32_t* num_cpus, OUT uint64_t* memory_size_bytes)
{
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	*num_cpus = si.dwNumberOfProcessors;

	ULONGLONG mem_kb;
	GetPhysicallyInstalledSystemMemory(&mem_kb);
	*memory_size_bytes = mem_kb * 1024;
}

static int32_t addprocess_windows(wh_procinfo* wpi, scap_t* handle, char* error)
{
	struct scap_threadinfo* tinfo;

	if(handle->m_proc_callback == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "process table construction in scap not supported on windows");
		return SCAP_FAILURE;
	}

	//
	//  Allocate the procinfo object.
	//
	if((tinfo = scap_proc_alloc(handle)) == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "addprocess_windows memory allocation error");
		return SCAP_FAILURE;
	}

	//
	// Fill the procinfo object
	//
	memset(tinfo, 0, sizeof(struct scap_threadinfo));

	tinfo->pid = wpi->pid;
	tinfo->ptid = wpi->ptid;
	snprintf(tinfo->comm, SCAP_MAX_PATH_SIZE, "%s", wpi->comm);
	snprintf(tinfo->exe, SCAP_MAX_PATH_SIZE, "%s", wpi->exe);
	snprintf(tinfo->exepath, SCAP_MAX_PATH_SIZE, "%s", wpi->exepath);
	snprintf(tinfo->args, SCAP_MAX_PATH_SIZE, "%s", wpi->args);
	tinfo->args_len = wpi->args_len;
	tinfo->vmsize_kb = wpi->vmsize_kb;
	tinfo->pfmajor = wpi->pfmajor;
	tinfo->pfminor = wpi->pfminor;
	tinfo->clone_ts = wpi->clone_ts;
	tinfo->tty = wpi->tty;
	tinfo->flags = 0;

	wh_proc_perf_info pinfo = p_wh_wmi_get_proc_perf_info(handle->m_whh, tinfo->pid);
	if(pinfo.m_result != 0)
	{
		tinfo->vmrss_kb = (uint32_t)(pinfo.m_memory_bytes / 1024);
		tinfo->vmswap_kb = (uint32_t)(pinfo.m_swap_bytes / 1024);
	}
	else
	{
		tinfo->vmrss_kb = 0;
		tinfo->vmswap_kb = 0;
	}

	wh_tidlist ptl = p_wh_get_pid_tids(handle->m_whh, (uint32_t)tinfo->pid);
	if(ptl.m_result != 0)
	{
		if(ptl.m_count > 1)
		{
			for(uint32_t j = 1; j < ptl.m_count; j++)
			{
				tinfo->tid = ptl.m_tids[j];
				handle->m_proc_callback(handle->m_proc_callback_context, handle, tinfo->tid, tinfo, NULL);
			}
		}

		tinfo->tid = ptl.m_tids[0];
	}
	else
	{
		tinfo->tid = tinfo->ptid;
	}

	wh_fdlist pfl = p_wh_get_pid_fds(handle->m_whh, (uint32_t)tinfo->pid);
	if(pfl.m_result != 0)
	{
		for(uint32_t j = 0; j < pfl.m_count; j++)
		{
			wh_fdinfo* wfd = &pfl.m_fds[j];

			int32_t res = SCAP_SUCCESS;
			scap_fdinfo *fdi = NULL;
			
			res = scap_fd_allocate_fdinfo(handle, &fdi, wfd->fd, wfd->type);
			if(res == SCAP_FAILURE)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "can't allocate scap fd handle for file fd %" PRIu64, wfd->fd);
				break;
			}

			switch(wfd->type)
			{
			case WH_FD_FILE:
				strncpy(fdi->info.fname, 
					wfd->info.fname + 4, // the +4 removes the "\\?\" from the beginning of the string
					SCAP_MAX_PATH_SIZE - 1);
				fdi->info.fname[SCAP_MAX_PATH_SIZE - 1] = 0;
				break;
			case WH_FD_IPV4_SOCK:
				fdi->info.ipv4info.sip = wfd->info.ipv4info.sip;
				fdi->info.ipv4info.dip = wfd->info.ipv4info.dip;
				fdi->info.ipv4info.sport = wfd->info.ipv4info.sport;
				fdi->info.ipv4info.dport = wfd->info.ipv4info.dport;
				fdi->info.ipv4info.l4proto = wfd->info.ipv4info.l4proto;
				break;
			default:
				ASSERT(false);
				continue;
			}

			int32_t ares = scap_add_fd_to_proc_table(handle, tinfo, fdi, error);
			if(ares != SCAP_SUCCESS)
			{
				return ares;
			}

			if(handle->m_proc_callback != NULL)
			{
				if(fdi)
				{
					scap_fd_free_fdinfo(&fdi);
				}
			}
		}
	}

	tinfo->flags |= PPM_CL_IS_MAIN_THREAD;
	handle->m_proc_callback(handle->m_proc_callback_context, handle, tinfo->tid, tinfo, NULL);

	free(tinfo);

	return SCAP_SUCCESS;
}

typedef int (CALLBACK* LPFNDLLFUNC1)();

int32_t scap_get_procs_windows(scap_t* handle, char* error)
{
	wh_proclist wgpres;

	//
	// Get the system processes through WMI
	//
	wgpres = p_wh_wmi_get_procs(handle->m_whh);
	if(wgpres.m_result == 0)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "%s", p_wh_getlasterror(handle->m_whh));
		return SCAP_FAILURE;
	}

	//
	// While we're here, refresh the docker state and the process performance table
	//
	if(p_wh_is_docker_present(handle->m_whh))
	{
		if (p_wh_docker_refresh(handle->m_whh) == 0)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "%s", p_wh_getlasterror(handle->m_whh));
			return SCAP_FAILURE;
		}
	}

	if(p_wh_wmi_update_procs_perf(handle->m_whh) == 0)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "%s", p_wh_getlasterror(handle->m_whh));
		return SCAP_FAILURE;
	}

	//
	// Scan the system handles and construct the FD list
	//
	bool cfdres = p_wh_create_fd_list(handle->m_whh);
	if(cfdres != WH_SUCCESS)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "%s", p_wh_getlasterror(handle->m_whh));
		return SCAP_FAILURE;
	}

	//
	// Scan the system threads and construct the tid list
	//
	if(p_wh_create_tid_list(handle->m_whh) == false)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "%s", p_wh_getlasterror(handle->m_whh));
		return SCAP_FAILURE;
	}

	//
	// Add the received processes to the scap list 
	//
	for(uint32_t j = 0; j < wgpres.m_count; j++)
	{
		wh_procinfo* wpi = &(wgpres.m_procs[j]);
		if(addprocess_windows(wpi, handle, error) != SCAP_SUCCESS)
		{
			p_wh_free_fd_list(handle->m_whh);
			p_wh_free_tid_list(handle->m_whh);
			return SCAP_FAILURE;
		}
	}

	//
	// Done with the file descriptors and tids, release the lists to save memory
	//
	p_wh_free_fd_list(handle->m_whh);
	p_wh_free_tid_list(handle->m_whh);

	return SCAP_SUCCESS;
}
