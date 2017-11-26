#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#define DRAGENT_WIN_HAL_C_ONLY
#include <dragent_win_hal_public.h>

#include "scap.h"
#include "scap-int.h"
#include "windows_hal.h"

int32_t addprocess_windows(wh_procinfo* wpi, scap_t* handle, struct scap_threadinfo** procinfo, char *error)
{
	struct scap_threadinfo* tinfo;

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
	tinfo->tid = wpi->tid;
	tinfo->ptid = wpi->ptid;
	snprintf(tinfo->comm, SCAP_MAX_PATH_SIZE, "%s", wpi->comm);
	snprintf(tinfo->exe, SCAP_MAX_PATH_SIZE, "%s", wpi->exe);
	snprintf(tinfo->exepath, SCAP_MAX_PATH_SIZE, "%s", wpi->exepath);
	snprintf(tinfo->args, SCAP_MAX_PATH_SIZE, "%s", wpi->args);
	tinfo->args_len = wpi->args_len;
	tinfo->vmsize_kb = wpi->vmsize_kb;
	tinfo->vmrss_kb = wpi->vmrss_kb;
	tinfo->vmswap_kb = wpi->vmswap_kb;
	tinfo->pfmajor = wpi->pfmajor;
	tinfo->pfminor = wpi->pfminor;
	tinfo->clone_ts = wpi->clone_ts;
	tinfo->tty = wpi->tty;

	//
	// Done. Add the entry to the process table, or fire the notification callback
	//
	if(handle->m_proc_callback == NULL)
	{
		int32_t uth_status = SCAP_SUCCESS;

		HASH_ADD_INT64(handle->m_proclist, pid, tinfo);
		if(uth_status != SCAP_SUCCESS)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "process table allocation error (2)");
			return SCAP_FAILURE;
		}
	}
	else
	{
		handle->m_proc_callback(handle->m_proc_callback_context, tinfo->tid, tinfo, NULL, handle);
		free(tinfo);
	}

	return SCAP_SUCCESS;
}

typedef int (CALLBACK* LPFNDLLFUNC1)();

int32_t scap_proc_scan_proc_dir_windows(scap_t* handle, struct scap_threadinfo** procinfo, char *error)
{
	wh_proclist wgpres;

	wgpres = wh_wmi_get_procs(handle->m_whh);
	if(wgpres.m_result == 0)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "%s", wh_getlasterror(handle->m_whh));
		return SCAP_FAILURE;
	}

	for(uint32_t j = 0; j < wgpres.m_count; j++)
	{
		wh_procinfo* wpi = &(wgpres.m_procs[j]);

		if(addprocess_windows(wpi, handle, procinfo, error) != SCAP_SUCCESS)
		{
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
}
