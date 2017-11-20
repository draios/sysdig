#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <dragent_win_hal_public.h>

#include "scap.h"
#include "scap-int.h"
#include "windows_hal.h"

int32_t addprocess_windows(PROCESSENTRY32* pe, scap_t* handle, struct scap_threadinfo** procinfo, char *error)
{
	struct scap_threadinfo* tinfo;
	HMODULE hmod = NULL;
/*
	//
	// Try to get a handle to the process.
	// NOTE: with regukar privileges, this will only succeed for the user's 
	//       processes. Other processes will require admin or system privileges.
	//
	HANDLE hprocess = OpenProcess(PROCESS_QUERY_INFORMATION |
								   PROCESS_VM_READ,
								   FALSE, pe->th32ProcessID);

	if(NULL != hprocess )
	{
		//
		// Get the process module handle
		//
		DWORD cbneeded;
		BOOL epmres = EnumProcessModules(hprocess, &hmod, sizeof(hmod), &cbneeded);
		if(epmres == 0)
		{
			hmod = NULL;
		}
	}
*/
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
/*
	tinfo.fdlist = NULL;
	tinfo.flags = 0;
	tinfo.vmsize_kb = 0;
	tinfo.vmrss_kb = 0;
	tinfo.vmswap_kb = 0;
	tinfo.pfmajor = 0;
	tinfo.pfminor = 0;
	tinfo.env_len = 0;
	tinfo.vtid = -1;
	tinfo.vpid = -1;
	tinfo.cgroups_len = 0;
	tinfo.filtered_out = 0;
	tinfo.root[0] = 0;
	tinfo.sid = -1;
	tinfo.clone_ts = 0;
	tinfo.tty = 0;
	tinfo.exepath[0] = 0;
*/

	tinfo->pid = pe->th32ProcessID;
	tinfo->tid = pe->th32ProcessID;
	tinfo->ptid = pe->th32ParentProcessID;
	snprintf(tinfo->comm, SCAP_MAX_PATH_SIZE, "%s", pe->szExeFile);
	snprintf(tinfo->exe, SCAP_MAX_PATH_SIZE, "%s", pe->szExeFile);
	if(hmod != NULL)
	{
		DWORD gmres = GetModuleFileName(hmod, tinfo->exepath, SCAP_MAX_PATH_SIZE);
		if(gmres == 0)
		{
			tinfo->exepath[0] = 0;
		}
	}

//	printf("*********** %s  (PID:%lu PPID:%d %p)\n", tinfo->exepath, tinfo->pid, hmod);

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

/*
	//
	// Release the handle to the process.
	//
	CloseHandle(hprocess);
*/
	return SCAP_SUCCESS;
}

typedef int (CALLBACK* LPFNDLLFUNC1)();

int32_t scap_proc_scan_proc_dir_windows(scap_t* handle, struct scap_threadinfo** procinfo, char *error)
{
	char res[1024];
	int uu = aaa(res);
	printf("!!!!!!!! %p %s\n", uu, res);
	return SCAP_FAILURE;

	HANDLE h = NULL;
	PROCESSENTRY32 pe = { 0 };
	DWORD ppid = 0;
	pe.dwSize = sizeof(PROCESSENTRY32);
	h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(Process32First(h, &pe)) 
	{
		do 
		{
			int32_t apres = addprocess_windows(&pe, handle, procinfo, error);
			if(apres != SCAP_SUCCESS)
			{
				return apres;
			}
		} while( Process32Next(h, &pe));
	}
	CloseHandle(h);
	return (ppid);

	return SCAP_SUCCESS;
}
