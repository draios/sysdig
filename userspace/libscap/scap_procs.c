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
#ifndef _WIN32
#include <unistd.h>
#include <sys/param.h>
#include <dirent.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#endif

#include "scap.h"
#include "../../driver/ppm_ringbuffer.h"
#include "scap-int.h"

#if defined(HAS_CAPTURE)
int32_t scap_proc_fill_cwd(char* procdirname, struct scap_threadinfo* tinfo)
{
	int target_res;
	char filename[SCAP_MAX_PATH_SIZE];

	snprintf(filename, sizeof(filename), "%scwd", procdirname);

	target_res = readlink(filename, tinfo->cwd, sizeof(tinfo->cwd) - 1);
	if(target_res <= 0)
	{
		return SCAP_FAILURE;
	}

	tinfo->cwd[target_res] = '\0';
	return SCAP_SUCCESS;
}

int32_t scap_proc_fill_info_from_stats(char* procdirname, struct scap_threadinfo* tinfo)
{
	char filename[SCAP_MAX_PATH_SIZE];
	uint32_t nfound = 0;
	int64_t tmp;
	uint32_t uid;
	uint64_t ppid;
	int64_t sid;
	uint32_t vmsize_kb;
	uint32_t vmrss_kb;
	uint32_t vmswap_kb;
	uint64_t pfmajor;
	uint64_t pfminor;
	char line[512];
	char tmpc;
	char* s;

	tinfo->uid = (uint32_t)-1;
	tinfo->ptid = (uint32_t)-1LL;
	tinfo->sid = 0;
	tinfo->vmsize_kb = 0;
	tinfo->vmrss_kb = 0;
	tinfo->vmswap_kb = 0;
	tinfo->pfmajor = 0;
	tinfo->pfminor = 0;
	tinfo->filtered_out = 0;

	snprintf(filename, sizeof(filename), "%sstatus", procdirname);

	FILE* f = fopen(filename, "r");
	if(f == NULL)
	{
		ASSERT(false);
		return SCAP_FAILURE;
	}

	while(fgets(line, sizeof(line), f) != NULL)
	{
		if(strstr(line, "Uid") == line)
		{
			nfound++;

			if(sscanf(line, "Uid: %" PRIu64 " %" PRIu32, &tmp, &uid) == 2)
			{
				tinfo->uid = uid;
			}
			else
			{
				ASSERT(false);
			}
		}
		else if(strstr(line, "Gid") == line)
		{
			nfound++;

			if(sscanf(line, "Gid: %" PRIu64 " %" PRIu32, &tmp, &uid) == 2)
			{
				tinfo->gid = uid;
			}
			else
			{
				ASSERT(false);
			}
		}
		else if(strstr(line, "PPid") == line)
		{
			nfound++;

			if(sscanf(line, "PPid: %" PRIu64, &ppid) == 1)
			{
				tinfo->ptid = ppid;
			}
			else
			{
				ASSERT(false);
			}
		}
		else if(strstr(line, "VmSize:") == line)
		{
			nfound++;

			if(sscanf(line, "VmSize: %" PRIu32, &vmsize_kb) == 1)
			{
				tinfo->vmsize_kb = vmsize_kb;
			}
			else
			{
				ASSERT(false);
			}
		}
		else if(strstr(line, "VmRSS:") == line)
		{
			nfound++;

			if(sscanf(line, "VmRSS: %" PRIu32, &vmrss_kb) == 1)
			{
				tinfo->vmrss_kb = vmrss_kb;
			}
			else
			{
				ASSERT(false);
			}
		}
		else if(strstr(line, "VmSwap:") == line)
		{
			nfound++;

			if(sscanf(line, "VmSwap: %" PRIu32, &vmswap_kb) == 1)
			{
				tinfo->vmswap_kb = vmswap_kb;
			}
			else
			{
				ASSERT(false);
			}
		}

		if(nfound == 6)
		{
			break;
		}
	}

	ASSERT(nfound == 6 || nfound == 5);

	fclose(f);

	snprintf(filename, sizeof(filename), "%sstat", procdirname);

	f = fopen(filename, "r");
	if(f == NULL)
	{
		ASSERT(false);
		return SCAP_FAILURE;
	}

	if(fgets(line, sizeof(line), f) == NULL)
	{
		ASSERT(false);
		fclose(f);
		return SCAP_FAILURE;
	}

	s = strrchr(line, ')');
	if(s == NULL)
	{
		ASSERT(false);
		fclose(f);
		return SCAP_FAILURE;
	}

	//
	// Extract the line content
	//
	if(sscanf(s + 2, "%c %" PRId64 " %" PRId64 " %" PRId64 " %" PRId64 " %" PRId64 " %" PRId64 " %" PRId64 " %" PRId64 " %" PRId64,
		&tmpc,
		&tmp,
		&sid,
		&tmp,
		&tmp,
		&tmp,
		&tmp,
		&pfminor,
		&tmp,
		&pfmajor) != 10)
	{
		ASSERT(false);
		fclose(f);
		return SCAP_FAILURE;
	}

	tinfo->pfmajor = pfmajor;
	tinfo->pfminor = pfminor;
	tinfo->sid = (uint64_t) sid;

	fclose(f);
	return SCAP_SUCCESS;
}

//
// use prlimit to extract the RLIMIT_NOFILE for the tid. On systems where prlimit
// is not supported, just return -1
//
static int32_t scap_proc_fill_flimit(uint64_t tid, struct scap_threadinfo* tinfo)
#ifdef SYS_prlimit64
{
	struct rlimit rl;

#ifdef __NR_prlimit64
	if(syscall(SYS_prlimit64, tid, RLIMIT_NOFILE, NULL, &rl) == 0)
	{
		tinfo->fdlimit = rl.rlim_cur;
		return SCAP_SUCCESS;
	}
#endif

	tinfo->fdlimit = -1;
	return SCAP_SUCCESS;
}
#else
{
	tinfo->fdlimit = -1;
	return SCAP_SUCCESS;
}
#endif

int32_t scap_proc_fill_cgroups(struct scap_threadinfo* tinfo, const char* procdirname)
{
	char filename[SCAP_MAX_PATH_SIZE];
	char line[SCAP_MAX_CGROUPS_SIZE];

	tinfo->cgroups_len = 0;
	snprintf(filename, sizeof(filename), "%scgroup", procdirname);

    if(access(filename, R_OK) == -1)
	{
		return SCAP_SUCCESS;
	}

	FILE* f = fopen(filename, "r");
	if(f == NULL)
	{
		ASSERT(false);
		return SCAP_FAILURE;
	}

	while(fgets(line, sizeof(line), f) != NULL)
	{
		char* token;
		char* subsys_list;
		char* cgroup;

		// id
		token = strtok(line, ":");
		if(token == NULL)
		{
			ASSERT(false);
			fclose(f);
			return SCAP_FAILURE;
		}

		// subsys
		subsys_list = strtok(NULL, ":");
		if(subsys_list == NULL)
		{
			ASSERT(false);
			fclose(f);
			return SCAP_FAILURE;
		}

		// transient cgroup
		if(strncmp(subsys_list, "name=", sizeof("name=") - 1) == 0)
		{
			continue;
		}

		// cgroup
		cgroup = strtok(NULL, ":");
		if(cgroup == NULL)
		{
			ASSERT(false);
			fclose(f);
			return SCAP_FAILURE;
		}

		// remove the \n
		cgroup[strlen(cgroup) - 1] = 0;

		while((token = strtok(subsys_list, ",")) != NULL)
		{
			subsys_list = NULL;
			if(strlen(cgroup) + 1 + strlen(token) + 1 > SCAP_MAX_CGROUPS_SIZE - tinfo->cgroups_len)
			{
				ASSERT(false);
				fclose(f);
				return SCAP_SUCCESS;
			}

			snprintf(tinfo->cgroups + tinfo->cgroups_len, SCAP_MAX_CGROUPS_SIZE - tinfo->cgroups_len, "%s=%s", token, cgroup);
			tinfo->cgroups_len += strlen(cgroup) + 1 + strlen(token) + 1;
		}
	}

	fclose(f);
	return SCAP_SUCCESS;
}

static int32_t scap_get_vtid(scap_t* handle, int64_t tid, int64_t *vtid)
{
	if(handle->m_file)
	{
		ASSERT(false);
		return SCAP_FAILURE;
	}

#if !defined(HAS_CAPTURE)
	ASSERT(false)
	return SCAP_FAILURE;
#else

	*vtid = ioctl(handle->m_devs[0].m_fd, PPM_IOCTL_GET_VTID, tid);

	if(*vtid == -1)
	{
		ASSERT(false);
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
#endif
}

static int32_t scap_get_vpid(scap_t* handle, int64_t tid, int64_t *vpid)
{
	if(handle->m_file)
	{
		ASSERT(false);
		return SCAP_FAILURE;
	}

#if !defined(HAS_CAPTURE)
	ASSERT(false)
	return SCAP_FAILURE;
#else

	*vpid = ioctl(handle->m_devs[0].m_fd, PPM_IOCTL_GET_VPID, tid);

	if(*vpid == -1)
	{
		ASSERT(false);
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
#endif
}

int32_t scap_getpid_global(scap_t* handle, int64_t* pid)
{
	if(handle->m_file)
	{
		ASSERT(false);
		return SCAP_FAILURE;
	}

#if !defined(HAS_CAPTURE)
	ASSERT(false)
	return SCAP_FAILURE;
#else

	*pid = ioctl(handle->m_devs[0].m_fd, PPM_IOCTL_GET_CURRENT_PID);
	if(*pid == -1)
	{
		ASSERT(false);
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
#endif
}

int32_t scap_proc_fill_root(struct scap_threadinfo* tinfo, const char* procdirname)
{
	char root_path[SCAP_MAX_PATH_SIZE];
	snprintf(root_path, sizeof(root_path), "%sroot", procdirname);
	if ( readlink(root_path, tinfo->root, sizeof(tinfo->root)) > 0)
	{
		return SCAP_SUCCESS;
	}
	else
	{
		return SCAP_FAILURE;
	}
}

//
// Add a process to the list by parsing its entry under /proc
//
static int32_t scap_proc_add_from_proc(scap_t* handle, uint32_t tid, int parenttid, int tid_to_scan, char* procdirname, struct scap_ns_socket_list** sockets_by_ns, scap_threadinfo** procinfo, char *error)
{
	char dir_name[256];
	char target_name[256];
	int target_res;
	char filename[252];
	char line[SCAP_MAX_ENV_SIZE];
	struct scap_threadinfo* tinfo;
	int32_t uth_status = SCAP_SUCCESS;
	FILE* f;
	size_t filesize;
	size_t exe_len;
	bool free_tinfo = false;
	int32_t res = SCAP_SUCCESS;

	snprintf(dir_name, sizeof(dir_name), "%s/%u/", procdirname, tid);
	snprintf(filename, sizeof(filename), "%sexe", dir_name);

	//
	// Gather the executable full name
	//
	target_res = readlink(filename, target_name, sizeof(target_name) - 1);			// Getting the target of the exe, i.e. to which binary it points to

	if(target_res <= 0)
	{
		//
		// No exe. This either
		//  - a kernel thread (if there is no cmdline). In that case we skip it.
		//  - a process that has been containerized or has some weird thing going on. In that case
		//    we accept it.
		//
		snprintf(filename, sizeof(filename), "%scmdline", dir_name);
		f = fopen(filename, "r");
		if(f == NULL)
		{
			return SCAP_SUCCESS;
		}

		ASSERT(sizeof(line) >= SCAP_MAX_PATH_SIZE);

		if(fgets(line, SCAP_MAX_PATH_SIZE, f) == NULL)
		{
			fclose(f);
			return SCAP_SUCCESS;
		}
		else
		{
			fclose(f);
		}
	}

	//
	// This is a real user level process. Allocate the procinfo structure.
	//
	tinfo = (scap_threadinfo*)malloc(sizeof(scap_threadinfo));
	if(tinfo == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "process table allocation error (1)");
		return SCAP_FAILURE;
	}

	memset(tinfo, 0, sizeof(scap_threadinfo));

	tinfo->tid = tid;
	if(parenttid != -1)
	{
		tinfo->pid = parenttid;
	}
	else
	{
		tinfo->pid = tid;
	}

	tinfo->fdlist = NULL;

	//
	// If tid is different from pid, assume this is a thread and that the FDs are shared, and set the
	// corresponding process flags.
	// XXX we should see if the process creation flags are stored somewhere in /proc and handle this
	// properly instead of making assumptions.
	//
	if(tinfo->tid == tinfo->pid)
	{
		tinfo->flags = 0;
	}
	else
	{
		tinfo->flags = PPM_CL_CLONE_THREAD | PPM_CL_CLONE_FILES;
	}

	//
	// Gather the command name
	//
	snprintf(filename, sizeof(filename), "%sstatus", dir_name);

	f = fopen(filename, "r");
	if(f == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't open %s", filename);
		free(tinfo);
		return SCAP_FAILURE;
	}
	else
	{
		ASSERT(sizeof(line) >= SCAP_MAX_PATH_SIZE);

		if(fgets(line, SCAP_MAX_PATH_SIZE, f) == NULL)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "can't read from %s", filename);
			fclose(f);
			free(tinfo);
			return SCAP_FAILURE;
		}

		line[SCAP_MAX_PATH_SIZE - 1] = 0;
		sscanf(line, "Name:%s", tinfo->comm);
		fclose(f);
	}

	//
	// Gather the command line
	//
	snprintf(filename, sizeof(filename), "%scmdline", dir_name);

	f = fopen(filename, "r");
	if(f == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't open %s", filename);
		free(tinfo);
		return SCAP_FAILURE;
	}
	else
	{
		ASSERT(sizeof(line) >= SCAP_MAX_ARGS_SIZE);

		filesize = fread(line, 1, SCAP_MAX_ARGS_SIZE - 1, f);
		if(filesize > 0)
		{
			line[filesize] = 0;

			exe_len = strlen(line);
			if(exe_len < filesize)
			{
				++exe_len;
			}

			snprintf(tinfo->exe, SCAP_MAX_PATH_SIZE, "%s", line);

			tinfo->args_len = filesize - exe_len;

			memcpy(tinfo->args, line + exe_len, tinfo->args_len);
			tinfo->args[SCAP_MAX_ARGS_SIZE - 1] = 0;
		}
		else
		{
			tinfo->args[0] = 0;
			tinfo->exe[0] = 0;
		}

		fclose(f);
	}

	//
	// Gather the environment
	//
	snprintf(filename, sizeof(filename), "%senviron", dir_name);

	f = fopen(filename, "r");
	if(f == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't open %s", filename);
		free(tinfo);
		return SCAP_FAILURE;
	}
	else
	{
		ASSERT(sizeof(line) >= SCAP_MAX_ENV_SIZE);

		filesize = fread(line, 1, SCAP_MAX_ENV_SIZE, f);

		if(filesize > 0)
		{
			line[filesize - 1] = 0;

			tinfo->env_len = filesize;

			memcpy(tinfo->env, line, tinfo->env_len);
			tinfo->env[SCAP_MAX_ENV_SIZE - 1] = 0;
		}
		else
		{
			tinfo->env[0] = 0;
		}

		fclose(f);
	}

	//
	// set the current working directory of the process
	//
	if(SCAP_FAILURE == scap_proc_fill_cwd(dir_name, tinfo))
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't fill cwd for %s", dir_name);
		free(tinfo);
		return SCAP_FAILURE;
	}

	//
	// extract the user id and ppid from /proc/pid/status
	//
	if(SCAP_FAILURE == scap_proc_fill_info_from_stats(dir_name, tinfo))
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't fill cwd for %s", dir_name);
		free(tinfo);
		return SCAP_FAILURE;
	}

	//
	// Set the file limit
	//
	if(SCAP_FAILURE == scap_proc_fill_flimit(tinfo->tid, tinfo))
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't fill flimit for %s", dir_name);
		free(tinfo);
		return SCAP_FAILURE;
	}

	if(scap_proc_fill_cgroups(tinfo, dir_name) == SCAP_FAILURE)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't fill cgroups for %" PRIu64, tinfo->tid);
		free(tinfo);
		return SCAP_FAILURE;
	}

	if(scap_get_vtid(handle, tinfo->tid, &tinfo->vtid) == SCAP_FAILURE)
	{
		tinfo->vtid = tinfo->tid;
	}

	if(scap_get_vpid(handle, tinfo->tid, &tinfo->vpid) == SCAP_FAILURE)
	{
		tinfo->vpid = tinfo->pid;
	}

	//
	// set the current root of the process
	//
	if(SCAP_FAILURE == scap_proc_fill_root(tinfo, dir_name))
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't fill root for %s", dir_name);
		free(tinfo);
		return SCAP_FAILURE;
	}

	//
	// if tid_to_scan is set we assume this is a runtime lookup so no
	// need to use the table
	//
	if(tid_to_scan == -1)
	{
		//
		// Done. Add the entry to the process table, or fire the notification callback
		//
		if(handle->m_proc_callback == NULL)
		{
			HASH_ADD_INT64(handle->m_proclist, tid, tinfo);
			if(uth_status != SCAP_SUCCESS)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "process table allocation error (2)");
				return SCAP_FAILURE;
			}
		}
		else
		{
			handle->m_proc_callback(handle->m_proc_callback_context, tinfo->tid, tinfo, NULL, handle);
			free_tinfo = true;
		}
	}
	else
	{
		*procinfo = tinfo;
	}

	//
	// Only add fds for processes, not threads
	//
	if(parenttid == -1)
	{
		res = scap_fd_scan_fd_dir(handle, dir_name, tinfo, sockets_by_ns, error);
	}

	if(free_tinfo)
	{
		free(tinfo);
	}

	return res;
}

//
// Scan a directory containing multiple processes under /proc
//
int32_t scap_proc_scan_proc_dir(scap_t* handle, char* procdirname, int parenttid, int tid_to_scan, struct scap_threadinfo** procinfo, char *error, bool scan_sockets)
{
	DIR *dir_p;
	struct dirent *dir_entry_p;
	scap_threadinfo* tinfo;
	uint64_t tid;
	int32_t res = SCAP_SUCCESS;
	char childdir[SCAP_MAX_PATH_SIZE];

	struct scap_ns_socket_list* sockets_by_ns = NULL;

	tid = 0;
	dir_p = opendir(procdirname);

	if(dir_p == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error opening the %s directory", procdirname);
		return SCAP_NOTFOUND;
	}

	if(-1 == parenttid)
	{
		if(!scan_sockets)
		{
			sockets_by_ns = (void*)-1;
		}
	}

	if(tid_to_scan != -1)
	{
		*procinfo = NULL;
	}

	while((dir_entry_p = readdir(dir_p)) != NULL)
	{
		if(strspn(dir_entry_p->d_name, "0123456789") != strlen(dir_entry_p->d_name))
		{
			continue;
		}

		//
		// Gather the process TID, which is the directory name
		//
		tid = atoi(dir_entry_p->d_name);

		//
		// Skip the main thread entry
		//
		if(parenttid != -1 && tid == parenttid)
		{
			continue;
		}

		//
		// if tid_to_scan is set we assume is a runtime lookup so no
		// need to use the table
		//
		if(tid_to_scan == -1)
		{
			HASH_FIND_INT64(handle->m_proclist, &tid, tinfo);
			if(tinfo != NULL)
			{
				ASSERT(false);
				snprintf(error, SCAP_LASTERR_SIZE, "duplicate process %"PRIu64, tid);
				res = SCAP_FAILURE;
				break;
			}
		}

		if(tid_to_scan == -1 || tid_to_scan == tid)
		{
			//
			// We have a process that needs to be explored
			//
			res = scap_proc_add_from_proc(handle, tid, parenttid, tid_to_scan, procdirname, &sockets_by_ns, procinfo, error);
			if(res != SCAP_SUCCESS)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "cannot add procs tid = %"PRIu64", parenttid = %"PRIi32", dirname = %s", tid, parenttid, procdirname);
				break;
			}

			if(tid_to_scan != -1)
			{
				//
				// procinfo should be filled, except when
				// the main thread already terminated and
				// the various proc files were not readable
				//
				// ASSERT(*procinfo);
				break;
			}
		}

		//
		// See if this process includes tasks that need to be added
		//
		snprintf(childdir, sizeof(childdir), "%s/%u/task", procdirname, (int)tid);
		if(scap_proc_scan_proc_dir(handle, childdir, tid, tid_to_scan, procinfo, error, scan_sockets) == SCAP_FAILURE)
		{
			res = SCAP_FAILURE;
			break;
		}

		if(tid_to_scan != -1 && *procinfo)
		{
			//
			// We found the process we were looking for, no need to keep iterating
			//
			break;
		}
	}

	closedir(dir_p);
	if(sockets_by_ns != NULL && sockets_by_ns != (void*)-1)
	{
		scap_fd_free_ns_sockets_list(handle, &sockets_by_ns);
	}
	return res;
}

#endif // HAS_CAPTURE

//
// Delete a process entry
//
void scap_proc_delete(scap_t* handle, scap_threadinfo* proc)
{
	//
	// First, free the fd table for this process descriptor
	//
	scap_fd_free_proc_fd_table(handle, proc);

	//
	// Second, remove the process descriptor from the table
	//
	HASH_DEL(handle->m_proclist, proc);

	//
	// Third, free the memory
	//
	free(proc);
}

//
// Free the process table
//
void scap_proc_free_table(scap_t* handle)
{
	struct scap_threadinfo* tinfo;
	struct scap_threadinfo* ttinfo;

	HASH_ITER(hh, handle->m_proclist, tinfo, ttinfo)
	{
		scap_proc_delete(handle, tinfo);
	}
}

struct scap_threadinfo* scap_proc_get(scap_t* handle, int64_t tid, bool scan_sockets)
{
#if !defined(HAS_CAPTURE)
	return NULL;
#else

	//
	// No /proc parsing for offline captures
	//
	if(handle->m_file)
	{
		return NULL;
	}

	struct scap_threadinfo* tinfo = NULL;
	char filename[SCAP_MAX_PATH_SIZE];
	snprintf(filename, sizeof(filename), "%s/proc", scap_get_host_root());
	if(scap_proc_scan_proc_dir(handle, filename, -1, tid, &tinfo, handle->m_lasterr, scan_sockets) != SCAP_SUCCESS)
	{
		return NULL;
	}

	return tinfo;
#endif // HAS_CAPTURE
}

bool scap_is_thread_alive(scap_t* handle, int64_t pid, int64_t tid, const char* comm)
{
#if !defined(HAS_CAPTURE)
	return false;
#else
	char charbuf[SCAP_MAX_PATH_SIZE];
	FILE* f;


	//
	// No /proc parsing for offline captures
	//
	if(handle->m_file)
	{
		return false;
	}

	snprintf(charbuf, sizeof(charbuf), "%s/proc/%" PRId64 "/task/%" PRId64 "/comm", scap_get_host_root(), pid, tid);

	f = fopen(charbuf, "r");

	if(f != NULL)
	{
		if(fgets(charbuf, sizeof(charbuf), f) != NULL)
		{
			if(strncmp(charbuf, comm, strlen(comm)) == 0)
			{
				fclose(f);
				return true;
			}
		}

		fclose(f);
	}
	else
	{
		//
		// If /proc/<pid>/task/<tid>/comm does not exist but /proc/<pid>/task/<tid>/exe does exist, we assume we're on an ancient
		// OS like RHEL5 and we return true.
		// This could generate some false positives on such old distros, and we're going to accept it.
		//
		snprintf(charbuf, sizeof(charbuf), "%s/proc/%" PRId64 "/task/%" PRId64 "/exe", scap_get_host_root(), pid, tid);
		f = fopen(charbuf, "r");
		if(f != NULL)
		{
			fclose(f);
			return true;
		}

	}

	return false;
#endif // HAS_CAPTURE
}

void scap_proc_free(scap_t* handle, struct scap_threadinfo* proc)
{
	scap_fd_free_proc_fd_table(handle, proc);
	free(proc);
}

//
// Internal helper functions to output the process table to screen
//
void scap_proc_print_info(scap_threadinfo* tinfo)
{
	fprintf(stderr, "TID:%"PRIu64" PID:%"PRIu64" FLAGS:%"PRIu32" COMM:%s EXE:%s ARGS:%s CWD:%s FLIMIT:%" PRId64 "\n", tinfo->tid, tinfo->pid, tinfo->flags,tinfo->comm, tinfo->exe, tinfo->args, tinfo->cwd, tinfo->fdlimit);
	scap_fd_print_table(tinfo);
}

void scap_proc_print_proc_by_tid(scap_t* handle, uint64_t tid)
{
	scap_threadinfo* tinfo;
	scap_threadinfo* ttinfo;

	HASH_ITER(hh, handle->m_proclist, tinfo, ttinfo)
	{
		if(tinfo->tid == tid)
		{
			scap_proc_print_info(tinfo);
		}
	}
}

void scap_proc_print_table(scap_t* handle)
{
	scap_threadinfo* tinfo;
	scap_threadinfo* ttinfo;

	printf("************** PROCESS TABLE **************\n");

	HASH_ITER(hh, handle->m_proclist, tinfo, ttinfo)
	{
		scap_proc_print_info(tinfo);
	}

	printf("*******************************************\n");
}
