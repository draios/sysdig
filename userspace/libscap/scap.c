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
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <sys/time.h>
#endif // _WIN32

#ifdef CYGWING_AGENT
#define DRAGENT_WIN_HAL_C_ONLY
#include <dragent_win_hal_public.h>
#endif

#include "scap.h"
#ifdef HAS_CAPTURE
#ifndef CYGWING_AGENT
#include "../../driver/driver_config.h"
#endif // CYGWING_AGENT
#endif // HAS_CAPTURE
#include "../../driver/ppm_ringbuffer.h"
#include "scap_savefile.h"
#include "scap-int.h"
#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT)
#include "scap_bpf.h"
#endif

//#define NDEBUG
#include <assert.h>

static const char *SYSDIG_BPF_PROBE_ENV = "SYSDIG_BPF_PROBE";

const char* scap_getlasterr(scap_t* handle)
{
	return handle->m_lasterr;
}

static int32_t copy_comms(scap_t *handle, const char **suppressed_comms)
{
	if(suppressed_comms)
	{
		uint32_t i;
		const char *comm;
		for(i = 0, comm = suppressed_comms[i]; comm && i < SCAP_MAX_SUPPRESSED_COMMS; i++, comm = suppressed_comms[i])
		{
			int32_t res;
			if((res = scap_suppress_events_comm(handle, comm)) != SCAP_SUCCESS)
			{
				return res;
			}
		}
	}

	return SCAP_SUCCESS;
}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
scap_t* scap_open_live_int(char *error, int32_t *rc,
			   proc_entry_callback proc_callback,
			   void* proc_callback_context,
			   bool import_users,
			   const char *bpf_probe,
			   const char **suppressed_comms)
{
	snprintf(error, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	*rc = SCAP_NOT_SUPPORTED;
	return NULL;
}
#else

static uint32_t get_max_consumers()
{
	uint32_t max;
	FILE *pfile = fopen("/sys/module/" PROBE_DEVICE_NAME "_probe/parameters/max_consumers", "r");
	if(pfile != NULL)
	{
		int w = fscanf(pfile, "%"PRIu32, &max);
		if(w == 0)
		{
			return 0;
		}

		fclose(pfile);
		return max;
	}

	return 0;
}

scap_t* scap_open_live_int(char *error, int32_t *rc,
			   proc_entry_callback proc_callback,
			   void* proc_callback_context,
			   bool import_users,
			   const char *bpf_probe,
			   const char **suppressed_comms)
{
	uint32_t j;
	char filename[SCAP_MAX_PATH_SIZE];
	scap_t* handle = NULL;
	uint32_t ndevs;

	//
	// Allocate the handle
	//
	handle = (scap_t*) calloc(sizeof(scap_t), 1);
	if(!handle)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the scap_t structure");
		*rc = SCAP_FAILURE;
		return NULL;
	}

	//
	// Preliminary initializations
	//
	handle->m_mode = SCAP_MODE_LIVE;

	//
	// While in theory we could always rely on the scap caller to properly
	// set a BPF probe from the environment variable, it's in practice easier
	// to do one more check here in scap so we don't have to repeat the logic
	// in all the possible users of the libraries (falco, sysdig, csysdig, dragent, ...)
	//
	if(!bpf_probe)
	{
		bpf_probe = scap_get_bpf_probe_from_env();
	}

	char buf[SCAP_MAX_PATH_SIZE];
	if(bpf_probe)
	{
		handle->m_bpf = true;

		if(strlen(bpf_probe) == 0)
		{
			const char *home = getenv("HOME");
			if(!home)
			{
				scap_close(handle);
				snprintf(error, SCAP_LASTERR_SIZE, "HOME environment not set");
				*rc = SCAP_FAILURE;
				return NULL;
			}

			snprintf(buf, sizeof(buf), "%s/.sysdig/%s-bpf.o", home, PROBE_NAME);
			bpf_probe = buf;
		}
	}
	else
	{
		handle->m_bpf = false;
	}

	handle->m_ncpus = sysconf(_SC_NPROCESSORS_CONF);
	if(handle->m_ncpus == -1)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "_SC_NPROCESSORS_CONF: %s", strerror(errno));
		*rc = SCAP_FAILURE;
		return NULL;
	}

	//
	// Find out how many devices we have to open, which equals to the number of CPUs
	//
	ndevs = sysconf(_SC_NPROCESSORS_ONLN);
	if(ndevs == -1)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "_SC_NPROCESSORS_ONLN: %s", strerror(errno));
		*rc = SCAP_FAILURE;
		return NULL;
	}

	handle->m_devs = (scap_device*) calloc(sizeof(scap_device), ndevs);
	if(!handle->m_devs)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the device handles");
		*rc = SCAP_FAILURE;
		return NULL;
	}

	for(j = 0; j < ndevs; j++)
	{
		handle->m_devs[j].m_buffer = (char*)MAP_FAILED;
		if(!handle->m_bpf)
		{
			handle->m_devs[j].m_bufinfo = (struct ppm_ring_buffer_info*)MAP_FAILED;
		}
	}

	handle->m_ndevs = ndevs;

	//
	// Extract machine information
	//
	handle->m_proc_callback = proc_callback;
	handle->m_proc_callback_context = proc_callback_context;
	handle->m_machine_info.num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	handle->m_machine_info.memory_size_bytes = (uint64_t)sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE);
	gethostname(handle->m_machine_info.hostname, sizeof(handle->m_machine_info.hostname) / sizeof(handle->m_machine_info.hostname[0]));
	handle->m_machine_info.reserved1 = 0;
	handle->m_machine_info.reserved2 = 0;
	handle->m_machine_info.reserved3 = 0;
	handle->m_machine_info.reserved4 = 0;
	handle->m_driver_procinfo = NULL;
	handle->m_fd_lookup_limit = 0;
#ifdef CYGWING_AGENT
	handle->m_whh = NULL;
#endif

	//
	// Create the interface list
	//
	if((*rc = scap_create_iflist(handle)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "error creating the interface list");
		return NULL;
	}

	//
	// Create the user list
	//
	if(import_users)
	{
		if((*rc = scap_create_userlist(handle)) != SCAP_SUCCESS)
		{
			scap_close(handle);
			snprintf(error, SCAP_LASTERR_SIZE, "error creating the interface list");
			return NULL;
		}
	}
	else
	{
		handle->m_userlist = NULL;
	}

	handle->m_fake_kernel_proc.tid = -1;
	handle->m_fake_kernel_proc.pid = -1;
	handle->m_fake_kernel_proc.flags = 0;
	snprintf(handle->m_fake_kernel_proc.comm, SCAP_MAX_PATH_SIZE, "kernel");
	snprintf(handle->m_fake_kernel_proc.exe, SCAP_MAX_PATH_SIZE, "kernel");
	handle->m_fake_kernel_proc.args[0] = 0;
	handle->refresh_proc_table_when_saving = true;

	handle->m_suppressed_comms = NULL;
	handle->m_num_suppressed_comms = 0;
	handle->m_suppressed_tids = NULL;
	handle->m_num_suppressed_evts = 0;

	if ((*rc = copy_comms(handle, suppressed_comms)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "error copying suppressed comms");
		return NULL;
	}

	//
	// Open and initialize all the devices
	//
	if(handle->m_bpf)
	{
		if((*rc = scap_bpf_load(handle, bpf_probe)) != SCAP_SUCCESS)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "%s", handle->m_lasterr);
			scap_close(handle);
			return NULL;
		}
	}
	else
	{
		int len;
		uint32_t all_scanned_devs;

		//
		// Allocate the device descriptors.
		//
		len = RING_BUF_SIZE * 2;

		for(j = 0, all_scanned_devs = 0; j < handle->m_ndevs && all_scanned_devs < handle->m_ncpus; ++all_scanned_devs)
		{
			//
			// Open the device
			//
			sprintf(filename, "%s/dev/" PROBE_DEVICE_NAME "%d", scap_get_host_root(), all_scanned_devs);

			if((handle->m_devs[j].m_fd = open(filename, O_RDWR | O_SYNC)) < 0)
			{
				if(errno == ENODEV)
				{
					//
					// This CPU is offline, so we just skip it
					//
					continue;
				}
				else if(errno == EBUSY)
				{
					uint32_t curr_max_consumers = get_max_consumers();
					snprintf(error, SCAP_LASTERR_SIZE, "Too many sysdig instances attached to device %s. Current value for /sys/module/" PROBE_DEVICE_NAME "_probe/parameters/max_consumers is '%"PRIu32"'.", filename, curr_max_consumers);
				}
				else
				{
					snprintf(error, SCAP_LASTERR_SIZE, "error opening device %s. Make sure you have root credentials and that the " PROBE_NAME " module is loaded.", filename);
				}

				scap_close(handle);
				*rc = SCAP_FAILURE;
				return NULL;
			}

			// Set close-on-exec for the fd
			if (fcntl(handle->m_devs[j].m_fd, F_SETFD, FD_CLOEXEC) == -1) {
				snprintf(error, SCAP_LASTERR_SIZE, "Can not set close-on-exec flag for fd for device %s (%s)", filename, strerror(errno));
				scap_close(handle);
				*rc = SCAP_FAILURE;
				return NULL;
			}

			//
			// Map the ring buffer
			//
			handle->m_devs[j].m_buffer = (char*)mmap(0,
						len,
						PROT_READ,
						MAP_SHARED,
						handle->m_devs[j].m_fd,
						0);

			if(handle->m_devs[j].m_buffer == MAP_FAILED)
			{
				// we cleanup this fd and then we let scap_close() take care of the other ones
				close(handle->m_devs[j].m_fd);

				scap_close(handle);
				snprintf(error, SCAP_LASTERR_SIZE, "error mapping the ring buffer for device %s", filename);
				*rc = SCAP_FAILURE;
				return NULL;
			}

			//
			// Map the ppm_ring_buffer_info that contains the buffer pointers
			//
			handle->m_devs[j].m_bufinfo = (struct ppm_ring_buffer_info*)mmap(0,
						sizeof(struct ppm_ring_buffer_info),
						PROT_READ | PROT_WRITE,
						MAP_SHARED,
						handle->m_devs[j].m_fd,
						0);

			if(handle->m_devs[j].m_bufinfo == MAP_FAILED)
			{
				// we cleanup this fd and then we let scap_close() take care of the other ones
				munmap(handle->m_devs[j].m_buffer, len);
				close(handle->m_devs[j].m_fd);

				scap_close(handle);

				snprintf(error, SCAP_LASTERR_SIZE, "error mapping the ring buffer info for device %s", filename);
				*rc = SCAP_FAILURE;
				return NULL;
			}

			++j;
		}
	}

	for(j = 0; j < handle->m_ndevs; ++j)
	{
		//
		// Additional initializations
		//
		handle->m_devs[j].m_lastreadsize = 0;
		handle->m_devs[j].m_sn_len = 0;
		handle->m_n_consecutive_waits = 0;
		scap_stop_dropping_mode(handle);
	}

	//
	// Create the process list
	//
	error[0] = '\0';
	snprintf(filename, sizeof(filename), "%s/proc", scap_get_host_root());
	if((*rc = scap_proc_scan_proc_dir(handle, filename, -1, -1, NULL, error, true)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "error creating the process list. Make sure you have root credentials.");
		return NULL;
	}

	//
	// Now that sysdig has done all its /proc parsing, start the capture
	//
	if((*rc = scap_start_capture(handle)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		return NULL;
	}

	return handle;
}
#endif // HAS_CAPTURE

scap_t* scap_open_offline_int(gzFile gzfile,
			      char *error,
			      int32_t *rc,
			      proc_entry_callback proc_callback,
			      void* proc_callback_context,
			      bool import_users,
			      uint64_t start_offset,
			      const char **suppressed_comms)
{
	scap_t* handle = NULL;

	//
	// Allocate the handle
	//
	handle = (scap_t*)malloc(sizeof(scap_t));
	if(!handle)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the scap_t structure");
		*rc = SCAP_FAILURE;
		return NULL;
	}

	//
	// Preliminary initializations
	//
	handle->m_mode = SCAP_MODE_CAPTURE;
	handle->m_proc_callback = proc_callback;
	handle->m_proc_callback_context = proc_callback_context;
	handle->m_devs = NULL;
	handle->m_ndevs = 0;
	handle->m_proclist = NULL;
	handle->m_evtcnt = 0;
	handle->m_file = NULL;
	handle->m_addrlist = NULL;
	handle->m_userlist = NULL;
	handle->m_machine_info.num_cpus = (uint32_t)-1;
	handle->m_last_evt_dump_flags = 0;
	handle->m_driver_procinfo = NULL;
	handle->refresh_proc_table_when_saving = true;
	handle->m_fd_lookup_limit = 0;
#ifdef CYGWING_AGENT
	handle->m_whh = NULL;
#endif
	handle->m_bpf = false;

	handle->m_file_evt_buf = (char*)malloc(FILE_READ_BUF_SIZE);
	if(!handle->m_file_evt_buf)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the read buffer");
		scap_close(handle);
		*rc = SCAP_FAILURE;
		return NULL;
	}

	handle->m_file = gzfile;

	//
	// If this is a merged file, we might have to move the read offset to the next section
	//
	if(start_offset != 0)
	{
		scap_fseek(handle, start_offset);
	}

	//
	// Validate the file and load the non-event blocks
	//
	if((*rc = scap_read_init(handle, handle->m_file)) != SCAP_SUCCESS)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "Could not initialize reader: %s", scap_getlasterr(handle));
		scap_close(handle);
		return NULL;
	}

	if(!import_users)
	{
		if(handle->m_userlist != NULL)
		{
			scap_free_userlist(handle->m_userlist);
			handle->m_userlist = NULL;
		}
	}

	//
	// Add the fake process for kernel threads
	//
	handle->m_fake_kernel_proc.tid = -1;
	handle->m_fake_kernel_proc.pid = -1;
	handle->m_fake_kernel_proc.flags = 0;
	snprintf(handle->m_fake_kernel_proc.comm, SCAP_MAX_PATH_SIZE, "kernel");
	snprintf(handle->m_fake_kernel_proc.exe, SCAP_MAX_PATH_SIZE, "kernel");
	handle->m_fake_kernel_proc.args[0] = 0;

	handle->m_suppressed_comms = NULL;
	handle->m_num_suppressed_comms = 0;
	handle->m_suppressed_tids = NULL;
	handle->m_num_suppressed_evts = 0;

	if ((*rc = copy_comms(handle, suppressed_comms)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "error copying suppressed comms");
		return NULL;
	}

	return handle;
}

scap_t* scap_open_offline(const char* fname, char *error, int32_t* rc)
{
	gzFile gzfile = gzopen(fname, "rb");
	if(gzfile == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't open file %s", fname);
		*rc = SCAP_FAILURE;
		return NULL;
	}

	return scap_open_offline_int(gzfile, error, rc, NULL, NULL, true, 0, NULL);
}

scap_t* scap_open_offline_fd(int fd, char *error, int32_t *rc)
{
	gzFile gzfile = gzdopen(fd, "rb");
	if(gzfile == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't open fd %d", fd);
		*rc = SCAP_FAILURE;
		return NULL;
	}

	return scap_open_offline_int(gzfile, error, rc, NULL, NULL, true, 0, NULL);
}

scap_t* scap_open_live(char *error, int32_t *rc)
{
	return scap_open_live_int(error, rc, NULL, NULL, true, NULL, NULL);
}

scap_t* scap_open_nodriver_int(char *error, int32_t *rc,
			       proc_entry_callback proc_callback,
			       void* proc_callback_context,
			       bool import_users)
{
#if !defined(HAS_CAPTURE)
	snprintf(error, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	*rc = SCAP_NOT_SUPPORTED;
	return NULL;
#else
	char filename[SCAP_MAX_PATH_SIZE];
	scap_t* handle = NULL;

	//
	// Allocate the handle
	//
	handle = (scap_t*)malloc(sizeof(scap_t));
	if(!handle)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the scap_t structure");
		*rc = SCAP_FAILURE;
		return NULL;
	}

	//
	// Preliminary initializations
	//
	memset(handle, 0, sizeof(scap_t));
	handle->m_mode = SCAP_MODE_NODRIVER;

	//
	// Extract machine information
	//
	handle->m_proc_callback = proc_callback;
	handle->m_proc_callback_context = proc_callback_context;
	handle->m_machine_info.num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	handle->m_machine_info.memory_size_bytes = (uint64_t)sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE);
	gethostname(handle->m_machine_info.hostname, sizeof(handle->m_machine_info.hostname) / sizeof(handle->m_machine_info.hostname[0]));
	handle->m_machine_info.reserved1 = 0;
	handle->m_machine_info.reserved2 = 0;
	handle->m_machine_info.reserved3 = 0;
	handle->m_machine_info.reserved4 = 0;
	handle->m_driver_procinfo = NULL;
	handle->m_fd_lookup_limit = SCAP_NODRIVER_MAX_FD_LOOKUP; // fd lookup is limited here because is very expensive

	//
	// If this is part of the windows agent, open the windows HAL
	//
#ifdef CYGWING_AGENT
	handle->m_whh = wh_open(error);
	if(handle->m_whh == NULL)
	{
		scap_close(handle);
		*rc = SCAP_FAILURE;
		return NULL;
	}
#endif

	//
	// Create the interface list
	//
	if((*rc = scap_create_iflist(handle)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "error creating the interface list");
		return NULL;
	}

	//
	// Create the user list
	//
	if(import_users)
	{
		if((*rc = scap_create_userlist(handle)) != SCAP_SUCCESS)
		{
			scap_close(handle);
			snprintf(error, SCAP_LASTERR_SIZE, "error creating the interface list");
			return NULL;
		}
	}
	else
	{
		handle->m_userlist = NULL;
	}

	handle->m_fake_kernel_proc.tid = -1;
	handle->m_fake_kernel_proc.pid = -1;
	handle->m_fake_kernel_proc.flags = 0;
	snprintf(handle->m_fake_kernel_proc.comm, SCAP_MAX_PATH_SIZE, "kernel");
	snprintf(handle->m_fake_kernel_proc.exe, SCAP_MAX_PATH_SIZE, "kernel");
	handle->m_fake_kernel_proc.args[0] = 0;
	handle->refresh_proc_table_when_saving = true;

	//
	// Create the process list
	//
	error[0] = '\0';
	snprintf(filename, sizeof(filename), "%s/proc", scap_get_host_root());
	if((*rc = scap_proc_scan_proc_dir(handle, filename, -1, -1, NULL, error, true)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "error creating the process list. Make sure you have root credentials.");
		return NULL;
	}

	return handle;
#endif // HAS_CAPTURE
}

scap_t* scap_open(scap_open_args args, char *error, int32_t *rc)
{
	switch(args.mode)
	{
	case SCAP_MODE_CAPTURE:
	{
		gzFile gzfile;

		if(args.fd != 0)
		{
			gzfile = gzdopen(args.fd, "rb");
		}
		else
		{
			gzfile = gzopen(args.fname, "rb");
		}

		if(gzfile == NULL)
		{
			if(args.fd != 0)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "can't open fd %d", args.fd);
			}
			else
			{
				snprintf(error, SCAP_LASTERR_SIZE, "can't open file %s", args.fname);
			}
			*rc = SCAP_FAILURE;
			return NULL;
		}

		return scap_open_offline_int(gzfile, error, rc,
					     args.proc_callback, args.proc_callback_context,
					     args.import_users, args.start_offset,
					     args.suppressed_comms);
	}
	case SCAP_MODE_LIVE:
#ifndef CYGWING_AGENT
		return scap_open_live_int(error, rc, args.proc_callback,
					  args.proc_callback_context,
					  args.import_users,
					  args.bpf_probe,
					  args.suppressed_comms);
#else
		snprintf(error,	SCAP_LASTERR_SIZE, "scap_open: live mode currently not supported on windows. Use nodriver mode instead.");
		*rc = SCAP_NOT_SUPPORTED;
		return NULL;
#endif
	case SCAP_MODE_NODRIVER:
		return scap_open_nodriver_int(error, rc, args.proc_callback,
					      args.proc_callback_context,
					      args.import_users);
	default:
		snprintf(error, SCAP_LASTERR_SIZE, "incorrect mode %d", args.mode);
		*rc = SCAP_FAILURE;
		return NULL;
	}
}

void scap_close(scap_t* handle)
{
	if(handle->m_file)
	{
		gzclose(handle->m_file);
	}
	else if(handle->m_mode == SCAP_MODE_LIVE)
	{
#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT)
		uint32_t j;

		ASSERT(handle->m_file == NULL);

		if(handle->m_devs != NULL)
		{
			if(handle->m_bpf)
			{
				if(scap_bpf_close(handle) != SCAP_SUCCESS)
				{
					ASSERT(false);
				}
			}
			else
			{
				//
				// Destroy all the device descriptors
				//
				for(j = 0; j < handle->m_ndevs; j++)
				{
					if(handle->m_devs[j].m_buffer != MAP_FAILED)
					{
						munmap(handle->m_devs[j].m_bufinfo, sizeof(struct ppm_ring_buffer_info));
						munmap(handle->m_devs[j].m_buffer, RING_BUF_SIZE * 2);
						close(handle->m_devs[j].m_fd);
					}
				}
			}

			//
			// Free the memory
			//
			free(handle->m_devs);
		}
#endif // HAS_CAPTURE
	}

#ifdef CYGWING_AGENT
	if(handle->m_whh != NULL)
	{
		wh_close(handle->m_whh);
	}
#endif

	if(handle->m_file_evt_buf)
	{
		free(handle->m_file_evt_buf);
	}

	// Free the process table
	if(handle->m_proclist != NULL)
	{
		scap_proc_free_table(handle);
	}

	// Free the interface list
	if(handle->m_addrlist)
	{
		scap_free_iflist(handle->m_addrlist);
	}

	// Free the user list
	if(handle->m_userlist)
	{
		scap_free_userlist(handle->m_userlist);
	}

	if(handle->m_driver_procinfo)
	{
		free(handle->m_driver_procinfo);
		handle->m_driver_procinfo = NULL;
	}

	if(handle->m_suppressed_comms)
	{
		uint32_t i;
		for(i=0; i < handle->m_num_suppressed_comms; i++)
		{
			free(handle->m_suppressed_comms[i]);
		}
		free(handle->m_suppressed_comms);
		handle->m_suppressed_comms = NULL;
	}

	if(handle->m_suppressed_tids)
	{
		struct scap_tid *tid;
		struct scap_tid *ttid;
		HASH_ITER(hh, handle->m_suppressed_tids, tid, ttid)
		{
			HASH_DEL(handle->m_suppressed_tids, tid);
			free(tid);
		}

		handle->m_suppressed_tids = NULL;
	}

	//
	// Release the handle
	//
	free(handle);
}

scap_os_platform scap_get_os_platform(scap_t* handle)
{
#if defined(_M_IX86) || defined(__i386__)
#ifdef linux
	return SCAP_PFORM_LINUX_I386;
#else
	return SCAP_PFORM_WINDOWS_I386;
#endif // linux
#else
#if defined(_M_X64) || defined(__AMD64__)
#ifdef linux
	return SCAP_PFORM_LINUX_X64;
#else
	return SCAP_PFORM_WINDOWS_X64;
#endif // linux
#else
	return SCAP_PFORM_UNKNOWN;
#endif // defined(_M_X64) || defined(__AMD64__)
#endif // defined(_M_IX86) || defined(__i386__)
}

uint32_t scap_get_ndevs(scap_t* handle)
{
	return handle->m_ndevs;
}

#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT)

#ifndef _WIN32
static inline void get_buf_pointers(struct ppm_ring_buffer_info* bufinfo, uint32_t* phead, uint32_t* ptail, uint64_t* pread_size)
#else
void get_buf_pointers(struct ppm_ring_buffer_info* bufinfo, uint32_t* phead, uint32_t* ptail, uint64_t* pread_size)
#endif
{
	*phead = bufinfo->head;
	*ptail = bufinfo->tail;

	if(*ptail > *phead)
	{
		*pread_size = RING_BUF_SIZE - *ptail + *phead;
	}
	else
	{
		*pread_size = *phead - *ptail;
	}
}

int32_t scap_readbuf(scap_t* handle, uint32_t cpuid, OUT char** buf, OUT uint32_t* len)
{
	if(handle->m_bpf)
	{
		return scap_bpf_readbuf(handle, cpuid, buf, len);
	}

	uint32_t thead;
	uint32_t ttail;
	uint64_t read_size;

	//
	// Update the tail based on the amount of data read in the *previous* call.
	// Tail is never updated when we serve the data, because we assume that the caller is using
	// the buffer we give to her until she calls us again.
	//
	ttail = handle->m_devs[cpuid].m_bufinfo->tail + handle->m_devs[cpuid].m_lastreadsize;

	//
	// Make sure every read of the old buffer is completed before we move the tail and the
	// producer (on another CPU) can start overwriting it.
	// I use this instead of asm(mfence) because it should be portable even on the weirdest
	// CPUs
	//
	__sync_synchronize();

	if(ttail < RING_BUF_SIZE)
	{
		handle->m_devs[cpuid].m_bufinfo->tail = ttail;
	}
	else
	{
		handle->m_devs[cpuid].m_bufinfo->tail = ttail - RING_BUF_SIZE;
	}

	//
	// Read the pointers.
	//
	get_buf_pointers(handle->m_devs[cpuid].m_bufinfo,
	                 &thead,
	                 &ttail,
	                 &read_size);

	//
	// Remember read_size so we can update the tail at the next call
	//
	handle->m_devs[cpuid].m_lastreadsize = read_size;

	//
	// Return the results
	//
	*len = read_size;
	*buf = handle->m_devs[cpuid].m_buffer + ttail;

	return SCAP_SUCCESS;
}

bool check_scap_next_wait(scap_t* handle)
{
	uint32_t j;
	bool res = true;

	for(j = 0; j < handle->m_ndevs; j++)
	{
		uint64_t read_size;

		if(handle->m_bpf)
		{
			uint64_t thead;
			uint64_t ttail;

			scap_bpf_get_buf_pointers(handle->m_devs[j].m_buffer, &thead, &ttail, &read_size);

		}
		else
		{
			uint32_t thead;
			uint32_t ttail;

			get_buf_pointers(handle->m_devs[j].m_bufinfo, &thead, &ttail, &read_size);
		}

		if(read_size > 20000)
		{
			handle->m_n_consecutive_waits = 0;
			res = false;
		}
	}

	if(res == false)
	{
		return false;
	}

	if(handle->m_n_consecutive_waits >= MAX_N_CONSECUTIVE_WAITS)
	{
		handle->m_n_consecutive_waits = 0;
		return false;
	}
	else
	{
		return true;
	}
}

int32_t refill_read_buffers(scap_t* handle)
{
	uint32_t j;
	uint32_t ndevs = handle->m_ndevs;

	if(check_scap_next_wait(handle))
	{
		usleep(BUFFER_EMPTY_WAIT_TIME_MS * 1000);
		handle->m_n_consecutive_waits++;
	}

	//
	// Refill our data for each of the devices
	//
	for(j = 0; j < ndevs; j++)
	{
		struct scap_device *dev = &(handle->m_devs[j]);

		int32_t res = scap_readbuf(handle,
		                           j,
		                           &dev->m_sn_next_event,
		                           &dev->m_sn_len);

		if(res != SCAP_SUCCESS)
		{
			return res;
		}
	}

	//
	// Note: we might return a spurious timeout here in case the previous loop extracted valid data to parse.
	//       It's ok, since this is rare and the caller will just call us again after receiving a
	//       SCAP_TIMEOUT.
	//
	return SCAP_TIMEOUT;
}

#endif // HAS_CAPTURE

#ifndef _WIN32
static inline int32_t scap_next_live(scap_t* handle, OUT scap_evt** pevent, OUT uint16_t* pcpuid)
#else
static int32_t scap_next_live(scap_t* handle, OUT scap_evt** pevent, OUT uint16_t* pcpuid)
#endif
{
#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
	//
	// this should be prevented at open time
	//
	ASSERT(false);
	return SCAP_FAILURE;
#else
	uint32_t j;
	uint64_t max_ts = 0xffffffffffffffffLL;
	scap_evt* pe = NULL;
	uint32_t ndevs = handle->m_ndevs;

	*pcpuid = 65535;

	for(j = 0; j < ndevs; j++)
	{
		scap_device* dev = &(handle->m_devs[j]);

		//
		// Make sure that we have data from this ring
		//
		if(dev->m_sn_len != 0)
		{
			//
			// We want to consume the event with the lowest timestamp
			//
			if(handle->m_bpf)
			{
				pe = scap_bpf_evt_from_perf_sample(dev->m_sn_next_event);
			}
			else
			{
				pe = (scap_evt *) dev->m_sn_next_event;
			}

			if(pe->ts < max_ts)
			{
				if(pe->len > dev->m_sn_len)
				{
					snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_next buffer corruption");

					//
					// if you get the following assertion, first recompile the driver and libscap
					//
					ASSERT(false);
					return SCAP_FAILURE;
				}

				*pevent = pe;
				*pcpuid = j;
				max_ts = pe->ts;
			}
		}
	}

	//
	// Check which buffer has been picked
	//
	if(*pcpuid != 65535)
	{
		struct scap_device *dev = &handle->m_devs[*pcpuid];

		//
		// Update the pointers.
		//
		if(handle->m_bpf)
		{
			scap_bpf_advance_to_evt(handle, *pcpuid, true,
						dev->m_sn_next_event,
						&dev->m_sn_next_event,
						&dev->m_sn_len);
		}
		else
		{
			ASSERT(dev->m_sn_len >= (*pevent)->len);
			dev->m_sn_len -= (*pevent)->len;
			dev->m_sn_next_event += (*pevent)->len;
		}

		return SCAP_SUCCESS;
	}
	else
	{
		//
		// All the buffers have been consumed. Check if there's enough data to keep going or
		// if we should wait.
		//
		return refill_read_buffers(handle);
	}
#endif
}

#ifndef _WIN32
static int32_t scap_next_nodriver(scap_t* handle, OUT scap_evt** pevent, OUT uint16_t* pcpuid)
{
	static scap_evt evt;
	evt.len = 0;
	evt.tid = -1;
	evt.type = PPME_SYSDIGEVENT_X;
	evt.nparams = 0;

	usleep(100000);

	struct timeval tv;
	gettimeofday(&tv, NULL);

	evt.ts = tv.tv_sec * (uint64_t) 1000000000 + tv.tv_usec * 1000;
	*pevent = &evt;
	return SCAP_SUCCESS;
}
#endif // _WIN32

int32_t scap_next(scap_t* handle, OUT scap_evt** pevent, OUT uint16_t* pcpuid)
{
	int32_t res;

	switch(handle->m_mode)
	{
	case SCAP_MODE_CAPTURE:
		res = scap_next_offline(handle, pevent, pcpuid);
		break;
	case SCAP_MODE_LIVE:
		res = scap_next_live(handle, pevent, pcpuid);
		break;
#ifndef _WIN32
	case SCAP_MODE_NODRIVER:
		res = scap_next_nodriver(handle, pevent, pcpuid);
		break;
#endif
	default:
		res = SCAP_FAILURE;
	}

	if(res == SCAP_SUCCESS)
	{
		bool suppressed;

		// Check to see if the event should be suppressed due
		// to coming from a supressed tid
		if((res = scap_check_suppressed(handle, *pevent, &suppressed)) != SCAP_SUCCESS)
		{
			return res;
		}

		if(suppressed)
		{
			handle->m_num_suppressed_evts++;
			return SCAP_TIMEOUT;
		}
		else
		{
			handle->m_evtcnt++;
		}
	}

	return res;
}

//
// Return the process list for the given handle
//
scap_threadinfo* scap_get_proc_table(scap_t* handle)
{
	return handle->m_proclist;
}

//
// Return the number of dropped events for the given handle
//
int32_t scap_get_stats(scap_t* handle, OUT scap_stats* stats)
{
	uint32_t j;

	stats->n_evts = 0;
	stats->n_drops = 0;
	stats->n_drops_buffer = 0;
	stats->n_drops_pf = 0;
	stats->n_drops_bug = 0;
	stats->n_preemptions = 0;
	stats->n_suppressed = handle->m_num_suppressed_evts;
	stats->n_tids_suppressed = HASH_COUNT(handle->m_suppressed_tids);

#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT)
	if(handle->m_bpf)
	{
		return scap_bpf_get_stats(handle, stats);
	}
	else
	{
		for(j = 0; j < handle->m_ndevs; j++)
		{
			stats->n_evts += handle->m_devs[j].m_bufinfo->n_evts;
			stats->n_drops_buffer += handle->m_devs[j].m_bufinfo->n_drops_buffer;
			stats->n_drops_pf += handle->m_devs[j].m_bufinfo->n_drops_pf;
			stats->n_drops += handle->m_devs[j].m_bufinfo->n_drops_buffer +
						handle->m_devs[j].m_bufinfo->n_drops_pf;
			stats->n_preemptions += handle->m_devs[j].m_bufinfo->n_preemptions;
		}
	}
#endif

	return SCAP_SUCCESS;
}

//
// Stop capturing the events
//
int32_t scap_stop_capture(scap_t* handle)
{
#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	uint32_t j;

	//
	// Not supported for files
	//
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "cannot stop not live captures");
		ASSERT(false);
		return SCAP_FAILURE;
	}

	//
	// Disable capture on all the rings
	//
	for(j = 0; j < handle->m_ndevs; j++)
	{
		if(handle->m_bpf)
		{
			return scap_bpf_stop_capture(handle);
		}
		else
		{
			if(ioctl(handle->m_devs[j].m_fd, PPM_IOCTL_DISABLE_CAPTURE))
			{
				snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "scap_stop_capture failed for device %" PRIu32, j);
				ASSERT(false);
				return SCAP_FAILURE;
			}
		}
	}

	return SCAP_SUCCESS;
#endif // HAS_CAPTURE
}

//
// Start capturing the events
//
int32_t scap_start_capture(scap_t* handle)
{
#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	uint32_t j;

	//
	// Not supported for files
	//
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "cannot start capture on this scap mode");
		ASSERT(false);
		return SCAP_FAILURE;
	}

	//
	// Enable capture on all the rings
	//
	if(handle->m_bpf)
	{
		return scap_bpf_start_capture(handle);
	}
	else
	{
		for(j = 0; j < handle->m_ndevs; j++)
		{
			if(ioctl(handle->m_devs[j].m_fd, PPM_IOCTL_ENABLE_CAPTURE))
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_start_capture failed for device %" PRIu32, j);
				ASSERT(false);
				return SCAP_FAILURE;
			}
		}
	}

	return SCAP_SUCCESS;
#endif // HAS_CAPTURE
}

#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT)
static int32_t scap_set_dropping_mode(scap_t* handle, int request, uint32_t sampling_ratio)
{
	//
	// Not supported for files
	//
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "%s: dropping not supported in replay mode", __FUNCTION__);
		ASSERT(false);
		return SCAP_FAILURE;
	}

	if(handle->m_ndevs)
	{
		ASSERT((request == PPM_IOCTL_ENABLE_DROPPING_MODE &&
			((sampling_ratio == 1)  ||
				(sampling_ratio == 2)  ||
				(sampling_ratio == 4)  ||
				(sampling_ratio == 8)  ||
				(sampling_ratio == 16) ||
				(sampling_ratio == 32) ||
				(sampling_ratio == 64) ||
				(sampling_ratio == 128))) || (request == PPM_IOCTL_DISABLE_DROPPING_MODE));

		if(ioctl(handle->m_devs[0].m_fd, request, sampling_ratio))
		{
			snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "%s, request %d for sampling ratio %u: %s",
					__FUNCTION__, request, sampling_ratio, strerror(errno));
			ASSERT(false);
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
}
#endif

#if defined(HAS_CAPTURE) && ! defined(CYGWING_AGENT)
int32_t scap_enable_tracers_capture(scap_t* handle)
{
	//
	// Not supported for files
	//
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_enable_tracers_capture not supported on this scap mode");
		ASSERT(false);
		return SCAP_FAILURE;
	}

	if(handle->m_ndevs)
	{
		if(handle->m_bpf)
		{
			return scap_bpf_enable_tracers_capture(handle);
		}
		else
		{
			if(ioctl(handle->m_devs[0].m_fd, PPM_IOCTL_SET_TRACERS_CAPTURE))
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "%s failed", __FUNCTION__);
				ASSERT(false);
				return SCAP_FAILURE;
			}
		}
	}

	return SCAP_SUCCESS;
}
#endif

#if defined(HAS_CAPTURE) && ! defined(CYGWING_AGENT)
int32_t scap_enable_page_faults(scap_t *handle)
{
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_enable_page_faults not supported on this scap mode");
		ASSERT(false);
		return SCAP_FAILURE;
	}

	if(handle->m_ndevs)
	{
		if(handle->m_bpf)
		{
			return scap_bpf_enable_page_faults(handle);
		}
		else
		{
			if(ioctl(handle->m_devs[0].m_fd, PPM_IOCTL_ENABLE_PAGE_FAULTS))
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "%s failed", __FUNCTION__);
				ASSERT(false);
				return SCAP_FAILURE;
			}
		}
	}

	return SCAP_SUCCESS;
}
#endif

int32_t scap_stop_dropping_mode(scap_t* handle)
{
#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	if(handle->m_bpf)
	{
		return scap_bpf_stop_dropping_mode(handle);
	}
	else
	{
		return scap_set_dropping_mode(handle, PPM_IOCTL_DISABLE_DROPPING_MODE, 0);
	}
#endif
}

int32_t scap_start_dropping_mode(scap_t* handle, uint32_t sampling_ratio)
{
#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	if(handle->m_bpf)
	{
		return scap_bpf_start_dropping_mode(handle, sampling_ratio);
	}
	else
	{
		return scap_set_dropping_mode(handle, PPM_IOCTL_ENABLE_DROPPING_MODE, sampling_ratio);
	}
#endif
}

//
// Return the list of device addresses
//
scap_addrlist* scap_get_ifaddr_list(scap_t* handle)
{
	return handle->m_addrlist;
}

//
// Return the list of machine users
//
scap_userlist* scap_get_user_list(scap_t* handle)
{
	return handle->m_userlist;
}

//
// Get the machine information
//
const scap_machine_info* scap_get_machine_info(scap_t* handle)
{
	if(handle->m_machine_info.num_cpus != (uint32_t)-1)
	{
		return (const scap_machine_info*)&handle->m_machine_info;
	}
	else
	{
		//
		// Reading from a file with no process info block
		//
		return NULL;
	}
}

int32_t scap_set_snaplen(scap_t* handle, uint32_t snaplen)
{
	//
	// Not supported on files
	//
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "setting snaplen not supported on this scap mode");
		return SCAP_FAILURE;
	}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else

	if(handle->m_bpf)
	{
		return scap_bpf_set_snaplen(handle, snaplen);
	}
	else
	{
		//
		// Tell the driver to change the snaplen
		//
		if(ioctl(handle->m_devs[0].m_fd, PPM_IOCTL_SET_SNAPLEN, snaplen))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_set_snaplen failed");
			ASSERT(false);
			return SCAP_FAILURE;
		}

		{
			uint32_t j;

			//
			// Force a flush of the read buffers, so we don't capture events with the old snaplen
			//
			for(j = 0; j < handle->m_ndevs; j++)
			{
				scap_readbuf(handle,
							j,
							&handle->m_devs[j].m_sn_next_event,
							&handle->m_devs[j].m_sn_len);

				handle->m_devs[j].m_sn_len = 0;
			}
		}
	}

	return SCAP_SUCCESS;
#endif
}

int64_t scap_get_readfile_offset(scap_t* handle)
{
	if(handle->m_mode != SCAP_MODE_CAPTURE)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "scap_get_readfile_offset only works on captures");
		return -1;
	}

	return gzoffset(handle->m_file);
}

#ifndef CYGWING_AGENT
static int32_t scap_handle_eventmask(scap_t* handle, uint32_t op, uint32_t event_id)
{
	//
	// Not supported on files
	//
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "manipulating eventmasks not supported on this scap mode");
		return SCAP_FAILURE;
	}

#if !defined(HAS_CAPTURE)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "eventmask not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	//
	// Tell the driver to change the snaplen
	//

	switch(op) {
	case PPM_IOCTL_MASK_ZERO_EVENTS:
	case PPM_IOCTL_MASK_SET_EVENT:
	case PPM_IOCTL_MASK_UNSET_EVENT:
		break;

	default:
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "%s(%d) internal error", __FUNCTION__, op);
		ASSERT(false);
		return SCAP_FAILURE;
		break;
	}

	if(handle->m_bpf)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "eventmask not supported on bpf");
		ASSERT(false);
		return SCAP_FAILURE;
	}
	else
	{
		if(ioctl(handle->m_devs[0].m_fd, op, event_id))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "%s(%d) failed", __FUNCTION__, op);
			ASSERT(false);
			return SCAP_FAILURE;
		}

		{
			uint32_t j;

			//
			// Force a flush of the read buffers, so we don't capture events with the old snaplen
			//
			for(j = 0; j < handle->m_ndevs; j++)
			{
				scap_readbuf(handle,
					j,
					&handle->m_devs[j].m_sn_next_event,
					&handle->m_devs[j].m_sn_len);

				handle->m_devs[j].m_sn_len = 0;
			}
		}
	}

	return SCAP_SUCCESS;
#endif // HAS_CAPTURE
}
#endif // CYGWING_AGENT

int32_t scap_clear_eventmask(scap_t* handle) {
#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "eventmask not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	return(scap_handle_eventmask(handle, PPM_IOCTL_MASK_ZERO_EVENTS, 0));
#endif
}

int32_t scap_set_eventmask(scap_t* handle, uint32_t event_id) {
#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "eventmask not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	return(scap_handle_eventmask(handle, PPM_IOCTL_MASK_SET_EVENT, event_id));
#endif
}

int32_t scap_unset_eventmask(scap_t* handle, uint32_t event_id) {
#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "eventmask not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	return(scap_handle_eventmask(handle, PPM_IOCTL_MASK_UNSET_EVENT, event_id));
#endif
}

uint32_t scap_event_get_dump_flags(scap_t* handle)
{
	return handle->m_last_evt_dump_flags;
}

int32_t scap_enable_dynamic_snaplen(scap_t* handle)
{
	//
	// Not supported on files
	//
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "setting snaplen not supported on this scap mode");
		return SCAP_FAILURE;
	}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else

	//
	// Tell the driver to change the snaplen
	//
	if(handle->m_bpf)
	{
		return scap_bpf_enable_dynamic_snaplen(handle);
	}
	else
	{
		if(ioctl(handle->m_devs[0].m_fd, PPM_IOCTL_ENABLE_DYNAMIC_SNAPLEN))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_enable_dynamic_snaplen failed");
			ASSERT(false);
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
#endif
}

int32_t scap_disable_dynamic_snaplen(scap_t* handle)
{
	//
	// Not supported on files
	//
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "setting snaplen not supported on this scap mode");
		return SCAP_FAILURE;
	}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else

	//
	// Tell the driver to change the snaplen
	//
	if(handle->m_bpf)
	{
		return scap_bpf_disable_dynamic_snaplen(handle);
	}
	else
	{
		if(ioctl(handle->m_devs[0].m_fd, PPM_IOCTL_DISABLE_DYNAMIC_SNAPLEN))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_disable_dynamic_snaplen failed");
			ASSERT(false);
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
#endif
}

const char* scap_get_host_root()
{
	char* p = getenv("SYSDIG_HOST_ROOT");
	static char env_str[SCAP_MAX_PATH_SIZE + 1];
	static bool inited = false;
	if (! inited) {
		strncpy(env_str, p ? p : "", SCAP_MAX_PATH_SIZE);
		env_str[SCAP_MAX_PATH_SIZE] = '\0';
		inited = true;
	}

	return env_str;
}

bool scap_alloc_proclist_info(scap_t* handle, uint32_t n_entries)
{
	uint32_t memsize;

	if(n_entries >= SCAP_DRIVER_PROCINFO_MAX_SIZE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "driver process list too big");
		return false;
	}

	memsize = sizeof(struct ppm_proclist_info) +
		sizeof(struct ppm_proc_info) * n_entries;

	struct ppm_proclist_info *procinfo = (struct ppm_proclist_info*) realloc(handle->m_driver_procinfo, memsize);
	if(procinfo == NULL)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "driver process list allocation error");
		return false;
	}

	if(handle->m_driver_procinfo == NULL)
	{
		procinfo->n_entries = 0;
	}

	procinfo->max_entries = n_entries;
	handle->m_driver_procinfo = procinfo;

	return true;
}

struct ppm_proclist_info* scap_get_threadlist(scap_t* handle)
{
	//
	// Not supported on files
	//
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_get_threadlist not supported on this scap mode");
		return NULL;
	}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return NULL;
#else
	if(handle->m_driver_procinfo == NULL)
	{
		if(scap_alloc_proclist_info(handle, SCAP_DRIVER_PROCINFO_INITIAL_SIZE) == false)
		{
			return NULL;
		}
	}

	if(handle->m_bpf)
	{
		return scap_bpf_get_threadlist(handle);
	}
	else
	{
		int ioctlres = ioctl(handle->m_devs[0].m_fd, PPM_IOCTL_GET_PROCLIST, handle->m_driver_procinfo);
		if(ioctlres)
		{
			if(errno == ENOSPC)
			{
				if(scap_alloc_proclist_info(handle, handle->m_driver_procinfo->n_entries + 256) == false)
				{
					return NULL;
				}
				else
				{
					return scap_get_threadlist(handle);
				}
			}
			else
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Error calling PPM_IOCTL_GET_PROCLIST");
				return NULL;
			}
		}
	}

	return handle->m_driver_procinfo;
#endif	// HAS_CAPTURE
}

void scap_set_refresh_proc_table_when_saving(scap_t* handle, bool refresh)
{
	handle->refresh_proc_table_when_saving = refresh;
}

uint64_t scap_get_unexpected_block_readsize(scap_t* handle)
{
	return handle->m_unexpected_block_readsize;
}

int32_t scap_enable_simpledriver_mode(scap_t* handle)
{
	//
	// Not supported on files
	//
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "setting simpledriver mode not supported on this scap mode");
		return SCAP_FAILURE;
	}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else

	//
	// Tell the driver to change the snaplen
	//
	if(handle->m_bpf)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "setting simpledriver mode not supported on bpf");
		ASSERT(false);
		return SCAP_FAILURE;
	}
	else
	{
		if(ioctl(handle->m_devs[0].m_fd, PPM_IOCTL_SET_SIMPLE_MODE))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_enable_simpledriver_mode failed");
			ASSERT(false);
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
#endif
}

int32_t scap_get_n_tracepoint_hit(scap_t* handle, long* ret)
{
	int ioctl_ret = 0;

	//
	// Not supported on files
	//
	if(handle->m_mode != SCAP_MODE_LIVE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "getting n_tracepoint_hit not supported on this scap mode");
		return SCAP_FAILURE;
	}

#if !defined(HAS_CAPTURE) || defined(CYGWING_AGENT)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else

	if(handle->m_bpf)
	{
		return scap_bpf_get_n_tracepoint_hit(handle, ret);
	}
	else
	{
		ioctl_ret = ioctl(handle->m_devs[0].m_fd, PPM_IOCTL_GET_N_TRACEPOINT_HIT, ret);
		if(ioctl_ret != 0)
		{
			if(errno == ENOTTY)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_get_n_tracepoint_hit failed, ioctl not supported");
			}
			else
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "scap_get_n_tracepoint_hit failed (%s)", strerror(errno));
			}

			ASSERT(false);
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
#endif
}

#ifdef CYGWING_AGENT
wh_t* scap_get_wmi_handle(scap_t* handle)
{
	return handle->m_whh;
}
#endif

const char *scap_get_bpf_probe_from_env()
{
	return getenv(SYSDIG_BPF_PROBE_ENV);
}

int32_t scap_suppress_events_comm(scap_t *handle, const char *comm)
{
	// If the comm is already present in the list, do nothing
	uint32_t i;
	for(i=0; i<handle->m_num_suppressed_comms; i++)
	{
		if(strcmp(handle->m_suppressed_comms[i], comm) == 0)
		{
			return SCAP_SUCCESS;
		}
	}

	if(handle->m_num_suppressed_comms >= SCAP_MAX_SUPPRESSED_COMMS)
	{
		return SCAP_FAILURE;
	}

	handle->m_num_suppressed_comms++;
	handle->m_suppressed_comms = (char **) realloc(handle->m_suppressed_comms,
						       handle->m_num_suppressed_comms * sizeof(char *));

	handle->m_suppressed_comms[handle->m_num_suppressed_comms-1] = strdup(comm);

	return SCAP_SUCCESS;
}

bool scap_check_suppressed_tid(scap_t *handle, int64_t tid)
{
	scap_tid *stid;
	HASH_FIND_INT64(handle->m_suppressed_tids, &tid, stid);

	return (stid != NULL);
}
