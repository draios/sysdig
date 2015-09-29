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
#endif // _WIN32

#include "scap.h"
#include "../../driver/ppm_ringbuffer.h"
#include "scap_savefile.h"
#include "scap-int.h"

//#define NDEBUG
#include <assert.h>

static uint32_t get_max_consumers()
{
	uint32_t max;
	FILE *pfile = fopen("/sys/module/sysdig_probe/parameters/max_consumers", "r");
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

char* scap_getlasterr(scap_t* handle)
{
	return handle->m_lasterr;
}

scap_t* scap_open_live_int(char *error, 
						   proc_entry_callback proc_callback,
						   void* proc_callback_context,
						   bool import_users)
{
#if !defined(HAS_CAPTURE)
	snprintf(error, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return NULL;
#else
	uint32_t j;
	char filename[SCAP_MAX_PATH_SIZE];
	scap_t* handle = NULL;
	int len;
	uint32_t ndevs;
	uint32_t res;
	uint32_t max_devs;
	uint32_t all_scanned_devs;

	//
	// Allocate the handle
	//
	handle = (scap_t*)malloc(sizeof(scap_t));
	if(!handle)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the scap_t structure");
		return NULL;
	}

	//
	// Preliminary initializations
	//
	memset(handle, 0, sizeof(scap_t));

	//
	// Find out how many devices we have to open, which equals to the number of CPUs
	//
	ndevs = sysconf(_SC_NPROCESSORS_ONLN);
	max_devs = sysconf(_SC_NPROCESSORS_CONF);	

	//
	// Allocate the device descriptors.
	//
	len = RING_BUF_SIZE * 2;

	handle->m_devs = (scap_device*)malloc(ndevs * sizeof(scap_device));
	if(!handle->m_devs)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the device handles");
		return NULL;
	}

	for(j = 0; j < ndevs; j++)
	{
		handle->m_devs[j].m_buffer = (char*)MAP_FAILED;
		handle->m_devs[j].m_bufinfo = (struct ppm_ring_buffer_info*)MAP_FAILED;
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

	//
	// Create the interface list
	//
	if(scap_create_iflist(handle) != SCAP_SUCCESS)
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
		if(scap_create_userlist(handle) != SCAP_SUCCESS)
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

	//
	// Open and initialize all the devices
	//
	for(j = 0, all_scanned_devs = 0; j < handle->m_ndevs && all_scanned_devs < max_devs; all_scanned_devs++)
	{
		//
		// Open the device
		//
		sprintf(filename, "%s/dev/sysdig%d", scap_get_host_root(), all_scanned_devs);

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
				snprintf(error, SCAP_LASTERR_SIZE, "Too many sysdig instances attached to device %s. Current value for /sys/module/sysdig_probe/parameters/max_consumers is '%"PRIu32"'.", filename, curr_max_consumers);
			}
			else
			{
				snprintf(error, SCAP_LASTERR_SIZE, "error opening device %s. Make sure you have root credentials and that the sysdig-probe module is loaded.", filename);
			}

			scap_close(handle);
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
			return NULL;
		}

		//
		// Additional initializations
		//
		scap_dev_init(handle->m_devs + j);
		scap_stop_dropping_mode(handle);
		j++;
	}
	scap_handle_late_init(handle);

	//
	// Create the process list
	//
	error[0] = '\0';
	snprintf(filename, sizeof(filename), "%s/proc", scap_get_host_root());
	if((res = scap_proc_scan_proc_dir(handle, filename, -1, -1, NULL, error, true)) != SCAP_SUCCESS)
	{
		scap_close(handle);
		snprintf(error, SCAP_LASTERR_SIZE, "error creating the process list. Make sure you have root credentials.");
		return NULL;
	}

	//
	// Now that sysdig has done all its /proc parsing, start the capture
	//
	scap_start_capture(handle);

	return handle;
#endif // HAS_CAPTURE
}

scap_t* scap_open_offline_int(const char* fname, 
							  char *error,
							  proc_entry_callback proc_callback, 
							  void* proc_callback_context,
							  bool import_users)
{
	scap_t* handle = NULL;

	//
	// Allocate the handle
	//
	handle = (scap_t*)malloc(sizeof(scap_t));
	if(!handle)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the scap_t structure");
		return NULL;
	}

	//
	// Preliminary initializations
	//
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

	handle->m_file_evt_buf = (char*)malloc(FILE_READ_BUF_SIZE);
	if(!handle->m_file_evt_buf)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "error allocating the read buffer");
		scap_close(handle);
		return NULL;
	}

	//
	// Open the file
	//
	handle->m_file = gzopen(fname, "rb");
	if(handle->m_file == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't open file %s", fname);
		scap_close(handle);
		return NULL;
	}

	//
	// Validate the file and load the non-event blocks
	//
	if(scap_read_init(handle, handle->m_file) != SCAP_SUCCESS)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "%s", scap_getlasterr(handle));
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

	return handle;
}

scap_t* scap_open_offline(const char* fname, char *error)
{
	return scap_open_offline_int(fname, error, NULL, NULL, true);
}

scap_t* scap_open_live(char *error)
{
	return scap_open_live_int(error, NULL, NULL, true);
}

scap_t* scap_open(scap_open_args args, char *error)
{
	if(args.fname != NULL)
	{
		return scap_open_offline_int(args.fname, error, 
			args.proc_callback, args.proc_callback_context,
			args.import_users);
	}
	else
	{
		return scap_open_live_int(error, args.proc_callback, 
			args.proc_callback_context,
			args.import_users);
	}
}

void scap_close(scap_t* handle)
{
#ifdef HAVE_EXTERNAL_SCAP_READER
	scap_external_close(handle);
#endif
	if(handle->m_file)
	{
		gzclose(handle->m_file);
	}
	else
	{
#if defined(HAS_CAPTURE)
		uint32_t j;

		ASSERT(handle->m_file == NULL);

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

		//
		// Free the memory
		//
		if(handle->m_devs != NULL)
		{
			free(handle->m_devs);
		}
#endif // HAS_CAPTURE
	}

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

#ifndef HAVE_EXTERNAL_SCAP_READER
#include "scap_next.h"
int32_t scap_next(scap_t* handle, OUT scap_evt** pevent, OUT uint16_t* pcpuid)
{
	return scap_next_main(handle, pevent, pcpuid);
}
#endif



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
	stats->n_preemptions = 0;

	for(j = 0; j < handle->m_ndevs; j++)
	{
		stats->n_evts += handle->m_devs[j].m_bufinfo->n_evts;
		stats->n_drops += handle->m_devs[j].m_bufinfo->n_drops_buffer + 
			handle->m_devs[j].m_bufinfo->n_drops_pf;
		stats->n_preemptions += handle->m_devs[j].m_bufinfo->n_preemptions;
	}

	return SCAP_SUCCESS;
}

//
// Stop capturing the events
//
int32_t scap_stop_capture(scap_t* handle)
{
#if !defined(HAS_CAPTURE)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	uint32_t j;

	//
	// Not supported for files
	//
	if(handle->m_file)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "cannot stop offline captures");
		ASSERT(false);
		return SCAP_FAILURE;
	}

	//
	// Disable capture on all the rings
	//
	for(j = 0; j < handle->m_ndevs; j++)
	{
		scap_stop_capture_pre(handle, j);
		if(ioctl(handle->m_devs[j].m_fd, PPM_IOCTL_DISABLE_CAPTURE))
		{
			snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "scap_stop_capture failed for device %" PRIu32, j);
			ASSERT(false);
			return SCAP_FAILURE;
		}
		scap_stop_capture_post(handle, j);
	}

	return SCAP_SUCCESS;
#endif // HAS_CAPTURE
}

//
// Start capturing the events
//
int32_t scap_start_capture(scap_t* handle)
{
#if !defined(HAS_CAPTURE)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	uint32_t j;

	//
	// Not supported for files
	//
	if(handle->m_file)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "cannot start offline captures");
		ASSERT(false);
		return SCAP_FAILURE;
	}

	//
	// Enable capture on all the rings
	//
	for(j = 0; j < handle->m_ndevs; j++)
	{
		if(ioctl(handle->m_devs[j].m_fd, PPM_IOCTL_ENABLE_CAPTURE))
		{
			snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "scap_start_capture failed for device %" PRIu32, j);
			ASSERT(false);
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
#endif // HAS_CAPTURE
}

#if defined(HAS_CAPTURE)
static int32_t scap_set_dropping_mode(scap_t* handle, int request, uint32_t sampling_ratio)
{
	//	
	// Not supported for files
	//
	if(handle->m_file)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "dropping mode not supported on offline captures");
		ASSERT(false);
		return SCAP_FAILURE;
	}

	if(handle->m_ndevs)
	{
		if(ioctl(handle->m_devs[0].m_fd, request, sampling_ratio))
		{
			snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "%s failed", __FUNCTION__);
			ASSERT(false);
			return SCAP_FAILURE;
		}		
	}

	return SCAP_SUCCESS;
}
#endif

int32_t scap_stop_dropping_mode(scap_t* handle)
{
#if !defined(HAS_CAPTURE)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	return scap_set_dropping_mode(handle, PPM_IOCTL_DISABLE_DROPPING_MODE, 0);
#endif
}

int32_t scap_start_dropping_mode(scap_t* handle, uint32_t sampling_ratio)
{
#if !defined(HAS_CAPTURE)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	return scap_set_dropping_mode(handle, PPM_IOCTL_ENABLE_DROPPING_MODE, sampling_ratio);
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
	if(handle->m_file)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "setting snaplen not supported on offline captures");
		return SCAP_FAILURE;
	}

#if !defined(HAS_CAPTURE)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	//
	// Tell the driver to change the snaplen
	//
	if(ioctl(handle->m_devs[0].m_fd, PPM_IOCTL_SET_SNAPLEN, snaplen))
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "scap_set_snaplen failed");
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
//			scap_readbuf(handle, j, false, &handle->m_devs[j].m_sn_next_event, &handle->m_devs[j].m_sn_len);
			scap_update_snap(handle->m_devs + j);
			handle->m_devs[j].m_sn_len = 0;
		}
	}

	return SCAP_SUCCESS;
#endif
}

int64_t scap_get_readfile_offset(scap_t* handle)
{
	if(handle->m_file == NULL)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "scap_get_readfile_offset only works on trace files");
		return -1;
	}

	return gzoffset(handle->m_file);
}

static int32_t scap_handle_eventmask(scap_t* handle, uint32_t op, uint32_t event_id)
{
	//
	// Not supported on files
	//
	if(handle->m_file)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "manipulating eventmasks not supported on offline captures");
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
//			scap_readbuf(handle, j, false, &handle->m_devs[j].m_sn_next_event, &handle->m_devs[j].m_sn_len);

			scap_update_snap(&handle->m_devs[j]);
			handle->m_devs[j].m_sn_len = 0;
		}
	}

	return SCAP_SUCCESS;
#endif
}

int32_t scap_clear_eventmask(scap_t* handle) {
#if !defined(HAS_CAPTURE)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "eventmask not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	return(scap_handle_eventmask(handle, PPM_IOCTL_MASK_ZERO_EVENTS, 0));
#endif
}

int32_t scap_set_eventmask(scap_t* handle, uint32_t event_id) {
#if !defined(HAS_CAPTURE)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "eventmask not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else
	return(scap_handle_eventmask(handle, PPM_IOCTL_MASK_SET_EVENT, event_id));
#endif
}

int32_t scap_unset_eventmask(scap_t* handle, uint32_t event_id) {
#if !defined(HAS_CAPTURE)
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
	if(handle->m_file)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "setting snaplen not supported on offline captures");
		return SCAP_FAILURE;
	}

#if !defined(HAS_CAPTURE)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else

	//
	// Tell the driver to change the snaplen
	//
	if(ioctl(handle->m_devs[0].m_fd, PPM_IOCTL_ENABLE_DYNAMIC_SNAPLEN))
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "scap_enable_dynamic_snaplen failed");
		ASSERT(false);
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
#endif
}

int32_t scap_disable_dynamic_snaplen(scap_t* handle)
{
	//
	// Not supported on files
	//
	if(handle->m_file)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "setting snaplen not supported on offline captures");
		return SCAP_FAILURE;
	}

#if !defined(HAS_CAPTURE)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return SCAP_FAILURE;
#else

	//
	// Tell the driver to change the snaplen
	//
	if(ioctl(handle->m_devs[0].m_fd, PPM_IOCTL_DISABLE_DYNAMIC_SNAPLEN))
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "scap_enable_dynamic_snaplen failed");
		ASSERT(false);
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
#endif
}

const char* scap_get_host_root()
{
	char* p = getenv("SYSDIG_HOST_ROOT");
	if(!p)
	{
		p = "";
	}

	return p;
}

bool alloc_proclist_info(scap_t* handle, uint32_t n_entries)
{
	uint32_t memsize;

	if(n_entries >= SCAP_DRIVER_PROCINFO_MAX_SIZE)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "driver process list too big");
		return false;
	}

	memsize = sizeof(struct ppm_proclist_info) + 
	sizeof(struct ppm_proc_info) * n_entries;

	if(handle->m_driver_procinfo != NULL)
	{
		free(handle->m_driver_procinfo);
	}

	handle->m_driver_procinfo = (struct ppm_proclist_info*)malloc(memsize);
	if(handle->m_driver_procinfo == NULL)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "driver process list allocation error");
		return false;
	}

	handle->m_driver_procinfo->max_entries = n_entries;
	handle->m_driver_procinfo->n_entries = 0;

	return true;
}

struct ppm_proclist_info* scap_get_threadlist_from_driver(scap_t* handle)
{
	//
	// Not supported on files
	//
	if(handle->m_file)
	{
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "scap_get_threadlist_from_driver not supported on offline captures");
		return NULL;
	}

#if !defined(HAS_CAPTURE)
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "live capture not supported on %s", PLATFORM_NAME);
	return NULL;
#else
	if(handle->m_driver_procinfo == NULL)
	{
		if(alloc_proclist_info(handle, SCAP_DRIVER_PROCINFO_INITIAL_SIZE) == false)
		{
			return NULL;
		}
	}

	int ioctlres = ioctl(handle->m_devs[0].m_fd, PPM_IOCTL_GET_PROCLIST, handle->m_driver_procinfo);
	if(ioctlres)
	{
		if(errno == ENOSPC)
		{
			if(alloc_proclist_info(handle, handle->m_driver_procinfo->n_entries + 256) == false)
			{
				return NULL;
			}
			else
			{
				return scap_get_threadlist_from_driver(handle);
			}
		}
		else
		{
			snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "Error calling PPM_IOCTL_GET_PROCLIST");
			return NULL;
		}
	}

	return handle->m_driver_procinfo;
#endif	// HAS_CAPTURE
}
