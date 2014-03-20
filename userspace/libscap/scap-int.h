/*
Copyright (C) 2013-2014 Draios inc.
 
This file is part of sysdig.

sysdig is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

////////////////////////////////////////////////////////////////////////////
// Private definitions for the scap library
////////////////////////////////////////////////////////////////////////////

#include "settings.h"

#ifdef __cplusplus
extern "C" {
#endif


#ifdef _WIN32
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif
#include <assert.h>

//
// The time scap_next will wait when a buffer is empty
//
#define BUFFER_EMPTY_WAIT_TIME_MS 30

//
// Process flags
//
#define PF_CLONING 1

//
// The device descriptor
//
typedef struct scap_device
{
	int m_fd;
	char* m_buffer;
	struct ppm_ring_buffer_info* m_bufinfo;
	uint32_t m_lastreadsize;
	char* m_sn_next_event; // Pointer to the next event available for scap_next
	uint32_t m_sn_len; // Number of bytes available in the buffer pointed by m_sn_next_event
//	uint64_t m_sn_next_ts; // timestamp
}scap_device;

//
// The open instance handle
//
struct scap
{
	scap_device* m_devs;
	struct pollfd* m_pollfds;
	uint32_t m_ndevs;
	FILE* m_file;
	char* m_file_evt_buf;
	char m_lasterr[SCAP_LASTERR_SIZE];
	scap_threadinfo* m_proclist;
	scap_threadinfo m_fake_kernel_proc;
	uint64_t m_evtcnt;
	uint32_t m_emptybuf_timeout_ms;
	scap_addrlist* m_addrlist;
	scap_machine_info m_machine_info;
	scap_userlist* m_userlist;
};

//
// Misc stuff
//
#define MEMBER_SIZE(type, member) sizeof(((type *)0)->member)
#define FILE_READ_BUF_SIZE 65536

//
// Internal library functions
//

// Read the full event buffer for the given processor
int32_t scap_readbuf(scap_t* handle, uint32_t proc, bool blocking, OUT char** buf, OUT uint32_t* len);
// Scan a directory containing process information
int32_t scap_proc_scan_proc_dir(scap_t* handle, char* procdirname, int parenttid, int tid_to_scan, struct scap_threadinfo** pi, char *error, bool scan_sockets);
// Remove an entry from the process list by parsin a PPME_PROC_EXIT event
// void scap_proc_schedule_removal(scap_t* handle, scap_evt* e);
// Remove the process that was scheduled for deletion for this handle
// void scap_proc_remove_scheduled(scap_t* handle);
// Free the process table
void scap_proc_free_table(scap_t* handle);
// Copy the fd table of a process into the one of another process
// int32_t scap_proc_copy_fd_table(scap_t* handle, scap_threadinfo* dst, scap_threadinfo* src);
// Internal helper function to output the process table to screen
void scap_proc_print_info(scap_threadinfo* pi);
void scap_proc_print_table(scap_t* handle);
// Free all the state related to a process and delete it from the fd table
void scap_proc_delete(scap_t* handle, scap_threadinfo* proc);
// Internal helper function to output the fd table of a process
void scap_fd_print_table(scap_threadinfo* pi);
// Internal helper function to output an fd table
void scap_fd_print_fd_table(scap_fdinfo* fds);
// Given an event, get the info entry for the process that generated it.
// NOTE: this is different from scap_event_getprocinfo() because it returns the full event information
// struct scap_threadinfo* scap_proc_get_from_event(scap_t* handle, scap_evt* e);
// Return the process info entry geiven a tid
// Free an fd table and set it to NULL when done
void scap_fd_free_table(scap_t* handle, scap_fdinfo** fds);
// Free a process' fd table
void scap_fd_free_proc_fd_table(scap_t* handle, scap_threadinfo* pi);
// Convert an fd entry's info into a string
int32_t scap_fd_info_to_string(scap_fdinfo* fdi, OUT char* str, uint32_t strlen);
// Calculate the length on disk of an fd entry's info
uint32_t scap_fd_info_len(scap_fdinfo* fdi);
// Write the given fd info to disk
int32_t scap_fd_write_to_disk(scap_t* handle, scap_fdinfo* fdi, FILE *f);
// Populate the given fd by reading the info from disk
uint32_t scap_fd_read_from_disk(scap_t* handle, OUT scap_fdinfo* fdi, OUT size_t* nbytes, FILE *f);
// Add the file descriptor info pointed by fdi to the fd table for process pi.
// Note: silently skips if fdi->type is SCAP_FD_UNKNOWN.
int32_t scap_add_fd_to_proc_table(scap_t* handle, scap_threadinfo* pi, scap_fdinfo* fdi);
// Remove the given fd from the process table of the process pointed by pi
void scap_fd_remove(scap_t* handle, scap_threadinfo* pi, int64_t fd);
// Parse the headers of a trace file and load the tables
int32_t scap_read_init(scap_t* handle, FILE* f);
// Read an event from disk
int32_t scap_next_offline(scap_t* handle, OUT scap_evt** pevent, OUT uint16_t* pcpuid);
// read the filedescriptors for a given process directory
int32_t scap_fd_scan_fd_dir(scap_t* handle, char * procdir, scap_threadinfo* pi, scap_fdinfo * sockets, char *error);
// read tcp or udp sockets from the proc filesystem
int32_t scap_fd_read_ipv4_sockets_from_proc_fs(scap_t* handle, char * dir, int l4proto, scap_fdinfo ** sockets);
// read all sockets and add them to the socket table hashed by their ino
int32_t scap_fd_read_sockets(scap_t* handle, scap_fdinfo** sockets);
// prints procs details for a give tid
void scap_proc_print_proc_by_tid(scap_t* handle, uint64_t tid);
// Allocate and return the list of interfaces on this system
int32_t scap_create_iflist(scap_t* handle);
// Free a previously allocated list of interfaces
void scap_free_iflist(scap_addrlist* ifhandle);
// Allocate and return the list of interfaces on this system
int32_t scap_create_userlist(scap_t* handle);
// Free a previously allocated list of users
void scap_free_userlist(scap_userlist* uhandle);

int32_t scap_fd_post_process_unix_sockets(scap_t* handle, scap_fdinfo* sockets);

uint32_t scap_event_compute_len(scap_evt* e);

//
// ASSERT implementation
//
#ifdef _DEBUG
#define ASSERT(X) assert(X)
#else // _DEBUG
#define ASSERT(X)
#endif // _DEBUG

#define CHECK_READ_SIZE(read_size, expected_size) if(read_size != expected_size) \
	{\
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "expecting %d bytes, read %d at %s, line %d. Is the file truncated?",\
			(int)expected_size,\
			(int)read_size,\
			__FILE__,\
			__LINE__);\
		ASSERT(false);\
		return SCAP_FAILURE;\
	}

//
// Useful stuff
//
#ifndef MIN
#define MIN(X,Y) ((X) < (Y)? (X):(Y))
#define MAX(X,Y) ((X) > (Y)? (X):(Y))
#endif

#ifdef __cplusplus
}
#endif
