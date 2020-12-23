#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <pthread.h>
#else // _WIN32
// enable use of snprintf
#pragma warning(disable : 4996)
// enable zero-sized array in struct/union
#pragma warning(disable : 4200)
#include <windows.h>
#endif // _WIN32

#include "scap.h"
#include "scap-int.h"
#include "../../driver/ppm_ringbuffer.h"

#define PPM_PORT_STATSD 8125

#ifndef _WIN32
#ifndef UDIG_INSTRUMENTER
#define ud_shm_open shm_open
#else
int ud_shm_open(const char *name, int flag, mode_t mode);
#endif

///////////////////////////////////////////////////////////////////////////////
// The following 2 function map the ring buffer and the ring buffer 
// descriptors into the address space of this process.
// This is the buffer that will be consumed by scap.
///////////////////////////////////////////////////////////////////////////////
int32_t udig_alloc_ring(void* ring_id, 
	uint8_t** ring, 
	uint32_t *ringsize,
	char *error)
{
	int* ring_fd = (int*)ring_id;

	//
	// First, try to open an existing ring
	//
	*ring_fd = ud_shm_open(UDIG_RING_SM_FNAME, O_RDWR, 0);
	if(*ring_fd >= 0)
	{
		//
		// Existing ring found, find out the size
		//
		struct stat rstat;
		if(fstat(*ring_fd, &rstat) < 0)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "udig_alloc_ring fstat error: %s\n", strerror(errno));
			return SCAP_FAILURE;
		}

		*ringsize = (uint32_t)rstat.st_size;
	}
	else
	{
		//
		// No ring found, allocate a new one.
		// Note that, according to the man page, the content of the buffer will
		// be initialized to 0.
		//
		*ringsize = UDIG_RING_SIZE;

		*ring_fd = ud_shm_open(UDIG_RING_SM_FNAME, O_CREAT | O_RDWR, 
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
		if(*ring_fd >= 0)
		{
			//
			// For some reason, shm_open doesn't always set the write flag for
			// 'group' and 'other'. Fix it here.
			//
			fchmod(*ring_fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

			if(ftruncate(*ring_fd, *ringsize) < 0)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "udig_alloc_ring ftruncate error: %s\n", strerror(errno));
				close(*ring_fd);
				return SCAP_FAILURE;
			}
		}
		else
		{
			snprintf(error, SCAP_LASTERR_SIZE, "udig_alloc_ring shm_open error: %s\n", strerror(errno));
			return SCAP_FAILURE;
		}
	}

	//
	// Map the ring. This is a multi-step process because we want to map two
	// consecutive copies of the same memory to reuse the driver fillers, which
	// expect to be able to go past the end of the ring.
	// First of all, allocate enough space for the 2 copies. This allows us 
	// to find an area of consecutive memory that is big enough.
	//
	uint8_t* buf1 = (uint8_t*)mmap(NULL, (*ringsize) * 2, 
		PROT_WRITE, MAP_SHARED,
		*ring_fd, 0);
	if(buf1 == MAP_FAILED)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't map double buffer\n");
		close(*ring_fd);
		return SCAP_FAILURE;
	}

	// Now that we have the address, unmap the double-lenght buffer so we can 
	// use the two halves.
	munmap(buf1, (*ringsize) * 2);

	// Map the first ring copy at exactly the beginning of the previously
	// allocated area, forcing it with MAP_FIXED.
	*ring = (uint8_t*)mmap(buf1, *ringsize, 
		PROT_WRITE, MAP_SHARED | MAP_FIXED, *ring_fd, 0);
	if(*ring != buf1)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "udig_alloc_ring mmap 2 error: %s\n", strerror(errno));
		close(*ring_fd);
		return SCAP_FAILURE;
	}

	// Map the second ring copy just after the end of the first one.
	uint8_t* buf2 = buf1 + *ringsize;
	uint8_t* ring2 = (uint8_t*)mmap(buf2, *ringsize, 
		PROT_WRITE, MAP_SHARED | MAP_FIXED, *ring_fd, 0);
	if(ring2 != buf2)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't map second copy of buffer, needed %p, obtained %p, base=%p\n", 
			buf2, ring2, buf1);
		close(*ring_fd);
		munmap(*ring, *ringsize);
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t udig_alloc_ring_descriptors(void* ring_descs_id, 
	struct ppm_ring_buffer_info** ring_info, 
	struct udig_ring_buffer_status** ring_status,
	char *error)
{
	int* ring_descs_fd = (int*)ring_descs_id;
	uint32_t mem_size = sizeof(struct ppm_ring_buffer_info) + sizeof(struct udig_ring_buffer_status);

	//
	// First, try to open an existing ring
	//
	*ring_descs_fd = ud_shm_open(UDIG_RING_DESCS_SM_FNAME, O_RDWR, 0);
	if(*ring_descs_fd < 0)
	{
		//
		// No existing ring file found in /dev/shm, create a new one.
		//
		*ring_descs_fd = ud_shm_open(UDIG_RING_DESCS_SM_FNAME, O_CREAT | O_RDWR | O_EXCL, 
				S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
		if(*ring_descs_fd >= 0)
		{
			//
			// For some reason, shm_open doesn't always set the write flag for
			// 'group' and 'other'. Fix it here.
			//
			fchmod(*ring_descs_fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

			//
			// Ring created, set its size
			//
			if(ftruncate(*ring_descs_fd, mem_size) < 0)
			{
				snprintf(error, SCAP_LASTERR_SIZE, "udig_alloc_ring_descriptors ftruncate error: %s\n", strerror(errno));
				close(*ring_descs_fd);
				shm_unlink(UDIG_RING_DESCS_SM_FNAME);
				return SCAP_FAILURE;
			}
		}
		else
		{
			snprintf(error, SCAP_LASTERR_SIZE, "udig_alloc_ring_descriptors shm_open error: %s\n", strerror(errno));
			shm_unlink(UDIG_RING_DESCS_SM_FNAME);
			return SCAP_FAILURE;
		}
	}

	//
	// Map the memory
	//
	uint8_t* descs = (uint8_t*)mmap(NULL, mem_size, PROT_READ|PROT_WRITE, MAP_SHARED, 
		*ring_descs_fd, 0);
	if(descs == MAP_FAILED)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't map descriptors\n");
		close(*ring_descs_fd);
		return SCAP_FAILURE;
	}

	*ring_info = (struct ppm_ring_buffer_info*)descs;

	//
	// Locate the ring buffer status object
	//
	*ring_status = (struct udig_ring_buffer_status*)((uint64_t)*ring_info + 
		sizeof(struct ppm_ring_buffer_info));

	//
	// If we are the original creators of the shared buffer, proceed to
	// initialize it.
	// Note that, according to the man page of ud_shm_open, we are guaranteed that 
	// the content of the buffer will initiually be initialized to 0.
	//
	if(__sync_bool_compare_and_swap(&((*ring_status)->m_initialized), 0, 1))
	{
		(*ring_status)->m_buffer_lock = 0;
		(*ring_status)->m_capturing_pid = 0;
		(*ring_status)->m_stopped = 0;
		(*ring_status)->m_last_print_time.tv_sec = 0;
		(*ring_status)->m_last_print_time.tv_nsec = 0;
	}

	return SCAP_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// These 2 function free the ring buffer and the ring buffer descriptors.
///////////////////////////////////////////////////////////////////////////////
void udig_free_ring(uint8_t* addr, uint32_t size)
{
	munmap(addr, size / 2);
	munmap(addr + size / 2, size / 2);
}

void udig_free_ring_descriptors(uint8_t* addr)
{
	uint32_t mem_size = sizeof(struct ppm_ring_buffer_info) + sizeof(struct udig_ring_buffer_status);
	munmap(addr, mem_size);
}

///////////////////////////////////////////////////////////////////////////////
// Capture control helpers.
///////////////////////////////////////////////////////////////////////////////
bool acquire_and_init_ring_status_buffer(scap_t* handle)
{
	struct udig_ring_buffer_status* rbs = handle->m_devs[0].m_bufstatus;
	bool res = __sync_bool_compare_and_swap(&(rbs->m_capturing_pid), 0, getpid());

	if(res)
	{
		//
		// Initialize the ring
		//
		rbs->m_stopped = 0;
		rbs->m_last_print_time.tv_sec = 0;
		rbs->m_last_print_time.tv_nsec = 0;

		//
		// Initialize the consumer
		//
		struct udig_consumer_t* consumer = &(rbs->m_consumer);

		memset(consumer, 0, sizeof(struct udig_consumer_t));
		consumer->dropping_mode = 0;
		consumer->snaplen = RW_SNAPLEN;
		consumer->sampling_ratio = 1;
		consumer->sampling_interval = 0;
		consumer->is_dropping = 0;
		consumer->do_dynamic_snaplen = false;
		consumer->need_to_insert_drop_e = 0;
		consumer->need_to_insert_drop_x = 0;
		consumer->fullcapture_port_range_start = 0;
		consumer->fullcapture_port_range_end = 0;
		consumer->statsd_port = PPM_PORT_STATSD;
	}

	return res;
}

int32_t udig_begin_capture(scap_t* handle, char *error)
{
	struct udig_ring_buffer_status* rbs = handle->m_devs[0].m_bufstatus;

	if(rbs->m_capturing_pid != 0)
	{
		//
		// Looks like there is already a consumer, but ther variable might still
		// be set by a previous crashed consumer. To understand that, we check if
		// there is an alive process with that pid. If not, we reset the variable.
		//
		char fbuf[48];
		snprintf(fbuf, sizeof(fbuf), "/proc/%d", rbs->m_capturing_pid);
		FILE* f = fopen(fbuf, "r");
		if(f == NULL)
		{
			rbs->m_capturing_pid = 0;
		}
		else
		{
			fclose(f);
			snprintf(error, SCAP_LASTERR_SIZE, "another udig capture is already active");
			return SCAP_FAILURE;
		}
	}

	struct ppm_ring_buffer_info* rbi = handle->m_devs[0].m_bufinfo;
	rbi->head = 0;
	rbi->tail = 0;
	rbi->n_evts = 0;
	rbi->n_drops_buffer = 0;

	if(acquire_and_init_ring_status_buffer(handle))
	{
		handle->m_udig_capturing = true;
		return SCAP_SUCCESS;
	}
	else
	{
		snprintf(error, SCAP_LASTERR_SIZE, "cannot start the capture");
		return SCAP_FAILURE;
	}
}

#else // _WIN32

///////////////////////////////////////////////////////////////////////////////
// The following 2 function map the ring buffer and the ring buffer 
// descriptors into the address space of this process.
// This is the buffer that will be consumed by scap.
///////////////////////////////////////////////////////////////////////////////
int32_t udig_alloc_ring(HANDLE* ring_handle,
	uint8_t** ring,
	uint32_t* ringsize,
	char* error)
{
	*ring_handle = NULL;

	//
	// First, try to open an existing ring
	//
	HANDLE fh = OpenFileMapping(
		FILE_MAP_ALL_ACCESS,
		FALSE,
		(TCHAR*)TEXT(UDIG_RING_SM_FNAME));

	if(fh != NULL)
	{
		//
		// Existing ring found, find out the size
		//
		uint8_t* pdbuf = (uint8_t*)MapViewOfFile(fh,
			FILE_MAP_ALL_ACCESS,
			0,
			0,
			0);

		MEMORY_BASIC_INFORMATION info;
		SIZE_T szBufferSize = VirtualQueryEx(GetCurrentProcess(), pdbuf, &info, sizeof(info));

		*ringsize = (uint32_t)info.RegionSize;

		UnmapViewOfFile(pdbuf);
	}
	else
	{
		//
		// No ring found, allocate a new one.
		// Note that, according to the man page, the content of the buffer will
		// be initialized to 0.
		//
		*ringsize = UDIG_RING_SIZE;

		fh = CreateFileMapping(INVALID_HANDLE_VALUE,
			NULL,
			PAGE_READWRITE,
			0,
			*ringsize,
			(TCHAR*)TEXT(UDIG_RING_SM_FNAME));

		if(fh == NULL)
		{
			_snprintf(error, SCAP_LASTERR_SIZE, "udig_alloc_ring CreateFileMapping error: %u\n", GetLastError());
			return SCAP_FAILURE;
		}
	}

	//
	// Map the ring. This is a multi-step process because we want to map two
	// consecutive copies of the same memory to reuse the driver fillers, which
	// expect to be able to go past the end of the ring.
	// First of all, map the first ring copy at exactly the beginning of the 
	// previously allocated area.
	*ring = (uint8_t*)MapViewOfFileEx(fh,
		FILE_MAP_ALL_ACCESS,
		0,
		0,
		*ringsize,
		NULL);
	if(*ring == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't map first copy of buffer error: %u\n", GetLastError());
		CloseHandle(fh);
		return SCAP_FAILURE;
	}

	// Map the second ring copy just after the end of the first one.
	uint8_t* buf2 = (*ring) + (*ringsize);
	uint8_t* ring2 = (uint8_t*)MapViewOfFileEx(fh,
		FILE_MAP_ALL_ACCESS,
		0,
		0,
		*ringsize,
		buf2);
	if(ring2 != buf2)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't map second copy of buffer, needed %p, obtained %p, base=%p\n", 
			buf2, ring2, *ring);
		UnmapViewOfFile(*ring);
		CloseHandle(fh);
		return SCAP_FAILURE;
	}

	*ring_handle = fh;
	return SCAP_SUCCESS;
}

int32_t udig_alloc_ring_descriptors(HANDLE* ring_descs_fd, struct ppm_ring_buffer_info** ring_info, 
	struct udig_ring_buffer_status** ring_status, char *error)
{
	*ring_descs_fd = NULL;

	uint32_t mem_size = sizeof(struct ppm_ring_buffer_info) + sizeof(struct udig_ring_buffer_status);

	//
	// First, try to open an existing memory area
	//
	HANDLE fh = OpenFileMapping(FILE_MAP_ALL_ACCESS,
		TRUE,
		(TCHAR*)TEXT(UDIG_RING_DESCS_SM_FNAME));

	if(fh == NULL)
	{
		//
		// No existing memory file found in /dev/shm, create a new one.
		//
		fh = CreateFileMapping(INVALID_HANDLE_VALUE,
			NULL,
			PAGE_READWRITE,
			0,
			mem_size,
			(TCHAR*)TEXT(UDIG_RING_DESCS_SM_FNAME));

		if(fh == NULL)
		{
			snprintf(error, SCAP_LASTERR_SIZE, "udig_alloc_ring_descriptors CreateFileMapping error: %u\n", GetLastError());
			return SCAP_FAILURE;
		}
	}

	//
	// Map the memory
	//
	uint8_t* descs = (uint8_t*)MapViewOfFile(fh,
		FILE_MAP_ALL_ACCESS,
		0,
		0,
		0);
	if(descs == NULL)
	{
		snprintf(error, SCAP_LASTERR_SIZE, "can't map descriptors\n");
		CloseHandle(fh);
		return SCAP_FAILURE;
	}

	*ring_info = (struct ppm_ring_buffer_info*)descs;

	//
	// Locate the ring buffer status object
	//
	*ring_status = (struct udig_ring_buffer_status*)((uint64_t)*ring_info + 
		sizeof(struct ppm_ring_buffer_info));

	//
	// If we are the original creators of the shared buffer, proceed to
	// initialize it.
	// Note that, according to the documentation of CreateFileMapping, we are 
	// guaranteed that the content of the buffer will initiually be initialized to 0.
	//
	if(InterlockedCompareExchange((volatile LONG*)&((*ring_status)->m_initialized), 1, 0) == 0)
	{
		(*ring_status)->m_buffer_lock = 0;
		(*ring_status)->m_capturing_pid = 0;
		(*ring_status)->m_stopped = 0;
		(*ring_status)->m_last_print_time.tv_sec = 0;
		(*ring_status)->m_last_print_time.tv_nsec = 0;
		
		(*ring_info)->head = 0;
		(*ring_info)->tail = 0;
		(*ring_info)->n_evts = 0;
		(*ring_info)->n_drops_buffer = 0;
		(*ring_info)->n_drops_pf = 0;
		(*ring_info)->n_preemptions = 0;
		(*ring_info)->n_context_switches = 0;
	}

	*ring_descs_fd = fh;
	return SCAP_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// These 2 function free the ring buffer and the ring buffer descriptors.
///////////////////////////////////////////////////////////////////////////////
void udig_free_ring(uint8_t* addr, uint32_t size)
{
	UnmapViewOfFile(addr);
	UnmapViewOfFile(addr + size / 2);
}

void udig_free_ring_descriptors(uint8_t* addr)
{
	UnmapViewOfFile(addr);
}

///////////////////////////////////////////////////////////////////////////////
// Capture control helpers.
///////////////////////////////////////////////////////////////////////////////
bool acquire_and_init_ring_status_buffer(scap_t* handle)
{
	struct udig_ring_buffer_status* rbs = handle->m_devs[0].m_bufstatus;
#ifdef _WIN32
	LONG dval = InterlockedCompareExchange(&(rbs->m_capturing_pid), GetCurrentProcessId(), 0);
	bool res = (dval == 0);
#else
	bool res = __sync_bool_compare_and_swap(&(rbs->m_capturing_pid), 0, getpid());
#endif

	if(res)
	{
		//
		// Initialize the ring
		//
		rbs->m_stopped = 0;
		rbs->m_last_print_time.tv_sec = 0;
		rbs->m_last_print_time.tv_nsec = 0;

		//
		// Initialize the consumer
		//
		struct udig_consumer_t* consumer = &(rbs->m_consumer);

		memset(consumer, 0, sizeof(struct udig_consumer_t));
		consumer->dropping_mode = 0;
		consumer->snaplen = RW_SNAPLEN;
		consumer->sampling_ratio = 1;
		consumer->sampling_interval = 0;
		consumer->is_dropping = 0;
		consumer->do_dynamic_snaplen = false;
		consumer->need_to_insert_drop_e = 0;
		consumer->need_to_insert_drop_x = 0;
		consumer->fullcapture_port_range_start = 0;
		consumer->fullcapture_port_range_end = 0;
		consumer->statsd_port = PPM_PORT_STATSD;
	}

	return res;
}

int32_t udig_begin_capture(scap_t* handle, char *error)
{
	struct udig_ring_buffer_status* rbs = handle->m_devs[0].m_bufstatus;

	if(rbs->m_capturing_pid != 0)
	{
#ifdef _WIN32
		HANDLE ph = OpenProcess(PROCESS_ALL_ACCESS, TRUE, rbs->m_capturing_pid);
		DWORD ecode;
		if(GetExitCodeProcess(ph, &ecode) != FALSE)
		{
			if(ecode != STILL_ACTIVE)
			{
				rbs->m_capturing_pid = 0;
			}
			else
			{
				CloseHandle(ph);
				snprintf(error, SCAP_LASTERR_SIZE, "another udig capture is already active");
				return SCAP_FAILURE;
			}
		}
#else
		//
		// Looks like there is already a consumer, but ther variable might still
		// be set by a previous crashed consumer. To understand that, we check if
		// there is an alive process with that pid. If not, we reset the variable.
		//
		char fbuf[48];
		snprintf(fbuf, sizeof(fbuf), "/proc/%d", rbs->m_capturing_pid);
		FILE* f = fopen(fbuf, "r");
		if(f == NULL)
		{
			rbs->m_capturing_pid = 0;
		}
		else
		{
			fclose(f);
			snprintf(error, SCAP_LASTERR_SIZE, "another udig capture is already active");
			return SCAP_FAILURE;
		}
#endif
	}

	struct ppm_ring_buffer_info* rbi = handle->m_devs[0].m_bufinfo;
	rbi->head = 0;
	rbi->tail = 0;
	rbi->n_evts = 0;
	rbi->n_drops_buffer = 0;

	if(acquire_and_init_ring_status_buffer(handle))
	{
		handle->m_udig_capturing = true;
		return SCAP_SUCCESS;
	}
	else
	{
		snprintf(error, SCAP_LASTERR_SIZE, "cannot start the capture");
		return SCAP_FAILURE;
	}
}

#endif // _WIN32

void udig_start_capture(scap_t* handle)
{
	struct udig_ring_buffer_status* rbs = handle->m_devs[0].m_bufstatus;
	rbs->m_stopped = 0;
}

void udig_stop_capture(scap_t* handle)
{
	struct udig_ring_buffer_status* rbs = handle->m_devs[0].m_bufstatus;
	rbs->m_stopped = 1;
}

void udig_end_capture(scap_t* handle)
{
	struct udig_ring_buffer_status* rbs = handle->m_devs[0].m_bufstatus;
	if(handle->m_udig_capturing)
	{
		//__sync_bool_compare_and_swap(&(rbs->m_capturing_pid), getpid(), 0);
		rbs->m_capturing_pid = 0;
	}
}

uint32_t udig_set_snaplen(scap_t* handle, uint32_t snaplen)
{
	struct udig_ring_buffer_status* rbs = handle->m_devs[0].m_bufstatus;
	rbs->m_consumer.snaplen = snaplen;
	return SCAP_SUCCESS;
}

int32_t udig_stop_dropping_mode(scap_t* handle)
{
	struct udig_consumer_t* consumer = &(handle->m_devs[0].m_bufstatus->m_consumer);
	consumer->dropping_mode = 0;
	consumer->sampling_interval = 1000000000;
	consumer->sampling_ratio = 1;

	return SCAP_SUCCESS;
}

int32_t udig_start_dropping_mode(scap_t* handle, uint32_t sampling_ratio)
{
	struct udig_consumer_t* consumer = &(handle->m_devs[0].m_bufstatus->m_consumer);

	consumer->dropping_mode = 1;

	if(sampling_ratio != 1 &&
		sampling_ratio != 2 &&
		sampling_ratio != 4 &&
		sampling_ratio != 8 &&
		sampling_ratio != 16 &&
		sampling_ratio != 32 &&
		sampling_ratio != 64 &&
		sampling_ratio != 128) 
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid sampling ratio %u\n", sampling_ratio);
		return SCAP_FAILURE;
	}

	consumer->sampling_interval = 1000000000 / sampling_ratio;
	consumer->sampling_ratio = sampling_ratio;

	return SCAP_SUCCESS;
}

