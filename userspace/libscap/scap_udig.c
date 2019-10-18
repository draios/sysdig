#ifndef _WIN32
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
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

#include "scap.h"
#include "scap-int.h"
#include "../../driver/ppm_ringbuffer.h"

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
int32_t udig_alloc_ring(int* ring_fd, 
	uint8_t** ring, 
	uint32_t *ringsize,
	char *error)
{
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

		*ring_fd = ud_shm_open(UDIG_RING_SM_FNAME, O_CREAT | O_RDWR | O_EXCL, 
			S_IWUSR | S_IWGRP| S_IWOTH);
		if(*ring_fd >= 0)
		{
			if(ftruncate(*ring_fd, *ringsize) < 0)
			{
				close(*ring_fd);
				return SCAP_FAILURE;
			}
		}
		else
		{
			close(*ring_fd);
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

int32_t udig_alloc_ring_descriptors(int* ring_descs_fd, 
	struct ppm_ring_buffer_info** ring_info, 
	struct udig_ring_buffer_status** ring_status,
	char *error)
{
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
			// Ring created, set its size
			//
			if(ftruncate(*ring_descs_fd, mem_size) < 0)
			{
				close(*ring_descs_fd);
				shm_unlink(UDIG_RING_DESCS_SM_FNAME);
				return SCAP_FAILURE;
			}
		}
		else
		{
			close(*ring_descs_fd);
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
int32_t udig_begin_capture(scap_t* handle, char *error)
{
	struct ppm_ring_buffer_info* rbi = handle->m_devs[0].m_bufinfo;
	rbi->head = 0;
	rbi->tail = 0;
	rbi->n_evts = 0;
	rbi->n_drops_buffer = 0;

	struct udig_ring_buffer_status* rbs = handle->m_devs[0].m_bufstatus;

	if(rbs->m_capturing_pid != 0)
	{
		//
		// Looks like there is already a consumer, but ther variable might still
		// be set by a previous crashed consumer. To understand that, we check if
		// there is an alive process with that pid. If not, we reset the variable.
		//
		char fbuf[48];
		snprintf(fbuf, sizeof(fbuf), "/proc/%d/comm", rbs->m_capturing_pid);
		FILE* f = fopen(fbuf, "r");
		if(f == NULL)
		{
			rbs->m_capturing_pid = 0;
		}
		else
		{
			fclose(f);
		}
	}

	if(udig_start_capture(handle))
	{
		return SCAP_SUCCESS;
	}

	snprintf(error, SCAP_LASTERR_SIZE, "another udig capture is already active");
	return SCAP_FAILURE;
}

bool udig_start_capture(scap_t* handle)
{
	struct udig_ring_buffer_status* rbs = handle->m_devs[0].m_bufstatus;
	return __sync_bool_compare_and_swap(&(rbs->m_capturing_pid), getpid(), 0);
}

void udig_stop_capture(scap_t* handle)
{
	struct udig_ring_buffer_status* rbs = handle->m_devs[0].m_bufstatus;
	__sync_bool_compare_and_swap(&(rbs->m_capturing_pid), getpid(), 0);
}

#endif // _WIN32
