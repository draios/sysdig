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
//#include <linux/futex.h>
	   
#include "scap.h"
#include "../../driver/ppm_ringbuffer.h"

#ifndef UDIG
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
	uint32_t mem_size = sizeof(struct ppm_ring_buffer_info) + sizeof(struct udig_ring_buffer_status);;

	//
	// First, try to open an existing ring
	//
	*ring_descs_fd = ud_shm_open(UDIG_RING_DESCS_SM_FNAME, O_RDWR, 0);
	if(*ring_descs_fd < 0)
	{
		//
		// No shared mem found, allocate a new one.
		// Note that, according to the man page, the content of the buffer will
		// be initialized to 0.
		//
		*ring_descs_fd = ud_shm_open(UDIG_RING_DESCS_SM_FNAME, O_CREAT | O_RDWR | O_EXCL, 
				S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
		if(*ring_descs_fd >= 0)
		{
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

	(*ring_status)->m_reader_active = false;

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

void udig_free_ring_descriptiors(uint8_t* addr)
{
	uint32_t mem_size = sizeof(struct ppm_ring_buffer_info) + sizeof(struct udig_ring_buffer_status);;
	munmap(addr, mem_size);
}

///////////////////////////////////////////////////////////////////////////////
// Mutex implementation coming from the futex man page.
///////////////////////////////////////////////////////////////////////////////
#if 0
static int futex(int *uaddr, int futex_op, int val,
		const struct timespec *timeout, int *uaddr2, int val3)
{
	return syscall(SYS_futex, uaddr, futex_op, val,
					timeout, uaddr, val3);
}

//
// Acquire the futex pointed to by 'futexp': wait for its value to
// become 1, and then set the value to 0.
//
int ud_lock(int *futexp)
{
	while (1) 
	{
		// Is the futex available?
		if(__sync_val_compare_and_swap(futexp, 0, 1))
		{
			break;
		}

		// Futex is not available; wait
		return futex(futexp, FUTEX_WAIT, 0, NULL, NULL, 0);
	}

	return 0;
}

//
// Release the futex pointed to by 'futexp': if the futex currently
// has the value 0, set its value to 1 and the wake any futex waiters,
// so that if the peer is blocked in fpost(), it can proceed.
//
int ud_unlock(int *futexp)
{
	if(__sync_val_compare_and_swap(futexp, 1, 0)) 
	{
		return futex(futexp, FUTEX_WAKE, 1, NULL, NULL, 0);
	}

	return 0;
}
#endif // 0

#endif // _WIN32
