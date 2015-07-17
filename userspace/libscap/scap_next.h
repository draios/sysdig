////////////////////////////////////////////////////////////////////////////
// Functions definitions for inlining
////////////////////////////////////////////////////////////////////////////

#pragma once

#include "settings.h"
#include <unistd.h>

#ifdef SCAP_INLINED
#include "scap-int.h"
#define SCAP_INLINED_STATIC static
#define SCAP_INLINED_INLINE inline
#else
#define SCAP_INLINED_STATIC
#define SCAP_INLINED_INLINE
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "../../driver/ppm_ringbuffer.h"

#if defined(HAS_CAPTURE)

#ifndef _WIN32
static inline void get_buf_pointers(struct ppm_ring_buffer_info* bufinfo, uint32_t* phead, uint32_t* ptail, uint32_t* pread_size)
#else
void get_buf_pointers(struct ppm_ring_buffer_info* bufinfo, uint32_t* phead, uint32_t* ptail, uint32_t* pread_size)
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

SCAP_INLINED_STATIC SCAP_INLINED_INLINE bool check_scap_next_wait(scap_t* handle)
{
	uint32_t j;
	bool res = true;

	for(j = 0; j < handle->m_ndevs; j++)
	{
		uint32_t thead;
		uint32_t ttail;
		scap_device* dev = &(handle->m_devs[j]);

		get_buf_pointers(dev->m_bufinfo, &thead, &ttail, &dev->m_read_size);

		if(dev->m_read_size > 20000)
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

SCAP_INLINED_STATIC SCAP_INLINED_INLINE int32_t scap_readbuf(scap_t* handle, uint32_t cpuid, bool blocking, OUT char** buf, OUT uint32_t* len)
{
	uint32_t thead;
	uint32_t ttail;
	uint32_t read_size;

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

SCAP_INLINED_STATIC SCAP_INLINED_INLINE int32_t refill_read_buffers(scap_t* handle, bool wait)
{
	uint32_t j;
	uint32_t ndevs = handle->m_ndevs;

	if(wait)
	{
		if(check_scap_next_wait(handle))
		{
			usleep(BUFFER_EMPTY_WAIT_TIME_MS * 1000);
			handle->m_n_consecutive_waits++;
		}
	}

	//
	// Refill our data for each of the devices
	//
	for(j = 0; j < ndevs; j++)
	{
		scap_device* dev = &(handle->m_devs[j]);

		int32_t res = scap_readbuf(handle,
		                           j,
		                           false,
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
#if !defined(HAS_CAPTURE)
	//
	// this should be prevented at open time
	//
	ASSERT(false);
	return SCAP_FAILURE;
#else
	uint32_t j;
	uint64_t max_ts = 0xffffffffffffffffLL;
	uint64_t max_buf_size = 0;
	scap_evt* pe = NULL;
	uint32_t ndevs = handle->m_ndevs;

	*pcpuid = 65535;

	for(j = 0; j < ndevs; j++)
	{
		scap_device* dev = &(handle->m_devs[j]);

		if(dev->m_sn_len == 0)
		{
			continue;
		}

		//
		// Make sure that we have data from this ring
		//
		if(dev->m_sn_len != 0)
		{
			if(dev->m_sn_len > max_buf_size)
			{
				max_buf_size = dev->m_sn_len;
			}

			//
			// We want to consume the event with the lowest timestamp
			//
			pe = (scap_evt*)dev->m_sn_next_event;

			if(pe->ts < max_ts)
			{
				if(pe->len > dev->m_sn_len)
				{
					snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "scap_next buffer corruption");

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
		//
		// Update the pointers.
		//
		ASSERT(handle->m_devs[*pcpuid].m_sn_len >= (*pevent)->len);
		handle->m_devs[*pcpuid].m_sn_len -= (*pevent)->len;
		handle->m_devs[*pcpuid].m_sn_next_event += (*pevent)->len;
		return SCAP_SUCCESS;
	}
	else
	{
		//
		// All the buffers have been consumed. Check if there's enough data to keep going or
		// if we should wait.
		//
		return refill_read_buffers(handle, true);
	}
#endif
}

#ifndef _WIN32
SCAP_INLINED_STATIC SCAP_INLINED_INLINE int32_t scap_next(scap_t* handle, OUT scap_evt** pevent, OUT uint16_t* pcpuid)
#else
int32_t scap_next(scap_t* handle, OUT scap_evt** pevent, OUT uint16_t* pcpuid)
#endif
{
	int32_t res;

	if(handle->m_file)
	{
		res = scap_next_offline(handle, pevent, pcpuid);
	}
#ifndef _WIN32
	else
	{
		res = scap_next_live(handle, pevent, pcpuid);
	}
#endif

	if(res == SCAP_SUCCESS)
	{
		handle->m_evtcnt++;
	}

	return res;
}

#ifdef __cplusplus
}
#endif
