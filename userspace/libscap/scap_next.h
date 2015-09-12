////////////////////////////////////////////////////////////////////////////
// Functions definitions for inlining
////////////////////////////////////////////////////////////////////////////

#pragma once

#include "settings.h"
#include <unistd.h>

#include "scap-int.h"
#define SCAP_INLINED_STATIC static
#if !defined(_WIN32)/* && !defined(_DEBUG)*/
#define SCAP_INLINED_INLINE __always_inline
#else
#define SCAP_INLINED_INLINE inline
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "../../driver/ppm_ringbuffer.h"

#if defined(HAS_CAPTURE)

SCAP_INLINED_STATIC SCAP_INLINED_INLINE uint32_t get_read_size(struct ppm_ring_buffer_info* const bufinfo)
{
	uint32_t phead = bufinfo->head;
	uint32_t ptail = bufinfo->tail;

	if(ptail > phead)
	{
		return (RING_BUF_SIZE - ptail + phead);
	}
	else
	{
		return (phead - ptail);
	}
}

//
// Updates the current snap length, the next event pointer and the buffer read size
// in order to advance the buffer reading.
// Returns the new snap length.
//
SCAP_INLINED_STATIC SCAP_INLINED_INLINE int32_t scap_update_snap(scap_device* const dev)
{
	uint32_t ttail;
	uint32_t read_size;

	//
	// Update the tail based on the amount of data read in the *previous* call.
	// Tail is never updated when we serve the data, because we assume that the caller is using
	// the buffer we give to her until she calls us again.
	//
	ttail = dev->m_bufinfo->tail + dev->m_lastreadsize;


	if(ttail >= RING_BUF_SIZE)
	{
		ttail = ttail - RING_BUF_SIZE;
	}
	//
	// Make sure every read of the old buffer is completed before we move the tail and the
	// producer (on another CPU) can start overwriting it.
	// I use this instead of asm(mfence) because it should be portable even on the weirdest
	// CPUs
	//
	__sync_synchronize();
	dev->m_bufinfo->tail = ttail;

	//
	// Read the pointers.
	//
	read_size = get_read_size(dev->m_bufinfo);

	//
	// Remember read_size so we can update the tail at the next call
	//
	dev->m_lastreadsize = read_size;

	//
	// Update the snap length and the next event pointer
	//
	dev->m_sn_len = read_size;
	dev->m_sn_next_event = dev->m_buffer + ttail;

	return read_size;
}

#endif // HAS_CAPTURE

//
// Handles the logic to extract en event from a single CPU buffer.
// Returns the event extracted (or NULL if none exists)
//
SCAP_INLINED_STATIC SCAP_INLINED_INLINE int32_t scap_next_live_cpu(const scap_device* const dev, OUT scap_evt** const pe)
{
	//
	// Make sure that we have data from this ring
	//
	if(dev->m_sn_len == 0)
	{
		return SCAP_EMPTY;
	}
	else
	{
		*pe = (scap_evt*)dev->m_sn_next_event;
		uint32_t len = (*pe)->len;
//		__builtin_prefetch((void*)((char *)dev->m_sn_next_event + len),0,3);
		if(len > dev->m_sn_len)
		{
			//
			// if you get the following assertion, first recompile the driver and libscap
			//
			ASSERT(false);
			return SCAP_FAILURE;
		}
	}
	return SCAP_SUCCESS;
}

#ifndef HAVE_EXTERNAL_SCAP_READER

#if defined(HAS_CAPTURE)

SCAP_INLINED_STATIC SCAP_INLINED_INLINE int32_t refill_read_buffers(scap_t* const handle)
{
	uint32_t j;
	uint32_t ndevs = handle->m_ndevs;
	int32_t res = SCAP_SLEEP;

	//
	// Check if we slept enough
	//
	if(handle->m_n_consecutive_waits >= MAX_N_CONSECUTIVE_WAITS)
	{
		handle->m_n_consecutive_waits = 0;
		res = SCAP_TIMEOUT;
	}

	//
	// Refill our data for each of the devices
	//
	for(j = 0; j < ndevs; j++)
	{
		scap_device* dev = &(handle->m_devs[j]);
		//
		// update device snap infos
		//
		int32_t next_snaplen = scap_update_snap(dev);

		//
		// (kindof) Check the event production rate
		//
		if(next_snaplen > 20000)
		{
			handle->m_n_consecutive_waits = 0;
			res = SCAP_TIMEOUT;
		}
	}

	//
	// Note: we might return a spurious timeout here in case the previous loop extracted valid data to parse.
	//       It's ok, since this is rare and the caller will just call us again after receiving a
	//       SCAP_TIMEOUT.
	//
	return res;
}

#endif // HAS_CAPTURE



SCAP_INLINED_STATIC SCAP_INLINED_INLINE int32_t scap_next_live(scap_t* const handle, OUT scap_evt** const pevent, OUT uint16_t* const pcpuid)
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
	uint32_t ndevs = handle->m_ndevs;

	*pcpuid = 65535;

	for(j = 0; j < ndevs; j++)
	{
		scap_device* const dev = &(handle->m_devs[j]);
//		res = scap_next_live_cpu(dev, &pe);

		if(dev->m_sn_len == 0)
		{
			continue;
		}
		else
		{
			scap_evt* const pe = (scap_evt*)(dev->m_sn_next_event);
//			__builtin_prefetch((void*)((char *)dev->m_sn_next_event + pe->len),0,3);
			if(pe->len > dev->m_sn_len)
			{
				//
				// if you get the following assertion, first recompile the driver and libscap
				//
				ASSERT(false);
				return SCAP_FAILURE;
			}
			//
			// We want to consume the event with the lowest timestamp
			//
			if(pe->ts < max_ts)
			{
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
		return refill_read_buffers(handle);
	}
#endif
}

SCAP_INLINED_STATIC SCAP_INLINED_INLINE int32_t scap_next_centralized(scap_t* handle, OUT scap_evt** pevent, OUT uint16_t* pcpuid)
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
	else if(res == SCAP_SLEEP)
	{
		//
		// Intercept SCAP_SLEEP, go sleeping and tell upper layers they must call us again
		//
		usleep(BUFFER_EMPTY_WAIT_TIME_MS * 1000);
		handle->m_n_consecutive_waits++;
		res = SCAP_TIMEOUT;
	}
	else if(res == SCAP_FAILURE)
	{
		//
		// if you get the following assertion, first recompile the driver and libscap
		//
		ASSERT(false);
		snprintf(handle->m_lasterr,	SCAP_LASTERR_SIZE, "scap_next buffer corruption");
	}

	return res;
}

#else // HAVE_EXTERNAL_SCAP_READER

#endif //HAVE_EXTERNAL_SCAP_READER

#ifdef __cplusplus
}
#endif
