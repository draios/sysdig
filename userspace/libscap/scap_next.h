#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "settings.h"
#include <unistd.h>
#include "scap.h"
#include "scap-int.h"
#include "scap_next_util.h"

#include "../../driver/ppm_ringbuffer.h"

#ifndef _WIN32
static __always_inline int32_t scap_next_live(scap_t* handle, OUT scap_evt** pevent, OUT uint16_t* pcpuid)
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


/*!
  \brief Get the next event from the from the given capture instance

  \param handle Handle to the capture instance.
  \param pevent User-provided event pointer that will be initialized with address of the event.
  \param pcpuid User-provided event pointer that will be initialized with the ID if the CPU
    where the event was captured.

  \return SCAP_SUCCESS if the call is succesful and pevent and pcpuid contain valid data.
   SCAP_TIMEOUT in case the read timeout expired and no event is available.
   SCAP_EOF when the end of an offline capture is reached.
   On Failure, SCAP_FAILURE is returned and scap_getlasterr() can be used to obtain the cause of the error.
*/
static __always_inline int32_t scap_next(scap_t* handle, OUT scap_evt** pevent, OUT uint16_t* pcpuid)
{
	int32_t res;

	if(handle->m_file)
	{
		res = scap_next_offline(handle, pevent, pcpuid);
	}
	else
	{
		res = scap_next_live(handle, pevent, pcpuid);
	}

	if(res == SCAP_SUCCESS)
	{
		handle->m_evtcnt++;
	}

	return res;
}

#ifdef __cplusplus
}
#endif