#ifndef PPM_H_
#define PPM_H_

#include "ppm_types.h"

static const uint32_t RING_BUF_SIZE = 1024 * 1024;
static const uint32_t MIN_USERSPACE_READ_SIZE = 128 * 1024;

//
// This gets mapped to user level, so we want to keep it as clean as possible
//
struct ppm_ring_buffer_info
{
	volatile uint32_t head;
	volatile uint32_t tail;
	volatile uint64_t n_evts;				// Total number of events that were received by the driver.
	volatile uint64_t n_drops_buffer;		// Number of dropped events (buffer full).
	volatile uint64_t n_drops_pf;			// Number of dropped events (page faults).
	volatile uint64_t n_preemptions;		// Number of preemptions.
	volatile uint64_t n_context_switches;	// Number of received context switch events.
};

#endif /* PPM_H_ */
