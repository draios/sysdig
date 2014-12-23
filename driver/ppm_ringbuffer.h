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

#ifndef PPM_H_
#define PPM_H_

#ifdef __KERNEL__
#include <linux/types.h>
#endif

static const __u32 RING_BUF_SIZE = 8 * 1024 * 1024;
static const __u32 MIN_USERSPACE_READ_SIZE = 128 * 1024;

/*
 * This gets mapped to user level, so we want to keep it as clean as possible
 */
struct ppm_ring_buffer_info {
	volatile __u32 head;
	volatile __u32 tail;
	volatile __u64 n_evts;			/* Total number of events that were received by the driver. */
	volatile __u64 n_drops_buffer;		/* Number of dropped events (buffer full). */
	volatile __u64 n_drops_pf;		/* Number of dropped events (page faults). */
	volatile __u64 n_preemptions;		/* Number of preemptions. */
	volatile __u64 n_context_switches;	/* Number of received context switch events. */
};

#endif /* PPM_H_ */
