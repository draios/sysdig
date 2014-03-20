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

#pragma once

#include "internal_metrics.h"

#ifdef GATHER_INTERNAL_STATS

//
// Processing stats class.
// Keeps a bunch of counters with key library performance metrics.
//
class SINSP_PUBLIC sinsp_stats : public internal_metrics::processor
{
public:
	void clear();
	void emit(FILE* f);
	internal_metrics::registry& get_metrics_registry()
	{
		return m_metrics_registry;
	}

	void process(internal_metrics::counter& metric);

	uint64_t m_n_seen_evts;
	uint64_t m_n_drops;
	uint64_t m_n_preemptions;
	uint64_t m_n_noncached_fd_lookups;
	uint64_t m_n_cached_fd_lookups;
	uint64_t m_n_failed_fd_lookups;
	uint64_t m_n_threads;
	uint64_t m_n_fds;
	uint64_t m_n_added_fds;
	uint64_t m_n_removed_fds;
	uint64_t m_n_stored_evts;
	uint64_t m_n_store_drops;
	uint64_t m_n_retrieved_evts;
	uint64_t m_n_retrieve_drops;

private:
	internal_metrics::registry m_metrics_registry;
	FILE* m_output_target;
};

#endif // GATHER_INTERNAL_STATS
