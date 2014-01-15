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
