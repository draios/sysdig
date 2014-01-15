#pragma once

#ifndef VISIBILITY_PRIVATE
#define VISIBILITY_PRIVATE private:
#endif

class sinsp_delays_info;
class sinsp_threadtable_listener;
class thread_analyzer_info;

typedef struct erase_fd_params
{
	bool m_remove_from_table;
	sinsp* m_inspector;
	int64_t m_fd;
	sinsp_threadinfo* m_tinfo;
	sinsp_fdinfo_t* m_fdinfo;
	uint64_t m_ts;
}erase_fd_params;

///////////////////////////////////////////////////////////////////////////////
// thread info entry
///////////////////////////////////////////////////////////////////////////////
class SINSP_PUBLIC sinsp_threadinfo
{
public:
	sinsp_threadinfo();
	void init();
	//sinsp_threadinfo(const sinsp_threadinfo &orig);
	sinsp_threadinfo(sinsp *inspector);
	~sinsp_threadinfo();
	void init(const scap_threadinfo* pi);
	string get_comm();
	string get_exe();
	string get_cwd();
	void set_args(const char* args, size_t len);
	void store_event(sinsp_evt *evt);
	bool is_lastevent_data_valid();
	void set_lastevent_data_validity(bool isvalid);
	bool is_main_thread();
	sinsp_threadinfo* get_main_thread();
	sinsp_fdinfo_t *get_fd(int64_t fd);
	void* get_private_state(uint32_t id);

	void print_on(FILE *f);

	//
	// Core state
	//
	int64_t m_tid;  // The id of this thread
	int64_t m_pid; // The id of the process containing this thread. In single thread threads, this is equal to tid.
	int64_t m_ptid; // The id of the process that started this thread.
	int64_t m_progid; // Main program id. If this process is part of a logical group of processes (e.g. it's one of the apache processes), the tid of the process that is the head of this group.
	string m_comm; // Command name (e.g. "top")
	string m_exe; // Full command name (e.g. "/bin/top")
	vector<string> m_args; // Command line arguments (e.g. "-d1")
	uint32_t m_flags; // The thread flags. See the PPM_CL_* declarations in ppm_events_public.h.
	int64_t m_fdlimit;  // The maximum number of FDs this thread can open
	uint32_t m_fd_usage_pct; // The ratio between open FDs and maximum available FDs for this thread
	uint32_t m_uid; // user id
	uint32_t m_gid; // group id
	uint64_t m_nchilds; // When this is 0 the process can be deleted

	//
	// State for multi-event processing
	//
	uint8_t m_lastevent_data[SP_EVT_BUF_SIZE]; // Used by some event parsers to store the last enter event
	int64_t m_lastevent_fd;
	uint64_t m_lastevent_ts;	// timestamp of the last event for this thread
	uint64_t m_prevevent_ts;	// timestamp of the event before the last for this thread
	uint16_t m_lastevent_type;
	uint16_t m_lastevent_cpuid;
	uint64_t m_lastaccess_ts;
	sinsp_evt::category m_lastevent_category;

	thread_analyzer_info* m_ainfo;

#ifdef HAS_FILTERING
	//
	// State for filtering
	//
	uint64_t m_last_latency_entertime;
	uint64_t m_latency;
#endif

	//
	// Global state
	//
	sinsp *m_inspector;

VISIBILITY_PRIVATE
	void fix_sockets_coming_from_proc();
	void add_fd(int64_t fd, sinsp_fdinfo_t *fdinfo);
	void remove_fd(int64_t fd);
	sinsp_fdtable* get_fd_table();
	void set_cwd(const char *cwd, uint32_t cwdlen);
	sinsp_threadinfo* get_cwd_root();
	void allocate_private_state();

	//  void push_fdop(sinsp_fdop* op);
	// the queue of recent fd operations
	//  std::deque<sinsp_fdop> m_last_fdop;

	//
	// Parameters that can't be accessed directly because they could be in the
	// parent thread info
	//
	sinsp_fdtable m_fdtable; // The fd table of this thread
	string m_cwd; // current working directory
	sinsp_threadinfo* m_main_thread;
	sinsp_threadinfo* m_main_program_thread;
	vector<void*> m_private_state;

	friend class sinsp;
	friend class sinsp_parser;
	friend class sinsp_analyzer;
	friend class sinsp_evt;
	friend class sinsp_thread_manager;
	friend class sinsp_transaction_table;
	friend class thread_analyzer_info;
};

typedef unordered_map<int64_t, sinsp_threadinfo> threadinfo_map_t;
typedef threadinfo_map_t::iterator threadinfo_map_iterator_t;


///////////////////////////////////////////////////////////////////////////////
// Little class that manages the allocation of private state in the thread info class
///////////////////////////////////////////////////////////////////////////////
class sinsp_thread_privatestate_manager
{
public:
	//
	// The return value is the ID of the newly reserved memory area
	//
	uint32_t reserve(uint32_t size)
	{
		m_memory_sizes.push_back(size);
		return m_memory_sizes.size() - 1;
	}

	uint32_t get_size()
	{
		return m_memory_sizes.size();
	}

private:
	vector<uint32_t> m_memory_sizes;

	friend class sinsp_threadinfo;
};

///////////////////////////////////////////////////////////////////////////////
// This class manages the thread table
///////////////////////////////////////////////////////////////////////////////
class SINSP_PUBLIC sinsp_thread_manager
{
public:
	sinsp_thread_manager(sinsp* inspector);
	void clear();

	void set_listener(sinsp_threadtable_listener* listener);
	sinsp_threadinfo* get_thread(int64_t tid);
	void add_thread(sinsp_threadinfo& threadinfo, bool from_scap_proctable=false);
	void remove_thread(int64_t tid);
	void remove_thread(threadinfo_map_iterator_t it);
	void remove_inactive_threads();
	void fix_sockets_coming_from_proc();

	uint32_t get_thread_count()
	{
		return m_threadtable.size();
	}

	void update_statistics();

	threadinfo_map_t* get_threads()
	{
		return &m_threadtable;
	}

	set<uint16_t> m_server_ports;

private:
	void increment_mainthread_childcount(sinsp_threadinfo* threadinfo);
	void increment_program_childcount(sinsp_threadinfo* threadinfo);
	// Don't set level, it's for internal use
	void decrement_program_childcount(sinsp_threadinfo* threadinfo, uint32_t level = 0);

	sinsp* m_inspector;
	threadinfo_map_t m_threadtable;
	int64_t m_last_tid;
	sinsp_threadinfo* m_last_tinfo;
	uint64_t m_last_flush_time_ns;
	uint32_t m_n_drops;

	sinsp_threadtable_listener* m_listener;

	INTERNAL_COUNTER(m_failed_lookups);
	INTERNAL_COUNTER(m_cached_lookups);
	INTERNAL_COUNTER(m_non_cached_lookups);
	INTERNAL_COUNTER(m_added_threads);
	INTERNAL_COUNTER(m_removed_threads);

	friend class sinsp_parser;
	friend class sinsp_analyzer;
	friend class sinsp;
	friend class sinsp_threadinfo;
};
