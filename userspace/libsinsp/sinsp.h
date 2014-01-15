////////////////////////////////////////////////////////////////////////////
// Public definitions for the scap library
////////////////////////////////////////////////////////////////////////////
#pragma once
#ifdef _WIN32
#pragma warning(disable: 4251)
#endif

#ifdef _WIN32
#define SINSP_PUBLIC __declspec(dllexport)
#include <Ws2tcpip.h>
#else
#define SINSP_PUBLIC
#include <arpa/inet.h>
#endif

#define __STDC_FORMAT_MACROS

#include <string>
#include <unordered_map>
#include <map>
#include <queue>
#include <vector>
#include <set>

using namespace std;

#include <scap.h>
#include "settings.h"
#include "logger.h"
#include "event.h"
#include "filter.h"
#include "dumper.h"
#include "stats.h"
#include "ifinfo.h"

#ifndef VISIBILITY_PRIVATE
#define VISIBILITY_PRIVATE private:
#endif

#define ONE_SECOND_IN_NS 1000000000LL

#include "tuples.h"
#include "fdinfo.h"
#include "threadinfo.h"
#include "ifinfo.h"
#include "eventformatter.h"

class sinsp_partial_transaction;
class sinsp_parser;
class sinsp_analyzer;
class sinsp_filter;

//
// Exception class
//
struct sinsp_exception : std::exception
{
	sinsp_exception()
	{
	}

	~sinsp_exception() throw() 
	{
	}

	sinsp_exception(string error_str)
	{
		m_error_str = error_str;
	}

	char const* what() const throw()
	{ 
		return m_error_str.c_str();
	}

	string m_error_str;
};

//
// Filter check information
//
class filter_check_info
{
public:
	string m_name;
	int32_t m_nfiedls;
	const filtercheck_field_info* m_fields;
};

//
// The root system inspection class
//
class SINSP_PUBLIC sinsp
{
public:
	typedef class sinsp_ipv4_connection_manager sinsp_ipv4_connection_manager;
	typedef class sinsp_unix_connection_manager sinsp_unix_connection_manager;
	typedef class sinsp_pipe_connection_manager sinsp_pipe_connection_manager;
	typedef class sinsp_connection sinsp_connection;

	
	sinsp();
	~sinsp();
	//
	// Start a live capture
	//
	void open(uint32_t timeout_ms = SCAP_TIMEOUT_MS);

	//
	// Open a capture file
	//
	void open(string filename);

	//
	// Close capture file and release all
	// resources
	//
	void close();

	//
	// Get the next event
	//
	int32_t next(OUT sinsp_evt** evt);

	//
	// Get the number of captured events
	//
	uint64_t get_num_events();

	//
	// Stop event capture
	//
	void set_snaplen(uint32_t snaplen);

	//
	// Stop event capture
	//
	void stop_capture();

	//
	// Start event capture
	//
	void start_capture();
	
	//
	// Drop mode control
	//
	void stop_dropping_mode();
	void start_dropping_mode(uint32_t sampling_ratio);
	
#ifdef HAS_FILTERING
	//
	// Set the capture filter. Only in debug mode for the moment.
	//
	void set_filter(string filter);
#endif

	//
	// Get the last error
	//
	string getlasterr()
	{
		return m_lasterr;
	}

	//
	// Set the target for the log strings
	//
	void set_log_callback(sinsp_logger_callback cb);

	void import_ipv4_interface(const sinsp_ipv4_ifinfo& ifinfo);

	//
	// Automatic event dump support
	//
	void autodump_start(const string dump_filename);
	void autodump_stop();

	//
	// Populate the given vector with the full list of filter check fields
	//
	static void get_filtercheck_fields_info(vector<const filter_check_info*>* list);

	bool has_metrics();

	//
	// Get information about the physical machine generating the events
	//
	const scap_machine_info* get_machine_info();

	//
	// Return a thread's information given its tid
	//
	sinsp_threadinfo* get_thread(int64_t tid, bool query_os_if_not_found);
	sinsp_threadinfo* get_thread(int64_t tid);

	const unordered_map<uint32_t, scap_userinfo*>* get_userlist();
	const unordered_map<uint32_t, scap_groupinfo*>* get_grouplist();

	//
	// Allocates private state in the thread info class.
	// Returns the ID to use when retrieving the memory area.
	// Will fail if called after the capture starts.
	//
	uint32_t reserve_thread_memory(uint32_t size);

	//
	// Fill the given structure with live capture statistics
	//
	void get_capture_stats(scap_stats* stats);


#ifdef GATHER_INTERNAL_STATS
	sinsp_stats get_stats();
#endif

#ifdef HAS_ANALYZER
	sinsp_analyzer* m_analyzer;
#endif

VISIBILITY_PRIVATE

	void init();
	void import_thread_table();
	void import_ifaddr_list();
	void import_user_list();

	void add_thread(const sinsp_threadinfo& ptinfo);
	void remove_thread(int64_t tid);

	scap_t* m_h;
	bool m_islive;
	sinsp_evt m_evt;
	string m_lasterr;
	int64_t m_tid_to_remove;
	int64_t m_tid_of_fd_to_remove;
	vector<int64_t>* m_fds_to_remove;
	uint64_t m_lastevent_ts;
	// the parsing engine
	sinsp_parser* m_parser;
	// the statistics analysis engine
	scap_dumper_t* m_dumper;
	const scap_machine_info* m_machine_info;
	uint32_t m_num_cpus;
	sinsp_thread_privatestate_manager m_thread_privatestate_manager;

	sinsp_network_interfaces* m_network_interfaces;

	sinsp_thread_manager* m_thread_manager;

#ifdef HAS_FILTERING
	uint64_t m_firstevent_ts;
	sinsp_filter* m_filter;
#endif

	//
	// Internal stats
	//
#ifdef GATHER_INTERNAL_STATS
	sinsp_stats m_stats;
#endif

	//
	// Some thread table limits
	//
	uint32_t m_max_thread_table_size;
	uint64_t m_thread_timeout_ns;
	uint64_t m_inactive_thread_scan_time_ns;

	//
	// User and group tables
	//
	unordered_map<uint32_t, scap_userinfo*> m_userlist;
	unordered_map<uint32_t, scap_groupinfo*> m_grouplist;

	//
	// Some dropping infrastructure
	//
	bool m_isdropping;

	friend class sinsp_parser;
	friend class sinsp_analyzer;
	friend class sinsp_evt;
	friend class sinsp_threadinfo;
	friend class sinsp_fdtable;
	friend class sinsp_thread_manager;
	friend class sinsp_dumper;

	template<class TKey,class THash,class TCompare> friend class sinsp_connection_manager;
};
