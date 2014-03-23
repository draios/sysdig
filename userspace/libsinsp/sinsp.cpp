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


#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <poll.h>
#endif // _WIN32

#include "sinsp.h"
#include "sinsp_int.h"
#include "filter.h"
#include "filterchecks.h"
#ifdef HAS_ANALYZER
#include "analyzer_int.h"
#include "analyzer.h"
#endif
//#include "drfilterParser.h"

extern sinsp_evttables g_infotables;
extern vector<chiseldir_info>* g_chisel_dirs;

///////////////////////////////////////////////////////////////////////////////
// sinsp implementation
///////////////////////////////////////////////////////////////////////////////
sinsp::sinsp() :
	m_evt(this)
{
	m_h = NULL;
	m_parser = NULL;
	m_dumper = NULL;
	m_network_interfaces = NULL;
	m_parser = new sinsp_parser(this);
	m_thread_manager = new sinsp_thread_manager(this);
	m_max_thread_table_size = MAX_THREAD_TABLE_SIZE;
	m_thread_timeout_ns = DEFAULT_THREAD_TIMEOUT_S * ONE_SECOND_IN_NS;
	m_inactive_thread_scan_time_ns = DEFAULT_INACTIVE_THREAD_SCAN_TIME_S * ONE_SECOND_IN_NS;

#ifdef HAS_ANALYZER
	m_analyzer = NULL;
#endif

#ifdef HAS_FILTERING
	m_filter = NULL;
	m_firstevent_ts = 0;
#endif

	m_fds_to_remove = new vector<int64_t>;
	m_machine_info = NULL;
	m_isdropping = false;
	m_n_proc_lookups = 0;
	m_max_n_proc_lookups = 0;
	m_max_n_proc_socket_lookups = 0;
	m_snaplen = DEFAULT_SNAPLEN;
	m_buffer_format = sinsp_evt::PF_NORMAL;
}

sinsp::~sinsp()
{
	close();

	if(m_fds_to_remove)
	{
		delete m_fds_to_remove;
	}

	if(m_parser)
	{
		delete m_parser;
		m_parser = NULL;
	}

	if(m_thread_manager)
	{
		delete m_thread_manager;
		m_thread_manager = NULL;
	}
}

void sinsp::open(uint32_t timeout_ms)
{
	char error[SCAP_LASTERR_SIZE];

	g_logger.log("starting live capture");

	m_islive = true;
	m_h = scap_open_live(error);

	if(m_h == NULL)
	{
		throw sinsp_exception(error);
	}

	init();
}

void sinsp::open(string filename)
{
	char error[SCAP_LASTERR_SIZE];

	m_islive = false;

	if(filename == "")
	{
		open();
		return;
	}

	g_logger.log("starting offline capture");

	m_h = scap_open_offline((char *)filename.c_str(), error);

	if(m_h == NULL)
	{
		throw sinsp_exception(error);
	}

	m_filename = filename;

	init();
}

void sinsp::close()
{
	if(m_h)
	{
		scap_close(m_h);
		m_h = NULL;
	}

	if(NULL != m_dumper)
	{
		scap_dump_close(m_dumper);
		m_dumper = NULL;
	}

	if(NULL != m_network_interfaces)
	{
		delete m_network_interfaces;
		m_network_interfaces = NULL;
	}

#ifdef HAS_FILTERING
	if(m_filter != NULL)
	{
		delete m_filter;
	}
#endif
}

void sinsp::autodump_start(const string dump_filename)
{
	if(NULL == m_h)
	{
		throw sinsp_exception("inspector not opened yet");
	}

	m_dumper = scap_dump_open(m_h, dump_filename.c_str());
	if(NULL == m_dumper)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

void sinsp::autodump_stop()
{
	if(NULL == m_h)
	{
		throw sinsp_exception("inspector not opened yet");
	}

	if(m_dumper != NULL)
	{
		scap_dump_close(m_dumper);
		m_dumper = NULL;
	}
}

void sinsp::import_thread_table()
{
	scap_threadinfo *pi;
	scap_threadinfo *tpi;
	sinsp_threadinfo newti(this);

	scap_threadinfo *table = scap_get_proc_table(m_h);

	//
	// Scan the scap table and add the threads to our list
	//
	HASH_ITER(hh, table, pi, tpi)
	{
		newti.init(pi);
		m_thread_manager->add_thread(newti, true);
	}

	//
	// Scan the list to create the proper parent/child dependencies
	//
	threadinfo_map_iterator_t it;
	for(it = m_thread_manager->m_threadtable.begin(); 
		it != m_thread_manager->m_threadtable.end(); ++it)
	{
		m_thread_manager->increment_mainthread_childcount(&it->second);
		m_thread_manager->increment_program_childcount(&it->second);
	}

	//
	// Scan the list to fix the direction of the sockets
	//
	m_thread_manager->fix_sockets_coming_from_proc();
}

void sinsp::import_ifaddr_list()
{
	m_network_interfaces = new sinsp_network_interfaces;
	m_network_interfaces->import_interfaces(scap_get_ifaddr_list(m_h));
}

sinsp_network_interfaces* sinsp::get_ifaddr_list()
{
	return m_network_interfaces;
}

void sinsp::import_user_list()
{
	uint32_t j;
	scap_userlist* ul = scap_get_user_list(m_h);

	for(j = 0; j < ul->nusers; j++)
	{
		m_userlist[ul->users[j].uid] = &(ul->users[j]); 
	}

	for(j = 0; j < ul->ngroups; j++)
	{
		m_grouplist[ul->groups[j].gid] = &(ul->groups[j]); 
	}
}

void sinsp::import_ipv4_interface(const sinsp_ipv4_ifinfo& ifinfo)
{
	ASSERT(m_network_interfaces);
	m_network_interfaces->import_ipv4_interface(ifinfo);
}

void sinsp::init()
{
	//
	// Retrieve machine information
	//
	m_machine_info = scap_get_machine_info(m_h);
	if(m_machine_info != NULL)
	{
		m_num_cpus = m_machine_info->num_cpus;
	}
	else
	{
		ASSERT(false);
		m_num_cpus = 0;
	}

	//
	// Reset the thread manager
	//
	m_thread_manager->clear();

	//
	// Basic inits
	//
#ifdef GATHER_INTERNAL_STATS
	m_stats.clear();
#endif

	m_tid_to_remove = -1;
	m_lastevent_ts = 0;

	import_ifaddr_list();
	import_thread_table();
	import_user_list();

#ifdef HAS_ANALYZER
	//
	// Notify the analyzer that we're starting
	//
	if(m_analyzer)
	{
		m_analyzer->on_capture_start();
	}
#endif

	//
	// If m_snaplen was modified, we set snaplen now
	//
	if (m_snaplen != DEFAULT_SNAPLEN)
	{
		set_snaplen(m_snaplen);
	}
}

bool should_drop(sinsp_evt *evt, bool* stopped, bool* switched);

int32_t sinsp::next(OUT sinsp_evt **evt)
{
	//
	// Get the event from libscap
	//
	int32_t res = scap_next(m_h, &(m_evt.m_pevt), &(m_evt.m_cpuid));
	if(res != SCAP_SUCCESS)
	{
		if(res == SCAP_TIMEOUT)
		{
			return res;
		}
		else if(res == SCAP_EOF)
		{
#ifdef HAS_ANALYZER
			if(m_analyzer)
			{
				m_analyzer->process_event(NULL, sinsp_analyzer::DF_NONE);
			}
#endif
		}
		else
		{
			throw sinsp_exception(scap_getlasterr(m_h));
		}

		return res;
	}

	//
	// Store a couple of values that we'll need later inside the event.
	//
	m_evt.m_evtnum = get_num_events();
	m_lastevent_ts = m_evt.get_ts();
#ifdef HAS_FILTERING
	if(m_firstevent_ts == 0)
	{
		m_firstevent_ts = m_lastevent_ts;
	}
#endif

#ifndef HAS_ANALYZER
	//
	// Deleayed removal of threads from the thread table, so that
	// things like exit() or close() can be parsed.
	// We only do this if the analyzer is not enabled, because the analyzer
	// needs the process at the end of the sample and will take care of deleting
	// it.
	//
	if(m_tid_to_remove != -1)
	{
		remove_thread(m_tid_to_remove);
		m_tid_to_remove = -1;
	}

	//
	// Run the periodic connection and thread table cleanup
	//
	m_thread_manager->remove_inactive_threads();
#endif // HAS_ANALYZER

	//
	// Deleayed removal of the fd, so that
	// things like exit() or close() can be parsed.
	//
	uint32_t nfdr = m_fds_to_remove->size();

	if(nfdr != 0)
	{
		sinsp_threadinfo* ptinfo = get_thread(m_tid_of_fd_to_remove, true);
		if(!ptinfo)
		{
			ASSERT(false);
			return res;
		}

		for(uint32_t j = 0; j < nfdr; j++)
		{
			ptinfo->remove_fd(m_fds_to_remove->at(j));
		}

		m_fds_to_remove->clear();
	}

#ifdef SIMULATE_DROP_MODE
	bool sd = false;
	bool sw = false;

	if(m_analyzer)
	{
		m_analyzer->m_configuration->set_analyzer_sample_len_ns(500000000);
	}

	sd = should_drop(&m_evt, &m_isdropping, &sw);
#endif

	//
	// Run the state engine
	//
#ifdef SIMULATE_DROP_MODE
	if(!sd || m_isdropping)
	{
		m_parser->process_event(&m_evt);
	}

	if(sd && !m_isdropping)
	{
		return SCAP_TIMEOUT;
	}
#else
	m_parser->process_event(&m_evt);
#endif

#if defined(HAS_FILTERING) && defined(HAS_CAPTURE_FILTERING)
	if(m_evt.m_filtered_out)
	{
		return SCAP_TIMEOUT;
	}
#endif

	//
	// If needed, dump the event to file
	//
	if(NULL != m_dumper)
	{
		res = scap_dump(m_h, m_dumper, m_evt.m_pevt, m_evt.m_cpuid);
		if(SCAP_SUCCESS != res)
		{
			throw sinsp_exception(scap_getlasterr(m_h));
		}
	}

	//
	// Run the analysis engine
	//
#ifdef HAS_ANALYZER
	if(m_analyzer)
	{
#ifdef SIMULATE_DROP_MODE
		if(!sd || m_isdropping || sw)
		{
			if(m_isdropping)
			{
				m_analyzer->process_event(&m_evt, sinsp_analyzer::DF_FORCE_FLUSH);
			}
			else if(sw)
			{
				m_analyzer->process_event(&m_evt, sinsp_analyzer::DF_FORCE_FLUSH_BUT_DONT_EMIT);
			}
			else
			{
				m_analyzer->process_event(&m_evt, sinsp_analyzer::DF_FORCE_NOFLUSH);
			}
		}
#else // SIMULATE_DROP_MODE
		m_analyzer->process_event(&m_evt, sinsp_analyzer::DF_NONE);
#endif // SIMULATE_DROP_MODE
	}
#endif

	//
	// Update the last event time for this thread
	//
	if(m_evt.m_tinfo)
	{
		m_evt.m_tinfo->m_prevevent_ts = m_evt.m_tinfo->m_lastevent_ts;
		m_evt.m_tinfo->m_lastevent_ts = m_lastevent_ts;
	}

	//
	// Done
	//
	*evt = &m_evt;
	return res;
}

uint64_t sinsp::get_num_events()
{
	return scap_event_get_num(m_h);
}

sinsp_threadinfo* sinsp::get_thread(int64_t tid, bool query_os_if_not_found)
{
	sinsp_threadinfo* sinsp_proc = m_thread_manager->get_thread(tid);

	if(sinsp_proc == NULL && query_os_if_not_found)
	{
		sinsp_threadinfo newti(this);
		scap_threadinfo* scap_proc = NULL;
		m_n_proc_lookups++;

		if(m_n_proc_lookups == m_max_n_proc_socket_lookups)
		{
			g_logger.format(sinsp_logger::SEV_INFO, "Reached max socket lookup number");
		}

		if(m_n_proc_lookups == m_max_n_proc_lookups)
		{
			g_logger.format(sinsp_logger::SEV_INFO, "Reached max processs lookup number");
		}

		if(m_max_n_proc_lookups == 0 || (m_max_n_proc_lookups != 0 &&
			(m_n_proc_lookups <= m_max_n_proc_lookups)))
		{
			bool scan_sockets = true;

			if(m_max_n_proc_socket_lookups == 0 || (m_max_n_proc_socket_lookups != 0 &&
				(m_n_proc_lookups <= m_max_n_proc_socket_lookups)))
			{
				scan_sockets = false;
			}

			scap_proc = scap_proc_get(m_h, tid, scan_sockets);
		}

		if(scap_proc)
		{
			newti.init(scap_proc);
			scap_proc_free(m_h, scap_proc);
		}
		else
		{
			//
			// Add a fake entry to avoid a continuous lookup
			//
			newti.m_tid = tid;
			newti.m_pid = tid;
			newti.m_ptid = -1;
			newti.m_comm = "<NA>";
			newti.m_exe = "<NA>";
			newti.m_uid = 0xffffffff;
			newti.m_gid = 0xffffffff;
		}

		m_thread_manager->add_thread(newti);
		sinsp_proc = m_thread_manager->get_thread(tid);
	}

	return sinsp_proc;
}

sinsp_threadinfo* sinsp::get_thread(int64_t tid)
{
	return get_thread(tid, false);
}

void sinsp::add_thread(const sinsp_threadinfo& ptinfo)
{
	m_thread_manager->add_thread((sinsp_threadinfo&)ptinfo);
}

void sinsp::remove_thread(int64_t tid)
{
	m_thread_manager->remove_thread(tid);
}

void sinsp::set_snaplen(uint32_t snaplen)
{
	//
	// If set_snaplen is called before opening of the inspector,
	// we register the value to be set after its initialization.
	//
	if (m_h == NULL)
	{
		m_snaplen = snaplen;
		return;
	}

	if(scap_set_snaplen(m_h, snaplen) != SCAP_SUCCESS)
	{
		//
		// We know that setting the snaplen on a file doesn't do anything and
		// we're ok with it.
		//
		if(m_islive)
		{
			throw sinsp_exception(scap_getlasterr(m_h));
		}
	}	
}

void sinsp::stop_capture()
{
	if(scap_stop_capture(m_h) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

void sinsp::start_capture()
{
	if(scap_start_capture(m_h) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

void sinsp::stop_dropping_mode()
{
	if(scap_stop_dropping_mode(m_h) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

void sinsp::start_dropping_mode(uint32_t sampling_ratio)
{
	if(m_islive)
	{
		if(scap_start_dropping_mode(m_h, sampling_ratio) != SCAP_SUCCESS)
		{
			throw sinsp_exception(scap_getlasterr(m_h));
		}
	}
}

#ifdef HAS_FILTERING
void sinsp::set_filter(string filter)
{
	if(m_filter != NULL)
	{
		ASSERT(false);
		throw sinsp_exception("filter can only be set once");
	}

	m_filter = new sinsp_filter(this, filter);
}
#endif

const scap_machine_info* sinsp::get_machine_info()
{
	return m_machine_info;
}

const unordered_map<uint32_t, scap_userinfo*>* sinsp::get_userlist()
{
	return &m_userlist;
}

const unordered_map<uint32_t, scap_groupinfo*>* sinsp::get_grouplist()
{
	return &m_grouplist;
}

#ifdef HAS_FILTERING
void sinsp::get_filtercheck_fields_info(OUT vector<const filter_check_info*>* list)
{
	sinsp_utils::get_filtercheck_fields_info(list);
}
#else
void sinsp::get_filtercheck_fields_info(OUT vector<const filter_check_info*>* list)
{
}
#endif

uint32_t sinsp::reserve_thread_memory(uint32_t size)
{
	if(m_h != NULL)
	{
		throw sinsp_exception("reserve_thread_memory can't be called after capture starts");
	}

	return m_thread_privatestate_manager.reserve(size);
}

void sinsp::get_capture_stats(scap_stats* stats)
{
	if(scap_get_stats(m_h, stats) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

#ifdef GATHER_INTERNAL_STATS
sinsp_stats sinsp::get_stats()
{
	scap_stats stats;

	//
	// Get capture stats from scap
	//
	if(m_h)
	{
		scap_get_stats(m_h, &stats);

		m_stats.m_n_seen_evts = stats.n_evts;
		m_stats.m_n_drops = stats.n_drops;
		m_stats.m_n_preemptions = stats.n_preemptions;
	}
	else
	{
		m_stats.m_n_seen_evts = 0;
		m_stats.m_n_drops = 0;
		m_stats.m_n_preemptions = 0;
	}

	//
	// Count the number of threads and fds by scanning the tables,
	// and update the thread-related stats.
	//
	if(m_thread_manager)
	{
		m_thread_manager->update_statistics();
	}

	//
	// Return the result
	//

	return m_stats;
}
#endif // GATHER_INTERNAL_STATS

void sinsp::set_log_callback(sinsp_logger_callback cb)
{
	g_logger.add_callback_log(cb);
}

sinsp_evttables* sinsp::get_event_info_tables()
{
	return &g_infotables;
}

void sinsp::add_chisel_dir(string dirname)
{
	if(dirname[dirname.size() -1] != '/')
	{
		dirname += "/";
	}

	chiseldir_info ncdi;

	strcpy(ncdi.m_dir, dirname.c_str());
	ncdi.m_need_to_resolve = false;

	g_chisel_dirs->push_back(ncdi);
}

void sinsp::set_buffer_format(sinsp_evt::param_fmt format)
{
	m_buffer_format = format;
}

sinsp_evt::param_fmt sinsp::get_buffer_format()
{
	return m_buffer_format;
}

bool sinsp::is_live()
{
	return m_islive;
}