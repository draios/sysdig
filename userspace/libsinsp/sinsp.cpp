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

#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/time.h>
#endif // _WIN32

#include "sinsp.h"
#include "sinsp_int.h"
#include "filter.h"
#include "filterchecks.h"
#include "cyclewriter.h"
#include "protodecoder.h"
#ifdef HAS_ANALYZER
#include "analyzer_int.h"
#include "analyzer.h"
#endif

extern sinsp_evttables g_infotables;
#ifdef HAS_CHISELS
extern vector<chiseldir_info>* g_chisel_dirs;
#endif

void on_new_entry_from_proc(void* context, int64_t tid, scap_threadinfo* tinfo, 
							scap_fdinfo* fdinfo, scap_t* newhandle); 

///////////////////////////////////////////////////////////////////////////////
// sinsp implementation
///////////////////////////////////////////////////////////////////////////////
sinsp::sinsp() :
	m_evt(this),
	m_container_manager(this)
{
	m_h = NULL;
	m_nevts = 0;
	m_parser = NULL;
	m_dumper = NULL;
	m_metaevt = NULL;
	m_skipped_evt = NULL;
	m_meinfo.m_piscapevt = NULL;
	m_network_interfaces = NULL;
	m_parser = new sinsp_parser(this);
	m_thread_manager = new sinsp_thread_manager(this);
	m_max_thread_table_size = MAX_THREAD_TABLE_SIZE;
	m_thread_timeout_ns = DEFAULT_THREAD_TIMEOUT_S * ONE_SECOND_IN_NS;
	m_inactive_thread_scan_time_ns = DEFAULT_INACTIVE_THREAD_SCAN_TIME_S * ONE_SECOND_IN_NS;
	m_inactive_container_scan_time_ns = DEFAULT_INACTIVE_CONTAINER_SCAN_TIME_S * ONE_SECOND_IN_NS;
	m_cycle_writer = NULL;
	m_write_cycling = false;
#ifdef HAS_ANALYZER
	m_analyzer = NULL;
#endif

#ifdef HAS_FILTERING
	m_filter = NULL;
#endif

	m_fds_to_remove = new vector<int64_t>;
	m_machine_info = NULL;
#ifdef SIMULATE_DROP_MODE
	m_isdropping = false;
#endif
	m_n_proc_lookups = 0;
	m_max_n_proc_lookups = 0;
	m_max_n_proc_socket_lookups = 0;
	m_snaplen = DEFAULT_SNAPLEN;
	m_buffer_format = sinsp_evt::PF_NORMAL;
	m_isdebug_enabled = false;
	m_isfatfile_enabled = false;
	m_max_evt_output_len = 0;
	m_filesize = -1;
	m_import_users = true;
	m_meta_evt_buf = new char[SP_EVT_BUF_SIZE];
	m_meta_evt.m_pevt = (scap_evt*) m_meta_evt_buf;
	m_meta_evt_pending = false;
	m_next_flush_time_ns = 0;
	m_last_procrequest_tod = 0;
	m_get_procs_cpu_from_driver = false;

	// Unless the cmd line arg "-pc" or "-pcontainer" is supplied this is false
	m_print_container_data = false;

#if defined(HAS_CAPTURE)
	m_sysdig_pid = 0;
#endif

	uint32_t evlen = sizeof(scap_evt) + 2 * sizeof(uint16_t) + 2 * sizeof(uint64_t);
	m_meinfo.m_piscapevt = (scap_evt*)new char[evlen];
	m_meinfo.m_piscapevt->type = PPME_PROCINFO_E;
	m_meinfo.m_piscapevt->len = evlen;
	uint16_t* lens = (uint16_t*)((char *)m_meinfo.m_piscapevt + sizeof(struct ppm_evt_hdr));
	lens[0] = 8;
	lens[1] = 8;
	m_meinfo.m_piscapevt_vals = (uint64_t*)(lens + 2);

	m_meinfo.m_pievt.m_inspector = this;
	m_meinfo.m_pievt.m_info = &(g_infotables.m_event_info[PPME_SYSDIGEVENT_X]);
	m_meinfo.m_pievt.m_pevt = NULL;
	m_meinfo.m_pievt.m_cpuid = 0;
	m_meinfo.m_pievt.m_evtnum = 0;
	m_meinfo.m_pievt.m_pevt = m_meinfo.m_piscapevt;
	m_meinfo.m_pievt.m_fdinfo = NULL;
	m_meinfo.m_n_procinfo_evts = 0;
	m_meta_event_callback = NULL;
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

	if(m_cycle_writer)
	{
		delete m_cycle_writer;
		m_cycle_writer = NULL;
	}

	if(m_meta_evt_buf)
	{
		delete[] m_meta_evt_buf;
		m_meta_evt_buf = NULL;
	}

	if(m_meinfo.m_piscapevt)
	{
		delete[] m_meinfo.m_piscapevt;
	}
}

void sinsp::add_protodecoders()
{
	m_parser->add_protodecoder("syslog");
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
	// Attach the protocol decoders
	//
	add_protodecoders();

	//
	// Allocate the cycle writer
	//
	m_cycle_writer = new cycle_writer();

	//
	// Basic inits
	//
#ifdef GATHER_INTERNAL_STATS
	m_stats.clear();
#endif

	m_tid_to_remove = -1;
	m_lastevent_ts = 0;
#ifdef HAS_FILTERING
	m_firstevent_ts = 0;
#endif
	m_fds_to_remove->clear();
	m_n_proc_lookups = 0;

	if(m_islive == false)
	{
		import_thread_table();
	}

	import_ifaddr_list();

	import_user_list();

	//
	// Scan the list to create the proper parent/child dependencies
	//
	m_thread_manager->create_child_dependencies();

	//
	// Scan the list to fix the direction of the sockets
	//
	m_thread_manager->fix_sockets_coming_from_proc();

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
	if(m_snaplen != DEFAULT_SNAPLEN)
	{
		set_snaplen(m_snaplen);
	}

#if defined(HAS_CAPTURE)
	if(m_islive)
	{
		if(scap_getpid_global(m_h, &m_sysdig_pid) != SCAP_SUCCESS)
		{
			ASSERT(false);
		}
	}
#endif
}

void sinsp::set_import_users(bool import_users)
{
	m_import_users = import_users;
}

void sinsp::open(uint32_t timeout_ms)
{
	char error[SCAP_LASTERR_SIZE];

	g_logger.log("starting live capture");

	m_islive = true;

	//
	// Reset the thread manager
	//
	m_thread_manager->clear();

	//
	// Start the capture
	//
	scap_open_args oargs;
	oargs.fname = NULL;
	oargs.proc_callback = ::on_new_entry_from_proc;
	oargs.proc_callback_context = this;
	oargs.import_users = m_import_users;

	m_h = scap_open(oargs, error);

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

	m_input_filename = filename;

	g_logger.log("starting offline capture");

	//
	// Reset the thread manager
	//
	m_thread_manager->clear();

	//
	// Start the capture
	//
	scap_open_args oargs;
	oargs.fname = filename.c_str();
	oargs.proc_callback = NULL;
	oargs.proc_callback_context = NULL;
	oargs.import_users = m_import_users;

	m_h = scap_open(oargs, error);

	if(m_h == NULL)
	{
		throw sinsp_exception(error);
	}

	//
	// gianluca: This might need to be replaced with
	// a portable stat(), since I'm afraid that on S3
	// (that we'll use in the backend) the seek will
	// read the entire file anyway
	//
	FILE* fp = fopen(filename.c_str(), "rb");
	if(fp)
	{
		fseek(fp, 0L, SEEK_END);
		m_filesize = ftell(fp);
		fclose(fp);
	}

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
		m_filter = NULL;
	}
#endif
}

void sinsp::autodump_start(const string& dump_filename, bool compress)
{
	if(NULL == m_h)
	{
		throw sinsp_exception("inspector not opened yet");
	}

	if(compress)
	{
		m_dumper = scap_dump_open(m_h, dump_filename.c_str(), SCAP_COMPRESSION_GZIP);
	}
	else
	{
		m_dumper = scap_dump_open(m_h, dump_filename.c_str(), SCAP_COMPRESSION_NONE);
	}

	if(NULL == m_dumper)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}

	m_container_manager.dump_containers(m_dumper);
}

void sinsp::autodump_next_file()
{
	autodump_stop();
	autodump_start(m_cycle_writer->get_current_file_name(), m_compress);
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

void sinsp::on_new_entry_from_proc(void* context, 
								   int64_t tid, 
								   scap_threadinfo* tinfo, 
								   scap_fdinfo* fdinfo,
								   scap_t* newhandle)
{
	ASSERT(tinfo != NULL);

	//
	// Retrieve machine information if we don't have it yet
	//
	if(m_machine_info == NULL)
	{
		m_machine_info = scap_get_machine_info(newhandle);
		if(m_machine_info != NULL)
		{
			m_num_cpus = m_machine_info->num_cpus;
		}
		else
		{
			ASSERT(false);
			m_num_cpus = 0;
		}
	}

	//
	// Add the thread or FD
	//
	if(fdinfo == NULL)
	{
		sinsp_threadinfo newti(this);
		newti.init(tinfo);

		m_thread_manager->add_thread(newti, true);
	}
	else
	{
		sinsp_threadinfo* sinsp_tinfo = find_thread(tid, true);

		if(sinsp_tinfo == NULL)
		{
			sinsp_threadinfo newti(this);
			newti.init(tinfo);

			m_thread_manager->add_thread(newti, true);

			sinsp_tinfo = find_thread(tid, true);
			if(sinsp_tinfo == NULL)
			{
				ASSERT(false);
				return;
			}
		}

		sinsp_tinfo->add_fd(fdinfo);
	}
}

void on_new_entry_from_proc(void* context, 
							int64_t tid, 
							scap_threadinfo* tinfo, 
							scap_fdinfo* fdinfo,
							scap_t* newhandle)
{
	sinsp* _this = (sinsp*)context;
	_this->on_new_entry_from_proc(context, tid, tinfo, fdinfo, newhandle);
}

void sinsp::import_thread_table()
{
	scap_threadinfo *pi;
	scap_threadinfo *tpi;

	scap_threadinfo *table = scap_get_proc_table(m_h);

	//
	// Scan the scap table and add the threads to our list
	//
	HASH_ITER(hh, table, pi, tpi)
	{
		sinsp_threadinfo newti(this);
		newti.init(pi);
		m_thread_manager->add_thread(newti, true);
	}
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

	if(ul)
	{
		for(j = 0; j < ul->nusers; j++)
		{
			m_userlist[ul->users[j].uid] = &(ul->users[j]);
		}

		for(j = 0; j < ul->ngroups; j++)
		{
			m_grouplist[ul->groups[j].gid] = &(ul->groups[j]);
		}
	}
}

void sinsp::import_ipv4_interface(const sinsp_ipv4_ifinfo& ifinfo)
{
	ASSERT(m_network_interfaces);
	m_network_interfaces->import_ipv4_interface(ifinfo);
}

bool should_drop(sinsp_evt *evt, bool* stopped, bool* switched);

void sinsp::add_meta_event(sinsp_evt *metaevt)
{
	m_metaevt = metaevt;
}

void sinsp::add_meta_event_and_repeat(sinsp_evt *metaevt)
{
	m_metaevt = metaevt;
	m_skipped_evt = &m_evt;
}

void schedule_next_threadinfo_evt(sinsp* _this, void* data)
{
	sinsp_proc_metainfo* mei = (sinsp_proc_metainfo*)data;
	ASSERT(mei->m_pli != NULL);

	while(true)
	{
		ASSERT(mei->m_cur_procinfo_evt <= (int32_t)mei->m_n_procinfo_evts);
		ppm_proc_info* pi = &(mei->m_pli->entries[mei->m_cur_procinfo_evt]);

		if(mei->m_cur_procinfo_evt >= 0)
		{
			mei->m_piscapevt->tid = pi->pid;
			mei->m_piscapevt_vals[0] = pi->utime;
			mei->m_piscapevt_vals[1] = pi->stime;
		}

		mei->m_cur_procinfo_evt++;

		if(mei->m_cur_procinfo_evt < (int32_t)mei->m_n_procinfo_evts)
		{
			if(pi->utime == 0 && pi->stime == 0)
			{
				continue;
			}

			_this->add_meta_event(&mei->m_pievt);
		}
		else if(mei->m_cur_procinfo_evt == (int32_t)mei->m_n_procinfo_evts)
		{
			_this->add_meta_event(mei->m_next_evt);
		}

		break;
	}
}

int32_t sinsp::next(OUT sinsp_evt **puevt)
{
	sinsp_evt* evt;
	int32_t res;
	// The number of bytes to consider in the dumper
	int32_t bytes_to_write;

	//
	// Check if there are fake cpu events to  events 
	//
	if(m_metaevt != NULL)
	{
		res = SCAP_SUCCESS;
		evt = m_metaevt;

		if(m_skipped_evt)
		{
			m_metaevt = m_skipped_evt;
			m_skipped_evt = NULL;
		}
		else
		{
			m_metaevt = NULL;
		}

		if(m_meta_event_callback != NULL)
		{
			m_meta_event_callback(this, &m_meinfo);
		}
	}
	else
	{
		evt = &m_evt;

		//
		// Reset previous event's decoders if required
		//
		if(m_decoders_reset_list.size() != 0)
		{
			vector<sinsp_protodecoder*>::iterator it;
			for(it = m_decoders_reset_list.begin(); it != m_decoders_reset_list.end(); ++it)
			{
				(*it)->on_reset(evt);
			}

			m_decoders_reset_list.clear();
		}

		//
		// Get the event from libscap
		//
		res = scap_next(m_h, &(evt->m_pevt), &(evt->m_cpuid));

		if(res != SCAP_SUCCESS)
		{
			if(res == SCAP_TIMEOUT)
			{
	#ifdef HAS_ANALYZER
				if(m_analyzer)
				{
					m_analyzer->process_event(NULL, sinsp_analyzer::DF_TIMEOUT);
				}
	#endif
				evt = NULL;
				return res;
			}
			else if(res == SCAP_EOF)
			{
	#ifdef HAS_ANALYZER
				if(m_analyzer)
				{
					m_analyzer->process_event(NULL, sinsp_analyzer::DF_EOF);
				}
	#endif
			}
			else
			{
				throw sinsp_exception(scap_getlasterr(m_h));
			}

			return res;
		}
	}

	uint64_t ts = evt->get_ts();

	//
	// If required, retrieve the processes cpu from the kernel
	//
	if(m_get_procs_cpu_from_driver && m_islive)
	{
		if(ts > m_next_flush_time_ns)
		{
			if(m_next_flush_time_ns != 0)
			{
				struct timeval tod;
				gettimeofday(&tod, NULL);

				uint64_t procrequest_tod = (uint64_t)tod.tv_sec * 1000000000 + tod.tv_usec * 1000;

				if(procrequest_tod - m_last_procrequest_tod > ONE_SECOND_IN_NS / 2)
				{
					m_last_procrequest_tod = procrequest_tod;
					m_next_flush_time_ns = ts - (ts % ONE_SECOND_IN_NS) + ONE_SECOND_IN_NS;	

					m_meinfo.m_pli = scap_get_threadlist_from_driver(m_h);
					if(m_meinfo.m_pli == NULL)
					{
						throw sinsp_exception(string("scap error: ") + scap_getlasterr(m_h));
					}

					m_meinfo.m_n_procinfo_evts = m_meinfo.m_pli->n_entries;

					if(m_meinfo.m_n_procinfo_evts > 0)
					{
						m_meinfo.m_cur_procinfo_evt = -1;

						m_meinfo.m_piscapevt->ts = m_next_flush_time_ns - (ONE_SECOND_IN_NS + 1);
						m_meinfo.m_next_evt = &m_evt;
						m_meta_event_callback = &schedule_next_threadinfo_evt;
						schedule_next_threadinfo_evt(this, &m_meinfo);
					}

					return SCAP_TIMEOUT;
				}
			}

			m_next_flush_time_ns = ts - (ts % ONE_SECOND_IN_NS) + ONE_SECOND_IN_NS;
		}
	}

	//
	// Store a couple of values that we'll need later inside the event.
	//
	m_nevts++;
	evt->m_evtnum = m_nevts;
	m_lastevent_ts = ts;
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
		remove_thread(m_tid_to_remove, false);
		m_tid_to_remove = -1;
	}

	//
	// Run the periodic connection and thread table cleanup
	//
	if(m_islive)
	{
		m_thread_manager->remove_inactive_threads();
		m_container_manager.remove_inactive_containers();
	}
#endif // HAS_ANALYZER

	//
	// Deleayed removal of the fd, so that
	// things like exit() or close() can be parsed.
	//
	uint32_t nfdr = (uint32_t)m_fds_to_remove->size();

	if(nfdr != 0)
	{
		sinsp_threadinfo* ptinfo = get_thread(m_tid_of_fd_to_remove, true, true);
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

	sd = should_drop(evt, &m_isdropping, &sw);
#endif

	//
	// Run the state engine
	//
#ifdef SIMULATE_DROP_MODE
	if(!sd || m_isdropping)
	{
		m_parser->process_event(evt);
	}

	if(sd && !m_isdropping)
	{
		*evt = NULL;
		return SCAP_TIMEOUT;
	}
#else
	m_parser->process_event(evt);
#endif

	//
	// If needed, dump the event to file
	//
	if(NULL != m_dumper)
	{
		if(m_meta_evt_pending)
		{
			m_meta_evt_pending = false;
			res = scap_dump(m_h, m_dumper, m_meta_evt.m_pevt, m_meta_evt.m_cpuid, 0);
			if(SCAP_SUCCESS != res)
			{
				throw sinsp_exception(scap_getlasterr(m_h));
			}
		}

#if defined(HAS_FILTERING) && defined(HAS_CAPTURE_FILTERING)
		scap_dump_flags dflags;
		
		bool do_drop;
		dflags = evt->get_dump_flags(&do_drop);
		if(do_drop)
		{
			*puevt = evt;
			return SCAP_TIMEOUT;
		}
#endif

		if(m_write_cycling)
		{
			res = scap_number_of_bytes_to_write(evt->m_pevt, evt->m_cpuid, &bytes_to_write);
			if(SCAP_SUCCESS != res)
			{
				throw sinsp_exception(scap_getlasterr(m_h));
			}
			else 
			{
				switch(m_cycle_writer->consider(bytes_to_write))
				{
					case cycle_writer::NEWFILE:
						autodump_next_file();
						break;

					case cycle_writer::DOQUIT:
						stop_capture();
						return SCAP_EOF;
						break;

					case cycle_writer::SAMEFILE:
						// do nothing.
						break;
				}
			}
		}

		res = scap_dump(m_h, m_dumper, evt->m_pevt, evt->m_cpuid, dflags);
		if(SCAP_SUCCESS != res)
		{
			throw sinsp_exception(scap_getlasterr(m_h));
		}
	}

#if defined(HAS_FILTERING) && defined(HAS_CAPTURE_FILTERING)
	if(evt->m_filtered_out)
	{
		*puevt = evt;
		return SCAP_TIMEOUT;
	}
#endif

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
				m_analyzer->process_event(evt, sinsp_analyzer::DF_FORCE_FLUSH);
			}
			else if(sw)
			{
				m_analyzer->process_event(evt, sinsp_analyzer::DF_FORCE_FLUSH_BUT_DONT_EMIT);
			}
			else
			{
				m_analyzer->process_event(evt, sinsp_analyzer::DF_FORCE_NOFLUSH);
			}
		}
#else // SIMULATE_DROP_MODE
		m_analyzer->process_event(evt, sinsp_analyzer::DF_NONE);
#endif // SIMULATE_DROP_MODE
	}
#endif

	//
	// Update the last event time for this thread
	//
	if(evt->m_tinfo && 
		evt->get_type() != PPME_SCHEDSWITCH_1_E &&
		evt->get_type() != PPME_SCHEDSWITCH_6_E)
	{
		evt->m_tinfo->m_prevevent_ts = evt->m_tinfo->m_lastevent_ts;
		evt->m_tinfo->m_lastevent_ts = m_lastevent_ts;
	}

	//
	// Done
	//
	*puevt = evt;
	return res;
}

uint64_t sinsp::get_num_events()
{
	return scap_event_get_num(m_h);
}

sinsp_threadinfo* sinsp::find_thread(int64_t tid, bool lookup_only)
{
	threadinfo_map_iterator_t it;

	//
	// Try looking up in our simple cache
	//
	if(m_thread_manager->m_last_tinfo && tid == m_thread_manager->m_last_tid)
	{
#ifdef GATHER_INTERNAL_STATS
		m_thread_manager->m_cached_lookups->increment();
#endif
		m_thread_manager->m_last_tinfo->m_lastaccess_ts = m_lastevent_ts;
		return m_thread_manager->m_last_tinfo;
	}

	//
	// Caching failed, do a real lookup
	//
	it = m_thread_manager->m_threadtable.find(tid);
	
	if(it != m_thread_manager->m_threadtable.end())
	{
#ifdef GATHER_INTERNAL_STATS
		m_thread_manager->m_non_cached_lookups->increment();
#endif
		if(!lookup_only)
		{
			m_thread_manager->m_last_tid = tid;
			m_thread_manager->m_last_tinfo = &(it->second);
			m_thread_manager->m_last_tinfo->m_lastaccess_ts = m_lastevent_ts;
		}
		return &(it->second);
	}
	else
	{
#ifdef GATHER_INTERNAL_STATS
		m_thread_manager->m_failed_lookups->increment();
#endif
		return NULL;
	}
}

sinsp_threadinfo* sinsp::find_thread_test(int64_t tid, bool lookup_only)
{
	return find_thread(tid, lookup_only);
}

sinsp_threadinfo* sinsp::get_thread(int64_t tid, bool query_os_if_not_found, bool lookup_only)
{
	sinsp_threadinfo* sinsp_proc = find_thread(tid, lookup_only);

	if(sinsp_proc == NULL && query_os_if_not_found)
	{
		scap_threadinfo* scap_proc = NULL;
		sinsp_threadinfo newti(this);

		if(m_thread_manager->m_threadtable.size() < m_max_thread_table_size)
		{
			m_n_proc_lookups++;

			if(m_n_proc_lookups == m_max_n_proc_socket_lookups)
			{
				g_logger.format(sinsp_logger::SEV_INFO, "Reached max socket lookup number, tid=%" PRIu64, tid);
			}

			if(m_n_proc_lookups == m_max_n_proc_lookups)
			{
				g_logger.format(sinsp_logger::SEV_INFO, "Reached max process lookup number");
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
			newti.m_nchilds = 0;
		}

		//
		// Since this thread is created out of thin air, we need to
		// properly set its reference count, by scanning the table 
		//
		threadinfo_map_t* pttable = &m_thread_manager->m_threadtable;
		threadinfo_map_iterator_t it;

		for(it = pttable->begin(); it != pttable->end(); ++it)
		{
			if(it->second.m_pid == tid)
			{
				newti.m_nchilds++;
			}
		}

		//
		// Done. Add the new thread to the list.
		//
		m_thread_manager->add_thread(newti, false);
		sinsp_proc = find_thread(tid, lookup_only);
	}

	return sinsp_proc;
}

sinsp_threadinfo* sinsp::get_thread(int64_t tid)
{
	return get_thread(tid, false, true);
}

void sinsp::add_thread(const sinsp_threadinfo& ptinfo)
{
	m_thread_manager->add_thread((sinsp_threadinfo&)ptinfo, false);
}

void sinsp::remove_thread(int64_t tid, bool force)
{
	m_thread_manager->remove_thread(tid, force);
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
	if(m_islive)
	{
		g_logger.format(sinsp_logger::SEV_ERROR, "stopping drop mode");

		if(scap_stop_dropping_mode(m_h) != SCAP_SUCCESS)
		{
			throw sinsp_exception(scap_getlasterr(m_h));
		}
	}
}

void sinsp::start_dropping_mode(uint32_t sampling_ratio)
{
	if(m_islive)
	{
		g_logger.format(sinsp_logger::SEV_ERROR, "setting drop mode to %" PRIu32, sampling_ratio);

		if(scap_start_dropping_mode(m_h, sampling_ratio) != SCAP_SUCCESS)
		{
			throw sinsp_exception(scap_getlasterr(m_h));
		}
	}
}

#ifdef HAS_FILTERING
void sinsp::set_filter(const string& filter)
{
	if(m_filter != NULL)
	{
		ASSERT(false);
		throw sinsp_exception("filter can only be set once");
	}

	m_filter = new sinsp_filter(this, filter);
	m_filterstring = filter;
}

const string sinsp::get_filter()
{
	return m_filterstring;
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

void sinsp::set_min_log_severity(sinsp_logger::severity sev)
{
	g_logger.set_severity(sev);
}

sinsp_evttables* sinsp::get_event_info_tables()
{
	return &g_infotables;
}

void sinsp::add_chisel_dir(string dirname, bool front_add)
{
#ifdef HAS_CHISELS
	trim(dirname);

	if(dirname[dirname.size() -1] != '/')
	{
		dirname += "/";
	}

	chiseldir_info ncdi;

	strcpy(ncdi.m_dir, dirname.c_str());
	ncdi.m_need_to_resolve = false;

	if(front_add)
	{
		g_chisel_dirs->insert(g_chisel_dirs->begin(), ncdi);
	}
	else
	{
		g_chisel_dirs->push_back(ncdi);
	}
#endif
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

void sinsp::set_debug_mode(bool enable_debug)
{
	m_isdebug_enabled = enable_debug;
}

void sinsp::set_print_container_data(bool print_container_data)
{
	m_print_container_data = print_container_data;
}

void sinsp::set_fatfile_dump_mode(bool enable_fatfile)
{
	m_isfatfile_enabled = enable_fatfile;
}

void sinsp::set_max_evt_output_len(uint32_t len)
{
	m_max_evt_output_len = len;
}

sinsp_protodecoder* sinsp::require_protodecoder(string decoder_name)
{
	return m_parser->add_protodecoder(decoder_name);
}

void sinsp::protodecoder_register_reset(sinsp_protodecoder* dec)
{
	m_decoders_reset_list.push_back(dec);
}

sinsp_parser* sinsp::get_parser()
{
	return m_parser;
}

bool sinsp::setup_cycle_writer(string base_file_name, int rollover_mb, int duration_seconds, int file_limit, bool do_cycle, bool compress) 
{
	m_compress = compress;

	if(rollover_mb != 0 || duration_seconds != 0 || file_limit != 0 || do_cycle == true)
	{
		m_write_cycling = true;
	}

	return m_cycle_writer->setup(base_file_name, rollover_mb, duration_seconds, file_limit, do_cycle);
}

double sinsp::get_read_progress()
{
	if(m_filesize == -1)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}

	ASSERT(m_filesize != 0);

	int64_t fpos = scap_get_readfile_offset(m_h);

	if(fpos == -1)
	{
		throw sinsp_exception(scap_getlasterr(m_h));		
	}

	return (double)fpos * 100 / m_filesize;
}

bool sinsp::remove_inactive_threads()
{
	return m_thread_manager->remove_inactive_threads();
}

///////////////////////////////////////////////////////////////////////////////
// Note: this is defined here so we can inline it in sinso::next
///////////////////////////////////////////////////////////////////////////////
bool sinsp_thread_manager::remove_inactive_threads()
{
	bool res = false;

	if(m_last_flush_time_ns == 0)
	{
		//
		// Set the first table scan for 30 seconds in, so that we can spot bugs in the logic without having
		// to wait for tens of minutes
		//
		if(m_inspector->m_inactive_thread_scan_time_ns > 30 * ONE_SECOND_IN_NS)
		{
			m_last_flush_time_ns = 
				(m_inspector->m_lastevent_ts - m_inspector->m_inactive_thread_scan_time_ns + 30 * ONE_SECOND_IN_NS);
		}
		else
		{
			m_last_flush_time_ns = 
				(m_inspector->m_lastevent_ts - m_inspector->m_inactive_thread_scan_time_ns);			
		}
	}

	if(m_inspector->m_lastevent_ts > 
		m_last_flush_time_ns + m_inspector->m_inactive_thread_scan_time_ns)
	{
		res = true;

		m_last_flush_time_ns = m_inspector->m_lastevent_ts;

		g_logger.format(sinsp_logger::SEV_INFO, "Flushing thread table");

		//
		// Go through the table and remove dead entries.
		//
		for(threadinfo_map_iterator_t it = m_threadtable.begin(); it != m_threadtable.end();)
		{
			bool closed = (it->second.m_flags & PPM_CL_CLOSED) != 0;

			if(closed || 
				((m_inspector->m_lastevent_ts > it->second.m_lastaccess_ts + m_inspector->m_thread_timeout_ns) &&
					!scap_is_thread_alive(m_inspector->m_h, it->second.m_pid, it->first, it->second.m_comm.c_str()))
					)
			{
				//
				// Reset the cache
				//
				m_last_tid = 0;
				m_last_tinfo = NULL;

#ifdef GATHER_INTERNAL_STATS
				m_removed_threads->increment();
#endif
				remove_thread(it++, closed);
			}
			else
			{
				++it;
			}
		}

		//
		// Rebalance the thread table dependency tree, so we free up threads that
		// exited but that are stuck because of reference counting.
		//
		recreate_child_dependencies();
	}

	return res;
}
