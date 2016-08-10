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
#include "chisel.h"
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
	m_parser = NULL;
	m_dumper = NULL;
	m_metaevt = NULL;
	m_skipped_evt = NULL;
	m_meinfo.m_piscapevt = NULL;
	m_network_interfaces = NULL;
	m_parser = new sinsp_parser(this);
	m_thread_manager = new sinsp_thread_manager(this);
	m_max_thread_table_size = MAX_THREAD_TABLE_SIZE;
	m_max_fdtable_size = MAX_FD_TABLE_SIZE;
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
	m_evttype_filter = NULL;
#endif

	m_fds_to_remove = new vector<int64_t>;
	m_machine_info = NULL;
#ifdef SIMULATE_DROP_MODE
	m_isdropping = false;
#endif
	m_n_proc_lookups = 0;
	m_n_proc_lookups_duration_ns = 0;
	m_max_n_proc_lookups = 0;
	m_max_n_proc_socket_lookups = 0;
	m_snaplen = DEFAULT_SNAPLEN;
	m_buffer_format = sinsp_evt::PF_NORMAL;
	m_isdebug_enabled = false;
	m_isfatfile_enabled = false;
	m_hostname_and_port_resolution_enabled = true;
	m_output_time_flag = 'h';
	m_max_evt_output_len = 0;
	m_filesize = -1;
	m_track_tracers_state = false;
	m_import_users = true;
	m_meta_evt_buf = new char[SP_EVT_BUF_SIZE];
	m_meta_evt.m_pevt = (scap_evt*) m_meta_evt_buf;
	m_meta_evt_pending = false;
	m_next_flush_time_ns = 0;
	m_last_procrequest_tod = 0;
	m_get_procs_cpu_from_driver = false;
	m_is_tracers_capture_enabled = false;

	// Unless the cmd line arg "-pc" or "-pcontainer" is supplied this is false
	m_print_container_data = false;

#if defined(HAS_CAPTURE)
	m_sysdig_pid = getpid();
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
	m_meta_event_callback_data = NULL;
	m_k8s_client = NULL;
	m_k8s_last_watch_time_ns = 0;

	m_k8s_client = NULL;
	m_k8s_api_server = NULL;
	m_k8s_api_cert = NULL;

	m_mesos_client = NULL;
	m_mesos_last_watch_time_ns = 0;

	m_filter_proc_table_when_saving = false;
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

	delete m_k8s_client;
	delete m_k8s_api_server;
	delete m_k8s_api_cert;

	delete m_mesos_client;
}

void sinsp::add_protodecoders()
{
	m_parser->add_protodecoder("syslog");
}

void sinsp::filter_proc_table_when_saving(bool filter)
{
	m_filter_proc_table_when_saving = filter;

	if(m_h != NULL)
	{
		scap_set_refresh_proc_table_when_saving(m_h, !filter);
	}
}

void sinsp::enable_tracers_capture()
{
#if defined(HAS_CAPTURE)
	if(!m_is_tracers_capture_enabled)
	{
		if(is_live() && m_h != NULL)
		{
			if(scap_enable_tracers_capture(m_h) != SCAP_SUCCESS)
			{
				throw sinsp_exception("error enabling tracers capture");
			}
		}

		m_is_tracers_capture_enabled = true;
	}
#endif
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
#ifndef HAS_ANALYZER
	add_protodecoders();
#endif
	//
	// Allocate the cycle writer
	//
	if(m_cycle_writer)
	{
		delete m_cycle_writer;
		m_cycle_writer = NULL;
	}

	m_cycle_writer = new cycle_writer(this->is_live());

	//
	// Basic inits
	//
#ifdef GATHER_INTERNAL_STATS
	m_stats.clear();
#endif

	m_nevts = 0;
	m_tid_to_remove = -1;
	m_lastevent_ts = 0;
#ifdef HAS_FILTERING
	m_firstevent_ts = 0;
#endif
	m_fds_to_remove->clear();
	m_n_proc_lookups = 0;
	m_n_proc_lookups_duration_ns = 0;

	//
	// Return the tracers to the pool and clear the tracers list
	//
	for(auto it = m_partial_tracers_list.begin(); it != m_partial_tracers_list.end(); ++it)
	{
		m_partial_tracers_pool->push(*it);
	}
	m_partial_tracers_list.clear();

	//
	// If we're reading from file, we try to pre-parse the container events before
	// importing the thread table, so that thread table filtering will work with
	// container filters
	//
	if(m_islive == false)
	{
		uint64_t off = scap_ftell(m_h);
		scap_evt* pevent;
		uint16_t pcpuid;
		uint32_t ncnt = 0;

		//
		// Count how many container events we have
		//
		while(true)
		{
			int32_t res = scap_next(m_h, &pevent, &pcpuid);

			if(res == SCAP_SUCCESS)
			{
				if((pevent->type != PPME_CONTAINER_E) && (pevent->type != PPME_CONTAINER_JSON_E))
				{
					break;
				}
				else
				{
					ncnt++;
					continue;
				}
			}
			else
			{
				break;
			}
		}

		//
		// Rewind and consume the exact number of events
		//
		scap_fseek(m_h, off);
		for(uint32_t j = 0; j < ncnt; j++)
		{
			sinsp_evt* tevt;
			next(&tevt);
		}
	}

	if(m_islive == false || m_filter_proc_table_when_saving == true)
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
	oargs.proc_callback = NULL;
	oargs.proc_callback_context = NULL;
	if(!m_filter_proc_table_when_saving)
	{
		oargs.proc_callback = ::on_new_entry_from_proc;
		oargs.proc_callback_context = this;
	}
	oargs.import_users = m_import_users;

	m_h = scap_open(oargs, error);

	if(m_h == NULL)
	{
		throw sinsp_exception(error);
	}

	scap_set_refresh_proc_table_when_saving(m_h, !m_filter_proc_table_when_saving);

	init();
}

int64_t sinsp::get_file_size(const std::string& fname, char *error)
{
	static string err_str = "Could not determine capture file size: ";
	std::string errdesc;
#ifdef _WIN32
	LARGE_INTEGER li = { 0 };
	HANDLE fh = CreateFile(fname.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);
	if (fh != INVALID_HANDLE_VALUE)
	{
		if (0 != GetFileSizeEx(fh, &li))
		{
			CloseHandle(fh);
			return li.QuadPart;
		}
		errdesc = get_error_desc(err_str);
		CloseHandle(fh);
	}
#else
	struct stat st;
	if (0 == stat(fname.c_str(), &st))
	{
		return st.st_size;
	}
#endif
	if(errdesc.empty()) errdesc = get_error_desc(err_str);
	strncpy(error, errdesc.c_str(), errdesc.size() > SCAP_LASTERR_SIZE ? SCAP_LASTERR_SIZE : errdesc.size());
	return -1;
}

std::string sinsp::get_error_desc(const std::string& msg)
{
#ifdef _WIN32
	DWORD err_no = GetLastError(); // first, so error is not wiped out by intermediate calls
	std::string errstr = msg;
	DWORD flg = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
	LPTSTR msg_buf = 0;
	if(FormatMessageA(flg, 0, err_no, 0, (LPTSTR)&msg_buf, 0, NULL))
	if(msg_buf)
	{
		errstr.append(msg_buf, strlen(msg_buf));
		LocalFree(msg_buf);
	}
#else
	char* msg_buf = strerror(errno); // first, so error is not wiped out by intermediate calls
	std::string errstr = msg;
	if(msg_buf)
	{
		errstr.append(msg_buf, strlen(msg_buf));
	}
#endif
	return errstr;
}

void sinsp::open(string filename)
{
	char error[SCAP_LASTERR_SIZE] = {0};

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

	m_filesize = get_file_size(filename, error);

	if(m_filesize < 0)
	{
		throw sinsp_exception(error);
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

	if(m_evttype_filter != NULL)
	{
		delete m_evttype_filter;
		m_evttype_filter = NULL;
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

		sinsp_fdinfo_t sinsp_fdinfo;
		sinsp_tinfo->add_fd_from_scap(fdinfo, &sinsp_fdinfo);
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
	m_network_interfaces = new sinsp_network_interfaces(this);
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

void sinsp::refresh_ifaddr_list()
{
#ifdef HAS_CAPTURE
	if(m_islive)
	{
		ASSERT(m_network_interfaces);
		scap_refresh_iflist(m_h);
		m_network_interfaces->clear();
		m_network_interfaces->import_interfaces(scap_get_ifaddr_list(m_h));
	}
#endif
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

void sinsp::add_meta_event_callback(meta_event_callback cback, void* data)
{
	m_meta_event_callback = cback;
	m_meta_event_callback_data = data;
}

void sinsp::remove_meta_event_callback()
{
	m_meta_event_callback = NULL;
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
			m_meta_event_callback(this, m_meta_event_callback_data);
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
				*puevt = NULL;
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
				m_lasterr = scap_getlasterr(m_h);
			}

			return res;
		}
	}

	uint64_t ts = evt->get_ts();

	if(m_firstevent_ts == 0)
	{
		m_firstevent_ts = ts;
	}

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
						add_meta_event_callback(&schedule_next_threadinfo_evt, &m_meinfo);
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

		if(m_k8s_client)
		{
			update_kubernetes_state();
		}

		if(m_mesos_client)
		{
			update_mesos_state();
		}
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
			//res = scap_number_of_bytes_to_write(evt->m_pevt, evt->m_cpuid, &bytes_to_write);
			switch(m_cycle_writer->consider(evt))
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

		scap_evt* pdevt = (evt->m_poriginal_evt)? evt->m_poriginal_evt : evt->m_pevt;

		res = scap_dump(m_h, m_dumper, pdevt, evt->m_cpuid, dflags);

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

	// Clean parse related event data after analyzer did its parsing too
	m_parser->event_cleanup(evt);

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
	ASSERT(m_h);
	return scap_event_get_num(m_h);
}

sinsp_threadinfo* sinsp::find_thread_test(int64_t tid, bool lookup_only)
{
	return find_thread(tid, lookup_only);
}

sinsp_threadinfo* sinsp::get_thread(int64_t tid, bool query_os_if_not_found, bool lookup_only)
{
	sinsp_threadinfo* sinsp_proc = find_thread(tid, lookup_only);

	if(sinsp_proc == NULL && query_os_if_not_found &&
	   (m_thread_manager->m_threadtable.size() < m_max_thread_table_size
#if defined(HAS_CAPTURE)
		   || tid == m_sysdig_pid
#endif
		))
	{
		scap_threadinfo* scap_proc = NULL;
		sinsp_threadinfo newti(this);

		m_n_proc_lookups++;

		if(m_n_proc_lookups == m_max_n_proc_socket_lookups)
		{
			g_logger.format(sinsp_logger::SEV_INFO, "Reached max socket lookup number, tid=%" PRIu64 ", duration=%" PRIu64,
				tid, m_n_proc_lookups_duration_ns / 1000000);
		}

		if(m_n_proc_lookups == m_max_n_proc_lookups)
		{
			g_logger.format(sinsp_logger::SEV_INFO, "Reached max process lookup number, duration=%" PRIu64,
				m_n_proc_lookups_duration_ns / 1000000);
		}

		if(m_max_n_proc_lookups == 0 || (m_max_n_proc_lookups != 0 &&
			(m_n_proc_lookups <= m_max_n_proc_lookups)))
		{
			bool scan_sockets = false;

			if(m_max_n_proc_socket_lookups == 0 || (m_max_n_proc_socket_lookups != 0 &&
				(m_n_proc_lookups <= m_max_n_proc_socket_lookups)))
			{
				scan_sockets = true;
			}

#ifdef HAS_ANALYZER
			uint64_t ts = sinsp_utils::get_current_time_ns();
#endif
			scap_proc = scap_proc_get(m_h, tid, scan_sockets);
#ifdef HAS_ANALYZER
			m_n_proc_lookups_duration_ns += sinsp_utils::get_current_time_ns() - ts;
#endif
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
		g_logger.format(sinsp_logger::SEV_INFO, "stopping drop mode");

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
		g_logger.format(sinsp_logger::SEV_INFO, "setting drop mode to %" PRIu32, sampling_ratio);

		if(scap_start_dropping_mode(m_h, sampling_ratio) != SCAP_SUCCESS)
		{
			throw sinsp_exception(scap_getlasterr(m_h));
		}
	}
}

#ifdef HAS_FILTERING
void sinsp::set_filter(sinsp_filter* filter)
{
	if(m_filter != NULL)
	{
		ASSERT(false);
		throw sinsp_exception("filter can only be set once");
	}

	m_filter = filter;
}

void sinsp::set_filter(const string& filter)
{
	if(m_filter != NULL)
	{
		ASSERT(false);
		throw sinsp_exception("filter can only be set once");
	}

	sinsp_filter_compiler compiler(this, filter);
	m_filter = compiler.compile();
	m_filterstring = filter;
}

const string sinsp::get_filter()
{
	return m_filterstring;
}

void sinsp::add_evttype_filter(string &name,
			       list<uint32_t> &evttypes,
			       sinsp_filter *filter)
{
	// Create the evttype filter if it doesn't exist.
	if(m_evttype_filter == NULL)
	{
		m_evttype_filter = new sinsp_evttype_filter();
	}

	m_evttype_filter->add(name, evttypes, filter);
}

bool sinsp::run_filters_on_evt(sinsp_evt *evt)
{
	//
	// First run the global filter, if there is one.
	//
	if(m_filter && m_filter->run(evt) == true)
	{
		return true;
	}

	//
	// Then run the evttype filter, if there is one.
	if(m_evttype_filter && m_evttype_filter->run(evt) == true)
	{
		return true;
	}

	return false;
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
	if(cb)
	{
		g_logger.add_callback_log(cb);
	}
	else
	{
		g_logger.remove_callback_log();
	}
}

void sinsp::set_log_file(string filename)
{
	g_logger.add_file_log(filename);
}

void sinsp::set_log_stderr()
{
	g_logger.add_stderr_log();
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

void sinsp::set_drop_event_flags(ppm_event_flags flags)
{
	m_parser->m_drop_event_flags = flags;
}

sinsp_evt::param_fmt sinsp::get_buffer_format()
{
	return m_buffer_format;
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

void sinsp::set_hostname_and_port_resolution_mode(bool enable)
{
	m_hostname_and_port_resolution_enabled = enable;
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

bool sinsp::setup_cycle_writer(string base_file_name, int rollover_mb, int duration_seconds, int file_limit, unsigned long event_limit, bool compress)
{
	m_compress = compress;

	if(rollover_mb != 0 || duration_seconds != 0 || file_limit != 0 || event_limit != 0)
	{
		m_write_cycling = true;
	}

	return m_cycle_writer->setup(base_file_name, rollover_mb, duration_seconds, file_limit, event_limit, &m_dumper);
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

void sinsp::init_mesos_client(string* api_server, bool verbose)
{
	m_verbose_json = verbose;
	if(m_mesos_client == NULL)
	{
		if(api_server)
		{
			// -m <url[,marathon_url]>
			std::string::size_type pos = api_server->find(',');
			if(pos != std::string::npos)
			{
				m_marathon_api_server.clear();
				m_marathon_api_server.push_back(api_server->substr(pos + 1));
			}
			m_mesos_api_server = api_server->substr(0, pos);
		}

		bool is_live = !m_mesos_api_server.empty();
		m_mesos_client = new mesos(m_mesos_api_server, mesos::default_state_api,
									m_marathon_api_server,
									mesos::default_groups_api,
									mesos::default_apps_api,
									m_marathon_api_server.empty(), // leader auto-follow if no uri
									mesos::default_timeout_ms,
									is_live,
									m_verbose_json);
	}
}

void sinsp::init_k8s_client(string* api_server, string* ssl_cert, bool verbose)
{
	ASSERT(api_server);
	m_verbose_json = verbose;
	m_k8s_api_server = api_server;
	m_k8s_api_cert = ssl_cert;

	if(m_k8s_client == NULL)
	{
#ifdef HAS_CAPTURE
		std::shared_ptr<sinsp_curl::ssl> k8s_ssl;
		std::shared_ptr<sinsp_curl::bearer_token> k8s_bt;

		if(ssl_cert)
		{
			std::string cert;
			std::string key;
			std::string key_pwd;
			std::string ca_cert;

			// -K <bt_file> | <cert_file>:<key_file[#password]>[:<ca_cert_file>]
			std::string::size_type pos = ssl_cert->find(':');
			if(pos == std::string::npos) // ca_cert-only is obsoleted, single entry is now bearer token
			{
				k8s_bt = std::make_shared<sinsp_curl::bearer_token>(*ssl_cert);
				ssl_cert->clear();
			}
			else
			{
				while(ssl_cert->length())
				{
					if(cert.empty() && pos != std::string::npos)
					{
						cert = ssl_cert->substr(0, pos);
						if(ssl_cert->length() > (pos + 1))
						{
							*ssl_cert = ssl_cert->substr(pos + 1);
						}
						else { break; }
					}
					else if(key.empty())
					{
						key = ssl_cert->substr(0, pos);
						if(ssl_cert->length() > (pos + 1))
						{
							*ssl_cert = ssl_cert->substr(pos + 1);
							std::string::size_type s_pos = key.find('#');
							if(s_pos != std::string::npos && key.length() > (s_pos + 1))
							{
								key_pwd = key.substr(s_pos + 1);
								key = key.substr(0, s_pos);
							}
							if(pos == std::string::npos) { break; }
						}
						else { break; }
					}
					else if(ca_cert.empty())
					{
						ca_cert = *ssl_cert;
						ssl_cert->clear();
					}
					else { goto ssl_err; }
					pos = ssl_cert->find(':', pos);
				}
				if(cert.empty() || key.empty()) { goto ssl_err; }
			}
			k8s_ssl = std::make_shared<sinsp_curl::ssl>(cert, key, key_pwd,
						ca_cert, ca_cert.empty() ? false : true, "PEM");
		}
#endif // HAS_CAPTURE
		bool is_live = !m_k8s_api_server->empty();
		m_k8s_client = new k8s(*m_k8s_api_server,
			is_live ? true : false, // watch
			false, // don't run watch in thread
			is_live ? true : false // capture
#ifdef HAS_CAPTURE
			,k8s_ssl
			,k8s_bt
#endif // HAS_CAPTURE
		);
	}

	return;

#ifdef HAS_CAPTURE
ssl_err:
	throw sinsp_exception(string("Invalid K8S SSL entry: ") + (ssl_cert ? *ssl_cert : string("NULL")));
#endif // HAS_CAPTURE
}

void sinsp::update_kubernetes_state()
{
	ASSERT(m_k8s_client);
	if(m_lastevent_ts > m_k8s_last_watch_time_ns + ONE_SECOND_IN_NS)
	{
		m_k8s_last_watch_time_ns = m_lastevent_ts;

		if(m_parser && m_k8s_client->is_alive())
		{
			uint64_t delta = sinsp_utils::get_current_time_ns();

			m_k8s_client->watch();
			m_parser->schedule_k8s_events(&m_meta_evt);

			delta = sinsp_utils::get_current_time_ns() - delta;

			g_logger.format(sinsp_logger::SEV_DEBUG, "Updating Kubernetes state took %" PRIu64 " ms", delta / 1000000LL);
		}
		else
		{
			g_logger.format(sinsp_logger::SEV_WARNING, "Kubernetes connection not active anymore, retrying");
			delete m_k8s_client;
			m_k8s_client = NULL;
			init_k8s_client(m_k8s_api_server, m_k8s_api_cert, m_verbose_json);
		}
	}
}

bool sinsp::get_mesos_data()
{
	bool ret = false;
#ifdef HAS_CAPTURE
	try
	{
		static time_t last_mesos_refresh = 0;
		ASSERT(m_mesos_client);
		ASSERT(m_mesos_client->is_alive());

		time_t now; time(&now);
		if(last_mesos_refresh)
		{
			g_logger.log("Collecting Mesos data ...", sinsp_logger::SEV_DEBUG);
			ret = m_mesos_client->collect_data();
		}
		if(difftime(now, last_mesos_refresh) > 10)
		{
			g_logger.log("Requesting Mesos data ...", sinsp_logger::SEV_DEBUG);
			m_mesos_client->send_data_request(false);
			last_mesos_refresh = now;
		}
	}
	catch(std::exception& ex)
	{
		g_logger.log(std::string("Mesos exception: ") + ex.what(), sinsp_logger::SEV_ERROR);
		delete m_mesos_client;
		m_mesos_client = NULL;
		init_mesos_client(0, m_verbose_json);
	}
#endif // HAS_CAPTURE
	return ret;
}

void sinsp::update_mesos_state()
{
	ASSERT(m_mesos_client);
	if(m_lastevent_ts > m_mesos_last_watch_time_ns + ONE_SECOND_IN_NS)
	{
		m_mesos_last_watch_time_ns = m_lastevent_ts;
		if(m_mesos_client->is_alive())
		{
			uint64_t delta = sinsp_utils::get_current_time_ns();
			if(m_parser && get_mesos_data())
			{
				m_parser->schedule_mesos_events(&m_meta_evt);
				delta = sinsp_utils::get_current_time_ns() - delta;
				g_logger.format(sinsp_logger::SEV_DEBUG, "Updating Mesos state took %" PRIu64 " ms", delta / 1000000LL);
			}
		}
		else
		{
			g_logger.format(sinsp_logger::SEV_ERROR, "Mesos connection not active anymore, retrying ...");
			delete m_mesos_client;
			m_mesos_client = NULL;
			init_mesos_client(0, m_verbose_json);
		}
	}
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
