/*
Copyright (C) 2013-2014 Draios inc.
 
This file is part of sysdig.

sysdig is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _WIN32
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#endif
#include <algorithm>
#include "sinsp.h"
#include "sinsp_int.h"

static void copy_ipv6_address(uint32_t* dest, uint32_t* src)
{
	dest[0] = src[0];
	dest[1] = src[1];
	dest[2] = src[2];
	dest[3] = src[3];
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_threadinfo implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_threadinfo::sinsp_threadinfo() :
	m_fdtable(NULL)
{
	m_inspector = NULL;
	init();
}

sinsp_threadinfo::sinsp_threadinfo(sinsp *inspector) :
	m_fdtable(inspector)
{
	m_inspector = inspector;
	init();
}

void sinsp_threadinfo::init()
{
	m_pid = (uint64_t) - 1LL;
	m_progid = -1LL;
	set_lastevent_data_validity(false);
	m_lastevent_type = -1;
	m_lastevent_ts = 0;
	m_prevevent_ts = 0;
	m_lastaccess_ts = 0;
	m_clone_ts = 0;
	m_lastevent_category.m_category = EC_UNKNOWN;
	m_flags = PPM_CL_NAME_CHANGED;
	m_nchilds = 0;
	m_fdlimit = -1;
	m_fd_usage_pct = 0;
	m_main_thread = NULL;
	m_main_program_thread = NULL;
	m_lastevent_fd = 0;
#ifdef HAS_FILTERING
	m_last_latency_entertime = 0;
	m_latency = 0;
#endif
	m_ainfo = NULL;
}

sinsp_threadinfo::~sinsp_threadinfo()
{
	uint32_t j;

	if((m_inspector != NULL) && 
		(m_inspector->m_thread_manager != NULL) &&
		(m_inspector->m_thread_manager->m_listener != NULL))
	{
		m_inspector->m_thread_manager->m_listener->on_thread_destroyed(this);
	}

	for(j = 0; j < m_private_state.size(); j++)
	{
		free(m_private_state[j]);
	}

	m_private_state.clear();
}

void sinsp_threadinfo::fix_sockets_coming_from_proc()
{
	unordered_map<int64_t, sinsp_fdinfo_t>::iterator it;

	for(it = m_fdtable.m_table.begin(); it != m_fdtable.m_table.end(); it++)
	{
		if(it->second.m_type == SCAP_FD_IPV4_SOCK)
		{
			if(m_inspector->m_thread_manager->m_server_ports.find(it->second.m_sockinfo.m_ipv4info.m_fields.m_sport) !=
				m_inspector->m_thread_manager->m_server_ports.end())
			{
				uint32_t tip;
				uint16_t tport;

				tip = it->second.m_sockinfo.m_ipv4info.m_fields.m_sip;
				tport = it->second.m_sockinfo.m_ipv4info.m_fields.m_sport;

				it->second.m_sockinfo.m_ipv4info.m_fields.m_sip = it->second.m_sockinfo.m_ipv4info.m_fields.m_dip;
				it->second.m_sockinfo.m_ipv4info.m_fields.m_dip = tip;
				it->second.m_sockinfo.m_ipv4info.m_fields.m_sport = it->second.m_sockinfo.m_ipv4info.m_fields.m_dport;
				it->second.m_sockinfo.m_ipv4info.m_fields.m_dport = tport;

				it->second.m_name = ipv4tuple_to_string(&it->second.m_sockinfo.m_ipv4info);

				it->second.set_role_server();
			}
			else
			{
				it->second.set_role_client();
			}
		}
	}
}

void sinsp_threadinfo::init(const scap_threadinfo* pi)
{
	scap_fdinfo *fdi;
	scap_fdinfo *tfdi;
	sinsp_fdinfo_t newfdi;
	string tcomm(pi->comm);

	init();

	m_tid = pi->tid;
	m_pid = pi->pid;
	m_ptid = pi->ptid;

	m_comm = pi->comm;

	if(tcomm == "" || tcomm[tcomm.length() - 1] == '/')
	{
		string ts(pi->exe);

		size_t commbegin = ts.rfind('/');

		if(commbegin != string::npos)
		{
			m_comm = ts.substr(commbegin + 1);
		}
	}

	m_exe = pi->exe;
	set_args(pi->args, pi->args_len);
	set_cwd(pi->cwd, strlen(pi->cwd));
	m_flags |= pi->flags;
	m_fdtable.clear();
	m_fdlimit = pi->fdlimit;
	m_uid = pi->uid;
	m_gid = pi->gid;

	HASH_ITER(hh, pi->fdlist, fdi, tfdi)
	{
		bool do_add = true;

		newfdi.m_type = fdi->type;
		newfdi.m_openflags = 0;
		newfdi.m_type = fdi->type;
		newfdi.m_flags = sinsp_fdinfo_t::FLAGS_FROM_PROC;
		newfdi.m_ino = fdi->ino;

		switch(newfdi.m_type)
		{
		case SCAP_FD_IPV4_SOCK:
			newfdi.m_sockinfo.m_ipv4info.m_fields.m_sip = fdi->info.ipv4info.sip;
			newfdi.m_sockinfo.m_ipv4info.m_fields.m_dip = fdi->info.ipv4info.dip;
			newfdi.m_sockinfo.m_ipv4info.m_fields.m_sport = fdi->info.ipv4info.sport;
			newfdi.m_sockinfo.m_ipv4info.m_fields.m_dport = fdi->info.ipv4info.dport;
			newfdi.m_sockinfo.m_ipv4info.m_fields.m_l4proto = fdi->info.ipv4info.l4proto;
			m_inspector->m_network_interfaces->update_fd(&newfdi);
			newfdi.m_name = ipv4tuple_to_string(&newfdi.m_sockinfo.m_ipv4info);
			break;
		case SCAP_FD_IPV4_SERVSOCK:
			newfdi.m_sockinfo.m_ipv4serverinfo.m_ip = fdi->info.ipv4serverinfo.ip;
			newfdi.m_sockinfo.m_ipv4serverinfo.m_port = fdi->info.ipv4serverinfo.port;
			newfdi.m_sockinfo.m_ipv4serverinfo.m_l4proto = fdi->info.ipv4serverinfo.l4proto;
			newfdi.m_name = ipv4serveraddr_to_string(&newfdi.m_sockinfo.m_ipv4serverinfo);
			
			//
			// We keep note of all the host bound server ports.
			// We'll need them later when patching connections direction.
			//
			m_inspector->m_thread_manager->m_server_ports.insert(newfdi.m_sockinfo.m_ipv4serverinfo.m_port);

			break;
		case SCAP_FD_IPV6_SOCK:
			if(sinsp_utils::is_ipv4_mapped_ipv6((uint8_t*)&fdi->info.ipv6info.sip) && 
				sinsp_utils::is_ipv4_mapped_ipv6((uint8_t*)&fdi->info.ipv6info.dip))
			{
				//
				// This is an IPv4-mapped IPv6 addresses (http://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses).
				// Convert it into the IPv4 representation.
				//
				newfdi.m_type = SCAP_FD_IPV4_SOCK;
				newfdi.m_sockinfo.m_ipv4info.m_fields.m_sip = fdi->info.ipv6info.sip[3];
				newfdi.m_sockinfo.m_ipv4info.m_fields.m_dip = fdi->info.ipv6info.dip[3];
				newfdi.m_sockinfo.m_ipv4info.m_fields.m_sport = fdi->info.ipv6info.sport;
				newfdi.m_sockinfo.m_ipv4info.m_fields.m_dport = fdi->info.ipv6info.dport;
				newfdi.m_sockinfo.m_ipv4info.m_fields.m_l4proto = fdi->info.ipv6info.l4proto;
				m_inspector->m_network_interfaces->update_fd(&newfdi);
				newfdi.m_name = ipv4tuple_to_string(&newfdi.m_sockinfo.m_ipv4info);
			}
			else
			{
				copy_ipv6_address(newfdi.m_sockinfo.m_ipv6info.m_fields.m_sip, fdi->info.ipv6info.sip);
				copy_ipv6_address(newfdi.m_sockinfo.m_ipv6info.m_fields.m_dip, fdi->info.ipv6info.dip);
				newfdi.m_sockinfo.m_ipv6info.m_fields.m_sport = fdi->info.ipv6info.sport;
				newfdi.m_sockinfo.m_ipv6info.m_fields.m_dport = fdi->info.ipv6info.dport;
				newfdi.m_sockinfo.m_ipv6info.m_fields.m_l4proto = fdi->info.ipv6info.l4proto;
				newfdi.m_name = ipv6tuple_to_string(&newfdi.m_sockinfo.m_ipv6info);
			}
			break;
		case SCAP_FD_IPV6_SERVSOCK:
			copy_ipv6_address(newfdi.m_sockinfo.m_ipv6serverinfo.m_ip, fdi->info.ipv6serverinfo.ip);
			newfdi.m_sockinfo.m_ipv6serverinfo.m_port = fdi->info.ipv6serverinfo.port;
			newfdi.m_sockinfo.m_ipv6serverinfo.m_l4proto = fdi->info.ipv6serverinfo.l4proto;
			newfdi.m_name = ipv6serveraddr_to_string(&newfdi.m_sockinfo.m_ipv6serverinfo);

			//
			// We keep note of all the host bound server ports.
			// We'll need them later when patching connections direction.
			//
			m_inspector->m_thread_manager->m_server_ports.insert(newfdi.m_sockinfo.m_ipv6serverinfo.m_port);

			break;
		case SCAP_FD_UNIX_SOCK:
			newfdi.m_sockinfo.m_unixinfo.m_fields.m_source = fdi->info.unix_socket_info.source;
			newfdi.m_sockinfo.m_unixinfo.m_fields.m_dest = fdi->info.unix_socket_info.destination;
			newfdi.m_name = fdi->info.unix_socket_info.fname;
			if(newfdi.m_name.empty())
			{
				newfdi.set_role_client();
			}
			else
			{
				newfdi.set_role_server();
			}
			break;
		case SCAP_FD_FIFO:
		case SCAP_FD_FILE:
		case SCAP_FD_DIRECTORY:
		case SCAP_FD_UNSUPPORTED:
		case SCAP_FD_SIGNALFD:
		case SCAP_FD_EVENTPOLL:
		case SCAP_FD_EVENT:
		case SCAP_FD_INOTIFY:
		case SCAP_FD_TIMERFD:
			newfdi.m_name = fdi->info.fname;
			break;
		default:
			ASSERT(false);
			do_add = false;
			break;
		}

		if(do_add)
		{
			m_fdtable.add(fdi->fd, &newfdi);
		}
	}
}

string sinsp_threadinfo::get_comm()
{
	return m_comm;
}

string sinsp_threadinfo::get_exe()
{
	return m_exe;
}

void sinsp_threadinfo::set_args(const char* args, size_t len)
{
	m_args.clear();

	size_t offset = 0;
	while(offset < len)
	{
		m_args.push_back(args + offset);
		offset += m_args.back().length() + 1;
	}
}

bool sinsp_threadinfo::is_main_thread()
{
	return m_tid == m_pid;
}

sinsp_threadinfo* sinsp_threadinfo::get_main_thread()
{
	if(m_main_thread == NULL)
	{
		//
		// Is this a child thread?
		//
		if(m_pid == m_tid)
		{
			//
			// No, this is either a single thread process or the root thread of a
			// multithread process.
			// Note: we don't set m_main_thread because there are cases in which this is 
			//       invoked for a threadinfo that is in the stack. Caching the this pointer
			//       would cause future mess.
			//
			return this;
		}
		else
		{
			//
			// Yes, this is a child thread. Find the process root thread.
			//
			sinsp_threadinfo *ptinfo = m_inspector->get_thread(m_pid, true);
			if(NULL == ptinfo)
			{
				ASSERT(false);
				return NULL;
			}

			m_main_thread = ptinfo;
		}
	}

	return m_main_thread;
}

sinsp_threadinfo* sinsp_threadinfo::get_parent_thread()
{
	return m_inspector->get_thread(m_ptid, false);
}

sinsp_fdtable* sinsp_threadinfo::get_fd_table()
{
	sinsp_threadinfo* root;

	if(!(m_flags & PPM_CL_CLONE_FILES))
	{
		root = this;
	}
	else
	{
		root = get_main_thread();
		if(NULL == root)
		{
			ASSERT(false);
			return NULL;
		}
	}

	return &(root->m_fdtable);
}

void sinsp_threadinfo::add_fd(int64_t fd, sinsp_fdinfo_t *fdinfo)
{
	get_fd_table()->add(fd, fdinfo);

	//
	// Update the last event fd. It's needed by the filtering engine
	//
	m_lastevent_fd = fd;
}

void sinsp_threadinfo::remove_fd(int64_t fd)
{
	get_fd_table()->erase(fd);
}

sinsp_fdinfo_t* sinsp_threadinfo::get_fd(int64_t fd)
{
	if(fd < 0)
	{
		return NULL;
	}

	sinsp_fdtable* fdt = get_fd_table();

	if(fdt)
	{
		return fdt->find(fd);
	}
	else
	{
		ASSERT(false);
	}

	return NULL;
}

bool sinsp_threadinfo::is_bound_to_port(uint16_t number)
{
	unordered_map<int64_t, sinsp_fdinfo_t>::iterator it;

	sinsp_fdtable* fdt = get_fd_table();

	for(it = fdt->m_table.begin(); 
		it != fdt->m_table.end(); ++it)
	{
		if(it->second.m_type == SCAP_FD_IPV4_SOCK)
		{
			if(it->second.m_sockinfo.m_ipv4info.m_fields.m_dport == number)
			{
				return true;
			}
		}
		else if(it->second.m_type == SCAP_FD_IPV4_SERVSOCK)
		{
			if(it->second.m_sockinfo.m_ipv4serverinfo.m_port == number)
			{
				return true;
			}
		}
	}

	return false;
}

bool sinsp_threadinfo::uses_client_port(uint16_t number)
{
	unordered_map<int64_t, sinsp_fdinfo_t>::iterator it;

	sinsp_fdtable* fdt = get_fd_table();

	for(it = fdt->m_table.begin(); 
		it != fdt->m_table.end(); ++it)
	{
		if(it->second.m_type == SCAP_FD_IPV4_SOCK)
		{
			if(it->second.m_sockinfo.m_ipv4info.m_fields.m_sport == number)
			{
				return true;
			}
		}
	}

	return false;
}

void sinsp_threadinfo::store_event(sinsp_evt *evt)
{
	uint32_t elen;

	//
	// Make sure the event data is going to fit
	//
	elen = scap_event_getlen(evt->m_pevt);

	if(elen > SP_EVT_BUF_SIZE)
	{
		ASSERT(false);
		return;
	}

	//
	// Copy the data
	//
	memcpy(m_lastevent_data, evt->m_pevt, elen);
	m_lastevent_cpuid = evt->get_cpuid();
}

bool sinsp_threadinfo::is_lastevent_data_valid()
{
	return (m_lastevent_cpuid != (uint16_t) - 1);
}

void sinsp_threadinfo::set_lastevent_data_validity(bool isvalid)
{
	if(isvalid)
	{
		m_lastevent_cpuid = (uint16_t)1;
	}
	else
	{
		m_lastevent_cpuid = (uint16_t) - 1;
	}
}

sinsp_threadinfo* sinsp_threadinfo::get_cwd_root()
{
	if(!(m_flags & PPM_CL_CLONE_FS))
	{
		return this;
	}
	else
	{
		return get_main_thread();
	}
}

string sinsp_threadinfo::get_cwd()
{
	sinsp_threadinfo* tinfo = get_cwd_root();

	if(tinfo)
	{
		return tinfo->m_cwd;
	}
	else
	{
		ASSERT(false);
		return "./";
	}
}

void sinsp_threadinfo::set_cwd(const char* cwd, uint32_t cwdlen)
{
	char tpath[SCAP_MAX_PATH_SIZE];
	sinsp_threadinfo* tinfo = get_cwd_root();

	if(tinfo)
	{
		sinsp_utils::concatenate_paths(tpath, 
			SCAP_MAX_PATH_SIZE, 
			(char*)tinfo->m_cwd.c_str(), 
			tinfo->m_cwd.size(), 
			cwd, 
			cwdlen);

		tinfo->m_cwd = tpath;

		if(tinfo->m_cwd[tinfo->m_cwd.size() - 1] != '/')
		{
			tinfo->m_cwd += '/';
		}
	}
	else
	{
		ASSERT(false);
	}
}

void sinsp_threadinfo::allocate_private_state()
{
	uint32_t j = 0;

	if(m_inspector != NULL)
	{
		m_private_state.clear();

		vector<uint32_t>* sizes = &m_inspector->m_thread_privatestate_manager.m_memory_sizes;
	
		for(j = 0; j < sizes->size(); j++)
		{
			void* newbuf = malloc(sizes->at(j));
			m_private_state.push_back(newbuf);
		}
	}
}

void* sinsp_threadinfo::get_private_state(uint32_t id)
{
	if(id >= m_private_state.size())
	{
		ASSERT(false);
		throw sinsp_exception("invalid thread state ID" + to_string((long long) id));
	}

	return m_private_state[id];
}


///////////////////////////////////////////////////////////////////////////////
// sinsp_thread_manager implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_thread_manager::sinsp_thread_manager(sinsp* inspector)
{
	m_inspector = inspector;
	m_listener = NULL;
	clear();
}

void sinsp_thread_manager::clear()
{
	m_threadtable.clear();
	m_last_tid = 0;
	m_last_tinfo = NULL;
	m_last_flush_time_ns = 0;
	m_n_drops = 0;

#ifdef GATHER_INTERNAL_STATS
	m_failed_lookups = &m_inspector->m_stats.get_metrics_registry().register_counter(internal_metrics::metric_name("thread_failed_lookups","Failed thread lookups"));
	m_cached_lookups = &m_inspector->m_stats.get_metrics_registry().register_counter(internal_metrics::metric_name("thread_cached_lookups","Cached thread lookups"));
	m_non_cached_lookups = &m_inspector->m_stats.get_metrics_registry().register_counter(internal_metrics::metric_name("thread_non_cached_lookups","Non cached thread lookups"));
	m_added_threads = &m_inspector->m_stats.get_metrics_registry().register_counter(internal_metrics::metric_name("thread_added","Number of added threads"));
	m_removed_threads = &m_inspector->m_stats.get_metrics_registry().register_counter(internal_metrics::metric_name("thread_removed","Removed threads"));
#endif
}

void sinsp_thread_manager::set_listener(sinsp_threadtable_listener* listener)
{
	m_listener = listener;
}

sinsp_threadinfo* sinsp_thread_manager::get_thread(int64_t tid)
{
	threadinfo_map_iterator_t it;

	//
	// Try looking up in our simple cache
	//
	if(m_last_tinfo && tid == m_last_tid)
	{
#ifdef GATHER_INTERNAL_STATS
		m_cached_lookups->increment();
#endif
		m_last_tinfo->m_lastaccess_ts = m_inspector->m_lastevent_ts;
		return m_last_tinfo;
	}

	//
	// Caching failed, do a real lookup
	//
	it = m_threadtable.find(tid);
	
	if(it != m_threadtable.end())
	{
#ifdef GATHER_INTERNAL_STATS
		m_non_cached_lookups->increment();
#endif
		m_last_tid = tid;
		m_last_tinfo = &(it->second);
		m_last_tinfo->m_lastaccess_ts = m_inspector->m_lastevent_ts;
		return &(it->second);
	}
	else
	{
#ifdef GATHER_INTERNAL_STATS
		m_failed_lookups->increment();
#endif
		return NULL;
	}
}

void sinsp_thread_manager::increment_mainthread_childcount(sinsp_threadinfo* threadinfo)
{
	if(threadinfo->m_flags & PPM_CL_CLONE_THREAD)
	{
		//
		// Increment the refcount of the main thread so it won't
		// be deleted (if it calls pthread_exit()) until we are done
		//
		ASSERT(threadinfo->m_pid != threadinfo->m_tid);
		sinsp_threadinfo* main_thread = m_inspector->get_thread(threadinfo->m_pid, false);
		if(main_thread)
		{
			++main_thread->m_nchilds;
		}
		else
		{
			ASSERT(false);
		}
	}
}

void sinsp_thread_manager::increment_program_childcount(sinsp_threadinfo* threadinfo)
{
	if(threadinfo->is_main_thread())
	{
		sinsp_threadinfo* parent_thread = m_inspector->get_thread(threadinfo->m_ptid, false);

		if(parent_thread)
		{
			if((parent_thread->m_comm == threadinfo->m_comm) &&
				(parent_thread->m_exe == threadinfo->m_exe))
			{
				threadinfo->m_progid = parent_thread->m_tid;
				++parent_thread->m_nchilds;
				increment_program_childcount(parent_thread);
			}
		}
	}
}

// Don't set level, it's for internal use
void sinsp_thread_manager::decrement_program_childcount(sinsp_threadinfo* threadinfo, uint32_t level)
{
	if(threadinfo->is_main_thread())
	{
		ASSERT(threadinfo->m_pid != threadinfo->m_progid);

		sinsp_threadinfo* prog_thread = m_inspector->get_thread(threadinfo->m_progid, false);

		if(prog_thread)
		{
			if(prog_thread->m_nchilds > 0)
			{
				--prog_thread->m_nchilds;
				decrement_program_childcount(prog_thread, level + 1);
			}
			else
			{
				ASSERT(false);
			}
		}

		if(level == 0)
		{
			threadinfo->m_progid = -1LL;
			threadinfo->m_main_program_thread = NULL;
		}
	}
}

void sinsp_thread_manager::add_thread(sinsp_threadinfo& threadinfo, bool from_scap_proctable)
{
#ifdef GATHER_INTERNAL_STATS
	m_added_threads->increment();
#endif

	if(m_threadtable.size() >= m_inspector->m_max_thread_table_size)
	{
		m_n_drops++;
		return;
	}

	if(!from_scap_proctable)
	{
		increment_mainthread_childcount(&threadinfo);
		increment_program_childcount(&threadinfo);
	}

	sinsp_threadinfo& newentry = (m_threadtable[threadinfo.m_tid] = threadinfo);
	newentry.allocate_private_state();
	if(m_listener)
	{
		m_listener->on_thread_created(&newentry);
	}
}

void sinsp_thread_manager::remove_thread(int64_t tid)
{
	remove_thread(m_threadtable.find(tid));
}

void sinsp_thread_manager::remove_thread(threadinfo_map_iterator_t it)
{
	if(it == m_threadtable.end())
	{
		//
		// Looks like there's no thread to remove.
		// Either the thread creation event was dropped or our logic doesn't support the
		// call that created this thread. The assertion will detect it, while in release mode we just
		// keep going.
		//
#ifdef GATHER_INTERNAL_STATS
		m_failed_lookups->increment();
#endif
		return;
	}
	else if(it->second.m_nchilds == 0)
	{
		//
		// Decrement the refcount of the main thread/program because
		// this reference is gone
		//
		if(it->second.m_flags & PPM_CL_CLONE_THREAD)
		{
			ASSERT(it->second.m_pid != it->second.m_tid);
			sinsp_threadinfo* main_thread = m_inspector->get_thread(it->second.m_pid, false);
			if(main_thread)
			{
				ASSERT(main_thread->m_nchilds);
				--main_thread->m_nchilds;
			}
			else
			{
				ASSERT(false);
			}
		}
		else if(it->second.m_progid != -1LL)
		{
			decrement_program_childcount(&it->second);
		}

		//
		// If this is the main thread of a process, erase all the FDs that the process owns
		//
		if(it->second.m_pid == it->second.m_tid)
		{
			unordered_map<int64_t, sinsp_fdinfo_t> fdtable = it->second.get_fd_table()->m_table;
			unordered_map<int64_t, sinsp_fdinfo_t>::iterator fdit;

			erase_fd_params eparams;
			eparams.m_remove_from_table = false;
			eparams.m_inspector = m_inspector;
			eparams.m_tinfo = &(it->second);
			eparams.m_ts = m_inspector->m_lastevent_ts;

			for(fdit = fdtable.begin(); fdit != fdtable.end(); ++fdit)
			{
				eparams.m_fd = fdit->first;

				//
				// The canceled fd should always be deleted immediately, so if it appears
				// here it means we have a problem.
				//
				ASSERT(eparams.m_fd != CANCELED_FD_NUMBER);
				eparams.m_fdinfo = &(fdit->second);

				m_inspector->m_parser->erase_fd(&eparams);
			}
		}

		//
		// Reset the cache
		//
		m_last_tid = 0;
		m_last_tinfo = NULL;

#ifdef GATHER_INTERNAL_STATS
		m_removed_threads->increment();
#endif

		m_threadtable.erase(it);
	}
}

void sinsp_thread_manager::remove_inactive_threads()
{
	if(m_last_flush_time_ns == 0)
	{
		m_last_flush_time_ns = m_inspector->m_lastevent_ts;
	}

	if(m_inspector->m_lastevent_ts > 
		m_last_flush_time_ns + m_inspector->m_inactive_thread_scan_time_ns)
	{
		m_last_flush_time_ns = m_inspector->m_lastevent_ts;

		for(threadinfo_map_iterator_t it = m_threadtable.begin(); it != m_threadtable.end();)
		{
			if(it->second.m_nchilds == 0 &&
				m_inspector->m_lastevent_ts > 
				it->second.m_lastaccess_ts + m_inspector->m_thread_timeout_ns)
			{
				//
				// Reset the cache
				//
				m_last_tid = 0;
				m_last_tinfo = NULL;

#ifdef GATHER_INTERNAL_STATS
				m_removed_threads->increment();
#endif
				m_threadtable.erase(it++);
			}
			else
			{
				++it;
			}
		}
	}
}

void sinsp_thread_manager::fix_sockets_coming_from_proc()
{
	threadinfo_map_iterator_t it;
	for(it = m_threadtable.begin(); 
		it != m_threadtable.end(); ++it)
	{
		it->second.fix_sockets_coming_from_proc();
	}
}


void sinsp_thread_manager::update_statistics()
{
#ifdef GATHER_INTERNAL_STATS
	m_inspector->m_stats.m_n_threads = get_thread_count();

	m_inspector->m_stats.m_n_fds = 0;
	for(threadinfo_map_iterator_t it = m_threadtable.begin(); it != m_threadtable.end(); it++)
	{
		m_inspector->m_stats.m_n_fds += it->second.get_fd_table()->size();
	}
#endif
}
