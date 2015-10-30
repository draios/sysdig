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

#ifdef _WIN32
#define NOMINMAX
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef _DEBUG
#endif // _DEBUG
#include <unistd.h>
#endif // _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <limits>

#include "sinsp.h"
#include "sinsp_int.h"
#include "../../driver/ppm_ringbuffer.h"
#include "parsers.h"
#include "sinsp_errno.h"
#include "filter.h"
#include "filterchecks.h"
#include "protodecoder.h"
#ifdef HAS_ANALYZER
#include "analyzer_int.h"
#include "analyzer_thread.h"
#endif
#ifdef SIMULATE_DROP_MODE
bool should_drop(sinsp_evt *evt);
#endif

extern sinsp_protodecoder_list g_decoderlist;

sinsp_parser::sinsp_parser(sinsp *inspector) :
	m_inspector(inspector),
	m_tmp_evt(m_inspector),
	m_fd_listener(NULL)
{
}

sinsp_parser::~sinsp_parser()
{
	for(uint32_t j = 0; j < m_protodecoders.size(); j++)
	{
		delete m_protodecoders[j];
	}

	m_protodecoders.clear();
}

///////////////////////////////////////////////////////////////////////////////
// PROCESSING ENTRY POINT
///////////////////////////////////////////////////////////////////////////////
void sinsp_parser::process_event(sinsp_evt *evt)
{
	uint16_t etype = evt->m_pevt->type;
	bool is_live = m_inspector->m_islive;

	//
	// Cleanup the event-related state
	//
	reset(evt);

	//
	// When debug mode is not enabled, filter out events about sysdig itself
	//
#if defined(HAS_CAPTURE)
	if(is_live && !m_inspector->is_debug_enabled())
	{
		if(evt->get_tid() == m_inspector->m_sysdig_pid && 
			etype != PPME_SCHEDSWITCH_1_E && 
			etype != PPME_SCHEDSWITCH_6_E &&
			etype != PPME_DROP_E &&
			etype != PPME_DROP_X &&
			etype != PPME_SYSDIGEVENT_E &&
			etype != PPME_PROCINFO_E &&
			m_inspector->m_sysdig_pid)
		{
			evt->m_filtered_out = true;
			return;
		}
	}
#endif

	//
	// Filtering
	//
#if defined(HAS_FILTERING) && defined(HAS_CAPTURE_FILTERING)
	bool do_filter_later = false;

	if(m_inspector->m_filter)
	{
		ppm_event_flags eflags = evt->get_flags();

		if(eflags & EF_MODIFIES_STATE)
		{
			do_filter_later = true;
		}
		else
		{
			if(m_inspector->m_filter->run(evt) == false)
			{
				if(evt->m_tinfo != NULL)
				{
					if(!(eflags & EF_SKIPPARSERESET || etype == PPME_SCHEDSWITCH_6_E))
					{
						evt->m_tinfo->m_lastevent_type = PPM_SC_MAX;
					}
				}

				evt->m_filtered_out = true;
				return;
			}
		}
	}

	evt->m_filtered_out = false;
#endif

	//
	// Route the event to the proper function
	//
	switch(etype)
	{
	case PPME_SYSCALL_OPEN_E:
	case PPME_SOCKET_SOCKET_E:
	case PPME_SYSCALL_EVENTFD_E:
	case PPME_SYSCALL_CHDIR_E:
	case PPME_SYSCALL_FCHDIR_E:
	case PPME_SYSCALL_CREAT_E:
	case PPME_SYSCALL_OPENAT_E:
	case PPME_SOCKET_SHUTDOWN_E:
	case PPME_SYSCALL_GETRLIMIT_E:
	case PPME_SYSCALL_SETRLIMIT_E:
	case PPME_SYSCALL_PRLIMIT_E:
	case PPME_SOCKET_SENDTO_E:
	case PPME_SOCKET_SENDMSG_E:
	case PPME_SYSCALL_SENDFILE_E:
	case PPME_SYSCALL_SETRESUID_E:
	case PPME_SYSCALL_SETRESGID_E:
	case PPME_SYSCALL_SETUID_E:
	case PPME_SYSCALL_SETGID_E:
		store_event(evt);
		break;
	case PPME_SYSCALL_READ_X:
	case PPME_SYSCALL_WRITE_X:
	case PPME_SOCKET_RECV_X:
	case PPME_SOCKET_SEND_X:
	case PPME_SOCKET_RECVFROM_X:
	case PPME_SOCKET_RECVMSG_X:
	case PPME_SOCKET_SENDTO_X:
	case PPME_SOCKET_SENDMSG_X:
	case PPME_SYSCALL_READV_X:
	case PPME_SYSCALL_WRITEV_X:
	case PPME_SYSCALL_PREAD_X:
	case PPME_SYSCALL_PWRITE_X:
	case PPME_SYSCALL_PREADV_X:
	case PPME_SYSCALL_PWRITEV_X:
		parse_rw_exit(evt);
		break;
	case PPME_SYSCALL_SENDFILE_X:
		parse_sendfile_exit(evt);
		break;
	case PPME_SYSCALL_OPEN_X:
	case PPME_SYSCALL_CREAT_X:
	case PPME_SYSCALL_OPENAT_X:
		parse_open_openat_creat_exit(evt);
		break;
	case PPME_SYSCALL_SELECT_E:
	case PPME_SYSCALL_POLL_E:
	case PPME_SYSCALL_PPOLL_E:
	case PPME_SYSCALL_EPOLLWAIT_E:
		parse_select_poll_epollwait_enter(evt);
		break;
	case PPME_SYSCALL_CLONE_11_X:
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_X:
	case PPME_SYSCALL_VFORK_17_X:
	case PPME_SYSCALL_VFORK_20_X:
		parse_clone_exit(evt);
		break;
	case PPME_SYSCALL_EXECVE_8_X:
	case PPME_SYSCALL_EXECVE_13_X:
	case PPME_SYSCALL_EXECVE_14_X:
	case PPME_SYSCALL_EXECVE_15_X:
	case PPME_SYSCALL_EXECVE_16_X:
		parse_execve_exit(evt);
		break;
	case PPME_PROCEXIT_E:
	case PPME_PROCEXIT_1_E:
		parse_thread_exit(evt);
		break;
	case PPME_SYSCALL_PIPE_X:
		parse_pipe_exit(evt);
		break;
	case PPME_SOCKET_SOCKET_X:
		parse_socket_exit(evt);
		break;
	case PPME_SOCKET_BIND_X:
		parse_bind_exit(evt);
		break;
	case PPME_SOCKET_CONNECT_X:
		parse_connect_exit(evt);
		break;
	case PPME_SOCKET_ACCEPT_X:
	case PPME_SOCKET_ACCEPT_5_X:
	case PPME_SOCKET_ACCEPT4_X:
	case PPME_SOCKET_ACCEPT4_5_X:
		parse_accept_exit(evt);
		break;
	case PPME_SYSCALL_CLOSE_E:
		parse_close_enter(evt);
		break;
	case PPME_SYSCALL_CLOSE_X:
		parse_close_exit(evt);
		break;
	case PPME_SYSCALL_FCNTL_E:
		parse_fcntl_enter(evt);
		break;
	case PPME_SYSCALL_FCNTL_X:
		parse_fcntl_exit(evt);
		break;
	case PPME_SYSCALL_EVENTFD_X :
		parse_eventfd_exit(evt);
		break;
	case PPME_SYSCALL_CHDIR_X:
		parse_chdir_exit(evt);
		break;
	case PPME_SYSCALL_FCHDIR_X:
		parse_fchdir_exit(evt);
		break;
	case PPME_SYSCALL_GETCWD_X:
		parse_getcwd_exit(evt);
		break;
	case PPME_SOCKET_SHUTDOWN_X:
		parse_shutdown_exit(evt);
		break;
	case PPME_SYSCALL_DUP_X:
		parse_dup_exit(evt);
		break;
	case PPME_SYSCALL_SIGNALFD_X:
		parse_signalfd_exit(evt);
		break;
	case PPME_SYSCALL_TIMERFD_CREATE_X:
		parse_timerfd_create_exit(evt);
		break;
	case PPME_SYSCALL_INOTIFY_INIT_X:
		parse_inotify_init_exit(evt);
		break;
	case PPME_SYSCALL_GETRLIMIT_X:
	case PPME_SYSCALL_SETRLIMIT_X:
		parse_getrlimit_setrlimit_exit(evt);
		break;
	case PPME_SYSCALL_PRLIMIT_X:
		parse_prlimit_exit(evt);
		break;
	case PPME_SOCKET_SOCKETPAIR_X:
		parse_socketpair_exit(evt);
		break;
	case PPME_SCHEDSWITCH_1_E:
	case PPME_SCHEDSWITCH_6_E:
		parse_context_switch(evt);
		break;
	case PPME_SYSCALL_BRK_4_X:
	case PPME_SYSCALL_MMAP_X:
	case PPME_SYSCALL_MMAP2_X:
	case PPME_SYSCALL_MUNMAP_X:
		parse_brk_munmap_mmap_exit(evt);
		break;
	case PPME_SYSCALL_SETRESUID_X:
		parse_setresuid_exit(evt);
		break;
	case PPME_SYSCALL_SETRESGID_X:
		parse_setresgid_exit(evt);
		break;
	case PPME_SYSCALL_SETUID_X:
		parse_setuid_exit(evt);
		break;
	case PPME_SYSCALL_SETGID_X:
		parse_setgid_exit(evt);
		break;
	case PPME_CONTAINER_E:
		parse_container_evt(evt);
		break;
	case PPME_CPU_HOTPLUG_E:
		parse_cpu_hotplug_enter(evt);
		break;
	default:
		break;
	}

	//
	// With some state-changing events like clone, execve and open, we do the
	// filtering after having updated the state
	//
#if defined(HAS_FILTERING) && defined(HAS_CAPTURE_FILTERING)
	if(do_filter_later)
	{
		if(m_inspector->m_filter)
		{
			if(m_inspector->m_filter->run(evt) == false)
			{
				evt->m_filtered_out = true;
				return;
			}
		}
		evt->m_filtered_out = false;
	}
#endif

	//
	// Offline captures can prodice events with the SCAP_DF_STATE_ONLY. They are
	// supposed to go through the engine, but they must be filtered out before 
	// reaching the user.
	//
	if(!is_live)
	{
		if(evt->get_dump_flags() & SCAP_DF_STATE_ONLY)
		{
			evt->m_filtered_out = true;
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
// HELPERS
///////////////////////////////////////////////////////////////////////////////

//
// Called before starting the parsing.
// Returns false in case of issues resetting the state.
//
bool sinsp_parser::reset(sinsp_evt *evt)
{
	//
	// Before anything can happen, the event needs to be initialized
	//
	evt->init();

	ppm_event_flags eflags = evt->get_flags();
	uint16_t etype = evt->get_type();

	evt->m_fdinfo = NULL;
	evt->m_errorcode = 0;

	//
	// Ignore scheduler events
	//
	if(eflags & EF_SKIPPARSERESET)
	{
		if(etype == PPME_PROCINFO_E)
		{
			evt->m_tinfo = m_inspector->get_thread(evt->m_pevt->tid, false, false);
		}
		else
		{
			evt->m_tinfo = NULL;
		}

		return false;
	}

	//
	// Find the thread info
	//

	//
	// If we're exiting a clone or if we have a scheduler event
	// (many kernel thread), we don't look for /proc
	//
	bool query_os;
	if(etype == PPME_SYSCALL_CLONE_11_X ||
		etype == PPME_SYSCALL_CLONE_16_X ||
		etype == PPME_SYSCALL_CLONE_17_X ||
		etype == PPME_SYSCALL_CLONE_20_X ||
		etype == PPME_SYSCALL_FORK_X ||
		etype == PPME_SYSCALL_FORK_17_X ||
		etype == PPME_SYSCALL_FORK_20_X ||
		etype == PPME_SYSCALL_VFORK_X ||
		etype == PPME_SYSCALL_VFORK_17_X ||
		etype == PPME_SYSCALL_VFORK_20_X ||
		etype == PPME_SCHEDSWITCH_6_E)
	{
		query_os = false;
	}
	else
	{
		query_os = true;
	}

	evt->m_tinfo = m_inspector->get_thread(evt->m_pevt->tid, query_os, false);

	if(etype == PPME_SCHEDSWITCH_6_E)
	{
		return false;
	}

	if(!evt->m_tinfo)
	{
		if(etype == PPME_SYSCALL_CLONE_11_X ||
			etype == PPME_SYSCALL_CLONE_16_X ||
			etype == PPME_SYSCALL_CLONE_17_X ||
			etype == PPME_SYSCALL_CLONE_20_X ||
			etype == PPME_SYSCALL_FORK_X ||
			etype == PPME_SYSCALL_FORK_17_X ||
			etype == PPME_SYSCALL_FORK_20_X ||
			etype == PPME_SYSCALL_VFORK_X ||
			etype == PPME_SYSCALL_VFORK_17_X ||
			etype == PPME_SYSCALL_VFORK_20_X)
		{
#ifdef GATHER_INTERNAL_STATS
			m_inspector->m_thread_manager->m_failed_lookups->decrement();
#endif
		}
		else
		{
			ASSERT(false);
		}

		return false;
	}

	if(query_os)
	{
		evt->m_tinfo->m_flags |= PPM_CL_ACTIVE;
	}

	if(PPME_IS_ENTER(etype))
	{
		evt->m_tinfo->m_lastevent_fd = -1;
		evt->m_tinfo->m_lastevent_type = etype;

		if(eflags & EF_USES_FD)
		{
			sinsp_evt_param *parinfo;

			//
			// Get the fd.
			// The fd is always the first parameter of the enter event.
			//
			parinfo = evt->get_param(0);
			ASSERT(parinfo->m_len == sizeof(int64_t));
			ASSERT(evt->get_param_info(0)->type == PT_FD);

			evt->m_tinfo->m_lastevent_fd = *(int64_t *)parinfo->m_val;
			evt->m_fdinfo = evt->m_tinfo->get_fd(evt->m_tinfo->m_lastevent_fd);
		}

		evt->m_tinfo->m_latency = 0;
		evt->m_tinfo->m_last_latency_entertime = evt->get_ts();
	}
	else
	{
		sinsp_threadinfo* tinfo = evt->m_tinfo;

		//
		// event latency
		//
		if(tinfo->m_last_latency_entertime != 0)
		{
			tinfo->m_latency = evt->get_ts() - tinfo->m_last_latency_entertime;
			ASSERT((int64_t)tinfo->m_latency >= 0);
		}

		if(etype == tinfo->m_lastevent_type + 1)
		{
			tinfo->set_lastevent_data_validity(true);
		}
		else
		{
			tinfo->set_lastevent_data_validity(false);
			return false;
		}

		//
		// Error detection logic
		//
		if(evt->m_info->nparams != 0 &&
			((evt->m_info->params[0].name[0] == 'r' && evt->m_info->params[0].name[1] == 'e' && evt->m_info->params[0].name[2] == 's') ||
			(evt->m_info->params[0].name[0] == 'f' && evt->m_info->params[0].name[1] == 'd')))
		{
			sinsp_evt_param *parinfo;

			parinfo = evt->get_param(0);
			ASSERT(parinfo->m_len == sizeof(int64_t));
			int64_t res = *(int64_t *)parinfo->m_val;

			if(res < 0)
			{
				evt->m_errorcode = -(int32_t)res;
			}
		}

		//
		// Retrieve the fd
		//
		if(eflags & EF_USES_FD)
		{
			evt->m_fdinfo = tinfo->get_fd(tinfo->m_lastevent_fd);

			if(evt->m_fdinfo == NULL)
			{
				return false;
			}

			if(evt->m_errorcode != 0 && m_fd_listener)
			{
				m_fd_listener->on_error(evt);
			}
			
			if(evt->m_fdinfo->m_flags & sinsp_fdinfo_t::FLAGS_CLOSE_CANCELED)
			{
				//
				// A close gets canceled when the same fd is created succesfully between
				// close enter and close exit.
				// If that happens
				//
				erase_fd_params eparams;

				evt->m_fdinfo->m_flags &= ~sinsp_fdinfo_t::FLAGS_CLOSE_CANCELED;
				eparams.m_fd = CANCELED_FD_NUMBER;
				eparams.m_fdinfo = tinfo->get_fd(CANCELED_FD_NUMBER);

				//
				// Remove the fd from the different tables
				//
				eparams.m_remove_from_table = true;
				eparams.m_inspector = m_inspector;
				eparams.m_tinfo = tinfo;
				eparams.m_ts = evt->get_ts();

				erase_fd(&eparams);
			}
		}
	}

	return true;
}

void sinsp_parser::store_event(sinsp_evt *evt)
{
	if(!evt->m_tinfo)
	{
		//
		// No thread in the table. We won't store this event, which mean that
		// we won't be able to parse the correspoding exit event and we'll have
		// to drop the information it carries.
		//
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats.m_n_store_drops++;
#endif
		return;
	}

	evt->m_tinfo->store_event(evt);

#ifdef GATHER_INTERNAL_STATS
	m_inspector->m_stats.m_n_stored_evts++;
#endif
}

bool sinsp_parser::retrieve_enter_event(sinsp_evt *enter_evt, sinsp_evt *exit_evt)
{
	//
	// Make sure there's a valid thread info
	//
	if(!exit_evt->m_tinfo)
	{
		return false;
	}

	//
	// Retrieve the copy of the enter event and initialize it
	//
	if(!exit_evt->m_tinfo->is_lastevent_data_valid())
	{
		//
		// This happen especially at the beginning of trace files, where events
		// can be truncated
		//
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats.m_n_retrieve_drops++;
#endif
		return false;
	}

	enter_evt->init(exit_evt->m_tinfo->m_lastevent_data, exit_evt->m_tinfo->m_lastevent_cpuid);

	//
	// Make sure that we're using the right enter event, to prevent inconsistencies when events
	// are dropped
	//
	if(enter_evt->get_type() != (exit_evt->get_type() - 1))
	{
		//ASSERT(false);
		exit_evt->m_tinfo->set_lastevent_data_validity(false);
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats.m_n_retrieve_drops++;
#endif
		return false;
	}

#ifdef GATHER_INTERNAL_STATS
	m_inspector->m_stats.m_n_retrieved_evts++;
#endif
	return true;
}

sinsp_protodecoder* sinsp_parser::add_protodecoder(string decoder_name)
{
	//
	// Make sure this decoder is not present yet
	//
	vector<sinsp_protodecoder*>::iterator it;
	for(it = m_protodecoders.begin(); it != m_protodecoders.end(); ++it)
	{
		if((*it)->get_name() == decoder_name)
		{
			return (*it);
		}
	}

	sinsp_protodecoder* nd = g_decoderlist.new_protodecoder_from_name(decoder_name,
		m_inspector);

	nd->init();

	m_protodecoders.push_back(nd);

	return nd;
}

void sinsp_parser::register_event_callback(sinsp_pd_callback_type etype, sinsp_protodecoder* dec)
{
	switch(etype)
	{
	case CT_OPEN:
		m_open_callbacks.push_back(dec);
		break;
	case CT_CONNECT:
		m_connect_callbacks.push_back(dec);
		break;
	default:
		ASSERT(false);
		break;
	}

	return;
}

///////////////////////////////////////////////////////////////////////////////
// PARSERS
///////////////////////////////////////////////////////////////////////////////
void sinsp_parser::parse_clone_exit(sinsp_evt *evt)
{
	sinsp_evt_param* parinfo;
	int64_t tid = evt->get_tid();
	int64_t childtid;
	bool is_inverted_clone = false; // true if clone() in the child returns before the one in the parent
	bool tid_collision = false;
	bool valid_parent = true;
	bool in_container = false;
	int64_t vtid = tid;
	int64_t vpid = -1;
	uint16_t etype = evt->get_type();

	//
	// Validate the return value and get the child tid
	//
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	childtid = *(int64_t *)parinfo->m_val;

	switch(evt->get_type())
	{
	case PPME_SYSCALL_CLONE_11_X:
		parinfo = evt->get_param(8);
		break;
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_VFORK_X:
		parinfo = evt->get_param(13);
		break;
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_VFORK_17_X:
		parinfo = evt->get_param(14);
		break;
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_20_X:
		parinfo = evt->get_param(15);
		break;
	default:
		ASSERT(false);
	}
	ASSERT(parinfo->m_len == sizeof(int32_t));
	uint32_t flags = *(int32_t *)parinfo->m_val;

	if(childtid < 0)
	{
		//
		// clone() failed. Do nothing and keep going.
		//
		return;
	}
	
	//
	// Get the vtid to check if the clone is within a container
	//
	switch(etype)
	{
	case PPME_SYSCALL_CLONE_11_X:
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_VFORK_X:
	case PPME_SYSCALL_VFORK_17_X:
		break;
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_20_X:
		parinfo = evt->get_param(18);
		ASSERT(parinfo->m_len == sizeof(int64_t));
		vtid = *(int64_t *)parinfo->m_val;

		parinfo = evt->get_param(19);
		ASSERT(parinfo->m_len == sizeof(int64_t));
		vpid = *(int64_t *)parinfo->m_val;
		break;
	default:
		ASSERT(false);
	}

	if(tid != vtid)
	{
		in_container = true;
	}

	if(childtid == 0)
	{
		//
		// clone() returns 0 in the child.
		// Validate that the child thread info has actually been created.
		//
		if(!evt->m_tinfo)
		{
			//
			// No thread yet.
			// This happens if
			//  - clone() returns in the child before than in the parent.
			//  - we dropped the clone exit event in the parent.
			//  - clone was executed in a container
			// In both cases, we create the thread entry here
			//
			// XXX: inverted_clone flag should be useless for containers
			// since just the child's clone is allowed to create a thread
			//
			is_inverted_clone = true;

			//
			// The tid to add is the one that generated this event
			//
			childtid = tid;

			//
			// Check if this is a process or a new thread
			//
			if(flags & PPM_CL_CLONE_THREAD)
			{
				//
				// This is a thread, the parent tid is the pid
				//
				parinfo = evt->get_param(4);
				ASSERT(parinfo->m_len == sizeof(int64_t));
				tid = *(int64_t *)parinfo->m_val;
			}
			else
			{
				//
				// This is not a thread, the parent tid is ptid
				//
				parinfo = evt->get_param(5);
				ASSERT(parinfo->m_len == sizeof(int64_t));
				tid = *(int64_t *)parinfo->m_val;
			}

			//
			// Keep going and add the event with the standard code below
			//
		}
		else
		{
			//
			// We are in the child's clone. If we are in a container, make
			// sure the vtid/vpid are reflected because the father was maybe
			// running outside the container so created the child thread without
			// knowing the internal vtid/vpid
			//
			if(in_container)
			{
				evt->m_tinfo->m_vtid = vtid;
				evt->m_tinfo->m_vpid = vpid;
			}

			return;
		}
	}
	else
	{
		//
		// We are in the father. If the father is running in a container,
		// don't create the child process but wait until we see child, because
		// the father just sees the internal tid of the child
		//
		if(in_container)
		{
			return;
		}
	}

	//
	// Lookup the thread that called clone() so we can copy its information
	//
	sinsp_threadinfo* ptinfo = m_inspector->get_thread(tid, true, true);
	if(NULL == ptinfo)
	{
		//
		// No clone() caller, we probably missed earlier events.
		// We simply return and ignore the event, which means this thread won't be added to the table.
		//
		ASSERT(false);
		return;
	}

	if(ptinfo->m_comm == "<NA>" && ptinfo->m_uid == 0xffffffff)
	{
		valid_parent = false;
	}

	//
	// See if the child is already there
	//
	sinsp_threadinfo* child = m_inspector->get_thread(childtid, false, true);
	if(NULL != child)
	{
		//
		// If this was an inverted clone, all is fine, we've already taken care
		// of adding the thread table entry in the child.
		// Otherwise, we assume that the entry is there because we missed the exit event
		// for a previous thread and we replace the info structure.
		//
		if(child->m_flags & PPM_CL_CLONE_INVERTED)
		{
			return;
		}
		else
		{
			m_inspector->remove_thread(childtid, true);
			tid_collision = true;
		}
	}

	//
	// Allocate the new thread info and initialize it
	// XXX this should absolutely not do a malloc, but get the item from a
	// preallocated list
	//
	sinsp_threadinfo tinfo(m_inspector);

	//
	// Set the tid and parent tid
	//
	tinfo.m_tid = childtid;
	tinfo.m_ptid = tid;

	if(valid_parent)
	{
		// Copy the command name from the parent
		tinfo.m_comm = ptinfo->m_comm;

		// Copy the full executable name from the parent
		tinfo.m_exe = ptinfo->m_exe;

		// Copy the command arguments from the parent
		tinfo.m_args = ptinfo->m_args;
	}
	else
	{
		//
		// Parent is an invalid thread, which is strange since it's performing 
		// a clone. We try to remove and look it up in proc.
		//
		m_inspector->remove_thread(tid, true);
		tid_collision = true;

		ptinfo = m_inspector->get_thread(tid, 
			true, true);

		if(ptinfo == NULL)
		{
			//
			// This can happen if the thread table has reached max capacity
			//
			ASSERT(false);
			return;
		}

		if(ptinfo->m_comm != "<NA>" && ptinfo->m_uid != 0xffffffff)
		{
			//
			// Parent found in proc, use its data
			//
			tinfo.m_comm = ptinfo->m_comm;
			tinfo.m_exe = ptinfo->m_exe;
			tinfo.m_args = ptinfo->m_args;
		}
		else
		{
			//
			// Parent not found in proc, use the event data
			//
			parinfo = evt->get_param(1);
			tinfo.m_exe = (char*)parinfo->m_val;

			switch(etype)
			{
			case PPME_SYSCALL_CLONE_11_X:
			case PPME_SYSCALL_CLONE_16_X:
			case PPME_SYSCALL_FORK_X:
			case PPME_SYSCALL_VFORK_X:
				tinfo.m_comm = tinfo.m_exe;
				break;
			case PPME_SYSCALL_CLONE_17_X:
			case PPME_SYSCALL_CLONE_20_X:
			case PPME_SYSCALL_FORK_17_X:
			case PPME_SYSCALL_FORK_20_X:
			case PPME_SYSCALL_VFORK_17_X:
			case PPME_SYSCALL_VFORK_20_X:
				parinfo = evt->get_param(13);
				tinfo.m_comm = parinfo->m_val;
				break;
			default:
				ASSERT(false);
			}

			parinfo = evt->get_param(2);
			tinfo.set_args(parinfo->m_val, parinfo->m_len);

			//
			// Also, propagate the same values to the parent
			//
			ptinfo->m_comm = tinfo.m_comm;
			ptinfo->m_exe = tinfo.m_exe;
			ptinfo->set_args(parinfo->m_val, parinfo->m_len);
		}
	}

	// Copy the pid
	parinfo = evt->get_param(4);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	tinfo.m_pid = *(int64_t *)parinfo->m_val;

	// Get the flags, and check if this is a thread or a new thread
	tinfo.m_flags = flags;

	//
	// If clone()'s PPM_CL_CLONE_THREAD is not set it means that a new
	// thread was created. In that case, we set the pid to the one of the CHILD thread that
	// is going to be created.
	//
	if(!(tinfo.m_flags & PPM_CL_CLONE_THREAD))
	{
		tinfo.m_pid = childtid;
	}

	//
	// Copy the fd list
	// XXX this is a gross oversimplification that will need to be fixed.
	// What we do is: if the child is NOT a thread, we copy all the parent fds.
	// The right thing to do is looking at PPM_CL_CLONE_FILES, but there are
	// syscalls like open and pipe2 that can override PPM_CL_CLONE_FILES with the O_CLOEXEC flag
	//
	if(!(tinfo.m_flags & PPM_CL_CLONE_THREAD))
	{
		tinfo.m_fdtable = *(ptinfo->get_fd_table());

		//
		// It's important to reset the cache of the child thread, to prevent it from
		// referring to an element in the parent's table.
		//
		tinfo.m_fdtable.reset_cache();
	}
	//if((tinfo.m_flags & (PPM_CL_CLONE_FILES)))
	//{
	//    tinfo.m_fdtable = ptinfo.m_fdtable;
	//}

	if(is_inverted_clone)
	{
		tinfo.m_flags |= PPM_CL_CLONE_INVERTED;
	}

	// Copy the command name
	parinfo = evt->get_param(1);
	tinfo.m_exe = (char*)parinfo->m_val;

	switch(etype)
	{
	case PPME_SYSCALL_CLONE_11_X:
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_VFORK_X:
		tinfo.m_comm = tinfo.m_exe;
		break;
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_17_X:
	case PPME_SYSCALL_VFORK_20_X:
		parinfo = evt->get_param(13);
		tinfo.m_comm = parinfo->m_val;
		break;
	default:
		ASSERT(false);
	}

	// Get the command arguments
	parinfo = evt->get_param(2);
	tinfo.set_args(parinfo->m_val, parinfo->m_len);

	// Copy the working directory
	parinfo = evt->get_param(6);
	tinfo.set_cwd(parinfo->m_val, parinfo->m_len);

	// Copy the fdlimit
	parinfo = evt->get_param(7);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	tinfo.m_fdlimit = *(int64_t *)parinfo->m_val;

	switch(etype)
	{
	case PPME_SYSCALL_CLONE_11_X:
		break;
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_X:
	case PPME_SYSCALL_VFORK_17_X:
	case PPME_SYSCALL_VFORK_20_X:
		// Get the pgflt_maj
		parinfo = evt->get_param(8);
		ASSERT(parinfo->m_len == sizeof(uint64_t));
		tinfo.m_pfmajor = *(uint64_t *)parinfo->m_val;

		// Get the pgflt_min
		parinfo = evt->get_param(9);
		ASSERT(parinfo->m_len == sizeof(uint64_t));
		tinfo.m_pfminor = *(uint64_t *)parinfo->m_val;

		// Get the vm_size
		parinfo = evt->get_param(10);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		tinfo.m_vmsize_kb = *(uint32_t *)parinfo->m_val;

		// Get the vm_rss
		parinfo = evt->get_param(11);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		tinfo.m_vmrss_kb = *(uint32_t *)parinfo->m_val;

		// Get the vm_swap
		parinfo = evt->get_param(12);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		tinfo.m_vmswap_kb = *(uint32_t *)parinfo->m_val;
		break;
	default:
		ASSERT(false);
	}

	// Copy the uid
	switch(etype)
	{
	case PPME_SYSCALL_CLONE_11_X:
		parinfo = evt->get_param(9);
		break;
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_VFORK_X:
		parinfo = evt->get_param(14);
		break;
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_VFORK_17_X:
		parinfo = evt->get_param(15);
		break;
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_20_X:
		parinfo = evt->get_param(16);
		break;
	default:
		ASSERT(false);
	}
	ASSERT(parinfo->m_len == sizeof(int32_t));
	tinfo.m_uid = *(int32_t *)parinfo->m_val;

	// Copy the uid
	switch(etype)
	{
	case PPME_SYSCALL_CLONE_11_X:
		parinfo = evt->get_param(10);
		break;
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_VFORK_X:
		parinfo = evt->get_param(15);
		break;
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_VFORK_17_X:
		parinfo = evt->get_param(16);
		break;
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_20_X:
		parinfo = evt->get_param(17);
		break;
	default:
		ASSERT(false);
	}
	ASSERT(parinfo->m_len == sizeof(int32_t));
	tinfo.m_gid = *(int32_t *)parinfo->m_val;

	//
	// If we're in a container, vtid and vpid are
	// initialized to the values coming from the event,
	// otherwise they are just set to tid and pid. We can't
	// use the event in that case because in a non-container
	// case also the clone exit from the father can create a
	// child process, and it doesn't have the right vtid and vpid
	// values
	//
	if(in_container)
	{
		tinfo.m_vtid = vtid;
		tinfo.m_vpid = vpid;
	}
	else
	{
		tinfo.m_vtid = tinfo.m_tid;
		tinfo.m_vpid = tinfo.m_pid;
	}

	//
	// Set cgroups and heuristically detect container id
	//
	switch(etype)
	{
		case PPME_SYSCALL_CLONE_20_X:
			parinfo = evt->get_param(14);
			tinfo.set_cgroups(parinfo->m_val, parinfo->m_len);
			m_inspector->m_container_manager.resolve_container_from_cgroups(tinfo.m_cgroups, m_inspector->m_islive, &tinfo.m_container_id);
			break;
	}

	//
	// Initilaize the thread clone time
	//
	tinfo.m_clone_ts = evt->get_ts();

	//
	// Add the new thread to the table
	//
	m_inspector->add_thread(tinfo);

	//
	// If we had to erase a previous entry for this tid and rebalance the table,
	// make sure we reinitialize the tinfo pointer for this event, as the thread
	// generating it might have gone away.
	//
	if(tid_collision)
	{
		reset(evt);
#ifdef HAS_ANALYZER
		m_inspector->m_tid_collisions.push_back(tinfo.m_tid);
#endif
#ifdef _DEBUG
		g_logger.format(sinsp_logger::SEV_INFO, 
			"tid collision for %" PRIu64 "(%s)", 
			tinfo.m_tid, tinfo.m_comm.c_str());
#endif
	}

	return;
}

void sinsp_parser::parse_execve_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	uint16_t etype = evt->get_type();

	// Validate the return value
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	retval = *(int64_t *)parinfo->m_val;

	if(retval < 0)
	{
		return;
	}

	//
	// We get here when execve returns. The thread has already been added by a previous fork or clone,
	// and we just update the entry with the new information.
	//
	if(!evt->m_tinfo)
	{
		//
		// No thread to update?
		// We probably missed the start event, so we will just do nothing
		//
		//fprintf(stderr, "comm = %s, args = %s\n",evt->get_param(1)->m_val,evt->get_param(1)->m_val);
		//ASSERT(false);
		return;
	}

	// Get the exe
	parinfo = evt->get_param(1);
	evt->m_tinfo->m_exe = parinfo->m_val;

	switch(etype)
	{
	case PPME_SYSCALL_EXECVE_8_X:
	case PPME_SYSCALL_EXECVE_13_X:
	case PPME_SYSCALL_EXECVE_14_X:
		// Old trace files didn't have comm, so just set it to exe
		evt->m_tinfo->m_comm = evt->m_tinfo->m_exe;
		break;
	case PPME_SYSCALL_EXECVE_15_X:
	case PPME_SYSCALL_EXECVE_16_X:
		// Get the comm
		parinfo = evt->get_param(13);
		evt->m_tinfo->m_comm = parinfo->m_val;
		break;
	default:
		ASSERT(false);
	}

	// Get the command arguments
	parinfo = evt->get_param(2);
	evt->m_tinfo->set_args(parinfo->m_val, parinfo->m_len);

	// Get the pid
	parinfo = evt->get_param(4);
	ASSERT(parinfo->m_len == sizeof(uint64_t));
	evt->m_tinfo->m_pid = *(uint64_t *)parinfo->m_val;

	// Get the working directory
	parinfo = evt->get_param(6);
	evt->m_tinfo->set_cwd(parinfo->m_val, parinfo->m_len);

	// Get the fdlimit
	parinfo = evt->get_param(7);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	evt->m_tinfo->m_fdlimit = *(int64_t *)parinfo->m_val;

	switch(etype)
	{
	case PPME_SYSCALL_EXECVE_8_X:
		break;
	case PPME_SYSCALL_EXECVE_13_X:
	case PPME_SYSCALL_EXECVE_14_X:
	case PPME_SYSCALL_EXECVE_15_X:
	case PPME_SYSCALL_EXECVE_16_X:
		// Get the pgflt_maj
		parinfo = evt->get_param(8);
		ASSERT(parinfo->m_len == sizeof(uint64_t));
		evt->m_tinfo->m_pfmajor = *(uint64_t *)parinfo->m_val;

		// Get the pgflt_min
		parinfo = evt->get_param(9);
		ASSERT(parinfo->m_len == sizeof(uint64_t));
		evt->m_tinfo->m_pfminor = *(uint64_t *)parinfo->m_val;

		// Get the vm_size
		parinfo = evt->get_param(10);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		evt->m_tinfo->m_vmsize_kb = *(uint32_t *)parinfo->m_val;

		// Get the vm_rss
		parinfo = evt->get_param(11);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		evt->m_tinfo->m_vmrss_kb = *(uint32_t *)parinfo->m_val;

		// Get the vm_swap
		parinfo = evt->get_param(12);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		evt->m_tinfo->m_vmswap_kb = *(uint32_t *)parinfo->m_val;
		break;
	default:
		ASSERT(false);
	}

	switch(etype)
	{
	case PPME_SYSCALL_EXECVE_8_X:
	case PPME_SYSCALL_EXECVE_13_X:
		break;
	case PPME_SYSCALL_EXECVE_14_X:
		// Get the environment
		parinfo = evt->get_param(13);
		evt->m_tinfo->set_env(parinfo->m_val, parinfo->m_len);
		break;
	case PPME_SYSCALL_EXECVE_15_X:
		// Get the environment
		parinfo = evt->get_param(14);
		evt->m_tinfo->set_env(parinfo->m_val, parinfo->m_len);
		break;
	case PPME_SYSCALL_EXECVE_16_X:
		// Get the environment
		parinfo = evt->get_param(15);
		evt->m_tinfo->set_env(parinfo->m_val, parinfo->m_len);

		//
		// Set cgroups and heuristically detect container id
		//
		parinfo = evt->get_param(14);
		evt->m_tinfo->set_cgroups(parinfo->m_val, parinfo->m_len);
		if(evt->m_tinfo->m_container_id.empty())
		{
			m_inspector->m_container_manager.resolve_container_from_cgroups(evt->m_tinfo->m_cgroups, m_inspector->m_islive, &evt->m_tinfo->m_container_id);
		}
		break;
	default:
		ASSERT(false);
	}

	//
	// execve starts with a clean fd list, so we get rid of the fd list that clone
	// copied from the parent
	// XXX validate this
	//
	//  scap_fd_free_table(handle, tinfo);

	//
	// Clear the flags for this thread, making sure to propagate the inverted flag
	//
	bool inverted = ((evt->m_tinfo->m_flags & PPM_CL_CLONE_INVERTED) != 0);
	evt->m_tinfo->m_flags = PPM_CL_ACTIVE;
	if(inverted)
	{
		evt->m_tinfo->m_flags |= PPM_CL_CLONE_INVERTED;
	}

	//
	// This process' name changed, so we need to include it in the protocol again
	//
	evt->m_tinfo->m_flags |= PPM_CL_NAME_CHANGED;

	//
	// Recompute the program hash
	//
	evt->m_tinfo->compute_program_hash();

#ifdef HAS_ANALYZER
	evt->m_tinfo->m_ainfo->clear_role_flags();
#endif
	return;
}

void sinsp_parser::parse_openat_dir(sinsp_evt *evt, char* name, int64_t dirfd, OUT string* sdir)
{
	bool is_absolute = (name[0] == '/');
	string tdirstr;

	if(is_absolute)
	{
		//
		// The path is absoulte.
		// Some processes (e.g. irqbalance) actually do this: they pass an invalid fd and
		// and bsolute path, and openat succeeds.
		//
		*sdir = ".";
	}
	else if(dirfd == PPM_AT_FDCWD)
	{
		*sdir = evt->m_tinfo->get_cwd();
	}
	else
	{
		evt->m_fdinfo = evt->m_tinfo->get_fd(dirfd);

		if(evt->m_fdinfo == NULL)
		{
			ASSERT(false);
			*sdir = "<UNKNOWN>";
		}
		else
		{
			if(evt->m_fdinfo->m_name[evt->m_fdinfo->m_name.length()] == '/')
			{
				*sdir = evt->m_fdinfo->m_name;
			}
			else
			{
				tdirstr = evt->m_fdinfo->m_name + '/';
				*sdir = tdirstr;
			}
		}
	}
}

void sinsp_parser::parse_open_openat_creat_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t fd;
	char *name;
	uint32_t namelen;
	uint32_t flags;
	//  uint32_t mode;
	sinsp_fdinfo_t fdi;
	sinsp_evt *enter_evt = &m_tmp_evt;
	string sdir;

	ASSERT(evt->m_tinfo);

	//
	// Load the enter event so we can access its arguments
	//
	if(!retrieve_enter_event(enter_evt, evt))
	{
		return;
	}

	//
	// Check the return value
	//
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd = *(int64_t *)parinfo->m_val;

	//
	// Parse the parameters, based on the event type
	//
	if(evt->get_type() == PPME_SYSCALL_OPEN_X)
	{
		parinfo = evt->get_param(1);
		name = parinfo->m_val;
		namelen = parinfo->m_len;

		parinfo = evt->get_param(2);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		flags = *(uint32_t *)parinfo->m_val;

		sdir = evt->m_tinfo->get_cwd();
	}
	else if(evt->get_type() == PPME_SYSCALL_CREAT_X)
	{
		parinfo = evt->get_param(1);
		name = parinfo->m_val;
		namelen = parinfo->m_len;

		flags = 0;

		sdir = evt->m_tinfo->get_cwd();
	}
	else if(evt->get_type() == PPME_SYSCALL_OPENAT_X)
	{
		parinfo = enter_evt->get_param(1);
		name = parinfo->m_val;
		namelen = parinfo->m_len;

		parinfo = enter_evt->get_param(2);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		flags = *(uint32_t *)parinfo->m_val;

		parinfo = enter_evt->get_param(0);
		ASSERT(parinfo->m_len == sizeof(int64_t));
		int64_t dirfd = *(int64_t *)parinfo->m_val;

		parse_openat_dir(evt, name, dirfd, &sdir);
	}
	else
	{
		ASSERT(false);
		return;
	}

	// XXX not implemented yet
	//parinfo = evt->get_param(2);
	//ASSERT(parinfo->m_len == sizeof(uint32_t));
	//mode = *(uint32_t*)parinfo->m_val;

	char fullpath[SCAP_MAX_PATH_SIZE];
	sinsp_utils::concatenate_paths(fullpath, SCAP_MAX_PATH_SIZE, sdir.c_str(), (uint32_t)sdir.length(), name, namelen);

	if(fd >= 0)
	{
		//
		// Populate the new fdi
		//
		if(flags & PPM_O_DIRECTORY)
		{
			fdi.m_type = SCAP_FD_DIRECTORY;
		}
		else
		{
			fdi.m_type = SCAP_FD_FILE;		
		}

		fdi.m_openflags = flags;
		fdi.add_filename(fullpath);

		//
		// Add the fd to the table.
		//
		evt->m_fdinfo = evt->m_tinfo->add_fd(fd, &fdi);

		//
		// Call the protocol decoder callbacks associated to this event
		//
		vector<sinsp_protodecoder*>::iterator it;
		for(it = m_open_callbacks.begin(); it != m_open_callbacks.end(); ++it)
		{
			(*it)->on_event(evt, CT_OPEN);
		}
	}

	if(m_fd_listener && !(flags & PPM_O_DIRECTORY))
	{
		m_fd_listener->on_file_create(evt, fullpath);
	}
}

//
// Helper function to allocate a socket fd, initialize it by parsing its parameters and add it to the fd table of the given thread.
//
inline void sinsp_parser::add_socket(sinsp_evt *evt, int64_t fd, uint32_t domain, uint32_t type, uint32_t protocol)
{
	sinsp_fdinfo_t fdi;

	//
	// Populate the new fdi
	//
	memset(&(fdi.m_sockinfo.m_ipv4info), 0, sizeof(fdi.m_sockinfo.m_ipv4info));
	fdi.m_type = SCAP_FD_UNKNOWN;
	fdi.m_sockinfo.m_ipv4info.m_fields.m_l4proto = SCAP_L4_UNKNOWN;

	if(domain == PPM_AF_UNIX)
	{
		fdi.m_type = SCAP_FD_UNIX_SOCK;
	}
	else if(domain == PPM_AF_INET || domain == PPM_AF_INET6)
	{
		fdi.m_type = (domain == PPM_AF_INET)? SCAP_FD_IPV4_SOCK : SCAP_FD_IPV6_SOCK;

		if(protocol == IPPROTO_TCP)
		{
			fdi.m_sockinfo.m_ipv4info.m_fields.m_l4proto = SCAP_L4_TCP;
		}
		else if(protocol == IPPROTO_UDP)
		{
			fdi.m_sockinfo.m_ipv4info.m_fields.m_l4proto = SCAP_L4_UDP;
		}
		else if(protocol == IPPROTO_IP)
		{
			//
			// XXX: we mask type because, starting from linux 2.6.27, type can be ORed with
			//      SOCK_NONBLOCK and SOCK_CLOEXEC. We need to validate that byte masking is
			//      acceptable
			//
			if((type & 0xff) == SOCK_STREAM)
			{
				fdi.m_sockinfo.m_ipv4info.m_fields.m_l4proto = SCAP_L4_TCP;
			}
			else if((type & 0xff) == SOCK_DGRAM)
			{
				fdi.m_sockinfo.m_ipv4info.m_fields.m_l4proto = SCAP_L4_UDP;
			}
			else
			{
				ASSERT(false);
			}
		}
		else if(protocol == IPPROTO_ICMP)
		{
			fdi.m_sockinfo.m_ipv4info.m_fields.m_l4proto = SCAP_L4_ICMP;
		}
	}
	else
	{
		if(domain != 16 &&  // AF_NETLINK, used by processes to talk to the kernel
		        domain != 10 && // IPv6
		        domain != 17)   // AF_PACKET, used for packet capture
		{
			//
			// IPv6 will go here
			//
			ASSERT(false);
		}
	}

#ifndef INCLUDE_UNKNOWN_SOCKET_FDS
	if(fdi.m_type == SCAP_FD_UNKNOWN)
	{
		return;
	}
#endif

	//
	// Add the fd to the table.
	//
	evt->m_fdinfo = evt->m_tinfo->add_fd(fd, &fdi);
}

void sinsp_parser::parse_socket_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t fd;
	uint32_t domain;
	uint32_t type;
	uint32_t protocol;
	sinsp_evt *enter_evt = &m_tmp_evt;

	//
	// NOTE: we don't check the return value of get_param() because we know the arguments we need are there.
	// XXX this extraction would be much faster if we parsed the event mnaually to extract the
	// parameters in one scan. We don't care too much because we assume that we get here
	// seldom enough that saving few tens of CPU cycles is not important.
	//
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd = *(int64_t *)parinfo->m_val;

	if(fd < 0)
	{
		//
		// socket() failed. Nothing to add to the table.
		//
		return;
	}

	//
	// Load the enter event so we can access its arguments
	//
	if(!retrieve_enter_event(enter_evt, evt))
	{
		return;
	}

	//
	// Extract the arguments
	//
	parinfo = enter_evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	domain = *(uint32_t *)parinfo->m_val;

	parinfo = enter_evt->get_param(1);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	type = *(uint32_t *)parinfo->m_val;

	parinfo = enter_evt->get_param(2);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	protocol = *(uint32_t *)parinfo->m_val;

	//
	// Allocate a new fd descriptor, populate it and add it to the thread fd table
	//
	add_socket(evt, fd, domain, type, protocol);
}

void sinsp_parser::parse_bind_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	const char *parstr;
	uint8_t *packed_data;
	uint8_t family;

	if(evt->m_fdinfo == NULL)
	{
		return;
	}

	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(uint64_t));
	retval = *(int64_t*)parinfo->m_val;

	if(retval < 0)
	{
		return;
	}

	parinfo = evt->get_param(1);
	if(parinfo->m_len == 0)
	{
		//
		// No address, there's nothing we can really do with this.
		// This happens for socket types that we don't support, so we have the assertion
		// to make sure that this is not a type of socket that we support.
		//
		ASSERT(!(evt->m_fdinfo->is_unix_socket() || evt->m_fdinfo->is_ipv4_socket()));
		return;
	}

	packed_data = (uint8_t*)parinfo->m_val;

	family = *packed_data;

	//
	// Update the FD info with this tuple, assume that if port > 0, means that
	// the socket is used for listening
	//
	if(family == PPM_AF_INET)
	{
		uint16_t port = *(uint16_t *)(packed_data + 5);
		if(port > 0)
		{
			evt->m_fdinfo->m_type = SCAP_FD_IPV4_SERVSOCK;
			evt->m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_port = port;
		}
	}
	else if (family == PPM_AF_INET6)
	{
		uint16_t port = *(uint16_t *)(packed_data + 17);
		if(port > 0)
		{
			evt->m_fdinfo->m_type = SCAP_FD_IPV6_SERVSOCK;
			evt->m_fdinfo->m_sockinfo.m_ipv6serverinfo.m_port = port;
		}
	}
	//
	// Update the name of this socket
	//
	evt->m_fdinfo->m_name = evt->get_param_as_str(1, &parstr, sinsp_evt::PF_SIMPLE);
}

void sinsp_parser::parse_connect_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	uint8_t *packed_data;
	uint8_t family;
	unordered_map<int64_t, sinsp_fdinfo_t>::iterator fdit;
	const char *parstr;
	int64_t retval;

	if(evt->m_fdinfo == NULL)
	{
		return;
	}

	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(uint64_t));
	retval = *(int64_t*)parinfo->m_val;

	if(retval < 0)
	{
		//
		// connections that return with a SE_EINPROGRESS are totally legit.
		//
		if(retval != -SE_EINPROGRESS)
		{
			return;
		}
	}

	parinfo = evt->get_param(1);
	if(parinfo->m_len == 0)
	{
		//
		// No address, there's nothing we can really do with this.
		// This happens for socket types that we don't support, so we have the assertion
		// to make sure that this is not a type of socket that we support.
		//
		ASSERT(!(evt->m_fdinfo->is_unix_socket() || evt->m_fdinfo->is_ipv4_socket()));
		return;
	}

	packed_data = (uint8_t*)parinfo->m_val;

	//
	// Validate the family
	//
	family = *packed_data;

	//
	// Fill the fd with the socket info
	//
	if(family == PPM_AF_INET || family == PPM_AF_INET6)
	{
		if(family == PPM_AF_INET6)
		{
			//
			// For the moment, we only support IPv4-mapped IPv6 addresses
			// (http://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses)
			//
			uint8_t* sip = packed_data + 1;
			uint8_t* dip = packed_data + 19;

			if(!(sinsp_utils::is_ipv4_mapped_ipv6(sip) && sinsp_utils::is_ipv4_mapped_ipv6(dip)))
			{
				return;
			}

			evt->m_fdinfo->m_type = SCAP_FD_IPV4_SOCK;
		}

		//
		// This should happen only in case of a bug in our code, because I'm assuming that the OS
		// causes a connect with the wrong socket type to fail.
		// Assert in debug mode and just keep going in release mode.
		//
		ASSERT(evt->m_fdinfo->m_type == SCAP_FD_IPV4_SOCK);

#ifndef HAS_ANALYZER
		//
		// Update the FD info with this tuple
		//
		if(family == PPM_AF_INET)
		{
			m_inspector->m_parser->set_ipv4_addresses_and_ports(evt->m_fdinfo, packed_data);
		}
		else
		{
			m_inspector->m_parser->set_ipv4_mapped_ipv6_addresses_and_ports(evt->m_fdinfo, packed_data);
		}
#endif

		//
		// Add the friendly name to the fd info
		//
		evt->m_fdinfo->m_name = evt->get_param_as_str(1, &parstr, sinsp_evt::PF_SIMPLE);
	}
	else
	{
		if(!evt->m_fdinfo->is_unix_socket())
		{
			//
			// This should happen only in case of a bug in our code, because I'm assuming that the OS
			// causes a connect with the wrong socket type to fail.
			// Assert in debug mode and just keep going in release mode.
			//
			ASSERT(false);
		}

		//
		// Add the friendly name to the fd info
		//
		evt->m_fdinfo->m_name = evt->get_param_as_str(1, &parstr, sinsp_evt::PF_SIMPLE);

#ifndef HAS_ANALYZER
		//
		// Update the FD with this tuple
		//
		m_inspector->m_parser->set_unix_info(evt->m_fdinfo, packed_data);
#endif
	}

	//
	// Mark this fd as a client
	//
	evt->m_fdinfo->set_role_client();

	//
	// Call the protocol decoder callbacks associated to this event
	//
	vector<sinsp_protodecoder*>::iterator it;
	for(it = m_connect_callbacks.begin(); it != m_connect_callbacks.end(); ++it)
	{
		(*it)->on_event(evt, CT_CONNECT);
	}

	//
	// If there's a listener callback, invoke it
	//
	if(m_fd_listener)
	{
		m_fd_listener->on_connect(evt, packed_data);
	}
}

void sinsp_parser::parse_accept_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t fd;
	uint8_t* packed_data;
	unordered_map<int64_t, sinsp_fdinfo_t>::iterator fdit;
	sinsp_fdinfo_t fdi;
	const char *parstr;

	//
	// Lookup the thread
	//
	if(!evt->m_tinfo)
	{
		ASSERT(false);
		return;
	}

	//
	// Extract the fd
	//
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd = *(int64_t *)parinfo->m_val;

	if(fd < 0)
	{
		//
		// Accept failure.
		// Do nothing.
		//
		return;
	}

	//
	// Update the last event fd. It's needed by the filtering engine
	//
	evt->m_tinfo->m_lastevent_fd = fd;

	//
	// Extract the address
	//
	parinfo = evt->get_param(1);
	if(parinfo->m_len == 0)
	{
		//
		// No address, there's nothing we can really do with this.
		// This happens for socket types that we don't support, so we have the assertion
		// to make sure that this is not a type of socket that we support.
		//
		return;
	}

	packed_data = (uint8_t*)parinfo->m_val;

	//
	// Populate the fd info class
	//
	if(*packed_data == PPM_AF_INET)
	{
		set_ipv4_addresses_and_ports(&fdi, packed_data);
		fdi.m_type = SCAP_FD_IPV4_SOCK;
		fdi.m_sockinfo.m_ipv4info.m_fields.m_l4proto = SCAP_L4_TCP;
	}
	else if(*packed_data == PPM_AF_INET6)
	{
		//
		// We only support IPv4-mapped IPv6 addresses (http://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses)
		// for the moment
		//
		uint8_t* sip = packed_data + 1;
		uint8_t* dip = packed_data + 19;

		if(sinsp_utils::is_ipv4_mapped_ipv6(sip) && sinsp_utils::is_ipv4_mapped_ipv6(dip))
		{
			set_ipv4_mapped_ipv6_addresses_and_ports(&fdi, packed_data);
			fdi.m_type = SCAP_FD_IPV4_SOCK;
			fdi.m_sockinfo.m_ipv4info.m_fields.m_l4proto = SCAP_L4_TCP;
		}
		else
		{
			fdi.m_type = SCAP_FD_IPV6_SOCK;
		}
	}
	else if(*packed_data == PPM_AF_UNIX)
	{
		fdi.m_type = SCAP_FD_UNIX_SOCK;
		set_unix_info(&fdi, packed_data);
	}
	else
	{
		//
		// Unsupported family
		//
		return;
	}

	fdi.m_name = evt->get_param_as_str(1, &parstr, sinsp_evt::PF_SIMPLE);
	fdi.m_flags = 0;

	if(m_fd_listener)
	{
		m_fd_listener->on_accept(evt, fd, packed_data, &fdi);
	}

	//
	// Mark this fd as a server
	//
	fdi.set_role_server();

	//
	// Add the entry to the table
	//
	evt->m_fdinfo = evt->m_tinfo->add_fd(fd, &fdi);
}

void sinsp_parser::parse_close_enter(sinsp_evt *evt)
{
	if(!evt->m_tinfo)
	{
		return;
	}

	evt->m_fdinfo = evt->m_tinfo->get_fd(evt->m_tinfo->m_lastevent_fd);
	if(evt->m_fdinfo == NULL)
	{
		return;
	}

	evt->m_fdinfo->m_flags |= sinsp_fdinfo_t::FLAGS_CLOSE_IN_PROGRESS;
}

//
// This function takes care of cleanung up the FD and removing it from all the tables
// (process FD table, connection table...).
// It's invoked when a close() or a threadexit happens.
//
void sinsp_parser::erase_fd(erase_fd_params* params)
{
	if(params->m_fdinfo == NULL)
	{
		//
		// This happens when more than one close has been canceled at the same time for
		// this thread. Since we currently handle just one canceling at at time (we
		// don't have a list of canceled closes, just a single entry), the second one
		// will generate a failed FD lookup. We do nothing.
		// NOTE: I do realize that this can cause a connection leak, I just assume that it's
		//       rare enough that the delayed connection cleanup (when the timestamp expires)
		//       is acceptable.
		//
		ASSERT(params->m_fd == CANCELED_FD_NUMBER);
		return;
	}

	//
	// Schedule the fd for removal
	//
	if(params->m_remove_from_table)
	{
		params->m_inspector->m_tid_of_fd_to_remove = params->m_tinfo->m_tid;
		params->m_inspector->m_fds_to_remove->push_back(params->m_fd);
	}

	if(m_fd_listener)
	{
		m_fd_listener->on_erase_fd(params);
	}
}

void sinsp_parser::parse_close_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// If the close() was successful, do the cleanup
	//
	if(retval >= 0)
	{
		if(evt->m_fdinfo == NULL)
		{
			return;
		}

		//
		// a close gets canceled when the same fd is created succesfully between
		// close enter and close exit.
		//
		erase_fd_params eparams;

		if(evt->m_fdinfo->m_flags & sinsp_fdinfo_t::FLAGS_CLOSE_CANCELED)
		{
			evt->m_fdinfo->m_flags &= ~sinsp_fdinfo_t::FLAGS_CLOSE_CANCELED;
			eparams.m_fd = CANCELED_FD_NUMBER;
			eparams.m_fdinfo = evt->m_tinfo->get_fd(CANCELED_FD_NUMBER);
		}
		else
		{
			eparams.m_fd = evt->m_tinfo->m_lastevent_fd;
			eparams.m_fdinfo = evt->m_fdinfo;
		}

		//
		// Remove the fd from the different tables
		//
		eparams.m_remove_from_table = true;
		eparams.m_inspector = m_inspector;
		eparams.m_tinfo = evt->m_tinfo;
		eparams.m_ts = evt->get_ts();

		erase_fd(&eparams);
	}
	else
	{
		if(evt->m_fdinfo != NULL)
		{
			evt->m_fdinfo->m_flags &= ~sinsp_fdinfo_t::FLAGS_CLOSE_IN_PROGRESS;
		}

		//
		// It is normal when a close fails that the fd lookup failed, so we revert the
		// increment of m_n_failed_fd_lookups (for the enter event too if there's one).
		//
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats.m_n_failed_fd_lookups--;
#endif
		if(evt->m_tinfo && evt->m_tinfo->is_lastevent_data_valid())
		{
#ifdef GATHER_INTERNAL_STATS
			m_inspector->m_stats.m_n_failed_fd_lookups--;
#endif
		}
	}
}

void sinsp_parser::add_pipe(sinsp_evt *evt, int64_t tid, int64_t fd, uint64_t ino)
{
	sinsp_fdinfo_t fdi;

	//
	// lookup the thread info
	//
	if(!evt->m_tinfo)
	{
		return;
	}

	//
	// Populate the new fdi
	//
	fdi.m_type = SCAP_FD_FIFO;
	fdi.m_name = "";
	fdi.m_ino = ino;

	//
	// Add the fd to the table.
	//
	evt->m_fdinfo = evt->m_tinfo->add_fd(fd, &fdi);
}

void sinsp_parser::parse_socketpair_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t fd1, fd2;
	int64_t retval;
	uint64_t source_address;
	uint64_t peer_address;

	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	if(retval < 0)
	{
		//
		// socketpair() failed. Nothing to add to the table.
		//
		return;
	}

	parinfo = evt->get_param(1);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd1 = *(int64_t *)parinfo->m_val;

	parinfo = evt->get_param(2);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd2 = *(int64_t *)parinfo->m_val;

	parinfo = evt->get_param(3);
	ASSERT(parinfo->m_len == sizeof(uint64_t));
	source_address = *(uint64_t *)parinfo->m_val;

	parinfo = evt->get_param(4);
	ASSERT(parinfo->m_len == sizeof(uint64_t));
	peer_address = *(uint64_t *)parinfo->m_val;

	sinsp_fdinfo_t fdi;
	fdi.m_type = SCAP_FD_UNIX_SOCK;
	fdi.m_sockinfo.m_unixinfo.m_fields.m_source = source_address;
	fdi.m_sockinfo.m_unixinfo.m_fields.m_dest = peer_address;
	evt->m_fdinfo = evt->m_tinfo->add_fd(fd1, &fdi);
	evt->m_tinfo->add_fd(fd2, &fdi);
}

void sinsp_parser::parse_pipe_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t fd1, fd2;
	int64_t retval;
	uint64_t ino;

	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	if(retval < 0)
	{
		//
		// pipe() failed. Nothing to add to the table.
		//
		return;
	}

	parinfo = evt->get_param(1);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd1 = *(int64_t *)parinfo->m_val;

	parinfo = evt->get_param(2);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd2 = *(int64_t *)parinfo->m_val;

	parinfo = evt->get_param(3);
	ASSERT(parinfo->m_len == sizeof(uint64_t));
	ino = *(uint64_t *)parinfo->m_val;

	add_pipe(evt, evt->get_tid(), fd1, ino);
	add_pipe(evt, evt->get_tid(), fd2, ino);
}


void sinsp_parser::parse_thread_exit(sinsp_evt *evt)
{
	//
	// Schedule the process for removal
	//
	if(evt->m_tinfo)
	{
		evt->m_tinfo->m_flags |= PPM_CL_CLOSED;
		m_inspector->m_tid_to_remove = evt->get_tid();
	}
}

bool sinsp_parser::set_ipv4_addresses_and_ports(sinsp_fdinfo_t* fdinfo, uint8_t* packed_data)
{
	uint32_t tsip, tdip;
	uint16_t tsport, tdport;

	tsip = *(uint32_t *)(packed_data + 1);
	tsport = *(uint16_t *)(packed_data + 5);
	tdip = *(uint32_t *)(packed_data + 7);
	tdport = *(uint16_t *)(packed_data + 11);

	if(fdinfo->m_type == SCAP_FD_IPV4_SOCK)
	{
		if((tsip == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip &&
			tsport == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport &&
			tdip == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip &&
			tdport == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport) ||
			(tdip == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip &&
			tdport == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport &&
			tsip == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip &&
			tsport == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport)
			)
		{
			return false;
		}
	}

	fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip = tsip;
	fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport = tsport;
	fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip = tdip;
	fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport = tdport;

	return true;
}

bool sinsp_parser::set_ipv4_mapped_ipv6_addresses_and_ports(sinsp_fdinfo_t* fdinfo, uint8_t* packed_data)
{
	uint32_t tsip, tdip;
	uint16_t tsport, tdport;

	tsip = *(uint32_t *)(packed_data + 13);
	tsport = *(uint16_t *)(packed_data + 17);
	tdip = *(uint32_t *)(packed_data + 31);
	tdport = *(uint16_t *)(packed_data + 35);

	if(fdinfo->m_type == SCAP_FD_IPV4_SOCK)
	{
		if((tsip == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip &&
			tsport == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport &&
			tdip == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip &&
			tdport == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport) ||
			(tdip == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip &&
			tdport == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport &&
			tsip == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip &&
			tsport == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport)
			)
		{
			return false;
		}
	}

	fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip = tsip;
	fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport = tsport;
	fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip = tdip;
	fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport = tdport;

	return true;
}

bool sinsp_parser::set_unix_info(sinsp_fdinfo_t* fdinfo, uint8_t* packed_data)
{
	fdinfo->m_sockinfo.m_unixinfo.m_fields.m_source = *(uint64_t *)(packed_data + 1);
	fdinfo->m_sockinfo.m_unixinfo.m_fields.m_dest = *(uint64_t *)(packed_data + 9);

	return true;
}


// Return false if the update didn't happen (for example because the tuple is NULL)
bool sinsp_parser::update_fd(sinsp_evt *evt, sinsp_evt_param *parinfo)
{
	uint8_t* packed_data = (uint8_t*)parinfo->m_val;
	uint8_t family = *packed_data;

	if(parinfo->m_len == 0)
	{
		return false;
	}

	if(family == PPM_AF_INET)
	{
		if(evt->m_fdinfo->m_type == SCAP_FD_IPV4_SERVSOCK)
		{
			//
			// If this was previously a server socket, propagate the L4 protocol
			//
			evt->m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_l4proto =
				evt->m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_l4proto;
		}

		evt->m_fdinfo->m_type = SCAP_FD_IPV4_SOCK;
		if(set_ipv4_addresses_and_ports(evt->m_fdinfo, packed_data) == false)
		{
			return false;
		}
	}
	else if(family == PPM_AF_INET6)
	{
		//
		// For the moment, we only support IPv4-mapped IPv6 addresses
		// (http://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses)
		//
		uint8_t* sip = packed_data + 1;
		uint8_t* dip = packed_data + 19;

		if(!(sinsp_utils::is_ipv4_mapped_ipv6(sip) && sinsp_utils::is_ipv4_mapped_ipv6(dip)))
		{
			return false;
		}

		evt->m_fdinfo->m_type = SCAP_FD_IPV4_SOCK;

		if(set_ipv4_mapped_ipv6_addresses_and_ports(evt->m_fdinfo, packed_data) == false)
		{
			return false;
		}
	}
	else if(family == PPM_AF_UNIX)
	{
		evt->m_fdinfo->m_type = SCAP_FD_UNIX_SOCK;
		if(set_unix_info(evt->m_fdinfo, packed_data) == false)
		{
			return false;
		}

		evt->m_fdinfo->m_name = ((char*)packed_data) + 17;

		//
		// Call the protocol decoder callbacks to notify the decoders that this FD
		// changed.
		//
		vector<sinsp_protodecoder*>::iterator it;
		for(it = m_connect_callbacks.begin(); it != m_connect_callbacks.end(); ++it)
		{
			(*it)->on_event(evt, CT_TUPLE_CHANGE);
		}

		return true;
	}

	//
	// If we reach this point and the protocol is not set yet, we assume this
	// connection is UDP, because TCP would fail if the address is changed in
	// the middle of a connection.
	//
	if(evt->m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_l4proto == SCAP_L4_UNKNOWN)
	{
		evt->m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_l4proto = SCAP_L4_UDP;
	}

	//
	// If this is an incomplete tuple, patch it using interface info
	//
	m_inspector->m_network_interfaces->update_fd(evt->m_fdinfo);

	//
	// Call the protocol decoder callbacks to notify the decoders that this FD
	// changed.
	//
	vector<sinsp_protodecoder*>::iterator it;
	for(it = m_connect_callbacks.begin(); it != m_connect_callbacks.end(); ++it)
	{
		(*it)->on_event(evt, CT_TUPLE_CHANGE);
	}

	return true;
}

void sinsp_parser::swap_ipv4_addresses(sinsp_fdinfo_t* fdinfo)
{
	uint32_t tip;
	uint16_t tport;

	tip = fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip;
	tport = fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport;
	fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip = fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip;
	fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport = fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport;
	fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip = tip;
	fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport = tport;
}

void sinsp_parser::parse_rw_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	int64_t tid = evt->get_tid();
	sinsp_evt *enter_evt = &m_tmp_evt;
	ppm_event_flags eflags = evt->get_flags();

	if(!evt->m_fdinfo)
	{
		return;
	}

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	retval = *(int64_t *)parinfo->m_val;

	//
	// If the operation was successful, validate that the fd exists
	//
	if(retval >= 0)
	{
		uint16_t etype = evt->get_type();

		if(eflags & EF_READS_FROM_FD)
		{
			char *data;
			uint32_t datalen;
			int32_t tupleparam = -1;

			if(etype == PPME_SOCKET_RECVFROM_X)
			{
				tupleparam = 2;
			}
			else if(etype == PPME_SOCKET_RECVMSG_X)
			{
				tupleparam = 3;
			}

			if(tupleparam != -1 && (evt->m_fdinfo->m_name.length() == 0 || !evt->m_fdinfo->is_tcp_socket()))
			{
				//
				// recvfrom contains tuple info.
				// If the fd still doesn't contain tuple info (because the socket is a
				// datagram one or because some event was lost),
				// add it here.
				//
				if(update_fd(evt, evt->get_param(tupleparam)))
				{
					const char *parstr;

					scap_fd_type fdtype = evt->m_fdinfo->m_type;

					if(fdtype == SCAP_FD_IPV4_SOCK)
					{
						if(evt->m_fdinfo->is_role_none())
						{
								evt->m_fdinfo->set_net_role_by_guessing(m_inspector,
									evt->m_tinfo,
									evt->m_fdinfo,
									true);
						}

						if(evt->m_fdinfo->is_role_client())
						{
							swap_ipv4_addresses(evt->m_fdinfo);
						}

						sinsp_utils::sockinfo_to_str(&evt->m_fdinfo->m_sockinfo,
							fdtype, &evt->m_paramstr_storage[0],
							(uint32_t)evt->m_paramstr_storage.size(),
							m_inspector->m_hostname_and_port_resolution_enabled);

						evt->m_fdinfo->m_name = &evt->m_paramstr_storage[0];
					}
					else
					{
						evt->m_fdinfo->m_name = evt->get_param_as_str(tupleparam, &parstr, sinsp_evt::PF_SIMPLE);
					}
				}
			}

			//
			// Extract the data buffer
			//
			if(etype == PPME_SYSCALL_READV_X || etype == PPME_SYSCALL_PREADV_X || etype == PPME_SOCKET_RECVMSG_X)
			{
				parinfo = evt->get_param(2);
			}
			else
			{
				parinfo = evt->get_param(1);
			}

			datalen = parinfo->m_len;
			data = parinfo->m_val;

			//
			// If there's an fd listener, call it now
			//
			if(m_fd_listener)
			{
				m_fd_listener->on_read(evt, tid, evt->m_tinfo->m_lastevent_fd, evt->m_fdinfo, 
					data, (uint32_t)retval, datalen);
			}

			//
			// Call the protocol decoder callbacks associated to this event
			//
			if(evt->m_fdinfo->m_callbaks)
			{
				vector<sinsp_protodecoder*>* cbacks = &(evt->m_fdinfo->m_callbaks->m_read_callbacks);

				for(auto it = cbacks->begin(); it != cbacks->end(); ++it)
				{
					(*it)->on_read(evt, data, datalen);
				}
			}
		}
		else
		{
			char *data;
			uint32_t datalen;
			int32_t tupleparam = -1;

			if(etype == PPME_SOCKET_SENDTO_X || etype == PPME_SOCKET_SENDMSG_X)
			{
				tupleparam = 2;
			}

			if(tupleparam != -1 && (evt->m_fdinfo->m_name.length() == 0 || !evt->m_fdinfo->is_tcp_socket()))
			{
				//
				// sendto contains tuple info in the enter event.
				// If the fd still doesn't contain tuple info (because the socket is a datagram one or because some event was lost),
				// add it here.
				//
				if(!retrieve_enter_event(enter_evt, evt))
				{
					return;
				}

				if(update_fd(evt, enter_evt->get_param(tupleparam)))
				{
					const char *parstr;

					scap_fd_type fdtype = evt->m_fdinfo->m_type;

					if(fdtype == SCAP_FD_IPV4_SOCK)
					{
						if(evt->m_fdinfo->is_role_none())
						{
								evt->m_fdinfo->set_net_role_by_guessing(m_inspector,
									evt->m_tinfo,
									evt->m_fdinfo,
									false);
						}

						if(evt->m_fdinfo->is_role_server())
						{
							swap_ipv4_addresses(evt->m_fdinfo);
						}

						sinsp_utils::sockinfo_to_str(&evt->m_fdinfo->m_sockinfo,
							fdtype, &evt->m_paramstr_storage[0],
							(uint32_t)evt->m_paramstr_storage.size(),
							m_inspector->m_hostname_and_port_resolution_enabled);

						evt->m_fdinfo->m_name = &evt->m_paramstr_storage[0];
					}
					else
					{
						evt->m_fdinfo->m_name = enter_evt->get_param_as_str(tupleparam, &parstr, sinsp_evt::PF_SIMPLE);
					}
				}
			}

			//
			// Extract the data buffer
			//
			parinfo = evt->get_param(1);
			datalen = parinfo->m_len;
			data = parinfo->m_val;

			//
			// If there's an fd listener, call it now
			//
			if(m_fd_listener)
			{
				m_fd_listener->on_write(evt, tid, evt->m_tinfo->m_lastevent_fd, evt->m_fdinfo,
					data, (uint32_t)retval, datalen);
			}

			//
			// Call the protocol decoder callbacks associated to this event
			//
			if(evt->m_fdinfo->m_callbaks)
			{
				vector<sinsp_protodecoder*>* cbacks = &(evt->m_fdinfo->m_callbaks->m_write_callbacks);

				for(auto it = cbacks->begin(); it != cbacks->end(); ++it)
				{
					(*it)->on_write(evt, data, datalen);
				}
			}
		}
	}
}

void sinsp_parser::parse_sendfile_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	if(!evt->m_fdinfo)
	{
		return;
	}

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	retval = *(int64_t *)parinfo->m_val;

	//
	// If the operation was successful, validate that the fd exists
	//
	if(retval >= 0)
	{
		sinsp_evt *enter_evt = &m_tmp_evt;
		int64_t fdin;

		if(!retrieve_enter_event(enter_evt, evt))
		{
			return;
		}

		//
		// Extract the in FD
		//
		parinfo = enter_evt->get_param(1);
		ASSERT(parinfo->m_len == sizeof(int64_t));
		fdin = *(int64_t *)parinfo->m_val;

		//
		// If there's an fd listener, call it now
		//
		if(m_fd_listener)
		{
			m_fd_listener->on_sendfile(evt, fdin, (uint32_t)retval);
		}
	}
}

void sinsp_parser::parse_eventfd_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t fd;
	sinsp_fdinfo_t fdi;

	//
	// lookup the thread info
	//
	if(!evt->m_tinfo)
	{
		ASSERT(false);
		return;
	}

	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd = *(int64_t *)parinfo->m_val;

	if(fd < 0)
	{
		//
		// eventfd() failed. Nothing to add to the table.
		//
		return;
	}

	//
	// Populate the new fdi
	//
	fdi.m_type = SCAP_FD_EVENT;
	fdi.m_name = "";

	//
	// Add the fd to the table.
	//
	evt->m_fdinfo = evt->m_tinfo->add_fd(fd, &fdi);
}

void sinsp_parser::parse_chdir_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// In case of success, update the thread working dir
	//
	if(retval >= 0)
	{
		sinsp_evt_param *parinfo;

		// Update the thread working directory
		parinfo = evt->get_param(1);
		evt->m_tinfo->set_cwd(parinfo->m_val, parinfo->m_len);
	}
}

void sinsp_parser::parse_fchdir_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// In case of success, update the thread working dir
	//
	if(retval >= 0)
	{
		//
		// Find the fd name
		//
		if(evt->m_fdinfo == NULL)
		{
			return;
		}

		// Update the thread working directory
		evt->m_tinfo->set_cwd((char *)evt->m_fdinfo->m_name.c_str(),
		                 (uint32_t)evt->m_fdinfo->m_name.size());
	}
}

void sinsp_parser::parse_getcwd_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// Check if the syscall was successful
	//
	if(retval >= 0)
	{
		if(!evt->m_tinfo)
		{
			//
			// No thread in the table. We won't store this event, which mean that
			// we won't be able to parse the correspoding exit event and we'll have
			// to drop the information it carries.
			//
			ASSERT(false);
			return;
		}

		parinfo = evt->get_param(1);

#ifdef _DEBUG
		string chkstr = string(parinfo->m_val);

		if(chkstr != "/")
		{
			if(chkstr + "/"  != evt->m_tinfo->get_cwd())
			{
				//
				// This shouldn't happen, because we should be able to stay in synch by
				// following chdir(). If it does, it's almost sure there was an event drop.
				// In that case, we use this value to update the thread cwd.
				//
#if defined(HAS_CAPTURE)
#ifdef _DEBUG
				int target_res;
				char target_name[1024];
				target_res = readlink((chkstr + "/").c_str(),
					target_name,
					sizeof(target_name) - 1);

				if(target_res > 0)
				{
					if(target_name != evt->m_tinfo->get_cwd())
					{
						printf("%s != %s", target_name, evt->m_tinfo->get_cwd().c_str());
						ASSERT(false);
					}
				}

#endif
#endif
			}
		}
#endif

		evt->m_tinfo->set_cwd(parinfo->m_val, parinfo->m_len);
	}
}

void sinsp_parser::parse_shutdown_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	retval = *(int64_t *)parinfo->m_val;

	//
	// If the operation was successful, do the cleanup
	//
	if(retval >= 0)
	{
		if(evt->m_fdinfo == NULL)
		{
			return;
		}

		if(m_fd_listener)
		{
			m_fd_listener->on_socket_shutdown(evt);
		}
	}
}

void sinsp_parser::parse_dup_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// Check if the syscall was successful
	//
	if(retval >= 0)
	{
		if(evt->m_fdinfo == NULL)
		{
			return;
		}

		//
		// If the old FD is in the table, remove it properly
		//
		sinsp_fdinfo_t* oldfdinfo = evt->m_tinfo->get_fd(retval);

		if(oldfdinfo != NULL)
		{
			erase_fd_params eparams;

			eparams.m_fd = retval;
			eparams.m_fdinfo = oldfdinfo;
			eparams.m_remove_from_table = false;
			eparams.m_inspector = m_inspector;
			eparams.m_tinfo = evt->m_tinfo;
			eparams.m_ts = evt->get_ts();

			erase_fd(&eparams);
		}

		//
		// Add the new fd to the table.
		//
		evt->m_fdinfo = evt->m_tinfo->add_fd(retval, evt->m_fdinfo);
	}
}

void sinsp_parser::parse_signalfd_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// Check if the syscall was successful
	//
	if(retval >= 0)
	{
		sinsp_fdinfo_t fdi;

		//
		// Populate the new fdi
		//
		fdi.m_type = SCAP_FD_SIGNALFD;
		fdi.m_name = "";

		//
		// Add the fd to the table.
		//
		evt->m_fdinfo = evt->m_tinfo->add_fd(retval, &fdi);
	}
}

void sinsp_parser::parse_timerfd_create_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// Check if the syscall was successful
	//
	if(retval >= 0)
	{
		sinsp_fdinfo_t fdi;

		//
		// Populate the new fdi
		//
		fdi.m_type = SCAP_FD_TIMERFD;
		fdi.m_name = "";

		//
		// Add the fd to the table.
		//
		evt->m_fdinfo = evt->m_tinfo->add_fd(retval, &fdi);
	}
}

void sinsp_parser::parse_inotify_init_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// Check if the syscall was successful
	//
	if(retval >= 0)
	{
		sinsp_fdinfo_t fdi;

		//
		// Populate the new fdi
		//
		fdi.m_type = SCAP_FD_INOTIFY;
		fdi.m_name = "";

		//
		// Add the fd to the table.
		//
		evt->m_fdinfo = evt->m_tinfo->add_fd(retval, &fdi);
	}
}

void sinsp_parser::parse_getrlimit_setrlimit_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	sinsp_evt *enter_evt = &m_tmp_evt;
	uint8_t resource;
	int64_t curval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// Check if the syscall was successful
	//
	if(retval >= 0)
	{
		//
		// Load the enter event so we can access its arguments
		//
		if(!retrieve_enter_event(enter_evt, evt))
		{
			return;
		}

		//
		// Extract the resource number
		//
		parinfo = enter_evt->get_param(0);
		resource = *(uint8_t *)parinfo->m_val;
		ASSERT(parinfo->m_len == sizeof(uint8_t));

		if(resource == PPM_RLIMIT_NOFILE)
		{
			//
			// Extract the current value for the resource
			//
			parinfo = evt->get_param(1);
			curval = *(uint64_t *)parinfo->m_val;
			ASSERT(parinfo->m_len == sizeof(uint64_t));

#ifdef _DEBUG
			if(evt->get_type() == PPME_SYSCALL_GETRLIMIT_X)
			{
				if(evt->m_tinfo->get_main_thread()->m_fdlimit != -1)
				{
					ASSERT(curval == evt->m_tinfo->get_main_thread()->m_fdlimit);
				}
			}
#endif

			if(curval != -1)
			{
				evt->m_tinfo->get_main_thread()->m_fdlimit = curval;
			}
			else
			{
				ASSERT(false);
			}
		}
	}
}

void sinsp_parser::parse_prlimit_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	sinsp_evt *enter_evt = &m_tmp_evt;
	uint8_t resource;
	int64_t newcur;
	int64_t tid;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// Check if the syscall was successful
	//
	if(retval >= 0)
	{
		//
		// Load the enter event so we can access its arguments
		//
		if(!retrieve_enter_event(enter_evt, evt))
		{
			return;
		}

		//
		// Extract the resource number
		//
		parinfo = enter_evt->get_param(1);
		resource = *(uint8_t *)parinfo->m_val;
		ASSERT(parinfo->m_len == sizeof(uint8_t));

		if(resource == PPM_RLIMIT_NOFILE)
		{
			//
			// Extract the current value for the resource
			//
			parinfo = evt->get_param(1);
			newcur = *(uint64_t *)parinfo->m_val;
			ASSERT(parinfo->m_len == sizeof(uint64_t));

			if(newcur != -1)
			{
				//
				// Extract the tid and look for its process info
				//
				parinfo = enter_evt->get_param(0);
				tid = *(int64_t *)parinfo->m_val;
				ASSERT(parinfo->m_len == sizeof(int64_t));

				sinsp_threadinfo* ptinfo = m_inspector->get_thread(tid, true, true);
				if(ptinfo == NULL)
				{
					ASSERT(false);
					return;
				}

				//
				// update the process fdlimit
				//
				ptinfo->get_main_thread()->m_fdlimit = newcur;
			}
		}
	}
}

void sinsp_parser::parse_select_poll_epollwait_enter(sinsp_evt *evt)
{
	if(evt->m_tinfo == NULL)
	{
		ASSERT(false);
		return;
	}

	*(uint64_t*)evt->m_tinfo->m_lastevent_data = evt->get_ts();
}

void sinsp_parser::parse_fcntl_enter(sinsp_evt *evt)
{
	if(!evt->m_tinfo)
	{
		return;
	}

	sinsp_evt_param *parinfo = evt->get_param(1);
	ASSERT(parinfo->m_len == sizeof(int8_t));
	uint8_t cmd = *(int8_t *)parinfo->m_val;

	if(cmd == PPM_FCNTL_F_DUPFD || cmd == PPM_FCNTL_F_DUPFD_CLOEXEC)
	{
		store_event(evt);
	}
}

void sinsp_parser::parse_fcntl_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	sinsp_evt *enter_evt = &m_tmp_evt;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// If this is not a F_DUPFD or F_DUPFD_CLOEXEC command, ignore it
	//
	if(!retrieve_enter_event(enter_evt, evt))
	{
		return;
	}

	//
	// Check if the syscall was successful
	//
	if(retval >= 0)
	{
		if(evt->m_fdinfo == NULL)
		{
			return;
		}

		//
		// Add the new fd to the table.
		// NOTE: dup2 and dup3 accept an existing FD and in that case they close it.
		//       For us it's ok to just overwrite it.
		//
		evt->m_fdinfo = evt->m_tinfo->add_fd(retval, evt->m_fdinfo);
	}
}

void sinsp_parser::parse_context_switch(sinsp_evt* evt)
{
	if(evt->m_tinfo)
	{
		sinsp_evt_param *parinfo;

		parinfo = evt->get_param(1);
		evt->m_tinfo->m_pfmajor = *(uint64_t *)parinfo->m_val;
		ASSERT(parinfo->m_len == sizeof(uint64_t));

		parinfo = evt->get_param(2);
		evt->m_tinfo->m_pfminor = *(uint64_t *)parinfo->m_val;
		ASSERT(parinfo->m_len == sizeof(uint64_t));

		parinfo = evt->get_param(3);
		evt->m_tinfo->m_vmsize_kb = *(uint32_t *)parinfo->m_val;
		ASSERT(parinfo->m_len == sizeof(uint32_t));

		parinfo = evt->get_param(4);
		evt->m_tinfo->m_vmrss_kb = *(uint32_t *)parinfo->m_val;
		ASSERT(parinfo->m_len == sizeof(uint32_t));

		parinfo = evt->get_param(5);
		evt->m_tinfo->m_vmswap_kb = *(uint32_t *)parinfo->m_val;
		ASSERT(parinfo->m_len == sizeof(uint32_t));
	}
}

void sinsp_parser::parse_brk_munmap_mmap_exit(sinsp_evt* evt)
{
	ASSERT(evt->m_tinfo);
	if(evt->m_tinfo)
	{
		sinsp_evt_param *parinfo;

		parinfo = evt->get_param(1);
		evt->m_tinfo->m_vmsize_kb = *(uint32_t *)parinfo->m_val;
		ASSERT(parinfo->m_len == sizeof(uint32_t));

		parinfo = evt->get_param(2);
		evt->m_tinfo->m_vmrss_kb = *(uint32_t *)parinfo->m_val;
		ASSERT(parinfo->m_len == sizeof(uint32_t));

		parinfo = evt->get_param(3);
		evt->m_tinfo->m_vmswap_kb = *(uint32_t *)parinfo->m_val;
		ASSERT(parinfo->m_len == sizeof(uint32_t));
	}
}

void sinsp_parser::parse_setresuid_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	sinsp_evt *enter_evt = &m_tmp_evt;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	if(retval >= 0 && retrieve_enter_event(enter_evt, evt))
	{
		parinfo = enter_evt->get_param(1);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		uint32_t new_euid = *(uint32_t *)parinfo->m_val;

		if(new_euid < std::numeric_limits<uint32_t>::max())
		{
			evt->get_thread_info()->m_uid = new_euid;
		}
	}
}

void sinsp_parser::parse_setresgid_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	sinsp_evt *enter_evt = &m_tmp_evt;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	if(retval >= 0 && retrieve_enter_event(enter_evt, evt))
	{
		parinfo = enter_evt->get_param(1);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		uint32_t new_egid = *(uint32_t *)parinfo->m_val;

		if(new_egid < std::numeric_limits<uint32_t>::max())
		{
			evt->get_thread_info()->m_gid = new_egid;
		}
	}
}

void sinsp_parser::parse_setuid_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	sinsp_evt *enter_evt = &m_tmp_evt;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	if(retval >= 0 && retrieve_enter_event(enter_evt, evt))
	{
		parinfo = enter_evt->get_param(0);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		uint32_t new_euid = *(uint32_t *)parinfo->m_val;
		evt->get_thread_info()->m_uid = new_euid;
	}
}

void sinsp_parser::parse_setgid_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	sinsp_evt *enter_evt = &m_tmp_evt;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	if(retval >= 0 && retrieve_enter_event(enter_evt, evt))
	{
		parinfo = enter_evt->get_param(0);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		uint32_t new_egid = *(uint32_t *)parinfo->m_val;
		evt->get_thread_info()->m_gid = new_egid;
	}
}

void sinsp_parser::parse_container_evt(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	sinsp_container_info container_info;

	parinfo = evt->get_param(0);
	container_info.m_id = parinfo->m_val;

	parinfo = evt->get_param(1);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	container_info.m_type = (sinsp_container_type) *(uint32_t *)parinfo->m_val;

	parinfo = evt->get_param(2);
	container_info.m_name = parinfo->m_val;

	parinfo = evt->get_param(3);
	container_info.m_image = parinfo->m_val;

	m_inspector->m_container_manager.add_container(container_info);
}

void sinsp_parser::parse_cpu_hotplug_enter(sinsp_evt *evt)
{
#ifdef HAS_ANALYZER
	if(m_inspector->is_live())
	{
		throw sinsp_exception("CPUs configuration change detected. Aborting.");
	}
#endif
}
