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

#ifndef _WIN32
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#endif
#include <algorithm>
#include "sinsp.h"
#include "sinsp_int.h"
#include "protodecoder.h"
#include "tracers.h"

extern sinsp_evttables g_infotables;

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
	m_tracer_parser = NULL;
	init();
}

sinsp_threadinfo::sinsp_threadinfo(sinsp *inspector) :
	m_fdtable(inspector)
{
	m_inspector = inspector;
	m_tracer_parser = NULL;
	init();
}

void sinsp_threadinfo::init()
{
	m_pid = (uint64_t) - 1LL;
	m_sid = (uint64_t) - 1LL;
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
	m_vmsize_kb = 0;
	m_vmrss_kb = 0;
	m_vmswap_kb = 0;
	m_pfmajor = 0;
	m_pfminor = 0;
	m_vtid = -1;
	m_vpid = -1;
	m_main_thread = NULL;
	m_lastevent_fd = 0;
#ifdef HAS_FILTERING
	m_last_latency_entertime = 0;
	m_latency = 0;
#endif
	m_ainfo = NULL;
	m_program_hash = 0;
	m_program_hash_falco = 0;
	m_lastevent_data = NULL;
	m_parent_loop_detected = false;
	m_tty = 0;
	m_blprogram = NULL;
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
	if(m_lastevent_data)
	{
		free(m_lastevent_data);
	}

	if(m_tracer_parser)
	{
		delete m_tracer_parser;
	}
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

				it->second.m_name = ipv4tuple_to_string(&it->second.m_sockinfo.m_ipv4info, m_inspector->m_hostname_and_port_resolution_enabled);

				it->second.set_role_server();
			}
			else
			{
				it->second.set_role_client();
			}
		}
	}
}

#define STR_AS_NUM_JAVA 0x6176616a
#define STR_AS_NUM_RUBY 0x79627572
#define STR_AS_NUM_PERL 0x6c726570
#define STR_AS_NUM_NODE 0x65646f6e

void sinsp_threadinfo::compute_program_hash()
{
	string phs = m_exe;

	phs += m_container_id;

	//
	// By default, the falco hash is just exe+container
	//
	m_program_hash_falco = std::hash<std::string>()(phs);

	//
	// The program hash includes the arguments as well
	//
	for(auto arg = m_args.begin(); arg != m_args.end(); ++arg)
	{
		phs += *arg;
	}

	m_program_hash = std::hash<std::string>()(phs);

	//
	// For some specific processes (essentially the scripting languages)
	// we include the arguments in the falco hash as well
	//
	if(m_comm.size() == 4)
	{
		uint32_t ncomm = *(uint32_t*)m_comm.c_str();

		if(ncomm == STR_AS_NUM_JAVA || ncomm == STR_AS_NUM_RUBY ||
			ncomm == STR_AS_NUM_PERL || ncomm == STR_AS_NUM_NODE)
		{
			m_program_hash_falco = m_program_hash;
		}
	}
	else if(m_comm.size() >= 6)
	{
		if(m_comm.substr(0, 6) == "python")
		{
			m_program_hash_falco = m_program_hash;
		}
	}
}

void sinsp_threadinfo::add_fd_from_scap(scap_fdinfo *fdi, OUT sinsp_fdinfo_t *res)
{
	sinsp_fdinfo_t* newfdi = res;
	newfdi->reset();
	bool do_add = true;

	newfdi->m_type = fdi->type;
	newfdi->m_openflags = 0;
	newfdi->m_type = fdi->type;
	newfdi->m_flags = sinsp_fdinfo_t::FLAGS_FROM_PROC;
	newfdi->m_ino = fdi->ino;

	switch(newfdi->m_type)
	{
	case SCAP_FD_IPV4_SOCK:
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_sip = fdi->info.ipv4info.sip;
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_dip = fdi->info.ipv4info.dip;
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_sport = fdi->info.ipv4info.sport;
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_dport = fdi->info.ipv4info.dport;
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_l4proto = fdi->info.ipv4info.l4proto;
		if(m_inspector->m_network_interfaces)
		{
			m_inspector->m_network_interfaces->update_fd(newfdi);
		}
		newfdi->m_name = ipv4tuple_to_string(&newfdi->m_sockinfo.m_ipv4info, m_inspector->m_hostname_and_port_resolution_enabled);
		break;
	case SCAP_FD_IPV4_SERVSOCK:
		newfdi->m_sockinfo.m_ipv4serverinfo.m_ip = fdi->info.ipv4serverinfo.ip;
		newfdi->m_sockinfo.m_ipv4serverinfo.m_port = fdi->info.ipv4serverinfo.port;
		newfdi->m_sockinfo.m_ipv4serverinfo.m_l4proto = fdi->info.ipv4serverinfo.l4proto;
		newfdi->m_name = ipv4serveraddr_to_string(&newfdi->m_sockinfo.m_ipv4serverinfo, m_inspector->m_hostname_and_port_resolution_enabled);

		//
		// We keep note of all the host bound server ports.
		// We'll need them later when patching connections direction.
		//
		m_inspector->m_thread_manager->m_server_ports.insert(newfdi->m_sockinfo.m_ipv4serverinfo.m_port);

		break;
	case SCAP_FD_IPV6_SOCK:
		if(sinsp_utils::is_ipv4_mapped_ipv6((uint8_t*)&fdi->info.ipv6info.sip) &&
			sinsp_utils::is_ipv4_mapped_ipv6((uint8_t*)&fdi->info.ipv6info.dip))
		{
			//
			// This is an IPv4-mapped IPv6 addresses (http://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses).
			// Convert it into the IPv4 representation.
			//
			newfdi->m_type = SCAP_FD_IPV4_SOCK;
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_sip = fdi->info.ipv6info.sip[3];
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_dip = fdi->info.ipv6info.dip[3];
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_sport = fdi->info.ipv6info.sport;
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_dport = fdi->info.ipv6info.dport;
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_l4proto = fdi->info.ipv6info.l4proto;
			if(m_inspector->m_network_interfaces)
			{
				m_inspector->m_network_interfaces->update_fd(newfdi);
			}
			newfdi->m_name = ipv4tuple_to_string(&newfdi->m_sockinfo.m_ipv4info, m_inspector->m_hostname_and_port_resolution_enabled);
		}
		else
		{
			copy_ipv6_address(newfdi->m_sockinfo.m_ipv6info.m_fields.m_sip, fdi->info.ipv6info.sip);
			copy_ipv6_address(newfdi->m_sockinfo.m_ipv6info.m_fields.m_dip, fdi->info.ipv6info.dip);
			newfdi->m_sockinfo.m_ipv6info.m_fields.m_sport = fdi->info.ipv6info.sport;
			newfdi->m_sockinfo.m_ipv6info.m_fields.m_dport = fdi->info.ipv6info.dport;
			newfdi->m_sockinfo.m_ipv6info.m_fields.m_l4proto = fdi->info.ipv6info.l4proto;
			newfdi->m_name = ipv6tuple_to_string(&newfdi->m_sockinfo.m_ipv6info, m_inspector->m_hostname_and_port_resolution_enabled);
		}
		break;
	case SCAP_FD_IPV6_SERVSOCK:
		copy_ipv6_address(newfdi->m_sockinfo.m_ipv6serverinfo.m_ip, fdi->info.ipv6serverinfo.ip);
		newfdi->m_sockinfo.m_ipv6serverinfo.m_port = fdi->info.ipv6serverinfo.port;
		newfdi->m_sockinfo.m_ipv6serverinfo.m_l4proto = fdi->info.ipv6serverinfo.l4proto;
		newfdi->m_name = ipv6serveraddr_to_string(&newfdi->m_sockinfo.m_ipv6serverinfo, m_inspector->m_hostname_and_port_resolution_enabled);

		//
		// We keep note of all the host bound server ports.
		// We'll need them later when patching connections direction.
		//
		m_inspector->m_thread_manager->m_server_ports.insert(newfdi->m_sockinfo.m_ipv6serverinfo.m_port);

		break;
	case SCAP_FD_UNIX_SOCK:
		newfdi->m_sockinfo.m_unixinfo.m_fields.m_source = fdi->info.unix_socket_info.source;
		newfdi->m_sockinfo.m_unixinfo.m_fields.m_dest = fdi->info.unix_socket_info.destination;
		newfdi->m_name = fdi->info.unix_socket_info.fname;
		if(newfdi->m_name.empty())
		{
			newfdi->set_role_client();
		}
		else
		{
			newfdi->set_role_server();
		}
		break;
	case SCAP_FD_FILE_V2:
		newfdi->m_openflags = fdi->info.regularinfo.open_flags;
		newfdi->m_name = fdi->info.regularinfo.fname;
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
	case SCAP_FD_NETLINK:
		newfdi->m_name = fdi->info.fname;

		if(newfdi->m_name == USER_EVT_DEVICE_NAME)
		{
			newfdi->m_flags |= sinsp_fdinfo_t::FLAGS_IS_TRACER_FILE;
		}
		else
		{
			newfdi->m_flags |= sinsp_fdinfo_t::FLAGS_IS_NOT_TRACER_FD;
		}

		break;
	default:
		ASSERT(false);
		do_add = false;
		break;
	}

	//
	// Call the protocol decoder callbacks associated to notify them about this FD
	//
	ASSERT(m_inspector != NULL);
	vector<sinsp_protodecoder*>::iterator it;

	for(it = m_inspector->m_parser->m_open_callbacks.begin();
		it != m_inspector->m_parser->m_open_callbacks.end(); ++it)
	{
		(*it)->on_fd_from_proc(newfdi);
	}

	//
	// Add the FD to the table
	//
	if(do_add)
	{
		m_fdtable.add(fdi->fd, newfdi);
	}
}

void sinsp_threadinfo::init(scap_threadinfo* pi)
{
	scap_fdinfo *fdi;
	scap_fdinfo *tfdi;

	init();

	m_tid = pi->tid;
	m_pid = pi->pid;
	m_ptid = pi->ptid;
	m_sid = pi->sid;

	m_comm = pi->comm;
	m_exe = pi->exe;
	m_exepath = pi->exepath;
	set_args(pi->args, pi->args_len);
	if(is_main_thread())
	{
		set_env(pi->env, pi->env_len);
		set_cwd(pi->cwd, (uint32_t)strlen(pi->cwd));
	}
	m_flags |= pi->flags;
	m_flags |= PPM_CL_ACTIVE; // Assume that all the threads coming from /proc are real, active threads
	m_fdtable.clear();
	m_fdlimit = pi->fdlimit;
	m_uid = pi->uid;
	m_gid = pi->gid;
	m_vmsize_kb = pi->vmsize_kb;
	m_vmrss_kb = pi->vmrss_kb;
	m_vmswap_kb = pi->vmswap_kb;
	m_pfmajor = pi->pfmajor;
	m_pfminor = pi->pfminor;
	m_nchilds = 0;
	m_vtid = pi->vtid;
	m_vpid = pi->vpid;
	m_clone_ts = pi->clone_ts;
	m_tty = pi->tty;

	set_cgroups(pi->cgroups, pi->cgroups_len);
	m_root = pi->root;
	ASSERT(m_inspector);
	m_inspector->m_container_manager.resolve_container(this, !m_inspector->is_capture());
	//
	// Prepare for filtering
	//
	sinsp_fdinfo_t tfdinfo;
	sinsp_evt tevt;
	scap_evt tscapevt;

	//
	// Initialize the fake events for filtering
	//
	tscapevt.ts = 0;
	tscapevt.type = PPME_SYSCALL_READ_X;
	tscapevt.len = 0;

	tevt.m_inspector = m_inspector;
	tevt.m_info = &(g_infotables.m_event_info[PPME_SYSCALL_READ_X]);
	tevt.m_pevt = NULL;
	tevt.m_cpuid = 0;
	tevt.m_evtnum = 0;
	tevt.m_pevt = &tscapevt;
	bool match = false;

	HASH_ITER(hh, pi->fdlist, fdi, tfdi)
	{
		add_fd_from_scap(fdi, &tfdinfo);

		if(m_inspector->m_filter != NULL && m_inspector->m_filter_proc_table_when_saving)
		{
			tevt.m_tinfo = this;
			tevt.m_fdinfo = &tfdinfo;
			tscapevt.tid = m_tid;
			int64_t tlefd = tevt.m_tinfo->m_lastevent_fd;
			tevt.m_tinfo->m_lastevent_fd = fdi->fd;

			if(m_inspector->m_filter->run(&tevt))
			{
				match = true;
			}
			else
			{
				//
				// This tells scap not to include this FD in the write file
				//
				fdi->type = SCAP_FD_UNINITIALIZED;
			}

			tevt.m_tinfo->m_lastevent_fd = tlefd;
		}
	}

	m_lastevent_data = NULL;

	if(m_inspector->m_filter != NULL && m_inspector->m_filter_proc_table_when_saving)
	{
		if(!match)
		{
			pi->filtered_out = 1;
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

string sinsp_threadinfo::get_exepath()
{
	return m_exepath;
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

void sinsp_threadinfo::set_env(const char* env, size_t len)
{
	m_env.clear();

	size_t offset = 0;
	while(offset < len)
	{
		const char* left = env + offset;
		// environment string may actually be shorter than indicated by len
		// if the rest is empty, we bail out early
		if(!strlen(left))
		{
			size_t sz = len - offset;
			void* zero = calloc(sz, sizeof(char));
			if(!memcmp(left, zero, sz))
			{
				free(zero);
				return;
			}
			free(zero);
		}
		m_env.push_back(left);

		offset += m_env.back().length() + 1;
	}
}

const vector<string>& sinsp_threadinfo::get_env()
{
	if(is_main_thread())
	{
		return m_env;
	}
	else
	{
		auto mtinfo = get_main_thread();
		if(mtinfo != nullptr)
		{
			return mtinfo->get_env();
		}
		else
		{
			// it should never happen but provide a safe fallback just in case
			ASSERT(false);
			return m_env;
		}
	}
}

string sinsp_threadinfo::get_env(const string& name)
{
	for(const auto& env_var : get_env())
	{
		if((env_var.length() > name.length()) && (env_var.substr(0, name.length()) == name))
		{
			std::string::size_type pos = env_var.find('=');
			if(pos != std::string::npos && env_var.size() > pos + 1)
			{
				string val = env_var.substr(pos + 1);
				std::string::size_type first = val.find_first_not_of(' ');
				std::string::size_type last = val.find_last_not_of(' ');
				return val.substr(first, last - first + 1);
			}
		}
	}

	return "";
}

void sinsp_threadinfo::set_cgroups(const char* cgroups, size_t len)
{
	m_cgroups.clear();

	size_t offset = 0;
	while(offset < len)
	{
		const char* str = cgroups + offset;
		const char* sep = strchr(str, '=');
		if(sep == NULL)
		{
			ASSERT(false);
			return;
		}

		string subsys(str, sep - str);
		string cgroup(sep + 1);

		size_t subsys_length = subsys.length();
		size_t pos = subsys.find("_cgroup");
		if(pos != string::npos)
		{
			subsys.erase(pos, sizeof("_cgroup") - 1);
		}

		if(subsys == "perf")
		{
			subsys = "perf_event";
		}
		else if(subsys == "mem")
		{
			subsys = "memory";
		}
		else if(subsys == "io")
		{
			// blkio has been renamed just `io`
			// in kernel space:
			// https://github.com/torvalds/linux/commit/c165b3e3c7bb68c2ed55a5ac2623f030d01d9567
			subsys = "blkio";
		}

		m_cgroups.push_back(std::make_pair(subsys, cgroup));
		offset += subsys_length + 1 + cgroup.length() + 1;
	}
}

sinsp_threadinfo* sinsp_threadinfo::get_parent_thread()
{
	return m_inspector->get_thread(m_ptid, false, true);
}

sinsp_fdinfo_t* sinsp_threadinfo::add_fd(int64_t fd, sinsp_fdinfo_t *fdinfo)
{
	sinsp_fdinfo_t* res = get_fd_table()->add(fd, fdinfo);

	//
	// Update the last event fd. It's needed by the filtering engine
	//
	m_lastevent_fd = fd;

	return res;
}

void sinsp_threadinfo::remove_fd(int64_t fd)
{
	get_fd_table()->erase(fd);
}

bool sinsp_threadinfo::is_bound_to_port(uint16_t number)
{
	unordered_map<int64_t, sinsp_fdinfo_t>::iterator it;

	sinsp_fdtable* fdt = get_fd_table();

	for(it = fdt->m_table.begin(); it != fdt->m_table.end(); ++it)
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

bool sinsp_threadinfo::is_lastevent_data_valid()
{
	return (m_lastevent_cpuid != (uint16_t) - 1);
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
	// Ideally we should use get_cwd_root()
	// but scap does not read CLONE_FS from /proc
	// Also glibc and muslc use always
	// CLONE_THREAD|CLONE_FS so let's use
	// get_main_thread() for now
	sinsp_threadinfo* tinfo = get_main_thread();

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
	sinsp_threadinfo* tinfo = get_main_thread();

	if(tinfo)
	{
		sinsp_utils::concatenate_paths(tpath,
			SCAP_MAX_PATH_SIZE,
			(char*)tinfo->m_cwd.c_str(),
			(uint32_t)tinfo->m_cwd.size(),
			cwd,
			cwdlen);

		tinfo->m_cwd = tpath;

		uint32_t size = tinfo->m_cwd.size();

		if(size == 0 || (tinfo->m_cwd[size - 1] != '/'))
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
			memset(newbuf, 0, sizes->at(j));
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

uint64_t sinsp_threadinfo::get_fd_usage_pct()
{
	int64_t fdlimit = get_fd_limit();
	if(fdlimit > 0)
	{
		uint64_t fd_opencount = get_fd_opencount();
		ASSERT(fd_opencount <= (uint64_t) fdlimit);
		if(fd_opencount <= (uint64_t) fdlimit)
		{
			return (fd_opencount * 100) / fdlimit;
		}
		else
		{
			return 100;
		}
	}
	else
	{
		return 0;
	}
}

double sinsp_threadinfo::get_fd_usage_pct_d()
{
	int64_t fdlimit = get_fd_limit();
	if(fdlimit > 0)
	{
		uint64_t fd_opencount = get_fd_opencount();
		ASSERT(fd_opencount <= (uint64_t) fdlimit);
		if(fd_opencount <= (uint64_t) fdlimit)
		{
			return ((double)fd_opencount * 100) / fdlimit;
		}
		else
		{
			return 100;
		}
	}
	else
	{
		return 0;
	}
}

uint64_t sinsp_threadinfo::get_fd_opencount()
{
	return get_main_thread()->m_fdtable.size();
}

uint64_t sinsp_threadinfo::get_fd_limit()
{
	return get_main_thread()->m_fdlimit;
}

void sinsp_threadinfo::traverse_parent_state(visitor_func_t &visitor)
{
	// Use two pointers starting at this, traversing the parent
	// state, at different rates. If they ever equal each other
	// before slow is NULL there's a loop.

	sinsp_threadinfo *slow=this->get_parent_thread(), *fast=slow;

	// Move fast to its parent
	fast = (fast ? fast->get_parent_thread() : fast);

	while(slow)
	{
		if(!visitor(slow))
		{
			break;
		}

		// Advance slow one step and advance fast two steps
		slow = slow->get_parent_thread();

		// advance fast 2 steps, checking to see if we meet
		// slow after each step.
		for (uint32_t i = 0; i < 2; i++) {
			fast = (fast ? fast->get_parent_thread() : fast);

			// If not at the end but fast == slow, there's a loop
			// in the thread state.
			if(slow && (slow == fast))
			{
				// Note we only log a loop once for a given main thread, to avoid flooding logs.
				if(!m_parent_loop_detected)
				{
					g_logger.log(string("Loop in parent thread state detected for pid ") +
						     std::to_string(m_pid), sinsp_logger::SEV_WARNING);
					m_parent_loop_detected = true;
				}
				return;
			}
		}
	}
}

sinsp_threadinfo* sinsp_threadinfo::lookup_thread()
{
	return m_inspector->get_thread(m_pid, true, true);
}

//
// Note: this is duplicated here because visual studio has trouble inlining
//       the method.
//
#ifdef _WIN32
sinsp_threadinfo* sinsp_threadinfo::get_main_thread()
{
	if (m_main_thread == NULL)
	{
		//
		// Is this a child thread?
		//
		if (m_pid == m_tid)
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
			sinsp_threadinfo* ptinfo = lookup_thread();
			if (NULL == ptinfo)
			{
				return NULL;
			}

			m_main_thread = ptinfo;
		}
	}

	return m_main_thread;
}
#endif

inline void scpy(char* dst, const char* src, uint32_t maxlen)
{
	if(maxlen == 0)
	{
		return;
	}

	while(true)
	{
		if(maxlen == 1)
		{
			*dst = 0;
			return;
		}

		if(*src == 0)
		{
			*dst = 0;
			return;
		}

		*(dst++) = *(src++);
		maxlen--;
	}
}

void sinsp_threadinfo::args_to_scap(scap_threadinfo* sctinfo)
{
	uint32_t alen = SCAP_MAX_ARGS_SIZE;
	uint32_t tlen = 0;
	char* dst = sctinfo->args;

	for(auto it = m_args.begin(); it != m_args.end(); ++it)
	{
		uint32_t len = it->size() + 1;

		scpy(dst + tlen, it->c_str(), alen);

		if(len >= alen) 
		{
			//
			// We saturated the args buffer. Null terminate it and return
			//
			sctinfo->args[SCAP_MAX_ARGS_SIZE - 1] = 0;
			sctinfo->args_len = SCAP_MAX_ARGS_SIZE;
			return;
		}
		else
		{
			tlen += len;
			alen -= len;
		}
	}

	sctinfo->args_len = tlen;
}

void sinsp_threadinfo::env_to_scap(scap_threadinfo* sctinfo)
{
	uint32_t alen = SCAP_MAX_ENV_SIZE;
	uint32_t tlen = 0;
	char* dst = sctinfo->env;

	for(auto it = m_env.begin(); it != m_env.end(); ++it)
	{
		uint32_t len = it->size() + 1;

		scpy(dst + tlen, it->c_str(), alen);

		if(len >= alen) 
		{
			//
			// We saturated the args buffer. Null terminate it and return
			//
			sctinfo->env[SCAP_MAX_ENV_SIZE - 1] = 0;
			sctinfo->env_len = SCAP_MAX_ENV_SIZE;
			return;
		}
		else
		{
			tlen += len;
			alen -= len;
		}
	}

	sctinfo->env_len = tlen;
}

void sinsp_threadinfo::cgroups_to_scap(scap_threadinfo* sctinfo)
{
	uint32_t alen = SCAP_MAX_CGROUPS_SIZE;
	uint32_t tlen = 0;
	char* dst = sctinfo->cgroups;

	for(auto it = m_cgroups.begin(); it != m_cgroups.end(); ++it)
	{
		string a = it->first + "=" + it->second;
		uint32_t len = a.size() + 1;

		scpy(dst + tlen, a.c_str(), alen);

		if(len >= alen) 
		{
			//
			// We saturated the args buffer. Null terminate it and return
			//
			sctinfo->cgroups[SCAP_MAX_CGROUPS_SIZE - 1] = 0;
			sctinfo->cgroups_len = SCAP_MAX_CGROUPS_SIZE;
			return;
		}
		else
		{
			tlen += len;
			alen -= len;
		}
	}

	sctinfo->cgroups_len = tlen;
}

void sinsp_threadinfo::fd_to_scap(scap_fdinfo *dst, sinsp_fdinfo_t* src)
{
	dst->type = src->m_type;
	dst->ino = src->m_ino;

	switch(dst->type)
	{
	case SCAP_FD_IPV4_SOCK:
		dst->info.ipv4info.sip = src->m_sockinfo.m_ipv4info.m_fields.m_sip;
		dst->info.ipv4info.dip = src->m_sockinfo.m_ipv4info.m_fields.m_dip;
		dst->info.ipv4info.sport = src->m_sockinfo.m_ipv4info.m_fields.m_sport;
		dst->info.ipv4info.dport = src->m_sockinfo.m_ipv4info.m_fields.m_dport;
		dst->info.ipv4info.l4proto = src->m_sockinfo.m_ipv4info.m_fields.m_l4proto;
		break;
	case SCAP_FD_IPV4_SERVSOCK:
		dst->info.ipv4serverinfo.ip = src->m_sockinfo.m_ipv4serverinfo.m_ip;
		dst->info.ipv4serverinfo.port = src->m_sockinfo.m_ipv4serverinfo.m_port;
		dst->info.ipv4serverinfo.l4proto = src->m_sockinfo.m_ipv4serverinfo.m_l4proto;
		break;
	case SCAP_FD_IPV6_SOCK:
		copy_ipv6_address(dst->info.ipv6info.sip, src->m_sockinfo.m_ipv6info.m_fields.m_sip);
		copy_ipv6_address(dst->info.ipv6info.dip, src->m_sockinfo.m_ipv6info.m_fields.m_dip);
		dst->info.ipv6info.sport = src->m_sockinfo.m_ipv6info.m_fields.m_sport;
		dst->info.ipv6info.dport = src->m_sockinfo.m_ipv6info.m_fields.m_dport;
		dst->info.ipv6info.l4proto = src->m_sockinfo.m_ipv6info.m_fields.m_l4proto;
		break;
	case SCAP_FD_IPV6_SERVSOCK:
		copy_ipv6_address(dst->info.ipv6serverinfo.ip, src->m_sockinfo.m_ipv6serverinfo.m_ip);
		dst->info.ipv6serverinfo.port = src->m_sockinfo.m_ipv6serverinfo.m_port;
		dst->info.ipv6serverinfo.l4proto = src->m_sockinfo.m_ipv6serverinfo.m_l4proto;
		break;
	case SCAP_FD_UNIX_SOCK:
		dst->info.unix_socket_info.source = src->m_sockinfo.m_unixinfo.m_fields.m_source;
		dst->info.unix_socket_info.destination = src->m_sockinfo.m_unixinfo.m_fields.m_dest;
		strncpy(dst->info.unix_socket_info.fname, src->m_name.c_str(), SCAP_MAX_PATH_SIZE);
		break;
	case SCAP_FD_FILE_V2:
		dst->info.regularinfo.open_flags = src->m_openflags;
		strncpy(dst->info.regularinfo.fname, src->m_name.c_str(), SCAP_MAX_PATH_SIZE);
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
	case SCAP_FD_NETLINK:
		strncpy(dst->info.fname, src->m_name.c_str(), SCAP_MAX_PATH_SIZE);
		break;
	default:
		ASSERT(false);
		break;
	}
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

void sinsp_thread_manager::increment_mainthread_childcount(sinsp_threadinfo* threadinfo)
{
	if(threadinfo->m_flags & PPM_CL_CLONE_THREAD)
	{
		//
		// Increment the refcount of the main thread so it won't
		// be deleted (if it calls pthread_exit()) until we are done
		//
		ASSERT(threadinfo->m_pid != threadinfo->m_tid);

		sinsp_threadinfo* main_thread = m_inspector->get_thread(threadinfo->m_pid, true, true);
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

void sinsp_thread_manager::add_thread(sinsp_threadinfo& threadinfo, bool from_scap_proctable)
{
#ifdef GATHER_INTERNAL_STATS
	m_added_threads->increment();
#endif

	m_last_tinfo = NULL;

	if (m_threadtable.size() >= m_inspector->m_max_thread_table_size
#if defined(HAS_CAPTURE)
		&& threadinfo.m_pid != m_inspector->m_sysdig_pid
#endif
		)
	{
		m_n_drops++;
		return;
	}

	if(!from_scap_proctable)
	{
		increment_mainthread_childcount(&threadinfo);
	}

	threadinfo.compute_program_hash();

	sinsp_threadinfo& newentry = (m_threadtable[threadinfo.m_tid] = threadinfo);

	newentry.allocate_private_state();

	if(m_listener)
	{
		m_listener->on_thread_created(&newentry);
	}
}

void sinsp_thread_manager::remove_thread(int64_t tid, bool force)
{
	remove_thread(m_threadtable.find(tid), force);
}

void sinsp_thread_manager::remove_thread(threadinfo_map_iterator_t it, bool force)
{
	uint64_t nchilds;

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
	else if((nchilds = it->second.m_nchilds) == 0 || force)
	{
		//
		// Decrement the refcount of the main thread/program because
		// this reference is gone
		//
		if(it->second.m_flags & PPM_CL_CLONE_THREAD)
		{
			ASSERT(it->second.m_pid != it->second.m_tid);
			sinsp_threadinfo* main_thread = m_inspector->get_thread(it->second.m_pid, false, true);
			if(main_thread)
			{
				if(main_thread->m_nchilds > 0)
				{
					--main_thread->m_nchilds;
				}
				else
				{
					ASSERT(false);
				}
			}
			else
			{
				ASSERT(false);
			}
		}

		//
		// If this is the main thread of a process, erase all the FDs that the process owns
		//
		if(it->second.m_pid == it->second.m_tid)
		{
			unordered_map<int64_t, sinsp_fdinfo_t>* fdtable = &(it->second.get_fd_table()->m_table);
			unordered_map<int64_t, sinsp_fdinfo_t>::iterator fdit;

			erase_fd_params eparams;
			eparams.m_remove_from_table = false;
			eparams.m_inspector = m_inspector;
			eparams.m_tinfo = &(it->second);
			eparams.m_ts = m_inspector->m_lastevent_ts;

			for(fdit = fdtable->begin(); fdit != fdtable->end(); ++fdit)
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

		//
		// If the thread has a nonzero refcount, it means that we are forcing the removal
		// of a main process or program that some childs refer to.
		// We need to recalculate the child relationships, or the table will become
		// corrupted.
		//
		if(nchilds != 0)
		{
			recreate_child_dependencies();
		}
	}
}

void sinsp_thread_manager::fix_sockets_coming_from_proc()
{
	threadinfo_map_iterator_t it;

	for(it = m_threadtable.begin(); it != m_threadtable.end(); ++it)
	{
		it->second.fix_sockets_coming_from_proc();
	}
}

void sinsp_thread_manager::clear_thread_pointers(threadinfo_map_iterator_t it)
{
	it->second.m_main_thread = NULL;

	sinsp_fdtable* fdt = it->second.get_fd_table();
	if(fdt != NULL)
	{
		fdt->reset_cache();
	}
}

/*
void sinsp_thread_manager::clear_thread_pointers(threadinfo_map_iterator_t it)
{
	it->second.m_main_program_thread = NULL;
	it->second.m_main_thread = NULL;
	it->second.m_progid = -1LL;
	it->second.m_fdtable.reset_cache();
}
*/

void sinsp_thread_manager::reset_child_dependencies()
{
	threadinfo_map_iterator_t it;

	m_last_tinfo = NULL;
	m_last_tid = 0;

	for(it = m_threadtable.begin(); it != m_threadtable.end(); ++it)
	{
		it->second.m_nchilds = 0;
		clear_thread_pointers(it);
	}
}

void sinsp_thread_manager::create_child_dependencies()
{
	threadinfo_map_iterator_t it;

	for(it = m_threadtable.begin(); it != m_threadtable.end(); ++it)
	{
		increment_mainthread_childcount(&it->second);
	}
}

void sinsp_thread_manager::recreate_child_dependencies()
{
	reset_child_dependencies();
	create_child_dependencies();
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

void sinsp_thread_manager::free_dump_fdinfos(vector<scap_fdinfo*>* fdinfos_to_free)
{
	for(uint32_t j = 0; j < fdinfos_to_free->size(); j++)
	{
		free(fdinfos_to_free->at(j));
	}

	fdinfos_to_free->clear();
}

void sinsp_thread_manager::thread_to_scap(sinsp_threadinfo& tinfo, 	scap_threadinfo* sctinfo)
{
	//
	// Fill in the thread data
	//
	sctinfo->tid = tinfo.m_tid;
	sctinfo->pid = tinfo.m_pid;
	sctinfo->ptid = tinfo.m_ptid;
	sctinfo->sid = tinfo.m_sid;

	strncpy(sctinfo->comm, tinfo.m_comm.c_str(), SCAP_MAX_PATH_SIZE);
	strncpy(sctinfo->exe, tinfo.m_exe.c_str(), SCAP_MAX_PATH_SIZE);
	strncpy(sctinfo->exepath, tinfo.m_exepath.c_str(), SCAP_MAX_PATH_SIZE);
	tinfo.args_to_scap(sctinfo);
	tinfo.env_to_scap(sctinfo);
	string tcwd = (tinfo.m_cwd == "")? "/": tinfo.m_cwd;
	strncpy(sctinfo->cwd, tcwd.c_str(), SCAP_MAX_PATH_SIZE);
	sctinfo->flags = tinfo.m_flags ;
	sctinfo->fdlimit = tinfo.m_fdlimit;
	sctinfo->uid = tinfo.m_uid;
	sctinfo->gid = tinfo.m_gid;
	sctinfo->vmsize_kb = tinfo.m_vmsize_kb;
	sctinfo->vmrss_kb = tinfo.m_vmrss_kb;
	sctinfo->vmswap_kb = tinfo.m_vmswap_kb;
	sctinfo->pfmajor = tinfo.m_pfmajor;
	sctinfo->pfminor = tinfo.m_pfminor;
	sctinfo->vtid = tinfo.m_vtid;
	sctinfo->vpid = tinfo.m_vpid;
	sctinfo->fdlist = NULL;
	tinfo.cgroups_to_scap(sctinfo);
	strncpy(sctinfo->root, tinfo.m_root.c_str(), SCAP_MAX_PATH_SIZE);
	sctinfo->filtered_out = false;
}

void sinsp_thread_manager::dump_threads_to_file(scap_dumper_t* dumper)
{
	//
	// First pass of the table to calculate the length
	//
	uint32_t totlen = 0;

	for(auto it = m_threadtable.begin(); it != m_threadtable.end(); ++it)
	{
		scap_threadinfo *sctinfo;

		if((sctinfo = scap_proc_alloc(m_inspector->m_h)) == NULL)
		{
			throw sinsp_exception(scap_getlasterr(m_inspector->m_h));
		}

		sinsp_threadinfo& tinfo = it->second;

		tinfo.args_to_scap(sctinfo);
		tinfo.env_to_scap(sctinfo);
		tinfo.cgroups_to_scap(sctinfo);

		string tcwd = (tinfo.m_cwd == "")? "/": tinfo.m_cwd;

		uint32_t il = (uint32_t)
			(sizeof(uint64_t) +	// tid
			sizeof(uint64_t) +	// pid
			sizeof(uint64_t) +	// ptid
			sizeof(uint64_t) +	// sid
			2 + MIN(tinfo.m_comm.size(), SCAP_MAX_PATH_SIZE) +
			2 + MIN(tinfo.m_exe.size(), SCAP_MAX_PATH_SIZE) +
			2 + MIN(tinfo.m_exepath.size(), SCAP_MAX_PATH_SIZE) +
			2 + sctinfo->args_len +
			2 + MIN(tcwd.size(), SCAP_MAX_PATH_SIZE) +
			sizeof(uint64_t) +	// fdlimit
			sizeof(uint32_t) +	// uid
			sizeof(uint32_t) +	// gid
			sizeof(uint32_t) +  // vmsize_kb
			sizeof(uint32_t) +  // vmrss_kb
			sizeof(uint32_t) +  // vmswap_kb
			sizeof(uint64_t) +  // pfmajor
			sizeof(uint64_t) +  // pfminor
			2 + sctinfo->env_len +
			sizeof(int64_t) +  // vtid
			sizeof(int64_t) +  // vpid
			2 + sctinfo->cgroups_len +
			sizeof(uint32_t) +
			2 + MIN(tinfo.m_root.size(), SCAP_MAX_PATH_SIZE));

		totlen += il;

		scap_proc_free(m_inspector->m_h, sctinfo);
	}

	//
	// Second pass of the table to dump the Threads
	//
	if(scap_write_proclist_header(m_inspector->m_h, dumper, totlen) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_inspector->m_h));
	}

	for(auto it = m_threadtable.begin(); it != m_threadtable.end(); ++it)
	{
		scap_threadinfo *sctinfo;

		if((sctinfo = scap_proc_alloc(m_inspector->m_h)) == NULL)
		{
			throw sinsp_exception(scap_getlasterr(m_inspector->m_h));
		}
		sinsp_threadinfo& tinfo = it->second;

		thread_to_scap(tinfo, sctinfo);

		if(scap_write_proclist_entry(m_inspector->m_h, dumper, sctinfo) != SCAP_SUCCESS)
		{
			throw sinsp_exception(scap_getlasterr(m_inspector->m_h));
		}

		scap_proc_free(m_inspector->m_h, sctinfo);
	}

	if(scap_write_proclist_trailer(m_inspector->m_h, dumper, totlen) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_inspector->m_h));
	}

	//
	// Third pass of the table to dump the FDs
	//

	for(auto it = m_threadtable.begin(); it != m_threadtable.end(); ++it)
	{
		scap_threadinfo *sctinfo;

		if((sctinfo = scap_proc_alloc(m_inspector->m_h)) == NULL)
		{
			throw sinsp_exception(scap_getlasterr(m_inspector->m_h));
		}

		sinsp_threadinfo& tinfo = it->second;

		thread_to_scap(tinfo, sctinfo);

		if(tinfo.is_main_thread())
		{
			//
			// Add the FDs
			//
			unordered_map<int64_t, sinsp_fdinfo_t>& fdtable = tinfo.get_fd_table()->m_table;
			for(auto it = fdtable.begin(); it != fdtable.end(); ++it)
			{
				//
				// Allocate the scap fd info
				//
				scap_fdinfo* scfdinfo = (scap_fdinfo*)malloc(sizeof(scap_fdinfo));
				if(scfdinfo == NULL)
				{
					scap_proc_free(m_inspector->m_h, sctinfo);
					throw sinsp_exception("thread memory allocation error in sinsp_thread_manager::to_scap");
				}

				//
				// Populate the fd info
				//
				scfdinfo->fd = it->first;
				tinfo.fd_to_scap(scfdinfo, &it->second);

				//
				// Add the new fd to the scap table
				//
				if(scap_fd_add(sctinfo, it->first, scfdinfo) != SCAP_SUCCESS)
				{
					scap_proc_free(m_inspector->m_h, sctinfo);
					throw sinsp_exception("error calling scap_fd_add in sinsp_thread_manager::to_scap");
				}
			}
		}

		//
		// Dump the thread to disk
		//
		if(scap_write_proc_fds(m_inspector->m_h, sctinfo, dumper) != SCAP_SUCCESS)
		{
			scap_proc_free(m_inspector->m_h, sctinfo);
			throw sinsp_exception("error calling scap_proc_add in sinsp_thread_manager::to_scap");
		}

		scap_proc_free(m_inspector->m_h, sctinfo);
	}
}
