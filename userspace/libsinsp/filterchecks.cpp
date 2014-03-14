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

#include <time.h>
#ifndef _WIN32
#include <algorithm>
#endif
#include "sinsp.h"
#include "sinsp_int.h"

#ifdef HAS_FILTERING
#include "filter.h"
#include "filterchecks.h"

extern sinsp_evttables g_infotables;

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_fd implementation
///////////////////////////////////////////////////////////////////////////////
const filtercheck_field_info sinsp_filter_check_fd_fields[] =
{
	{PT_INT64, EPF_NONE, PF_DEC, "fd.num", "the unique number identifying the file descriptor."},
	{PT_CHARBUF, EPF_NONE, PF_DEC, "fd.type", "type of FD. Can be 'file', 'ipv4', 'ipv6', 'unix', 'pipe', 'event', 'signalfd', 'eventpoll', 'inotify' or 'signalfd'."},
	{PT_CHARBUF, EPF_NONE, PF_DEC, "fd.typechar", "type of FD as a single character. Can be 'f' for file, 4 for IPv4 socket, 6 for IPv6 socket, 'u' for unix socket, p for pipe, 'e' for eventfd, 's' for signalfd, 'l' for eventpoll, 'i' for inotify, or 's' for signalfd, 'o' for uknown."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.name", "FD full name. If the fd is a file, this field contains the full path. If the FD is a socket, this field contain the connection tuple."},
	{PT_IPV4ADDR, EPF_FILTER_ONLY, PF_NA, "fd.ip", "matches the ip address (client or server) of the fd."},
	{PT_IPV4ADDR, EPF_NONE, PF_NA, "fd.cip", "client IP address."},
	{PT_IPV4ADDR, EPF_NONE, PF_NA, "fd.sip", "server IP address."},
	{PT_PORT, EPF_FILTER_ONLY, PF_DEC, "fd.port", "matches the port (client or server) of the fd."},
	{PT_PORT, EPF_NONE, PF_DEC, "fd.cport", "for TCP/UDP FDs, the client port."},
	{PT_PORT, EPF_NONE, PF_DEC, "fd.sport", "for TCP/UDP FDs, server port."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.l4proto", "the IP protocol of a socket. Can be 'tcp', 'udp', 'icmp' or 'raw'."},
	{PT_SOCKFAMILY, EPF_NONE, PF_DEC, "fd.sockfamily", "the socket family for socket events. Can be 'ip' or 'unix'."},
	{PT_BOOL, EPF_NONE, PF_NA, "fd.is_server", "'true' if the process owning this FD is the server endpoint in the connection."},
};

sinsp_filter_check_fd::sinsp_filter_check_fd()
{
	m_tinfo = NULL;
	m_fdinfo = NULL;

	m_info.m_name = "fd";
	m_info.m_fields = sinsp_filter_check_fd_fields;
	m_info.m_nfiedls = sizeof(sinsp_filter_check_fd_fields) / sizeof(sinsp_filter_check_fd_fields[0]);
}

sinsp_filter_check* sinsp_filter_check_fd::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_fd();
}

int32_t sinsp_filter_check_fd::parse_field_name(const char* str)
{
	return sinsp_filter_check::parse_field_name(str);
}

uint8_t* sinsp_filter_check_fd::extract_fdtype(sinsp_fdinfo_t* fdinfo)
{
	switch(fdinfo->m_type)
	{
	case SCAP_FD_FILE:
	case SCAP_FD_DIRECTORY:
		return (uint8_t*)"file";
	case SCAP_FD_IPV4_SOCK:
	case SCAP_FD_IPV4_SERVSOCK:
		return (uint8_t*)"ipv4";
	case SCAP_FD_IPV6_SOCK:
	case SCAP_FD_IPV6_SERVSOCK:
		return (uint8_t*)"ipv6";
	case SCAP_FD_UNIX_SOCK:
		return (uint8_t*)"unix";
	case SCAP_FD_FIFO:
		return (uint8_t*)"pipe";
	case SCAP_FD_EVENT:
		return (uint8_t*)"event";
	case SCAP_FD_SIGNALFD:
		return (uint8_t*)"signalfd";
	case SCAP_FD_EVENTPOLL:
		return (uint8_t*)"eventpoll";
	case SCAP_FD_INOTIFY:
		return (uint8_t*)"inotify";
	case SCAP_FD_TIMERFD:
		return (uint8_t*)"timerfd";
	default:
		return NULL;
	}
}

uint8_t* sinsp_filter_check_fd::extract(sinsp_evt *evt, OUT uint32_t* len)
{
	ASSERT(evt);

	if(!extract_fd(evt))
	{
		return NULL;
	}

	//
	// TYPE_FDNUM doesn't need fdinfo
	//
	if(m_field_id == TYPE_FDNUM)
	{
		return (uint8_t*)&m_tinfo->m_lastevent_fd;
	}

	if(m_fdinfo == NULL)
	{
		return NULL;
	}

	switch(m_field_id)
	{
	case TYPE_FDNAME:
		m_tstr = m_fdinfo->m_name;
		m_tstr.erase(remove_if(m_tstr.begin(), m_tstr.end(), g_invalidchar()), m_tstr.end());

		return (uint8_t*)m_tstr.c_str();
	case TYPE_FDTYPE:
		return extract_fdtype(m_fdinfo);
	case TYPE_FDTYPECHAR:
		m_tcstr[0] = m_fdinfo->get_typechar();
		m_tcstr[1] = 0;
		return m_tcstr;
	case TYPE_CLIENTIP:
		{
			scap_fd_type evt_type = m_fdinfo->m_type;

			if(m_fdinfo->is_role_none())
			{
				return NULL;
			}

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				return (uint8_t*)&(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip);
			}
		}

		break;
	case TYPE_SERVERIP:
		{
			scap_fd_type evt_type = m_fdinfo->m_type;

			if(m_fdinfo->is_role_none())
			{
				return NULL;
			}

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				return (uint8_t*)&(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip);
			}
			else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
			{
				return (uint8_t*)&(m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_ip);
			}
		}

		break;
	case TYPE_CLIENTPORT:
		{
			scap_fd_type evt_type = m_fdinfo->m_type;

			if(m_fdinfo->is_role_none())
			{
				return NULL;
			}

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				return (uint8_t*)&(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport);
			}
			else if(evt_type == SCAP_FD_IPV6_SOCK)
			{
				return (uint8_t*)&(m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sport);
			}
		}
	case TYPE_SERVERPORT:
		{
			scap_fd_type evt_type = m_fdinfo->m_type;

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				if(m_fdinfo->is_role_none())
				{
					return NULL;
				}

				return (uint8_t*)&(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport);
			}
			else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
			{
				return (uint8_t*)&(m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_port);
			}
			else if(evt_type == SCAP_FD_IPV6_SOCK)
			{
				if(m_fdinfo->is_role_none())
				{
					return NULL;
				}

				return (uint8_t*)&(m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dport);
			}
			else if(evt_type == SCAP_FD_IPV6_SERVSOCK)
			{
				return (uint8_t*)&(m_fdinfo->m_sockinfo.m_ipv6serverinfo.m_port);
			}
			else
			{
				return NULL;
			}
		}
	case TYPE_L4PROTO:
		{
			scap_l4_proto l4p = m_fdinfo->get_l4proto();

			switch(l4p)
			{
			case SCAP_L4_TCP:
				m_tstr = "tcp";
				break;
			case SCAP_L4_UDP:
				m_tstr = "udp";
				break;
			case SCAP_L4_ICMP:
				m_tstr = "icmp";
				break;
			case SCAP_L4_RAW:
				m_tstr = "raw";
				break;
			default:
				m_tstr = "<NA>";
				break;
			}

			return (uint8_t*)m_tstr.c_str();
		}
	case TYPE_IS_SERVER:
		{
			m_tbool = 
				m_inspector->get_ifaddr_list()->is_ipv4addr_in_local_machine(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip);
			return (uint8_t*)&m_tbool;
		}
		break;
	default:
		ASSERT(false);
	}

	return NULL;
}

bool sinsp_filter_check_fd::compare_ip(sinsp_evt *evt)
{
	if(!extract_fd(evt))
	{
		return false;
	}

	if(m_fdinfo != NULL)
	{
		scap_fd_type evt_type = m_fdinfo->m_type;

		if(evt_type == SCAP_FD_IPV4_SOCK)
		{
			if(m_cmpop == CO_EQ)
			{
				if(flt_compare(m_cmpop, PT_IPV4ADDR, &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip, &m_val_storage[0]) ||
					flt_compare(m_cmpop, PT_IPV4ADDR, &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip, &m_val_storage[0]))
				{
					return true;
				}
			}
			else if(m_cmpop == CO_NE)
			{
				if(flt_compare(m_cmpop, PT_IPV4ADDR, &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip, &m_val_storage[0]) &&
					flt_compare(m_cmpop, PT_IPV4ADDR, &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip, &m_val_storage[0]))
				{
					return true;
				}
			}
			else
			{
				throw sinsp_exception("filter error: IP filter only supports '=' and '!=' operators");
			}
		}
		else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
		{
			if(m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_ip == *(uint32_t*)&m_val_storage[0])
			{
				return true;
			}
		}
	}

	return false;
}

bool sinsp_filter_check_fd::compare_port(sinsp_evt *evt)
{
	if(!extract_fd(evt))
	{
		return false;
	}

	if(m_fdinfo != NULL)
	{
		scap_fd_type evt_type = m_fdinfo->m_type;

		if(evt_type == SCAP_FD_IPV4_SOCK)
		{
			if(m_cmpop == CO_EQ)
			{
				if(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport == *(uint16_t*)&m_val_storage[0] ||
					m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport == *(uint16_t*)&m_val_storage[0])
				{
					return true;
				}
			}
			else if(m_cmpop == CO_NE)
			{
				if(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport != *(uint16_t*)&m_val_storage[0] &&
					m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport != *(uint16_t*)&m_val_storage[0])
				{
					return true;
				}
			}
			else
			{
				throw sinsp_exception("filter error: IP filter only supports '=' and '!=' operators");
			}
		}
		else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
		{
			if(m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_port == *(uint16_t*)&m_val_storage[0])
			{
				return true;
			}
		}
		else if(evt_type == SCAP_FD_IPV6_SOCK)
		{
			if(m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sport == *(uint16_t*)&m_val_storage[0] ||
				m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dport == *(uint16_t*)&m_val_storage[0])
			{
				return true;
			}
		}
		else if(evt_type == SCAP_FD_IPV6_SERVSOCK)
		{
			if(m_fdinfo->m_sockinfo.m_ipv6serverinfo.m_port == *(uint16_t*)&m_val_storage[0])
			{
				return true;
			}
		}
	}

	return false;
}

bool sinsp_filter_check_fd::extract_fd(sinsp_evt *evt)
{
	ppm_event_flags eflags = evt->get_flags();

	//
	// Make sure this is an event that creates or consumes an fd
	//
	if(eflags & (EF_CREATES_FD | EF_USES_FD | EF_DESTROYS_FD))
	{
		//
		// This is an fd-related event, get the thread info and the fd info
		//
		m_tinfo = evt->get_thread_info();
		if(m_tinfo == NULL)
		{
			return false;
		}

		m_fdinfo = evt->get_fd_info();

		if(m_fdinfo == NULL && m_tinfo->m_lastevent_fd != -1)
		{
			m_fdinfo = m_tinfo->get_fd(m_tinfo->m_lastevent_fd);
		}

		// We'll check if fd is null below
	}
	else
	{
		return false;
	}

	return true;
}

bool sinsp_filter_check_fd::compare(sinsp_evt *evt)
{
	//
	// A couple of fields are filter only and therefore get a special treatment
	//
	if(m_field_id == TYPE_IP)
	{
		return compare_ip(evt);
	}
	else if(m_field_id == TYPE_PORT)
	{
		return compare_port(evt);
	}

	//
	// Standard extract-based fields
	//
	uint32_t len;
	uint8_t* extracted_val = extract(evt, &len);

	if(extracted_val == NULL)
	{
		return false;
	}

	return flt_compare(m_cmpop, 
		m_info.m_fields[m_field_id].m_type, 
		extracted_val, 
		&m_val_storage[0]);
}

char* sinsp_filter_check_fd::tostring(sinsp_evt* evt)
{
	uint32_t len;

	uint8_t* rawval = extract(evt, &len);

	if(rawval == NULL)
	{
		return NULL;
	}

	return rawval_to_string(rawval, m_field, len);
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_thread implementation
///////////////////////////////////////////////////////////////////////////////
const filtercheck_field_info sinsp_filter_check_thread_fields[] =
{
	{PT_INT64, EPF_NONE, PF_DEC, "proc.pid", "the id of the process generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.exe", "the full name (including the path) of the executable generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.name", "the name (excluding thr path) of the executable generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.args", "the arguments passed on the command line when starting the process generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.cwd", "the current working directory of the event."},
	{PT_UINT32, EPF_NONE, PF_DEC, "proc.nchilds", "the number of child threads of that the process generating the event currently has."},
	{PT_INT64, EPF_NONE, PF_DEC, "thread.tid", "the id of the thread generating the event."},
	{PT_BOOL, EPF_NONE, PF_NA, "thread.ismain", "'true' if the thread generating the event is the main one in the process."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.parentname", "the name (excluding thr path) of the parent of the process generating the event."},
	{PT_UINT64, EPF_NONE, PF_DEC, "iobytes", "I/O bytes (either read or write) generated by I/O calls like read, write, send receive..."},
	{PT_UINT64, EPF_NONE, PF_DEC, "totiobytes", "aggregated number of I/O bytes (either read or write) since the beginning of the capture."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "latency", "number of nanoseconds spent in the last system call."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "totlatency", "aggregated number of nanoseconds spent in system calls since the beginning of the capture.."},
};

sinsp_filter_check_thread::sinsp_filter_check_thread()
{
	m_info.m_name = "process";
	m_info.m_fields = sinsp_filter_check_thread_fields;
	m_info.m_nfiedls = sizeof(sinsp_filter_check_thread_fields) / sizeof(sinsp_filter_check_thread_fields[0]);

	m_u64val = 0;
}

sinsp_filter_check* sinsp_filter_check_thread::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_thread();
}

int32_t sinsp_filter_check_thread::parse_field_name(const char* str)
{
	string val(str);

	if(string(val, 0, sizeof("arg") - 1) == "arg")
	{
		//
		// 'arg' is handled in a custom way
		//
		throw sinsp_exception("filter error: proc.arg filter not implemented yet");
	}
	else
	{
		return sinsp_filter_check::parse_field_name(str);
	}
}

uint8_t* sinsp_filter_check_thread::extract(sinsp_evt *evt, OUT uint32_t* len)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL && m_field_id != TYPE_TID)
	{
		return NULL;
	}

	switch(m_field_id)
	{
	case TYPE_TID:
		m_u64val = evt->get_tid();
		return (uint8_t*)&m_u64val;
	case TYPE_PID:
		return (uint8_t*)&tinfo->m_pid;
	case TYPE_NAME:
		m_tstr = tinfo->get_comm();
		return (uint8_t*)m_tstr.c_str();
	case TYPE_EXE:
		m_tstr = tinfo->get_exe();
		return (uint8_t*)m_tstr.c_str();
	case TYPE_ARGS:
		{
			m_tstr.clear();

			uint32_t j;
			uint32_t nargs = tinfo->m_args.size();

			for(j = 0; j < nargs; j++)
			{
				m_tstr += tinfo->m_args[j];
				if(j < nargs -1)
				{
					m_tstr += ' ';
				}
			}

			return (uint8_t*)m_tstr.c_str();
		}
	case TYPE_CWD:
		m_tstr = tinfo->get_cwd();
		return (uint8_t*)m_tstr.c_str();
	case TYPE_ISMAINTHREAD:
		m_tbool = (uint32_t)tinfo->is_main_thread();
		return (uint8_t*)&m_tbool;
	case TYPE_PARENTNAME:
		{
			sinsp_threadinfo* ptinfo = 
				m_inspector->get_thread(tinfo->m_ptid);

			if(ptinfo != NULL)
			{
				m_tstr = ptinfo->get_comm();
				return (uint8_t*)m_tstr.c_str();
			}
			else
			{
				return NULL;
			}
		}
	case IOBYTES:
	case TOTIOBYTES:
		{
			//
			// Extract the return value
			//
			uint16_t etype = evt->get_type();
			uint64_t res;

			if(etype == PPME_SYSCALL_READ_X || etype == PPME_SYSCALL_WRITE_X || etype == PPME_SOCKET_RECV_X ||
				etype == PPME_SOCKET_SEND_X|| etype == PPME_SOCKET_RECVFROM_X || etype == PPME_SOCKET_RECVMSG_X ||
				etype == PPME_SOCKET_SENDTO_X || etype == PPME_SOCKET_SENDMSG_X || etype == PPME_SYSCALL_READV_X ||
				etype == PPME_SYSCALL_WRITEV_X || etype == PPME_SYSCALL_PREAD_X || etype == PPME_SYSCALL_PWRITE_X || 
				etype == PPME_SYSCALL_PREADV_X || etype == PPME_SYSCALL_PWRITEV_X)
			{
				sinsp_evt_param *parinfo = evt->get_param(0);
				ASSERT(parinfo->m_len == sizeof(int64_t));
				res = *(int64_t *)parinfo->m_val;
			}
			else
			{
				res = 0;
			}

			if(m_field_id == IOBYTES)
			{
				m_u64val = res;

				if(m_u64val != 0)
				{
					return (uint8_t*)&m_u64val;
				}
				else
				{
					return NULL;
				}
			}
			else
			{
				m_u64val += res;
				return (uint8_t*)&m_u64val;
			}
		}
	case LATENCY:
		if(tinfo->m_latency != 0)
		{
			return (uint8_t*)&tinfo->m_latency;
		}
		else
		{
			return NULL;
		}
	case TOTLATENCY:
		m_u64val += tinfo->m_latency;
		return (uint8_t*)&m_u64val;
	default:
		ASSERT(false);
		return NULL;
	}
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_event implementation
///////////////////////////////////////////////////////////////////////////////
const filtercheck_field_info sinsp_filter_check_event_fields[] =
{
	{PT_UINT64, EPF_NONE, PF_DEC, "evt.num", "event number."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.time", "event timestamp as a time string that includes the nanosecond part."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.time.s", "event timestamp as a time string with no nanoseconds."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.datetime", "event timestamp as a time string that inclused the date."},
	{PT_ABSTIME, EPF_NONE, PF_DEC, "evt.rawtime", "absolute event timestamp, i.e. nanoseconds from epoch."},
	{PT_ABSTIME, EPF_NONE, PF_DEC, "evt.rawtime.s", "integer part of the event timestamp (e.g. seconds since epoch)."},
	{PT_ABSTIME, EPF_NONE, PF_10_PADDED_DEC, "evt.rawtime.ns", "fractional part of the absolute event timestamp."},
	{PT_RELTIME, EPF_NONE, PF_10_PADDED_DEC, "evt.reltime", "number of nanoseconds from the beginning of the capture."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "evt.reltime.s", "number of seconds from the beginning of the capture."},
	{PT_RELTIME, EPF_NONE, PF_10_PADDED_DEC, "evt.reltime.ns", "fractional part (in ns) of the time from the beginning of the capture."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "evt.latency", "delta between an exit event and the correspondent enter event."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "evt.latency.s", "integer part of the event latency delta."},
	{PT_RELTIME, EPF_NONE, PF_10_PADDED_DEC, "evt.latency.ns", "fractional part of the event latency delta."},
	{PT_CHARBUF, EPF_PRINT_ONLY, PF_NA, "evt.dir", "event direction can be either '>' for enter events or '<' for exit events."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.type", "For system call events, this is the name of the system call (e.g. 'open')."},
	{PT_INT16, EPF_NONE, PF_DEC, "evt.cpu", "number of the CPU where this event happened."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.args", "all the event arguments, aggregated into a single string."},
	{PT_CHARBUF, EPF_REQUIRES_ARGUMENT, PF_NA, "evt.arg", "one of the event arguments specified by name or by number. Some events (e.g. return codes or FDs) will be converted into a text representation when possible. E.g. 'resarg.fd' or 'resarg[0]'."},
	{PT_DYN, EPF_REQUIRES_ARGUMENT, PF_NA, "evt.rawarg", "one of the event arguments specified by name. E.g. 'arg.fd'."},
	{PT_CHARBUF, EPF_NONE, PF_DEC, "evt.res", "event return value, as an error code string (e.g. 'ENOENT')."},
	{PT_INT64, EPF_NONE, PF_DEC, "evt.rawres", "event return value, as a number (e.g. -2). Useful for range comparisons."},
	{PT_BOOL, EPF_NONE, PF_NA, "evt.is_io", "'true' for events that read or write to FDs, like read(), send, recvfrom(), etc."},
	{PT_BOOL, EPF_NONE, PF_NA, "evt.is_io_read", "'true' for events that read from FDs, like read(), recv(), recvfrom(), etc."},
	{PT_BOOL, EPF_NONE, PF_NA, "evt.is_io_write", "'true' for events that write to FDs, like write(), send(), etc."},
};

sinsp_filter_check_event::sinsp_filter_check_event()
{
	m_first_ts = 0;
	m_info.m_name = "evt";
	m_info.m_fields = sinsp_filter_check_event_fields;
	m_info.m_nfiedls = sizeof(sinsp_filter_check_event_fields) / sizeof(sinsp_filter_check_event_fields[0]);
}

sinsp_filter_check* sinsp_filter_check_event::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_event();
}

int32_t sinsp_filter_check_event::extract_arg(string fldname, string val, OUT const struct ppm_param_info** parinfo)
{
	uint32_t parsed_len = 0;

	//
	// 'arg' and 'resarg' are handled in a custom way
	//
	if(val[fldname.size()] == '[')
	{
		if(parinfo != NULL)
		{
			throw sinsp_exception("evt.arg fields must be expressed explicitly");
		}

		parsed_len = val.find(']');
		string numstr = val.substr(fldname.size() + 1, parsed_len - fldname.size() - 1);
		m_argid = sinsp_numparser::parsed32(numstr);
		parsed_len++;
	}
	else if(val[fldname.size()] == '.')
	{
		const struct ppm_param_info* pi = 
			sinsp_utils::find_longest_matching_evt_param(val.substr(fldname.size() + 1));

		m_argname = pi->name;
		parsed_len = fldname.size() + strlen(pi->name) + 1;
		m_argid = -1;

		if(parinfo != NULL)
		{
			*parinfo = pi;
		}
	}
	else
	{
		throw sinsp_exception("filter syntax error: " + val);
	}

	return parsed_len; 
}

int32_t sinsp_filter_check_event::parse_field_name(const char* str)
{
	string val(str);

	//
	// A couple of fields are handled in a custom way
	//
	if(string(val, 0, sizeof("evt.arg") - 1) == "evt.arg" &&
		string(val, 0, sizeof("evt.args") - 1) != "evt.args")
	{
		m_field_id = TYPE_ARGSTR;
		m_field = &m_info.m_fields[m_field_id];

		return extract_arg("evt.arg", val, NULL);
	}
	else if(string(val, 0, sizeof("evt.rawarg") - 1) == "evt.rawarg")
	{
		m_field_id = TYPE_ARGRAW;
		m_customfield = m_info.m_fields[m_field_id];

		int32_t res = extract_arg("evt.rawarg", val, &m_arginfo);

		m_customfield.m_type = m_arginfo->type;

		return res;
	}
	else if(string(val, 0, sizeof("evt.latency") - 1) == "evt.latency" ||
		string(val, 0, sizeof("evt.latency.s") - 1) == "evt.latency.s" ||
		string(val, 0, sizeof("evt.latency.ns") - 1) == "evt.latency.ns")
	{
		//
		// These fields need to store the previuos event type in the thread state
		//
		m_th_state_id = m_inspector->reserve_thread_memory(sizeof(uint16_t));
		return sinsp_filter_check::parse_field_name(str);
	}
	else
	{
		return sinsp_filter_check::parse_field_name(str);
	}
}

void sinsp_filter_check_event::parse_filter_value(const char* str)
{
	string val(str);

	if(m_field_id == TYPE_ARGRAW)
	{
		//
		// 'rawarg' is handled in a custom way
		//
		ASSERT(m_arginfo != NULL);
		return sinsp_filter_check::string_to_rawval(str, m_arginfo->type);
	}
	else
	{
		return sinsp_filter_check::parse_filter_value(str);
	}
}

const filtercheck_field_info* sinsp_filter_check_event::get_field_info()
{
	if(m_field_id == TYPE_ARGRAW)
	{
		return &m_customfield;
	}
	else
	{
		return &m_info.m_fields[m_field_id];
	}
}

int32_t sinsp_filter_check_event::gmt2local(time_t t)
{
	register int dt, dir;
	register struct tm *gmt, *loc;
	struct tm sgmt;

	if(t == 0)
	{
		t = time(NULL);
	}

	gmt = &sgmt;
	*gmt = *gmtime(&t);
	loc = localtime(&t);

	dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 + (loc->tm_min - gmt->tm_min) * 60;

	dir = loc->tm_year - gmt->tm_year;
	if(dir == 0)
	{
		dir = loc->tm_yday - gmt->tm_yday;
	}

	dt += dir * 24 * 60 * 60;

	return (dt);
}

void sinsp_filter_check_event::ts_to_string(uint64_t ts, OUT string* res, bool date, bool ns)
{
	struct tm *tm;
	time_t Time;
	uint64_t sec = ts / ONE_SECOND_IN_NS;
	uint64_t nsec = ts % ONE_SECOND_IN_NS;
	int32_t thiszone = gmt2local(0);
	int32_t s = (sec + thiszone) % 86400;
	int32_t bufsize = 0;
	char buf[256];

	if(date) 
	{
		Time = (sec + thiszone) - s;
		tm = gmtime (&Time);
		if(!tm)
		{
			bufsize = sprintf(buf, "<date error> ");
		}
		else
		{
			bufsize = sprintf(buf, "%04d-%02d-%02d ",
				   tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday);
		}
	}

	if(ns)
	{
		sprintf(buf + bufsize, "%02d:%02d:%02d.%09u",
				s / 3600, (s % 3600) / 60, s % 60, (unsigned)nsec);
	}
	else
	{
		sprintf(buf + bufsize, "%02d:%02d:%02d",
				s / 3600, (s % 3600) / 60, s % 60);
	}

	*res = buf;
}

uint8_t* sinsp_filter_check_event::extract(sinsp_evt *evt, OUT uint32_t* len)
{
	switch(m_field_id)
	{
	case TYPE_TIME:
		ts_to_string(evt->get_ts(), &m_strstorage, false, true);
		return (uint8_t*)m_strstorage.c_str();
	case TYPE_TIME_S:
		ts_to_string(evt->get_ts(), &m_strstorage, false, false);
		return (uint8_t*)m_strstorage.c_str();
	case TYPE_DATETIME:
		ts_to_string(evt->get_ts(), &m_strstorage, true, true);
		return (uint8_t*)m_strstorage.c_str();
	case TYPE_RAWTS:
		return (uint8_t*)&evt->m_pevt->ts;
	case TYPE_RAWTS_S:
		m_u64val = evt->get_ts() / ONE_SECOND_IN_NS;
		return (uint8_t*)&m_u64val;
	case TYPE_RAWTS_NS:
		m_u64val = evt->get_ts() % ONE_SECOND_IN_NS;
		return (uint8_t*)&m_u64val;
	case TYPE_RELTS:
		if(m_first_ts == 0)
		{
			m_first_ts = evt->get_ts();
		}

		m_u64val = evt->get_ts() - m_first_ts;
		return (uint8_t*)&m_u64val;
	case TYPE_RELTS_S:
		if(m_first_ts == 0)
		{
			m_first_ts = evt->get_ts();
		}

		m_u64val = (evt->get_ts() - m_first_ts) / ONE_SECOND_IN_NS;
		return (uint8_t*)&m_u64val;
	case TYPE_RELTS_NS:
		if(m_first_ts == 0)
		{
			m_first_ts = evt->get_ts();
		}

		m_u64val = (evt->get_ts() - m_first_ts) % ONE_SECOND_IN_NS;
		return (uint8_t*)&m_u64val;
	case TYPE_LATENCY:
		{
			m_u64val = 0;

			if(evt->get_direction() == SCAP_ED_IN)
			{
				if(evt->m_tinfo != NULL)
				{
					uint16_t* pt = (uint16_t*)evt->m_tinfo->get_private_state(m_th_state_id);
					*pt = evt->get_type();
				}

				return (uint8_t*)&m_u64val;
			}

			if(evt->m_tinfo != NULL)
			{
				uint16_t* pt = (uint16_t*)evt->m_tinfo->get_private_state(m_th_state_id);
				if(evt->get_type() == *pt + 1)
				{
					m_u64val = (evt->get_ts() - evt->m_tinfo->m_prevevent_ts);
				}
			}

			return (uint8_t*)&m_u64val;
		}
	case TYPE_LATENCY_S:
	case TYPE_LATENCY_NS:
		{
			m_u64val = 0;

			if(evt->get_direction() == SCAP_ED_IN)
			{
				if(evt->m_tinfo != NULL)
				{
					uint16_t* pt = (uint16_t*)evt->m_tinfo->get_private_state(m_th_state_id);
					*pt = evt->get_type();
				}

				return (uint8_t*)&m_u64val;
			}

			if(evt->m_tinfo != NULL)
			{
				uint16_t* pt = (uint16_t*)evt->m_tinfo->get_private_state(m_th_state_id);
				if(evt->get_type() == *pt + 1)
				{
					if(m_field_id == TYPE_LATENCY_S)
					{
						m_u64val = (evt->get_ts() - evt->m_tinfo->m_prevevent_ts) / 1000000000;
					}
					else
					{
						m_u64val = (evt->get_ts() - evt->m_tinfo->m_prevevent_ts) % 1000000000;
					}
				}
			}

			return (uint8_t*)&m_u64val;
		}
	case TYPE_DIR:
		if(PPME_IS_ENTER(evt->get_type()))
		{
			return (uint8_t*)">";
		}
		else
		{
			return (uint8_t*)"<";
		}
	case TYPE_TYPE:
		{
			uint8_t* evname;

			if(evt->m_pevt->type == PPME_GENERIC_E || evt->m_pevt->type == PPME_GENERIC_X)
			{
				sinsp_evt_param *parinfo = evt->get_param(0);
				ASSERT(parinfo->m_len == sizeof(uint16_t));
				uint16_t evid = *(uint16_t *)parinfo->m_val;

				evname = (uint8_t*)g_infotables.m_syscall_info_table[evid].name;
			}
			else
			{
				evname = (uint8_t*)evt->get_name();
			}

			return evname;
		}
		break;
	case TYPE_NUMBER:
		return (uint8_t*)&evt->m_evtnum;
	case TYPE_CPU:
		return (uint8_t*)&evt->m_cpuid;
	case TYPE_ARGRAW:
		{
			const sinsp_evt_param* pi = evt->get_param_value_raw(m_arginfo->name);

			if(pi != NULL)
			{
				*len = pi->m_len;
				return (uint8_t*)pi->m_val;
			}
			else
			{
				return NULL;
			}
		}
		break;
	case TYPE_ARGSTR:
		{
			const char* resolved_argstr;
			const char* argstr;

			ASSERT(m_inspector != NULL);

			if(m_argid != -1)
			{
				if(m_argid >= (int32_t)evt->m_info->nparams)
				{
					return NULL;
				}

				argstr = evt->get_param_as_str(m_argid, &resolved_argstr, m_inspector->get_buffer_format());
			}
			else
			{
				argstr = evt->get_param_value_str(m_argname.c_str(), &resolved_argstr, m_inspector->get_buffer_format());
			}

			if(resolved_argstr != NULL && resolved_argstr[0] != 0)
			{
				return (uint8_t*)resolved_argstr;
			}
			else
			{
				return (uint8_t*)argstr;
			}
		}
		break;
	case TYPE_ARGS:
		{
			if(evt->get_type() == PPME_GENERIC_E || evt->get_type() == PPME_GENERIC_X)
			{
				//
				// Don't print the arguments for generic events: they have only internal use
				//
				return (uint8_t*)"";
			}

			const char* resolved_argstr = NULL;
			const char* argstr = NULL;
			uint32_t nargs = evt->get_num_params();
			m_strstorage.clear();

			for(uint32_t j = 0; j < nargs; j++)
			{
				ASSERT(m_inspector != NULL);

				argstr = evt->get_param_as_str(j, &resolved_argstr, m_inspector->get_buffer_format());

				if(resolved_argstr[0] == 0)
				{
					m_strstorage += evt->get_param_name(j);
					m_strstorage += '=';
					m_strstorage += argstr;
					m_strstorage += " ";
				}
				else
				{
					m_strstorage += evt->get_param_name(j);
					m_strstorage += '=';
					m_strstorage += argstr;
					m_strstorage += string("(") + resolved_argstr + ") ";
				}
			}

			return (uint8_t*)m_strstorage.c_str();
		}
		break;
	case TYPE_RESRAW:
		{
			const sinsp_evt_param* pi = evt->get_param_value_raw("res");

			if(pi != NULL)
			{
				*len = pi->m_len;
				return (uint8_t*)pi->m_val;
			}

			if((evt->get_flags() & EF_CREATES_FD) && PPME_IS_EXIT(evt->get_type()))
			{
				pi = evt->get_param_value_raw("fd");

				if(pi != NULL)
				{
					*len = pi->m_len;
					return (uint8_t*)pi->m_val;
				}
			}

			return NULL;
		}
		break;
	case TYPE_RESSTR:
		{
			const char* resolved_argstr;
			const char* argstr;

			argstr = evt->get_param_value_str("res", &resolved_argstr);

			if(resolved_argstr != NULL && resolved_argstr[0] != 0)
			{
				return (uint8_t*)resolved_argstr;
			}
			else
			{
				if(argstr == NULL)
				{
					if((evt->get_flags() & EF_CREATES_FD) && PPME_IS_EXIT(evt->get_type()))
					{
						argstr = evt->get_param_value_str("fd", &resolved_argstr);

						if(resolved_argstr != NULL && resolved_argstr[0] != 0)
						{
							return (uint8_t*)resolved_argstr;
						}
						else
						{
							return (uint8_t*)argstr;
						}
					}
					else
					{
						return NULL;
					}
				}
				else
				{
					return (uint8_t*)argstr;
				}
			}
		}
		break;
	case TYPE_ISIO:
		{
			ppm_event_flags eflags = evt->get_flags();
			if(eflags & (EF_READS_FROM_FD | EF_WRITES_TO_FD))
			{
				m_u32val = 1;
			}
			else
			{
				m_u32val = 0;
			}
		}

		return (uint8_t*)&m_u32val;
	case TYPE_ISIO_READ:
		{
			ppm_event_flags eflags = evt->get_flags();
			if(eflags & EF_READS_FROM_FD)
			{
				m_u32val = 1;
			}
			else
			{
				m_u32val = 0;
			}

			return (uint8_t*)&m_u32val;
		}
	case TYPE_ISIO_WRITE:
		{
			ppm_event_flags eflags = evt->get_flags();
			if(eflags & EF_WRITES_TO_FD)
			{
				m_u32val = 1;
			}
			else
			{
				m_u32val = 0;
			}

			return (uint8_t*)&m_u32val;
		}
	default:
		ASSERT(false);
		return NULL;
	}

	return NULL;
}

char* sinsp_filter_check_event::tostring(sinsp_evt* evt)
{
	if(m_field_id == TYPE_ARGRAW)
	{
		uint32_t len;
		uint8_t* rawval = extract(evt, &len);

		if(rawval == NULL)
		{
			return NULL;
		}

		return rawval_to_string(rawval, &m_customfield, len);
	}
	else
	{
		return sinsp_filter_check::tostring(evt);
	}
}

bool sinsp_filter_check_event::compare(sinsp_evt *evt)
{
	if(m_field_id == TYPE_ARGRAW)
	{
		uint32_t len;
		uint8_t* extracted_val = extract(evt, &len);

		if(extracted_val == NULL)
		{
			return false;
		}

		ASSERT(m_arginfo != NULL);

		return flt_compare(m_cmpop, 
			m_arginfo->type, 
			extracted_val, 
			&m_val_storage[0]);
	}
	else
	{
		return sinsp_filter_check::compare(evt);
	}
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_user implementation
///////////////////////////////////////////////////////////////////////////////
const filtercheck_field_info sinsp_filter_check_user_fields[] =
{
	{PT_UINT64, EPF_NONE, PF_DEC, "user.id", "user ID."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "user.name", "user name."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "user.homedir", "home directory of the user."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "user.shell", "user's shell."},
};

sinsp_filter_check_user::sinsp_filter_check_user()
{
	m_info.m_name = "user";
	m_info.m_fields = sinsp_filter_check_user_fields;
	m_info.m_nfiedls = sizeof(sinsp_filter_check_user_fields) / sizeof(sinsp_filter_check_user_fields[0]);
}

sinsp_filter_check* sinsp_filter_check_user::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_user();
}

uint8_t* sinsp_filter_check_user::extract(sinsp_evt *evt, OUT uint32_t* len)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();
	scap_userinfo* uinfo;

	if(tinfo == NULL)
	{
		return NULL;
	}

	if(m_field_id != TYPE_UID)
	{
		unordered_map<uint32_t, scap_userinfo*>::iterator it;

		ASSERT(m_inspector != NULL);
		unordered_map<uint32_t, scap_userinfo*>* userlist = 
			(unordered_map<uint32_t, scap_userinfo*>*)m_inspector->get_userlist();
		ASSERT(userlist->size() != 0);

		if(tinfo->m_uid == 0xffffffff)
		{
			return NULL;
		}

		it = userlist->find(tinfo->m_uid);
		if(it == userlist->end())
		{
			ASSERT(false);
			return NULL;
		}

		uinfo = it->second;
		ASSERT(uinfo != NULL);
	}

	switch(m_field_id)
	{
	case TYPE_UID:
		return (uint8_t*)&tinfo->m_uid;
	case TYPE_NAME:
		return (uint8_t*)uinfo->name;
	case TYPE_HOMEDIR:
		return (uint8_t*)uinfo->homedir;
	case TYPE_SHELL:
		return (uint8_t*) uinfo->shell;
	default:
		ASSERT(false);
		break;
	}

	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_group implementation
///////////////////////////////////////////////////////////////////////////////
const filtercheck_field_info sinsp_filter_check_group_fields[] =
{
	{PT_UINT64, EPF_NONE, PF_DEC, "group.gid", "group ID."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "group.name", "group name."},
};

sinsp_filter_check_group::sinsp_filter_check_group()
{
	m_info.m_name = "group";
	m_info.m_fields = sinsp_filter_check_group_fields;
	m_info.m_nfiedls = sizeof(sinsp_filter_check_group_fields) / sizeof(sinsp_filter_check_group_fields[0]);
}

sinsp_filter_check* sinsp_filter_check_group::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_group();
}

uint8_t* sinsp_filter_check_group::extract(sinsp_evt *evt, OUT uint32_t* len)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL)
	{
		return NULL;
	}

	switch(m_field_id)
	{
	case TYPE_GID:
		return (uint8_t*)&tinfo->m_gid;
	case TYPE_NAME:
		{
			unordered_map<uint32_t, scap_groupinfo*>::iterator it;

			ASSERT(m_inspector != NULL);
			unordered_map<uint32_t, scap_groupinfo*>* grouplist = 
				(unordered_map<uint32_t, scap_groupinfo*>*)m_inspector->get_grouplist();
			ASSERT(grouplist->size() != 0);

			if(tinfo->m_gid == 0xffffffff)
			{
				return NULL;
			}

			it = grouplist->find(tinfo->m_gid);
			if(it == grouplist->end())
			{
				ASSERT(false);
				return NULL;
			}

			scap_groupinfo* ginfo = it->second;
			ASSERT(ginfo != NULL);

			return (uint8_t*)ginfo->name;
		}
	default:
		ASSERT(false);
		break;
	}

	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
// rawstring_check implementation
///////////////////////////////////////////////////////////////////////////////
const filtercheck_field_info rawstring_check_fields[] =
{
	{PT_CHARBUF, EPF_NONE, PF_NA, "NA", "INTERNAL."},
};

rawstring_check::rawstring_check(string text)
{
	m_field = rawstring_check_fields;
	set_text(text);
}

sinsp_filter_check* rawstring_check::allocate_new()
{
	ASSERT(false);
	return NULL;
}

void rawstring_check::set_text(string text)
{
	m_text_len = text.size();
	m_text = text;
}

int32_t rawstring_check::parse_field_name(const char* str)
{
	ASSERT(false);
	return -1;
}

void rawstring_check::parse_filter_value(const char* str)
{
	ASSERT(false);
}

uint8_t* rawstring_check::extract(sinsp_evt *evt, OUT uint32_t* len)
{
	*len = m_text_len;
	return (uint8_t*)m_text.c_str();
}

#endif // HAS_FILTERING
