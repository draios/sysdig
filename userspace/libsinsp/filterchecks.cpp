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

#include <time.h>
#ifndef _WIN32
#include <algorithm>
#endif
#include "sinsp.h"
#include "sinsp_int.h"

#ifdef HAS_FILTERING
#include "filter.h"
#include "filterchecks.h"
#include "protodecoder.h"

extern sinsp_evttables g_infotables;

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_fd implementation
///////////////////////////////////////////////////////////////////////////////
const filtercheck_field_info sinsp_filter_check_fd_fields[] =
{
	{PT_INT64, EPF_NONE, PF_DEC, "fd.num", "the unique number identifying the file descriptor."},
	{PT_CHARBUF, EPF_NONE, PF_DEC, "fd.type", "type of FD. Can be 'file', 'directory', ipv4', 'ipv6', 'unix', 'pipe', 'event', 'signalfd', 'eventpoll', 'inotify' or 'signalfd'."},
	{PT_CHARBUF, EPF_NONE, PF_DEC, "fd.typechar", "type of FD as a single character. Can be 'f' for file, 4 for IPv4 socket, 6 for IPv6 socket, 'u' for unix socket, p for pipe, 'e' for eventfd, 's' for signalfd, 'l' for eventpoll, 'i' for inotify, 'o' for uknown."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.name", "FD full name. If the fd is a file, this field contains the full path. If the FD is a socket, this field contain the connection tuple."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.directory", "If the fd is a file, the directory that contains it."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.filename", "If the fd is a file, the filename without the path."},
	{PT_IPV4ADDR, EPF_NONE, PF_NA, "fd.ip", "matches the ip address (client or server) of the fd."},
	{PT_IPV4ADDR, EPF_NONE, PF_NA, "fd.cip", "client IP address."},
	{PT_IPV4ADDR, EPF_NONE, PF_NA, "fd.sip", "server IP address."},
	{PT_PORT, EPF_FILTER_ONLY, PF_DEC, "fd.port", "matches the port (either client or server) of the fd."},
	{PT_PORT, EPF_NONE, PF_DEC, "fd.cport", "for TCP/UDP FDs, the client port."},
	{PT_PORT, EPF_NONE, PF_DEC, "fd.sport", "for TCP/UDP FDs, server port."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.l4proto", "the IP protocol of a socket. Can be 'tcp', 'udp', 'icmp' or 'raw'."},
	{PT_CHARBUF, EPF_NONE, PF_DEC, "fd.sockfamily", "the socket family for socket events. Can be 'ip' or 'unix'."},
	{PT_BOOL, EPF_NONE, PF_NA, "fd.is_server", "'true' if the process owning this FD is the server endpoint in the connection."},
};

sinsp_filter_check_fd::sinsp_filter_check_fd()
{
	m_tinfo = NULL;
	m_fdinfo = NULL;

	m_info.m_name = "fd";
	m_info.m_fields = sinsp_filter_check_fd_fields;
	m_info.m_nfiedls = sizeof(sinsp_filter_check_fd_fields) / sizeof(sinsp_filter_check_fd_fields[0]);
	m_info.m_flags = filter_check_info::FL_WORKS_ON_THREAD_TABLE;
}

sinsp_filter_check* sinsp_filter_check_fd::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_fd();
}

int32_t sinsp_filter_check_fd::parse_field_name(const char* str)
{
	return sinsp_filter_check::parse_field_name(str);
}

bool sinsp_filter_check_fd::extract_fdname_from_creator(sinsp_evt *evt, OUT uint32_t* len)
{
	const char* resolved_argstr;
	uint16_t etype = evt->get_type();

	if(PPME_IS_ENTER(etype))
	{
		return false;
	}

	switch(etype)
	{
	case PPME_SYSCALL_OPEN_X:
	case PPME_SOCKET_ACCEPT_X:
	case PPME_SOCKET_ACCEPT4_X:
	case PPME_SYSCALL_CREAT_X:
		{
			const char* argstr = evt->get_param_as_str(1, &resolved_argstr, 
				m_inspector->get_buffer_format());
			
			if(resolved_argstr[0] != 0)
			{
				m_tstr = resolved_argstr;
			}
			else
			{
				m_tstr = argstr;
			}

			return true;
		}
	case PPME_SOCKET_CONNECT_X:
		{
			const char* argstr = evt->get_param_as_str(1, &resolved_argstr, 
				m_inspector->get_buffer_format());
			
			if(resolved_argstr[0] != 0)
			{
				m_tstr = resolved_argstr;
			}
			else
			{
				m_tstr = argstr;
			}

			return true;
		}
	case PPME_SYSCALL_OPENAT_X:
		{
			//
			// XXX This is highly inefficient, as it re-requests the enter event and then
			// does unnecessary allocations and copies. We assume that failed openat() happen
			// rarely enough that we don't care.
			//
			sinsp_evt enter_evt;
			if(!m_inspector->get_parser()->retrieve_enter_event(&enter_evt, evt))
			{
				return false;
			}

			sinsp_evt_param *parinfo;
			char *name;
			uint32_t namelen;
			string sdir;

			parinfo = enter_evt.get_param(1);
			name = parinfo->m_val;
			namelen = parinfo->m_len;

			parinfo = enter_evt.get_param(0);
			ASSERT(parinfo->m_len == sizeof(int64_t));
			int64_t dirfd = *(int64_t *)parinfo->m_val;

			sinsp_parser::parse_openat_dir(evt, name, dirfd, &sdir);

			char fullpath[SCAP_MAX_PATH_SIZE];

			sinsp_utils::concatenate_paths(fullpath, SCAP_MAX_PATH_SIZE, 
				sdir.c_str(), 
				(uint32_t)sdir.length(), 
				name, 
				namelen);
	
			m_tstr = fullpath;
			m_tstr.erase(remove_if(m_tstr.begin(), m_tstr.end(), g_invalidchar()), m_tstr.end());
			return true;
		}
	default:
		m_tstr = "";
		return true;
	}
}

uint8_t* sinsp_filter_check_fd::extract_from_null_fd(sinsp_evt *evt, OUT uint32_t* len)
{
	//
	// Even is there's no fd, we still try to extract a name from exit events that create
	// one. With these events, the fact that there's no FD means that the call failed,
	// but even if that happened we still want to collect the name.
	//
	switch(m_field_id)
	{
	case TYPE_FDNAME:
	{
		if(extract_fdname_from_creator(evt, len) == true)
		{
			return (uint8_t*)m_tstr.c_str();
		}
		else
		{
			return NULL;
		}
	}
	case TYPE_DIRECTORY:
	{
		if(extract_fdname_from_creator(evt, len) == true)
		{
			m_tstr.erase(remove_if(m_tstr.begin(), m_tstr.end(), g_invalidchar()), m_tstr.end());

			size_t pos = m_tstr.rfind('/');
			if(pos != string::npos)
			{
				if(pos < m_tstr.size() - 1)
				{
					m_tstr.resize(pos + 1);
				}
			}
			else
			{
				m_tstr = "/";
			}

			return (uint8_t*)m_tstr.c_str();
		}
		else
		{
			return NULL;
		}
	}
	case TYPE_FILENAME:
	{
		if(evt->get_type() != PPME_SYSCALL_OPEN_E && evt->get_type() != PPME_SYSCALL_OPENAT_E &&
			evt->get_type() != PPME_SYSCALL_CREAT_E)
		{
			return NULL;
		}
 
		if(extract_fdname_from_creator(evt, len) == true)
		{
			m_tstr.erase(remove_if(m_tstr.begin(), m_tstr.end(), g_invalidchar()), m_tstr.end());

			size_t pos = m_tstr.rfind('/');
			if(pos != string::npos)
			{
				if(pos < m_tstr.size() - 1)
				{
					m_tstr = m_tstr.substr(pos + 1, string::npos);
				}
			}

			return (uint8_t*)m_tstr.c_str();
		}
		else
		{
			return NULL;
		}
	}
	case TYPE_FDTYPECHAR:
		switch(PPME_MAKE_ENTER(evt->get_type()))
		{
		case PPME_SYSCALL_OPEN_E:
		case PPME_SYSCALL_OPENAT_E:
		case PPME_SYSCALL_CREAT_E:
			m_tcstr[0] = CHAR_FD_FILE;
			m_tcstr[1] = 0;
			return m_tcstr;
		case PPME_SOCKET_SOCKET_E:
		case PPME_SOCKET_ACCEPT_E:
		case PPME_SOCKET_ACCEPT4_E:
			//
			// Note, this is not accurate, because it always
			// returns IPv4 even if this could be IPv6 or unix.
			// For the moment, I assume it's better than nothing, and doing
			// real event parsing here would be a pain. 
			//
			m_tcstr[0] = CHAR_FD_IPV4_SOCK;
			m_tcstr[1] = 0;
			return m_tcstr;
		case PPME_SYSCALL_PIPE_E:
			m_tcstr[0] = CHAR_FD_FIFO;
			m_tcstr[1] = 0;
			return m_tcstr;
		case PPME_SYSCALL_EVENTFD_E:
			m_tcstr[0] = CHAR_FD_EVENT;
			m_tcstr[1] = 0;
			return m_tcstr;
		case PPME_SYSCALL_SIGNALFD_E:
			m_tcstr[0] = CHAR_FD_SIGNAL;
			m_tcstr[1] = 0;
			return m_tcstr;
		case PPME_SYSCALL_TIMERFD_CREATE_E:
			m_tcstr[0] = CHAR_FD_TIMERFD;
			m_tcstr[1] = 0;
			return m_tcstr;
		case PPME_SYSCALL_INOTIFY_INIT_E:
			m_tcstr[0] = CHAR_FD_INOTIFY;
			m_tcstr[1] = 0;
			return m_tcstr;
		default:
			m_tcstr[0] = 'o';
			m_tcstr[1] = 0;
			return m_tcstr;
		}
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

	switch(m_field_id)
	{
	case TYPE_FDNAME:
		if(m_fdinfo == NULL)
		{
			return extract_from_null_fd(evt, len);
		}

		if(evt->get_type() == PPME_SOCKET_CONNECT_X)
		{
			sinsp_evt_param *parinfo;

			parinfo = evt->get_param(0);
			ASSERT(parinfo->m_len == sizeof(uint64_t));
			int64_t retval = *(int64_t*)parinfo->m_val;

			if(retval < 0)
			{
				return extract_from_null_fd(evt, len);
			}
		}

		m_tstr = m_fdinfo->m_name;
		m_tstr.erase(remove_if(m_tstr.begin(), m_tstr.end(), g_invalidchar()), m_tstr.end());
		return (uint8_t*)m_tstr.c_str();
	case TYPE_FDTYPE:
		if(m_fdinfo == NULL)
		{
			return NULL;
		}

		return (uint8_t*)m_fdinfo->get_typestring();
	case TYPE_DIRECTORY:
		{
			if(m_fdinfo == NULL)
			{
				return extract_from_null_fd(evt, len);
			}

			if(!(m_fdinfo->is_file() || m_fdinfo->is_directory()))
			{
				return NULL;
			}

			m_tstr = m_fdinfo->m_name;
			m_tstr.erase(remove_if(m_tstr.begin(), m_tstr.end(), g_invalidchar()), m_tstr.end());

			if(m_fdinfo->is_file())
			{
				size_t pos = m_tstr.rfind('/');
				if(pos != string::npos)
				{
					if(pos < m_tstr.size() - 1)
					{
						m_tstr.resize(pos + 1);
					}
				}
				else
				{
					m_tstr = "/";
				}
			}

			return (uint8_t*)m_tstr.c_str();
		}
	case TYPE_FILENAME:
		{
			if(m_fdinfo == NULL)
			{
				return extract_from_null_fd(evt, len);
			}

			if(!m_fdinfo->is_file())
			{
				return NULL;
			}

			m_tstr = m_fdinfo->m_name;
			m_tstr.erase(remove_if(m_tstr.begin(), m_tstr.end(), g_invalidchar()), m_tstr.end());

			size_t pos = m_tstr.rfind('/');
			if(pos != string::npos)
			{
				if(pos < m_tstr.size() - 1)
				{
					m_tstr = m_tstr.substr(pos + 1, string::npos);
				}
			}
			else
			{
				m_tstr = "/";
			}

			return (uint8_t*)m_tstr.c_str();
		}
	case TYPE_FDTYPECHAR:
		if(m_fdinfo == NULL)
		{
			return extract_from_null_fd(evt, len);
		}

		m_tcstr[0] = m_fdinfo->get_typechar();
		m_tcstr[1] = 0;
		return m_tcstr;
	case TYPE_CLIENTIP:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			if(m_fdinfo->is_role_none())
			{
				return NULL;
			}

			scap_fd_type evt_type = m_fdinfo->m_type;
			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				return (uint8_t*)&(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip);
			}
		}

		break;
	case TYPE_SERVERIP:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

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
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

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
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

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
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

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
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			if(m_fdinfo->m_type == SCAP_FD_IPV4_SERVSOCK || m_fdinfo->m_type == SCAP_FD_IPV6_SERVSOCK)
			{
				m_tbool = true;
			}
			else if(m_fdinfo->m_type == SCAP_FD_IPV4_SOCK)
			{
				m_tbool = 
					m_inspector->get_ifaddr_list()->is_ipv4addr_in_local_machine(m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip);
			}
			else
			{
				m_tbool = false;
			}


			return (uint8_t*)&m_tbool;
		}
		break;
	case TYPE_SOCKFAMILY:
		{
			if(m_fdinfo == NULL)
			{
				return NULL;
			}

			if(m_fdinfo->m_type == SCAP_FD_IPV4_SOCK || m_fdinfo->m_type == SCAP_FD_IPV6_SOCK)
			{
				m_tstr = "ip";
				return (uint8_t*)m_tstr.c_str();
			}
			else if(m_fdinfo->m_type == SCAP_FD_IPV4_SOCK || m_fdinfo->m_type == SCAP_FD_IPV6_SOCK)
			{
				m_tstr = "unix";
				return (uint8_t*)m_tstr.c_str();
			}
			else
			{
				return NULL;
			}
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
		uint16_t* sport;
		uint16_t* dport;
		scap_fd_type evt_type = m_fdinfo->m_type;

		if(evt_type == SCAP_FD_IPV4_SOCK)
		{
			sport = &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport;
			dport = &m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport;
		}
		else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
		{
			sport = &m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_port;
			dport = &m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_port;
		}
		else if(evt_type == SCAP_FD_IPV6_SOCK)
		{
			sport = &m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sport;
			dport = &m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dport;
		}
		else if(evt_type == SCAP_FD_IPV6_SERVSOCK)
		{
			sport = &m_fdinfo->m_sockinfo.m_ipv6serverinfo.m_port;
			dport = &m_fdinfo->m_sockinfo.m_ipv6serverinfo.m_port;
		}
		else
		{
			return false;
		}

		switch(m_cmpop)
		{
		case CO_EQ:
			if(*sport == *(uint16_t*)&m_val_storage[0] ||
				*dport == *(uint16_t*)&m_val_storage[0])
			{
				return true;
			}
			break;
		case CO_NE:
			if(*sport != *(uint16_t*)&m_val_storage[0] &&
				*dport != *(uint16_t*)&m_val_storage[0])
			{
				return true;
			}
			break;
		case CO_LT:
			if(*sport < *(uint16_t*)&m_val_storage[0] ||
				*dport < *(uint16_t*)&m_val_storage[0])
			{
				return true;
			}
			break;
		case CO_LE:
			if(*sport <= *(uint16_t*)&m_val_storage[0] ||
				*dport <= *(uint16_t*)&m_val_storage[0])
			{
				return true;
			}
			break;
		case CO_GT:
			if(*sport > *(uint16_t*)&m_val_storage[0] ||
				*dport > *(uint16_t*)&m_val_storage[0])
			{
				return true;
			}
			break;
		case CO_GE:
			if(*sport >= *(uint16_t*)&m_val_storage[0] ||
				*dport >= *(uint16_t*)&m_val_storage[0])
			{
				return true;
			}
			break;
		default:
			throw sinsp_exception("filter error: unsupported port comparison operator");
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

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_thread implementation
///////////////////////////////////////////////////////////////////////////////
const filtercheck_field_info sinsp_filter_check_thread_fields[] =
{
	{PT_INT64, EPF_NONE, PF_DEC, "proc.pid", "the id of the process generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.exe", "the full name (including the path) of the executable generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.name", "the name (excluding the path) of the executable generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.args", "the arguments passed on the command line when starting the process generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.env", "the environment variables of the process generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.cmdline", "full process command line, i.e name + arguments."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.cwd", "the current working directory of the event."},
	{PT_UINT32, EPF_NONE, PF_DEC, "proc.nchilds", "the number of child threads of that the process generating the event currently has."},
	{PT_INT64, EPF_NONE, PF_DEC, "proc.ppid", "the pid of the parent of the process generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.pname", "the name (excluding the path) of the parent of the process generating the event."},
	{PT_INT64, EPF_NONE, PF_DEC, "proc.apid", "the pid of one of the process ancestors. E.g. proc.apid[1] returns the parent pid, proc.apid[2] returns the grandparent pid, and so on. proc.apid[0] is the pid of the current process. proc.apid without arguments can be used in filters only and matches any of the process ancestors, e.g. proc.apid=1234."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.aname", "the name (excluding the path) of one of the process ancestors. E.g. proc.aname[1] returns the parent name, proc.aname[2] returns the grandparent name, and so on. proc.aname[0] is the name of the current process. proc.aname without arguments can be used in filters only and matches any of the process ancestors, e.g. proc.aname=bash."},
	{PT_INT64, EPF_NONE, PF_DEC, "proc.loginshellid", "the pid of the oldest shell among the ancestors of the current process, if there is one. This field can be used to separate different user sessions, and is useful in conjunction with chisels like spy_user."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "proc.duration", "number of nanoseconds since the process started."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.fdopencount", "number of open FDs for the process"},
	{PT_INT64, EPF_NONE, PF_DEC, "proc.fdlimit", "maximum number of FDs the process can open."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.fdusage", "the ratio between open FDs and maximum available FDs for the process."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.vmsize", "total virtual memory for the process (as kb)."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.vmrss", "resident non-swapped memory for the process (as kb)."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.vmswap", "swapped memory for the process (as kb)."},
	{PT_UINT64, EPF_NONE, PF_DEC, "thread.pfmajor", "number of major page faults since thread start."},
	{PT_UINT64, EPF_NONE, PF_DEC, "thread.pfminor", "number of minor page faults since thread start."},
	{PT_INT64, EPF_NONE, PF_DEC, "thread.tid", "the id of the thread generating the event."},
	{PT_BOOL, EPF_NONE, PF_NA, "thread.ismain", "'true' if the thread generating the event is the main one in the process."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "thread.exectime", "CPU time spent by the last scheduled thread, in nanoseconds. Exported by switch events only."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "thread.totexectime", "Total CPU time, in nanoseconds since the beginning of the capture, for the current thread. Exported by switch events only."},
//	{PT_UINT64, EPF_NONE, PF_DEC, "iobytes", "I/O bytes (either read or write) generated by I/O calls like read, write, send receive..."},
//	{PT_UINT64, EPF_NONE, PF_DEC, "totiobytes", "aggregated number of I/O bytes (either read or write) since the beginning of the capture."},
//	{PT_RELTIME, EPF_NONE, PF_DEC, "latency", "number of nanoseconds spent in the last system call."},
//	{PT_RELTIME, EPF_NONE, PF_DEC, "totlatency", "aggregated number of nanoseconds spent in system calls since the beginning of the capture.."},
};

sinsp_filter_check_thread::sinsp_filter_check_thread()
{
	m_info.m_name = "process";
	m_info.m_fields = sinsp_filter_check_thread_fields;
	m_info.m_nfiedls = sizeof(sinsp_filter_check_thread_fields) / sizeof(sinsp_filter_check_thread_fields[0]);
	m_info.m_flags = filter_check_info::FL_WORKS_ON_THREAD_TABLE;

	m_u64val = 0;
}

sinsp_filter_check* sinsp_filter_check_thread::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_thread();
}

int32_t sinsp_filter_check_thread::extract_arg(string fldname, string val, OUT const struct ppm_param_info** parinfo)
{
	uint32_t parsed_len = 0;

	//
	// 'arg' and 'resarg' are handled in a custom way
	//
	if(val[fldname.size()] == '[')
	{
		parsed_len = (uint32_t)val.find(']');
		string numstr = val.substr(fldname.size() + 1, parsed_len - fldname.size() - 1);
		m_argid = sinsp_numparser::parsed32(numstr);
		parsed_len++;
	}
	else
	{
		throw sinsp_exception("filter syntax error: " + val);
	}

	return parsed_len; 
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
	else if(string(val, 0, sizeof("proc.apid") - 1) == "proc.apid")
	{
		m_field_id = TYPE_APID;
		m_field = &m_info.m_fields[m_field_id];

		int32_t res = 0;

		try
		{
			res = extract_arg("proc.apid", val, NULL);
		}
		catch(...)
		{
			if(val == "proc.apid")
			{
				m_argid = -1;
				res = (int32_t)val.size();
			}
		}

		return res;
	}
	else if(string(val, 0, sizeof("proc.aname") - 1) == "proc.aname")
	{
		m_field_id = TYPE_ANAME;
		m_field = &m_info.m_fields[m_field_id];

		int32_t res = 0;

		try
		{
			res = extract_arg("proc.aname", val, NULL);
		}
		catch(...)
		{
			if(val == "proc.aname")
			{
				m_argid = -1;
				res = (int32_t)val.size();
			}
		}

		return res;
	}
	else if(string(val, 0, sizeof("thread.totexectime") - 1) == "thread.totexectime")
	{
		//
		// Allocate thread storage for the value
		//
		m_th_state_id = m_inspector->reserve_thread_memory(sizeof(uint64_t));
		return sinsp_filter_check::parse_field_name(str);
	}
	else
	{
		return sinsp_filter_check::parse_field_name(str);
	}
}

uint64_t sinsp_filter_check_thread::extract_exectime(sinsp_evt *evt) 
{
	uint64_t res = 0;

	if(m_last_proc_switch_times.size() == 0)
	{
		//
		// Initialize the vector of CPU times
		//
		const scap_machine_info* minfo = m_inspector->get_machine_info();
		ASSERT(minfo->num_cpus != 0);

		for(uint32_t j = 0; j < minfo->num_cpus; j++)
		{
			m_last_proc_switch_times.push_back(0);
		}
	}

	uint32_t cpuid = evt->get_cpuid();
	uint64_t ts = evt->get_ts();
	uint64_t lasttime = m_last_proc_switch_times[cpuid];

	if(lasttime != 0)
	{
		res = ts - lasttime;
	}

	ASSERT(cpuid < m_last_proc_switch_times.size());

	m_last_proc_switch_times[cpuid] = ts;

	return res;
}

uint8_t* sinsp_filter_check_thread::extract(sinsp_evt *evt, OUT uint32_t* len)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL && 
		m_field_id != TYPE_TID &&
		m_field_id != TYPE_EXECTIME &&
		m_field_id != TYPE_TOTEXECTIME)
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
			uint32_t nargs = (uint32_t)tinfo->m_args.size();

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
	case TYPE_ENV:
		{
			m_tstr.clear();

			uint32_t j;
			uint32_t nargs = (uint32_t)tinfo->m_env.size();

			for(j = 0; j < nargs; j++)
			{
				m_tstr += tinfo->m_env[j];
				if(j < nargs -1)
				{
					m_tstr += ' ';
				}
			}

			return (uint8_t*)m_tstr.c_str();
		}
	case TYPE_CMDLINE:
		{
			m_tstr = tinfo->get_comm() + " ";

			uint32_t j;
			uint32_t nargs = (uint32_t)tinfo->m_args.size();

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
	case TYPE_EXECTIME:
		{
			m_u64val = 0;
			uint16_t etype = evt->get_type();

			if(etype == PPME_SCHEDSWITCH_1_E || etype == PPME_SCHEDSWITCH_6_E)
			{
				m_u64val = extract_exectime(evt);
			}

			return (uint8_t*)&m_u64val;
		}
	case TYPE_TOTEXECTIME:
		{
			m_u64val = 0;
			uint16_t etype = evt->get_type();

			if(etype == PPME_SCHEDSWITCH_1_E || etype == PPME_SCHEDSWITCH_6_E)
			{
				m_u64val = extract_exectime(evt);
			}

			sinsp_threadinfo* tinfo = evt->get_thread_info(false);

			if(tinfo != NULL)
			{
				uint64_t* ptot = (uint64_t*)tinfo->get_private_state(m_th_state_id);
				*ptot += m_u64val;
				return (uint8_t*)ptot;
			}
			else
			{
				return NULL;
			}
		}
	case TYPE_PPID:
		if(tinfo->is_main_thread())
		{
			return (uint8_t*)&tinfo->m_ptid;
		}
		else
		{
			sinsp_threadinfo* mt = tinfo->get_main_thread();

			if(mt != NULL)
			{
				return (uint8_t*)&mt->m_ptid;
			}
			else
			{
				return NULL;
			}
		}
	case TYPE_PNAME:
		{
			sinsp_threadinfo* ptinfo = 
				m_inspector->get_thread(tinfo->m_ptid, false, true);

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
	case TYPE_APID:
		{
			sinsp_threadinfo* mt = NULL;

			if(tinfo->is_main_thread())
			{
				mt = tinfo;
			}
			else
			{
				mt = tinfo->get_main_thread();

				if(mt == NULL)
				{
					return NULL;
				}
			}

			//
			// Search for a specific ancestors
			//
			for(int32_t j = 0; j < m_argid; j++)
			{
				mt = mt->get_parent_thread();

				if(mt == NULL)
				{
					return NULL;
				}
			}

			return (uint8_t*)&mt->m_pid;
		}
	case TYPE_ANAME:
		{
			sinsp_threadinfo* mt = NULL;

			if(tinfo->is_main_thread())
			{
				mt = tinfo;
			}
			else
			{
				mt = tinfo->get_main_thread();

				if(mt == NULL)
				{
					return NULL;
				}
			}

			for(int32_t j = 0; j < m_argid; j++)
			{
				mt = mt->get_parent_thread();

				if(mt == NULL)
				{
					return NULL;
				}
			}

			m_tstr = mt->get_comm();
			return (uint8_t*)m_tstr.c_str();
		}
	case TYPE_LOGINSHELLID:
		{
			sinsp_threadinfo* mt = NULL;
			int64_t* res = NULL;

			if(tinfo->is_main_thread())
			{
				mt = tinfo;
			}
			else
			{
				mt = tinfo->get_main_thread();

				if(mt == NULL)
				{
					return NULL;
				}
			}

			for(; mt != NULL; mt = mt->get_parent_thread())
			{
				size_t len = mt->m_comm.size();

				if(len >= 2 && mt->m_comm[len - 2] == 's' && mt->m_comm[len - 1] == 'h')
				{
					res = &mt->m_pid;
				}
			}

			return (uint8_t*)res;
		}
	case TYPE_DURATION:
		if(tinfo->m_clone_ts != 0)
		{
			m_s64val = evt->get_ts() - tinfo->m_clone_ts;
			ASSERT(m_s64val > 0);
			return (uint8_t*)&m_s64val;
		}
		else
		{
			return NULL;
		}
	case TYPE_IOBYTES:
	case TYPE_TOTIOBYTES:
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

			if(m_field_id == TYPE_IOBYTES)
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
	case TYPE_LATENCY:
		if(tinfo->m_latency != 0)
		{
			return (uint8_t*)&tinfo->m_latency;
		}
		else
		{
			return NULL;
		}
	case TYPE_TOTLATENCY:
		m_u64val += tinfo->m_latency;
		return (uint8_t*)&m_u64val;
	case TYPE_FDOPENCOUNT:
		m_u64val = tinfo->get_fd_opencount();
		return (uint8_t*)&m_u64val;
	case TYPE_FDLIMIT:
		m_s64val = tinfo->get_fd_limit();
		return (uint8_t*)&m_s64val;
	case TYPE_FDUSAGE:
		m_u64val = tinfo->get_fd_usage_pct();
		return (uint8_t*)&m_u64val;
	case TYPE_VMSIZE:
		m_u64val = tinfo->m_vmsize_kb;
		return (uint8_t*)&m_u64val;
	case TYPE_VMRSS:
		m_u64val = tinfo->m_vmrss_kb;
		return (uint8_t*)&m_u64val;
	case TYPE_VMSWAP:
		m_u64val = tinfo->m_vmswap_kb;
		return (uint8_t*)&m_u64val;
	case TYPE_PFMAJOR:
		m_u64val = tinfo->m_pfmajor;
		return (uint8_t*)&m_u64val;
	case TYPE_PFMINOR:
		m_u64val = tinfo->m_pfminor;
		return (uint8_t*)&m_u64val;
	default:
		ASSERT(false);
		return NULL;
	}
}

bool sinsp_filter_check_thread::compare_full_apid(sinsp_evt *evt)
{
	bool res;
	uint32_t j;

	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL)
	{
		return NULL;
	}

	sinsp_threadinfo* mt = NULL;

	if(tinfo->is_main_thread())
	{
		mt = tinfo;
	}
	else
	{
		mt = tinfo->get_main_thread();

		if(mt == NULL)
		{
			return NULL;
		}
	}

	//
	// No id specified, search in all of the ancestors
	//
	for(j = 0; mt != NULL; mt = mt->get_parent_thread(), j++)
	{
		if(j > 0)
		{
			res = flt_compare(m_cmpop,
				PT_PID, 
				&mt->m_pid, 
				&m_val_storage[0]);

			if(res == true)
			{
				return true;
			}
		}
	}

	return false;
}

bool sinsp_filter_check_thread::compare_full_aname(sinsp_evt *evt)
{
	bool res;
	uint32_t j;

	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL)
	{
		return NULL;
	}

	sinsp_threadinfo* mt = NULL;

	if(tinfo->is_main_thread())
	{
		mt = tinfo;
	}
	else
	{
		mt = tinfo->get_main_thread();

		if(mt == NULL)
		{
			return NULL;
		}
	}

	//
	// No id specified, search in all of the ancestors
	//
	for(j = 0; mt != NULL; mt = mt->get_parent_thread(), j++)
	{
		if(j > 0)
		{
			res = flt_compare(m_cmpop,
				PT_CHARBUF, 
				(void*)mt->m_comm.c_str(), 
				&m_val_storage[0]);

			if(res == true)
			{
				return true;
			}
		}
	}

	return false;
}

bool sinsp_filter_check_thread::compare(sinsp_evt *evt)
{
	if(m_field_id == TYPE_APID)
	{
		if(m_argid == -1)
		{
			return compare_full_apid(evt);
		}
	}
	else if(m_field_id == TYPE_ANAME)
	{
		if(m_argid == -1)
		{
			return compare_full_aname(evt);
		}
	}

	return sinsp_filter_check::compare(evt);
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_event implementation
///////////////////////////////////////////////////////////////////////////////
const filtercheck_field_info sinsp_filter_check_event_fields[] =
{
	{PT_UINT64, EPF_NONE, PF_DEC, "evt.num", "event number."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.time", "event timestamp as a time string that includes the nanosecond part."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.time.s", "event timestamp as a time string with no nanoseconds."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.datetime", "event timestamp as a time string that includes the date."},
	{PT_ABSTIME, EPF_NONE, PF_DEC, "evt.rawtime", "absolute event timestamp, i.e. nanoseconds from epoch."},
	{PT_ABSTIME, EPF_NONE, PF_DEC, "evt.rawtime.s", "integer part of the event timestamp (e.g. seconds since epoch)."},
	{PT_ABSTIME, EPF_NONE, PF_10_PADDED_DEC, "evt.rawtime.ns", "fractional part of the absolute event timestamp."},
	{PT_RELTIME, EPF_NONE, PF_10_PADDED_DEC, "evt.reltime", "number of nanoseconds from the beginning of the capture."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "evt.reltime.s", "number of seconds from the beginning of the capture."},
	{PT_RELTIME, EPF_NONE, PF_10_PADDED_DEC, "evt.reltime.ns", "fractional part (in ns) of the time from the beginning of the capture."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "evt.latency", "delta between an exit event and the correspondent enter event."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "evt.latency.s", "integer part of the event latency delta."},
	{PT_RELTIME, EPF_NONE, PF_10_PADDED_DEC, "evt.latency.ns", "fractional part of the event latency delta."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "evt.deltatime", "delta between this event and the previous event."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "evt.deltatime.s", "integer part of the delta between this event and the previous event."},
	{PT_RELTIME, EPF_NONE, PF_10_PADDED_DEC, "evt.deltatime.ns", "fractional part of the delta between this event and the previous event."},
	{PT_CHARBUF, EPF_PRINT_ONLY, PF_NA, "evt.dir", "event direction can be either '>' for enter events or '<' for exit events."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.type", "For system call events, this is the name of the system call (e.g. 'open')."},
	{PT_INT16, EPF_NONE, PF_DEC, "evt.cpu", "number of the CPU where this event happened."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.args", "all the event arguments, aggregated into a single string."},
	{PT_CHARBUF, EPF_REQUIRES_ARGUMENT, PF_NA, "evt.arg", "one of the event arguments specified by name or by number. Some events (e.g. return codes or FDs) will be converted into a text representation when possible. E.g. 'resarg.fd' or 'resarg[0]'."},
	{PT_DYN, EPF_REQUIRES_ARGUMENT, PF_NA, "evt.rawarg", "one of the event arguments specified by name. E.g. 'arg.fd'."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.info", "for most events, this field returns the same value as evt.args. However, for some events (like writes to /dev/log) it provides higher level information coming from decoding the arguments."},
	{PT_BYTEBUF, EPF_NONE, PF_NA, "evt.buffer", "the binary data buffer for events that have one, like read(), recvfrom(), etc. Use this field in filters with 'contains' to search into I/O data buffers."},
	{PT_CHARBUF, EPF_NONE, PF_DEC, "evt.res", "event return value, as an error code string (e.g. 'ENOENT')."},
	{PT_INT64, EPF_NONE, PF_DEC, "evt.rawres", "event return value, as a number (e.g. -2). Useful for range comparisons."},
	{PT_BOOL, EPF_NONE, PF_NA, "evt.failed", "'true' for events that returned an error status."},
	{PT_BOOL, EPF_NONE, PF_NA, "evt.is_io", "'true' for events that read or write to FDs, like read(), send, recvfrom(), etc."},
	{PT_BOOL, EPF_NONE, PF_NA, "evt.is_io_read", "'true' for events that read from FDs, like read(), recv(), recvfrom(), etc."},
	{PT_BOOL, EPF_NONE, PF_NA, "evt.is_io_write", "'true' for events that write to FDs, like write(), send(), etc."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.io_dir", "'r' for events that read from FDs, like read(); 'w' for events that write to FDs, like write()."},
	{PT_BOOL, EPF_NONE, PF_NA, "evt.is_wait", "'true' for events that make the thread wait, e.g. sleep(), select(), poll()."},
	{PT_BOOL, EPF_NONE, PF_NA, "evt.is_syslog", "'true' for events that are writes to /dev/log."},
	{PT_UINT32, EPF_NONE, PF_DEC, "evt.count", "This filter field always returns 1 and can be used to count events from inside chisels."},
	{PT_UINT64, EPF_FILTER_ONLY, PF_DEC, "evt.around", "Accepts the event if it's around the specified time interval. The syntax is evt.around[T]=D, where T is the value returned by %evt.rawtime for the event and D is a delta in milliseconds. For example, evt.around[1404996934793590564]=1000 will return the events with timestamp with one second before the timestamp and one second after it, for a total of two seconds of capture."},
	{PT_CHARBUF, EPF_REQUIRES_ARGUMENT, PF_NA, "evt.abspath", "Absolute path calculated from dirfd and name during (linkat|symlinkat|unlinkat|openat|renameat) syscalls. Use 'evt.abspath.src' or 'evt.abspath.dst' for syscalls that support multiple paths."},
};

sinsp_filter_check_event::sinsp_filter_check_event()
{
	m_first_ts = 0;
	m_is_compare = false;
	m_info.m_name = "evt";
	m_info.m_fields = sinsp_filter_check_event_fields;
	m_info.m_nfiedls = sizeof(sinsp_filter_check_event_fields) / sizeof(sinsp_filter_check_event_fields[0]);
	m_u64val = 0;
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

		parsed_len = (uint32_t)val.find(']');
		string numstr = val.substr(fldname.size() + 1, parsed_len - fldname.size() - 1);

		if(m_field_id == TYPE_AROUND)
		{
			m_u64val = sinsp_numparser::parseu64(numstr);		
		}
		else
		{
			m_argid = sinsp_numparser::parsed32(numstr);
		}

		parsed_len++;
	}
	else if(val[fldname.size()] == '.')
	{
		if(m_field_id == TYPE_AROUND)
		{
			throw sinsp_exception("wrong syntax for evt.around");
		}

		const struct ppm_param_info* pi = 
			sinsp_utils::find_longest_matching_evt_param(val.substr(fldname.size() + 1));

		if(pi == NULL)
		{
			throw sinsp_exception("unknown event argument " + val.substr(fldname.size() + 1));
		}

		m_argname = pi->name;
		parsed_len = (uint32_t)(fldname.size() + strlen(pi->name) + 1);
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
		m_field = &m_customfield;

		int32_t res = extract_arg("evt.rawarg", val, &m_arginfo);

		m_customfield.m_type = m_arginfo->type;

		return res;
	}
	else if(string(val, 0, sizeof("evt.around") - 1) == "evt.around")
	{
		m_field_id = TYPE_AROUND;
		m_field = &m_info.m_fields[m_field_id];

		return extract_arg("evt.around", val, NULL);
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
	else if(string(val, 0, sizeof("evt.abspath") - 1) == "evt.abspath")
	{
		m_field_id = TYPE_ABSPATH;
		m_field = &m_info.m_fields[m_field_id];

		if (val == "evt.abspath") {
			m_argid = 0;
		} else if (val == "evt.abspath.src") {
			m_argid = 1;
		} else if (val == "evt.abspath.dst") {
			m_argid = 2;
		} else {
			throw sinsp_exception("wrong syntax for evt.abspath");
		}

		return val.size() + 1;
	}
	else
	{
		return sinsp_filter_check::parse_field_name(str);
	}
}

void sinsp_filter_check_event::parse_filter_value(const char* str, uint32_t len)
{
	string val(str);

	if(m_field_id == TYPE_ARGRAW)
	{
		//
		// 'rawarg' is handled in a custom way
		//
		ASSERT(m_arginfo != NULL);
		return sinsp_filter_check::string_to_rawval(str, len, m_arginfo->type);
	}
	else if(m_field_id == TYPE_TYPE)
	{
		sinsp_evttables* einfo = m_inspector->get_event_info_tables();
		const struct ppm_event_info* etable = einfo->m_event_info;
		const struct ppm_syscall_desc* stable = einfo->m_syscall_info_table;
		string stype(str, len);

		for(uint32_t j = 0; j < PPM_EVENT_MAX; j++)
		{
			if(stype == etable[j].name)
			{
				return sinsp_filter_check::parse_filter_value(str, len);
			}
		}

		for(uint32_t j = 0; j < PPM_SC_MAX; j++)
		{
			if(stype == stable[j].name)
			{
				return sinsp_filter_check::parse_filter_value(str, len);
			}
		}

		throw sinsp_exception("unknown event type " + stype);
	}
	else if(m_field_id == TYPE_AROUND)
	{
		if(m_cmpop != CO_EQ)
		{
			throw sinsp_exception("evt.around supports only '=' comparison operator");
		}

		sinsp_filter_check::parse_filter_value(str, len);

		m_tsdelta = sinsp_numparser::parseu64(str) * 1000000;

		return;
	}
	else
	{
		return sinsp_filter_check::parse_filter_value(str, len);
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
	int dt, dir;
	struct tm *gmt, *loc;
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

	return dt;
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

uint8_t* extract_argraw(sinsp_evt *evt, OUT uint32_t* len, const char *argname)
{
	const sinsp_evt_param* pi = evt->get_param_value_raw(argname);

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

uint8_t *sinsp_filter_check_event::extract_abspath(sinsp_evt *evt, OUT uint32_t *len)
{
	sinsp_evt_param *parinfo;
	char *path;
	uint32_t pathlen;
	string spath;

	ASSERT(evt->m_tinfo);

	string name = evt->get_name();

	const char *dirfdarg = NULL, *patharg = NULL;
	if (name == "openat") {
		if (m_argid == 0) {
			dirfdarg = "dirfd";
			patharg = "name";
		}
	} else if (name == "renameat") {
		if (m_argid == 1) {
			dirfdarg = "olddirfd";
			patharg = "oldpath";
		} else if (m_argid == 2) {
			dirfdarg = "newdirfd";
			patharg = "newpath";
		}
	} else if (name == "linkat") {
		if (m_argid == 1) {
			dirfdarg = "olddirfd";
			patharg = "oldpath";
		} else if (m_argid == 2) {
			dirfdarg = "newdirfd";
			patharg = "newpath";
		}
	} else if (name == "symlinkat") {
		if (m_argid == 2) {
			dirfdarg = "linkdirfd";
			patharg = "linkpath";
		}
	} else if (name == "unlinkat") {
		if (m_argid == 0) {
			dirfdarg = "dirfd";
			patharg = "name";
		}
	}

	if (!dirfdarg || !patharg) {
		return 0;
	}

	int dirfdargidx = -1, pathargidx = -1, idx = 0;
	while (((dirfdargidx < 0) || (pathargidx < 0)) && (idx < (int) evt->get_num_params())) {
		const char *name = evt->get_param_name(idx);
		if ((dirfdargidx < 0) && (strcmp(name, dirfdarg) == 0)) {
			dirfdargidx = idx;
		}
		if ((pathargidx < 0) && (strcmp(name, patharg) == 0)) {
			pathargidx = idx;
		}
		idx++;
	}

	if ((dirfdargidx < 0) || (pathargidx < 0)) {
		return 0;
	}

	parinfo = evt->get_param(dirfdargidx);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	int64_t dirfd = *(int64_t *)parinfo->m_val;

	parinfo = evt->get_param(pathargidx);
	path = parinfo->m_val;
	pathlen = parinfo->m_len;

	string sdir;

	bool is_absolute = (path[0] == '/');
	if(is_absolute)
	{
		//
		// The path is absoulte.
		// Some processes (e.g. irqbalance) actually do this: they pass an invalid fd and
		// and bsolute path, and openat succeeds.
		//
		sdir = ".";
	}
	else if(dirfd == PPM_AT_FDCWD)
	{
		sdir = evt->m_tinfo->get_cwd();
	}
	else
	{
		evt->m_fdinfo = evt->m_tinfo->get_fd(dirfd);

		if(evt->m_fdinfo == NULL)
		{
			ASSERT(false);
			sdir = "<UNKNOWN>/";
		}
		else
		{
			if(evt->m_fdinfo->m_name[evt->m_fdinfo->m_name.length()] == '/')
			{
				sdir = evt->m_fdinfo->m_name;
			}
			else
			{
				sdir = evt->m_fdinfo->m_name + '/';
			}
		}
	}

	char fullname[SCAP_MAX_PATH_SIZE];
	sinsp_utils::concatenate_paths(fullname, SCAP_MAX_PATH_SIZE, sdir.c_str(), (uint32_t)sdir.length(), path, pathlen);

	m_strstorage = fullname;

	return (uint8_t*)m_strstorage.c_str();
}

Json::Value sinsp_filter_check_event::extract_as_js(sinsp_evt *evt, OUT uint32_t* len)
{
	switch(m_field_id)
	{
	case TYPE_TIME:
	case TYPE_TIME_S:
	case TYPE_DATETIME:
		return (Json::Value::Int64)evt->get_ts();

	case TYPE_RAWTS:
	case TYPE_RAWTS_S:
	case TYPE_RAWTS_NS:
	case TYPE_RELTS:
	case TYPE_RELTS_S:
	case TYPE_RELTS_NS:
	case TYPE_LATENCY:
	case TYPE_LATENCY_S:
	case TYPE_LATENCY_NS:
	case TYPE_DELTA:
	case TYPE_DELTA_S:
	case TYPE_DELTA_NS:
		return (Json::Value::Int64)*(uint64_t*)extract(evt, len);
	case TYPE_COUNT:
		m_u32val = 1;
		return m_u32val;

	default:
		return Json::Value::null;
	}

	return Json::Value::null;
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
				if(evt->m_tinfo->m_prevevent_ts && evt->get_type() == *pt + 1)
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
				if(evt->m_tinfo->m_prevevent_ts && evt->get_type() == *pt + 1)
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
	case TYPE_DELTA:
	case TYPE_DELTA_S:
	case TYPE_DELTA_NS:
		{
			if(m_u64val == 0)
			{
				m_u64val = evt->get_ts();
				m_tsdelta = 0;
			}
			else
			{
				uint64_t tts = evt->get_ts();
				
				if(m_field_id == TYPE_DELTA)
				{
					m_tsdelta = tts - m_u64val;
				}
				else if(m_field_id == TYPE_DELTA_S)
				{
					m_tsdelta = (tts - m_u64val) / ONE_SECOND_IN_NS;
				}
				else if(m_field_id == TYPE_DELTA_NS)
				{
					m_tsdelta = (tts - m_u64val) % ONE_SECOND_IN_NS;
				}

				m_u64val = tts;
			}

			return (uint8_t*)&m_tsdelta;
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
		return extract_argraw(evt, len, m_arginfo->name);
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
	case TYPE_INFO:
		{
			sinsp_fdinfo_t* fdinfo = evt->m_fdinfo;

			if(fdinfo != NULL)
			{
				char* il;
				vector<sinsp_protodecoder*>* cbacks = &(fdinfo->m_write_callbacks);

				vector<sinsp_protodecoder*>::iterator it;
				for(it = cbacks->begin(); it != cbacks->end(); ++it)
				{
					if((*it)->get_info_line(&il))
					{
						return (uint8_t*)il;
					}
				}
			}
		}
		//
		// NOTE: this falls through to TYPE_ARGSTR, and that's what we want!
		//       Please don't add anything here!
		//
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
	case TYPE_BUFFER:
		{
			if(m_is_compare)
			{
				return extract_argraw(evt, len, "data");
			}

			const char* resolved_argstr;
			const char* argstr;
			argstr = evt->get_param_value_str("data", &resolved_argstr, m_inspector->get_buffer_format());
			*len = evt->m_rawbuf_str_len;

			return (uint8_t*)argstr;
		}
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
	case TYPE_FAILED:
		{
			m_u32val = 0;
			const sinsp_evt_param* pi = evt->get_param_value_raw("res");

			if(pi != NULL)
			{
				ASSERT(pi->m_len == sizeof(int64_t));
				if(*(int64_t*)pi->m_val < 0)
				{
					m_u32val = 1;
				}
			}
			else if((evt->get_flags() & EF_CREATES_FD) && PPME_IS_EXIT(evt->get_type()))
			{
				pi = evt->get_param_value_raw("fd");

				if(pi != NULL)
				{
					ASSERT(pi->m_len == sizeof(int64_t));
					if(*(int64_t*)pi->m_val < 0)
					{
						m_u32val = 1;
					}
				}
			}

			return (uint8_t*)&m_u32val;
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
	case TYPE_IODIR:
		{
			ppm_event_flags eflags = evt->get_flags();
			if(eflags & EF_WRITES_TO_FD)
			{
				m_strstorage = "write";
			}
			else if(eflags & EF_READS_FROM_FD)
			{
				m_strstorage = "read";
			}
			else
			{
				return NULL;
			}

			return (uint8_t*)m_strstorage.c_str();
		}
	case TYPE_ISWAIT:
		{
			ppm_event_flags eflags = evt->get_flags();
			if(eflags & (EF_WAITS))
			{
				m_u32val = 1;
			}
			else
			{
				m_u32val = 0;
			}
		}

		return (uint8_t*)&m_u32val;
	case TYPE_ISSYSLOG:
		{
			m_u32val = 0;

			ppm_event_flags eflags = evt->get_flags();
			if(eflags & EF_WRITES_TO_FD)
			{
				sinsp_fdinfo_t* fdinfo = evt->m_fdinfo;

				if(fdinfo != NULL)
				{
					if(fdinfo->m_name.find("/dev/log") != string::npos)
					{
						m_u32val = 1;
					}
				}
			}

			return (uint8_t*)&m_u32val;
		}
	case TYPE_COUNT:
		m_u32val = 1;
		return (uint8_t*)&m_u32val;
	case TYPE_ABSPATH:
		return extract_abspath(evt, len);
	default:
		ASSERT(false);
		return NULL;
	}

	return NULL;
}

bool sinsp_filter_check_event::compare(sinsp_evt *evt)
{
	bool res;

	m_is_compare = true;

	if(m_field_id == TYPE_ARGRAW)
	{
		uint32_t len;
		uint8_t* extracted_val = extract(evt, &len);

		if(extracted_val == NULL)
		{
			return false;
		}

		ASSERT(m_arginfo != NULL);

		res = flt_compare(m_cmpop,
			m_arginfo->type, 
			extracted_val, 
			&m_val_storage[0]);
	}
	else if(m_field_id == TYPE_AROUND)
	{
		uint64_t ts = evt->get_ts();
		uint64_t t1 = ts - m_tsdelta;
		uint64_t t2 = ts + m_tsdelta;

		bool res1 = flt_compare(CO_GE,
			PT_UINT64,
			&m_u64val,
			&t1);

		bool res2 = flt_compare(CO_LE,
			PT_UINT64,
			&m_u64val,
			&t2);

		return res1 && res2;
	}
	else
	{
		res = sinsp_filter_check::compare(evt);
	}

	m_is_compare = false;

	return res;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_user implementation
///////////////////////////////////////////////////////////////////////////////
const filtercheck_field_info sinsp_filter_check_user_fields[] =
{
	{PT_UINT32, EPF_NONE, PF_DEC, "user.uid", "user ID."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "user.name", "user name."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "user.homedir", "home directory of the user."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "user.shell", "user's shell."},
};

sinsp_filter_check_user::sinsp_filter_check_user()
{
	m_info.m_name = "user";
	m_info.m_fields = sinsp_filter_check_user_fields;
	m_info.m_nfiedls = sizeof(sinsp_filter_check_user_fields) / sizeof(sinsp_filter_check_user_fields[0]);
	m_info.m_flags = filter_check_info::FL_WORKS_ON_THREAD_TABLE;
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
		unordered_map<uint32_t, scap_userinfo*>::const_iterator it;

		ASSERT(m_inspector != NULL);
		const unordered_map<uint32_t, scap_userinfo*>* userlist = m_inspector->get_userlist();
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
	m_info.m_flags = filter_check_info::FL_WORKS_ON_THREAD_TABLE;
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
	m_field_id = 0;
	set_text(text);
}

sinsp_filter_check* rawstring_check::allocate_new()
{
	ASSERT(false);
	return NULL;
}

void rawstring_check::set_text(string text)
{
	m_text_len = (uint32_t)text.size();
	m_text = text;
}

int32_t rawstring_check::parse_field_name(const char* str)
{
	ASSERT(false);
	return -1;
}

void rawstring_check::parse_filter_value(const char* str, uint32_t len)
{
	ASSERT(false);
}

uint8_t* rawstring_check::extract(sinsp_evt *evt, OUT uint32_t* len)
{
	*len = m_text_len;
	return (uint8_t*)m_text.c_str();
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_syslog implementation
///////////////////////////////////////////////////////////////////////////////
const filtercheck_field_info sinsp_filter_check_syslog_fields[] =
{
	{PT_CHARBUF, EPF_NONE, PF_NA, "syslog.facility.str", "facility as a string."},
	{PT_UINT32, EPF_NONE, PF_DEC, "syslog.facility", "facility as a number (0-23)."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "syslog.severity.str", "severity as a string. Can have one of these values: emerg, alert, crit, err, warn, notice, info, debug"},
	{PT_UINT32, EPF_NONE, PF_DEC, "syslog.severity", "severity as a number (0-7)."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "syslog.message", "message sent to syslog."},
};

sinsp_filter_check_syslog::sinsp_filter_check_syslog()
{
	m_info.m_name = "syslog";
	m_info.m_fields = sinsp_filter_check_syslog_fields;
	m_info.m_nfiedls = sizeof(sinsp_filter_check_syslog_fields) / sizeof(sinsp_filter_check_syslog_fields[0]);
	m_decoder = NULL;
}

sinsp_filter_check* sinsp_filter_check_syslog::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_syslog();
}

int32_t sinsp_filter_check_syslog::parse_field_name(const char* str)
{
	int32_t res = sinsp_filter_check::parse_field_name(str);
	if(res != -1)
	{
		m_decoder = (sinsp_decoder_syslog*)m_inspector->require_protodecoder("syslog");
	}

	return res;
}

uint8_t* sinsp_filter_check_syslog::extract(sinsp_evt *evt, OUT uint32_t* len)
{
	ASSERT(m_decoder != NULL);
	if(!m_decoder->is_data_valid())
	{
		return NULL;
	}

	switch(m_field_id)
	{
	case TYPE_FACILITY:
		return (uint8_t*)&m_decoder->m_facility;
	case TYPE_FACILITY_STR:
		return (uint8_t*)m_decoder->get_facility_str();
	case TYPE_SEVERITY:
		return (uint8_t*)&m_decoder->m_severity;
	case TYPE_SEVERITY_STR:
		return (uint8_t*)m_decoder->get_severity_str();
	case TYPE_MESSAGE:
		return (uint8_t*)m_decoder->m_msg.c_str();
	default:
		ASSERT(false);
		return NULL;
	}
}

#endif // HAS_FILTERING
