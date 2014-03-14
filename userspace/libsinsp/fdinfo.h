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

#pragma once

#ifdef _WIN32
#define CANCELED_FD_NUMBER INT64_MAX
#else
#define CANCELED_FD_NUMBER std::numeric_limits<int64_t>::max()
#endif

// fd type characters
#define CHAR_FD_FILE			'f'
#define CHAR_FD_IPV4_SOCK		'4'
#define CHAR_FD_IPV6_SOCK		'6'
#define CHAR_FD_DIRECTORY		'd'
#define CHAR_FD_IPV4_SERVSOCK	'2'
#define CHAR_FD_IPV6_SERVSOCK	'3'
#define CHAR_FD_FIFO			'p'
#define CHAR_FD_UNIX_SOCK		'u'
#define CHAR_FD_EVENT			'e'
#define CHAR_FD_UNKNOWN			'o'
#define CHAR_FD_UNSUPPORTED		'X'
#define CHAR_FD_SIGNAL			's'
#define CHAR_FD_EVENTPOLL		'l'
#define CHAR_FD_INOTIFY			'i'
#define CHAR_FD_TIMERFD			't'

/** @defgroup state State management 
 * A collection of classes to query process and FD state.
 *  @{
 */

typedef union _sinsp_sockinfo
{
	ipv4tuple m_ipv4info; ///< The tuple if this an IPv4 socket.
	ipv6tuple m_ipv6info; ///< The tuple if this an IPv6 socket.
	ipv4serverinfo m_ipv4serverinfo;  ///< Information about an IPv4 server socket.
	ipv6serverinfo m_ipv6serverinfo; ///< Information about an IPv6 server socket.
	unix_tuple m_unixinfo; ///< The tuple if this a unix socket.
}sinsp_sockinfo;

/*!
  \brief File Descriptor information class.
  This class contains the full state for a FD, and a bunch of functions to
  manipulate FDs and retrieve FD information.

  \note As a library user, you won't need to construct thread objects. Rather,
   you get them by calling \ref sinsp_evt::get_fd_info or 
   \ref sinsp_threadinfo::get_fd.
*/template<class T>
class SINSP_PUBLIC sinsp_fdinfo
{
public:
	sinsp_fdinfo();
	string* tostring();

	/*!
	  \brief Return a single ASCII character that identifies the FD type.

	  Refer to the CHAR_FD_* defines in this fdinfo.h.
	*/
	char get_typechar();

	/*!
	  \brief Returns true if this is a unix socket.
	*/
	bool is_unix_socket()
	{
		return m_type == SCAP_FD_UNIX_SOCK;
	}

	/*!
	  \brief Returns true if this is an IPv4 socket.
	*/
	bool is_ipv4_socket()
	{
		return m_type == SCAP_FD_IPV4_SOCK;
	}

	/*!
	  \brief Returns true if this is an IPv4 socket.
	*/
	bool is_ipv6_socket()
	{
		return m_type == SCAP_FD_IPV6_SOCK;
	}

	/*!
	  \brief Returns true if this is a UDP socket.
	*/
	bool is_udp_socket()
	{
		return m_type == SCAP_FD_IPV4_SOCK && m_sockinfo.m_ipv4info.m_fields.m_l4proto == SCAP_L4_UDP;
	}

	/*!
	  \brief Returns true if this is a unix TCP.
	*/
	bool is_tcp_socket()
	{
		return m_type == SCAP_FD_IPV4_SOCK && m_sockinfo.m_ipv4info.m_fields.m_l4proto == SCAP_L4_TCP;
	}

	/*!
	  \brief Returns true if this is a pipe.
	*/
	bool is_pipe()
	{
		return m_type == SCAP_FD_FIFO;
	}

	/*!
	  \brief If this is a socket, returns the IP protocol. Otherwise, return SCAP_FD_UNKNOWN.
	*/
	scap_l4_proto get_l4proto();

	scap_fd_type m_type; ///< The fd type, e.g. file, directory, IPv4 socket...
	uint32_t m_openflags; ///< If this FD is a file, the flags that were used when opening it. See the PPM_O_* definitions in driver/ppm_events_public.h.
	
	/*!
	  \brief Socket-specific state.
	  This is uninitialized for non-socket FDs.
	*/
	sinsp_sockinfo m_sockinfo;

	string m_name; ///< Human readable rendering of this FD. For files, this is the full file name. For sockets, this is the tuple. And so on.

VISIBILITY_PRIVATE

// Doxygen doesn't understand VISIBILITY_PRIVATE
#ifdef _DOXYGEN
private:
#endif

	/*!
	  \brief FD flags.
	*/
	enum flags
	{
		FLAGS_NONE = 0,
		FLAGS_FROM_PROC = (1 << 0),
		FLAGS_TRANSACTION = (1 << 1),
		FLAGS_ROLE_CLIENT = (1 << 2),
		FLAGS_ROLE_SERVER = (1 << 3),
		FLAGS_CLOSE_IN_PROGRESS = (1 << 4),
		FLAGS_CLOSE_CANCELED = (1 << 5),
		// Pipe-specific flags
		FLAGS_IS_SOCKET_PIPE = (1 << 6),
	};

	void add_filename(const char* directory, uint32_t directorylen, const char* filename, uint32_t filenamelen);

	bool is_role_server()
	{
		return (m_flags & FLAGS_ROLE_SERVER) == FLAGS_ROLE_SERVER;
	}

	bool is_role_client()
	{
		return (m_flags & FLAGS_ROLE_CLIENT) == FLAGS_ROLE_CLIENT;
	}

	bool is_role_none()
	{
		return (m_flags & (FLAGS_ROLE_CLIENT | FLAGS_ROLE_SERVER)) == 0;
	}

	bool is_transaction()
	{
		return (m_flags & FLAGS_TRANSACTION) == FLAGS_TRANSACTION; 
	}

	void set_is_transaction()
	{
		m_flags |= FLAGS_TRANSACTION;
	}

	void set_role_server()
	{
		m_flags |= FLAGS_ROLE_SERVER;
	}

	void set_role_client()
	{
		m_flags |= FLAGS_ROLE_CLIENT;
	}

	bool set_net_role_by_guessing(sinsp* inspector, 
		sinsp_threadinfo* ptinfo, 
		sinsp_fdinfo_t* pfdinfo,
		bool incoming);

	void reset_flags()
	{
		m_flags = FLAGS_NONE;
	}

	void set_socketpipe()
	{
		m_flags |= FLAGS_IS_SOCKET_PIPE;
	}

	bool is_socketpipe()
	{
		return (m_flags & FLAGS_IS_SOCKET_PIPE) == FLAGS_IS_SOCKET_PIPE; 
	}

	bool has_no_role()
	{
		return !is_role_client() && !is_role_server();
	}

	T m_usrstate;
	uint32_t m_flags;
	uint64_t m_ino;

	friend class sinsp_parser;
	friend class sinsp_threadinfo;
	friend class sinsp_analyzer;
	friend class thread_analyzer_info;
	friend class sinsp_analyzer_fd_listener;
	friend class sinsp_fdtable;
	friend class sinsp_filter_check_fd;
};

/*@}*/

///////////////////////////////////////////////////////////////////////////////
// fd info table
///////////////////////////////////////////////////////////////////////////////
class sinsp_fdtable
{
public:
	sinsp_fdtable(sinsp* inspector);
	sinsp_fdinfo_t* find(int64_t fd);
	// If the key is already present, overwrite the existing value and return false.
	void add(int64_t fd, sinsp_fdinfo_t* fdinfo);
	// If the key is present, returns true, otherwise returns false.
	void erase(int64_t fd);
	void clear();
	size_t size();
	void reset_cache();

	sinsp* m_inspector;
	unordered_map<int64_t, sinsp_fdinfo_t> m_table;

	//
	// Simple fd cache
	//
	int64_t m_last_accessed_fd;
	sinsp_fdinfo_t *m_last_accessed_fdinfo;
};
