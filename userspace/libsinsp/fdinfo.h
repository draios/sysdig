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

///////////////////////////////////////////////////////////////////////////////
// fd info
///////////////////////////////////////////////////////////////////////////////
template<class T>
class SINSP_PUBLIC sinsp_fdinfo
{
public:
	//
	// fd flags
	//
	enum flags
	{
		FLAGS_NONE = 0,
		FLAGS_FROM_PROC = (1 << 0),		// Set if this FD is arriving from proc
		FLAGS_TRANSACTION = (1 << 1),
		FLAGS_ROLE_CLIENT = (1 << 2),
		FLAGS_ROLE_SERVER = (1 << 3),
		FLAGS_CLOSE_IN_PROGRESS = (1 << 4),
		FLAGS_CLOSE_CANCELED = (1 << 5),
		// Pipe-specific flags
		FLAGS_IS_SOCKET_PIPE = (1 << 6),
	};

	sinsp_fdinfo();
	string* tostring();
	char get_typechar();

	scap_fd_type m_type;
	uint64_t m_create_time;
	uint32_t m_openflags;
	uint32_t m_flags;
	uint64_t m_ino;
	union
	{
		ipv4tuple m_ipv4info;
		ipv6tuple m_ipv6info;
		struct
		{
		  uint32_t m_ip;
		  uint16_t m_port;
		  uint8_t m_l4proto;
		} m_ipv4serverinfo;
		struct
		{
			uint32_t m_ip[4];
			uint16_t m_port;
			uint8_t m_l4proto;
		} m_ipv6serverinfo;
		unix_tuple m_unixinfo;
	}m_info;
	string m_name;

	bool is_unix_socket()
	{
		return m_type == SCAP_FD_UNIX_SOCK;
	}

	bool is_udp_socket()
	{
		return m_type == SCAP_FD_IPV4_SOCK && m_info.m_ipv4info.m_fields.m_l4proto == SCAP_L4_UDP;
	}

	bool is_tcp_socket()
	{
		return m_type == SCAP_FD_IPV4_SOCK && m_info.m_ipv4info.m_fields.m_l4proto == SCAP_L4_TCP;
	}

	bool is_ipv4_socket()
	{
		return m_type == SCAP_FD_IPV4_SOCK;
	}

	bool is_pipe()
	{
		return m_type == SCAP_FD_FIFO;
	}

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
		return m_flags == FLAGS_NONE;
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

	void set_role_by_guessing(bool incoming);

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

	void print_on(FILE* f);

private:
	void add_filename(const char* directory, uint32_t directorylen, const char* filename, uint32_t filenamelen);

	T m_usrstate;

	friend class sinsp_parser;
	friend class sinsp_analyzer;
	friend class thread_analyzer_info;
	friend class sinsp_analyzer_fd_listener;
};

//
// fd operation
//
class sinsp_fdop
{
public:
	sinsp_fdop()
	{
	}

	sinsp_fdop(int64_t fd, uint16_t type)
	{
		m_fd = fd;
		m_type = type;
	}

	int64_t m_fd;
	uint16_t m_type;
};

///////////////////////////////////////////////////////////////////////////////
// fd info table
///////////////////////////////////////////////////////////////////////////////
//typedef fdtable_t::iterator fdtable_iterator_t;

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

	void print_on(FILE* f);

	sinsp* m_inspector;
	unordered_map<int64_t, sinsp_fdinfo_t> m_table;

	//
	// Simple fd cache
	//
	int64_t m_last_accessed_fd;
	sinsp_fdinfo_t *m_last_accessed_fdinfo;
};