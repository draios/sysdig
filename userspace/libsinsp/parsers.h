////////////////////////////////////////////////////////////////////////////
// Public definitions for the scap library
////////////////////////////////////////////////////////////////////////////
#pragma once

class sinsp_fd_listener;

class sinsp_parser
{
public:
	sinsp_parser(sinsp* inspector);
	~sinsp_parser();

	//
	// Processing entry point
	//
	void process_event(sinsp_evt* evt);
	void erase_fd(erase_fd_params* params);

private:
	//
	// Helpers
	//
	bool reset(sinsp_evt *evt);
	void store_event(sinsp_evt* evt);
	bool retrieve_enter_event(sinsp_evt* enter_evt, sinsp_evt* exit_evt);

	//
	// Parsers
	//
	void parse_clone_exit(sinsp_evt* evt); 
	void parse_execve_exit(sinsp_evt* evt); 
	void proc_schedule_removal(sinsp_evt* evt);
	void parse_open_openat_creat_exit(sinsp_evt* evt);	
	void parse_pipe_exit(sinsp_evt* evt);
	void parse_socketpair_exit(sinsp_evt* evt);
	void parse_socket_exit(sinsp_evt* evt);	
	void parse_connect_exit(sinsp_evt* evt);
	void parse_accept_exit(sinsp_evt* evt);
	void parse_close_enter(sinsp_evt* evt);
	void parse_close_exit(sinsp_evt* evt);
	void parse_thread_exit(sinsp_evt* evt);
	void parse_rw_enter(sinsp_evt* evt);
	void parse_rw_exit(sinsp_evt* evt);
	void parse_eventfd_exit(sinsp_evt* evt);
	void parse_bind_exit(sinsp_evt* evt);
	void parse_chdir_exit(sinsp_evt* evt);
	void parse_fchdir_exit(sinsp_evt* evt);
	void parse_getcwd_exit(sinsp_evt* evt);
	void parse_shutdown_exit(sinsp_evt* evt);
	void parse_dup_exit(sinsp_evt* evt);
	void parse_signalfd_exit(sinsp_evt* evt);
	void parse_timerfd_create_exit(sinsp_evt* evt);
	void parse_inotify_init_exit(sinsp_evt* evt);
	void parse_getrlimit_setrlimit_exit(sinsp_evt* evt);
	void parse_prlimit_exit(sinsp_evt* evt);
	void parse_select_poll_epollwait_enter(sinsp_evt *evt);

	inline void add_socket(sinsp_evt* evt, int64_t fd, uint32_t domain, uint32_t type, uint32_t protocol);
	inline void add_pipe(sinsp_evt *evt, int64_t tid, int64_t fd, uint64_t ino);
	void update_fd(sinsp_evt *evt, sinsp_evt_param* parinfo);
	void set_ipv4_addresses_and_ports(sinsp_fdinfo_t* fdinfo, uint8_t* packed_data);
	void set_ipv4_mapped_ipv6_addresses_and_ports(sinsp_fdinfo_t* fdinfo, uint8_t* packed_data);
	void set_unix_info(sinsp_fdinfo_t* fdinfo, uint8_t* packed_data);

	//
	// Pointers to inspector context
	//
	sinsp* m_inspector;

	// Temporary storage to avoid memory allocation
	sinsp_evt m_tmp_evt;
	// The transaction table. Key pair is <tid, fd>.
//	unordered_map<pair<int64_t, int64_t>, sinsp_transactinfo> m_transactable;

	sinsp_fd_listener* m_fd_listener;

	friend class sinsp_analyzer;
	friend class sinsp_analyzer_fd_listener;
};
