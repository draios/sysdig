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

////////////////////////////////////////////////////////////////////////////
// Public definitions for the scap library
////////////////////////////////////////////////////////////////////////////
#pragma once

class sinsp_fd_listener;

class metaevents_state
{
public:
	bool m_new_group;
	uint32_t m_n_additional_events_to_add;
	sinsp_evt m_metaevt;
	scap_evt* m_piscapevt;
	uint32_t m_scap_buf_size;
};

class sinsp_parser
{
public:
	sinsp_parser(sinsp* inspector);
	~sinsp_parser();

	//
	// Processing entry point
	//
	void process_event(sinsp_evt* evt);
	void event_cleanup(sinsp_evt* evt);

	void erase_fd(erase_fd_params* params);

	//
	// Get the enter event matching the last received event
	//
	bool retrieve_enter_event(sinsp_evt* enter_evt, sinsp_evt* exit_evt);

	//
	// Combine the openat arguments into a full file name
	//
	static void parse_openat_dir(sinsp_evt *evt, char* name, int64_t dirfd, OUT string* sdir);

	//
	// Protocol decoder infrastructure methods
	//
	sinsp_protodecoder* add_protodecoder(string decoder_name);
	void register_event_callback(sinsp_pd_callback_type etype, sinsp_protodecoder* dec);

	void schedule_k8s_events(sinsp_evt *evt);
	void schedule_mesos_events(sinsp_evt *evt);

	//
	// Protocol decoders callback lists
	//
	vector<sinsp_protodecoder*> m_open_callbacks;
	vector<sinsp_protodecoder*> m_connect_callbacks;

	//
	// Initializers
	//
	static void init_scapevt(metaevents_state& evt_state, uint16_t evt_type, uint16_t buf_size);

private:
	//
	// Initializers
	//
	void init_metaevt(metaevents_state& evt_state, uint16_t evt_type, uint16_t buf_size);

	//
	// Helpers
	//
	bool reset(sinsp_evt *evt);
	void store_event(sinsp_evt* evt);

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
	void parse_rw_exit(sinsp_evt* evt);
	void parse_sendfile_exit(sinsp_evt* evt);
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
	void parse_fcntl_enter(sinsp_evt* evt);
	void parse_fcntl_exit(sinsp_evt* evt);
	void parse_context_switch(sinsp_evt* evt);
	void parse_brk_munmap_mmap_exit(sinsp_evt* evt);
	void parse_setresuid_exit(sinsp_evt* evt);
	void parse_setresgid_exit(sinsp_evt* evt);
	void parse_setuid_exit(sinsp_evt* evt);
	void parse_setgid_exit(sinsp_evt* evt);
	void parse_container_evt(sinsp_evt* evt); // deprecated, only for backward-compatibility
	void parse_container_json_evt(sinsp_evt *evt);
	inline void parse_tracer(sinsp_evt *evt, int64_t retval);
	void parse_cpu_hotplug_enter(sinsp_evt* evt);
	void parse_k8s_evt(sinsp_evt *evt);
	void parse_chroot_exit(sinsp_evt *evt);
	void parse_mesos_evt(sinsp_evt *evt);

	inline void add_socket(sinsp_evt* evt, int64_t fd, uint32_t domain, uint32_t type, uint32_t protocol);
	inline void add_pipe(sinsp_evt *evt, int64_t tid, int64_t fd, uint64_t ino);
	// Return false if the update didn't happen (for example because the tuple is NULL)
	bool update_fd(sinsp_evt *evt, sinsp_evt_param* parinfo);
	// Return false if the update didn't happen because the tuple is identical to the given address
	bool set_ipv4_addresses_and_ports(sinsp_fdinfo_t* fdinfo, uint8_t* packed_data);
	// Return false if the update didn't happen because the tuple is identical to the given address
	bool set_ipv4_mapped_ipv6_addresses_and_ports(sinsp_fdinfo_t* fdinfo, uint8_t* packed_data);
	// Return false if the update didn't happen because the tuple is identical to the given address
	bool set_unix_info(sinsp_fdinfo_t* fdinfo, uint8_t* packed_data);
	void swap_ipv4_addresses(sinsp_fdinfo_t* fdinfo);
	uint8_t* reserve_event_buffer();
	void free_event_buffer(uint8_t*);

	//
	// Pointers to inspector context
	//
	sinsp* m_inspector;

	//
	// Temporary storage to avoid memory allocation
	//
	sinsp_evt m_tmp_evt;
	uint8_t m_fake_userevt_storage[4096];
	scap_evt* m_fake_userevt;
	string m_tracer_error_string;

	// FD listener callback
	sinsp_fd_listener* m_fd_listener;

	//
	// The protocol decoders allocated by this parser
	//
	vector<sinsp_protodecoder*> m_protodecoders;

	metaevents_state m_k8s_metaevents_state;
	metaevents_state m_mesos_metaevents_state;

	stack<uint8_t*> m_tmp_events_buffer;
	friend class sinsp_analyzer;
	friend class sinsp_analyzer_fd_listener;
	friend class sinsp_protodecoder;
};
