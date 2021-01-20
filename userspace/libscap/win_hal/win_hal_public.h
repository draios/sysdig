#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

//
// This MUST be smaller of equal than SCAP_LASTERR_SIZE, or bad things will happen
//
#define WH_LASTERR_SIZE 256

#define WH_SUCCESS 0
#define WH_FAILURE 1

#define WH_MAX_PATH_SIZE 1024
#define WH_MAX_ARGS_SIZE 4096
#define WH_MAX_ENV_SIZE 4096
#define WH_MAX_CGROUPS_SIZE 4096

typedef struct wh_t wh_t;

///////////////////////////////////////////////////////////////////////////////
// This section is consumable by C and C++ programs
///////////////////////////////////////////////////////////////////////////////
//
// Process information
//
typedef struct wh_procinfo
{
	uint64_t tid; ///< The thread/task id.
	uint64_t pid; ///< The id of the process containing this thread. In single thread processes, this is equal to tid.
	uint64_t ptid; ///< The id of the thread that created this thread.
	uint32_t sid; ///< The session id of the process containing this thread.
	char comm[WH_MAX_PATH_SIZE+1]; ///< Command name (e.g. "top")
	char exe[WH_MAX_PATH_SIZE+1]; ///< argv[0] (e.g. "sshd: user@pts/4")
	char exepath[WH_MAX_PATH_SIZE+1]; ///< full executable path
	char args[WH_MAX_ARGS_SIZE+1]; ///< Command line arguments (e.g. "-d1")
	uint16_t args_len; ///< Command line arguments length
	uint32_t vmsize_kb; ///< total virtual memory (as kb)
	uint64_t pfmajor; ///< number of major page faults since start
	uint64_t pfminor; ///< number of minor page faults since start
	uint64_t clone_ts;
	int32_t tty;
}wh_procinfo;

typedef struct wh_proclist
{
	int m_result; // nonzero if success
	uint32_t m_count;
	wh_procinfo* m_procs;
}wh_proclist;

typedef struct wh_proc_perf_info
{
	int m_result; // nonzero if success
	double m_cpu_percent;
	uint64_t m_memory_bytes;
	uint32_t m_swap_bytes;
}wh_proc_perf_info;

//
// File descriptor information
//
typedef enum wh_fd_type
{
	WH_FD_UNINITIALIZED = -1,
	WH_FD_UNKNOWN = 0,
	WH_FD_FILE = 1,
	WH_FD_DIRECTORY = 2,
	WH_FD_IPV4_SOCK = 3,
	WH_FD_IPV6_SOCK = 4,
	WH_FD_IPV4_SERVSOCK = 5,
	WH_FD_IPV6_SERVSOCK = 6,
}wh_fd_type;

typedef enum wh_l4_proto
{
	WH_L4_UNKNOWN = 0, ///< unknown protocol, likely caused by some parsing problem
	WH_L4_NA = 1, ///< protocol not available, because the fd is not a socket
	WH_L4_TCP = 2,
	WH_L4_UDP = 3,
	WH_L4_ICMP = 4,
	WH_L4_RAW = 5, ///< Raw socket
}wh_l4_proto;

typedef struct wh_fdinfo
{
	int64_t fd; ///< The FD number, which uniquely identifies this file descriptor.
	wh_fd_type type; ///< This file descriptor's type.
	union
	{
		struct
		{
		  uint32_t sip; ///< Source IP
		  uint32_t dip; ///< Destination IP
		  uint16_t sport; ///< Source port
		  uint16_t dport; ///< Destination port
		  uint8_t l4proto; ///< Transport protocol. See \ref scap_l4_proto.
		} ipv4info; ///< Information specific to IPv4 sockets
		struct
		{
			uint32_t sip[4]; ///< Source IP
			uint32_t dip[4]; ///< Destination IP
			uint16_t sport; ///< Source Port
			uint16_t dport; ///< Destination Port
			uint8_t l4proto; ///< Transport protocol. See \ref scap_l4_proto.
		} ipv6info; ///< Information specific to IPv6 sockets
		struct
		{
		  uint32_t ip; ///< Local IP
		  uint16_t port; ///< Local Port
		  uint8_t l4proto; ///< Transport protocol. See \ref scap_l4_proto.
		} ipv4serverinfo; ///< Information specific to IPv4 server sockets, e.g. sockets used for bind().
		struct
		{
			uint32_t ip[4]; ///< Local IP
			uint16_t port; ///< Local Port
			uint8_t l4proto; ///< Transport protocol. See \ref scap_l4_proto.
		} ipv6serverinfo; ///< Information specific to IPv6 server sockets, e.g. sockets used for bind().
		char fname[WH_MAX_PATH_SIZE];  ///< The name for file system FDs
	}info;
}wh_fdinfo;

typedef struct wh_fdlist
{
	int m_result; // nonzero if success
	uint32_t m_count;
	wh_fdinfo* m_fds;
}wh_fdlist;

typedef struct wh_tidlist
{
	int m_result; // nonzero if success
	uint32_t m_count;
	uint32_t* m_tids;
}wh_tidlist;

__declspec(dllexport) char* wh_getlasterror(wh_t* handle);
__declspec(dllexport) wh_t* wh_open(char* error);
__declspec(dllexport) void wh_close(wh_t* handle);
__declspec(dllexport) wh_proclist wh_wmi_get_procs(wh_t* handle);
// no 'bool' in vanilla C, so the next two functions return an int-ized bool 
__declspec(dllexport) int wh_is_docker_present(wh_t* handle);
__declspec(dllexport) int wh_docker_refresh(wh_t* handle);
__declspec(dllexport) int wh_wmi_update_procs_perf(wh_t* handle);
__declspec(dllexport) wh_proc_perf_info wh_wmi_get_proc_perf_info(wh_t* handle, uint64_t pid);
__declspec(dllexport) void wh_free_fd_list(wh_t* handle);
__declspec(dllexport) wh_fdlist wh_get_pid_fds(wh_t* handle, uint64_t pid);
__declspec(dllexport) bool wh_create_tid_list(wh_t* handle);
__declspec(dllexport) void wh_free_tid_list(wh_t* handle);
__declspec(dllexport) wh_tidlist wh_get_pid_tids(wh_t* handle, uint64_t pid);

#ifndef DRAGENT_WIN_HAL_C_ONLY
using namespace std;

//
// Mounted file systems info
//
typedef struct wh_mounted_fs_info
{
	char device[WH_MAX_PATH_SIZE+1];
	char mount_dir[WH_MAX_PATH_SIZE+1];
	char type[WH_MAX_PATH_SIZE+1];
	uint64_t size_bytes;
	uint64_t used_bytes;
	uint64_t available_bytes;
}wh_mounted_fs_info;

typedef struct wh_mountlist
{
	int m_result; // nonzero if success
	uint32_t m_count;
	wh_mounted_fs_info* m_mounts;
}wh_mountlist;

//
// Network interfaces info
//
typedef struct wh_interface_info
{
	char name[WH_MAX_PATH_SIZE+1];
	uint64_t m_bytes_in;
	uint64_t m_bytes_out;
}wh_interface_info;

typedef struct wh_interfacelist
{
	int m_result; // nonzero if success
	uint32_t m_count;
	wh_interface_info* m_interfaces;
}wh_interfacelist;

typedef struct wh_machine_bandwidth_info
{
	int m_result; // nonzero if success
	uint64_t m_bytes_in;
	uint64_t m_bytes_out;
}wh_machine_bandwidth_info;

typedef struct wh_machine_disk_bandwidth_info
{
	int m_result; // nonzero if success
	uint64_t m_bytes_in;
	uint64_t m_bytes_out;
	uint64_t m_count_in;
	uint64_t m_count_out;
}wh_machine_disk_bandwidth_info;

//
// CPUs info
//
typedef struct wh_cpu_info
{
	double load;
	double user;
	double system;
	double idle;
	double irq;
	double softirq; // dpc
}wh_cpu_info;

typedef struct wh_cpulist
{
	int m_result; // nonzero if success
	uint32_t m_count;
	wh_cpu_info* m_cpus;
}wh_cpulist;


typedef struct wh_os_times
{
	int m_result; // nonzero if success
	uint64_t m_boot_time_s_unix;
	uint64_t m_uptime_s_unix;
}wh_os_times;

//
// Memory information
//
typedef struct wh_meminfo
{
	int m_result; // nonzero if success
	uint64_t m_used_kb;
	uint64_t m_free_kb;
	uint64_t total_swap_kb;
	uint64_t avail_swap_kb;
	uint64_t used_swap_kb;
}wh_meminfo;

//
// Containers information
//
typedef struct wh_docker_container_info
{
	bool m_res;
	const char* m_container_id;
	const char* m_container_name;
}wh_docker_container_info;

typedef struct wh_docker_io_bytes
{
    int m_result; // nonzero if success
    uint64_t m_net_bytes_in;
    uint64_t m_net_bytes_out;
    uint64_t m_file_bytes_in;
    uint64_t m_file_bytes_out;
}wh_docker_io_bytes;

//
// Public API
//
__declspec(dllexport) wh_mountlist wh_wmi_get_mounts(wh_t* handle);
__declspec(dllexport) wh_interfacelist wh_wmi_get_net_interfaces(wh_t* handle);
__declspec(dllexport) wh_machine_bandwidth_info wh_wmi_get_machine_net_totbytes(wh_t* handle);
__declspec(dllexport) wh_machine_disk_bandwidth_info wh_wmi_get_machine_disk_bandwidth(wh_t* handle);
__declspec(dllexport) wh_cpulist wh_wmi_get_cpus(wh_t* handle);
__declspec(dllexport) wh_os_times wh_wmi_get_os_times(wh_t* handle);
__declspec(dllexport) wh_meminfo wh_wmi_get_meminfo(wh_t* handle);
__declspec(dllexport) wh_docker_container_info wh_docker_resolve_pid(wh_t* handle, uint64_t pid);
__declspec(dllexport) bool wh_query_docker(wh_t* handle, char* query, const char** response);
__declspec(dllexport) wh_docker_io_bytes wh_docker_get_io_bytes(wh_t* handle, const char* container_id);
__declspec(dllexport) int wh_create_fd_list(wh_t* handle);

bool init_os_times(wh_t* handle);

#endif // DRAGENT_WIN_HAL_C_ONLY

#ifdef __cplusplus
} // extern "C"
#endif
