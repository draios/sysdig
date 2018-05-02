#ifndef __TYPES_H
#define __TYPES_H

#define __bpf_section(NAME) __attribute__((section(NAME), used))

#define __always_inline inline __attribute__((always_inline))

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
#error Kernel version must be >= 4.12 with eBPF enabled
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
#define BPF_FORBIDS_ZERO_ACCESS
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#define BPF_FORBIDS_BIG_PROGRAMS
#endif

struct sys_enter_args {
	__u64 pad;
	long id;
	unsigned long args[6];
};

struct sys_exit_args {
	__u64 pad;
	long id;
	long ret;
};

struct sched_process_exit_args {
	__u64 pad;
	char comm[16];
	pid_t pid;
	int prio;
};

struct sched_switch_args {
	__u64 pad;
	char prev_comm[TASK_COMM_LEN];
	pid_t prev_pid;
	int prev_prio;
	long prev_state;
	char next_comm[TASK_COMM_LEN];
	pid_t next_pid;
	int next_prio;
};

struct sched_process_fork_args {
	__u64 pad;
	char parent_comm[TASK_COMM_LEN];
	pid_t parent_pid;
	char child_comm[TASK_COMM_LEN];
	pid_t child_pid;
};

struct page_fault_args {
	__u64 pad;
	unsigned long address;
	unsigned long ip;
	unsigned long error_code;
};

struct signal_deliver_args {
	__u64 pad;
	int sig;
	int errno;
	int code;
	unsigned long sa_handler;
	unsigned long sa_flags;
};

struct syscall_filler_data {
	long syscall_id;
	long ret;
};

struct sched_switch_filler_data {
	pid_t next_pid;
};

struct page_fault_filler_data {
	unsigned long address;
	unsigned long ip;
	unsigned long error_code;
};

struct signal_filler_data {
	int sig;
};

union event_filler_data {
	struct syscall_filler_data syscall_data;
	struct sched_switch_filler_data sched_switch_data;
	struct page_fault_filler_data page_fault_data;
	struct signal_filler_data signal_data;
};

/* Can't put any pointer here */
struct tail_context {
	enum ppm_event_type evt_type;
	unsigned long long ts;
	union event_filler_data event_data;
};

struct filler_data {
	struct tail_context tail_ctx;
	struct sysdig_bpf_settings *settings;
	char *tmp_scratch;
	bool tmp_scratch_in_use;
	const struct ppm_event_info *evt;
	const struct ppm_event_entry *filler_info;
	unsigned long curarg;
	bool curarg_already_on_frame;
	char *buf;
	unsigned long curoff;
	unsigned long len;
	unsigned long *args;
	int fd;
};

struct sys_stash_args {
	unsigned long args[6];
};

#endif
