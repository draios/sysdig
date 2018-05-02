#ifndef __MAPS_H
#define __MAPS_H

#define SCRATCH_SIZE (1 << 15)
#define SCRATCH_SIZE_MAX (SCRATCH_SIZE - 1)
#define SCRATCH_SIZE_HALF (SCRATCH_SIZE_MAX >> 1)

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
	unsigned int inner_map_idx;
	unsigned int numa_node;
};

enum sysdig_map_types {
	SYSDIG_PERF_MAP = 0,
	SYSDIG_TAIL_MAP = 1,
	SYSDIG_SYSCALL_CODE_ROUTING_TABLE = 2,
	SYSDIG_SYSCALL_TABLE = 3,
	SYSDIG_EVENT_INFO_TABLE = 4,
	SYSDIG_FILLERS_TABLE = 5,
	SYSDIG_STASH_MAP = 6,
	SYSDIG_FRAME_SCRATCH_MAP = 7,
	SYSDIG_TMP_SCRATCH_MAP = 8,
	SYSDIG_SETTINGS_MAP = 9,
	SYSDIG_LOCAL_STATE_MAP = 10
};

struct sysdig_bpf_settings {
	uint64_t boot_time;
	void *socket_file_ops;
	uint32_t snaplen;
	uint32_t sampling_ratio;
	bool capture_enabled;
	bool do_dynamic_snaplen;
	bool page_faults;
	bool dropping_mode;
	bool is_dropping;
	bool tracers_enabled;
} __attribute__((packed));

struct sysdig_bpf_per_cpu_state {
	long preempt_count;
	unsigned long long n_evts;
	unsigned long long n_drops_buffer;
	unsigned long long n_drops_pf;
	unsigned long long n_context_switches;
} __attribute__((packed));

#ifdef __KERNEL__
#include "types.h"

struct bpf_map_def __bpf_section("maps") perf_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 0,
};

struct bpf_map_def __bpf_section("maps") tail_map = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = BPF_FILLER_ID_MAX,
};

struct bpf_map_def __bpf_section("maps") syscall_code_routing_table = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = SYSCALL_TABLE_SIZE,
};

struct bpf_map_def __bpf_section("maps") syscall_table = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct syscall_evt_pair),
	.max_entries = SYSCALL_TABLE_SIZE,
};

struct bpf_map_def __bpf_section("maps") event_info_table = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct ppm_event_info),
	.max_entries = PPM_EVENT_MAX,
};

struct bpf_map_def __bpf_section("maps") fillers_table = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct ppm_event_entry),
	.max_entries = PPM_EVENT_MAX,
};

struct bpf_map_def __bpf_section("maps") stash_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(struct sys_stash_args),
	.max_entries = 65535,
};

struct bpf_map_def __bpf_section("maps") frame_scratch_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = SCRATCH_SIZE,
	.max_entries = 1,
};

struct bpf_map_def __bpf_section("maps") tmp_scratch_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = SCRATCH_SIZE,
	.max_entries = 1,
};

struct bpf_map_def __bpf_section("maps") settings_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct sysdig_bpf_settings),
	.max_entries = 1,
};

struct bpf_map_def __bpf_section("maps") local_state_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct sysdig_bpf_per_cpu_state),
	.max_entries = 0,
};

#endif /* __KERNEL__ */

#endif
