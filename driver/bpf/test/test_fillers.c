/* SPDX-License-Identifier: GPL-2.0 */

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <linux/perf_event.h>

#include "ppm_fillers.h"
#include "ppm_events_public.h"
#include "../types.h"

#define FILLER_NAME_FN(x) #x,
static const char *g_fillers_names[PPM_FILLER_MAX] = {
	FILLER_LIST_MAPPER(FILLER_NAME_FN)};
#undef FILLER_NAME_FN

// drivers common external interface for syscall<->ppm interfacing/routing
extern const struct ppm_event_entry g_ppm_events[];
extern const struct syscall_evt_pair g_syscall_table[];
extern const struct ppm_event_info g_event_info[];
extern const enum ppm_syscall_code g_syscall_code_routing_table[];

void set_rlimit_infinity(void)
{
	struct rlimit rinf = {RLIM_INFINITY, RLIM_INFINITY};

	setrlimit(RLIMIT_MEMLOCK, &rinf);
}

static void bpf_handle_cb(void *ctx, int cpu, void *data, __u32 size)
{
	struct ppm_evt_hdr *evt = data;
	if(evt->type == PERF_RECORD_SAMPLE)
	{
		fprintf(stdout, "filler sample available %u\n", evt->ts);
		// todo: extract filler arguments from here

	}
}

static int32_t lookup_filler_id(const char *filler_name)
{
	int j;

	for(j = 0; j < sizeof(g_fillers_names) / sizeof(g_fillers_names[0]); ++j)
	{
		if(strcmp(filler_name, g_fillers_names[j]) == 0)
		{
			return j;
		}
	}

	return -1;
}

int main(int argc, char **argv)
{
	struct bpf_program *prog;
	struct bpf_map *map;
	struct bpf_object *obj;
	struct bpf_object_load_attr load_attr = {};
	struct bpf_map *perf_map;
	struct bpf_map *tail_map;
	struct bpf_map *fillers_table_map;
	struct bpf_map *settings_map;
	struct bpf_map *event_table_map;
	struct bpf_map *syscall_code_routing_table;
	struct bpf_map *syscall_table;
	char probe_path[256];

	snprintf(probe_path, sizeof(probe_path), "%s", argv[1]);

	obj = bpf_object__open(probe_path);
	load_attr.obj = obj;

	if(libbpf_get_error(obj))
	{
		fprintf(stderr, "error opening the bpf object\n");
		return EXIT_FAILURE;
	}
	uint32_t n_cpu = sysconf(_SC_NPROCESSORS_CONF);

	set_rlimit_infinity();

	bpf_object__for_each_map(map, obj)
	{
		const char *map_name = bpf_map__name(map);
		if(strcmp(map_name, "frame_scratch_map") == 0 ||
		   strcmp(map_name, "local_state_map") == 0 ||
		   strcmp(map_name, "perf_map") == 0 ||
		   strcmp(map_name, "tmp_scratch_map") == 0)
		{
			bpf_map__set_max_entries(map, n_cpu);
		}
		fprintf(stdout, "map found: %s\n", bpf_map__name(map));
	}

	if(bpf_object__load_xattr(&load_attr))
	{
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	perf_map = bpf_object__find_map_by_name(obj, "perf_map");
	tail_map = bpf_object__find_map_by_name(obj, "tail_map");
	fillers_table_map = bpf_object__find_map_by_name(obj, "fillers_table");
	settings_map = bpf_object__find_map_by_name(obj, "settings_map");
	event_table_map = bpf_object__find_map_by_name(obj, "event_info_table");
	syscall_code_routing_table = bpf_object__find_map_by_name(obj, "syscall_code_routing_table");
	syscall_table = bpf_object__find_map_by_name(obj, "syscall_table");

	// load raw tracepoints and fillers
	bpf_object__for_each_program(prog, obj)
	{
		const char *event_name = bpf_program__name(prog);
		const char *shname = bpf_program__section_name(prog);
		int program_fd = bpf_program__fd(prog);

		fprintf(stdout, "program: %s\n", shname);
		struct bpf_link *link;

		if(!bpf_program__is_raw_tracepoint(prog))
		{
			continue;
		}

		// if the program is a filler, update the tail call map
		if(memcmp(shname, "raw_tracepoint/filler/", sizeof("raw_tracepoint/filler/") - 1) == 0)
		{
			shname += sizeof("raw_tracepoint/filler/") - 1;
			int32_t filler_id = lookup_filler_id(shname);
			if(filler_id == -1)
			{
				fprintf(stderr, "ERROR: unable to determine filler for program: %s", shname);
				goto cleanup;
			}

			int err = bpf_map_update_elem(bpf_map__fd(tail_map), &filler_id, &program_fd, BPF_ANY);
			if(err != 0)
			{
				fprintf(stderr, "ERROR could not update tail map array\n");
				goto cleanup;
			}

			continue;
		}

		// load all the main raw tracepoints so that the fillers are called
		shname += sizeof("raw_tracepoint/") - 1;
		link = bpf_program__attach_raw_tracepoint(prog, shname);
		if((unsigned long)link < 0)
		{
			fprintf(stderr, "ERROR: could not attach to the sys_exit raw tracepoint for prog: %s", event_name);
			bpf_link__destroy(link);
			goto cleanup;
		}
	}

	// update the fillers table map
	for(int j = 0; j < PPM_EVENT_MAX; ++j)
	{
		const struct ppm_event_entry *e = &g_ppm_events[j];
		int err = bpf_map_update_elem(bpf_map__fd(fillers_table_map), &j, e, BPF_ANY);
		if(err != 0)
		{
			fprintf(stderr, "ERROR could not update fillers table map\n");
			goto cleanup;
		}
	}

	// update the event table map
	for(int j = 0; j < PPM_EVENT_MAX; ++j)
	{
		const struct ppm_event_info *e = &g_event_info[j];
		int err = bpf_map_update_elem(bpf_map__fd(event_table_map), &j, e, BPF_ANY);
		if(err != 0)
		{
			fprintf(stderr, "ERROR could not update event table map\n");
			goto cleanup;
		}
	}

	// setup code routing table
	for(int j = 0; j < SYSCALL_TABLE_SIZE; ++j)
	{
		long code = g_syscall_code_routing_table[j];
		int err = bpf_map_update_elem(bpf_map__fd(syscall_code_routing_table), &j, &code, BPF_ANY);
		if(err != 0)
		{
			fprintf(stderr, "ERROR could not update syscall_code_routing_table map\n");
			goto cleanup;
		}
	}

	// setup syscall table
	for(int j = 0; j < SYSCALL_TABLE_SIZE; ++j)
	{
		const struct syscall_evt_pair *p = &g_syscall_table[j];
		int err = bpf_map_update_elem(bpf_map__fd(syscall_table), &j, p, BPF_ANY);
		if(err != 0)
		{
			fprintf(stderr, "ERROR could not update syscall table map\n");
			goto cleanup;
		}
	}

	// update settings
	struct sysdig_bpf_settings settings;
	int key = 0;
	if(bpf_map_lookup_elem(bpf_map__fd(settings_map), &key, &settings) != 0)
	{
		fprintf(stderr, "ERROR could not retrieve the settings map\n");
		goto cleanup;
	}
	settings.capture_enabled = true;

	if(bpf_map_update_elem(bpf_map__fd(settings_map), &key, &settings, BPF_ANY) != 0)
	{
		fprintf(stderr, "ERROR could not update the settings map\n");
		goto cleanup;
	}

	// create and read the perf buffer
	struct perf_buffer_opts pb_opts = {};
	pb_opts.sample_cb = bpf_handle_cb;
	struct perf_buffer *pb;

	// todo(fntlnz): not sure about how many pages to access, check current code
	pb = perf_buffer__new(bpf_map__fd(perf_map), 8, &pb_opts);
	// todo(fntlnz): deal with threads and affinity here, also do timeouts
	while((perf_buffer__poll(pb, -1)) >= 0)
	{
	}

	return EXIT_SUCCESS;
cleanup:
	bpf_object__close(obj);
	return EXIT_FAILURE;
}
