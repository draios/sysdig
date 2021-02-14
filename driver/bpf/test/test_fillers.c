/* SPDX-License-Identifier: GPL-2.0 */

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>


void set_rlimit_infinity(void)
{
	struct rlimit rinf = {RLIM_INFINITY, RLIM_INFINITY};

	setrlimit(RLIMIT_MEMLOCK, &rinf);
}

static void bpf_handle_cb(void *ctx, int cpu, void *data, __u32 size)
{
	fprintf(stdout, "filler call available\n");
}


int main(int argc, char **argv)
{
	struct bpf_program *prog;
	struct bpf_map *map;
	struct bpf_object *obj;
	struct bpf_object_load_attr load_attr = {};


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

	struct bpf_map *perf_map = bpf_object__find_map_by_name(obj, "perf_map");

	bpf_object__for_each_program(prog, obj)
	{
		const char *event_name = bpf_program__name(prog);
		struct bpf_link *link;

		if(!bpf_program__is_raw_tracepoint(prog))
		{
			continue;
		}

		// todo load the right tracepoint for every program, and make sure to deal with the non entry/exit ones
		link = bpf_program__attach_raw_tracepoint(prog, "sys_exit");
		if((unsigned long)link < 0)
		{
			fprintf(stderr, "ERROR: could not attach to the sys_exit raw tracepoint for prog: %s", event_name);
			bpf_link__destroy(link);
			goto cleanup;
		}
	}

	struct perf_buffer_opts pb_opts = {};
	pb_opts.sample_cb = bpf_handle_cb;
	struct perf_buffer *pb;
	pb = perf_buffer__new(bpf_map__fd(perf_map), 8, &pb_opts); // not sure about how many pages to access, check current code

	while ((perf_buffer__poll(pb, -1)) >= 0) {
		// todo(fntlnz): deal with threads and affinity here, also do timeouts
	}

	return EXIT_SUCCESS;
cleanup:
	bpf_object__close(obj);
	return EXIT_FAILURE;
}
