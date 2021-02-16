/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PERF_COMPAT_H
#define __PERF_COMPAT_H

#include <sys/epoll.h>

struct perf_buffer
{
	perf_buffer_event_fn event_cb;
	perf_buffer_sample_fn sample_cb;
	perf_buffer_lost_fn lost_cb;
	void *ctx; /* passed into callbacks */

	size_t page_size;
	size_t mmap_size;
	struct perf_cpu_buf **cpu_bufs;
	struct epoll_event *events;
	int cpu_cnt;  /* number of allocated CPU buffers */
	int epoll_fd; /* perf event FD */
	int map_fd;   /* BPF_MAP_TYPE_PERF_EVENT_ARRAY BPF map FD */
};

struct perf_cpu_buf
{
	struct perf_buffer *pb;
	void *base; /* mmap()'ed memory */
	void *buf;  /* for reconstructing segmented data */
	size_t buf_size;
	int fd;
	int cpu;
	int map_key;
};

struct perf_sample_raw
{
	struct perf_event_header header;
	uint32_t size;
	char data[];
};

struct perf_sample_lost
{
	struct perf_event_header header;
	uint64_t id;
	uint64_t lost;
	uint64_t sample_id;
};

static enum bpf_perf_event_ret
perf_buffer__process_record(struct perf_event_header *e, void *ctx)
{
	struct perf_cpu_buf *cpu_buf = ctx;
	struct perf_buffer *pb = cpu_buf->pb;
	return pb->event_cb(pb->ctx, cpu_buf->cpu, e);
}

static int perf_buffer__process_records(struct perf_buffer *pb,
					struct perf_cpu_buf *cpu_buf)
{
	enum bpf_perf_event_ret ret;

	ret = bpf_perf_event_read_simple(cpu_buf->base, pb->mmap_size,
					 pb->page_size, &cpu_buf->buf,
					 &cpu_buf->buf_size,
					 perf_buffer__process_record, cpu_buf);
	return ret;
}

int sysdig_perf_buffer__poll(struct perf_buffer *pb, int timeout_ms)
{
	int i, cnt, ret;

	cnt = epoll_wait(pb->epoll_fd, pb->events, pb->cpu_cnt, timeout_ms);
	for(i = 0; i < cnt; i++)
	{
		struct perf_cpu_buf *cpu_buf = pb->events[i].data.ptr;

		ret = perf_buffer__process_records(pb, cpu_buf);
		if(ret != LIBBPF_PERF_EVENT_CONT)
		{
			return ret;
		}
	}
	return LIBBPF_PERF_EVENT_ERROR;
}

#endif // __PERF_COMPAT_H