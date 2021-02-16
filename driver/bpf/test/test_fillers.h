#ifndef __TEST_FILLERS_H
#define __TEST_FILLERS_H

#include "ppm_fillers.h"
#include "ppm_events_public.h"
#include "../types.h"

// drivers common external interface for syscall<->ppm interfacing/routing
extern const struct ppm_event_entry g_ppm_events[];
extern const struct syscall_evt_pair g_syscall_table[];
extern const struct ppm_event_info g_event_info[];
extern const enum ppm_syscall_code g_syscall_code_routing_table[];

#define FILLER_NAME_FN(x) #x,
static const char *g_fillers_names[PPM_FILLER_MAX] = {
	FILLER_LIST_MAPPER(FILLER_NAME_FN)};
#undef FILLER_NAME_FN

#define TEST_FILLER_SETUP(x)                                  \
	static __always_inline void test_filler_setup__##x(); \
	static __always_inline void test_filler_setup__##x()

#define TEST_FILLER(x)                                                                                    \
	static __always_inline int test_filler__##x(void *ctx, int cpu, struct perf_event_header *event); \
	static __always_inline int test_filler__##x(void *ctx, int cpu, struct perf_event_header *event)

#define TEST_FILLER_FN(x) \
	test_filler__##x

#define TEST_FILLER_SETUP_FN(x) \
	test_filler_setup__##x

#define TEST_FILLER_MAP_FN(FN) \
	FN(renameat2_example)

#define TEST_FILLER_SYSCALL_GUARD                     \
	void *data = event;                              \
	struct ppm_evt_hdr *evt;                         \
	const struct ppm_event_info *info;               \
	if(event->type == PERF_RECORD_SAMPLE)            \
	{                                                \
		struct perf_sample_raw *s = data;        \
		evt = (struct ppm_evt_hdr *)s->data;     \
		info = &(g_event_info[evt->type]);       \
		if(strcmp(info->name, "renameat2") != 0) \
		{                                        \
			return LIBBPF_PERF_EVENT_CONT;   \
		}                                        \
		if(evt->tid != getpid())                 \
		{                                        \
			return LIBBPF_PERF_EVENT_CONT;   \
		}                                        \
	}                                                \
	else                                             \
	{                                                \
		return LIBBPF_PERF_EVENT_CONT;           \
	}

#endif // _TEST_FILLERS_H