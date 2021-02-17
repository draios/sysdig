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

pid_t g_pid; // todo: make this forked setup pid local to the test instead of global

#ifdef BPF_TEST_DEBUG
#define debug_fprintf fprintf
#else
#define debug_fprintf
#endif

#define FILLER_NAME_FN(x) #x,
static const char *g_fillers_names[PPM_FILLER_MAX] = {
	FILLER_LIST_MAPPER(FILLER_NAME_FN)};
#undef FILLER_NAME_FN

#define TEST_FILLER_GUARD(x)                           \
	void *data = event;                            \
	struct ppm_evt_hdr *evt;                       \
	const struct ppm_event_info *info;             \
	if(event->type == PERF_RECORD_SAMPLE)          \
	{                                              \
		struct perf_sample_raw *s = data;      \
		evt = (struct ppm_evt_hdr *)s->data;   \
		info = &(g_event_info[evt->type]);     \
		if(evt->tid != g_pid)                  \
		{                                      \
			return LIBBPF_PERF_EVENT_CONT; \
		}                                      \
	}                                              \
	else                                           \
	{                                              \
		return LIBBPF_PERF_EVENT_CONT;         \
	}

#define TEST_FILLER_SETUP_GUARD \
	g_pid = fork(); // todo: change the global pid to a locally scoped one

#define STRINGIZE(x) #x

#define TEST_FILLER(test_name, setup, body)                                                                      \
	static __always_inline void test_filler_setup__##test_name(void) { TEST_FILLER_SETUP_GUARD setup }       \
	static __always_inline int test_filler__##test_name(void *ctx, int cpu, struct perf_event_header *event) \
	{                                                                                                        \
		TEST_FILLER_GUARD(test_name)                                                                     \
		const char *current_test_name = STRINGIZE(test_name);                                            \
		body                                                                                             \
	}

#define TEST_FILLER_FN(x) \
	test_filler__##x

#define TEST_FILLER_SETUP_FN(x) \
	test_filler_setup__##x

#define TEST_FILLER_MAP_FN(FN) \
	FN(renameat2_example)

#define GUARD_SYSCALL(x)                          \
	if(strcmp(info->name, STRINGIZE(x)) != 0) \
	{                                         \
		return LIBBPF_PERF_EVENT_CONT;    \
	}

#define GUARD_SYSCALL_EXIT(x)                  \
	GUARD_SYSCALL(x)                       \
	if(!PPME_IS_EXIT(evt->type))           \
	{                                      \
		return LIBBPF_PERF_EVENT_CONT; \
	}

#define GUARD_SYSCALL_ENTER(x)                 \
	GUARD_SYSCALL(x)                       \
	if(!PPME_IS_ENTER(evt->type))          \
	{                                      \
		return LIBBPF_PERF_EVENT_CONT; \
	}

#define ASSERT_TRUE(c)                                                                                   \
	if((c) == false)                                                                                 \
	{                                                                                                \
		fprintf(stderr, "FAILURE: %s assertion failed (%s)\n", current_test_name, STRINGIZE(c)); \
		return LIBBPF_PERF_EVENT_ERROR;                                                          \
	}
#endif // _TEST_FILLERS_H