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

#define TEST_FILLER(x)                                                                            \
	static __always_inline void test_filler__##x(void *ctx, int cpu, void *data, __u32 size); \
	static __always_inline void test_filler__##x(void *ctx, int cpu, void *data, __u32 size)

#define TEST_FILLER_FN(x) \
	test_filler__##x

#define TEST_FILLER_CALL(x) \
	TEST_FILLER_FN(x)

#define TEST_FILLER_MAP_FN(FN) \
	FN(renameat2_example)

#endif // _TEST_FILLERS_H