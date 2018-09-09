#ifndef __COMPAT_MISC_H
#define __COMPAT_MISC_H

#include "bpf.h"

#ifndef __NR_bpf
#ifdef __x86_64__
#define __NR_bpf 321
#else
#define __NR_bpf 357
#endif /* __x86_64__ */
#endif /* __NR_bpf */

#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME 7
#endif

static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

static int sys_perf_event_open(struct perf_event_attr *attr,
			       pid_t pid, int cpu, int group_fd,
			       unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

#endif
