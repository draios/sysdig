/*
Copyright (C) 2013-2014 Draios inc.

This file is part of sysdig.

sysdig is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef PPM_FILLERS_H_
#define PPM_FILLERS_H_

#ifdef __KERNEL__
#include "ppm.h"
#endif

/* This is described in syscall(2). Some syscalls take 64-bit arguments. On
 * arches that have 64-bit registers, these arguments are shipped in a register.
 * On 32-bit arches, however, these are split between two consecutive registers,
 * with some alignment requirements. Some require an odd/even pair while some
 * others require even/odd. For now I assume they all do what x86_32 does, and
 * we can handle the rest when we port those.
 */
#ifdef __KERNEL__
#ifdef CONFIG_64BIT
#define _64BIT_ARGS_SINGLE_REGISTER
#endif /* CONFIG_64BIT */
#else
#ifdef __x86_64__
#define _64BIT_ARGS_SINGLE_REGISTER
#endif /* __x86_64__ */
#endif /* __KERNEL__ */

#define PPM_MS_MGC_MSK 0xffff0000
#define PPM_MS_MGC_VAL 0xC0ED0000

#ifndef __KERNEL__
#define CAPTURE_CONTEXT_SWITCHES
#define CAPTURE_SIGNAL_DELIVERIES
#define CAPTURE_PAGE_FAULTS
#endif

#define BPF_FILLER_ID_f_sys_autofill			0
int f_sys_autofill(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_generic			1
int f_sys_generic(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_empty			2
int f_sys_empty(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_single			3
int f_sys_single(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_single_x			4
int f_sys_single_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_open_x			5
int f_sys_open_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_read_x			6
int f_sys_read_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_write_x			7
int f_sys_write_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_execve_e			8
int f_sys_execve_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_proc_startupdate		9
#define BPF_FILLER_ID_f_proc_startupdate_2		10
#define BPF_FILLER_ID_f_proc_startupdate_3		11
int f_proc_startupdate(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_socketpair_x		12
int f_sys_socketpair_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_connect_x			13
int f_sys_connect_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_accept4_e			14
int f_sys_accept4_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_accept_x			15
int f_sys_accept_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_send_e			16
int f_sys_send_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_send_x			17
int f_sys_send_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_sendto_e			18
int f_sys_sendto_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_sendmsg_e			19
int f_sys_sendmsg_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_sendmsg_x			20
int f_sys_sendmsg_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_recv_x			21
int f_sys_recv_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_recvfrom_x			22
int f_sys_recvfrom_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_recvmsg_x			23
#define BPF_FILLER_ID_f_sys_recvmsg_x_2			24
int f_sys_recvmsg_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_shutdown_e			25
int f_sys_shutdown_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_pipe_x			26
int f_sys_pipe_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_eventfd_e			27
int f_sys_eventfd_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_futex_e			28
int f_sys_futex_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_lseek_e			29
int f_sys_lseek_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_llseek_e			30
int f_sys_llseek_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_socket_bind_x		31
int f_sys_socket_bind_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_poll_e			32
int f_sys_poll_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_poll_x			33
int f_sys_poll_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_openat_e			34
int f_sys_openat_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_pread64_e			35
int f_sys_pread64_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_preadv64_e			36
int f_sys_preadv64_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_writev_e			37
int f_sys_writev_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_pwrite64_e			38
int f_sys_pwrite64_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_readv_preadv_x		39
int f_sys_readv_preadv_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_writev_pwritev_x		40
int f_sys_writev_pwritev_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_pwritev_e			41
int f_sys_pwritev_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_nanosleep_e			42
int f_sys_nanosleep_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_getrlimit_setrlimit_e	43
int f_sys_getrlimit_setrlimit_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_getrlimit_setrlrimit_x	44
int f_sys_getrlimit_setrlrimit_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_prlimit_e			45
int f_sys_prlimit_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_prlimit_x			46
int f_sys_prlimit_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sched_switch_e			47
int f_sched_switch_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sched_drop			48
int f_sched_drop(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_fcntl_e			49
int f_sys_fcntl_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_ptrace_e			50
int f_sys_ptrace_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_ptrace_x			51
int f_sys_ptrace_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_mmap_e			52
int f_sys_mmap_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_brk_munmap_mmap_x		53
int f_sys_brk_munmap_mmap_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_renameat_x			54
int f_sys_renameat_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_symlinkat_x			55
int f_sys_symlinkat_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_procexit_e			56
int f_sys_procexit_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_sendfile_e			57
int f_sys_sendfile_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_sendfile_x			58
int f_sys_sendfile_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_quotactl_e			59
int f_sys_quotactl_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_quotactl_x			60
int f_sys_quotactl_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_sysdigevent_e		61
int f_sys_sysdigevent_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_getresuid_and_gid_x		62
int f_sys_getresuid_and_gid_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_signaldeliver_e		63
int f_sys_signaldeliver_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_pagefault_e			64
int f_sys_pagefault_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_setns_e			65
int f_sys_setns_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_unshare_e			66
int f_sys_unshare_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_flock_e			67
int f_sys_flock_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_cpu_hotplug_e			68
int f_cpu_hotplug_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_semop_x			69
int f_sys_semop_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_semget_e			70
int f_sys_semget_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_semctl_e			71
int f_sys_semctl_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_ppoll_e			72
int f_sys_ppoll_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_mount_e			73
int f_sys_mount_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_access_e			74
int f_sys_access_e(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_socket_x			75
#define f_sys_socket_x f_sys_single_x

#define BPF_FILLER_ID_f_sys_bpf_x			76
int f_sys_bpf_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_unlinkat_x			77
int f_sys_unlinkat_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_f_sys_mkdirat_x			78
int f_sys_mkdirat_x(struct event_filler_arguments *args);

#define BPF_FILLER_ID_terminate_filler			79

#define BPF_FILLER_ID_MAX				80

#endif /* PPM_FILLERS_H_ */
