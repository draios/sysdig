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

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/compat.h>
#include <linux/cdev.h>
#include <asm/syscall.h>
#include <asm/unistd.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/file.h>
#include <linux/futex.h>
#include <linux/fs_struct.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/quota.h>
#include <linux/cgroup.h>
#include <asm/mman.h>

#include "ppm_ringbuffer.h"
#include "ppm_events_public.h"
#include "ppm_events.h"
#include "ppm.h"

/* This is described in syscall(2). Some syscalls take 64-bit arguments. On
 * arches that have 64-bit registers, these arguments are shipped in a register.
 * On 32-bit arches, however, these are split between two consecutive registers,
 * with some alignment requirements. Some require an odd/even pair while some
 * others require even/odd. For now I assume they all do what x86_32 does, and
 * we can handle the rest when we port those.
 */
#ifdef CONFIG_64BIT
#define _64BIT_ARGS_SINGLE_REGISTER
#endif

static int f_sys_generic(struct event_filler_arguments *args);	/* generic syscall event filler that includes the system call number */
static int f_sys_empty(struct event_filler_arguments *args);		/* empty filler */
static int f_sys_single(struct event_filler_arguments *args);		/* generic enter filler that copies a single argument syscall into a single parameter event */
static int f_sys_single_x(struct event_filler_arguments *args);		/* generic exit filler that captures an integer */
static int f_sys_open_x(struct event_filler_arguments *args);
static int f_sys_read_x(struct event_filler_arguments *args);
static int f_sys_write_x(struct event_filler_arguments *args);
static int f_proc_startupdate(struct event_filler_arguments *args);
static int f_sys_socketpair_x(struct event_filler_arguments *args);
static int f_sys_connect_x(struct event_filler_arguments *args);
static int f_sys_accept4_e(struct event_filler_arguments *args);
static int f_sys_accept_x(struct event_filler_arguments *args);
static int f_sys_send_e(struct event_filler_arguments *args);
static int f_sys_send_x(struct event_filler_arguments *args);
static int f_sys_sendto_e(struct event_filler_arguments *args);
static int f_sys_sendmsg_e(struct event_filler_arguments *args);
static int f_sys_sendmsg_x(struct event_filler_arguments *args);
static int f_sys_recv_e(struct event_filler_arguments *args);
static int f_sys_recv_x(struct event_filler_arguments *args);
static int f_sys_recvfrom_e(struct event_filler_arguments *args);
static int f_sys_recvfrom_x(struct event_filler_arguments *args);
static int f_sys_recvmsg_e(struct event_filler_arguments *args);
static int f_sys_recvmsg_x(struct event_filler_arguments *args);
static int f_sys_shutdown_e(struct event_filler_arguments *args);
static int f_sys_pipe_x(struct event_filler_arguments *args);
static int f_sys_eventfd_e(struct event_filler_arguments *args);
static int f_sys_futex_e(struct event_filler_arguments *args);
static int f_sys_lseek_e(struct event_filler_arguments *args);
static int f_sys_llseek_e(struct event_filler_arguments *args);
static int f_sys_socket_bind_x(struct event_filler_arguments *args);
static int f_sys_poll_e(struct event_filler_arguments *args);
static int f_sys_poll_x(struct event_filler_arguments *args);
static int f_sys_openat_e(struct event_filler_arguments *args);
#ifndef _64BIT_ARGS_SINGLE_REGISTER
static int f_sys_pread64_e(struct event_filler_arguments *args);
static int f_sys_preadv_e(struct event_filler_arguments *args);
#endif
static int f_sys_writev_e(struct event_filler_arguments *args);
static int f_sys_pwrite64_e(struct event_filler_arguments *args);
static int f_sys_readv_x(struct event_filler_arguments *args);
static int f_sys_writev_e(struct event_filler_arguments *args);
static int f_sys_writev_pwritev_x(struct event_filler_arguments *args);
static int f_sys_preadv_x(struct event_filler_arguments *args);
static int f_sys_pwritev_e(struct event_filler_arguments *args);
static int f_sys_nanosleep_e(struct event_filler_arguments *args);
static int f_sys_getrlimit_setrlimit_e(struct event_filler_arguments *args);
static int f_sys_getrlimit_setrlrimit_x(struct event_filler_arguments *args);
static int f_sys_prlimit_e(struct event_filler_arguments *args);
static int f_sys_prlimit_x(struct event_filler_arguments *args);
#ifdef CAPTURE_CONTEXT_SWITCHES
static int f_sched_switch_e(struct event_filler_arguments *args);
#endif
static int f_sched_drop(struct event_filler_arguments *args);
static int f_sched_fcntl_e(struct event_filler_arguments *args);
static int f_sys_ptrace_e(struct event_filler_arguments *args);
static int f_sys_ptrace_x(struct event_filler_arguments *args);
static int f_sys_mmap_e(struct event_filler_arguments *args);
static int f_sys_brk_munmap_mmap_x(struct event_filler_arguments *args);
static int f_sys_renameat_x(struct event_filler_arguments *args);
static int f_sys_symlinkat_x(struct event_filler_arguments *args);
static int f_sys_procexit_e(struct event_filler_arguments *args);
static int f_sys_sendfile_e(struct event_filler_arguments *args);
static int f_sys_sendfile_x(struct event_filler_arguments *args);
static int f_sys_quotactl_e(struct event_filler_arguments *args);
static int f_sys_quotactl_x(struct event_filler_arguments *args);
static int f_sys_sysdigevent_e(struct event_filler_arguments *args);
static int f_sys_getresuid_and_gid_x(struct event_filler_arguments *args);
#ifdef CAPTURE_SIGNAL_DELIVERIES
static int f_sys_signaldeliver_e(struct event_filler_arguments *args);
#endif

/*
 * Note, this is not part of g_event_info because we want to share g_event_info with userland.
 * However, separating this information in a different struct is not ideal and we should find a better way.
 */
const struct ppm_event_entry g_ppm_events[PPM_EVENT_MAX] = {
	[PPME_GENERIC_E] = {f_sys_generic},
	[PPME_GENERIC_X] = {f_sys_generic},
	[PPME_SYSCALL_OPEN_E] = {f_sys_empty},
	[PPME_SYSCALL_OPEN_X] = {f_sys_open_x},
	[PPME_SYSCALL_CREAT_E] = {f_sys_empty},
	[PPME_SYSCALL_CREAT_X] = {PPM_AUTOFILL, 3, APT_REG, {{AF_ID_RETVAL}, {0}, {AF_ID_USEDEFAULT, 0} } },
	[PPME_SYSCALL_CLOSE_E] = {f_sys_single},
	[PPME_SYSCALL_CLOSE_X] = {f_sys_single_x},
	[PPME_SYSCALL_READ_E] = {PPM_AUTOFILL, 2, APT_REG, {{0}, {2} } },
	[PPME_SYSCALL_READ_X] = {f_sys_read_x},
	[PPME_SYSCALL_WRITE_E] = {PPM_AUTOFILL, 2, APT_REG, {{0}, {2} } },
	[PPME_SYSCALL_WRITE_X] = {f_sys_write_x},
	[PPME_PROCEXIT_1_E] = {f_sys_procexit_e},
	[PPME_SOCKET_SOCKET_E] = {PPM_AUTOFILL, 3, APT_SOCK, {{0}, {1}, {2} } },
	[PPME_SOCKET_SOCKET_X] = {f_sys_single_x},
	[PPME_SOCKET_SOCKETPAIR_E] = {PPM_AUTOFILL, 3, APT_SOCK, {{0}, {1}, {2} } },
	[PPME_SOCKET_SOCKETPAIR_X] = {f_sys_socketpair_x},
	[PPME_SOCKET_BIND_E] = {PPM_AUTOFILL, 1, APT_SOCK, {{0} } },
	[PPME_SOCKET_BIND_X] = {f_sys_socket_bind_x},
	[PPME_SOCKET_CONNECT_E] = {PPM_AUTOFILL, 1, APT_SOCK, {{0} } },
	[PPME_SOCKET_CONNECT_X] = {f_sys_connect_x},
	[PPME_SOCKET_LISTEN_E] = {PPM_AUTOFILL, 2, APT_SOCK, {{0}, {1} } },
	[PPME_SOCKET_LISTEN_X] = {f_sys_single_x},
	[PPME_SOCKET_ACCEPT_E] = {f_sys_empty},
	[PPME_SOCKET_ACCEPT_X] = {f_sys_accept_x},
	[PPME_SOCKET_ACCEPT4_E] = {f_sys_accept4_e},
	[PPME_SOCKET_ACCEPT4_X] = {f_sys_accept_x},
	[PPME_SOCKET_SEND_E] = {f_sys_send_e},
	[PPME_SOCKET_SEND_X] = {f_sys_send_x},
	[PPME_SOCKET_SENDTO_E] = {f_sys_sendto_e},
	[PPME_SOCKET_SENDTO_X] = {f_sys_send_x},
	[PPME_SOCKET_SENDMSG_E] = {f_sys_sendmsg_e},
	[PPME_SOCKET_SENDMSG_X] = {f_sys_sendmsg_x},
	[PPME_SOCKET_RECV_E] = {f_sys_recv_e},
	[PPME_SOCKET_RECV_X] = {f_sys_recv_x},
	[PPME_SOCKET_RECVFROM_E] = {f_sys_recvfrom_e},
	[PPME_SOCKET_RECVFROM_X] = {f_sys_recvfrom_x},
	[PPME_SOCKET_RECVMSG_E] = {f_sys_recvmsg_e},
	[PPME_SOCKET_RECVMSG_X] = {f_sys_recvmsg_x},
	[PPME_SOCKET_SHUTDOWN_E] = {f_sys_shutdown_e},
	[PPME_SOCKET_SHUTDOWN_X] = {f_sys_single_x},
	[PPME_SYSCALL_PIPE_E] = {f_sys_empty},
	[PPME_SYSCALL_PIPE_X] = {f_sys_pipe_x},
	[PPME_SYSCALL_EVENTFD_E] = {f_sys_eventfd_e},
	[PPME_SYSCALL_EVENTFD_X] = {f_sys_single_x},
	[PPME_SYSCALL_FUTEX_E] = {f_sys_futex_e},
	[PPME_SYSCALL_FUTEX_X] = {f_sys_single_x},
	[PPME_SYSCALL_STAT_E] = {f_sys_empty},
	[PPME_SYSCALL_STAT_X] = {PPM_AUTOFILL, 2, APT_REG, {{AF_ID_RETVAL}, {0} } },
	[PPME_SYSCALL_LSTAT_E] = {f_sys_empty},
	[PPME_SYSCALL_LSTAT_X] = {PPM_AUTOFILL, 2, APT_REG, {{AF_ID_RETVAL}, {0} } },
	[PPME_SYSCALL_FSTAT_E] = {f_sys_single},
	[PPME_SYSCALL_FSTAT_X] = {f_sys_single_x},
	[PPME_SYSCALL_STAT64_E] = {f_sys_empty},
	[PPME_SYSCALL_STAT64_X] = {PPM_AUTOFILL, 2, APT_REG, {{AF_ID_RETVAL}, {0} } },
	[PPME_SYSCALL_LSTAT64_E] = {f_sys_empty},
	[PPME_SYSCALL_LSTAT64_X] = {PPM_AUTOFILL, 2, APT_REG, {{AF_ID_RETVAL}, {0} } },
	[PPME_SYSCALL_FSTAT64_E] = {f_sys_single},
	[PPME_SYSCALL_FSTAT64_X] = {f_sys_single_x},
	[PPME_SYSCALL_EPOLLWAIT_E] = {PPM_AUTOFILL, 1, APT_REG, {{2} } },
	[PPME_SYSCALL_EPOLLWAIT_X] = {f_sys_single_x},
	[PPME_SYSCALL_POLL_E] = {f_sys_poll_e},
	[PPME_SYSCALL_POLL_X] = {f_sys_poll_x},
	[PPME_SYSCALL_SELECT_E] = {f_sys_empty},
	[PPME_SYSCALL_SELECT_X] = {f_sys_single_x},
	[PPME_SYSCALL_NEWSELECT_E] = {f_sys_empty},
	[PPME_SYSCALL_NEWSELECT_X] = {f_sys_single_x},
	[PPME_SYSCALL_LSEEK_E] = {f_sys_lseek_e},
	[PPME_SYSCALL_LSEEK_X] = {f_sys_single_x},
	[PPME_SYSCALL_LLSEEK_E] = {f_sys_llseek_e},
	[PPME_SYSCALL_LLSEEK_X] = {f_sys_single_x},
	[PPME_SYSCALL_IOCTL_3_E] = {PPM_AUTOFILL, 3, APT_REG, {{0}, {1}, {2} } },
	[PPME_SYSCALL_IOCTL_3_X] = {f_sys_single_x},
	[PPME_SYSCALL_GETCWD_E] = {f_sys_empty},
	[PPME_SYSCALL_GETCWD_X] = {PPM_AUTOFILL, 2, APT_REG, {{AF_ID_RETVAL}, {0} } },
	[PPME_SYSCALL_CHDIR_E] = {f_sys_empty},
	[PPME_SYSCALL_CHDIR_X] = {PPM_AUTOFILL, 2, APT_REG, {{AF_ID_RETVAL}, {0} } },
	[PPME_SYSCALL_FCHDIR_E] = {f_sys_single},
	[PPME_SYSCALL_FCHDIR_X] = {f_sys_single_x},
	[PPME_SYSCALL_MKDIR_E] = {PPM_AUTOFILL, 2, APT_REG, {{0}, {AF_ID_USEDEFAULT, 0} } },
	[PPME_SYSCALL_MKDIR_X] = {f_sys_single_x},
	[PPME_SYSCALL_RMDIR_E] = {f_sys_single},
	[PPME_SYSCALL_RMDIR_X] = {f_sys_single_x},
	[PPME_SYSCALL_OPENAT_E] = {f_sys_openat_e},
	[PPME_SYSCALL_OPENAT_X] = {f_sys_single_x},
	[PPME_SYSCALL_LINK_E] = {PPM_AUTOFILL, 2, APT_REG, {{0}, {1} } },
	[PPME_SYSCALL_LINK_X] = {f_sys_single_x},
	[PPME_SYSCALL_LINKAT_E] = {PPM_AUTOFILL, 4, APT_REG, {{0}, {1}, {2}, {3} } },
	[PPME_SYSCALL_LINKAT_X] = {f_sys_single_x},
	[PPME_SYSCALL_UNLINK_E] = {f_sys_single},
	[PPME_SYSCALL_UNLINK_X] = {f_sys_single_x},
	[PPME_SYSCALL_UNLINKAT_E] = {PPM_AUTOFILL, 2, APT_REG, {{0}, {1} } },
	[PPME_SYSCALL_UNLINKAT_X] = {f_sys_single_x},
#ifdef _64BIT_ARGS_SINGLE_REGISTER
	[PPME_SYSCALL_PREAD_E] = {PPM_AUTOFILL, 3, APT_REG, {{0}, {2}, {3} } },
#else
	[PPME_SYSCALL_PREAD_E] = {f_sys_pread64_e},
#endif
	[PPME_SYSCALL_PREAD_X] = {f_sys_read_x},
	[PPME_SYSCALL_PWRITE_E] = {f_sys_pwrite64_e},
	[PPME_SYSCALL_PWRITE_X] = {f_sys_write_x},
	[PPME_SYSCALL_READV_E] = {f_sys_single},
	[PPME_SYSCALL_READV_X] = {f_sys_readv_x},
	[PPME_SYSCALL_WRITEV_E] = {f_sys_writev_e},
	[PPME_SYSCALL_WRITEV_X] = {f_sys_writev_pwritev_x},
#ifdef _64BIT_ARGS_SINGLE_REGISTER
	[PPME_SYSCALL_PREADV_E] = {PPM_AUTOFILL, 2, APT_REG, {{0}, {3} } },
#else
	[PPME_SYSCALL_PREADV_E] = {f_sys_preadv_e},
#endif
	[PPME_SYSCALL_PREADV_X] = {f_sys_preadv_x},
	[PPME_SYSCALL_PWRITEV_E] = {f_sys_pwritev_e},
	[PPME_SYSCALL_PWRITEV_X] = {f_sys_writev_pwritev_x},
	[PPME_SYSCALL_DUP_E] = {PPM_AUTOFILL, 1, APT_REG, {{0} } },
	[PPME_SYSCALL_DUP_X] = {f_sys_single_x},
	/* Mask and Flags not implemented yet */
	[PPME_SYSCALL_SIGNALFD_E] = {PPM_AUTOFILL, 3, APT_REG, {{0}, {AF_ID_USEDEFAULT, 0}, {AF_ID_USEDEFAULT, 0} } },
	[PPME_SYSCALL_SIGNALFD_X] = {f_sys_single_x},
	[PPME_SYSCALL_KILL_E] = {PPM_AUTOFILL, 2, APT_REG, {{0}, {1} } },
	[PPME_SYSCALL_KILL_X] = {f_sys_single_x},
	[PPME_SYSCALL_TKILL_E] = {PPM_AUTOFILL, 2, APT_REG, {{0}, {1} } },
	[PPME_SYSCALL_TKILL_X] = {f_sys_single_x},
	[PPME_SYSCALL_TGKILL_E] = {PPM_AUTOFILL, 3, APT_REG, {{0}, {1}, {2} } },
	[PPME_SYSCALL_TGKILL_X] = {f_sys_single_x},
	[PPME_SYSCALL_NANOSLEEP_E] = {f_sys_nanosleep_e},
	[PPME_SYSCALL_NANOSLEEP_X] = {f_sys_single_x},
	[PPME_SYSCALL_TIMERFD_CREATE_E] = {PPM_AUTOFILL, 2, APT_REG, {{AF_ID_USEDEFAULT, 0}, {AF_ID_USEDEFAULT, 0} } },
	[PPME_SYSCALL_TIMERFD_CREATE_X] = {f_sys_single_x},
	[PPME_SYSCALL_INOTIFY_INIT_E] = {PPM_AUTOFILL, 1, APT_REG, {{AF_ID_USEDEFAULT, 0} } },
	[PPME_SYSCALL_INOTIFY_INIT_X] = {f_sys_single_x},
	[PPME_SYSCALL_GETRLIMIT_E] = {f_sys_getrlimit_setrlimit_e},
	[PPME_SYSCALL_GETRLIMIT_X] = {f_sys_getrlimit_setrlrimit_x},
	[PPME_SYSCALL_SETRLIMIT_E] = {f_sys_getrlimit_setrlimit_e},
	[PPME_SYSCALL_SETRLIMIT_X] = {f_sys_getrlimit_setrlrimit_x},
	[PPME_SYSCALL_PRLIMIT_E] = {f_sys_prlimit_e},
	[PPME_SYSCALL_PRLIMIT_X] = {f_sys_prlimit_x},
#ifdef CAPTURE_CONTEXT_SWITCHES
	[PPME_SCHEDSWITCH_6_E] = {f_sched_switch_e},
#endif
	[PPME_DROP_E] = {f_sched_drop},
	[PPME_DROP_X] = {f_sched_drop},
	[PPME_SYSCALL_FCNTL_E] = {f_sched_fcntl_e},
	[PPME_SYSCALL_FCNTL_X] = {f_sys_single_x},
	[PPME_SYSCALL_EXECVE_16_E] = {f_sys_empty},
	[PPME_SYSCALL_EXECVE_16_X] = {f_proc_startupdate},
	[PPME_SYSCALL_CLONE_20_E] = {f_sys_empty},
	[PPME_SYSCALL_CLONE_20_X] = {f_proc_startupdate},
	[PPME_SYSCALL_BRK_4_E] = {PPM_AUTOFILL, 1, APT_REG, {{0} } },
	[PPME_SYSCALL_BRK_4_X] = {f_sys_brk_munmap_mmap_x},
	[PPME_SYSCALL_MMAP_E] = {f_sys_mmap_e},
	[PPME_SYSCALL_MMAP_X] = {f_sys_brk_munmap_mmap_x},
	[PPME_SYSCALL_MMAP2_E] = {f_sys_mmap_e},
	[PPME_SYSCALL_MMAP2_X] = {f_sys_brk_munmap_mmap_x},
	[PPME_SYSCALL_MUNMAP_E] = {PPM_AUTOFILL, 2, APT_REG, {{0}, {1} } },
	[PPME_SYSCALL_MUNMAP_X] = {f_sys_brk_munmap_mmap_x},
	[PPME_SYSCALL_SPLICE_E] = {PPM_AUTOFILL, 4, APT_REG, {{0}, {2}, {4}, {5} } },
	[PPME_SYSCALL_SPLICE_X] = {PPM_AUTOFILL, 1, APT_REG, {{AF_ID_RETVAL} } },
	[PPME_SYSCALL_PTRACE_E] = {f_sys_ptrace_e},
	[PPME_SYSCALL_PTRACE_X] = {f_sys_ptrace_x},
	[PPME_SYSCALL_RENAME_E] = {f_sys_empty},
	[PPME_SYSCALL_RENAME_X] = {PPM_AUTOFILL, 3, APT_REG, {{AF_ID_RETVAL}, {0}, {1} } },
	[PPME_SYSCALL_RENAMEAT_E] = {f_sys_empty},
	[PPME_SYSCALL_RENAMEAT_X] = {f_sys_renameat_x},
	[PPME_SYSCALL_SYMLINK_E] = {f_sys_empty},
	[PPME_SYSCALL_SYMLINK_X] = {PPM_AUTOFILL, 3, APT_REG, {{AF_ID_RETVAL}, {0}, {1} } },
	[PPME_SYSCALL_SYMLINKAT_E] = {f_sys_empty},
	[PPME_SYSCALL_SYMLINKAT_X] = {f_sys_symlinkat_x},
	[PPME_SYSCALL_FORK_20_E] = {f_sys_empty},
	[PPME_SYSCALL_FORK_20_X] = {f_proc_startupdate},
	[PPME_SYSCALL_VFORK_20_E] = {f_sys_empty},
	[PPME_SYSCALL_VFORK_20_X] = {f_proc_startupdate},
	[PPME_SYSCALL_SENDFILE_E] = {f_sys_sendfile_e},
	[PPME_SYSCALL_SENDFILE_X] = {f_sys_sendfile_x},
	[PPME_SYSCALL_QUOTACTL_E] = {f_sys_quotactl_e},
	[PPME_SYSCALL_QUOTACTL_X] = {f_sys_quotactl_x},
	[PPME_SYSCALL_SETRESUID_E] = {PPM_AUTOFILL, 3, APT_REG, {{0}, {1}, {2} } },
	[PPME_SYSCALL_SETRESUID_X] = {PPM_AUTOFILL, 1, APT_REG, {{AF_ID_RETVAL} } },
	[PPME_SYSCALL_SETRESGID_E] = {PPM_AUTOFILL, 3, APT_REG, {{0}, {1}, {2} } },
	[PPME_SYSCALL_SETRESGID_X] = {PPM_AUTOFILL, 1, APT_REG, {{AF_ID_RETVAL} } },
	[PPME_SYSDIGEVENT_E] = {f_sys_sysdigevent_e},
	[PPME_SYSCALL_SETUID_E] = {PPM_AUTOFILL, 1, APT_REG, {{0} } },
	[PPME_SYSCALL_SETUID_X] = {PPM_AUTOFILL, 1, APT_REG, {{AF_ID_RETVAL} } },
	[PPME_SYSCALL_SETGID_E] = {PPM_AUTOFILL, 1, APT_REG, {{0} } },
	[PPME_SYSCALL_SETGID_X] = {PPM_AUTOFILL, 1, APT_REG, {{AF_ID_RETVAL} } },
	[PPME_SYSCALL_GETUID_E] = {f_sys_empty},
	[PPME_SYSCALL_GETUID_X] = {PPM_AUTOFILL, 1, APT_REG, {{AF_ID_RETVAL} } },
	[PPME_SYSCALL_GETEUID_E] = {f_sys_empty},
	[PPME_SYSCALL_GETEUID_X] = {PPM_AUTOFILL, 1, APT_REG, {{AF_ID_RETVAL} } },
	[PPME_SYSCALL_GETGID_E] = {f_sys_empty},
	[PPME_SYSCALL_GETGID_X] = {PPM_AUTOFILL, 1, APT_REG, {{AF_ID_RETVAL} } },
	[PPME_SYSCALL_GETEGID_E] = {f_sys_empty},
	[PPME_SYSCALL_GETEGID_X] = {PPM_AUTOFILL, 1, APT_REG, {{AF_ID_RETVAL} } },
	[PPME_SYSCALL_GETRESUID_E] = {f_sys_empty},
	[PPME_SYSCALL_GETRESUID_X] = {f_sys_getresuid_and_gid_x},
	[PPME_SYSCALL_GETRESGID_E] = {f_sys_empty},
	[PPME_SYSCALL_GETRESGID_X] = {f_sys_getresuid_and_gid_x},
#ifdef CAPTURE_SIGNAL_DELIVERIES
	[PPME_SYSCALL_SIGNALDELIVER_E] = {f_sys_signaldeliver_e},
	[PPME_SYSCALL_SIGNALDELIVER_X] = {f_sys_empty},
#endif
};

/*
 * do-nothing implementation of compat_ptr for systems that are not compiled
 * with CONFIG_COMPAT.
 */
#ifndef CONFIG_COMPAT
#define compat_ptr(X) X
#endif

#define merge_64(hi, lo) ((((unsigned long long)(hi)) << 32) + ((lo) & 0xffffffffUL))

static int f_sys_generic(struct event_filler_arguments *args)
{
	int res;
	long table_index = args->syscall_id - SYSCALL_TABLE_ID0;

#ifdef __NR_socketcall
	if (unlikely(args->syscall_id == __NR_socketcall)) {
		/*
		 * All the socket calls should be implemented
		 */
		ASSERT(false);
		return PPM_FAILURE_BUG;
	}
#endif /* __NR_socketcall */
	/*
	 * name
	 */
	if (likely(table_index >= 0 &&
		   table_index <  SYSCALL_TABLE_SIZE)) {
		enum ppm_syscall_code sc_code = g_syscall_code_routing_table[table_index];

		/*
		 * ID
		 */
		res = val_to_ring(args, sc_code, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		if (args->event_type == PPME_GENERIC_E) {
			/*
			 * nativeID
			 */
			res = val_to_ring(args, args->syscall_id, 0, false, 0);
			if (unlikely(res != PPM_SUCCESS))
				return res;
		}
	} else {
		ASSERT(false);
		res = val_to_ring(args, (unsigned long)"<out of bound>", 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	return add_sentinel(args);
}

static int f_sys_empty(struct event_filler_arguments *args)
{
	return add_sentinel(args);
}

static int f_sys_single(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;

	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_single_x(struct event_filler_arguments *args)
{
	int res;
	int64_t retval;

	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static inline u32 open_flags_to_scap(unsigned long flags)
{
	u32 res = 0;

	switch (flags & (O_RDONLY | O_WRONLY | O_RDWR)) {
	case O_WRONLY:
		res |= PPM_O_WRONLY;
		break;
	case O_RDWR:
		res |= PPM_O_RDWR;
		break;
	default:
		res |= PPM_O_RDONLY;
		break;
	}

	if (flags & O_CREAT)
		res |= PPM_O_CREAT;

	if (flags & O_APPEND)
		res |= PPM_O_APPEND;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	if (flags & O_DSYNC)
		res |= PPM_O_DSYNC;
#endif

	if (flags & O_EXCL)
		res |= PPM_O_EXCL;

	if (flags & O_NONBLOCK)
		res |= PPM_O_NONBLOCK;

	if (flags & O_SYNC)
		res |= PPM_O_SYNC;

	if (flags & O_TRUNC)
		res |= PPM_O_TRUNC;

	if (flags & O_DIRECT)
		res |= PPM_O_DIRECT;

	if (flags & O_DIRECTORY)
		res |= PPM_O_DIRECTORY;

	if (flags & O_LARGEFILE)
		res |= PPM_O_LARGEFILE;

	return res;
}

static int f_sys_open_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * name
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Flags
	 * Note that we convert them into the ppm portable representation before pushing them to the ring
	 */
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, open_flags_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Mode
	 * XXX: at this time, mode decoding is not supported. We nonetheless return a value (zero)
	 * so the format of the event is ready for when we'll export the mode in the future.
	 *
	 * syscall_get_arguments(current, args->regs, 2, 1, &val);
	 */
	res = val_to_ring(args, 0, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_read_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;
	unsigned long bufsize;

	/*
	 * Retrieve the FD. It will be used for dynamic snaplen calculation.
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	args->fd = (int)val;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * data
	 */
	if (retval < 0) {
		/*
		 * The operation failed, return an empty buffer
		 */
		val = 0;
		bufsize = 0;
	} else {
		syscall_get_arguments(current, args->regs, 1, 1, &val);

		/*
		 * The return value can be lower than the value provided by the user,
		 * and we take that into account.
		 */
		bufsize = retval;
	}

	/*
	 * Copy the buffer
	 */
	args->enforce_snaplen = true;
	res = val_to_ring(args, val, bufsize, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_write_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;
	unsigned long bufsize;

	/*
	 * Retrieve the FD. It will be used for dynamic snaplen calculation.
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	args->fd = (int)val;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * data
	 */
	syscall_get_arguments(current, args->regs, 2, 1, &val);
	bufsize = val;

	/*
	 * Copy the buffer
	 */
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	args->enforce_snaplen = true;
	res = val_to_ring(args, val, bufsize, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static inline u32 clone_flags_to_scap(unsigned long flags)
{
	u32 res = 0;

	if (flags & CLONE_FILES)
		res |= PPM_CL_CLONE_FILES;

	if (flags & CLONE_FS)
		res |= PPM_CL_CLONE_FS;

	if (flags & CLONE_IO)
		res |= PPM_CL_CLONE_IO;

	if (flags & CLONE_NEWIPC)
		res |= PPM_CL_CLONE_NEWIPC;

	if (flags & CLONE_NEWNET)
		res |= PPM_CL_CLONE_NEWNET;

	if (flags & CLONE_NEWNS)
		res |= PPM_CL_CLONE_NEWNS;

	if (flags & CLONE_NEWPID)
		res |= PPM_CL_CLONE_NEWPID;

	if (flags & CLONE_NEWUTS)
		res |= PPM_CL_CLONE_NEWUTS;

	if (flags & CLONE_PARENT_SETTID)
		res |= PPM_CL_CLONE_PARENT_SETTID;

	if (flags & CLONE_PARENT)
		res |= PPM_CL_CLONE_PARENT;

	if (flags & CLONE_PTRACE)
		res |= PPM_CL_CLONE_PTRACE;

	if (flags & CLONE_SIGHAND)
		res |= PPM_CL_CLONE_SIGHAND;

	if (flags & CLONE_SYSVSEM)
		res |= PPM_CL_CLONE_SYSVSEM;

	if (flags & CLONE_THREAD)
		res |= PPM_CL_CLONE_THREAD;

	if (flags & CLONE_UNTRACED)
		res |= PPM_CL_CLONE_UNTRACED;

	if (flags & CLONE_VM)
		res |= PPM_CL_CLONE_VM;

	return res;
}

/*
 * get_mm_counter was not inline and exported between 3.0 and 3.4
 * https://github.com/torvalds/linux/commit/69c978232aaa99476f9bd002c2a29a84fa3779b5
 * Hence the crap in these two functions
 */
unsigned long ppm_get_mm_counter(struct mm_struct *mm, int member)
{
	long val = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
	val = get_mm_counter(mm, member);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	val = atomic_long_read(&mm->rss_stat.count[member]);

	if (val < 0)
		val = 0;
#endif

	return val;
}

static unsigned long ppm_get_mm_swap(struct mm_struct *mm)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	return ppm_get_mm_counter(mm, MM_SWAPENTS);
#endif
	return 0;
}

static unsigned long ppm_get_mm_rss(struct mm_struct *mm)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
	return get_mm_rss(mm);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	return ppm_get_mm_counter(mm, MM_FILEPAGES) +
		ppm_get_mm_counter(mm, MM_ANONPAGES);
#else
	return get_mm_rss(mm);
#endif
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34)
static int ppm_cgroup_path(const struct cgroup *cgrp, char *buf, int buflen)
{
	char *start;
	struct dentry *dentry = rcu_dereference(cgrp->dentry);

	if (!dentry) {
		/*
		 * Inactive subsystems have no dentry for their root
		 * cgroup
		 */
		strcpy(buf, "/");
		return 0;
	}

	start = buf + buflen;

	*--start = '\0';
	for (;;) {
		int len = dentry->d_name.len;
		if ((start -= len) < buf)
			return -ENAMETOOLONG;
		memcpy(start, cgrp->dentry->d_name.name, len);
		cgrp = cgrp->parent;
		if (!cgrp)
			break;
		dentry = rcu_dereference(cgrp->dentry);
		if (!cgrp->parent)
			continue;
		if (--start < buf)
			return -ENAMETOOLONG;
		*start = '/';
	}
	memmove(buf, start, buf + buflen - start);
	return 0;
}
#endif

#ifdef CONFIG_CGROUPS
static int append_cgroup(const char* subsys_name, int subsys_id, char* buf, int* available)
{
	int pathlen;
	int subsys_len;
	char *path;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
	int res;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
	struct cgroup_subsys_state *css = task_css(current, subsys_id);
#else
	struct cgroup_subsys_state *css = task_subsys_state(current, subsys_id);
#endif
	if (!css) {
		ASSERT(false);
		return 1;
	}

	if (!css->cgroup) {
		ASSERT(false);
		return 1;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
	path = cgroup_path(css->cgroup, buf, *available);
	if (!path) {
		ASSERT(false);
		path = "NA";
	}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	res = cgroup_path(css->cgroup, buf, *available);
	if (res < 0) {
		ASSERT(false);
		path = "NA";
	} else {
		path = buf;
	}
#else
	res = ppm_cgroup_path(css->cgroup, buf, *available);
	if (res < 0) {
		ASSERT(false);
		path = "NA";
	} else {
		path = buf;
	}
#endif

	pathlen = strlen(path);
	subsys_len = strlen(subsys_name);
	if (subsys_len + 1 + pathlen + 1 > *available) {
		return 1;
	}

	memmove(buf + subsys_len + 1, path, pathlen);
	memcpy(buf, subsys_name, subsys_len);
	buf += subsys_len;
	*buf++ = '=';
	buf += pathlen;
	*buf++ = 0;
	*available -= (subsys_len + 1 + pathlen + 1);
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
#define SUBSYS(_x) 																						\
if (append_cgroup(#_x, _x ## _cgrp_id, args->str_storage + STR_STORAGE_SIZE - available, &available)) 	\
	goto cgroups_error;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#define IS_SUBSYS_ENABLED(option) IS_BUILTIN(option)
#define SUBSYS(_x) 																						\
if (append_cgroup(#_x, _x ## _subsys_id, args->str_storage + STR_STORAGE_SIZE - available, &available)) \
	goto cgroups_error;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
#define IS_SUBSYS_ENABLED(option) IS_ENABLED(option)
#define SUBSYS(_x) 																						\
if (append_cgroup(#_x, _x ## _subsys_id, args->str_storage + STR_STORAGE_SIZE - available, &available)) \
	goto cgroups_error;
#else
#define SUBSYS(_x) 																						\
if (append_cgroup(#_x, _x ## _subsys_id, args->str_storage + STR_STORAGE_SIZE - available, &available)) \
	goto cgroups_error;
#endif

#endif

static int f_proc_startupdate(struct event_filler_arguments *args)
{
	unsigned long val;
	int res = 0;
	unsigned int exe_len = 0;
	unsigned int args_len = 0;
	struct mm_struct *mm = current->mm;
	int64_t retval;
	int ptid;
	char *spwd;
	long total_vm = 0;
	long total_rss = 0;
	long swap = 0;
	int available = STR_STORAGE_SIZE;

	/*
	 * Make sure the operation was successful
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	if (likely(retval >= 0)) {
		if (unlikely(!mm)) {
			args->str_storage[0] = 0;
			pr_info("f_proc_startupdate drop, mm=NULL\n");
			return PPM_FAILURE_BUG;
		}

		if (unlikely(!mm->arg_end)) {
			args->str_storage[0] = 0;
			pr_info("f_proc_startupdate drop, mm->arg_end=NULL\n");
			return PPM_FAILURE_BUG;
		}

		args_len = mm->arg_end - mm->arg_start;

		if (args_len) {
			if (args_len > PAGE_SIZE)
				args_len = PAGE_SIZE;

			if (unlikely(ppm_copy_from_user(args->str_storage, (const void __user *)mm->arg_start, args_len)))
				return PPM_FAILURE_INVALID_USER_MEMORY;

			args->str_storage[args_len - 1] = 0;
		} else {
			*args->str_storage = 0;
		}
		
		exe_len = strnlen(args->str_storage, args_len);
		if (exe_len < args_len)
			++exe_len;
	} else {
		/*
		 * The call failed. Return empty strings for exe and args
		 */
		*args->str_storage = 0;
	}

	/*
	 * exe
	 */
	res = val_to_ring(args, (uint64_t)(long)args->str_storage, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Args
	 */
	res = val_to_ring(args, (int64_t)(long)args->str_storage + exe_len, args_len - exe_len, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * tid
	 */
	res = val_to_ring(args, (int64_t)current->pid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * pid
	 */
	res = val_to_ring(args, (int64_t)current->tgid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * ptid
	 */
	if (current->real_parent)
		ptid = current->parent->pid;
	else
		ptid = 0;

	res = val_to_ring(args, (int64_t)ptid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * cwd
	 */
	spwd = npm_getcwd(args->str_storage, STR_STORAGE_SIZE - 1);
	if (spwd == NULL)
		spwd = "";

	args->str_storage[STR_STORAGE_SIZE - 1] = '\0';

	res = val_to_ring(args, (uint64_t)(long)spwd, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * fdlimit
	 */
	res = val_to_ring(args, (int64_t)rlimit(RLIMIT_NOFILE), 0, false, 0);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * pgft_maj
	 */
	res = val_to_ring(args, current->maj_flt, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * pgft_min
	 */
	res = val_to_ring(args, current->min_flt, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	if (mm) {
		total_vm = mm->total_vm << (PAGE_SHIFT-10);
		total_rss = ppm_get_mm_rss(mm) << (PAGE_SHIFT-10);
		swap = ppm_get_mm_swap(mm) << (PAGE_SHIFT-10);
	}

	/*
	 * vm_size
	 */
	res = val_to_ring(args, total_vm, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * vm_rss
	 */
	res = val_to_ring(args, total_rss, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * vm_swap
	 */
	res = val_to_ring(args, swap, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * comm
	 */
	res = val_to_ring(args, (uint64_t)current->comm, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * cgroups
	 */
	args->str_storage[0] = 0;
#ifdef CONFIG_CGROUPS
	rcu_read_lock();
#include <linux/cgroup_subsys.h>
cgroups_error:
	rcu_read_unlock();
#endif

	res = val_to_ring(args, (int64_t)(long)args->str_storage, STR_STORAGE_SIZE - available, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	if (args->event_type == PPME_SYSCALL_CLONE_20_X ||
		args->event_type == PPME_SYSCALL_FORK_20_X ||
		args->event_type == PPME_SYSCALL_VFORK_20_X) {
		/*
		 * clone-only parameters
		 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
		uint64_t euid = from_kuid_munged(current_user_ns(), current_euid());
		uint64_t egid = from_kgid_munged(current_user_ns(), current_egid());
#else
		uint64_t euid = current_euid();
		uint64_t egid = current_egid();
#endif

		/*
		 * flags
		 */
		if (args->event_type == PPME_SYSCALL_CLONE_20_X)
			syscall_get_arguments(current, args->regs, 0, 1, &val);
		else
			val = 0;

		res = val_to_ring(args, (uint64_t)clone_flags_to_scap(val), 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		/*
		 * uid
		 */
		res = val_to_ring(args, euid, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		/*
		 * gid
		 */
		res = val_to_ring(args, egid, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
		
		/*
		 * vtid
		 */
		res = val_to_ring(args, task_pid_vnr(current), 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		/*
		 * vpid
		 */
		res = val_to_ring(args, task_tgid_vnr(current), 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

	} else if (args->event_type == PPME_SYSCALL_EXECVE_16_X) {
		/*
		 * execve-only parameters
		 */
		unsigned long env_len = 0;

		if (likely(retval >= 0)) {
			/*
			 * Already checked for mm validity
			 */
			env_len = mm->env_end - mm->env_start;

			if (env_len) {
				if (env_len > PAGE_SIZE)
					env_len = PAGE_SIZE;

				if (unlikely(ppm_copy_from_user(args->str_storage, (const void __user *)mm->env_start, env_len)))
					return PPM_FAILURE_INVALID_USER_MEMORY;

				args->str_storage[env_len - 1] = 0;
			} else {
				*args->str_storage = 0;
			}
		} else {
			/*
			 * The call failed. Return empty strings for env as well
			 */
			*args->str_storage = 0;
		}

		/*
		 * environ
		 */
		res = val_to_ring(args, (int64_t)(long)args->str_storage, env_len, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	return add_sentinel(args);
}

static int f_sys_socket_bind_x(struct event_filler_arguments *args)
{
	int res;
	int64_t retval;
	int err = 0;
	u16 size = 0;
	struct sockaddr __user *usrsockaddr;
	unsigned long val;
	struct sockaddr_storage address;
	char *targetbuf = args->str_storage;

	/*
	 * res
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);

	/*
	 * addr
	 */
#ifndef __NR_socketcall
	syscall_get_arguments(current, args->regs, 1, 1, &val);
#else
	val = args->socketcall_args[1];
#endif
	usrsockaddr = (struct sockaddr __user *)val;

	/*
	 * Get the address len
	 */
#ifndef __NR_socketcall
	syscall_get_arguments(current, args->regs, 2, 1, &val);
#else
	val = args->socketcall_args[2];
#endif

	if (usrsockaddr != NULL && val != 0) {
		/*
		 * Copy the address
		 */
		err = addr_to_kernel(usrsockaddr, val, (struct sockaddr *)&address);
		if (likely(err >= 0)) {
			/*
			 * Convert the fd into socket endpoint information
			 */
			size = pack_addr((struct sockaddr *)&address,
				val,
				targetbuf,
				STR_STORAGE_SIZE);
		}
	}

	/*
	 * Copy the endpoint info into the ring
	 */
	res = val_to_ring(args,
			    (uint64_t)(unsigned long)targetbuf,
			    size,
			    false,
			    0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_connect_x(struct event_filler_arguments *args)
{
	int res;
	int64_t retval;
	int err = 0;
	int fd;
	struct sockaddr __user *usrsockaddr;
	u16 size = 0;
	char *targetbuf = args->str_storage;
	struct sockaddr_storage address;
	unsigned long val;

	/*
	 * Push the result
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);

	/*
	 * Retrieve the fd and push it to the ring.
	 * Note that, even if we are in the exit callback, the arguments are still
	 * in the stack, and therefore we can consume them.
	 */
#ifndef __NR_socketcall
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	fd = (int)val;
#else
	fd = (int)args->socketcall_args[0];
#endif

	if (fd >= 0) {
		/*
		 * Get the address
		 */
#ifndef __NR_socketcall
		syscall_get_arguments(current, args->regs, 1, 1, &val);
#else
		val = args->socketcall_args[1];
#endif
		usrsockaddr = (struct sockaddr __user *)val;

		/*
		 * Get the address len
		 */
#ifndef __NR_socketcall
		syscall_get_arguments(current, args->regs, 2, 1, &val);
#else
		val = args->socketcall_args[2];
#endif

		if (usrsockaddr != NULL && val != 0) {
			/*
			 * Copy the address
			 */
			err = addr_to_kernel(usrsockaddr, val, (struct sockaddr *)&address);
			if (likely(err >= 0)) {
				/*
				 * Convert the fd into socket endpoint information
				 */
				size = fd_to_socktuple(fd,
					(struct sockaddr *)&address,
					val,
					true,
					false,
					targetbuf,
					STR_STORAGE_SIZE);
			}
		}
	}

	/*
	 * Copy the endpoint info into the ring
	 */
	res = val_to_ring(args,
			    (uint64_t)(unsigned long)targetbuf,
			    size,
			    false,
			    0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_socketpair_x(struct event_filler_arguments *args)
{
	int res;
	int64_t retval;
	unsigned long val;
	int fds[2];
	int err;
	struct socket *sock;
	struct unix_sock *us;
	struct sock *speer;

	/*
	 * retval
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * If the call was succesful, copy the FDs
	 */
	if (likely(retval >= 0)) {
		/*
		 * fds
		 */
#ifndef __NR_socketcall
		syscall_get_arguments(current, args->regs, 3, 1, &val);
#else
		val = args->socketcall_args[3];
#endif
		if (unlikely(ppm_copy_from_user(fds, (const void __user *)val, sizeof(fds))))
			return PPM_FAILURE_INVALID_USER_MEMORY;

		res = val_to_ring(args, fds[0], 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		res = val_to_ring(args, fds[1], 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		/* get socket source and peer address */
		sock = sockfd_lookup(fds[0], &err);
		if (likely(sock != NULL)) {
			us = unix_sk(sock->sk);
			speer = us->peer;
			res = val_to_ring(args, (unsigned long)us, 0, false, 0);
			if (unlikely(res != PPM_SUCCESS)) {
				sockfd_put(sock);
				return res;
			}

			res = val_to_ring(args, (unsigned long)speer, 0, false, 0);
			if (unlikely(res != PPM_SUCCESS)) {
				sockfd_put(sock);
				return res;
			}

			sockfd_put(sock);
		} else {
			return err;
		}
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	return add_sentinel(args);
}

static int f_sys_accept4_e(struct event_filler_arguments *args)
{
	int res;

	/*
	 * push the flags into the ring.
	 * XXX we don't support flags yet and so we just return zero
	 */
	/* res = val_to_ring(args, args->socketcall_args[3]); */
	res = val_to_ring(args, 0, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_accept_x(struct event_filler_arguments *args)
{
	int res;
	int fd;
	char *targetbuf = args->str_storage;
	u16 size = 0;
	unsigned long val;
	unsigned long srvskfd;
	int err = 0;
	struct socket *sock;

	/*
	 * Push the fd
	 */
	fd = syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, (int64_t)fd, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Convert the fd into socket endpoint information
	 */
	size = fd_to_socktuple(fd,
		NULL,
		0,
		false,
		true,
		targetbuf,
		STR_STORAGE_SIZE);

	/*
	 * Copy the endpoint info into the ring
	 */
	res = val_to_ring(args,
			    (uint64_t)(unsigned long)targetbuf,
			    size,
			    false,
			    0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * queuepct
	 */
#ifndef __NR_socketcall
	syscall_get_arguments(current, args->regs, 0, 1, &srvskfd);
#else
	srvskfd = args->socketcall_args[0];
#endif
	sock = sockfd_lookup(srvskfd, &err);

	if (unlikely(!sock || !(sock->sk))) {
		val = 0;

		if (sock)
			sockfd_put(sock);
	} else {
		if (sock->sk->sk_max_ack_backlog == 0)
			val = 0;
		else
			val = (unsigned long)sock->sk->sk_ack_backlog * 100 / sock->sk->sk_max_ack_backlog;
		sockfd_put(sock);
	}

	res = val_to_ring(args, val, 0, false, 0);
	if (res != PPM_SUCCESS)
		return res;

	return add_sentinel(args);
}

static int f_sys_send_e_common(struct event_filler_arguments *args, int *fd)
{
	int res;
	unsigned long size;
	unsigned long val;

	/*
	 * fd
	 */
#ifndef __NR_socketcall
	syscall_get_arguments(current, args->regs, 0, 1, &val);
#else
	val = args->socketcall_args[0];
#endif
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	*fd = val;

	/*
	 * size
	 */
#ifndef __NR_socketcall
	syscall_get_arguments(current, args->regs, 2, 1, &size);
#else
	size = args->socketcall_args[2];
#endif
	res = val_to_ring(args, size, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return PPM_SUCCESS;
}

static int f_sys_send_e(struct event_filler_arguments *args)
{
	int res;
	int fd;

	res = f_sys_send_e_common(args, &fd);

	if (likely(res == PPM_SUCCESS))
		return add_sentinel(args);
	else
		return res;
}

static int f_sys_sendto_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	u16 size = 0;
	char *targetbuf = args->str_storage;
	int fd;
	struct sockaddr __user *usrsockaddr;
	struct sockaddr_storage address;
	int err = 0;

	*targetbuf = 250;

	/*
	 * Push the common params to the ring
	 */
	res = f_sys_send_e_common(args, &fd);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Get the address
	 */
#ifndef __NR_socketcall
	syscall_get_arguments(current, args->regs, 4, 1, &val);
#else
	val = args->socketcall_args[4];
#endif
	usrsockaddr = (struct sockaddr __user *)val;

	/*
	 * Get the address len
	 */
#ifndef __NR_socketcall
	syscall_get_arguments(current, args->regs, 5, 1, &val);
#else
	val = args->socketcall_args[5];
#endif

	if (usrsockaddr != NULL && val != 0) {
		/*
		 * Copy the address
		 */
		err = addr_to_kernel(usrsockaddr, val, (struct sockaddr *)&address);
		if (likely(err >= 0)) {
			/*
			 * Convert the fd into socket endpoint information
			 */
			size = fd_to_socktuple(fd,
				(struct sockaddr *)&address,
				val,
				true,
				false,
				targetbuf,
				STR_STORAGE_SIZE);
		}
	}

	/*
	 * Copy the endpoint info into the ring
	 */
	res = val_to_ring(args,
			    (uint64_t)(unsigned long)targetbuf,
			    size,
			    false,
			    0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_send_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;
	unsigned long bufsize;

	/*
	 * Retrieve the FD. It will be used for dynamic snaplen calculation.
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	args->fd = (int)val;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * data
	 */
	if (retval < 0) {
		/*
		 * The operation failed, return an empty buffer
		 */
		val = 0;
		bufsize = 0;
	} else {
#ifndef __NR_socketcall
		syscall_get_arguments(current, args->regs, 1, 1, &val);
#else
		val = args->socketcall_args[1];
#endif

		/*
		 * The return value can be lower than the value provided by the user,
		 * and we take that into account.
		 */
		bufsize = retval;
	}

	args->enforce_snaplen = true;
	res = val_to_ring(args, val, bufsize, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_recv_e_common(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;

	/*
	 * fd
	 */
#ifndef __NR_socketcall
	syscall_get_arguments(current, args->regs, 0, 1, &val);
#else
	val = args->socketcall_args[0];
#endif
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * size
	 */
#ifndef __NR_socketcall
	syscall_get_arguments(current, args->regs, 2, 1, &val);
#else
	val = args->socketcall_args[2];
#endif
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return PPM_SUCCESS;
}

static int f_sys_recv_e(struct event_filler_arguments *args)
{
	int res;

	res = f_sys_recv_e_common(args);

	if (likely(res == PPM_SUCCESS))
		return add_sentinel(args);
	else
		return res;
}

static int f_sys_recvfrom_e(struct event_filler_arguments *args)
{
	int res;

	res = f_sys_recv_e_common(args);
	if (likely(res == PPM_SUCCESS))
		return add_sentinel(args);
	else
		return res;
}

static int f_sys_recv_x_common(struct event_filler_arguments *args, int64_t *retval)
{
	int res;
	unsigned long val;
	unsigned long bufsize;

	/*
	 * Retrieve the FD. It will be used for dynamic snaplen calculation.
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	args->fd = (int)val;

	/*
	 * res
	 */
	*retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, *retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * data
	 */
	if (*retval < 0) {
		/*
		 * The operation failed, return an empty buffer
		 */
		val = 0;
		bufsize = 0;
	} else {
#ifndef __NR_socketcall
		syscall_get_arguments(current, args->regs, 1, 1, &val);
#else
		val = args->socketcall_args[1];
#endif

		/*
		 * The return value can be lower than the value provided by the user,
		 * and we take that into account.
		 */
		bufsize = *retval;
	}

	args->enforce_snaplen = true;
	res = val_to_ring(args, val, bufsize, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return PPM_SUCCESS;
}

static int f_sys_recv_x(struct event_filler_arguments *args)
{
	int res;
	int64_t retval;

	res = f_sys_recv_x_common(args, &retval);

	if (likely(res == PPM_SUCCESS))
		return add_sentinel(args);
	else
		return res;
}

static int f_sys_recvfrom_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	u16 size = 0;
	int64_t retval;
	char *targetbuf = args->str_storage;
	int fd;
	struct sockaddr __user *usrsockaddr;
	struct sockaddr_storage address;
	int addrlen;
	int err = 0;

	/*
	 * Push the common params to the ring
	 */
	res = f_sys_recv_x_common(args, &retval);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	if (retval >= 0) {
		/*
		 * Get the fd
		 */
#ifndef __NR_socketcall
		syscall_get_arguments(current, args->regs, 0, 1, &val);
		fd = (int)val;
#else
		fd = (int)args->socketcall_args[0];
#endif

		/*
		 * Get the address
		 */
#ifndef __NR_socketcall
		syscall_get_arguments(current, args->regs, 4, 1, &val);
#else
		val = args->socketcall_args[4];
#endif
		usrsockaddr = (struct sockaddr __user *)val;

		/*
		 * Get the address len
		 */
#ifndef __NR_socketcall
		syscall_get_arguments(current, args->regs, 5, 1, &val);
#else
		val = args->socketcall_args[5];
#endif
		if (usrsockaddr != NULL && val != 0) {
			if (unlikely(ppm_copy_from_user(&addrlen, (const void __user *)val, sizeof(addrlen))))
				return PPM_FAILURE_INVALID_USER_MEMORY;

			/*
			 * Copy the address
			 */
			err = addr_to_kernel(usrsockaddr, addrlen, (struct sockaddr *)&address);
			if (likely(err >= 0)) {
				/*
				 * Convert the fd into socket endpoint information
				 */
				size = fd_to_socktuple(fd,
					(struct sockaddr *)&address,
					addrlen,
					true,
					true,
					targetbuf,
					STR_STORAGE_SIZE);
			}
		}
	}

	/*
	 * Copy the endpoint info into the ring
	 */
	res = val_to_ring(args,
			    (uint64_t)(unsigned long)targetbuf,
			    size,
			    false,
			    0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_sendmsg_e(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
	struct user_msghdr mh;
#else
	struct msghdr mh;
#endif
	char *targetbuf = args->str_storage;
	const struct iovec __user *iov;
	unsigned long iovcnt;
	int fd;
	u16 size = 0;
	int addrlen;
	int err = 0;
	struct sockaddr __user *usrsockaddr;
	struct sockaddr_storage address;

	/*
	 * fd
	 */
#ifndef __NR_socketcall
	syscall_get_arguments(current, args->regs, 0, 1, &val);
#else
	val = args->socketcall_args[0];
#endif
	fd = val;
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Retrieve the message header
	 */
#ifndef __NR_socketcall
	syscall_get_arguments(current, args->regs, 1, 1, &val);
#else
	val = args->socketcall_args[1];
#endif

	if (unlikely(ppm_copy_from_user(&mh, (const void __user *)val, sizeof(mh))))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	/*
	 * size
	 */
	iov = (const struct iovec __user *)mh.msg_iov;
	iovcnt = mh.msg_iovlen;

	res = parse_readv_writev_bufs(args, iov, iovcnt, args->consumer->snaplen, PRB_FLAG_PUSH_SIZE);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * tuple
	 */
	usrsockaddr = (struct sockaddr __user *)mh.msg_name;
	addrlen = mh.msg_namelen;

	if (usrsockaddr != NULL && addrlen != 0) {
		/*
		 * Copy the address
		 */
		err = addr_to_kernel(usrsockaddr, addrlen, (struct sockaddr *)&address);
		if (likely(err >= 0)) {
			/*
			 * Convert the fd into socket endpoint information
			 */
			size = fd_to_socktuple(fd,
				(struct sockaddr *)&address,
				addrlen,
				true,
				false,
				targetbuf,
				STR_STORAGE_SIZE);
		}
	}

	/* Copy the endpoint info into the ring */
	res = val_to_ring(args,
			    (uint64_t)(unsigned long)targetbuf,
			    size,
			    false,
			    0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_sendmsg_x(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;
	int64_t retval;
	const struct iovec __user *iov;
	unsigned long iovcnt;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
	struct user_msghdr mh;
#else
	struct msghdr mh;
#endif

	/*
	 * res
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Retrieve the message header
	 */
#ifndef __NR_socketcall
	syscall_get_arguments(current, args->regs, 1, 1, &val);
#else
	val = args->socketcall_args[1];
#endif

	if (unlikely(ppm_copy_from_user(&mh, (const void __user *)val, sizeof(mh))))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	/*
	 * data
	 */
	iov = (const struct iovec __user *)mh.msg_iov;
	iovcnt = mh.msg_iovlen;

	res = parse_readv_writev_bufs(args, iov, iovcnt, args->consumer->snaplen, PRB_FLAG_PUSH_DATA);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_recvmsg_e(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;

	/*
	 * fd
	 */
#ifndef __NR_socketcall
	syscall_get_arguments(current, args->regs, 0, 1, &val);
#else
	val = args->socketcall_args[0];
#endif
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_recvmsg_x(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;
	int64_t retval;
	const struct iovec __user *iov;
	unsigned long iovcnt;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
	struct user_msghdr mh;
#else
	struct msghdr mh;
#endif
	char *targetbuf = args->str_storage;
	int fd;
	struct sockaddr __user *usrsockaddr;
	struct sockaddr_storage address;
	u16 size = 0;
	int addrlen;
	int err = 0;

	/*
	 * res
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Retrieve the message header
	 */
#ifndef __NR_socketcall
	syscall_get_arguments(current, args->regs, 1, 1, &val);
#else
	val = args->socketcall_args[1];
#endif

	if (unlikely(ppm_copy_from_user(&mh, (const void __user *)val, sizeof(mh))))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	/*
	 * data and size
	 */
	iov = (const struct iovec __user *)mh.msg_iov;
	iovcnt = mh.msg_iovlen;

	res = parse_readv_writev_bufs(args, iov, iovcnt, retval, PRB_FLAG_PUSH_ALL);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * tuple
	 */
	if (retval >= 0) {
		/*
		 * Get the fd
		 */
#ifndef __NR_socketcall
		syscall_get_arguments(current, args->regs, 0, 1, &val);
		fd = (int)val;
#else
		fd = (int)args->socketcall_args[0];
#endif

		/*
		 * Get the address
		 */
		usrsockaddr = (struct sockaddr __user *)mh.msg_name;
		addrlen = mh.msg_namelen;

		if (usrsockaddr != NULL && addrlen != 0) {
			/*
			 * Copy the address
			 */
			err = addr_to_kernel(usrsockaddr, addrlen, (struct sockaddr *)&address);
			if (likely(err >= 0)) {
				/*
				 * Convert the fd into socket endpoint information
				 */
				size = fd_to_socktuple(fd,
					(struct sockaddr *)&address,
					addrlen,
					true,
					true,
					targetbuf,
					STR_STORAGE_SIZE);
			}
		}
	}

	/* Copy the endpoint info into the ring */
	res = val_to_ring(args,
			    (uint64_t)(unsigned long)targetbuf,
			    size,
			    false,
			    0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}


static int f_sys_pipe_x(struct event_filler_arguments *args)
{
	int res;
	int64_t retval;
	unsigned long val;
	int fds[2];
	struct file *file;

	/*
	 * retval
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * fds
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);

	if (unlikely(ppm_copy_from_user(fds, (const void __user *)val, sizeof(fds))))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	res = val_to_ring(args, fds[0], 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	res = val_to_ring(args, fds[1], 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	file = fget(fds[0]);
	val = 0;
	if (likely(file != NULL)) {
		val = file->f_path.dentry->d_inode->i_ino;
		fput(file);
	}

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_eventfd_e(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;

	/*
	 * initval
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * flags
	 * XXX not implemented yet
	 */
	/* syscall_get_arguments(current, args->regs, 1, 1, &val); */
	val = 0;
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static inline u16 shutdown_how_to_scap(unsigned long how)
{
	if (how == SHUT_RD) {
		return PPM_SHUT_RD;
	} else if (how == SHUT_WR) {
		return SHUT_WR;
	} else if (how == SHUT_RDWR) {
		return SHUT_RDWR;
	}

	ASSERT(false);
	return (u16)how;
}

static int f_sys_shutdown_e(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;

	/*
	 * fd
	 */
#ifndef __NR_socketcall
	syscall_get_arguments(current, args->regs, 0, 1, &val);
#else
	val = args->socketcall_args[0];
#endif
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * how
	 */
#ifndef __NR_socketcall
	syscall_get_arguments(current, args->regs, 1, 1, &val);
#else
	val = args->socketcall_args[1];
#endif
	res = val_to_ring(args, (unsigned long)shutdown_how_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static inline u16 futex_op_to_scap(unsigned long op)
{
	u16 res = 0;
	unsigned long flt_op = op & 127;

	if (flt_op == FUTEX_WAIT)
		res = PPM_FU_FUTEX_WAIT;
	else if (flt_op == FUTEX_WAKE)
		res = PPM_FU_FUTEX_WAKE;
	else if (flt_op == FUTEX_FD)
		res = PPM_FU_FUTEX_FD;
	else if (flt_op == FUTEX_REQUEUE)
		res = PPM_FU_FUTEX_REQUEUE;
	else if (flt_op == FUTEX_CMP_REQUEUE)
		res = PPM_FU_FUTEX_CMP_REQUEUE;
	else if (flt_op == FUTEX_WAKE_OP)
		res = PPM_FU_FUTEX_WAKE_OP;
	else if (flt_op == FUTEX_LOCK_PI)
		res = PPM_FU_FUTEX_LOCK_PI;
	else if (flt_op == FUTEX_UNLOCK_PI)
		res = PPM_FU_FUTEX_UNLOCK_PI;
	else if (flt_op == FUTEX_TRYLOCK_PI)
		res = PPM_FU_FUTEX_TRYLOCK_PI;
	else if (flt_op == FUTEX_WAIT_BITSET)
		res = PPM_FU_FUTEX_WAIT_BITSET;
	else if (flt_op == FUTEX_WAKE_BITSET)
		res = PPM_FU_FUTEX_WAKE_BITSET;
	else if (flt_op == FUTEX_WAIT_REQUEUE_PI)
		res = PPM_FU_FUTEX_WAIT_REQUEUE_PI;
	else if (flt_op == FUTEX_CMP_REQUEUE_PI)
		res = PPM_FU_FUTEX_CMP_REQUEUE_PI;

	if (op & FUTEX_PRIVATE_FLAG)
		res |= PPM_FU_FUTEX_PRIVATE_FLAG;

	if (op & FUTEX_CLOCK_REALTIME)
		res |= PPM_FU_FUTEX_CLOCK_REALTIME;

	return res;
}

static int f_sys_futex_e(struct event_filler_arguments *args)
{
	int res;
	unsigned long val;

	/*
	 * addr
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * op
	 */
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, (unsigned long)futex_op_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * val
	 */
	syscall_get_arguments(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static inline uint64_t lseek_whence_to_scap(unsigned long whence)
{
	uint64_t res = 0;

	if (whence == SEEK_SET)
		res = PPM_SEEK_SET;
	else if (whence == SEEK_CUR)
		res = PPM_SEEK_CUR;
	else if (whence == SEEK_END)
		res = PPM_SEEK_END;

	return res;
}

static int f_sys_lseek_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	/*
	 * fd
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * offset
	 */
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * whence
	 */
	syscall_get_arguments(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, lseek_whence_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_llseek_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	unsigned long oh;
	unsigned long ol;
	uint64_t offset;

	/*
	 * fd
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * offset
	 * We build it by combining the offset_high and offset_low system call arguments
	 */
	syscall_get_arguments(current, args->regs, 1, 1, &oh);
	syscall_get_arguments(current, args->regs, 2, 1, &ol);
	offset = (((uint64_t)oh) << 32) + ((uint64_t)ol);
	res = val_to_ring(args, offset, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * whence
	 */
	syscall_get_arguments(current, args->regs, 4, 1, &val);
	res = val_to_ring(args, lseek_whence_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

/* XXX this is very basic for the moment, we'll need to improve it */
static inline u16 poll_events_to_scap(short revents)
{
	u16 res = 0;

	if (revents & POLLIN)
		res |= PPM_POLLIN;

	if (revents & PPM_POLLPRI)
		res |= PPM_POLLPRI;

	if (revents & POLLOUT)
		res |= PPM_POLLOUT;

	if (revents & POLLRDHUP)
		res |= PPM_POLLRDHUP;

	if (revents & POLLERR)
		res |= PPM_POLLERR;

	if (revents & POLLHUP)
		res |= PPM_POLLHUP;

	if (revents & POLLNVAL)
		res |= PPM_POLLNVAL;

	if (revents & POLLRDNORM)
		res |= PPM_POLLRDNORM;

	if (revents & POLLRDBAND)
		res |= PPM_POLLRDBAND;

	if (revents & POLLWRNORM)
		res |= PPM_POLLWRNORM;

	if (revents & POLLWRBAND)
		res |= PPM_POLLWRBAND;

	return res;
}

static int poll_parse_fds(struct event_filler_arguments *args, bool enter_event)
{
	struct pollfd *fds;
	char *targetbuf;
	unsigned long val;
	unsigned long nfds;
	unsigned long fds_count;
	u32 j;
	u32 pos;
	u16 flags;

	/*
	 * fds
	 *
	 * Get the number of fds
	 */
	syscall_get_arguments(current, args->regs, 1, 1, &nfds);

	/*
	 * Check if we have enough space to store both the fd list
	 * from user space and the temporary buffer to serialize to the ring
	 */
	if (unlikely(sizeof(struct pollfd) * nfds + 2 + 10 * nfds > STR_STORAGE_SIZE))
		return PPM_FAILURE_BUFFER_FULL;

	/* Get the fds pointer */
	syscall_get_arguments(current, args->regs, 0, 1, &val);

	fds = (struct pollfd *)args->str_storage;
	if (unlikely(ppm_copy_from_user(fds, (const void __user *)val, nfds * sizeof(struct pollfd))))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	pos = 2;
	targetbuf = args->str_storage + nfds * sizeof(struct pollfd) + pos;
	fds_count = 0;

	/* Copy each fd into the temporary buffer */
	for (j = 0; j < nfds; j++) {
		if (enter_event) {
			flags = poll_events_to_scap(fds[j].events);
		} else {
			/*
			 * If it's an exit event, we copy only the fds that
			 * returned something
			 */
			if (!fds[j].revents)
				continue;

			flags = poll_events_to_scap(fds[j].revents);
		}

		*(int64_t *)(targetbuf + pos) = fds[j].fd;
		*(int16_t *)(targetbuf + pos + 8) = flags;
		pos += 10;
		++fds_count;
	}

	*(u16 *)(targetbuf) = (u16)fds_count;

	return val_to_ring(args, (uint64_t)(unsigned long)targetbuf, pos, false, 0);
}

static int f_sys_poll_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	res = poll_parse_fds(args, true);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * timeout
	 */
	syscall_get_arguments(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_poll_x(struct event_filler_arguments *args)
{
	int64_t retval;
	int res;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	res = poll_parse_fds(args, false);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_openat_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	/*
	 * dirfd
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);

	if (val == AT_FDCWD)
		val = PPM_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * name
	 */
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Flags
	 * Note that we convert them into the ppm portable representation before pushing them to the ring
	 */
	syscall_get_arguments(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, open_flags_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Mode
	 * XXX: at this time, mode decoding is not supported. We nonetheless return a value (zero)
	 * so the format of the event is ready for when we'll export the mode in the future.
	 *
	 * syscall_get_arguments(current, args->regs, 3, 1, &val);
	 */
	res = val_to_ring(args, 0, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

#ifndef _64BIT_ARGS_SINGLE_REGISTER
static int f_sys_pread64_e(struct event_filler_arguments *args)
{
	unsigned long val;
	unsigned long size;
	int res;
	unsigned long pos0;
	unsigned long pos1;
	uint64_t pos64;

	/*
	 * fd
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * size
	 */
	syscall_get_arguments(current, args->regs, 2, 1, &size);
	res = val_to_ring(args, size, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * pos
	 */
#if defined CONFIG_X86
	syscall_get_arguments(current, args->regs, 3, 1, &pos0);
	syscall_get_arguments(current, args->regs, 4, 1, &pos1);
#elif defined CONFIG_ARM && CONFIG_AEABI
	syscall_get_arguments(current, args->regs, 4, 1, &pos0);
	syscall_get_arguments(current, args->regs, 5, 1, &pos1);
#else
 #error This architecture/abi not yet supported
#endif

	pos64 = merge_64(pos1, pos0);

	res = val_to_ring(args, pos64, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}
#endif /* _64BIT_ARGS_SINGLE_REGISTER */

static int f_sys_pwrite64_e(struct event_filler_arguments *args)
{
	unsigned long val;
	unsigned long size;
	int res;
#ifndef _64BIT_ARGS_SINGLE_REGISTER
	unsigned long pos0;
	unsigned long pos1;
	uint64_t pos64;
#endif

	/*
	 * fd
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * size
	 */
	syscall_get_arguments(current, args->regs, 2, 1, &size);
	res = val_to_ring(args, size, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * pos
	 * NOTE: this is a 64bit value, which means that on 32bit systems it uses two
	 * separate registers that we need to merge.
	 */
#ifdef _64BIT_ARGS_SINGLE_REGISTER
	syscall_get_arguments(current, args->regs, 3, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;
#else
 #if defined CONFIG_X86
	syscall_get_arguments(current, args->regs, 3, 1, &pos0);
	syscall_get_arguments(current, args->regs, 4, 1, &pos1);
 #elif defined CONFIG_ARM && CONFIG_AEABI
	syscall_get_arguments(current, args->regs, 4, 1, &pos0);
	syscall_get_arguments(current, args->regs, 5, 1, &pos1);
 #else
  #error This architecture/abi not yet supported
 #endif

	pos64 = merge_64(pos1, pos0);

	res = val_to_ring(args, pos64, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;
#endif

	return add_sentinel(args);
}

static int f_sys_readv_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int64_t retval;
	int res;
	const struct iovec __user *iov;
	unsigned long iovcnt;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * data and size
	 */
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	iov = (const struct iovec __user *)val;
	syscall_get_arguments(current, args->regs, 2, 1, &iovcnt);

	res = parse_readv_writev_bufs(args, iov, iovcnt, retval, PRB_FLAG_PUSH_ALL);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_writev_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	const struct iovec __user *iov;
	unsigned long iovcnt;

	/*
	 * fd
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * size
	 */
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	iov = (const struct iovec __user *)val;
	syscall_get_arguments(current, args->regs, 2, 1, &iovcnt);

	/*
	 * Copy the buffer
	 */
	res = parse_readv_writev_bufs(args, iov, iovcnt, args->consumer->snaplen, PRB_FLAG_PUSH_SIZE);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_writev_pwritev_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;
	const struct iovec __user *iov;
	unsigned long iovcnt;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * data and size
	 */
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	iov = (const struct iovec __user *)val;
	syscall_get_arguments(current, args->regs, 2, 1, &iovcnt);

	/*
	 * Copy the buffer
	 */
	res = parse_readv_writev_bufs(args, iov, iovcnt, args->consumer->snaplen, PRB_FLAG_PUSH_DATA);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

#ifndef _64BIT_ARGS_SINGLE_REGISTER
static int f_sys_preadv_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	unsigned long pos0;
	unsigned long pos1;
	uint64_t pos64;

	/*
	 * fd
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * pos
	 */

	/*
	 * Note that in preadv and pwritev have NO 64-bit arguments in the
	 * syscall (despite having one in the userspace API), so no alignment
	 * requirements apply here. For an overly-detailed discussion about
	 * this, see https://lwn.net/Articles/311630/
	 */
	syscall_get_arguments(current, args->regs, 3, 1, &pos0);
	syscall_get_arguments(current, args->regs, 4, 1, &pos1);

	pos64 = merge_64(pos1, pos0);

	res = val_to_ring(args, pos64, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}
#endif /* _64BIT_ARGS_SINGLE_REGISTER */

static int f_sys_preadv_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int64_t retval;
	int res;
	const struct iovec __user *iov;
	unsigned long iovcnt;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * data and size
	 */
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	iov = (const struct iovec __user *)val;
	syscall_get_arguments(current, args->regs, 2, 1, &iovcnt);

	res = parse_readv_writev_bufs(args, iov, iovcnt, retval, PRB_FLAG_PUSH_ALL);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_pwritev_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
#ifndef _64BIT_ARGS_SINGLE_REGISTER
	unsigned long pos0;
	unsigned long pos1;
	uint64_t pos64;
#endif
	const struct iovec __user *iov;
	unsigned long iovcnt;

	/*
	 * fd
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * size
	 */
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	iov = (const struct iovec __user *)val;
	syscall_get_arguments(current, args->regs, 2, 1, &iovcnt);

	/*
	 * Copy the buffer
	 */
	res = parse_readv_writev_bufs(args, iov, iovcnt, args->consumer->snaplen, PRB_FLAG_PUSH_SIZE);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * pos
	 * NOTE: this is a 64bit value, which means that on 32bit systems it uses two
	 * separate registers that we need to merge.
	 */
#ifdef _64BIT_ARGS_SINGLE_REGISTER
	syscall_get_arguments(current, args->regs, 3, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;
#else
	/*
	 * Note that in preadv and pwritev have NO 64-bit arguments in the
	 * syscall (despite having one in the userspace API), so no alignment
	 * requirements apply here. For an overly-detailed discussion about
	 * this, see https://lwn.net/Articles/311630/
	 */
	syscall_get_arguments(current, args->regs, 3, 1, &pos0);
	syscall_get_arguments(current, args->regs, 4, 1, &pos1);

	pos64 = merge_64(pos1, pos0);

	res = val_to_ring(args, pos64, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;
#endif

	return add_sentinel(args);
}

static int f_sys_nanosleep_e(struct event_filler_arguments *args)
{
	int res;
	uint64_t longtime;
	unsigned long val;
	char *targetbuf = args->str_storage;
	struct timespec *tts = (struct timespec *)targetbuf;
	int cfulen;

	/*
	 * interval
	 * We copy the timespec structure and then convert it to a 64bit relative time
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);

	cfulen = (int)ppm_copy_from_user(targetbuf, (void __user *)val, sizeof(struct timespec));

	if (unlikely(cfulen != 0))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	longtime = ((uint64_t)tts->tv_sec) * 1000000000 + tts->tv_nsec;

	res = val_to_ring(args, longtime, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static inline u8 rlimit_resource_to_scap(unsigned long rresource)
{
	switch (rresource) {
	case RLIMIT_CPU:
		return PPM_RLIMIT_CPU;
	case RLIMIT_FSIZE:
		return PPM_RLIMIT_FSIZE;
	case RLIMIT_DATA:
		return PPM_RLIMIT_DATA;
	case RLIMIT_STACK:
		return PPM_RLIMIT_STACK;
	case RLIMIT_CORE:
		return PPM_RLIMIT_CORE;
	case RLIMIT_RSS:
		return PPM_RLIMIT_RSS;
	case RLIMIT_NPROC:
		return PPM_RLIMIT_NPROC;
	case RLIMIT_NOFILE:
		return PPM_RLIMIT_NOFILE;
	case RLIMIT_MEMLOCK:
		return PPM_RLIMIT_MEMLOCK;
	case RLIMIT_AS:
		return PPM_RLIMIT_AS;
	case RLIMIT_LOCKS:
		return PPM_RLIMIT_LOCKS;
	case RLIMIT_SIGPENDING:
		return PPM_RLIMIT_SIGPENDING;
	case RLIMIT_MSGQUEUE:
		return PPM_RLIMIT_MSGQUEUE;
	case RLIMIT_NICE:
		return PPM_RLIMIT_NICE;
	case RLIMIT_RTPRIO:
		return PPM_RLIMIT_RTPRIO;
	case RLIMIT_RTTIME:
		return PPM_RLIMIT_RTTIME;
	default:
		return PPM_RLIMIT_UNKNOWN;
	}
}

static int f_sys_getrlimit_setrlimit_e(struct event_filler_arguments *args)
{
	u8 ppm_resource;
	unsigned long val;
	int res;

	/*
	 * resource
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);

	ppm_resource = rlimit_resource_to_scap(val);

	res = val_to_ring(args, (uint64_t)ppm_resource, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_getrlimit_setrlrimit_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;
	struct rlimit rl;
	int64_t cur;
	int64_t max;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Copy the user structure and extract cur and max
	 */
	if (retval >= 0 || args->event_type == PPME_SYSCALL_SETRLIMIT_X) {
		syscall_get_arguments(current, args->regs, 1, 1, &val);

		if (unlikely(ppm_copy_from_user(&rl, (const void __user *)val, sizeof(struct rlimit))))
			return PPM_FAILURE_INVALID_USER_MEMORY;

		cur = rl.rlim_cur;
		max = rl.rlim_max;
	} else {
		cur = -1;
		max = -1;
	}

	/*
	 * cur
	 */
	res = val_to_ring(args, cur, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * max
	 */
	res = val_to_ring(args, max, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_prlimit_e(struct event_filler_arguments *args)
{
	u8 ppm_resource;
	unsigned long val;
	int res;

	/*
	 * pid
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * resource
	 */
	syscall_get_arguments(current, args->regs, 1, 1, &val);

	ppm_resource = rlimit_resource_to_scap(val);

	res = val_to_ring(args, (uint64_t)ppm_resource, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_prlimit_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;
	struct rlimit rl;
	int64_t newcur;
	int64_t newmax;
	int64_t oldcur;
	int64_t oldmax;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Copy the user structure and extract cur and max
	 */
	if (retval >= 0) {
		syscall_get_arguments(current, args->regs, 2, 1, &val);

		if (unlikely(ppm_copy_from_user(&rl, (const void __user *)val, sizeof(struct rlimit)))) {
			newcur = -1;
			newmax = -1;
		} else {
			newcur = rl.rlim_cur;
			newmax = rl.rlim_max;
		}
	} else {
		newcur = -1;
		newmax = -1;
	}

	syscall_get_arguments(current, args->regs, 3, 1, &val);

	if (unlikely(ppm_copy_from_user(&rl, (const void __user *)val, sizeof(struct rlimit)))) {
		oldcur = -1;
		oldmax = -1;
	} else {
		oldcur = rl.rlim_cur;
		oldmax = rl.rlim_max;
	}

	/*
	 * newcur
	 */
	res = val_to_ring(args, newcur, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * newmax
	 */
	res = val_to_ring(args, newmax, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * oldcur
	 */
	res = val_to_ring(args, oldcur, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * oldmax
	 */
	res = val_to_ring(args, oldmax, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

#ifdef CAPTURE_CONTEXT_SWITCHES
static int f_sched_switch_e(struct event_filler_arguments *args)
{
	int res;
	long total_vm = 0;
	long total_rss = 0;
	long swap = 0;
	struct mm_struct *mm = NULL;

	if (args->sched_prev == NULL || args->sched_next == NULL) {
		ASSERT(false);
		return -1;
	}

	/*
	 * next
	 */
	res = val_to_ring(args, args->sched_next->pid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * pgft_maj
	 */
	res = val_to_ring(args, args->sched_prev->maj_flt, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * pgft_min
	 */
	res = val_to_ring(args, args->sched_prev->min_flt, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	mm = args->sched_prev->mm;
	if (mm) {
		total_vm = mm->total_vm << (PAGE_SHIFT-10);
		total_rss = ppm_get_mm_rss(mm) << (PAGE_SHIFT-10);
		swap = ppm_get_mm_swap(mm) << (PAGE_SHIFT-10);
	}

	/*
	 * vm_size
	 */
	res = val_to_ring(args, total_vm, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * vm_rss
	 */
	res = val_to_ring(args, total_rss, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * vm_swap
	 */
	res = val_to_ring(args, swap, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

/*
	//
	// steal
	//
	steal = cputime64_to_clock_t(kcpustat_this_cpu->cpustat[CPUTIME_STEAL]);
	res = val_to_ring(args, steal, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}
*/

	return add_sentinel(args);
}
#endif /* CAPTURE_CONTEXT_SWITCHES */

static int f_sched_drop(struct event_filler_arguments *args)
{
	int res;

	/*
	 * next
	 */
	res = val_to_ring(args, args->consumer->sampling_ratio, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static inline u8 fcntl_cmd_to_scap(unsigned long cmd)
{
	switch (cmd) {
	case F_DUPFD:
		return PPM_FCNTL_F_DUPFD;
	case F_GETFD:
		return PPM_FCNTL_F_GETFD;
	case F_SETFD:
		return PPM_FCNTL_F_SETFD;
	case F_GETFL:
		return PPM_FCNTL_F_GETFL;
	case F_SETFL:
		return PPM_FCNTL_F_SETFL;
	case F_GETLK:
		return PPM_FCNTL_F_GETLK;
	case F_SETLK:
		return PPM_FCNTL_F_SETLK;
	case F_SETLKW:
		return PPM_FCNTL_F_SETLKW;
	case F_SETOWN:
		return PPM_FCNTL_F_SETOWN;
	case F_GETOWN:
		return PPM_FCNTL_F_GETOWN;
	case F_SETSIG:
		return PPM_FCNTL_F_SETSIG;
	case F_GETSIG:
		return PPM_FCNTL_F_GETSIG;
#ifndef CONFIG_64BIT
	case F_GETLK64:
		return PPM_FCNTL_F_GETLK64;
	case F_SETLK64:
		return PPM_FCNTL_F_SETLK64;
	case F_SETLKW64:
		return PPM_FCNTL_F_SETLKW64;
#endif
	case F_SETOWN_EX:
		return PPM_FCNTL_F_SETOWN_EX;
	case F_GETOWN_EX:
		return PPM_FCNTL_F_GETOWN_EX;
	case F_SETLEASE:
		return PPM_FCNTL_F_SETLEASE;
	case F_GETLEASE:
		return PPM_FCNTL_F_GETLEASE;
	case F_CANCELLK:
		return PPM_FCNTL_F_CANCELLK;
	case F_DUPFD_CLOEXEC:
		return PPM_FCNTL_F_DUPFD_CLOEXEC;
	case F_NOTIFY:
		return PPM_FCNTL_F_NOTIFY;
#ifdef F_SETPIPE_SZ
	case F_SETPIPE_SZ:
		return PPM_FCNTL_F_SETPIPE_SZ;
#endif
#ifdef F_GETPIPE_SZ
	case F_GETPIPE_SZ:
		return PPM_FCNTL_F_GETPIPE_SZ;
#endif
	default:
		ASSERT(false);
		return PPM_FCNTL_UNKNOWN;
	}
}

static int f_sched_fcntl_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	/*
	 * fd
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * cmd
	 */
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, fcntl_cmd_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static inline u16 ptrace_requests_to_scap(unsigned long req)
{
	switch (req) {
#ifdef PTRACE_SINGLEBLOCK
	case PTRACE_SINGLEBLOCK:
		return PPM_PTRACE_SINGLEBLOCK;
#endif
#ifdef PTRACE_SYSEMU_SINGLESTEP
	case PTRACE_SYSEMU_SINGLESTEP:
		return PPM_PTRACE_SYSEMU_SINGLESTEP;
#endif

#ifdef PTRACE_SYSEMU
	case PTRACE_SYSEMU:
		return PPM_PTRACE_SYSEMU;
#endif
#ifdef PTRACE_ARCH_PRCTL
	case PTRACE_ARCH_PRCTL:
		return PPM_PTRACE_ARCH_PRCTL;
#endif
#ifdef PTRACE_SET_THREAD_AREA
	case PTRACE_SET_THREAD_AREA:
		return PPM_PTRACE_SET_THREAD_AREA;
#endif
	case PTRACE_GET_THREAD_AREA:
		return PPM_PTRACE_GET_THREAD_AREA;
	case PTRACE_OLDSETOPTIONS:
		return PPM_PTRACE_OLDSETOPTIONS;
#ifdef PTRACE_SETFPXREGS
	case PTRACE_SETFPXREGS:
		return PPM_PTRACE_SETFPXREGS;
#endif
#ifdef PTRACE_GETFPXREGS
	case PTRACE_GETFPXREGS:
		return PPM_PTRACE_GETFPXREGS;
#endif
	case PTRACE_SETFPREGS:
		return PPM_PTRACE_SETFPREGS;
	case PTRACE_GETFPREGS:
		return PPM_PTRACE_GETFPREGS;
	case PTRACE_SETREGS:
		return PPM_PTRACE_SETREGS;
	case PTRACE_GETREGS:
		return PPM_PTRACE_GETREGS;
#ifdef PTRACE_SETSIGMASK
	case PTRACE_SETSIGMASK:
		return PPM_PTRACE_SETSIGMASK;
#endif
#ifdef PTRACE_GETSIGMASK
	case PTRACE_GETSIGMASK:
		return PPM_PTRACE_GETSIGMASK;
#endif
#ifdef PTRACE_PEEKSIGINFO
	case PTRACE_PEEKSIGINFO:
		return PPM_PTRACE_PEEKSIGINFO;
#endif
#ifdef PTRACE_LISTEN
	case PTRACE_LISTEN:
		return PPM_PTRACE_LISTEN;
#endif
#ifdef PTRACE_INTERRUPT
	case PTRACE_INTERRUPT:
		return PPM_PTRACE_INTERRUPT;
#endif
#ifdef PTRACE_SEIZE
	case PTRACE_SEIZE:
		return PPM_PTRACE_SEIZE;
#endif
#ifdef PTRACE_SETREGSET
	case PTRACE_SETREGSET:
		return PPM_PTRACE_SETREGSET;
#endif
#ifdef PTRACE_GETREGSET
	case PTRACE_GETREGSET:
		return PPM_PTRACE_GETREGSET;
#endif
	case PTRACE_SETSIGINFO:
		return PPM_PTRACE_SETSIGINFO;
	case PTRACE_GETSIGINFO:
		return PPM_PTRACE_GETSIGINFO;
	case PTRACE_GETEVENTMSG:
		return PPM_PTRACE_GETEVENTMSG;
	case PTRACE_SETOPTIONS:
		return PPM_PTRACE_SETOPTIONS;
	case PTRACE_SYSCALL:
		return PPM_PTRACE_SYSCALL;
	case PTRACE_DETACH:
		return PPM_PTRACE_DETACH;
	case PTRACE_ATTACH:
		return PPM_PTRACE_ATTACH;
	case PTRACE_SINGLESTEP:
		return PPM_PTRACE_SINGLESTEP;
	case PTRACE_KILL:
		return PPM_PTRACE_KILL;
	case PTRACE_CONT:
		return PPM_PTRACE_CONT;
	case PTRACE_POKEUSR:
		return PPM_PTRACE_POKEUSR;
	case PTRACE_POKEDATA:
		return PPM_PTRACE_POKEDATA;
	case PTRACE_POKETEXT:
		return PPM_PTRACE_POKETEXT;
	case PTRACE_PEEKUSR:
		return PPM_PTRACE_PEEKUSR;
	case PTRACE_PEEKDATA:
		return PPM_PTRACE_PEEKDATA;
	case PTRACE_PEEKTEXT:
		return PPM_PTRACE_PEEKTEXT;
	case PTRACE_TRACEME:
		return PPM_PTRACE_TRACEME;
	default:
		return PPM_PTRACE_UNKNOWN;
	}
}

static inline int parse_ptrace_addr(struct event_filler_arguments *args, u16 request)
{
	unsigned long val;
	uint64_t dst;
	u8 idx;

	syscall_get_arguments(current, args->regs, 2, 1, &val);
	switch (request) {
	default:
		idx = PPM_PTRACE_IDX_UINT64;
		dst = (uint64_t)val;
	}

	return val_to_ring(args, dst, 0, false, idx);
}

static inline int parse_ptrace_data(struct event_filler_arguments *args, u16 request)
{
	unsigned long val;
	unsigned long len;
	uint64_t dst;
	u8 idx;

	syscall_get_arguments(current, args->regs, 3, 1, &val);
	switch (request) {
	case PPM_PTRACE_PEEKTEXT:
	case PPM_PTRACE_PEEKDATA:
	case PPM_PTRACE_PEEKUSR:
		idx = PPM_PTRACE_IDX_UINT64;
		len = ppm_copy_from_user(&dst, (const void __user *)val, sizeof(long));
		if (unlikely(len != 0))
			return PPM_FAILURE_INVALID_USER_MEMORY;

		break;
	case PPM_PTRACE_CONT:
	case PPM_PTRACE_SINGLESTEP:
	case PPM_PTRACE_DETACH:
	case PPM_PTRACE_SYSCALL:
		idx = PPM_PTRACE_IDX_SIGTYPE;
		dst = (uint64_t)val;
		break;
	case PPM_PTRACE_ATTACH:
	case PPM_PTRACE_TRACEME:
	case PPM_PTRACE_POKETEXT:
	case PPM_PTRACE_POKEDATA:
	case PPM_PTRACE_POKEUSR:
	default:
		idx = PPM_PTRACE_IDX_UINT64;
		dst = (uint64_t)val;
		break;
	}

	return val_to_ring(args, dst, 0, false, idx);
}

static int f_sys_ptrace_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	/*
	 * request
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, ptrace_requests_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * pid
	 */
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_ptrace_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int64_t retval;
	u16 request;
	int res;

	/*
	 * res
	 */
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	if (retval < 0) {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;

		return add_sentinel(args);
	}

	/*
	 * request
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	request = ptrace_requests_to_scap(val);

	res = parse_ptrace_addr(args, request);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	res = parse_ptrace_data(args, request);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_brk_munmap_mmap_x(struct event_filler_arguments *args)
{
	int64_t retval;
	int res = 0;
	struct mm_struct *mm = current->mm;
	long total_vm = 0;
	long total_rss = 0;
	long swap = 0;

	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	if (mm) {
		total_vm = mm->total_vm << (PAGE_SHIFT-10);
		total_rss = ppm_get_mm_rss(mm) << (PAGE_SHIFT-10);
		swap = ppm_get_mm_swap(mm) << (PAGE_SHIFT-10);
	}

	/*
	 * vm_size
	 */
	res = val_to_ring(args, total_vm, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * vm_rss
	 */
	res = val_to_ring(args, total_rss, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * vm_swap
	 */
	res = val_to_ring(args, swap, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static u32 prot_flags_to_scap(int prot)
{
	u32 res = 0;

	if (prot & PROT_READ)
		res |= PPM_PROT_READ;

	if (prot & PROT_WRITE)
		res |= PPM_PROT_WRITE;

	if (prot & PROT_EXEC)
		res |= PPM_PROT_EXEC;

	if (prot & PROT_SEM)
		res |= PPM_PROT_SEM;

	if (prot & PROT_GROWSDOWN)
		res |= PPM_PROT_GROWSDOWN;

	if (prot & PROT_GROWSUP)
		res |= PPM_PROT_GROWSUP;

#ifdef PROT_SAO
	if (prot & PROT_SAO)
		res |= PPM_PROT_SAO;
#endif

	return res;
}

static u32 mmap_flags_to_scap(int flags)
{
	u32 res = 0;

	if (flags & MAP_SHARED)
		res |= PPM_MAP_SHARED;

	if (flags & MAP_PRIVATE)
		res |= PPM_MAP_PRIVATE;

	if (flags & MAP_FIXED)
		res |= PPM_MAP_FIXED;

	if (flags & MAP_ANONYMOUS)
		res |= PPM_MAP_ANONYMOUS;

#ifdef MAP_32BIT
	if (flags & MAP_32BIT)
		res |= PPM_MAP_32BIT;
#endif

#ifdef MAP_RENAME
	if (flags & MAP_RENAME)
		res |= PPM_MAP_RENAME;
#endif

	if (flags & MAP_NORESERVE)
		res |= PPM_MAP_NORESERVE;

	if (flags & MAP_POPULATE)
		res |= PPM_MAP_POPULATE;

	if (flags & MAP_NONBLOCK)
		res |= PPM_MAP_NONBLOCK;

	if (flags & MAP_GROWSDOWN)
		res |= PPM_MAP_GROWSDOWN;

	if (flags & MAP_DENYWRITE)
		res |= PPM_MAP_DENYWRITE;

	if (flags & MAP_EXECUTABLE)
		res |= PPM_MAP_EXECUTABLE;

#ifdef MAP_INHERIT
	if (flags & MAP_INHERIT)
		res |= PPM_MAP_INHERIT;
#endif

	if (flags & MAP_FILE)
		res |= PPM_MAP_FILE;

	if (flags & MAP_LOCKED)
		res |= PPM_MAP_LOCKED;

	return res;
}

static int f_sys_mmap_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;

	/*
	 * addr
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * length
	 */
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * prot
	 */
	syscall_get_arguments(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, prot_flags_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * flags
	 */
	syscall_get_arguments(current, args->regs, 3, 1, &val);
	res = val_to_ring(args, mmap_flags_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * fd
	 */
	syscall_get_arguments(current, args->regs, 4, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * offset/pgoffset
	 */
	syscall_get_arguments(current, args->regs, 5, 1, &val);
	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_renameat_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * olddirfd
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);

	if (val == AT_FDCWD)
		val = PPM_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * oldpath
	 */
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * newdirfd
	 */
	syscall_get_arguments(current, args->regs, 2, 1, &val);

	if (val == AT_FDCWD)
		val = PPM_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * newpath
	 */
	syscall_get_arguments(current, args->regs, 3, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_symlinkat_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * oldpath
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * newdirfd
	 */
	syscall_get_arguments(current, args->regs, 1, 1, &val);

	if (val == AT_FDCWD)
		val = PPM_AT_FDCWD;

	res = val_to_ring(args, val, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * newpath
	 */
	syscall_get_arguments(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_procexit_e(struct event_filler_arguments *args)
{
	int res;

	if (args->sched_prev == NULL) {
		ASSERT(false);
		return -1;
	}

	/*
	 * status
	 */
	res = val_to_ring(args, args->sched_prev->exit_code, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_sendfile_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	off_t offset;

	/*
	 * out_fd
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * in_fd
	 */
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * offset
	 */
	syscall_get_arguments(current, args->regs, 2, 1, &val);

	if (val != 0) {
		if (unlikely(ppm_copy_from_user(&offset, (void *)val, sizeof(off_t))))
			val = 0;
		else
			val = offset;
	}

	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * size
	 */
	syscall_get_arguments(current, args->regs, 3, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_sendfile_x(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	int64_t retval;
	off_t offset;

	/*
	 * res
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * offset
	 */
	syscall_get_arguments(current, args->regs, 2, 1, &val);

	if (val != 0) {
		if (unlikely(ppm_copy_from_user(&offset, (void *)val, sizeof(off_t))))
			val = 0;
		else
			val = offset;
	}

	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static inline uint8_t quotactl_type_to_scap(unsigned long cmd)
{
	switch (cmd & SUBCMDMASK) {
	case USRQUOTA:
		return PPM_USRQUOTA;
	case GRPQUOTA:
		return PPM_GRPQUOTA;
	}
	return 0;
}

static inline uint16_t quotactl_cmd_to_scap(unsigned long cmd)
{
	uint16_t res;

	switch (cmd >> SUBCMDSHIFT) {
	case Q_SYNC:
		res = PPM_Q_SYNC;
		break;
	case Q_QUOTAON:
		res = PPM_Q_QUOTAON;
		break;
	case Q_QUOTAOFF:
		res = PPM_Q_QUOTAOFF;
		break;
	case Q_GETFMT:
		res = PPM_Q_GETFMT;
		break;
	case Q_GETINFO:
		res = PPM_Q_GETINFO;
		break;
	case Q_SETINFO:
		res = PPM_Q_SETINFO;
		break;
	case Q_GETQUOTA:
		res = PPM_Q_GETQUOTA;
		break;
	case Q_SETQUOTA:
		res = PPM_Q_SETQUOTA;
		break;
	/*
	 *  XFS specific
	 */
	case Q_XQUOTAON:
		res = PPM_Q_XQUOTAON;
		break;
	case Q_XQUOTAOFF:
		res = PPM_Q_XQUOTAOFF;
		break;
	case Q_XGETQUOTA:
		res = PPM_Q_XGETQUOTA;
		break;
	case Q_XSETQLIM:
		res = PPM_Q_XSETQLIM;
		break;
	case Q_XGETQSTAT:
		res = PPM_Q_XGETQSTAT;
		break;
	case Q_XQUOTARM:
		res = PPM_Q_XQUOTARM;
		break;
	case Q_XQUOTASYNC:
		res = PPM_Q_XQUOTASYNC;
		break;
	default:
		res = 0;
	}
	return res;
}

static inline uint8_t quotactl_fmt_to_scap(unsigned long fmt)
{
	switch (fmt) {
	case QFMT_VFS_OLD:
		return PPM_QFMT_VFS_OLD;
	case QFMT_VFS_V0:
		return PPM_QFMT_VFS_V0;
#ifdef QFMT_VFS_V1
	case QFMT_VFS_V1:
		return PPM_QFMT_VFS_V1;
#endif
	default:
		return PPM_QFMT_NOT_USED;
	}
}

static int f_sys_quotactl_e(struct event_filler_arguments *args)
{
	unsigned long val;
	int res;
	uint32_t id;
	uint8_t quota_fmt;
	uint16_t cmd;

	/*
	 * extract cmd
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	cmd = quotactl_cmd_to_scap(val);
	res = val_to_ring(args, cmd, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * extract type
	 */
	res = val_to_ring(args, quotactl_type_to_scap(val), 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 *  extract id
	 */
	id = 0;
	syscall_get_arguments(current, args->regs, 2, 1, &val);
	if ((cmd == PPM_Q_GETQUOTA) ||
		 (cmd == PPM_Q_SETQUOTA) ||
		 (cmd == PPM_Q_XGETQUOTA) ||
		 (cmd == PPM_Q_XSETQLIM)) {
		/*
		 * in this case id represent an userid or groupid so add it
		 */
		id = val;
	}
	res = val_to_ring(args, id, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * extract quota_fmt from id
	 */
	quota_fmt = PPM_QFMT_NOT_USED;
	if (cmd == PPM_Q_QUOTAON)
		quota_fmt = quotactl_fmt_to_scap(val);

	res = val_to_ring(args, quota_fmt, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_quotactl_x(struct event_filler_arguments *args)
{
	unsigned long val, len;
	int res;
	int64_t retval;
	uint16_t cmd;
	struct if_dqblk dqblk;
	struct if_dqinfo dqinfo;
	uint32_t quota_fmt_out;

	char empty_string[] = "";

	/*
	 * extract cmd
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	cmd = quotactl_cmd_to_scap(val);

	/*
	 * return value
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * Add special
	 */
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * get addr
	 */
	syscall_get_arguments(current, args->regs, 3, 1, &val);

	/*
	 * get quotafilepath only for QUOTAON
	 */
	if (cmd == PPM_Q_QUOTAON)
		res = val_to_ring(args, val, 0, true, 0);
	else
		res = val_to_ring(args, (unsigned long)empty_string, 0, false, 0);

	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * dqblk fields if present
	 */
	dqblk.dqb_valid = 0;
	if ((cmd == PPM_Q_GETQUOTA) || (cmd == PPM_Q_SETQUOTA)) {
		len = ppm_copy_from_user(&dqblk, (void *)val, sizeof(struct if_dqblk));
		if (unlikely(len != 0))
			return PPM_FAILURE_INVALID_USER_MEMORY;
	}
	if (dqblk.dqb_valid & QIF_BLIMITS) {
		res = val_to_ring(args, dqblk.dqb_bhardlimit, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
		res = val_to_ring(args, dqblk.dqb_bsoftlimit, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	if (dqblk.dqb_valid & QIF_SPACE) {
		res = val_to_ring(args, dqblk.dqb_curspace, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	if (dqblk.dqb_valid & QIF_ILIMITS) {
		res = val_to_ring(args, dqblk.dqb_ihardlimit, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
		res = val_to_ring(args, dqblk.dqb_isoftlimit, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	if (dqblk.dqb_valid & QIF_BTIME) {
		res = val_to_ring(args, dqblk.dqb_btime, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	if (dqblk.dqb_valid & QIF_ITIME) {
		res = val_to_ring(args, dqblk.dqb_itime, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	/*
	 * dqinfo fields if present
	 */
	dqinfo.dqi_valid = 0;
	if ((cmd == PPM_Q_GETINFO) || (cmd == PPM_Q_SETINFO)) {
		len = ppm_copy_from_user(&dqinfo, (void *)val, sizeof(struct if_dqinfo));
		if (unlikely(len != 0))
			return PPM_FAILURE_INVALID_USER_MEMORY;
	}

	if (dqinfo.dqi_valid & IIF_BGRACE) {
		res = val_to_ring(args, dqinfo.dqi_bgrace, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	if (dqinfo.dqi_valid & IIF_IGRACE) {
		res = val_to_ring(args, dqinfo.dqi_igrace, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	if (dqinfo.dqi_valid & IIF_FLAGS) {
		res = val_to_ring(args, dqinfo.dqi_flags, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	} else {
		res = val_to_ring(args, 0, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	quota_fmt_out = PPM_QFMT_NOT_USED;
	if (cmd == PPM_Q_GETFMT) {
		len = ppm_copy_from_user(&quota_fmt_out, (void *)val, sizeof(uint32_t));
		if (unlikely(len != 0))
			return PPM_FAILURE_INVALID_USER_MEMORY;
		quota_fmt_out = quotactl_fmt_to_scap(quota_fmt_out);
	}
	res = val_to_ring(args, quota_fmt_out, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_sysdigevent_e(struct event_filler_arguments *args)
{
	int res;

	/*
	 * event_type
	 */
	res = val_to_ring(args, (unsigned long)args->sched_prev, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * event_data
	 */
	res = val_to_ring(args, (unsigned long)args->sched_next, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

static int f_sys_getresuid_and_gid_x(struct event_filler_arguments *args)
{
	int res;
	unsigned long val, len;
	uint32_t uid;
	int16_t retval;

	/*
	 * return value
	 */
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * ruid
	 */
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	len = ppm_copy_from_user(&uid, (void *)val, sizeof(uint32_t));
	if (unlikely(len != 0))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	res = val_to_ring(args, uid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * euid
	 */
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	len = ppm_copy_from_user(&uid, (void *)val, sizeof(uint32_t));
	if (unlikely(len != 0))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	res = val_to_ring(args, uid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * suid
	 */
	syscall_get_arguments(current, args->regs, 2, 1, &val);
	len = ppm_copy_from_user(&uid, (void *)val, sizeof(uint32_t));
	if (unlikely(len != 0))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	res = val_to_ring(args, uid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}

#ifdef CAPTURE_SIGNAL_DELIVERIES
static int f_sys_signaldeliver_e(struct event_filler_arguments *args)
{
	int res;

	/*
	 * source pid
	 */
	res = val_to_ring(args, args->spid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * destination pid
	 */
	res = val_to_ring(args, args->dpid, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	/*
	 * signal number
	 */
	res = val_to_ring(args, args->signo, 0, false, 0);
	if (unlikely(res != PPM_SUCCESS))
		return res;

	return add_sentinel(args);
}
#endif
