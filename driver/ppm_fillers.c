/*
Copyright (C) 2013-2014 Draios inc.
 
This file is part of sysdig.

sysdig is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

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
#include <linux/version.h>

#include "ppm_ringbuffer.h"
#include "ppm_events_public.h"
#include "ppm_events.h"
#include "ppm.h"

static int32_t f_sys_generic(struct event_filler_arguments* args);	// generic syscall event filler that includes the system call number
static int32_t f_sys_empty(struct event_filler_arguments* args);		// empty filler
static int32_t f_sys_single(struct event_filler_arguments* args);		// generic enter filler that copies a single argument syscall into a single parameter event
static int32_t f_sys_single_x(struct event_filler_arguments* args);		// generic exit filler that captures an integer
static int32_t f_sys_open_x(struct event_filler_arguments* args);
static int32_t f_sys_read_x(struct event_filler_arguments* args);
static int32_t f_sys_write_x(struct event_filler_arguments* args);
static int32_t f_proc_startupdate(struct event_filler_arguments* args);
static int32_t f_sys_socketpair_x(struct event_filler_arguments* args);
static int32_t f_sys_connect_x(struct event_filler_arguments* args);
static int32_t f_sys_accept4_e(struct event_filler_arguments* args);
static int32_t f_sys_accept_x(struct event_filler_arguments* args);
static int32_t f_sys_send_e(struct event_filler_arguments* args);
static int32_t f_sys_send_x(struct event_filler_arguments* args);
static int32_t f_sys_sendto_e(struct event_filler_arguments* args);
static int32_t f_sys_sendmsg_e(struct event_filler_arguments* args);
static int32_t f_sys_sendmsg_x(struct event_filler_arguments* args);
static int32_t f_sys_recv_e(struct event_filler_arguments* args);
static int32_t f_sys_recv_x(struct event_filler_arguments* args);
static int32_t f_sys_recvfrom_e(struct event_filler_arguments* args);
static int32_t f_sys_recvfrom_x(struct event_filler_arguments* args);
static int32_t f_sys_recvmsg_e(struct event_filler_arguments* args);
static int32_t f_sys_recvmsg_x(struct event_filler_arguments* args);
static int32_t f_sys_shutdown_e(struct event_filler_arguments* args);
static int32_t f_sys_pipe_x(struct event_filler_arguments* args);
static int32_t f_sys_eventfd_e(struct event_filler_arguments* args);
static int32_t f_sys_futex_e(struct event_filler_arguments* args);
static int32_t f_sys_lseek_e(struct event_filler_arguments* args);
static int32_t f_sys_llseek_e(struct event_filler_arguments* args);
static int32_t f_sys_socket_bind_x(struct event_filler_arguments* args);
static int32_t f_sys_poll_e(struct event_filler_arguments* args);
static int32_t f_sys_poll_x(struct event_filler_arguments* args);
static int32_t f_sys_openat_e(struct event_filler_arguments* args);
#ifndef __x86_64__
static int32_t f_sys_pread64_e(struct event_filler_arguments* args);
static int32_t f_sys_preadv_e(struct event_filler_arguments* args);
#endif
static int32_t f_sys_writev_e(struct event_filler_arguments* args);
static int32_t f_sys_pwrite64_e(struct event_filler_arguments* args);
static int32_t f_sys_readv_x(struct event_filler_arguments* args);
static int32_t f_sys_writev_e(struct event_filler_arguments* args);
static int32_t f_sys_writev_pwritev_x(struct event_filler_arguments* args);
static int32_t f_sys_preadv_x(struct event_filler_arguments* args);
static int32_t f_sys_pwritev_e(struct event_filler_arguments* args);
static int32_t f_sys_nanosleep_e(struct event_filler_arguments* args);
static int32_t f_sys_getrlimit_setrlimit_e(struct event_filler_arguments* args);
static int32_t f_sys_getrlimit_setrlrimit_x(struct event_filler_arguments* args);
static int32_t f_sys_prlimit_e(struct event_filler_arguments* args);
static int32_t f_sys_prlimit_x(struct event_filler_arguments* args);
#ifdef CAPTURE_CONTEXT_SWITCHES
static int32_t f_sched_switch_e(struct event_filler_arguments* args);
#endif
static int32_t f_sched_drop(struct event_filler_arguments* args);
static int32_t f_sched_fcntl_e(struct event_filler_arguments* args);

//
// Note, this is not part of g_event_info because we want to share g_event_info with userland.
// However, separating this information in a different struct is not ideal and we should find a better way.
//
const struct ppm_event_entry g_ppm_events[PPM_EVENT_MAX] =
{
	[PPME_GENERIC_E] = {f_sys_generic},
	[PPME_GENERIC_X] = {f_sys_generic},
	[PPME_SYSCALL_OPEN_E] = {f_sys_empty},
	[PPME_SYSCALL_OPEN_X] = {f_sys_open_x},
	[PPME_SYSCALL_CREAT_E] = {f_sys_empty},
	[PPME_SYSCALL_CREAT_X] = {PPM_AUTOFILL, 3, APT_REG, {{AF_ID_RETVAL}, {0}, {AF_ID_USEDEFAULT, 0}}},
	[PPME_SYSCALL_CLOSE_E] = {f_sys_single},
	[PPME_SYSCALL_CLOSE_X] = {f_sys_single_x},
	[PPME_SYSCALL_READ_E] = {PPM_AUTOFILL, 2, APT_REG, {{0}, {2}}},
	[PPME_SYSCALL_READ_X] = {f_sys_read_x},
	[PPME_SYSCALL_WRITE_E] = {PPM_AUTOFILL, 2, APT_REG, {{0}, {2}}},
	[PPME_SYSCALL_WRITE_X] = {f_sys_write_x},
	[PPME_SYSCALL_BRK_E] = {PPM_AUTOFILL, 1, APT_REG, {{0}}},
	[PPME_SYSCALL_BRK_X] = {f_sys_single_x},
	[PPME_SYSCALL_EXECVE_E] = {f_sys_empty},
	[PPME_SYSCALL_EXECVE_X] = {f_proc_startupdate},
	[PPME_CLONE_E] = {f_sys_empty},
	[PPME_CLONE_X] = {f_proc_startupdate},
	[PPME_PROCEXIT_E] = {f_sys_empty},
	[PPME_SOCKET_SOCKET_E] = {PPM_AUTOFILL, 3, APT_SOCK, {{0}, {1}, {2}}},
	[PPME_SOCKET_SOCKET_X] = {f_sys_single_x},
	[PPME_SOCKET_SOCKETPAIR_E] = {PPM_AUTOFILL, 3, APT_SOCK, {{0}, {1}, {2}}},
	[PPME_SOCKET_SOCKETPAIR_X] = {f_sys_socketpair_x},
	[PPME_SOCKET_BIND_E] = {PPM_AUTOFILL, 1, APT_SOCK, {{0}}},
	[PPME_SOCKET_BIND_X] = {f_sys_socket_bind_x},
	[PPME_SOCKET_CONNECT_E] = {PPM_AUTOFILL, 1, APT_SOCK, {{0}}},
	[PPME_SOCKET_CONNECT_X] = {f_sys_connect_x},
	[PPME_SOCKET_LISTEN_E] = {PPM_AUTOFILL, 2, APT_SOCK, {{0}, {1}}},
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
	[PPME_SYSCALL_STAT_X] = {PPM_AUTOFILL, 2, APT_REG, {{AF_ID_RETVAL}, {0}}},
	[PPME_SYSCALL_LSTAT_E] = {f_sys_empty},
	[PPME_SYSCALL_LSTAT_X] = {PPM_AUTOFILL, 2, APT_REG, {{AF_ID_RETVAL}, {0}}},
	[PPME_SYSCALL_FSTAT_E] = {f_sys_single},
	[PPME_SYSCALL_FSTAT_X] = {f_sys_single_x},
	[PPME_SYSCALL_STAT64_E] = {f_sys_empty},
	[PPME_SYSCALL_STAT64_X] = {PPM_AUTOFILL, 2, APT_REG, {{AF_ID_RETVAL}, {0}}},
	[PPME_SYSCALL_LSTAT64_E] = {f_sys_empty},
	[PPME_SYSCALL_LSTAT64_X] = {PPM_AUTOFILL, 2, APT_REG, {{AF_ID_RETVAL}, {0}}},
	[PPME_SYSCALL_FSTAT64_E] = {f_sys_single},
	[PPME_SYSCALL_FSTAT64_X] = {f_sys_single_x},
	[PPME_SYSCALL_EPOLLWAIT_E] = {PPM_AUTOFILL, 1, APT_REG, {{2}}},
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
	[PPME_SYSCALL_IOCTL_E] = {PPM_AUTOFILL, 2, APT_REG, {{0}, {1}}},
	[PPME_SYSCALL_IOCTL_X] = {f_sys_single_x},
	[PPME_SYSCALL_GETCWD_E] = {f_sys_empty},
	[PPME_SYSCALL_GETCWD_X] = {PPM_AUTOFILL, 2, APT_REG, {{AF_ID_RETVAL}, {0}}},
	[PPME_SYSCALL_CHDIR_E] = {f_sys_empty},
	[PPME_SYSCALL_CHDIR_X] = {PPM_AUTOFILL, 2, APT_REG, {{AF_ID_RETVAL}, {0}}},
	[PPME_SYSCALL_FCHDIR_E] = {f_sys_single},
	[PPME_SYSCALL_FCHDIR_X] = {f_sys_single_x},
	[PPME_SYSCALL_MKDIR_E] = {PPM_AUTOFILL, 2, APT_REG, {{0}, {AF_ID_USEDEFAULT, 0}}},
	[PPME_SYSCALL_MKDIR_X] = {f_sys_single_x},
	[PPME_SYSCALL_RMDIR_E] = {f_sys_single},
	[PPME_SYSCALL_RMDIR_X] = {f_sys_single_x},
	[PPME_SYSCALL_OPENAT_E] = {f_sys_openat_e},
	[PPME_SYSCALL_OPENAT_X] = {f_sys_single_x},
	[PPME_SYSCALL_LINK_E] = {PPM_AUTOFILL, 2, APT_REG, {{0}, {1}}},
	[PPME_SYSCALL_LINK_X] = {f_sys_single_x},
	[PPME_SYSCALL_LINKAT_E] = {PPM_AUTOFILL, 4, APT_REG, {{0}, {1}, {2}, {3}}},
	[PPME_SYSCALL_LINKAT_X] = {f_sys_single_x},
	[PPME_SYSCALL_UNLINK_E] = {f_sys_single},
	[PPME_SYSCALL_UNLINK_X] = {f_sys_single_x},
	[PPME_SYSCALL_UNLINKAT_E] = {PPM_AUTOFILL, 2, APT_REG, {{0}, {1}}},
	[PPME_SYSCALL_UNLINKAT_X] = {f_sys_single_x},
#ifdef __x86_64__
	[PPME_SYSCALL_PREAD_E] = {PPM_AUTOFILL, 3, APT_REG, {{0}, {2}, {3}}},
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
#ifdef __x86_64__
	[PPME_SYSCALL_PREADV_E] = {PPM_AUTOFILL, 2, APT_REG, {{0}, {3}}},
#else
	[PPME_SYSCALL_PREADV_E] = {f_sys_preadv_e},
#endif
	[PPME_SYSCALL_PREADV_X] = {f_sys_preadv_x},
	[PPME_SYSCALL_PWRITEV_E] = {f_sys_pwritev_e},
	[PPME_SYSCALL_PWRITEV_X] = {f_sys_writev_pwritev_x},
	[PPME_SYSCALL_DUP_E] = {PPM_AUTOFILL, 1, APT_REG, {{0}}},
	[PPME_SYSCALL_DUP_X] = {f_sys_single_x},
	// Mask and Flags not implemented yet
	[PPME_SYSCALL_SIGNALFD_E] = {PPM_AUTOFILL, 3, APT_REG, {{0}, {AF_ID_USEDEFAULT, 0}, {AF_ID_USEDEFAULT, 0}}},
	[PPME_SYSCALL_SIGNALFD_X] = {f_sys_single_x},
	[PPME_SYSCALL_KILL_E] = {PPM_AUTOFILL, 2, APT_REG, {{0}, {1}}},
	[PPME_SYSCALL_KILL_X] = {f_sys_single_x},
	[PPME_SYSCALL_TKILL_E] = {PPM_AUTOFILL, 2, APT_REG, {{0}, {1}}},
	[PPME_SYSCALL_TKILL_X] = {f_sys_single_x},
	[PPME_SYSCALL_TGKILL_E] = {PPM_AUTOFILL, 3, APT_REG, {{0}, {1}, {2}}},
	[PPME_SYSCALL_TGKILL_X] = {f_sys_single_x},
	[PPME_SYSCALL_NANOSLEEP_E] = {f_sys_nanosleep_e},
	[PPME_SYSCALL_NANOSLEEP_X] = {f_sys_single_x},
	[PPME_SYSCALL_TIMERFD_CREATE_E] = {PPM_AUTOFILL, 2, APT_REG, {{AF_ID_USEDEFAULT, 0}, {AF_ID_USEDEFAULT, 0}}},
	[PPME_SYSCALL_TIMERFD_CREATE_X] = {f_sys_single_x},
	[PPME_SYSCALL_INOTIFY_INIT_E] = {PPM_AUTOFILL, 1, APT_REG, {{AF_ID_USEDEFAULT, 0}}},
	[PPME_SYSCALL_INOTIFY_INIT_X] = {f_sys_single_x},
	[PPME_SYSCALL_GETRLIMIT_E] = {f_sys_getrlimit_setrlimit_e},
	[PPME_SYSCALL_GETRLIMIT_X] = {f_sys_getrlimit_setrlrimit_x},
	[PPME_SYSCALL_SETRLIMIT_E] = {f_sys_getrlimit_setrlimit_e},
	[PPME_SYSCALL_SETRLIMIT_X] = {f_sys_getrlimit_setrlrimit_x},
	[PPME_SYSCALL_PRLIMIT_E] = {f_sys_prlimit_e},
	[PPME_SYSCALL_PRLIMIT_X] = {f_sys_prlimit_x},
#ifdef CAPTURE_CONTEXT_SWITCHES
	[PPME_SCHEDSWITCH_E] = {f_sched_switch_e},
#endif	
	[PPME_DROP_E] = {f_sched_drop},
	[PPME_DROP_X] = {f_sched_drop},
	[PPME_SYSCALL_FCNTL_E] = {f_sched_fcntl_e},
	[PPME_SYSCALL_FCNTL_X] = {f_sys_single_x},
};

extern uint32_t g_sampling_ratio;

//
// do-nothing implementation of compat_ptr for systems that are not compiled
// with CONFIG_COMPAT.
//
#ifndef CONFIG_COMPAT
#define compat_ptr(X) X
#endif

#define merge_64(hi, lo) ((((unsigned long long)(hi)) << 32) + ((lo) & 0xffffffffUL));

static int32_t f_sys_generic(struct event_filler_arguments* args)
{
	int32_t res;

#ifndef __x86_64__
	if(unlikely(args->syscall_id == __NR_socketcall))
	{
		//
		// All the socket calls should be implemented
		//
		ASSERT(false);
		return PPM_FAILURE_BUG;
	}
	else
	{
#endif // __x86_64__
		//
		// name
		//
		if(likely(args->syscall_id < SYSCALL_TABLE_SIZE))
		{
			ppm_syscall_code sc_code = g_syscall_code_routing_table[args->syscall_id];

			//
			// ID
			//
			res = val_to_ring(args, sc_code, 0, false);
			if(unlikely(res != PPM_SUCCESS))
			{
				return res;
			}

			if(args->event_type == PPME_GENERIC_E)
			{
				//
				// nativeID
				//
				res = val_to_ring(args, args->syscall_id, 0, false);
				if(unlikely(res != PPM_SUCCESS))
				{
					return res;
				}
			}
		}
		else
		{
			ASSERT(false);
			res = val_to_ring(args, (unsigned long)"<out of bound>", 0, false);
			if(unlikely(res != PPM_SUCCESS))
			{
				return res;
			}
		}
#ifndef __x86_64__
	}
#endif

	return add_sentinel(args);
}

static int32_t f_sys_empty(struct event_filler_arguments* args)
{
	return add_sentinel(args);
}

static int32_t f_sys_single(struct event_filler_arguments* args)
{
	int32_t res;
	unsigned long val;

	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static int32_t f_sys_single_x(struct event_filler_arguments* args)
{
	int32_t res;
	int64_t retval;

	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static inline uint32_t open_flags_to_scap(unsigned long flags)
{
	uint32_t res = 0;

	switch(flags & (O_RDONLY | O_WRONLY | O_RDWR))
	{
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

	if(flags & O_CREAT)
	{
		res |= PPM_O_CREAT;
	}

	if(flags & O_APPEND)
	{
		res |= PPM_O_APPEND;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
	if(flags & O_DSYNC)
	{
		res |= PPM_O_DSYNC;
	}
#endif

	if(flags & O_EXCL)
	{
		res |= PPM_O_EXCL;
	}

	if(flags & O_NONBLOCK)
	{
		res |= PPM_O_NONBLOCK;
	}

	if(flags & O_SYNC)
	{
		res |= PPM_O_SYNC;
	}

	if(flags & O_TRUNC)
	{
		res |= PPM_O_TRUNC;
	}

	if(flags & O_DIRECT)
	{
		res |= PPM_O_DIRECT;
	}

	if(flags & O_DIRECTORY)
	{
		res |= PPM_O_DIRECTORY;
	}

	if(flags & O_LARGEFILE)
	{
		res |= PPM_O_LARGEFILE;
	}

	return res;
}

static int32_t f_sys_open_x(struct event_filler_arguments* args)
{
	unsigned long val;
	int32_t res;
	int64_t retval;

	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// name
	//
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, true);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// Flags
	// Note that we convert them into the ppm portable representation before pushing them to the ring
	//
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, open_flags_to_scap(val), 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// Mode
	// XXX: at this time, mode decoding is not supported. We nonetheless return a value (zero)
	//      so the format of the event is ready for when we'll export the mode in the future.
	//
	//syscall_get_arguments(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, 0, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static int32_t f_sys_read_x(struct event_filler_arguments* args)
{
	unsigned long val;
	int32_t res;
	int64_t retval;
	unsigned long bufsize;
	unsigned int snaplen;

	//
	// res
	//
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// data
	//
	if(retval < 0)
	{
		//
		// The operation failed, return an empty buffer
		//
		val = 0;
		bufsize = 0;
	}
	else
	{
		syscall_get_arguments(current, args->regs, 1, 1, &val);

		//
		// The return value can be lower than the value provided by the user,
		// and we take that into account.
		//
		bufsize = retval;
	}

	//
	// Determine the snaplen by checking the fd type.
	// (note: not implemeted yet)
	//
	snaplen = g_snaplen;	
#if 0
	{
		int fd;
		int err, fput_needed;
		struct socket *sock;

		syscall_get_arguments(current, args->regs, 0, 1, &val);
		fd = (int)val;

		sock = ppm_sockfd_lookup_light(fd, &err, &fput_needed);
		if(sock)
		{
			snaplen = g_snaplen;
			fput_light(sock->file, fput_needed);
		}
		else
		{
			snaplen = RW_SNAPLEN;
		}
	}
#endif

	//
	// Copy the buffer
	//
	res = val_to_ring(args, val, min(bufsize, (unsigned long)snaplen), true);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static int32_t f_sys_write_x(struct event_filler_arguments* args)
{
	unsigned long val;
	int32_t res;
	int64_t retval;
	unsigned long bufsize;
	unsigned int snaplen;

	//
	// res
	//
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// data
	//
	syscall_get_arguments(current, args->regs, 2, 1, &val);
	bufsize = val;

	//
	// Determine the snaplen by checking the fd type.
	// (note: not implemeted yet)
	//
	snaplen = g_snaplen;	
#if 0
	{
		int fd;
		int err, fput_needed;
		struct socket *sock;
	
		syscall_get_arguments(current, args->regs, 0, 1, &val);
		fd = (int)val;

		sock = ppm_sockfd_lookup_light(fd, &err, &fput_needed);
		if(sock)
		{
			snaplen = g_snaplen;
			fput_light(sock->file, fput_needed);
		}
		else
		{
			snaplen = RW_SNAPLEN;
		}
	}
#endif

	//
	// Copy the buffer
	//
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, min(bufsize, (unsigned long)snaplen), true);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static inline uint32_t clone_flags_to_scap(unsigned long flags)
{
	uint32_t res = 0;

	if(flags & CLONE_FILES)
	{
		res |= PPM_CL_CLONE_FILES;
	}

	if(flags & CLONE_FS)
	{
		res |= PPM_CL_CLONE_FS;
	}

	if(flags & CLONE_IO)
	{
		res |= PPM_CL_CLONE_IO;
	}

	if(flags & CLONE_NEWIPC)
	{
		res |= PPM_CL_CLONE_NEWIPC;
	}

	if(flags & CLONE_NEWNET)
	{
		res |= PPM_CL_CLONE_NEWNET;
	}

	if(flags & CLONE_NEWNS)
	{
		res |= PPM_CL_CLONE_NEWNS;
	}

	if(flags & CLONE_NEWPID)
	{
		res |= PPM_CL_CLONE_NEWPID;
	}

	if(flags & CLONE_NEWUTS)
	{
		res |= PPM_CL_CLONE_NEWUTS;
	}

	if(flags & CLONE_PARENT_SETTID)
	{
		res |= PPM_CL_CLONE_PARENT_SETTID;
	}

	if(flags & CLONE_PARENT)
	{
		res |= PPM_CL_CLONE_PARENT;
	}

	if(flags & CLONE_PTRACE)
	{
		res |= PPM_CL_CLONE_PTRACE;
	}

	if(flags & CLONE_SIGHAND)
	{
		res |= PPM_CL_CLONE_SIGHAND;
	}

	if(flags & CLONE_SYSVSEM)
	{
		res |= PPM_CL_CLONE_SYSVSEM;
	}

	if(flags & CLONE_THREAD)
	{
		res |= PPM_CL_CLONE_THREAD;
	}

	if(flags & CLONE_UNTRACED)
	{
		res |= PPM_CL_CLONE_UNTRACED;
	}

	if(flags & CLONE_VM)
	{
		res |= PPM_CL_CLONE_VM;
	}

	return res;
}

static int32_t f_proc_startupdate(struct event_filler_arguments* args)
{
	unsigned long val;
	int res = 0;
	unsigned int exe_len = 0;
	unsigned int args_len = 0;
	struct mm_struct* mm = current->mm;
	int64_t retval;
	const char* argstr;
	int ptid;
	char* spwd;

	trace_enter();

	//
	// Make sure the operation was successful
	//
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	if(likely(retval >= 0))
	{
		if(unlikely(!mm))
		{
			args->str_storage[0] = 0;
			printk(KERN_INFO "sysdig-probe: f_proc_startupdate drop, mm=NULL\n");
			return PPM_FAILURE_BUG;
		}
		if(unlikely(!mm->arg_end))
		{
			args->str_storage[0] = 0;
			printk(KERN_INFO "sysdig-probe: f_proc_startupdate drop, mm->arg_end=NULL\n");
			return PPM_FAILURE_BUG;
		}

		args_len = mm->arg_end - mm->arg_start;

		if(args_len > PAGE_SIZE)
		{
			args_len = PAGE_SIZE;
		}

		if(unlikely(ppm_copy_from_user(args->str_storage, (const void*) mm->arg_start, args_len)))
		{
			return PPM_FAILURE_INVALID_USER_MEMORY;
		}

		args->str_storage[args_len - 1] = 0;

		exe_len = strnlen(args->str_storage, args_len);
		if(exe_len < args_len)
		{
			++exe_len;
		}
	}
	else
	{
		//
		// The call failed. Return empty strings for exe and args
		//
		*args->str_storage = 0;
		argstr = "";
	}

	//
	// exe
	//
	res = val_to_ring(args, (uint64_t)(long)args->str_storage, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// Args
	//
	res = val_to_ring(args, (int64_t)(long)args->str_storage + exe_len, args_len - exe_len, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// tid
	//
	res = val_to_ring(args, (int64_t)current->pid, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// pid
	//
	res = val_to_ring(args, (int64_t)current->tgid, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// ptid
	//
	if(current->real_parent)
	{
		ptid = current->parent->pid;
	}
	else
	{
		ptid = 0;
	}

	res = val_to_ring(args, (int64_t)ptid, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// cwd
	//
	spwd = npm_getcwd(args->str_storage, STR_STORAGE_SIZE - 1);
	if(spwd == NULL)
	{
		spwd = "";
	}

	res = val_to_ring(args, (uint64_t)(long)spwd, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// fdlimit
	//
	res = val_to_ring(args, (int64_t)rlimit(RLIMIT_NOFILE), 0, false);
	if(res != PPM_SUCCESS)
	{
		return res;
	}

	//
	// clone-only parameters
	//
	if(args->event_type == PPME_CLONE_X)
	{
		//
		// flags
		//
		syscall_get_arguments(current, args->regs, 0, 1, &val);
		res = val_to_ring(args, (uint64_t)clone_flags_to_scap(val), 0, false);
		if(unlikely(res != PPM_SUCCESS))
		{
			return res;
		}

		//
		// uid
		//
		syscall_get_arguments(current, args->regs, 0, 1, &val);
		res = val_to_ring(args, (uint64_t)current->cred->euid, 0, false);
		if(unlikely(res != PPM_SUCCESS))
		{
			return res;
		}

		//
		// gid
		//
		syscall_get_arguments(current, args->regs, 0, 1, &val);
		res = val_to_ring(args, (uint64_t)current->cred->egid, 0, false);
		if(unlikely(res != PPM_SUCCESS))
		{
			return res;
		}
	}

	return add_sentinel(args);
}

static int32_t f_sys_socket_bind_x(struct event_filler_arguments* args)
{
	int32_t res;
	int64_t retval;
	int err = 0;
	uint16_t size = 0;
	struct sockaddr __user* usrsockaddr;
	unsigned long val;
	struct sockaddr_storage address;
	char* targetbuf = args->str_storage;

	//
	// res
	//
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false);

	//
	// addr
	//
#ifdef __x86_64__
	syscall_get_arguments(current, args->regs, 1, 1, &val);
#else
	val = args->socketcall_args[1];
#endif
	usrsockaddr = (struct sockaddr __user*)val;

	//
	// Get the address len
	//
#ifdef __x86_64__
	syscall_get_arguments(current, args->regs, 2, 1, &val);
#else
	val = args->socketcall_args[2];
#endif

	if(usrsockaddr != NULL && val != 0)
	{
		//
		// Copy the address
		//
		err = addr_to_kernel(usrsockaddr, val, (struct sockaddr *)&address);
		if(likely(err >= 0))
		{
			//
			// Convert the fd into socket endpoint information
			//
			size = pack_addr((struct sockaddr *)&address,
				val,
				targetbuf, 
				STR_STORAGE_SIZE);
		}
	}

	//
	// Copy the endpoint info into the ring
	//
	res = val_to_ring(args,
	                    (uint64_t)(unsigned long)targetbuf,
	                    size,
	                    false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static int32_t f_sys_connect_x(struct event_filler_arguments* args)
{
	int32_t res;
	int64_t retval;
	int err = 0;
	int fd;
	struct sockaddr __user* usrsockaddr;
	uint16_t size = 0;
	char* targetbuf = args->str_storage;
	struct sockaddr_storage address;
	unsigned long val;

	//
	// Push the result
	//
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false);

	//
	// Retrieve the fd and push it to the ring.
	// Note that, even if we are in the exit callback, the arguments are still
	// in the stack, and therefore we can consume them.
	//
#ifdef __x86_64__
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	fd = (int)val;
#else
	fd = (int)args->socketcall_args[0];
#endif

	if(fd >= 0)
	{
		//
		// Get the address
		//
#ifdef __x86_64__
		syscall_get_arguments(current, args->regs, 1, 1, &val);
#else
		val = args->socketcall_args[1];
#endif
		usrsockaddr = (struct sockaddr __user*)val;

		//
		// Get the address len
		//
#ifdef __x86_64__
		syscall_get_arguments(current, args->regs, 2, 1, &val);
#else
		val = args->socketcall_args[2];
#endif

		if(usrsockaddr != NULL && val != 0)
		{
			//
			// Copy the address
			//
			err = addr_to_kernel(usrsockaddr, val, (struct sockaddr *)&address);
			if(likely(err >= 0))
			{
				//
				// Convert the fd into socket endpoint information
				//
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

	//
	// Copy the endpoint info into the ring
	//
	res = val_to_ring(args,
	                    (uint64_t)(unsigned long)targetbuf,
	                    size,
	                    false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static int32_t f_sys_socketpair_x(struct event_filler_arguments* args)
{
	int32_t res;
	int64_t retval;
	unsigned long val;
	int fds[2];
	int err;
	struct socket* sock;
	struct unix_sock* us;
	struct sock* speer;


	//
	// retval
	//
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// If the call was succesful, copy the FDs
	//
	if(likely(retval >= 0))
	{
		//
		// fds
		//
#ifdef __x86_64__
		syscall_get_arguments(current, args->regs, 3, 1, &val);
#else
		val = args->socketcall_args[3];
#endif
		if(unlikely(ppm_copy_from_user(fds, (const void*)val, sizeof(fds))))
		{
			return PPM_FAILURE_INVALID_USER_MEMORY;
		}

		res = val_to_ring(args, fds[0], 0, false);
		if(unlikely(res != PPM_SUCCESS))
		{
			return res;
		}

		res = val_to_ring(args, fds[1], 0, false);
		if(unlikely(res != PPM_SUCCESS))
		{
			return res;
		}

		// get socket source and peer address
		sock = sockfd_lookup(fds[0], &err);
		if(likely(sock != NULL))
		{
			us = unix_sk(sock->sk);
			speer = us->peer;
			res = val_to_ring(args, (unsigned long)us, 0, false);
			if(unlikely(res != PPM_SUCCESS))
			{
				sockfd_put(sock);
				return res;
			}
			res = val_to_ring(args, (unsigned long)speer, 0, false);
			if(unlikely(res != PPM_SUCCESS))
			{
				sockfd_put(sock);
				return res;
			}

			sockfd_put(sock);
		}
		else
		{
			return err;
		}
	}
	else
	{
		res = val_to_ring(args, 0, 0, false);
		if(unlikely(res != PPM_SUCCESS))
		{
			return res;
		}

		res = val_to_ring(args, 0, 0, false);
		if(unlikely(res != PPM_SUCCESS))
		{
			return res;
		}
	}

	return add_sentinel(args);
}

static int32_t f_sys_accept4_e(struct event_filler_arguments* args)
{
	int32_t res;

	//
	// push the flags into the ring.
	// XXX we don't support flags yet and so we just return zero
	//
//	res = val_to_ring(args, args->socketcall_args[3]);
	res = val_to_ring(args, 0, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static int32_t f_sys_accept_x(struct event_filler_arguments* args)
{
	int32_t res;
	int fd;
	char* targetbuf = args->str_storage;
	uint16_t size = 0;
	unsigned long val;
	unsigned long srvskfd;
	int err = 0;
	struct socket* sock;

	//
	// Push the fd
	//
	fd = syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, (int64_t)fd, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// Convert the fd into socket endpoint information
	//
	size = fd_to_socktuple(fd,
		NULL,
		0,
		false,
		true, 
		targetbuf, 
		STR_STORAGE_SIZE);

	//
	// Copy the endpoint info into the ring
	//
	res = val_to_ring(args,
	                    (uint64_t)(unsigned long)targetbuf,
	                    size,
	                    false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// queuepct
	//
#ifdef __x86_64__
	syscall_get_arguments(current, args->regs, 0, 1, &srvskfd);
#else
	srvskfd = args->socketcall_args[0];
#endif
	sock = sockfd_lookup(srvskfd, &err);

	if(unlikely(!sock || !(sock->sk)))
	{
		val = 0;
		
		if(sock)
		{
			sockfd_put(sock);			
		}
	}
	else
	{
		val = (unsigned long)sock->sk->sk_ack_backlog * 100 / sock->sk->sk_max_ack_backlog;
		sockfd_put(sock);
	}

	res = val_to_ring(args, val, 0, false);
	if(res != PPM_SUCCESS)
	{
		return res;
	}	

	return add_sentinel(args);
}

static int32_t f_sys_send_e_common(struct event_filler_arguments* args, int* fd)
{
	int32_t res;
	unsigned long size;
	unsigned long val;

	//
	// fd
	//
#ifdef __x86_64__
	syscall_get_arguments(current, args->regs, 0, 1, &val);
#else
	val = args->socketcall_args[0];
#endif
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	*fd = val;

	//
	// size
	//
#ifdef __x86_64__
	syscall_get_arguments(current, args->regs, 2, 1, &size);
#else
	size = args->socketcall_args[2];
#endif
	res = val_to_ring(args, size, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return PPM_SUCCESS;
}

static int32_t f_sys_send_e(struct event_filler_arguments* args)
{
	int32_t res;
	int fd;

	res = f_sys_send_e_common(args, &fd);

	if(likely(res == PPM_SUCCESS))
	{
		return add_sentinel(args);
	}
	else
	{
		return res;
	}
}

static int32_t f_sys_sendto_e(struct event_filler_arguments* args)
{
	unsigned long val;
	int32_t res;
	uint16_t size = 0;
	char* targetbuf = args->str_storage;
	int fd;
	struct sockaddr __user* usrsockaddr;
	struct sockaddr_storage address;
	int err = 0;

	*targetbuf = 250;

	//
	// Push the common params to the ring
	//
	res = f_sys_send_e_common(args, &fd);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// Get the address
	//
#ifdef __x86_64__
	syscall_get_arguments(current, args->regs, 4, 1, &val);
#else
	val = args->socketcall_args[4];
#endif
	usrsockaddr = (struct sockaddr __user*)val;

	//
	// Get the address len
	//
#ifdef __x86_64__
	syscall_get_arguments(current, args->regs, 5, 1, &val);
#else
	val = args->socketcall_args[5];
#endif

	if(usrsockaddr != NULL && val != 0)
	{
		//
		// Copy the address
		//
		err = addr_to_kernel(usrsockaddr, val, (struct sockaddr *)&address);
		if(likely(err >= 0))
		{
			//
			// Convert the fd into socket endpoint information
			//
			size = fd_to_socktuple(fd, 
				(struct sockaddr *)&address,
				val,
				true,
				false, 
				targetbuf, 
				STR_STORAGE_SIZE);
		}
	}

	//
	// Copy the endpoint info into the ring
	//
	res = val_to_ring(args,
	                    (uint64_t)(unsigned long)targetbuf,
	                    size,
	                    false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static int32_t f_sys_send_x(struct event_filler_arguments* args)
{
	unsigned long val;
	int32_t res;
	int64_t retval;
	unsigned long bufsize;

	//
	// res
	//
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// data
	//
	if(retval < 0)
	{
		//
		// The operation failed, return an empty buffer
		//
		val = 0;
		bufsize = 0;
	}
	else
	{
#ifdef __x86_64__
		syscall_get_arguments(current, args->regs, 1, 1, &val);
#else
		val = args->socketcall_args[1];
#endif

		//
		// The return value can be lower than the value provided by the user,
		// and we take that into account.
		//
		bufsize = retval;
	}

	res = val_to_ring(args, val, min(bufsize, (unsigned long)g_snaplen), true);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static int32_t f_sys_recv_e_common(struct event_filler_arguments* args)
{
	int32_t res;
	unsigned long val;

	//
	// fd
	//
#ifdef __x86_64__
	syscall_get_arguments(current, args->regs, 0, 1, &val);
#else
	val = args->socketcall_args[0];
#endif
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// size
	//
#ifdef __x86_64__
	syscall_get_arguments(current, args->regs, 2, 1, &val);
#else
	val = args->socketcall_args[2];
#endif
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return PPM_SUCCESS;
}

static int32_t f_sys_recv_e(struct event_filler_arguments* args)
{
	int32_t res;

	res = f_sys_recv_e_common(args);

	if(likely(res == PPM_SUCCESS))
	{
		return add_sentinel(args);
	}
	else
	{
		return res;
	}
}

static int32_t f_sys_recvfrom_e(struct event_filler_arguments* args)
{
	int32_t res;

	res = f_sys_recv_e_common(args);
	if(likely(res == PPM_SUCCESS))
	{
		return add_sentinel(args);
	}
	else
	{
		return res;
	}
}

static int32_t f_sys_recv_x_common(struct event_filler_arguments* args, int64_t* retval)
{
	int32_t res;
	unsigned long val;
	unsigned long bufsize;

	//
	// res
	//
	*retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, *retval, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// data
	//
	if(*retval < 0)
	{
		//
		// The operation failed, return an empty buffer
		//
		val = 0;
		bufsize = 0;
	}
	else
	{
#ifdef __x86_64__
		syscall_get_arguments(current, args->regs, 1, 1, &val);
#else
		val = args->socketcall_args[1];
#endif

		//
		// The return value can be lower than the value provided by the user,
		// and we take that into account.
		//
		bufsize = *retval;
	}

	res = val_to_ring(args, val, min(bufsize, (unsigned long)g_snaplen), true);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return PPM_SUCCESS;
}

static int32_t f_sys_recv_x(struct event_filler_arguments* args)
{
	int32_t res;
	int64_t retval;

	res = f_sys_recv_x_common(args, &retval);

	if(likely(res == PPM_SUCCESS))
	{
		return add_sentinel(args);
	}
	else
	{
		return res;
	}
}

static int32_t f_sys_recvfrom_x(struct event_filler_arguments* args)
{
	unsigned long val;
	int32_t res;
	uint16_t size = 0;
	int64_t retval;
	char* targetbuf = args->str_storage;
	int fd;
	struct sockaddr __user* usrsockaddr;
	struct sockaddr_storage address;
	int addrlen;
	int err = 0;

	//
	// Push the common params to the ring
	//
	res = f_sys_recv_x_common(args, &retval);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	if(retval >= 0)
	{
		//
		// Get the fd
		//
#ifdef __x86_64__
		syscall_get_arguments(current, args->regs, 0, 1, &val);
		fd = (int)val;
#else
		fd = (int)args->socketcall_args[0];
#endif

		//
		// Get the address
		//
#ifdef __x86_64__
		syscall_get_arguments(current, args->regs, 4, 1, &val);
#else
		val = args->socketcall_args[4];
#endif
		usrsockaddr = (struct sockaddr __user*)val;

		//
		// Get the address len
		//
#ifdef __x86_64__
		syscall_get_arguments(current, args->regs, 5, 1, &val);
#else
		val = args->socketcall_args[5];
#endif
		if(usrsockaddr != NULL && val != 0)
		{
			if(unlikely(ppm_copy_from_user(&addrlen, (const void*)val, sizeof(addrlen))))
			{
				return PPM_FAILURE_INVALID_USER_MEMORY;
			}

			//
			// Copy the address
			//
			err = addr_to_kernel(usrsockaddr, addrlen, (struct sockaddr *)&address);
			if(likely(err >= 0))
			{
				//
				// Convert the fd into socket endpoint information
				//
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

	//
	// Copy the endpoint info into the ring
	//
	res = val_to_ring(args,
	                    (uint64_t)(unsigned long)targetbuf,
	                    size,
	                    false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static int32_t f_sys_sendmsg_e(struct event_filler_arguments* args)
{
	int32_t res;
	unsigned long val;
	struct msghdr mh;
	char* targetbuf = args->str_storage;
	const struct iovec* iov;
	unsigned long iovcnt;
	int fd;
	uint16_t size = 0;
	int addrlen;
	int err = 0;
	struct sockaddr __user* usrsockaddr;
	struct sockaddr_storage address;

	//
	// fd
	//
#ifdef __x86_64__
	syscall_get_arguments(current, args->regs, 0, 1, &val);
#else
	val = args->socketcall_args[0];
#endif
	fd = val;
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// Retrieve the message header
	//
#ifdef __x86_64__
	syscall_get_arguments(current, args->regs, 1, 1, &val);
#else
	val = args->socketcall_args[1];
#endif

	if(unlikely(ppm_copy_from_user(&mh, (const void*)val, sizeof(struct msghdr))))
	{
		return PPM_FAILURE_INVALID_USER_MEMORY;
	}

	//
	// size
	//
	iov = mh.msg_iov;
	iovcnt = mh.msg_iovlen;

	res = parse_readv_writev_bufs(args, iov, iovcnt, g_snaplen, PRB_FLAG_PUSH_SIZE);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// tuple
	//
	usrsockaddr = (struct sockaddr __user*)mh.msg_name;
	addrlen = mh.msg_namelen;

	if(usrsockaddr != NULL && addrlen != 0)
	{
		//
		// Copy the address
		//
		err = addr_to_kernel(usrsockaddr, addrlen, (struct sockaddr *)&address);
		if(likely(err >= 0))
		{
			//
			// Convert the fd into socket endpoint information
			//
			size = fd_to_socktuple(fd, 
				(struct sockaddr *)&address,
				addrlen,
				true,
				false, 
				targetbuf, 
				STR_STORAGE_SIZE);
		}
	}

	// Copy the endpoint info into the ring
	res = val_to_ring(args,
	                    (uint64_t)(unsigned long)targetbuf,
	                    size,
	                    false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static int32_t f_sys_sendmsg_x(struct event_filler_arguments* args)
{
	int32_t res;
	unsigned long val;
	int64_t retval;
	const struct iovec* iov;
	unsigned long iovcnt;
	struct msghdr mh;

	//
	// res
	//
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// Retrieve the message header
	//
#ifdef __x86_64__
	syscall_get_arguments(current, args->regs, 1, 1, &val);
#else
	val = args->socketcall_args[1];
#endif

	if(unlikely(ppm_copy_from_user(&mh, (const void*)val, sizeof(struct msghdr))))
	{
		return PPM_FAILURE_INVALID_USER_MEMORY;
	}

	//
	// data
	//
	iov = mh.msg_iov;
	iovcnt = mh.msg_iovlen;

	res = parse_readv_writev_bufs(args, iov, iovcnt, g_snaplen, PRB_FLAG_PUSH_DATA);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static int32_t f_sys_recvmsg_e(struct event_filler_arguments* args)
{
	int32_t res;
	unsigned long val;

	//
	// fd
	//
#ifdef __x86_64__
	syscall_get_arguments(current, args->regs, 0, 1, &val);
#else
	val = args->socketcall_args[0];
#endif
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static int32_t f_sys_recvmsg_x(struct event_filler_arguments* args)
{
	int32_t res;
	unsigned long val;
	int64_t retval;
	const struct iovec* iov;
	unsigned long iovcnt;
	struct msghdr mh;
	char* targetbuf = args->str_storage;
	int fd;
	struct sockaddr __user* usrsockaddr;
	struct sockaddr_storage address;
	uint16_t size = 0;
	int addrlen;
	int err = 0;

	//
	// res
	//
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// Retrieve the message header
	//
#ifdef __x86_64__
	syscall_get_arguments(current, args->regs, 1, 1, &val);
#else
	val = args->socketcall_args[1];
#endif

	if(unlikely(ppm_copy_from_user(&mh, (const void*)val, sizeof(struct msghdr))))
	{
		return PPM_FAILURE_INVALID_USER_MEMORY;
	}

	//
	// data and size
	//
	iov = mh.msg_iov;
	iovcnt = mh.msg_iovlen;

	res = parse_readv_writev_bufs(args, iov, iovcnt, retval, PRB_FLAG_PUSH_ALL);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// tuple
	//
	if(retval >= 0)
	{
		//
		// Get the fd
		//
#ifdef __x86_64__
		syscall_get_arguments(current, args->regs, 0, 1, &val);
		fd = (int)val;
#else
		fd = (int)args->socketcall_args[0];
#endif

		//
		// Get the address
		//
		usrsockaddr = (struct sockaddr __user*)mh.msg_name;
		addrlen = mh.msg_namelen;

		if(usrsockaddr != NULL && addrlen != 0)
		{
			//
			// Copy the address
			//
			err = addr_to_kernel(usrsockaddr, addrlen, (struct sockaddr *)&address);
			if(likely(err >= 0))
			{
				//
				// Convert the fd into socket endpoint information
				//
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

	// Copy the endpoint info into the ring
	res = val_to_ring(args,
	                    (uint64_t)(unsigned long)targetbuf,
	                    size,
	                    false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}


static int32_t f_sys_pipe_x(struct event_filler_arguments* args)
{
	int32_t res;
	int64_t retval;
	unsigned long val;
	int fds[2];
	struct file* file;

	//
	// retval
	//
	retval = (int64_t)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// fds
	//
	syscall_get_arguments(current, args->regs, 0, 1, &val);

	if(unlikely(ppm_copy_from_user(fds, (const void*)val, sizeof(fds))))
	{
		return PPM_FAILURE_INVALID_USER_MEMORY;
	}

	res = val_to_ring(args, fds[0], 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	res = val_to_ring(args, fds[1], 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	file = fget(fds[0]);
	val = 0;
	if(likely(file != NULL))
	{
		val = file->f_dentry->d_inode->i_ino;
		fput(file);
	}
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static int32_t f_sys_eventfd_e(struct event_filler_arguments* args)
{
	int32_t res;
	unsigned long val;

	//
	// initval
	//
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// flags
	// XXX not implemented yet
	//
//	syscall_get_arguments(current, args->regs, 1, 1, &val);
	val = 0;
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static inline uint16_t shutdown_how_to_scap(unsigned long how)
{
	if(how == SHUT_RD)
	{
		return PPM_SHUT_RD;
	}
	else if(how == SHUT_WR)
	{
		return SHUT_WR;
	}
	else if(how == SHUT_RDWR)
	{
		return SHUT_RDWR;
	}
	else
	{
		ASSERT(false);
		return (uint16_t)how;
	}
}

static int32_t f_sys_shutdown_e(struct event_filler_arguments* args)
{
	int32_t res;
	unsigned long val;

	//
	// fd
	//
#ifdef __x86_64__
	syscall_get_arguments(current, args->regs, 0, 1, &val);
#else
	val = args->socketcall_args[0];
#endif
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// how
	//
#ifdef __x86_64__
	syscall_get_arguments(current, args->regs, 1, 1, &val);
#else
	val = args->socketcall_args[1];
#endif
	res = val_to_ring(args, (unsigned long)shutdown_how_to_scap(val), 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static inline uint16_t futex_op_to_scap(unsigned long op)
{
	uint16_t res = 0;
	unsigned long flt_op = op & 127;

	if(flt_op == FUTEX_WAIT)
	{
		res = PPM_FU_FUTEX_WAIT;
	}
	else if(flt_op == FUTEX_WAKE)
	{
		res = PPM_FU_FUTEX_WAKE;
	}
	else if(flt_op == FUTEX_FD)
	{
		res = PPM_FU_FUTEX_FD;
	}
	else if(flt_op == FUTEX_REQUEUE)
	{
		res = PPM_FU_FUTEX_REQUEUE;
	}
	else if(flt_op == FUTEX_CMP_REQUEUE)
	{
		res = PPM_FU_FUTEX_CMP_REQUEUE;
	}
	else if(flt_op == FUTEX_WAKE_OP)
	{
		res = PPM_FU_FUTEX_WAKE_OP;
	}
	else if(flt_op == FUTEX_LOCK_PI)
	{
		res = PPM_FU_FUTEX_LOCK_PI;
	}
	else if(flt_op == FUTEX_UNLOCK_PI)
	{
		res = PPM_FU_FUTEX_UNLOCK_PI;
	}
	else if(flt_op == FUTEX_TRYLOCK_PI)
	{
		res = PPM_FU_FUTEX_TRYLOCK_PI;
	}
	else if(flt_op == FUTEX_WAIT_BITSET)
	{
		res = PPM_FU_FUTEX_WAIT_BITSET;
	}
	else if(flt_op == FUTEX_WAKE_BITSET)
	{
		res = PPM_FU_FUTEX_WAKE_BITSET;
	}
	else if(flt_op == FUTEX_WAIT_REQUEUE_PI)
	{
		res = PPM_FU_FUTEX_WAIT_REQUEUE_PI;
	}
	else if(flt_op == FUTEX_CMP_REQUEUE_PI)
	{
		res = PPM_FU_FUTEX_CMP_REQUEUE_PI;
	}

	if(op & FUTEX_PRIVATE_FLAG)
	{
		res |= PPM_FU_FUTEX_PRIVATE_FLAG;
	}

	if(op & FUTEX_CLOCK_REALTIME)
	{
		res |= PPM_FU_FUTEX_CLOCK_REALTIME;
	}

	return res;
}

static int32_t f_sys_futex_e(struct event_filler_arguments* args)
{
	int32_t res;
	unsigned long val;

	//
	// addr
	//
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// op
	//
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, (unsigned long)futex_op_to_scap(val), 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// val
	//
	syscall_get_arguments(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static inline uint64_t lseek_whence_to_scap(unsigned long whence)
{
	uint64_t res = 0;

	if(whence == SEEK_SET)
	{
		res = PPM_SEEK_SET;
	}
	else if(whence == SEEK_CUR)
	{
		res = PPM_SEEK_CUR;
	}
	else if(whence == SEEK_END)
	{
		res = PPM_SEEK_END;
	}

	return res;
}

static int32_t f_sys_lseek_e(struct event_filler_arguments* args)
{
	unsigned long val;
	int32_t res;

	//
	// fd
	//
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// offset
	//
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// whence
	//
	syscall_get_arguments(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, lseek_whence_to_scap(val), 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static int32_t f_sys_llseek_e(struct event_filler_arguments* args)
{
	unsigned long val;
	int32_t res;
	unsigned long oh;
	unsigned long ol;
	uint64_t offset;

	//
	// fd
	//
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// offset
	// We build it by combining the offset_high and offset_low system call arguments
	//
	syscall_get_arguments(current, args->regs, 1, 1, &oh);
	syscall_get_arguments(current, args->regs, 2, 1, &ol);
	offset = (((uint64_t)oh) << 32) + ((uint64_t)ol);
	res = val_to_ring(args, offset, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// whence
	//
	syscall_get_arguments(current, args->regs, 4, 1, &val);
	res = val_to_ring(args, lseek_whence_to_scap(val), 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

// XXX this is very basic for the moment, we'll need to improve it
static inline uint16_t poll_events_to_scap(short revents)
{
	uint16_t res = 0;

	if(revents & POLLIN)
	{
		res |= PPM_POLLIN;
	}

	if(revents & PPM_POLLPRI)
	{
		res |= PPM_POLLPRI;
	}

	if(revents & POLLOUT)
	{
		res |= PPM_POLLOUT;
	}

	if(revents & POLLRDHUP)
	{
		res |= PPM_POLLRDHUP;
	}

	if(revents & POLLERR)
	{
		res |= PPM_POLLERR;
	}

	if(revents & POLLHUP)
	{
		res |= PPM_POLLHUP;
	}

	if(revents & POLLNVAL)
	{
		res |= PPM_POLLNVAL;
	}

	if(revents & POLLRDNORM)
	{
		res |= PPM_POLLRDNORM;
	}

	if(revents & POLLRDBAND)
	{
		res |= PPM_POLLRDBAND;
	}

	if(revents & POLLWRNORM)
	{
		res |= PPM_POLLWRNORM;
	}

	if(revents & POLLWRBAND)
	{
		res |= PPM_POLLWRBAND;
	}

	return res;
}

static int32_t poll_parse_fds(struct event_filler_arguments* args, bool enter_event)
{
	struct pollfd* fds;
	char* targetbuf;
	unsigned long val;
	unsigned long nfds;
	unsigned long fds_count;
	uint32_t j;
	uint32_t pos;
	uint16_t flags;

	//
	// fds
	//
	// Get the number of fds
	syscall_get_arguments(current, args->regs, 1, 1, &nfds);

	//
	// Check if we have enough space to store both the fd list
	// from user space and the temporary buffer to serialize to the ring
	//
	if(unlikely(sizeof(struct pollfd) * nfds + 2 + 10 * nfds > STR_STORAGE_SIZE))
	{
		return PPM_FAILURE_BUFFER_FULL;
	}

	// Get the fds pointer
	syscall_get_arguments(current, args->regs, 0, 1, &val);

	fds = (struct pollfd*)args->str_storage;
	if(unlikely(ppm_copy_from_user(fds, (const void*)val, nfds * sizeof(struct pollfd))))
	{
		return PPM_FAILURE_INVALID_USER_MEMORY;
	}

	pos = 2;
	targetbuf = args->str_storage + nfds * sizeof(struct pollfd) + pos;
	fds_count = 0;

	// Copy each fd into the temporary buffer
	for(j = 0; j < nfds; j++)
	{
		if(enter_event)
		{
			flags = poll_events_to_scap(fds[j].events);
		}
		else
		{
			//
			// If it's an exit event, we copy only the fds that
			// returned something
			//
			if(!fds[j].revents)
			{
				continue;
			}

			flags = poll_events_to_scap(fds[j].revents);			
		}

		*(int64_t*)(targetbuf + pos) = fds[j].fd;
		*(int16_t*)(targetbuf + pos + 8) = flags;
		pos += 10;
		++fds_count;
	}

	*(uint16_t*)(targetbuf) = (uint16_t)fds_count;

	return val_to_ring(args, (uint64_t)(unsigned long)targetbuf, pos, false);
}

static int32_t f_sys_poll_e(struct event_filler_arguments* args)
{
	unsigned long val;
	int32_t res;

	res = poll_parse_fds(args, true);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// timeout
	//
	syscall_get_arguments(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static int32_t f_sys_poll_x(struct event_filler_arguments* args)
{
	int64_t retval;
	int32_t res;

	//
	// res
	//
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	res = poll_parse_fds(args, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static int32_t f_sys_openat_e(struct event_filler_arguments* args)
{
	unsigned long val;
	int32_t res;

	//
	// dirfd
	//
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	
	if(val == AT_FDCWD)
	{
		val = PPM_AT_FDCWD;
	}

	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// name
	//
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, val, 0, true);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// Flags
	// Note that we convert them into the ppm portable representation before pushing them to the ring
	//
	syscall_get_arguments(current, args->regs, 2, 1, &val);
	res = val_to_ring(args, open_flags_to_scap(val), 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// Mode
	// XXX: at this time, mode decoding is not supported. We nonetheless return a value (zero)
	//      so the format of the event is ready for when we'll export the mode in the future.
	//
	//syscall_get_arguments(current, args->regs, 3, 1, &val);
	res = val_to_ring(args, 0, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

#ifndef __x86_64__
static int32_t f_sys_pread64_e(struct event_filler_arguments* args)
{
	unsigned long val;
	unsigned long size;
	int32_t res;
	unsigned long pos0;
	unsigned long pos1;
	uint64_t pos64;

	//
	// fd
	//
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// size
	//
	syscall_get_arguments(current, args->regs, 2, 1, &size);
	res = val_to_ring(args, size, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// pos
	//
	syscall_get_arguments(current, args->regs, 3, 1, &pos0);
	syscall_get_arguments(current, args->regs, 4, 1, &pos1);

	pos64 = merge_64(pos1, pos0);

	res = val_to_ring(args, pos64, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}
#endif // __x86_64__

static int32_t f_sys_pwrite64_e(struct event_filler_arguments* args)
{
	unsigned long val;
	unsigned long size;
	int32_t res;
#ifndef __x86_64__	
	unsigned long pos0;
	unsigned long pos1;
	uint64_t pos64;
#endif

	//
	// fd
	//
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// size
	//
	syscall_get_arguments(current, args->regs, 2, 1, &size);
	res = val_to_ring(args, size, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// pos
	// NOTE: this is a 64bit value, which means that on 32bit systems it uses two
	// separate registers that we need to merge.
	//
#ifdef __x86_64__
	syscall_get_arguments(current, args->regs, 3, 1, &val);
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}
#else
	syscall_get_arguments(current, args->regs, 3, 1, &pos0);
	syscall_get_arguments(current, args->regs, 4, 1, &pos1);
	pos64 = merge_64(pos1, pos0);

	res = val_to_ring(args, pos64, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}
#endif

	return add_sentinel(args);
}

static int32_t f_sys_readv_x(struct event_filler_arguments* args)
{
	unsigned long val;
	int64_t retval;
	int32_t res;
	const struct iovec* iov;
	unsigned long iovcnt;

	//
	// res
	//
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// data and size
	//
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	iov = (const struct iovec*)val;
	syscall_get_arguments(current, args->regs, 2, 1, &iovcnt);

	res = parse_readv_writev_bufs(args, iov, iovcnt, retval, PRB_FLAG_PUSH_ALL);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static int32_t f_sys_writev_e(struct event_filler_arguments* args)
{
	unsigned long val;
	int32_t res;
	const struct iovec* iov;
	unsigned long iovcnt;
	unsigned int snaplen;

	//
	// fd
	//
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// size
	//
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	iov = (const struct iovec*)val;
	syscall_get_arguments(current, args->regs, 2, 1, &iovcnt);

	//
	// Determine the snaplen by checking the fd type.
	// (note: not implemeted yet)
	//
	snaplen = g_snaplen;
#if 0
	{
		int fd;
		int err, fput_needed;
		struct socket *sock;
	
		syscall_get_arguments(current, args->regs, 0, 1, &val);
		fd = (int)val;

		sock = ppm_sockfd_lookup_light(fd, &err, &fput_needed);
		if(sock)
		{
			snaplen = g_snaplen;
			fput_light(sock->file, fput_needed);
		}
		else
		{
			snaplen = RW_SNAPLEN;
		}
	}
#endif

	//
	// Copy the buffer
	//
	res = parse_readv_writev_bufs(args, iov, iovcnt, snaplen, PRB_FLAG_PUSH_SIZE);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static int32_t f_sys_writev_pwritev_x(struct event_filler_arguments* args)
{
	unsigned long val;
	int32_t res;
	int64_t retval;
	const struct iovec* iov;
	unsigned long iovcnt;
	unsigned int snaplen;

	//
	// res
	//
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// data and size
	//
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	iov = (const struct iovec*)val;
	syscall_get_arguments(current, args->regs, 2, 1, &iovcnt);

	//
	// Determine the snaplen by checking the fd type.
	// (note: not implemeted yet)
	//
	snaplen = g_snaplen;
#if 0
	{
		int fd;
		int err, fput_needed;
		struct socket *sock;
	
		syscall_get_arguments(current, args->regs, 0, 1, &val);
		fd = (int)val;

		sock = ppm_sockfd_lookup_light(fd, &err, &fput_needed);
		if(sock)
		{
			snaplen = g_snaplen;
			fput_light(sock->file, fput_needed);
		}
		else
		{
			snaplen = RW_SNAPLEN;
		}
	}
#endif

	//
	// Copy the buffer
	//
	res = parse_readv_writev_bufs(args, iov, iovcnt, snaplen, PRB_FLAG_PUSH_DATA);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

#ifndef __x86_64__
static int32_t f_sys_preadv_e(struct event_filler_arguments* args)
{
	unsigned long val;
	int32_t res;
	unsigned long pos0;
	unsigned long pos1;
	uint64_t pos64;

	//
	// fd
	//
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// pos
	//
	syscall_get_arguments(current, args->regs, 3, 1, &pos0);
	syscall_get_arguments(current, args->regs, 4, 1, &pos1);

	pos64 = merge_64(pos1, pos0);

	res = val_to_ring(args, pos64, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}
#endif // __x86_64__

static int32_t f_sys_preadv_x(struct event_filler_arguments* args)
{
	unsigned long val;
	int64_t retval;
	int32_t res;
	const struct iovec* iov;
	unsigned long iovcnt;

	//
	// res
	//
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// data and size
	//
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	iov = (const struct iovec*)val;
	syscall_get_arguments(current, args->regs, 2, 1, &iovcnt);

	res = parse_readv_writev_bufs(args, iov, iovcnt, retval, PRB_FLAG_PUSH_ALL);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static int32_t f_sys_pwritev_e(struct event_filler_arguments* args)
{
	unsigned long val;
	int32_t res;
#ifndef __x86_64__	
	unsigned long pos0;
	unsigned long pos1;
	uint64_t pos64;
#endif
	const struct iovec* iov;
	unsigned long iovcnt;
	unsigned int snaplen;

	//
	// fd
	//
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// size
	//
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	iov = (const struct iovec*)val;
	syscall_get_arguments(current, args->regs, 2, 1, &iovcnt);

	//
	// Determine the snaplen by checking the fd type.
	// (note: not implemeted yet)
	//
	snaplen = g_snaplen;
#if 0
	{
		int fd;
		int err, fput_needed;
		struct socket *sock;
	
		syscall_get_arguments(current, args->regs, 0, 1, &val);
		fd = (int)val;

		sock = ppm_sockfd_lookup_light(fd, &err, &fput_needed);
		if(sock)
		{
			snaplen = g_snaplen;
			fput_light(sock->file, fput_needed);
		}
		else
		{
			snaplen = RW_SNAPLEN;
		}
	}
#endif

	//
	// Copy the buffer
	//
	res = parse_readv_writev_bufs(args, iov, iovcnt, snaplen, PRB_FLAG_PUSH_SIZE);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// pos
	// NOTE: this is a 64bit value, which means that on 32bit systems it uses two
	// separate registers that we need to merge.
	//
#ifdef __x86_64__
	syscall_get_arguments(current, args->regs, 3, 1, &val);
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}
#else
	syscall_get_arguments(current, args->regs, 3, 1, &pos0);
	syscall_get_arguments(current, args->regs, 4, 1, &pos1);
	pos64 = merge_64(pos1, pos0);

	res = val_to_ring(args, pos64, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}
#endif

	return add_sentinel(args);
}

static int32_t f_sys_nanosleep_e(struct event_filler_arguments* args)
{
	int32_t res;
	uint64_t longtime;
	unsigned long val;
	char* targetbuf = args->str_storage;
	struct timespec* tts = (struct timespec*)targetbuf;
	int32_t cfulen;

	//
	// interval
	// We copy the timespec structure and then convert it to a 64bit relative time
	//
	syscall_get_arguments(current, args->regs, 0, 1, &val);

	cfulen = (int32_t)ppm_copy_from_user(targetbuf,
			(void*)val,
			sizeof(struct timespec));

	if(unlikely(cfulen != 0))
	{
		return PPM_FAILURE_INVALID_USER_MEMORY;
	}

	longtime = ((uint64_t)tts->tv_sec) * 1000000000 + tts->tv_nsec;

	res = val_to_ring(args, longtime, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static inline uint8_t rlimit_resource_to_scap(unsigned long rresource)
{
	switch(rresource)
	{
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
			ASSERT(false);
			return PPM_RLIMIT_UNKNOWN;
	}
}

static int32_t f_sys_getrlimit_setrlimit_e(struct event_filler_arguments* args)
{
	uint8_t ppm_resource;
	unsigned long val;
	int32_t res;

	//
	// resource
	//
	syscall_get_arguments(current, args->regs, 0, 1, &val);

	ppm_resource = rlimit_resource_to_scap(val);

	res = val_to_ring(args, (uint64_t)ppm_resource, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static int32_t f_sys_getrlimit_setrlrimit_x(struct event_filler_arguments* args)
{
	unsigned long val;
	int32_t res;
	int64_t retval;
	struct rlimit rl;
	int64_t cur;
	int64_t max;

	//
	// res
	//
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// Copy the user structure and extract cur and max
	//
	if(retval >= 0 || args->event_type == PPME_SYSCALL_SETRLIMIT_X)
	{
		syscall_get_arguments(current, args->regs, 1, 1, &val);

		if(unlikely(ppm_copy_from_user(&rl, (const void*)val, sizeof(struct rlimit))))
		{
			return PPM_FAILURE_INVALID_USER_MEMORY;
		}

		cur = rl.rlim_cur;
		max = rl.rlim_max;
	}
	else
	{
		cur = -1;
		max = -1;
	}

	//
	// cur
	//
	res = val_to_ring(args, cur, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// max
	//
	res = val_to_ring(args, max, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static int32_t f_sys_prlimit_e(struct event_filler_arguments* args)
{
	uint8_t ppm_resource;
	unsigned long val;
	int32_t res;

	//
	// pid
	//
	syscall_get_arguments(current, args->regs, 0, 1, &val);

	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// resource
	//
	syscall_get_arguments(current, args->regs, 1, 1, &val);

	ppm_resource = rlimit_resource_to_scap(val);

	res = val_to_ring(args, (uint64_t)ppm_resource, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static int32_t f_sys_prlimit_x(struct event_filler_arguments* args)
{
	unsigned long val;
	int32_t res;
	int64_t retval;
	struct rlimit rl;
	int64_t newcur;
	int64_t newmax;
	int64_t oldcur;
	int64_t oldmax;

	//
	// res
	//
	retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
	res = val_to_ring(args, retval, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// Copy the user structure and extract cur and max
	//
	if(retval >= 0)
	{
		syscall_get_arguments(current, args->regs, 2, 1, &val);

		if(unlikely(ppm_copy_from_user(&rl, (const void*)val, sizeof(struct rlimit))))
		{
			newcur = -1;
			newmax = -1;
		}
		else
		{
			newcur = rl.rlim_cur;
			newmax = rl.rlim_max;			
		}
	}
	else
	{
		newcur = -1;
		newmax = -1;
	}

	syscall_get_arguments(current, args->regs, 3, 1, &val);

	if(unlikely(ppm_copy_from_user(&rl, (const void*)val, sizeof(struct rlimit))))
	{
		oldcur = -1;
		oldmax = -1;
	}
	else
	{
		oldcur = rl.rlim_cur;
		oldmax = rl.rlim_max;			
	}

	//
	// newcur
	//
	res = val_to_ring(args, newcur, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// newmax
	//
	res = val_to_ring(args, newmax, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// oldcur
	//
	res = val_to_ring(args, oldcur, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// oldmax
	//
	res = val_to_ring(args, oldmax, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

#ifdef CAPTURE_CONTEXT_SWITCHES
#include <linux/kernel_stat.h>

static int32_t f_sched_switch_e(struct event_filler_arguments* args)
{
	int32_t res;
//	uint64_t steal;

	if(args->sched_prev == NULL || args->sched_next == NULL)
	{
		ASSERT(false);
		return -1;
	}

	//
	// next
	//
	res = val_to_ring(args, args->sched_next->pid, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

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

#if 0
static int32_t f_sched_switchex_e(struct event_filler_arguments* args)
{
	int32_t res;

	if(args->sched_prev == NULL || args->sched_next == NULL)
	{
		ASSERT(false);
		return -1;
	}

	//
	// next
	//
	res = val_to_ring(args, args->sched_next->pid, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// pgft_maj
	//
	res = val_to_ring(args, args->sched_prev->maj_flt, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// pgft_min
	//
	res = val_to_ring(args, args->sched_prev->min_flt, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// next_pgft_maj
	//
	res = val_to_ring(args, args->sched_next->maj_flt, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// next_pgft_min
	//
	res = val_to_ring(args, args->sched_next->min_flt, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}
#endif // 0
#endif // CAPTURE_CONTEXT_SWITCHES

static int32_t f_sched_drop(struct event_filler_arguments* args)
{
	int32_t res;

	//
	// next
	//
	res = val_to_ring(args, g_sampling_ratio, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}

static inline uint8_t fcntl_cmd_to_scap(unsigned long cmd)
{
	switch(cmd)
	{
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
		case F_GETLK64:
			return PPM_FCNTL_F_GETLK64;
		case F_SETLK64:    
			return PPM_FCNTL_F_SETLK64;
		case F_SETLKW64:    
			return PPM_FCNTL_F_SETLKW64;
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

static int32_t f_sched_fcntl_e(struct event_filler_arguments* args)
{
	unsigned long val;
	int32_t res;

	//
	// fd
	//
	syscall_get_arguments(current, args->regs, 0, 1, &val);
	res = val_to_ring(args, val, 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	//
	// cmd
	//
	syscall_get_arguments(current, args->regs, 1, 1, &val);
	res = val_to_ring(args, fcntl_cmd_to_scap(val), 0, false);
	if(unlikely(res != PPM_SUCCESS))
	{
		return res;
	}

	return add_sentinel(args);
}
