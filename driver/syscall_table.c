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

#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kdev_t.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/wait.h>
#include <asm/syscall.h>
#include <net/sock.h>
#include <asm/unistd.h>

#include "ppm_ringbuffer.h"
#include "ppm_events_public.h"
#include "ppm_events.h"
#include "ppm.h"

/*
 * SYSCALL TABLE
 */
struct syscall_evt_pair g_syscall_table[SYSCALL_TABLE_SIZE] = {
	[__NR_open] =			{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_OPEN_E, PPME_SYSCALL_OPEN_X},
	[__NR_creat] =			{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_CREAT_E, PPME_SYSCALL_CREAT_X},
	[__NR_close] =			{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_CLOSE_X},
	[__NR_brk] =			{UF_USED, PPME_SYSCALL_BRK_E, PPME_SYSCALL_BRK_X},
	[__NR_read] =			{UF_USED, PPME_SYSCALL_READ_E, PPME_SYSCALL_READ_X},
	[__NR_write] =			{UF_USED, PPME_SYSCALL_WRITE_E, PPME_SYSCALL_WRITE_X},
	[__NR_execve] =		{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_EXECVE_E, PPME_SYSCALL_EXECVE_X},
	[__NR_clone] =			{UF_USED | UF_NEVER_DROP, PPME_CLONE_E, PPME_CLONE_X},
	[__NR_pipe] =			{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_PIPE_E, PPME_SYSCALL_PIPE_X},
	[__NR_pipe2] =			{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_PIPE_E, PPME_SYSCALL_PIPE_X},
	[__NR_eventfd] =		{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_EVENTFD_E, PPME_SYSCALL_EVENTFD_X},
	[__NR_eventfd2] =		{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_EVENTFD_E, PPME_SYSCALL_EVENTFD_X},
	[__NR_futex] =			{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_FUTEX_E, PPME_SYSCALL_FUTEX_X},
	[__NR_stat] =			{UF_USED, PPME_SYSCALL_STAT_E, PPME_SYSCALL_STAT_X},
	[__NR_lstat] =			{UF_USED, PPME_SYSCALL_LSTAT_E, PPME_SYSCALL_LSTAT_X},
	[__NR_fstat] =			{UF_USED, PPME_SYSCALL_FSTAT_E, PPME_SYSCALL_FSTAT_X},
	[__NR_epoll_wait] =	{UF_USED, PPME_SYSCALL_EPOLLWAIT_E, PPME_SYSCALL_EPOLLWAIT_X},
	[__NR_poll] =			{UF_USED, PPME_SYSCALL_POLL_E, PPME_SYSCALL_POLL_X},
	[__NR_select] =		{UF_USED, PPME_SYSCALL_SELECT_E, PPME_SYSCALL_SELECT_X},
	[__NR_lseek] =			{UF_USED, PPME_SYSCALL_LSEEK_E, PPME_SYSCALL_LSEEK_X},
	[__NR_ioctl] =			{UF_USED, PPME_SYSCALL_IOCTL_E, PPME_SYSCALL_IOCTL_X},
	[__NR_getcwd] =		{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_GETCWD_E, PPME_SYSCALL_GETCWD_X},
	[__NR_chdir] =			{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_CHDIR_E, PPME_SYSCALL_CHDIR_X},
	[__NR_fchdir] =		{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_FCHDIR_E, PPME_SYSCALL_FCHDIR_X},
	[__NR_mkdir] =			{UF_USED, PPME_SYSCALL_MKDIR_E, PPME_SYSCALL_MKDIR_X},
	[__NR_rmdir] =			{UF_USED, PPME_SYSCALL_RMDIR_E, PPME_SYSCALL_RMDIR_X},
	[__NR_openat] =		{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_OPENAT_E, PPME_SYSCALL_OPENAT_X},
	[__NR_link] =			{UF_USED, PPME_SYSCALL_LINK_E, PPME_SYSCALL_LINK_X},
	[__NR_linkat] =		{UF_USED, PPME_SYSCALL_LINKAT_E, PPME_SYSCALL_LINKAT_X},
	[__NR_unlink] =		{UF_USED, PPME_SYSCALL_UNLINK_E, PPME_SYSCALL_UNLINK_X},
	[__NR_unlinkat] =		{UF_USED, PPME_SYSCALL_UNLINKAT_E, PPME_SYSCALL_UNLINKAT_X},
	[__NR_pread64] =		{UF_USED, PPME_SYSCALL_PREAD_E, PPME_SYSCALL_PREAD_X},
	[__NR_pwrite64] =		{UF_USED, PPME_SYSCALL_PWRITE_E, PPME_SYSCALL_PWRITE_X},
	[__NR_readv] =			{UF_USED, PPME_SYSCALL_READV_E, PPME_SYSCALL_READV_X},
	[__NR_writev] =		{UF_USED, PPME_SYSCALL_WRITEV_E, PPME_SYSCALL_WRITEV_X},
	[__NR_preadv] =		{UF_USED, PPME_SYSCALL_PREADV_E, PPME_SYSCALL_PREADV_X},
	[__NR_pwritev] =		{UF_USED, PPME_SYSCALL_PWRITEV_E, PPME_SYSCALL_PWRITEV_X},
	[__NR_dup] =			{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_DUP_E, PPME_SYSCALL_DUP_X},
	[__NR_dup2] =			{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_DUP_E, PPME_SYSCALL_DUP_X},
	[__NR_dup3] =			{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_DUP_E, PPME_SYSCALL_DUP_X},
	[__NR_signalfd] =		{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_SIGNALFD_E, PPME_SYSCALL_SIGNALFD_X},
	[__NR_signalfd4] =		{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_SIGNALFD_E, PPME_SYSCALL_SIGNALFD_X},
	[__NR_kill] =			{UF_USED, PPME_SYSCALL_KILL_E, PPME_SYSCALL_KILL_X},
	[__NR_tkill] =			{UF_USED, PPME_SYSCALL_TKILL_E, PPME_SYSCALL_TKILL_X},
	[__NR_tgkill] =		{UF_USED, PPME_SYSCALL_TGKILL_E, PPME_SYSCALL_TGKILL_X},
	[__NR_nanosleep] =		{UF_USED, PPME_SYSCALL_NANOSLEEP_E, PPME_SYSCALL_NANOSLEEP_X},
	[__NR_timerfd_create] =	{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_TIMERFD_CREATE_E, PPME_SYSCALL_TIMERFD_CREATE_X},
	[__NR_inotify_init] =	{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_INOTIFY_INIT_E, PPME_SYSCALL_INOTIFY_INIT_X},
	[__NR_inotify_init1] =	{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_INOTIFY_INIT_E, PPME_SYSCALL_INOTIFY_INIT_X},
	[__NR_getrlimit] =		{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_GETRLIMIT_E, PPME_SYSCALL_GETRLIMIT_X},
	[__NR_setrlimit] =		{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_SETRLIMIT_E, PPME_SYSCALL_SETRLIMIT_X},
#ifdef __NR_prlimit64
	[__NR_prlimit64] =		{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_PRLIMIT_E, PPME_SYSCALL_PRLIMIT_X},
#endif
#ifdef __NR_ugetrlimit
	[__NR_ugetrlimit] =		{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_GETRLIMIT_E, PPME_SYSCALL_GETRLIMIT_X},
#endif
	[__NR_fcntl] =			{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_FCNTL_E, PPME_SYSCALL_FCNTL_X},
#ifdef __NR_fcntl64
	[__NR_fcntl64] =		{UF_USED | UF_NEVER_DROP, PPME_SYSCALL_FCNTL_E, PPME_SYSCALL_FCNTL_X},
#endif
/* [__NR_ppoll] =			{UF_USED, PPME_GENERIC_E, PPME_GENERIC_X}, */
/* [__NR_old_select] =	{UF_USED, PPME_GENERIC_E, PPME_GENERIC_X}, */
	[__NR_pselect6] =		{UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_epoll_create] =	{UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_epoll_ctl] =		{UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_uselib] =		{UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_sched_setparam] = {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_sched_getparam] = {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_fork] =			{UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_syslog] =		{UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_chmod] =			{UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_lchown] =		{UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_utime] =			{UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_mount] =			{UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_umount2] =		{UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_setuid] =		{UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_getuid] =		{UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_ptrace] =		{UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_alarm] =			{UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_pause] =			{UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
#ifdef __x86_64__
	[__NR_socket] =		{UF_USED, PPME_SOCKET_SOCKET_E, PPME_SOCKET_SOCKET_X},
	[__NR_bind] =			{UF_USED, PPME_SOCKET_BIND_E,  PPME_SOCKET_BIND_X},
	[__NR_connect] =		{UF_USED, PPME_SOCKET_CONNECT_E, PPME_SOCKET_CONNECT_X},
	[__NR_listen] =		{UF_USED, PPME_SOCKET_LISTEN_E, PPME_SOCKET_LISTEN_X},
	[__NR_accept] =		{UF_USED, PPME_SOCKET_ACCEPT_E, PPME_SOCKET_ACCEPT_X},
	[__NR_getsockname] =	{UF_USED, PPME_SOCKET_GETSOCKNAME_E, PPME_SOCKET_GETSOCKNAME_X},
	[__NR_getpeername] =	{UF_USED, PPME_SOCKET_GETPEERNAME_E, PPME_SOCKET_GETPEERNAME_X},
	[__NR_socketpair] =	{UF_USED | UF_NEVER_DROP, PPME_SOCKET_SOCKETPAIR_E, PPME_SOCKET_SOCKETPAIR_X},
	[__NR_sendto] =		{UF_USED, PPME_SOCKET_SENDTO_E, PPME_SOCKET_SENDTO_X},
	[__NR_recvfrom] =		{UF_USED, PPME_SOCKET_RECVFROM_E, PPME_SOCKET_RECVFROM_X},
	[__NR_shutdown] =		{UF_USED, PPME_SOCKET_SHUTDOWN_E, PPME_SOCKET_SHUTDOWN_X},
	[__NR_setsockopt] =	{UF_USED, PPME_SOCKET_SETSOCKOPT_E, PPME_SOCKET_SETSOCKOPT_X},
	[__NR_getsockopt] =	{UF_USED, PPME_SOCKET_GETSOCKOPT_E, PPME_SOCKET_GETSOCKOPT_X},
	[__NR_sendmsg] =		{UF_USED, PPME_SOCKET_SENDMSG_E, PPME_SOCKET_SENDMSG_X},
#ifdef __NR_sendmmsg
	[__NR_sendmmsg] =		{UF_USED, PPME_SOCKET_SENDMMSG_E, PPME_SOCKET_SENDMMSG_X},
#endif
	[__NR_recvmsg] =		{UF_USED, PPME_SOCKET_RECVMSG_E, PPME_SOCKET_RECVMSG_X},
#ifdef __NR_recvmmsg
	[__NR_recvmmsg] =		{UF_USED, PPME_SOCKET_RECVMMSG_E, PPME_SOCKET_RECVMMSG_X},
#endif
	[__NR_accept4] =		{UF_USED, PPME_SOCKET_ACCEPT4_E, PPME_SOCKET_ACCEPT4_X},
#else /* __x86_64__ */
	[__NR_stat64] =		{UF_USED, PPME_SYSCALL_STAT64_E, PPME_SYSCALL_STAT64_X},
	[__NR_fstat64] =		{UF_USED, PPME_SYSCALL_FSTAT64_E, PPME_SYSCALL_FSTAT64_X},
	[__NR__llseek] =		{UF_USED, PPME_SYSCALL_LLSEEK_E, PPME_SYSCALL_LLSEEK_X}
#endif /* __x86_64__ */
};

/*
 * SYSCALL ROUTING TABLE
 */
const enum ppm_syscall_code g_syscall_code_routing_table[SYSCALL_TABLE_SIZE] = {
	[__NR_restart_syscall] = PPM_SC_RESTART_SYSCALL,
	[__NR_exit] = PPM_SC_EXIT,
	[__NR_read] = PPM_SC_READ,
	[__NR_write] = PPM_SC_WRITE,
	[__NR_open] = PPM_SC_OPEN,
	[__NR_close] = PPM_SC_CLOSE,
	[__NR_creat] = PPM_SC_CREAT,
	[__NR_link] = PPM_SC_LINK,
	[__NR_unlink] = PPM_SC_UNLINK,
	[__NR_chdir] = PPM_SC_CHDIR,
	[__NR_time] = PPM_SC_TIME,
	[__NR_mknod] = PPM_SC_MKNOD,
	[__NR_chmod] = PPM_SC_CHMOD,
/* [__NR_lchown16] = PPM_SC_NR_LCHOWN16, */
	[__NR_stat] = PPM_SC_STAT,
	[__NR_lseek] = PPM_SC_LSEEK,
	[__NR_getpid] = PPM_SC_GETPID,
	[__NR_mount] = PPM_SC_MOUNT,
/* [__NR_oldumount] = PPM_SC_NR_OLDUMOUNT, */
/* [__NR_setuid16] = PPM_SC_NR_SETUID16, */
/* [__NR_getuid16] = PPM_SC_NR_GETUID16, */
	[__NR_ptrace] = PPM_SC_PTRACE,
	[__NR_alarm] = PPM_SC_ALARM,
	[__NR_fstat] = PPM_SC_FSTAT,
	[__NR_pause] = PPM_SC_PAUSE,
	[__NR_utime] = PPM_SC_UTIME,
	[__NR_access] = PPM_SC_ACCESS,
	[__NR_sync] = PPM_SC_SYNC,
	[__NR_kill] = PPM_SC_KILL,
	[__NR_rename] = PPM_SC_RENAME,
	[__NR_mkdir] = PPM_SC_MKDIR,
	[__NR_rmdir] = PPM_SC_RMDIR,
	[__NR_dup] = PPM_SC_DUP,
	[__NR_pipe] = PPM_SC_PIPE,
	[__NR_times] = PPM_SC_TIMES,
	[__NR_brk] = PPM_SC_BRK,
/* [__NR_setgid16] = PPM_SC_NR_SETGID16, */
/* [__NR_getgid16] = PPM_SC_NR_GETGID16, */
/* [__NR_geteuid16] = PPM_SC_NR_GETEUID16, */
/* [__NR_getegid16] = PPM_SC_NR_GETEGID16, */
	[__NR_acct] = PPM_SC_ACCT,
	[__NR_ioctl] = PPM_SC_IOCTL,
	[__NR_fcntl] = PPM_SC_FCNTL,
	[__NR_setpgid] = PPM_SC_SETPGID,
	[__NR_umask] = PPM_SC_UMASK,
	[__NR_chroot] = PPM_SC_CHROOT,
	[__NR_ustat] = PPM_SC_USTAT,
	[__NR_dup2] = PPM_SC_DUP2,
	[__NR_getppid] = PPM_SC_GETPPID,
	[__NR_getpgrp] = PPM_SC_GETPGRP,
	[__NR_setsid] = PPM_SC_SETSID,
	[__NR_sethostname] = PPM_SC_SETHOSTNAME,
	[__NR_setrlimit] = PPM_SC_SETRLIMIT,
/* [__NR_old_getrlimit] = PPM_SC_NR_OLD_GETRLIMIT, */
	[__NR_getrusage] = PPM_SC_GETRUSAGE,
	[__NR_gettimeofday] = PPM_SC_GETTIMEOFDAY,
	[__NR_settimeofday] = PPM_SC_SETTIMEOFDAY,
/* [__NR_getgroups16] = PPM_SC_NR_GETGROUPS16, */
/* [__NR_setgroups16] = PPM_SC_NR_SETGROUPS16, */
/* [__NR_old_select] = PPM_SC_NR_OLD_SELECT, */
	[__NR_symlink] = PPM_SC_SYMLINK,
	[__NR_lstat] = PPM_SC_LSTAT,
	[__NR_readlink] = PPM_SC_READLINK,
	[__NR_uselib] = PPM_SC_USELIB,
	[__NR_swapon] = PPM_SC_SWAPON,
	[__NR_reboot] = PPM_SC_REBOOT,
/* [__NR_old_readdir] = PPM_SC_NR_OLD_READDIR, */
/* [__NR_old_mmap] = PPM_SC_NR_OLD_MMAP, */
	[__NR_mmap] = PPM_SC_MMAP,
	[__NR_munmap] = PPM_SC_MUNMAP,
	[__NR_truncate] = PPM_SC_TRUNCATE,
	[__NR_ftruncate] = PPM_SC_FTRUNCATE,
	[__NR_fchmod] = PPM_SC_FCHMOD,
/* [__NR_fchown16] = PPM_SC_NR_FCHOWN16, */
	[__NR_getpriority] = PPM_SC_GETPRIORITY,
	[__NR_setpriority] = PPM_SC_SETPRIORITY,
	[__NR_statfs] = PPM_SC_STATFS,
	[__NR_fstatfs] = PPM_SC_FSTATFS,
	[__NR_syslog] = PPM_SC_SYSLOG,
	[__NR_setitimer] = PPM_SC_SETITIMER,
	[__NR_getitimer] = PPM_SC_GETITIMER,
/* [__NR_newstat] = PPM_SC_NR_NEWSTAT, */
/* [__NR_newlstat] = PPM_SC_NR_NEWLSTAT, */
/* [__NR_newfstat] = PPM_SC_NR_NEWFSTAT, */
	[__NR_uname] = PPM_SC_UNAME,
	[__NR_vhangup] = PPM_SC_VHANGUP,
	[__NR_wait4] = PPM_SC_WAIT4,
	[__NR_swapoff] = PPM_SC_SWAPOFF,
	[__NR_sysinfo] = PPM_SC_SYSINFO,
	[__NR_fsync] = PPM_SC_FSYNC,
	[__NR_setdomainname] = PPM_SC_SETDOMAINNAME,
/* [__NR_newuname] = PPM_SC_NR_NEWUNAME, */
	[__NR_adjtimex] = PPM_SC_ADJTIMEX,
	[__NR_mprotect] = PPM_SC_MPROTECT,
	[__NR_init_module] = PPM_SC_INIT_MODULE,
	[__NR_delete_module] = PPM_SC_DELETE_MODULE,
	[__NR_quotactl] = PPM_SC_QUOTACTL,
	[__NR_getpgid] = PPM_SC_GETPGID,
	[__NR_fchdir] = PPM_SC_FCHDIR,
	[__NR_sysfs] = PPM_SC_SYSFS,
	[__NR_personality] = PPM_SC_PERSONALITY,
/* [__NR_setfsuid16] = PPM_SC_NR_SETFSUID16, */
/* [__NR_setfsgid16] = PPM_SC_NR_SETFSGID16, */
/* [__NR_llseek] = PPM_SC_NR_LLSEEK, */
	[__NR_getdents] = PPM_SC_GETDENTS,
	[__NR_select] = PPM_SC_SELECT,
	[__NR_flock] = PPM_SC_FLOCK,
	[__NR_msync] = PPM_SC_MSYNC,
	[__NR_readv] = PPM_SC_READV,
	[__NR_writev] = PPM_SC_WRITEV,
	[__NR_getsid] = PPM_SC_GETSID,
	[__NR_fdatasync] = PPM_SC_FDATASYNC,
/* [__NR_sysctl] = PPM_SC_NR_SYSCTL, */
	[__NR_mlock] = PPM_SC_MLOCK,
	[__NR_munlock] = PPM_SC_MUNLOCK,
	[__NR_mlockall] = PPM_SC_MLOCKALL,
	[__NR_munlockall] = PPM_SC_MUNLOCKALL,
	[__NR_sched_setparam] = PPM_SC_SCHED_SETPARAM,
	[__NR_sched_getparam] = PPM_SC_SCHED_GETPARAM,
	[__NR_sched_setscheduler] = PPM_SC_SCHED_SETSCHEDULER,
	[__NR_sched_getscheduler] = PPM_SC_SCHED_GETSCHEDULER,
	[__NR_sched_yield] = PPM_SC_SCHED_YIELD,
	[__NR_sched_get_priority_max] = PPM_SC_SCHED_GET_PRIORITY_MAX,
	[__NR_sched_get_priority_min] = PPM_SC_SCHED_GET_PRIORITY_MIN,
	[__NR_sched_rr_get_interval] = PPM_SC_SCHED_RR_GET_INTERVAL,
	[__NR_nanosleep] = PPM_SC_NANOSLEEP,
	[__NR_mremap] = PPM_SC_MREMAP,
/* [__NR_setresuid16] = PPM_SC_NR_SETRESUID16, */
/* [__NR_getresuid16] = PPM_SC_NR_GETRESUID16, */
	[__NR_poll] = PPM_SC_POLL,
/* [__NR_setresgid16] = PPM_SC_NR_SETRESGID16, */
/* [__NR_getresgid16] = PPM_SC_NR_GETRESGID16, */
	[__NR_prctl] = PPM_SC_PRCTL,
	[__NR_rt_sigaction] = PPM_SC_RT_SIGACTION,
	[__NR_rt_sigprocmask] = PPM_SC_RT_SIGPROCMASK,
	[__NR_rt_sigpending] = PPM_SC_RT_SIGPENDING,
	[__NR_rt_sigtimedwait] = PPM_SC_RT_SIGTIMEDWAIT,
	[__NR_rt_sigqueueinfo] = PPM_SC_RT_SIGQUEUEINFO,
	[__NR_rt_sigsuspend] = PPM_SC_RT_SIGSUSPEND,
/* [__NR_chown16] = PPM_SC_NR_CHOWN16, */
	[__NR_getcwd] = PPM_SC_GETCWD,
	[__NR_capget] = PPM_SC_CAPGET,
	[__NR_capset] = PPM_SC_CAPSET,
	[__NR_sendfile] = PPM_SC_SENDFILE,
	[__NR_getrlimit] = PPM_SC_GETRLIMIT,
/* [__NR_mmap_pgoff] = PPM_SC_NR_MMAP_PGOFF, */
	[__NR_lchown] = PPM_SC_LCHOWN,
	[__NR_getuid] = PPM_SC_GETUID,
	[__NR_getgid] = PPM_SC_GETGID,
	[__NR_geteuid] = PPM_SC_GETEUID,
	[__NR_getegid] = PPM_SC_GETEGID,
	[__NR_setreuid] = PPM_SC_SETREUID,
	[__NR_setregid] = PPM_SC_SETREGID,
	[__NR_getgroups] = PPM_SC_GETGROUPS,
	[__NR_setgroups] = PPM_SC_SETGROUPS,
	[__NR_fchown] = PPM_SC_FCHOWN,
	[__NR_setresuid] = PPM_SC_SETRESUID,
	[__NR_getresuid] = PPM_SC_GETRESUID,
	[__NR_setresgid] = PPM_SC_SETRESGID,
	[__NR_getresgid] = PPM_SC_GETRESGID,
	[__NR_chown] = PPM_SC_CHOWN,
	[__NR_setuid] = PPM_SC_SETUID,
	[__NR_setgid] = PPM_SC_SETGID,
	[__NR_setfsuid] = PPM_SC_SETFSUID,
	[__NR_setfsgid] = PPM_SC_SETFSGID,
	[__NR_pivot_root] = PPM_SC_PIVOT_ROOT,
	[__NR_mincore] = PPM_SC_MINCORE,
	[__NR_madvise] = PPM_SC_MADVISE,
	[__NR_gettid] = PPM_SC_GETTID,
	[__NR_setxattr] = PPM_SC_SETXATTR,
	[__NR_lsetxattr] = PPM_SC_LSETXATTR,
	[__NR_fsetxattr] = PPM_SC_FSETXATTR,
	[__NR_getxattr] = PPM_SC_GETXATTR,
	[__NR_lgetxattr] = PPM_SC_LGETXATTR,
	[__NR_fgetxattr] = PPM_SC_FGETXATTR,
	[__NR_listxattr] = PPM_SC_LISTXATTR,
	[__NR_llistxattr] = PPM_SC_LLISTXATTR,
	[__NR_flistxattr] = PPM_SC_FLISTXATTR,
	[__NR_removexattr] = PPM_SC_REMOVEXATTR,
	[__NR_lremovexattr] = PPM_SC_LREMOVEXATTR,
	[__NR_fremovexattr] = PPM_SC_FREMOVEXATTR,
	[__NR_tkill] = PPM_SC_TKILL,
	[__NR_futex] = PPM_SC_FUTEX,
	[__NR_sched_setaffinity] = PPM_SC_SCHED_SETAFFINITY,
	[__NR_sched_getaffinity] = PPM_SC_SCHED_GETAFFINITY,
	[__NR_set_thread_area] = PPM_SC_SET_THREAD_AREA,
	[__NR_get_thread_area] = PPM_SC_GET_THREAD_AREA,
	[__NR_io_setup] = PPM_SC_IO_SETUP,
	[__NR_io_destroy] = PPM_SC_IO_DESTROY,
	[__NR_io_getevents] = PPM_SC_IO_GETEVENTS,
	[__NR_io_submit] = PPM_SC_IO_SUBMIT,
	[__NR_io_cancel] = PPM_SC_IO_CANCEL,
	[__NR_exit_group] = PPM_SC_EXIT_GROUP,
	[__NR_epoll_create] = PPM_SC_EPOLL_CREATE,
	[__NR_epoll_ctl] = PPM_SC_EPOLL_CTL,
	[__NR_epoll_wait] = PPM_SC_EPOLL_WAIT,
	[__NR_remap_file_pages] = PPM_SC_REMAP_FILE_PAGES,
	[__NR_set_tid_address] = PPM_SC_SET_TID_ADDRESS,
	[__NR_timer_create] = PPM_SC_TIMER_CREATE,
	[__NR_timer_settime] = PPM_SC_TIMER_SETTIME,
	[__NR_timer_gettime] = PPM_SC_TIMER_GETTIME,
	[__NR_timer_getoverrun] = PPM_SC_TIMER_GETOVERRUN,
	[__NR_timer_delete] = PPM_SC_TIMER_DELETE,
	[__NR_clock_settime] = PPM_SC_CLOCK_SETTIME,
	[__NR_clock_gettime] = PPM_SC_CLOCK_GETTIME,
	[__NR_clock_getres] = PPM_SC_CLOCK_GETRES,
	[__NR_clock_nanosleep] = PPM_SC_CLOCK_NANOSLEEP,
	[__NR_tgkill] = PPM_SC_TGKILL,
	[__NR_utimes] = PPM_SC_UTIMES,
	[__NR_mq_open] = PPM_SC_MQ_OPEN,
	[__NR_mq_unlink] = PPM_SC_MQ_UNLINK,
	[__NR_mq_timedsend] = PPM_SC_MQ_TIMEDSEND,
	[__NR_mq_timedreceive] = PPM_SC_MQ_TIMEDRECEIVE,
	[__NR_mq_notify] = PPM_SC_MQ_NOTIFY,
	[__NR_mq_getsetattr] = PPM_SC_MQ_GETSETATTR,
	[__NR_kexec_load] = PPM_SC_KEXEC_LOAD,
	[__NR_waitid] = PPM_SC_WAITID,
	[__NR_add_key] = PPM_SC_ADD_KEY,
	[__NR_request_key] = PPM_SC_REQUEST_KEY,
	[__NR_keyctl] = PPM_SC_KEYCTL,
	[__NR_ioprio_set] = PPM_SC_IOPRIO_SET,
	[__NR_ioprio_get] = PPM_SC_IOPRIO_GET,
	[__NR_inotify_init] = PPM_SC_INOTIFY_INIT,
	[__NR_inotify_add_watch] = PPM_SC_INOTIFY_ADD_WATCH,
	[__NR_inotify_rm_watch] = PPM_SC_INOTIFY_RM_WATCH,
	[__NR_openat] = PPM_SC_OPENAT,
	[__NR_mkdirat] = PPM_SC_MKDIRAT,
	[__NR_mknodat] = PPM_SC_MKNODAT,
	[__NR_fchownat] = PPM_SC_FCHOWNAT,
	[__NR_futimesat] = PPM_SC_FUTIMESAT,
	[__NR_unlinkat] = PPM_SC_UNLINKAT,
	[__NR_renameat] = PPM_SC_RENAMEAT,
	[__NR_linkat] = PPM_SC_LINKAT,
	[__NR_symlinkat] = PPM_SC_SYMLINKAT,
	[__NR_readlinkat] = PPM_SC_READLINKAT,
	[__NR_fchmodat] = PPM_SC_FCHMODAT,
	[__NR_faccessat] = PPM_SC_FACCESSAT,
	[__NR_pselect6] = PPM_SC_PSELECT6,
	[__NR_ppoll] = PPM_SC_PPOLL,
	[__NR_unshare] = PPM_SC_UNSHARE,
	[__NR_set_robust_list] = PPM_SC_SET_ROBUST_LIST,
	[__NR_get_robust_list] = PPM_SC_GET_ROBUST_LIST,
	[__NR_splice] = PPM_SC_SPLICE,
	[__NR_tee] = PPM_SC_TEE,
	[__NR_vmsplice] = PPM_SC_VMSPLICE,
#ifdef __NR_getcpu
	[__NR_getcpu] = PPM_SC_GETCPU,
#endif
	[__NR_epoll_pwait] = PPM_SC_EPOLL_PWAIT,
	[__NR_utimensat] = PPM_SC_UTIMENSAT,
	[__NR_signalfd] = PPM_SC_SIGNALFD,
	[__NR_timerfd_create] = PPM_SC_TIMERFD_CREATE,
	[__NR_eventfd] = PPM_SC_EVENTFD,
	[__NR_timerfd_settime] = PPM_SC_TIMERFD_SETTIME,
	[__NR_timerfd_gettime] = PPM_SC_TIMERFD_GETTIME,
	[__NR_signalfd4] = PPM_SC_SIGNALFD4,
	[__NR_eventfd2] = PPM_SC_EVENTFD2,
	[__NR_epoll_create1] = PPM_SC_EPOLL_CREATE1,
	[__NR_dup3] = PPM_SC_DUP3,
	[__NR_pipe2] = PPM_SC_PIPE2,
	[__NR_inotify_init1] = PPM_SC_INOTIFY_INIT1,
	[__NR_preadv] = PPM_SC_PREADV,
	[__NR_pwritev] = PPM_SC_PWRITEV,
	[__NR_rt_tgsigqueueinfo] = PPM_SC_RT_TGSIGQUEUEINFO,
	[__NR_perf_event_open] = PPM_SC_PERF_EVENT_OPEN,
#ifdef __NR_fanotify_init
	[__NR_fanotify_init] = PPM_SC_FANOTIFY_INIT,
#endif
#ifdef __NR_prlimit64
	[__NR_prlimit64] = PPM_SC_PRLIMIT64,
#endif
#ifdef __NR_clock_adjtime
	[__NR_clock_adjtime] = PPM_SC_CLOCK_ADJTIME,
#endif
#ifdef __NR_syncfs
	[__NR_syncfs] = PPM_SC_SYNCFS,
#endif
#ifdef __NR_setns
	[__NR_setns] = PPM_SC_SETNS,
#endif
	[__NR_getdents64] =  PPM_SC_GETDENTS64,
#ifdef __x86_64__
	/*
	 * Non-multiplexed socket family
	 */
	[__NR_socket] =  PPM_SC_SOCKET,
	[__NR_bind] =	PPM_SC_BIND,
	[__NR_connect] =  PPM_SC_CONNECT,
	[__NR_listen] =  PPM_SC_LISTEN,
	[__NR_accept] =  PPM_SC_ACCEPT,
	[__NR_getsockname] = PPM_SC_GETSOCKNAME,
	[__NR_getpeername] = PPM_SC_GETPEERNAME,
	[__NR_socketpair] = PPM_SC_SOCKETPAIR,
/* [__NR_send] =	PPM_SC_NR_SEND, */
	[__NR_sendto] =  PPM_SC_SENDTO,
/* [__NR_recv] =	PPM_SC_NR_RECV, */
	[__NR_recvfrom] =  PPM_SC_RECVFROM,
	[__NR_shutdown] =  PPM_SC_SHUTDOWN,
	[__NR_setsockopt] = PPM_SC_SETSOCKOPT,
	[__NR_getsockopt] = PPM_SC_GETSOCKOPT,
	[__NR_sendmsg] =  PPM_SC_SENDMSG,
#ifdef __NR_sendmmsg
	[__NR_sendmmsg] =  PPM_SC_SENDMMSG,
#endif
	[__NR_recvmsg] =  PPM_SC_RECVMSG,
#ifdef __NR_recvmmsg
	[__NR_recvmmsg] =  PPM_SC_RECVMMSG,
#endif
	[__NR_accept4] =  PPM_SC_ACCEPT4,
	/*
	 * Non-multiplexed IPC family
	 */
	[__NR_semop] =  PPM_SC_SEMOP,
	[__NR_semget] =  PPM_SC_SEMGET,
	[__NR_semctl] =  PPM_SC_SEMCTL,
	[__NR_msgsnd] =  PPM_SC_MSGSND,
	[__NR_msgrcv] =  PPM_SC_MSGRCV,
	[__NR_msgget] =  PPM_SC_MSGGET,
	[__NR_msgctl] =  PPM_SC_MSGCTL,
/* [__NR_shmatcall] =  PPM_SC_NR_SHMATCALL, */
	[__NR_shmdt] =  PPM_SC_SHMDT,
	[__NR_shmget] =  PPM_SC_SHMGET,
	[__NR_shmctl] =  PPM_SC_SHMCTL,
/* [__NR_fcntl64] =  PPM_SC_NR_FCNTL64, */
#else
	[__NR_statfs64] = PPM_SC_STATFS64,
	[__NR_fstatfs64] = PPM_SC_FSTATFS64,
	[__NR_fstatat64] = PPM_SC_FSTATAT64,
	[__NR_sendfile64] = PPM_SC_SENDFILE64,
	[__NR_ugetrlimit] = PPM_SC_UGETRLIMIT,
	[__NR_bdflush] = PPM_SC_BDFLUSH,
	[__NR_sigprocmask] = PPM_SC_SIGPROCMASK,
	[__NR_ipc] = PPM_SC_IPC,
	[__NR_socketcall] = PPM_SC_SOCKETCALL,
	[__NR_stat64] = PPM_SC_STAT64,
	[__NR_lstat64] = PPM_SC_LSTAT64,
	[__NR_fstat64] = PPM_SC_FSTAT64,
	[__NR_fcntl64] = PPM_SC_FCNTL64,
	[__NR_mmap2] = PPM_SC_MMAP2,
	[__NR__newselect] = PPM_SC__NEWSELECT,
	[__NR_sgetmask] = PPM_SC_SGETMASK,
	[__NR_ssetmask] = PPM_SC_SSETMASK,
/* [__NR_setreuid16] = PPM_SC_NR_SETREUID16, */
/* [__NR_setregid16] = PPM_SC_NR_SETREGID16, */
	[__NR_sigpending] = PPM_SC_SIGPENDING,
	[__NR_olduname] = PPM_SC_OLDUNAME,
	[__NR_umount] = PPM_SC_UMOUNT,
	[__NR_signal] = PPM_SC_SIGNAL,
	[__NR_nice] = PPM_SC_NICE,
	[__NR_stime] = PPM_SC_STIME,
	[__NR__llseek] =	PPM_SC__LLSEEK,
	[__NR_waitpid] = PPM_SC_WAITPID,
	[__NR_pread64] = PPM_SC_PREAD64,
	[__NR_pwrite64] = PPM_SC_PWRITE64,
#endif /* __x86_64__ */
};
