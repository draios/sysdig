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
const struct syscall_evt_pair g_syscall_table[SYSCALL_TABLE_SIZE] = {
	[__NR_open - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_OPEN_E, PPME_SYSCALL_OPEN_X},
	[__NR_creat - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_CREAT_E, PPME_SYSCALL_CREAT_X},
	[__NR_close - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_CLOSE_X},
	[__NR_brk - SYSCALL_TABLE_ID0] =                        {UF_USED, PPME_SYSCALL_BRK_4_E, PPME_SYSCALL_BRK_4_X},
	[__NR_read - SYSCALL_TABLE_ID0] =                       {UF_USED, PPME_SYSCALL_READ_E, PPME_SYSCALL_READ_X},
	[__NR_write - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_WRITE_E, PPME_SYSCALL_WRITE_X},
	[__NR_execve - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_EXECVE_13_E, PPME_SYSCALL_EXECVE_13_X},
	[__NR_clone - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP, PPME_CLONE_16_E, PPME_CLONE_16_X},
	[__NR_pipe - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_PIPE_E, PPME_SYSCALL_PIPE_X},
	[__NR_pipe2 - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_PIPE_E, PPME_SYSCALL_PIPE_X},
	[__NR_eventfd - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_EVENTFD_E, PPME_SYSCALL_EVENTFD_X},
	[__NR_eventfd2 - SYSCALL_TABLE_ID0] =                   {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_EVENTFD_E, PPME_SYSCALL_EVENTFD_X},
	[__NR_futex - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_FUTEX_E, PPME_SYSCALL_FUTEX_X},
	[__NR_stat - SYSCALL_TABLE_ID0] =                       {UF_USED, PPME_SYSCALL_STAT_E, PPME_SYSCALL_STAT_X},
	[__NR_lstat - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_LSTAT_E, PPME_SYSCALL_LSTAT_X},
	[__NR_fstat - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_FSTAT_E, PPME_SYSCALL_FSTAT_X},
	[__NR_epoll_wait - SYSCALL_TABLE_ID0] =                 {UF_USED, PPME_SYSCALL_EPOLLWAIT_E, PPME_SYSCALL_EPOLLWAIT_X},
	[__NR_poll - SYSCALL_TABLE_ID0] =                       {UF_USED, PPME_SYSCALL_POLL_E, PPME_SYSCALL_POLL_X},
#ifdef __NR_select
	[__NR_select - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_SELECT_E, PPME_SYSCALL_SELECT_X},
#endif
	[__NR_lseek - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_LSEEK_E, PPME_SYSCALL_LSEEK_X},
	[__NR_ioctl - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_IOCTL_E, PPME_SYSCALL_IOCTL_X},
	[__NR_getcwd - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_GETCWD_E, PPME_SYSCALL_GETCWD_X},
	[__NR_chdir - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_CHDIR_E, PPME_SYSCALL_CHDIR_X},
	[__NR_fchdir - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_FCHDIR_E, PPME_SYSCALL_FCHDIR_X},
	[__NR_mkdir - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_MKDIR_E, PPME_SYSCALL_MKDIR_X},
	[__NR_rmdir - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_RMDIR_E, PPME_SYSCALL_RMDIR_X},
	[__NR_openat - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_OPENAT_E, PPME_SYSCALL_OPENAT_X},
	[__NR_link - SYSCALL_TABLE_ID0] =                       {UF_USED, PPME_SYSCALL_LINK_E, PPME_SYSCALL_LINK_X},
	[__NR_linkat - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_LINKAT_E, PPME_SYSCALL_LINKAT_X},
	[__NR_unlink - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_UNLINK_E, PPME_SYSCALL_UNLINK_X},
	[__NR_unlinkat - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_UNLINKAT_E, PPME_SYSCALL_UNLINKAT_X},
	[__NR_pread64 - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_PREAD_E, PPME_SYSCALL_PREAD_X},
	[__NR_pwrite64 - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SYSCALL_PWRITE_E, PPME_SYSCALL_PWRITE_X},
	[__NR_readv - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_READV_E, PPME_SYSCALL_READV_X},
	[__NR_writev - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_WRITEV_E, PPME_SYSCALL_WRITEV_X},
	[__NR_preadv - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_PREADV_E, PPME_SYSCALL_PREADV_X},
	[__NR_pwritev - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_PWRITEV_E, PPME_SYSCALL_PWRITEV_X},
	[__NR_dup - SYSCALL_TABLE_ID0] =                        {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_DUP_E, PPME_SYSCALL_DUP_X},
	[__NR_dup2 - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_DUP_E, PPME_SYSCALL_DUP_X},
	[__NR_dup3 - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_DUP_E, PPME_SYSCALL_DUP_X},
	[__NR_signalfd - SYSCALL_TABLE_ID0] =                   {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_SIGNALFD_E, PPME_SYSCALL_SIGNALFD_X},
	[__NR_signalfd4 - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_SIGNALFD_E, PPME_SYSCALL_SIGNALFD_X},
	[__NR_kill - SYSCALL_TABLE_ID0] =                       {UF_USED, PPME_SYSCALL_KILL_E, PPME_SYSCALL_KILL_X},
	[__NR_tkill - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_TKILL_E, PPME_SYSCALL_TKILL_X},
	[__NR_tgkill - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_TGKILL_E, PPME_SYSCALL_TGKILL_X},
	[__NR_nanosleep - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_SYSCALL_NANOSLEEP_E, PPME_SYSCALL_NANOSLEEP_X},
	[__NR_timerfd_create - SYSCALL_TABLE_ID0] =             {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_TIMERFD_CREATE_E, PPME_SYSCALL_TIMERFD_CREATE_X},
	[__NR_inotify_init - SYSCALL_TABLE_ID0] =               {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_INOTIFY_INIT_E, PPME_SYSCALL_INOTIFY_INIT_X},
	[__NR_inotify_init1 - SYSCALL_TABLE_ID0] =              {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_INOTIFY_INIT_E, PPME_SYSCALL_INOTIFY_INIT_X},
	[__NR_getrlimit - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_GETRLIMIT_E, PPME_SYSCALL_GETRLIMIT_X},
	[__NR_setrlimit - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_SETRLIMIT_E, PPME_SYSCALL_SETRLIMIT_X},
#ifdef __NR_prlimit64
	[__NR_prlimit64 - SYSCALL_TABLE_ID0] =                  {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_PRLIMIT_E, PPME_SYSCALL_PRLIMIT_X},
#endif
#ifdef __NR_ugetrlimit
	[__NR_ugetrlimit - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_GETRLIMIT_E, PPME_SYSCALL_GETRLIMIT_X},
#endif
	[__NR_fcntl - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_FCNTL_E, PPME_SYSCALL_FCNTL_X},
#ifdef __NR_fcntl64
	[__NR_fcntl64 - SYSCALL_TABLE_ID0] =                    {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_FCNTL_E, PPME_SYSCALL_FCNTL_X},
#endif
/* [__NR_ppoll - SYSCALL_TABLE_ID0] =			{UF_USED, PPME_GENERIC_E, PPME_GENERIC_X}, */
/* [__NR_old_select - SYSCALL_TABLE_ID0] =	{UF_USED, PPME_GENERIC_E, PPME_GENERIC_X}, */
	[__NR_pselect6 - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_epoll_create - SYSCALL_TABLE_ID0] =               {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_epoll_ctl - SYSCALL_TABLE_ID0] =                  {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_uselib - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_sched_setparam - SYSCALL_TABLE_ID0] =             {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_sched_getparam - SYSCALL_TABLE_ID0] =             {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_fork - SYSCALL_TABLE_ID0] =                       {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_syslog - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_chmod - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_lchown - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_utime - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_mount - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_umount2 - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_setuid - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_getuid - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_ptrace - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_PTRACE_E, PPME_SYSCALL_PTRACE_X},
	[__NR_alarm - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},
	[__NR_pause - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_GENERIC_E, PPME_GENERIC_X},

#ifndef __NR_socketcall
	[__NR_socket - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SOCKET_SOCKET_E, PPME_SOCKET_SOCKET_X},
	[__NR_bind - SYSCALL_TABLE_ID0] =                       {UF_USED, PPME_SOCKET_BIND_E,  PPME_SOCKET_BIND_X},
	[__NR_connect - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SOCKET_CONNECT_E, PPME_SOCKET_CONNECT_X},
	[__NR_listen - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SOCKET_LISTEN_E, PPME_SOCKET_LISTEN_X},
	[__NR_accept - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SOCKET_ACCEPT_E, PPME_SOCKET_ACCEPT_X},
	[__NR_getsockname - SYSCALL_TABLE_ID0] =                {UF_USED, PPME_SOCKET_GETSOCKNAME_E, PPME_SOCKET_GETSOCKNAME_X},
	[__NR_getpeername - SYSCALL_TABLE_ID0] =                {UF_USED, PPME_SOCKET_GETPEERNAME_E, PPME_SOCKET_GETPEERNAME_X},
	[__NR_socketpair - SYSCALL_TABLE_ID0] =                 {UF_USED | UF_NEVER_DROP, PPME_SOCKET_SOCKETPAIR_E, PPME_SOCKET_SOCKETPAIR_X},
	[__NR_sendto - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SOCKET_SENDTO_E, PPME_SOCKET_SENDTO_X},
	[__NR_recvfrom - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SOCKET_RECVFROM_E, PPME_SOCKET_RECVFROM_X},
	[__NR_shutdown - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SOCKET_SHUTDOWN_E, PPME_SOCKET_SHUTDOWN_X},
	[__NR_setsockopt - SYSCALL_TABLE_ID0] =                 {UF_USED, PPME_SOCKET_SETSOCKOPT_E, PPME_SOCKET_SETSOCKOPT_X},
	[__NR_getsockopt - SYSCALL_TABLE_ID0] =                 {UF_USED, PPME_SOCKET_GETSOCKOPT_E, PPME_SOCKET_GETSOCKOPT_X},
	[__NR_sendmsg - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SOCKET_SENDMSG_E, PPME_SOCKET_SENDMSG_X},
	[__NR_accept4 - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SOCKET_ACCEPT4_E, PPME_SOCKET_ACCEPT4_X},
#endif

#ifdef __NR_sendmmsg
	[__NR_sendmmsg - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SOCKET_SENDMMSG_E, PPME_SOCKET_SENDMMSG_X},
#endif
#ifdef __NR_recvmsg
	[__NR_recvmsg - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SOCKET_RECVMSG_E, PPME_SOCKET_RECVMSG_X},
#endif
#ifdef __NR_recvmmsg
	[__NR_recvmmsg - SYSCALL_TABLE_ID0] =                   {UF_USED, PPME_SOCKET_RECVMMSG_E, PPME_SOCKET_RECVMMSG_X},
#endif
#ifdef __NR_stat64
	[__NR_stat64 - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_STAT64_E, PPME_SYSCALL_STAT64_X},
#endif
#ifdef __NR_fstat64
	[__NR_fstat64 - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_FSTAT64_E, PPME_SYSCALL_FSTAT64_X},
#endif
#ifdef __NR__llseek
	[__NR__llseek - SYSCALL_TABLE_ID0] =                    {UF_USED, PPME_SYSCALL_LLSEEK_E, PPME_SYSCALL_LLSEEK_X},
#endif
	[__NR_mmap - SYSCALL_TABLE_ID0] =                    	{UF_USED, PPME_SYSCALL_MMAP_E, PPME_SYSCALL_MMAP_X},
#ifdef __NR_mmap2
	[__NR_mmap2 - SYSCALL_TABLE_ID0] =                    	{UF_USED, PPME_SYSCALL_MMAP2_E, PPME_SYSCALL_MMAP2_X},
#endif
	[__NR_munmap - SYSCALL_TABLE_ID0] =						{UF_USED, PPME_SYSCALL_MUNMAP_E, PPME_SYSCALL_MUNMAP_X},
	[__NR_splice - SYSCALL_TABLE_ID0] =                     {UF_USED, PPME_SYSCALL_SPLICE_E, PPME_SYSCALL_SPLICE_X},
};

/*
 * SYSCALL ROUTING TABLE
 */
const enum ppm_syscall_code g_syscall_code_routing_table[SYSCALL_TABLE_SIZE] = {
	[__NR_restart_syscall - SYSCALL_TABLE_ID0] = PPM_SC_RESTART_SYSCALL,
	[__NR_exit - SYSCALL_TABLE_ID0] = PPM_SC_EXIT,
	[__NR_read - SYSCALL_TABLE_ID0] = PPM_SC_READ,
	[__NR_write - SYSCALL_TABLE_ID0] = PPM_SC_WRITE,
	[__NR_open - SYSCALL_TABLE_ID0] = PPM_SC_OPEN,
	[__NR_close - SYSCALL_TABLE_ID0] = PPM_SC_CLOSE,
	[__NR_creat - SYSCALL_TABLE_ID0] = PPM_SC_CREAT,
	[__NR_link - SYSCALL_TABLE_ID0] = PPM_SC_LINK,
	[__NR_unlink - SYSCALL_TABLE_ID0] = PPM_SC_UNLINK,
	[__NR_chdir - SYSCALL_TABLE_ID0] = PPM_SC_CHDIR,
	[__NR_time - SYSCALL_TABLE_ID0] = PPM_SC_TIME,
	[__NR_mknod - SYSCALL_TABLE_ID0] = PPM_SC_MKNOD,
	[__NR_chmod - SYSCALL_TABLE_ID0] = PPM_SC_CHMOD,
/* [__NR_lchown16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_LCHOWN16, */
	[__NR_stat - SYSCALL_TABLE_ID0] = PPM_SC_STAT,
	[__NR_lseek - SYSCALL_TABLE_ID0] = PPM_SC_LSEEK,
	[__NR_getpid - SYSCALL_TABLE_ID0] = PPM_SC_GETPID,
	[__NR_mount - SYSCALL_TABLE_ID0] = PPM_SC_MOUNT,
/* [__NR_oldumount - SYSCALL_TABLE_ID0] = PPM_SC_NR_OLDUMOUNT, */
/* [__NR_setuid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETUID16, */
/* [__NR_getuid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_GETUID16, */
	[__NR_ptrace - SYSCALL_TABLE_ID0] = PPM_SC_PTRACE,
	[__NR_alarm - SYSCALL_TABLE_ID0] = PPM_SC_ALARM,
	[__NR_fstat - SYSCALL_TABLE_ID0] = PPM_SC_FSTAT,
	[__NR_pause - SYSCALL_TABLE_ID0] = PPM_SC_PAUSE,
	[__NR_utime - SYSCALL_TABLE_ID0] = PPM_SC_UTIME,
	[__NR_access - SYSCALL_TABLE_ID0] = PPM_SC_ACCESS,
	[__NR_sync - SYSCALL_TABLE_ID0] = PPM_SC_SYNC,
	[__NR_kill - SYSCALL_TABLE_ID0] = PPM_SC_KILL,
	[__NR_rename - SYSCALL_TABLE_ID0] = PPM_SC_RENAME,
	[__NR_mkdir - SYSCALL_TABLE_ID0] = PPM_SC_MKDIR,
	[__NR_rmdir - SYSCALL_TABLE_ID0] = PPM_SC_RMDIR,
	[__NR_dup - SYSCALL_TABLE_ID0] = PPM_SC_DUP,
	[__NR_pipe - SYSCALL_TABLE_ID0] = PPM_SC_PIPE,
	[__NR_times - SYSCALL_TABLE_ID0] = PPM_SC_TIMES,
	[__NR_brk - SYSCALL_TABLE_ID0] = PPM_SC_BRK,
/* [__NR_setgid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETGID16, */
/* [__NR_getgid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_GETGID16, */
/* [__NR_geteuid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_GETEUID16, */
/* [__NR_getegid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_GETEGID16, */
	[__NR_acct - SYSCALL_TABLE_ID0] = PPM_SC_ACCT,
	[__NR_ioctl - SYSCALL_TABLE_ID0] = PPM_SC_IOCTL,
	[__NR_fcntl - SYSCALL_TABLE_ID0] = PPM_SC_FCNTL,
	[__NR_setpgid - SYSCALL_TABLE_ID0] = PPM_SC_SETPGID,
	[__NR_umask - SYSCALL_TABLE_ID0] = PPM_SC_UMASK,
	[__NR_chroot - SYSCALL_TABLE_ID0] = PPM_SC_CHROOT,
	[__NR_ustat - SYSCALL_TABLE_ID0] = PPM_SC_USTAT,
	[__NR_dup2 - SYSCALL_TABLE_ID0] = PPM_SC_DUP2,
	[__NR_getppid - SYSCALL_TABLE_ID0] = PPM_SC_GETPPID,
	[__NR_getpgrp - SYSCALL_TABLE_ID0] = PPM_SC_GETPGRP,
	[__NR_setsid - SYSCALL_TABLE_ID0] = PPM_SC_SETSID,
	[__NR_sethostname - SYSCALL_TABLE_ID0] = PPM_SC_SETHOSTNAME,
	[__NR_setrlimit - SYSCALL_TABLE_ID0] = PPM_SC_SETRLIMIT,
/* [__NR_old_getrlimit - SYSCALL_TABLE_ID0] = PPM_SC_NR_OLD_GETRLIMIT, */
	[__NR_getrusage - SYSCALL_TABLE_ID0] = PPM_SC_GETRUSAGE,
	[__NR_gettimeofday - SYSCALL_TABLE_ID0] = PPM_SC_GETTIMEOFDAY,
	[__NR_settimeofday - SYSCALL_TABLE_ID0] = PPM_SC_SETTIMEOFDAY,
/* [__NR_getgroups16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_GETGROUPS16, */
/* [__NR_setgroups16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETGROUPS16, */
/* [__NR_old_select - SYSCALL_TABLE_ID0] = PPM_SC_NR_OLD_SELECT, */
	[__NR_symlink - SYSCALL_TABLE_ID0] = PPM_SC_SYMLINK,
	[__NR_lstat - SYSCALL_TABLE_ID0] = PPM_SC_LSTAT,
	[__NR_readlink - SYSCALL_TABLE_ID0] = PPM_SC_READLINK,
	[__NR_uselib - SYSCALL_TABLE_ID0] = PPM_SC_USELIB,
	[__NR_swapon - SYSCALL_TABLE_ID0] = PPM_SC_SWAPON,
	[__NR_reboot - SYSCALL_TABLE_ID0] = PPM_SC_REBOOT,
/* [__NR_old_readdir - SYSCALL_TABLE_ID0] = PPM_SC_NR_OLD_READDIR, */
/* [__NR_old_mmap - SYSCALL_TABLE_ID0] = PPM_SC_NR_OLD_MMAP, */
	[__NR_mmap - SYSCALL_TABLE_ID0] = PPM_SC_MMAP,
	[__NR_munmap - SYSCALL_TABLE_ID0] = PPM_SC_MUNMAP,
	[__NR_truncate - SYSCALL_TABLE_ID0] = PPM_SC_TRUNCATE,
	[__NR_ftruncate - SYSCALL_TABLE_ID0] = PPM_SC_FTRUNCATE,
	[__NR_fchmod - SYSCALL_TABLE_ID0] = PPM_SC_FCHMOD,
/* [__NR_fchown16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_FCHOWN16, */
	[__NR_getpriority - SYSCALL_TABLE_ID0] = PPM_SC_GETPRIORITY,
	[__NR_setpriority - SYSCALL_TABLE_ID0] = PPM_SC_SETPRIORITY,
	[__NR_statfs - SYSCALL_TABLE_ID0] = PPM_SC_STATFS,
	[__NR_fstatfs - SYSCALL_TABLE_ID0] = PPM_SC_FSTATFS,
	[__NR_syslog - SYSCALL_TABLE_ID0] = PPM_SC_SYSLOG,
	[__NR_setitimer - SYSCALL_TABLE_ID0] = PPM_SC_SETITIMER,
	[__NR_getitimer - SYSCALL_TABLE_ID0] = PPM_SC_GETITIMER,
/* [__NR_newstat - SYSCALL_TABLE_ID0] = PPM_SC_NR_NEWSTAT, */
/* [__NR_newlstat - SYSCALL_TABLE_ID0] = PPM_SC_NR_NEWLSTAT, */
/* [__NR_newfstat - SYSCALL_TABLE_ID0] = PPM_SC_NR_NEWFSTAT, */
	[__NR_uname - SYSCALL_TABLE_ID0] = PPM_SC_UNAME,
	[__NR_vhangup - SYSCALL_TABLE_ID0] = PPM_SC_VHANGUP,
	[__NR_wait4 - SYSCALL_TABLE_ID0] = PPM_SC_WAIT4,
	[__NR_swapoff - SYSCALL_TABLE_ID0] = PPM_SC_SWAPOFF,
	[__NR_sysinfo - SYSCALL_TABLE_ID0] = PPM_SC_SYSINFO,
	[__NR_fsync - SYSCALL_TABLE_ID0] = PPM_SC_FSYNC,
	[__NR_setdomainname - SYSCALL_TABLE_ID0] = PPM_SC_SETDOMAINNAME,
/* [__NR_newuname - SYSCALL_TABLE_ID0] = PPM_SC_NR_NEWUNAME, */
	[__NR_adjtimex - SYSCALL_TABLE_ID0] = PPM_SC_ADJTIMEX,
	[__NR_mprotect - SYSCALL_TABLE_ID0] = PPM_SC_MPROTECT,
	[__NR_init_module - SYSCALL_TABLE_ID0] = PPM_SC_INIT_MODULE,
	[__NR_delete_module - SYSCALL_TABLE_ID0] = PPM_SC_DELETE_MODULE,
	[__NR_quotactl - SYSCALL_TABLE_ID0] = PPM_SC_QUOTACTL,
	[__NR_getpgid - SYSCALL_TABLE_ID0] = PPM_SC_GETPGID,
	[__NR_fchdir - SYSCALL_TABLE_ID0] = PPM_SC_FCHDIR,
	[__NR_sysfs - SYSCALL_TABLE_ID0] = PPM_SC_SYSFS,
	[__NR_personality - SYSCALL_TABLE_ID0] = PPM_SC_PERSONALITY,
/* [__NR_setfsuid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETFSUID16, */
/* [__NR_setfsgid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETFSGID16, */
/* [__NR_llseek - SYSCALL_TABLE_ID0] = PPM_SC_NR_LLSEEK, */
	[__NR_getdents - SYSCALL_TABLE_ID0] = PPM_SC_GETDENTS,
#ifdef __NR_select
	[__NR_select - SYSCALL_TABLE_ID0] = PPM_SC_SELECT,
#endif
	[__NR_flock - SYSCALL_TABLE_ID0] = PPM_SC_FLOCK,
	[__NR_msync - SYSCALL_TABLE_ID0] = PPM_SC_MSYNC,
	[__NR_readv - SYSCALL_TABLE_ID0] = PPM_SC_READV,
	[__NR_writev - SYSCALL_TABLE_ID0] = PPM_SC_WRITEV,
	[__NR_getsid - SYSCALL_TABLE_ID0] = PPM_SC_GETSID,
	[__NR_fdatasync - SYSCALL_TABLE_ID0] = PPM_SC_FDATASYNC,
/* [__NR_sysctl - SYSCALL_TABLE_ID0] = PPM_SC_NR_SYSCTL, */
	[__NR_mlock - SYSCALL_TABLE_ID0] = PPM_SC_MLOCK,
	[__NR_munlock - SYSCALL_TABLE_ID0] = PPM_SC_MUNLOCK,
	[__NR_mlockall - SYSCALL_TABLE_ID0] = PPM_SC_MLOCKALL,
	[__NR_munlockall - SYSCALL_TABLE_ID0] = PPM_SC_MUNLOCKALL,
	[__NR_sched_setparam - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_SETPARAM,
	[__NR_sched_getparam - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_GETPARAM,
	[__NR_sched_setscheduler - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_SETSCHEDULER,
	[__NR_sched_getscheduler - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_GETSCHEDULER,
	[__NR_sched_yield - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_YIELD,
	[__NR_sched_get_priority_max - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_GET_PRIORITY_MAX,
	[__NR_sched_get_priority_min - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_GET_PRIORITY_MIN,
	[__NR_sched_rr_get_interval - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_RR_GET_INTERVAL,
	[__NR_nanosleep - SYSCALL_TABLE_ID0] = PPM_SC_NANOSLEEP,
	[__NR_mremap - SYSCALL_TABLE_ID0] = PPM_SC_MREMAP,
/* [__NR_setresuid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETRESUID16, */
/* [__NR_getresuid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_GETRESUID16, */
	[__NR_poll - SYSCALL_TABLE_ID0] = PPM_SC_POLL,
/* [__NR_setresgid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETRESGID16, */
/* [__NR_getresgid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_GETRESGID16, */
	[__NR_prctl - SYSCALL_TABLE_ID0] = PPM_SC_PRCTL,
#ifdef __NR_arch_prctl
	[__NR_arch_prctl - SYSCALL_TABLE_ID0] = PPM_SC_ARCH_PRCTL,
#endif
	[__NR_rt_sigaction - SYSCALL_TABLE_ID0] = PPM_SC_RT_SIGACTION,
	[__NR_rt_sigprocmask - SYSCALL_TABLE_ID0] = PPM_SC_RT_SIGPROCMASK,
	[__NR_rt_sigpending - SYSCALL_TABLE_ID0] = PPM_SC_RT_SIGPENDING,
	[__NR_rt_sigtimedwait - SYSCALL_TABLE_ID0] = PPM_SC_RT_SIGTIMEDWAIT,
	[__NR_rt_sigqueueinfo - SYSCALL_TABLE_ID0] = PPM_SC_RT_SIGQUEUEINFO,
	[__NR_rt_sigsuspend - SYSCALL_TABLE_ID0] = PPM_SC_RT_SIGSUSPEND,
/* [__NR_chown16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_CHOWN16, */
	[__NR_getcwd - SYSCALL_TABLE_ID0] = PPM_SC_GETCWD,
	[__NR_capget - SYSCALL_TABLE_ID0] = PPM_SC_CAPGET,
	[__NR_capset - SYSCALL_TABLE_ID0] = PPM_SC_CAPSET,
	[__NR_sendfile - SYSCALL_TABLE_ID0] = PPM_SC_SENDFILE,
	[__NR_getrlimit - SYSCALL_TABLE_ID0] = PPM_SC_GETRLIMIT,
/* [__NR_mmap_pgoff - SYSCALL_TABLE_ID0] = PPM_SC_NR_MMAP_PGOFF, */
	[__NR_lchown - SYSCALL_TABLE_ID0] = PPM_SC_LCHOWN,
	[__NR_getuid - SYSCALL_TABLE_ID0] = PPM_SC_GETUID,
	[__NR_getgid - SYSCALL_TABLE_ID0] = PPM_SC_GETGID,
	[__NR_geteuid - SYSCALL_TABLE_ID0] = PPM_SC_GETEUID,
	[__NR_getegid - SYSCALL_TABLE_ID0] = PPM_SC_GETEGID,
	[__NR_setreuid - SYSCALL_TABLE_ID0] = PPM_SC_SETREUID,
	[__NR_setregid - SYSCALL_TABLE_ID0] = PPM_SC_SETREGID,
	[__NR_getgroups - SYSCALL_TABLE_ID0] = PPM_SC_GETGROUPS,
	[__NR_setgroups - SYSCALL_TABLE_ID0] = PPM_SC_SETGROUPS,
	[__NR_fchown - SYSCALL_TABLE_ID0] = PPM_SC_FCHOWN,
	[__NR_setresuid - SYSCALL_TABLE_ID0] = PPM_SC_SETRESUID,
	[__NR_getresuid - SYSCALL_TABLE_ID0] = PPM_SC_GETRESUID,
	[__NR_setresgid - SYSCALL_TABLE_ID0] = PPM_SC_SETRESGID,
	[__NR_getresgid - SYSCALL_TABLE_ID0] = PPM_SC_GETRESGID,
	[__NR_chown - SYSCALL_TABLE_ID0] = PPM_SC_CHOWN,
	[__NR_setuid - SYSCALL_TABLE_ID0] = PPM_SC_SETUID,
	[__NR_setgid - SYSCALL_TABLE_ID0] = PPM_SC_SETGID,
	[__NR_setfsuid - SYSCALL_TABLE_ID0] = PPM_SC_SETFSUID,
	[__NR_setfsgid - SYSCALL_TABLE_ID0] = PPM_SC_SETFSGID,
	[__NR_pivot_root - SYSCALL_TABLE_ID0] = PPM_SC_PIVOT_ROOT,
	[__NR_mincore - SYSCALL_TABLE_ID0] = PPM_SC_MINCORE,
	[__NR_madvise - SYSCALL_TABLE_ID0] = PPM_SC_MADVISE,
	[__NR_gettid - SYSCALL_TABLE_ID0] = PPM_SC_GETTID,
	[__NR_setxattr - SYSCALL_TABLE_ID0] = PPM_SC_SETXATTR,
	[__NR_lsetxattr - SYSCALL_TABLE_ID0] = PPM_SC_LSETXATTR,
	[__NR_fsetxattr - SYSCALL_TABLE_ID0] = PPM_SC_FSETXATTR,
	[__NR_getxattr - SYSCALL_TABLE_ID0] = PPM_SC_GETXATTR,
	[__NR_lgetxattr - SYSCALL_TABLE_ID0] = PPM_SC_LGETXATTR,
	[__NR_fgetxattr - SYSCALL_TABLE_ID0] = PPM_SC_FGETXATTR,
	[__NR_listxattr - SYSCALL_TABLE_ID0] = PPM_SC_LISTXATTR,
	[__NR_llistxattr - SYSCALL_TABLE_ID0] = PPM_SC_LLISTXATTR,
	[__NR_flistxattr - SYSCALL_TABLE_ID0] = PPM_SC_FLISTXATTR,
	[__NR_removexattr - SYSCALL_TABLE_ID0] = PPM_SC_REMOVEXATTR,
	[__NR_lremovexattr - SYSCALL_TABLE_ID0] = PPM_SC_LREMOVEXATTR,
	[__NR_fremovexattr - SYSCALL_TABLE_ID0] = PPM_SC_FREMOVEXATTR,
	[__NR_tkill - SYSCALL_TABLE_ID0] = PPM_SC_TKILL,
	[__NR_futex - SYSCALL_TABLE_ID0] = PPM_SC_FUTEX,
	[__NR_sched_setaffinity - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_SETAFFINITY,
	[__NR_sched_getaffinity - SYSCALL_TABLE_ID0] = PPM_SC_SCHED_GETAFFINITY,
#ifdef __NR_set_thread_area
	[__NR_set_thread_area - SYSCALL_TABLE_ID0] = PPM_SC_SET_THREAD_AREA,
#endif
#ifdef __NR_get_thread_area
	[__NR_get_thread_area - SYSCALL_TABLE_ID0] = PPM_SC_GET_THREAD_AREA,
#endif
	[__NR_io_setup - SYSCALL_TABLE_ID0] = PPM_SC_IO_SETUP,
	[__NR_io_destroy - SYSCALL_TABLE_ID0] = PPM_SC_IO_DESTROY,
	[__NR_io_getevents - SYSCALL_TABLE_ID0] = PPM_SC_IO_GETEVENTS,
	[__NR_io_submit - SYSCALL_TABLE_ID0] = PPM_SC_IO_SUBMIT,
	[__NR_io_cancel - SYSCALL_TABLE_ID0] = PPM_SC_IO_CANCEL,
	[__NR_exit_group - SYSCALL_TABLE_ID0] = PPM_SC_EXIT_GROUP,
	[__NR_epoll_create - SYSCALL_TABLE_ID0] = PPM_SC_EPOLL_CREATE,
	[__NR_epoll_ctl - SYSCALL_TABLE_ID0] = PPM_SC_EPOLL_CTL,
	[__NR_epoll_wait - SYSCALL_TABLE_ID0] = PPM_SC_EPOLL_WAIT,
	[__NR_remap_file_pages - SYSCALL_TABLE_ID0] = PPM_SC_REMAP_FILE_PAGES,
	[__NR_set_tid_address - SYSCALL_TABLE_ID0] = PPM_SC_SET_TID_ADDRESS,
	[__NR_timer_create - SYSCALL_TABLE_ID0] = PPM_SC_TIMER_CREATE,
	[__NR_timer_settime - SYSCALL_TABLE_ID0] = PPM_SC_TIMER_SETTIME,
	[__NR_timer_gettime - SYSCALL_TABLE_ID0] = PPM_SC_TIMER_GETTIME,
	[__NR_timer_getoverrun - SYSCALL_TABLE_ID0] = PPM_SC_TIMER_GETOVERRUN,
	[__NR_timer_delete - SYSCALL_TABLE_ID0] = PPM_SC_TIMER_DELETE,
	[__NR_clock_settime - SYSCALL_TABLE_ID0] = PPM_SC_CLOCK_SETTIME,
	[__NR_clock_gettime - SYSCALL_TABLE_ID0] = PPM_SC_CLOCK_GETTIME,
	[__NR_clock_getres - SYSCALL_TABLE_ID0] = PPM_SC_CLOCK_GETRES,
	[__NR_clock_nanosleep - SYSCALL_TABLE_ID0] = PPM_SC_CLOCK_NANOSLEEP,
	[__NR_tgkill - SYSCALL_TABLE_ID0] = PPM_SC_TGKILL,
	[__NR_utimes - SYSCALL_TABLE_ID0] = PPM_SC_UTIMES,
	[__NR_mq_open - SYSCALL_TABLE_ID0] = PPM_SC_MQ_OPEN,
	[__NR_mq_unlink - SYSCALL_TABLE_ID0] = PPM_SC_MQ_UNLINK,
	[__NR_mq_timedsend - SYSCALL_TABLE_ID0] = PPM_SC_MQ_TIMEDSEND,
	[__NR_mq_timedreceive - SYSCALL_TABLE_ID0] = PPM_SC_MQ_TIMEDRECEIVE,
	[__NR_mq_notify - SYSCALL_TABLE_ID0] = PPM_SC_MQ_NOTIFY,
	[__NR_mq_getsetattr - SYSCALL_TABLE_ID0] = PPM_SC_MQ_GETSETATTR,
	[__NR_kexec_load - SYSCALL_TABLE_ID0] = PPM_SC_KEXEC_LOAD,
	[__NR_waitid - SYSCALL_TABLE_ID0] = PPM_SC_WAITID,
	[__NR_add_key - SYSCALL_TABLE_ID0] = PPM_SC_ADD_KEY,
	[__NR_request_key - SYSCALL_TABLE_ID0] = PPM_SC_REQUEST_KEY,
	[__NR_keyctl - SYSCALL_TABLE_ID0] = PPM_SC_KEYCTL,
	[__NR_ioprio_set - SYSCALL_TABLE_ID0] = PPM_SC_IOPRIO_SET,
	[__NR_ioprio_get - SYSCALL_TABLE_ID0] = PPM_SC_IOPRIO_GET,
	[__NR_inotify_init - SYSCALL_TABLE_ID0] = PPM_SC_INOTIFY_INIT,
	[__NR_inotify_add_watch - SYSCALL_TABLE_ID0] = PPM_SC_INOTIFY_ADD_WATCH,
	[__NR_inotify_rm_watch - SYSCALL_TABLE_ID0] = PPM_SC_INOTIFY_RM_WATCH,
	[__NR_openat - SYSCALL_TABLE_ID0] = PPM_SC_OPENAT,
	[__NR_mkdirat - SYSCALL_TABLE_ID0] = PPM_SC_MKDIRAT,
	[__NR_mknodat - SYSCALL_TABLE_ID0] = PPM_SC_MKNODAT,
	[__NR_fchownat - SYSCALL_TABLE_ID0] = PPM_SC_FCHOWNAT,
	[__NR_futimesat - SYSCALL_TABLE_ID0] = PPM_SC_FUTIMESAT,
	[__NR_unlinkat - SYSCALL_TABLE_ID0] = PPM_SC_UNLINKAT,
	[__NR_renameat - SYSCALL_TABLE_ID0] = PPM_SC_RENAMEAT,
	[__NR_linkat - SYSCALL_TABLE_ID0] = PPM_SC_LINKAT,
	[__NR_symlinkat - SYSCALL_TABLE_ID0] = PPM_SC_SYMLINKAT,
	[__NR_readlinkat - SYSCALL_TABLE_ID0] = PPM_SC_READLINKAT,
	[__NR_fchmodat - SYSCALL_TABLE_ID0] = PPM_SC_FCHMODAT,
	[__NR_faccessat - SYSCALL_TABLE_ID0] = PPM_SC_FACCESSAT,
	[__NR_pselect6 - SYSCALL_TABLE_ID0] = PPM_SC_PSELECT6,
	[__NR_ppoll - SYSCALL_TABLE_ID0] = PPM_SC_PPOLL,
	[__NR_unshare - SYSCALL_TABLE_ID0] = PPM_SC_UNSHARE,
	[__NR_set_robust_list - SYSCALL_TABLE_ID0] = PPM_SC_SET_ROBUST_LIST,
	[__NR_get_robust_list - SYSCALL_TABLE_ID0] = PPM_SC_GET_ROBUST_LIST,
	[__NR_splice - SYSCALL_TABLE_ID0] = PPM_SC_SPLICE,
	[__NR_tee - SYSCALL_TABLE_ID0] = PPM_SC_TEE,
	[__NR_vmsplice - SYSCALL_TABLE_ID0] = PPM_SC_VMSPLICE,
#ifdef __NR_getcpu
	[__NR_getcpu - SYSCALL_TABLE_ID0] = PPM_SC_GETCPU,
#endif
	[__NR_epoll_pwait - SYSCALL_TABLE_ID0] = PPM_SC_EPOLL_PWAIT,
	[__NR_utimensat - SYSCALL_TABLE_ID0] = PPM_SC_UTIMENSAT,
	[__NR_signalfd - SYSCALL_TABLE_ID0] = PPM_SC_SIGNALFD,
	[__NR_timerfd_create - SYSCALL_TABLE_ID0] = PPM_SC_TIMERFD_CREATE,
	[__NR_eventfd - SYSCALL_TABLE_ID0] = PPM_SC_EVENTFD,
	[__NR_timerfd_settime - SYSCALL_TABLE_ID0] = PPM_SC_TIMERFD_SETTIME,
	[__NR_timerfd_gettime - SYSCALL_TABLE_ID0] = PPM_SC_TIMERFD_GETTIME,
	[__NR_signalfd4 - SYSCALL_TABLE_ID0] = PPM_SC_SIGNALFD4,
	[__NR_eventfd2 - SYSCALL_TABLE_ID0] = PPM_SC_EVENTFD2,
	[__NR_epoll_create1 - SYSCALL_TABLE_ID0] = PPM_SC_EPOLL_CREATE1,
	[__NR_dup3 - SYSCALL_TABLE_ID0] = PPM_SC_DUP3,
	[__NR_pipe2 - SYSCALL_TABLE_ID0] = PPM_SC_PIPE2,
	[__NR_inotify_init1 - SYSCALL_TABLE_ID0] = PPM_SC_INOTIFY_INIT1,
	[__NR_preadv - SYSCALL_TABLE_ID0] = PPM_SC_PREADV,
	[__NR_pwritev - SYSCALL_TABLE_ID0] = PPM_SC_PWRITEV,
	[__NR_rt_tgsigqueueinfo - SYSCALL_TABLE_ID0] = PPM_SC_RT_TGSIGQUEUEINFO,
	[__NR_perf_event_open - SYSCALL_TABLE_ID0] = PPM_SC_PERF_EVENT_OPEN,
#ifdef __NR_fanotify_init
	[__NR_fanotify_init - SYSCALL_TABLE_ID0] = PPM_SC_FANOTIFY_INIT,
#endif
#ifdef __NR_prlimit64
	[__NR_prlimit64 - SYSCALL_TABLE_ID0] = PPM_SC_PRLIMIT64,
#endif
#ifdef __NR_clock_adjtime
	[__NR_clock_adjtime - SYSCALL_TABLE_ID0] = PPM_SC_CLOCK_ADJTIME,
#endif
#ifdef __NR_syncfs
	[__NR_syncfs - SYSCALL_TABLE_ID0] = PPM_SC_SYNCFS,
#endif
#ifdef __NR_setns
	[__NR_setns - SYSCALL_TABLE_ID0] = PPM_SC_SETNS,
#endif
	[__NR_getdents64 - SYSCALL_TABLE_ID0] =  PPM_SC_GETDENTS64,
#ifndef __NR_socketcall
	/*
	 * Non-multiplexed socket family
	 */
	[__NR_socket - SYSCALL_TABLE_ID0] =  PPM_SC_SOCKET,
	[__NR_bind - SYSCALL_TABLE_ID0] =	PPM_SC_BIND,
	[__NR_connect - SYSCALL_TABLE_ID0] =  PPM_SC_CONNECT,
	[__NR_listen - SYSCALL_TABLE_ID0] =  PPM_SC_LISTEN,
	[__NR_accept - SYSCALL_TABLE_ID0] =  PPM_SC_ACCEPT,
	[__NR_getsockname - SYSCALL_TABLE_ID0] = PPM_SC_GETSOCKNAME,
	[__NR_getpeername - SYSCALL_TABLE_ID0] = PPM_SC_GETPEERNAME,
	[__NR_socketpair - SYSCALL_TABLE_ID0] = PPM_SC_SOCKETPAIR,
/* [__NR_send - SYSCALL_TABLE_ID0] =	PPM_SC_NR_SEND, */
	[__NR_sendto - SYSCALL_TABLE_ID0] =  PPM_SC_SENDTO,
/* [__NR_recv - SYSCALL_TABLE_ID0] =	PPM_SC_NR_RECV, */
	[__NR_recvfrom - SYSCALL_TABLE_ID0] =  PPM_SC_RECVFROM,
	[__NR_shutdown - SYSCALL_TABLE_ID0] =  PPM_SC_SHUTDOWN,
	[__NR_setsockopt - SYSCALL_TABLE_ID0] = PPM_SC_SETSOCKOPT,
	[__NR_getsockopt - SYSCALL_TABLE_ID0] = PPM_SC_GETSOCKOPT,
	[__NR_sendmsg - SYSCALL_TABLE_ID0] =  PPM_SC_SENDMSG,
	[__NR_recvmsg - SYSCALL_TABLE_ID0] =  PPM_SC_RECVMSG,
	[__NR_accept4 - SYSCALL_TABLE_ID0] =  PPM_SC_ACCEPT4,
#else
	[__NR_socketcall - SYSCALL_TABLE_ID0] = PPM_SC_SOCKETCALL,
#endif


#ifdef __NR_sendmmsg
	[__NR_sendmmsg - SYSCALL_TABLE_ID0] =  PPM_SC_SENDMMSG,
#endif
#ifdef __NR_recvmmsg
	[__NR_recvmmsg - SYSCALL_TABLE_ID0] =  PPM_SC_RECVMMSG,
#endif
	/*
	 * Non-multiplexed IPC family
	 */
#ifdef __NR_semop
	[__NR_semop - SYSCALL_TABLE_ID0] =  PPM_SC_SEMOP,
#endif
#ifdef __NR_semget
	[__NR_semget - SYSCALL_TABLE_ID0] =  PPM_SC_SEMGET,
#endif
#ifdef __NR_semctl
	[__NR_semctl - SYSCALL_TABLE_ID0] =  PPM_SC_SEMCTL,
#endif
#ifdef __NR_msgsnd
	[__NR_msgsnd - SYSCALL_TABLE_ID0] =  PPM_SC_MSGSND,
#endif
#ifdef __NR_msgrcv
	[__NR_msgrcv - SYSCALL_TABLE_ID0] =  PPM_SC_MSGRCV,
#endif
#ifdef __NR_msgget
	[__NR_msgget - SYSCALL_TABLE_ID0] =  PPM_SC_MSGGET,
#endif
#ifdef __NR_msgctl
	[__NR_msgctl - SYSCALL_TABLE_ID0] =  PPM_SC_MSGCTL,
#endif
/* [__NR_shmatcall - SYSCALL_TABLE_ID0] =  PPM_SC_NR_SHMATCALL, */
#ifdef __NR_shmdt
	[__NR_shmdt - SYSCALL_TABLE_ID0] =  PPM_SC_SHMDT,
#endif
#ifdef __NR_shmget
	[__NR_shmget - SYSCALL_TABLE_ID0] =  PPM_SC_SHMGET,
#endif
#ifdef __NR_shmctl
	[__NR_shmctl - SYSCALL_TABLE_ID0] =  PPM_SC_SHMCTL,
#endif
/* [__NR_fcntl64 - SYSCALL_TABLE_ID0] =  PPM_SC_NR_FCNTL64, */
#ifdef __NR_statfs64
	[__NR_statfs64 - SYSCALL_TABLE_ID0] = PPM_SC_STATFS64,
#endif
#ifdef __NR_fstatfs64
	[__NR_fstatfs64 - SYSCALL_TABLE_ID0] = PPM_SC_FSTATFS64,
#endif
#ifdef __NR_fstatat64
	[__NR_fstatat64 - SYSCALL_TABLE_ID0] = PPM_SC_FSTATAT64,
#endif
#ifdef __NR_sendfile64
	[__NR_sendfile64 - SYSCALL_TABLE_ID0] = PPM_SC_SENDFILE64,
#endif
#ifdef __NR_ugetrlimit
	[__NR_ugetrlimit - SYSCALL_TABLE_ID0] = PPM_SC_UGETRLIMIT,
#endif
#ifdef __NR_bdflush
	[__NR_bdflush - SYSCALL_TABLE_ID0] = PPM_SC_BDFLUSH,
#endif
#ifdef __NR_sigprocmask
	[__NR_sigprocmask - SYSCALL_TABLE_ID0] = PPM_SC_SIGPROCMASK,
#endif
#ifdef __NR_ipc
	[__NR_ipc - SYSCALL_TABLE_ID0] = PPM_SC_IPC,
#endif
#ifdef __NR_stat64
	[__NR_stat64 - SYSCALL_TABLE_ID0] = PPM_SC_STAT64,
#endif
#ifdef __NR_lstat64
	[__NR_lstat64 - SYSCALL_TABLE_ID0] = PPM_SC_LSTAT64,
#endif
#ifdef __NR_fstat64
	[__NR_fstat64 - SYSCALL_TABLE_ID0] = PPM_SC_FSTAT64,
#endif
#ifdef __NR_fcntl64
	[__NR_fcntl64 - SYSCALL_TABLE_ID0] = PPM_SC_FCNTL64,
#endif
#ifdef __NR_mmap2
	[__NR_mmap2 - SYSCALL_TABLE_ID0] = PPM_SC_MMAP2,
#endif
#ifdef __NR__newselect
	[__NR__newselect - SYSCALL_TABLE_ID0] = PPM_SC__NEWSELECT,
#endif
#ifdef __NR_sgetmask
	[__NR_sgetmask - SYSCALL_TABLE_ID0] = PPM_SC_SGETMASK,
#endif
#ifdef __NR_ssetmask
	[__NR_ssetmask - SYSCALL_TABLE_ID0] = PPM_SC_SSETMASK,
#endif

/* [__NR_setreuid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETREUID16, */
/* [__NR_setregid16 - SYSCALL_TABLE_ID0] = PPM_SC_NR_SETREGID16, */
#ifdef __NR_sigpending
	[__NR_sigpending - SYSCALL_TABLE_ID0] = PPM_SC_SIGPENDING,
#endif
#ifdef __NR_olduname
	[__NR_olduname - SYSCALL_TABLE_ID0] = PPM_SC_OLDUNAME,
#endif
#ifdef __NR_umount
	[__NR_umount - SYSCALL_TABLE_ID0] = PPM_SC_UMOUNT,
#endif
#ifdef __NR_signal
	[__NR_signal - SYSCALL_TABLE_ID0] = PPM_SC_SIGNAL,
#endif
#ifdef __NR_nice
	[__NR_nice - SYSCALL_TABLE_ID0] = PPM_SC_NICE,
#endif
#ifdef __NR_stime
	[__NR_stime - SYSCALL_TABLE_ID0] = PPM_SC_STIME,
#endif
#ifdef __NR__llseek
	[__NR__llseek - SYSCALL_TABLE_ID0] = PPM_SC__LLSEEK,
#endif
#ifdef __NR_waitpid
	[__NR_waitpid - SYSCALL_TABLE_ID0] = PPM_SC_WAITPID,
#endif
#ifdef __NR_pread64
	[__NR_pread64 - SYSCALL_TABLE_ID0] = PPM_SC_PREAD64,
#endif
#ifdef __NR_pwrite64
	[__NR_pwrite64 - SYSCALL_TABLE_ID0] = PPM_SC_PWRITE64,
#endif
#ifdef __NR_shmat
	[__NR_shmat - SYSCALL_TABLE_ID0] = PPM_SC_SHMAT,
#endif
#ifdef __NR_rt_sigreturn
	[__NR_rt_sigreturn - SYSCALL_TABLE_ID0] = PPM_SC_SIGRETURN,
#endif
#ifdef __NR_fallocate
	[__NR_fallocate - SYSCALL_TABLE_ID0] = PPM_SC_FALLOCATE,
#endif
#ifdef __NR_newfstatat
	[__NR_newfstatat - SYSCALL_TABLE_ID0] = PPM_SC_NEWFSSTAT,
#endif
};
