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

#include "../common/sysdig_types.h"
#include "../../driver/ppm_events_public.h"
#include "scap.h"

/*
 * SYSCALL INFO TABLE
 */
const struct ppm_syscall_desc g_syscall_info_table[PPM_SC_MAX] = {
	/*dummy*/ { EC_OTHER, (enum ppm_event_flags)(EF_NONE), "<unknown>" },
	/*PPM_SC_RESTART_SYSCALL*/ { EC_SYSTEM, (enum ppm_event_flags)(EF_NONE), "restart_syscall" },
	/*PPM_SC_EXIT*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "exit" },
	/*PPM_SC_READ*/ { EC_IO_READ, (enum ppm_event_flags)(EF_DROP_FALCO), "read" },
	/*PPM_SC_WRITE*/ { EC_IO_WRITE, (enum ppm_event_flags)(EF_DROP_FALCO), "write" },
	/*PPM_SC_OPEN*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "open" },
	/*PPM_SC_CLOSE*/ { EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "close" },
	/*PPM_SC_CREAT*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "creat" },
	/*PPM_SC_LINK*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "link" },
	/*PPM_SC_UNLINK*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "unlink" },
	/*PPM_SC_CHDIR*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "chdir" },
	/*PPM_SC_TIME*/ { EC_TIME, (enum ppm_event_flags)(EF_NONE), "time" },
	/*PPM_SC_MKNOD*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "mknod" },
	/*PPM_SC_CHMOD*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "chmod" },
	/*PPM_SC_STAT*/ { EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "stat" },
	/*PPM_SC_LSEEK*/ { EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "lseek" },
	/*PPM_SC_GETPID*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "getpid" },
	/*PPM_SC_MOUNT*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "mount" },
	/*PPM_SC_PTRACE*/ { EC_OTHER, (enum ppm_event_flags)(EF_NONE), "ptrace" },
	/*PPM_SC_ALARM*/ { EC_TIME, (enum ppm_event_flags)(EF_NONE), "alarm" },
	/*PPM_SC_FSTAT*/ { EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "fstat" },
	/*PPM_SC_PAUSE*/ { EC_WAIT, (enum ppm_event_flags)(EF_NONE), "pause" },	/* WAIT UNTIL A SIGNAL ARRIVES */
	/*PPM_SC_UTIME*/ { EC_TIME, (enum ppm_event_flags)(EF_NONE), "utime" },
	/*PPM_SC_ACCESS*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "access" },	/* checks whether the calling process can access the file pathname */
	/*PPM_SC_SYNC*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "sync" },	/* causes all buffered modifications to file metadata and data to be written to the underlying file systems. */
	/*PPM_SC_KILL*/ { EC_IPC, (enum ppm_event_flags)(EF_NONE), "kill" },
	/*PPM_SC_RENAME*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "rename" },
	/*PPM_SC_MKDIR*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "mkdir" },
	/*PPM_SC_RMDIR*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "rmdir" },
	/*PPM_SC_DUP*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "dup" },
	/*PPM_SC_PIPE*/ { EC_IPC, (enum ppm_event_flags)(EF_NONE), "pipe" },
	/*PPM_SC_TIMES*/ { EC_TIME, (enum ppm_event_flags)(EF_NONE), "times" },
	/*PPM_SC_BRK*/ { EC_MEMORY, (enum ppm_event_flags)(EF_NONE), "brk" },
	/*PPM_SC_ACCT*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "acct" },
	/*PPM_SC_IOCTL*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "ioctl" },
	/*PPM_SC_FCNTL*/ { EC_WAIT, (enum ppm_event_flags)(EF_DROP_FALCO), "fcntl" },
	/*PPM_SC_SETPGID*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "setpgid" },
	/*PPM_SC_UMASK*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "umask" },	/* sets the calling process's file mode creation mask */
	/*PPM_SC_CHROOT*/ { EC_IPC, (enum ppm_event_flags)(EF_NONE), "chroot" }, /* changes the root directory of the calling process to that specified in path. This directory will be used for pathnames beginning with /. The root directory is inherited by all children of the calling process. */
	/*PPM_SC_USTAT*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "ustat" }, /* returns information about a mounted file system. */
	/*PPM_SC_DUP2*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "dup2" },
	/*PPM_SC_GETPPID*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "getppid" },
	/*PPM_SC_GETPGRP*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "getpgrp" },
	/*PPM_SC_SETSID*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "setsid" }, /* creates a session and sets the process group ID */
	/*PPM_SC_SETHOSTNAME*/ { EC_SYSTEM, (enum ppm_event_flags)(EF_NONE), "sethostname" },
	/*PPM_SC_SETRLIMIT*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "setrlimit" }, /* get/set resource (CPU, FDs, memory...) limits */
	/*PPM_SC_GETRUSAGE*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "getrusage" }, /* returns resource usage measures for who */
	/*PPM_SC_GETTIMEOFDAY*/ { EC_TIME, (enum ppm_event_flags)(EF_DROP_FALCO), "gettimeofday" },
	/*PPM_SC_SETTIMEOFDAY*/ { EC_TIME, (enum ppm_event_flags)(EF_DROP_FALCO), "settimeofday" },
	/*PPM_SC_SYMLINK*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "symlink" },
	/*PPM_SC_LSTAT*/ { EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "lstat" },
	/*PPM_SC_READLINK*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "readlink" },
	/*PPM_SC_USELIB*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "uselib" }, /* load shared library */
	/*PPM_SC_SWAPON*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "swapon" }, /* start/stop swapping to file/device */
	/*PPM_SC_REBOOT*/ { EC_SYSTEM, (enum ppm_event_flags)(EF_NONE), "reboot" },
	/*PPM_SC_MMAP*/ { EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "mmap" },
	/*PPM_SC_MUNMAP*/ { EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "munmap" },
	/*PPM_SC_TRUNCATE*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "truncate" }, /* truncate a file to a specified length */
	/*PPM_SC_FTRUNCATE*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "ftruncate" }, /* truncate a file to a specified length */
	/*PPM_SC_FCHMOD*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "fchmod" },
	/*PPM_SC_GETPRIORITY*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "getpriority" }, /* get/set program scheduling priority */
	/*PPM_SC_SETPRIORITY*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "setpriority" }, /* get/set program scheduling priority */
	/*PPM_SC_STATFS*/ { EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "statfs" }, /* returns information about a mounted file system */
	/*PPM_SC_FSTATFS*/ { EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "fstatfs" }, /* returns information about a mounted file system */
	/*PPM_SC_SYSLOG*/ { EC_SYSTEM, (enum ppm_event_flags)(EF_NONE), "syslog" }, /* read and/or clear kernel message ring buffer; set console_loglevel */
	/*PPM_SC_SETITIMER*/ { EC_TIME, (enum ppm_event_flags)(EF_DROP_FALCO), "setitimer" },
	/*PPM_SC_GETITIMER*/ { EC_TIME, (enum ppm_event_flags)(EF_DROP_FALCO), "getitimer" },
	/*PPM_SC_UNAME*/ { EC_SYSTEM, (enum ppm_event_flags)(EF_NONE), "uname" }, /* get name and information about current kernel */
	/*PPM_SC_VHANGUP*/ { EC_OTHER , (enum ppm_event_flags)(EF_NONE), "vhangup" }, /* simulates a hangup on the current terminal. This call arranges for other users to have a "clean" terminal at login time. */
	/*PPM_SC_WAIT4*/ { EC_WAIT, (enum ppm_event_flags)(EF_DROP_FALCO), "wait4" }, /* OBSOLETE */
	/*PPM_SC_SWAPOFF*/ { EC_SYSTEM, (enum ppm_event_flags)(EF_NONE), "swapoff" }, /* start/stop swapping to file/device */
	/*PPM_SC_SYSINFO*/ { EC_SYSTEM, (enum ppm_event_flags)(EF_NONE), "sysinfo" }, /* returns information on overall system statistics */
	/*PPM_SC_FSYNC*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "fsync" },	/* sync file content */
	/*PPM_SC_SETDOMAINNAME*/ { EC_SYSTEM, (enum ppm_event_flags)(EF_NONE), "setdomainname" },
	/*PPM_SC_ADJTIMEX*/ { EC_SYSTEM, (enum ppm_event_flags)(EF_NONE), "adjtimex" }, /* tune kernel clock */
	/*PPM_SC_MPROTECT*/ { EC_MEMORY, (enum ppm_event_flags)(EF_NONE), "mprotect" }, /* set protection on a region of memory */
	/*PPM_SC_INIT_MODULE*/ { EC_SYSTEM, (enum ppm_event_flags)(EF_NONE), "init_module" }, /* load a kernel module */
	/*PPM_SC_DELETE_MODULE*/ { EC_SYSTEM, (enum ppm_event_flags)(EF_NONE), "delete_module" },
	/*PPM_SC_QUOTACTL*/ { EC_SYSTEM, (enum ppm_event_flags)(EF_NONE), "quotactl" },
	/*PPM_SC_GETPGID*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "getpgid" },
	/*PPM_SC_FCHDIR*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "fchdir" },
	/*PPM_SC_SYSFS*/ { EC_SYSTEM, (enum ppm_event_flags)(EF_NONE), "sysfs" }, /* get file system type information */
	/*PPM_SC_PERSONALITY*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "personality" }, /* set the process execution domain */
	/*PPM_SC_GETDENTS*/ { EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "getdents" }, /* get directory entries */
	/*PPM_SC_SELECT*/ { EC_WAIT, (enum ppm_event_flags)(EF_DROP_FALCO), "select" },
	/*PPM_SC_FLOCK*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "flock" }, /* apply or remove an advisory lock on an open file */
	/*PPM_SC_MSYNC*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "msync" }, /* synchronize a file with a memory map */
	/*PPM_SC_READV*/ { EC_IO_READ, (enum ppm_event_flags)(EF_DROP_FALCO), "readv" },
	/*PPM_SC_WRITEV*/ { EC_IO_WRITE, (enum ppm_event_flags)(EF_DROP_FALCO), "writev" },
	/*PPM_SC_GETSID*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "getsid" }, /* returns the session ID of the calling process */
	/*PPM_SC_FDATASYNC*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "fdatasync" }, /* synchronize a file's in-core state with storage device */
	/*PPM_SC_MLOCK*/ { EC_MEMORY, (enum ppm_event_flags)(EF_NONE), "mlock" }, /* mlock() and mlockall() respectively lock part or all of the calling process's virtual address space into RAM */
	/*PPM_SC_MUNLOCK*/ { EC_MEMORY, (enum ppm_event_flags)(EF_NONE), "munlock" }, /* mlock() and mlockall() respectively lock part or all of the calling process's virtual address space into RAM */
	/*PPM_SC_MLOCKALL*/ { EC_MEMORY, (enum ppm_event_flags)(EF_NONE), "mlockall" }, /* mlock() and mlockall() respectively lock part or all of the calling process's virtual address space into RAM */
	/*PPM_SC_MUNLOCKALL*/ { EC_MEMORY, (enum ppm_event_flags)(EF_NONE), "munlockall" }, /* mlock() and mlockall() respectively lock part or all of the calling process's virtual address space into RAM */
	/*PPM_SC_SCHED_SETPARAM*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "sched_setparam" },
	/*PPM_SC_SCHED_GETPARAM*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "sched_getparam" },
	/*PPM_SC_SCHED_SETSCHEDULER*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "sched_setscheduler" },
	/*PPM_SC_SCHED_GETSCHEDULER*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "sched_getscheduler" },
	/*PPM_SC_SCHED_YIELD*/ { EC_SLEEP, (enum ppm_event_flags)(EF_DROP_FALCO), "sched_yield" },
	/*PPM_SC_SCHED_GET_PRIORITY_MAX*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "sched_get_priority_max" },
	/*PPM_SC_SCHED_GET_PRIORITY_MIN*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "sched_get_priority_min" },
	/*PPM_SC_SCHED_RR_GET_INTERVAL*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "sched_rr_get_interval" },
	/*PPM_SC_NANOSLEEP*/ { EC_SLEEP, (enum ppm_event_flags)(EF_NONE), "nanosleep" },
	/*PPM_SC_MREMAP*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "mremap" },
	/*PPM_SC_POLL*/ { EC_WAIT, (enum ppm_event_flags)(EF_DROP_FALCO), "poll" },
	/*PPM_SC_PRCTL*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "prctl" }, /* operations on a process */
	/*PPM_SC_RT_SIGACTION*/ { EC_SIGNAL, (enum ppm_event_flags)(EF_NONE), "rt_sigaction" },
	/*PPM_SC_RT_SIGPROCMASK*/ { EC_SIGNAL, (enum ppm_event_flags)(EF_NONE), "rt_sigprocmask" },
	/*PPM_SC_RT_SIGPENDING*/ { EC_SIGNAL, (enum ppm_event_flags)(EF_NONE), "rt_sigpending" },
	/*PPM_SC_RT_SIGTIMEDWAIT*/ { EC_SIGNAL, (enum ppm_event_flags)(EF_NONE), "rt_sigtimedwait" },
	/*PPM_SC_RT_SIGQUEUEINFO*/ { EC_SIGNAL, (enum ppm_event_flags)(EF_NONE), "rt_sigqueueinfo" },
	/*PPM_SC_RT_SIGSUSPEND*/ { EC_SIGNAL, (enum ppm_event_flags)(EF_NONE), "rt_sigsuspend" },
	/*PPM_SC_GETCWD*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "getcwd" },
	/*PPM_SC_CAPGET*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "capget" }, /* set/get capabilities of thread(s) */
	/*PPM_SC_CAPSET*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "capset" }, /* set/get capabilities of thread(s) */
	/*PPM_SC_SENDFILE*/ { EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "sendfile" }, /* transfer data between file descriptors */
	/*PPM_SC_GETRLIMIT*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "getrlimit" },
	/*PPM_SC_LCHOWN*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "lchown" },
	/*PPM_SC_GETUID*/ { EC_USER, (enum ppm_event_flags)(EF_NONE), "getuid" },
	/*PPM_SC_GETGID*/ { EC_USER, (enum ppm_event_flags)(EF_NONE), "getgid" },
	/*PPM_SC_GETEUID*/ { EC_USER, (enum ppm_event_flags)(EF_NONE), "geteuid" },
	/*PPM_SC_GETEGID*/ { EC_USER, (enum ppm_event_flags)(EF_NONE), "getegid" },
	/*PPM_SC_SETREUID*/ { EC_USER, (enum ppm_event_flags)(EF_NONE), "setreuid" },
	/*PPM_SC_SETREGID*/ { EC_USER, (enum ppm_event_flags)(EF_NONE), "setregid" },
	/*PPM_SC_GETGROUPS*/ { EC_USER, (enum ppm_event_flags)(EF_NONE), "getgroups" }, /* returns the supplementary group IDs of the calling process */
	/*PPM_SC_SETGROUPS*/ { EC_USER, (enum ppm_event_flags)(EF_NONE), "setgroups" }, /* returns the supplementary group IDs of the calling process */
	/*PPM_SC_FCHOWN*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "fchown" },
	/*PPM_SC_SETRESUID*/ { EC_USER, (enum ppm_event_flags)(EF_NONE), "setresuid" },
	/*PPM_SC_GETRESUID*/ { EC_USER, (enum ppm_event_flags)(EF_NONE), "getresuid" },
	/*PPM_SC_SETRESGID*/ { EC_USER, (enum ppm_event_flags)(EF_NONE), "setresgid" },
	/*PPM_SC_GETRESGID*/ { EC_USER, (enum ppm_event_flags)(EF_NONE), "getresgid" },
	/*PPM_SC_CHOWN*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "chown" },
	/*PPM_SC_SETUID*/ { EC_USER, (enum ppm_event_flags)(EF_NONE), "setuid" },
	/*PPM_SC_SETGID*/ { EC_USER, (enum ppm_event_flags)(EF_NONE), "setgid" },
	/*PPM_SC_SETFSUID*/ { EC_USER, (enum ppm_event_flags)(EF_NONE), "setfsuid" },
	/*PPM_SC_SETFSGID*/ { EC_USER, (enum ppm_event_flags)(EF_NONE), "setfsgid" },
	/*PPM_SC_PIVOT_ROOT*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "pivot_root" },
	/*PPM_SC_MINCORE*/ { EC_MEMORY, (enum ppm_event_flags)(EF_NONE), "mincore" }, /* determine whether pages are resident in memory */
	/*PPM_SC_MADVISE*/ { EC_MEMORY, (enum ppm_event_flags)(EF_NONE), "madvise" }, /* give advice about use of memory */
	/*PPM_SC_GETTID*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "gettid" },	/* returns the caller's thread ID (TID) */
	/*PPM_SC_SETXATTR*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "setxattr" }, /* set inode attribute */
	/*PPM_SC_LSETXATTR*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "lsetxattr" },
	/*PPM_SC_FSETXATTR*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "fsetxattr" },
	/*PPM_SC_GETXATTR*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "getxattr" },
	/*PPM_SC_LGETXATTR*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "lgetxattr" },
	/*PPM_SC_FGETXATTR*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "fgetxattr" },
	/*PPM_SC_LISTXATTR*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "listxattr" },
	/*PPM_SC_LLISTXATTR*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "llistxattr" },
	/*PPM_SC_FLISTXATTR*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "flistxattr" },
	/*PPM_SC_REMOVEXATTR*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "removexattr" },
	/*PPM_SC_LREMOVEXATTR*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "lremovexattr" },
	/*PPM_SC_FREMOVEXATTR*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "fremovexattr" },
	/*PPM_SC_TKILL*/ { EC_SIGNAL, (enum ppm_event_flags)(EF_NONE), "tkill" }, /* send a signal to a thread */
	/*PPM_SC_FUTEX*/ { EC_IPC, (enum ppm_event_flags)(EF_DROP_FALCO), "futex" },
	/*PPM_SC_SCHED_SETAFFINITY*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "sched_setaffinity" },
	/*PPM_SC_SCHED_GETAFFINITY*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "sched_getaffinity" },
	/*PPM_SC_SET_THREAD_AREA*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "set_thread_area" },
	/*PPM_SC_GET_THREAD_AREA*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "get_thread_area" },
	/*PPM_SC_IO_SETUP*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "io_setup" }, /* create an asynchronous I/O context (for libaio) */
	/*PPM_SC_IO_DESTROY*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "io_destroy" },
	/*PPM_SC_IO_GETEVENTS*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "io_getevents" },
	/*PPM_SC_IO_SUBMIT*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "io_submit" },
	/*PPM_SC_IO_CANCEL*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "io_cancel" },
	/*PPM_SC_EXIT_GROUP*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "exit_group" },
	/*PPM_SC_EPOLL_CREATE*/ { EC_WAIT, (enum ppm_event_flags)(EF_DROP_FALCO), "epoll_create" },
	/*PPM_SC_EPOLL_CTL*/ { EC_WAIT, (enum ppm_event_flags)(EF_DROP_FALCO), "epoll_ctl" },
	/*PPM_SC_EPOLL_WAIT*/ { EC_WAIT, (enum ppm_event_flags)(EF_DROP_FALCO), "epoll_wait" },
	/*PPM_SC_REMAP_FILE_PAGES*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "remap_file_pages" }, /* create a nonlinear file mapping */
	/*PPM_SC_SET_TID_ADDRESS*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "set_tid_address" }, /* set pointer to thread ID */
	/*PPM_SC_TIMER_CREATE*/ { EC_TIME, (enum ppm_event_flags)(EF_DROP_FALCO), "timer_create" },
	/*PPM_SC_TIMER_SETTIME*/ { EC_TIME, (enum ppm_event_flags)(EF_DROP_FALCO), "timer_settime" },
	/*PPM_SC_TIMER_GETTIME*/ { EC_TIME, (enum ppm_event_flags)(EF_DROP_FALCO), "timer_gettime" },
	/*PPM_SC_TIMER_GETOVERRUN*/ { EC_TIME, (enum ppm_event_flags)(EF_DROP_FALCO), "timer_getoverrun" },
	/*PPM_SC_TIMER_DELETE*/ { EC_TIME, (enum ppm_event_flags)(EF_DROP_FALCO), "timer_delete" },
	/*PPM_SC_CLOCK_SETTIME*/ { EC_TIME, (enum ppm_event_flags)(EF_DROP_FALCO), "clock_settime" },
	/*PPM_SC_CLOCK_GETTIME*/ { EC_TIME, (enum ppm_event_flags)(EF_DROP_FALCO), "clock_gettime" },
	/*PPM_SC_CLOCK_GETRES*/ { EC_TIME, (enum ppm_event_flags)(EF_DROP_FALCO), "clock_getres" },
	/*PPM_SC_CLOCK_NANOSLEEP*/ { EC_SLEEP, (enum ppm_event_flags)(EF_DROP_FALCO), "clock_nanosleep" },
	/*PPM_SC_TGKILL*/ { EC_SIGNAL, (enum ppm_event_flags)(EF_NONE), "tgkill" },
	/*PPM_SC_UTIMES*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "utimes" }, /* change file last access and modification times */
	/*PPM_SC_MQ_OPEN*/ { EC_IPC, (enum ppm_event_flags)(EF_NONE), "mq_open" }, /* Message queues. See http://linux.die.net/man/7/mq_overview. */
	/*PPM_SC_MQ_UNLINK*/ { EC_IPC, (enum ppm_event_flags)(EF_NONE), "mq_unlink" },
	/*PPM_SC_MQ_TIMEDSEND*/ { EC_IPC, (enum ppm_event_flags)(EF_NONE), "mq_timedsend" },
	/*PPM_SC_MQ_TIMEDRECEIVE*/ { EC_IPC, (enum ppm_event_flags)(EF_NONE), "mq_timedreceive" },
	/*PPM_SC_MQ_NOTIFY*/ { EC_IPC, (enum ppm_event_flags)(EF_NONE), "mq_notify" },
	/*PPM_SC_MQ_GETSETATTR*/ { EC_IPC, (enum ppm_event_flags)(EF_NONE), "mq_getsetattr" },
	/*PPM_SC_KEXEC_LOAD*/ { EC_SYSTEM, (enum ppm_event_flags)(EF_NONE), "kexec_load" }, /* load a new kernel for later execution */
	/*PPM_SC_WAITID*/ { EC_WAIT, (enum ppm_event_flags)(EF_NONE), "waitid" },
	/*PPM_SC_ADD_KEY*/ { EC_SYSTEM, (enum ppm_event_flags)(EF_NONE), "add_key" }, /* add a key to the kernel's key management facility */
	/*PPM_SC_REQUEST_KEY*/ { EC_SYSTEM, (enum ppm_event_flags)(EF_NONE), "request_key" },
	/*PPM_SC_KEYCTL*/ { EC_SYSTEM, (enum ppm_event_flags)(EF_NONE), "keyctl" },
	/*PPM_SC_IOPRIO_SET*/ { EC_PROCESS, (enum ppm_event_flags)(EF_DROP_FALCO), "ioprio_set" }, /* get/set I/O scheduling class and priority */
	/*PPM_SC_IOPRIO_GET*/ { EC_PROCESS, (enum ppm_event_flags)(EF_DROP_FALCO), "ioprio_get" }, /* get/set I/O scheduling class and priority */
	/*PPM_SC_INOTIFY_INIT*/ { EC_IPC, (enum ppm_event_flags)(EF_NONE), "inotify_init" }, /* initialize an inotify event queue instance. See http://en.wikipedia.org/wiki/Inotify. */
	/*PPM_SC_INOTIFY_ADD_WATCH*/ { EC_IPC, (enum ppm_event_flags)(EF_NONE), "inotify_add_watch" },
	/*PPM_SC_INOTIFY_RM_WATCH*/ { EC_IPC, (enum ppm_event_flags)(EF_NONE), "inotify_rm_watch" },
	/*PPM_SC_OPENAT*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "openat" },
	/*PPM_SC_MKDIRAT*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "mkdirat" },
	/*PPM_SC_MKNODAT*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "mknodat" },
	/*PPM_SC_FCHOWNAT*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "fchownat" },
	/*PPM_SC_FUTIMESAT*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "futimesat" },
	/*PPM_SC_UNLINKAT*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "unlinkat" },
	/*PPM_SC_RENAMEAT*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "renameat" },
	/*PPM_SC_LINKAT*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "linkat" },
	/*PPM_SC_SYMLINKAT*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "symlinkat" },
	/*PPM_SC_READLINKAT*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "readlinkat" },
	/*PPM_SC_FCHMODAT*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "fchmodat" },
	/*PPM_SC_FACCESSAT*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "faccessat" },
	/*PPM_SC_PSELECT6*/ { EC_WAIT, (enum ppm_event_flags)(EF_DROP_FALCO), "pselect6" },
	/*PPM_SC_PPOLL*/ { EC_WAIT, (enum ppm_event_flags)(EF_DROP_FALCO), "ppoll" },
	/*PPM_SC_UNSHARE*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "unshare" }, /* disassociate parts of the process execution context */
	/*PPM_SC_SET_ROBUST_LIST*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "set_robust_list" }, /* get/set list of robust futexes */
	/*PPM_SC_GET_ROBUST_LIST*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "get_robust_list" }, /* get/set list of robust futexes */
	/*PPM_SC_SPLICE*/ { EC_IPC, (enum ppm_event_flags)(EF_DROP_FALCO), "splice" }, /* transfers up to len bytes of data from the file descriptor fd_in to the file descriptor fd_out, where one of the descriptors must refer to a pipe. */
	/*PPM_SC_TEE*/ { EC_IPC, (enum ppm_event_flags)(EF_DROP_FALCO), "tee" }, /* tee() duplicates up to len bytes of data from the pipe referred to by the file descriptor fd_in to the pipe referred to by the file descriptor fd_out. It does not consume the data that is duplicated from fd_in. */
	/*PPM_SC_VMSPLICE*/ { EC_IPC, (enum ppm_event_flags)(EF_NONE), "vmsplice" }, /* splice user pages into a pipe */
	/*PPM_SC_GETCPU*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "getcpu" }, /* determine CPU and NUMA node on which the calling thread is running */
	/*PPM_SC_EPOLL_PWAIT*/ { EC_WAIT, (enum ppm_event_flags)(EF_DROP_FALCO), "epoll_pwait" },
	/*PPM_SC_UTIMENSAT*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "utimensat" }, /* change file timestamps with nanosecond precision */
	/*PPM_SC_SIGNALFD*/ { EC_SIGNAL, (enum ppm_event_flags)(EF_NONE), "signalfd" }, /* create a pollable file descriptor for accepting signals */
	/*PPM_SC_TIMERFD_CREATE*/ { EC_TIME, (enum ppm_event_flags)(EF_DROP_FALCO), "timerfd_create" }, /* // create and operate on a timer that delivers timer expiration notifications via a file descriptor */
	/*PPM_SC_EVENTFD*/ { EC_IPC, (enum ppm_event_flags)(EF_DROP_FALCO), "eventfd" }, /* create a file descriptor for event notification */
	/*PPM_SC_TIMERFD_SETTIME*/ { EC_TIME, (enum ppm_event_flags)(EF_DROP_FALCO), "timerfd_settime" }, /* create and operate on a timer that delivers timer expiration notifications via a file descriptor */
	/*PPM_SC_TIMERFD_GETTIME*/ { EC_TIME, (enum ppm_event_flags)(EF_DROP_FALCO), "timerfd_gettime" }, /* create and operate on a timer that delivers timer expiration notifications via a file descriptor */
	/*PPM_SC_SIGNALFD4*/ { EC_SIGNAL, (enum ppm_event_flags)(EF_NONE), "signalfd4" }, /* create a pollable file descriptor for accepting signals */
	/*PPM_SC_EVENTFD2*/ { EC_IPC, (enum ppm_event_flags)(EF_NONE), "eventfd2" }, /* create a file descriptor for event notification */
	/*PPM_SC_EPOLL_CREATE1*/ { EC_WAIT, (enum ppm_event_flags)(EF_DROP_FALCO), "epoll_create1" }, /* variant of epoll_create */
	/*PPM_SC_DUP3*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "dup3" },
	/*PPM_SC_PIPE2*/ { EC_IPC, (enum ppm_event_flags)(EF_NONE), "pipe2" },
	/*PPM_SC_INOTIFY_INIT1*/ { EC_IPC, (enum ppm_event_flags)(EF_NONE), "inotify_init1" },
	/*PPM_SC_PREADV*/ { EC_IO_READ, (enum ppm_event_flags)(EF_DROP_FALCO), "preadv" },
	/*PPM_SC_PWRITEV*/ { EC_IO_WRITE, (enum ppm_event_flags)(EF_DROP_FALCO), "pwritev" },
	/*PPM_SC_RT_TGSIGQUEUEINFO*/ { EC_OTHER, (enum ppm_event_flags)(EF_NONE), "rt_tgsigqueueinfo" },
	/*PPM_SC_PERF_EVENT_OPEN*/ { EC_OTHER, (enum ppm_event_flags)(EF_NONE), "perf_event_open" },
	/*PPM_SC_FANOTIFY_INIT*/ { EC_IPC, (enum ppm_event_flags)(EF_NONE), "fanotify_init" },
	/*PPM_SC_PRLIMIT64*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "prlimit64" },
	/*PPM_SC_CLOCK_ADJTIME*/ { EC_OTHER, (enum ppm_event_flags)(EF_NONE), "clock_adjtime" },
	/*PPM_SC_SYNCFS*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "syncfs" },
	/*PPM_SC_SETNS*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "setns" }, /* reassociate thread with a namespace */
	/*PPM_SC_GETDENTS64*/  { EC_IPC, (enum ppm_event_flags)(EF_DROP_FALCO), "getdents64" },
	/*  */
	/* Non-multiplexed socket family */
	/*  */
	/*PPM_SC_SOCKET*/  { EC_NET, (enum ppm_event_flags)(EF_NONE), "socket" },
	/*PPM_SC_BIND*/	{ EC_NET, (enum ppm_event_flags)(EF_NONE), "bind" },
	/*PPM_SC_CONNECT*/  { EC_NET, (enum ppm_event_flags)(EF_NONE), "connect" },
	/*PPM_SC_LISTEN*/  { EC_NET, (enum ppm_event_flags)(EF_NONE), "listen" },
	/*PPM_SC_ACCEPT*/  { EC_NET, (enum ppm_event_flags)(EF_NONE), "accept" },
	/*PPM_SC_GETSOCKNAME*/ { EC_NET, (enum ppm_event_flags)(EF_NONE), "getsockname" },
	/*PPM_SC_GETPEERNAME*/ { EC_NET, (enum ppm_event_flags)(EF_NONE), "getpeername" },
	/*PPM_SC_SOCKETPAIR*/ { EC_NET, (enum ppm_event_flags)(EF_NONE), "socketpair" },
	/*PPM_SC_SENDTO*/  { EC_NET, (enum ppm_event_flags)(EF_DROP_FALCO), "sendto" },
	/*PPM_SC_RECVFROM*/  { EC_NET, (enum ppm_event_flags)(EF_DROP_FALCO), "recvfrom" },
	/*PPM_SC_SHUTDOWN*/  { EC_NET, (enum ppm_event_flags)(EF_DROP_FALCO), "shutdown" },
	/*PPM_SC_SETSOCKOPT*/ { EC_NET, (enum ppm_event_flags)(EF_NONE), "setsockopt" },
	/*PPM_SC_GETSOCKOPT*/ { EC_NET, (enum ppm_event_flags)(EF_NONE), "getsockopt" },
	/*PPM_SC_SENDMSG*/  { EC_NET, (enum ppm_event_flags)(EF_DROP_FALCO), "sendmsg" },
	/*PPM_SC_SENDMMSG*/  { EC_NET, (enum ppm_event_flags)(EF_DROP_FALCO), "sendmmsg" },
	/*PPM_SC_RECVMSG*/  { EC_NET, (enum ppm_event_flags)(EF_DROP_FALCO), "recvmsg" },
	/*PPM_SC_RECVMMSG*/  { EC_NET, (enum ppm_event_flags)(EF_DROP_FALCO), "recvmmsg" },
	/*PPM_SC_ACCEPT4*/  { EC_NET, (enum ppm_event_flags)(EF_NONE), "accept4" },
	/*
	 * Non-multiplexed IPC family
	 */
	/*PPM_SC_SEMOP*/  { EC_IPC, (enum ppm_event_flags)(EF_NONE), "semop" },
	/*PPM_SC_SEMGET*/  { EC_IPC, (enum ppm_event_flags)(EF_NONE), "semget" },
	/*PPM_SC_SEMCTL*/  { EC_IPC, (enum ppm_event_flags)(EF_NONE), "semctl" },
	/*PPM_SC_MSGSND*/  { EC_IPC, (enum ppm_event_flags)(EF_NONE), "msgsnd" },
	/*PPM_SC_MSGRCV*/  { EC_IPC, (enum ppm_event_flags)(EF_NONE), "msgrcv" },
	/*PPM_SC_MSGGET*/  { EC_IPC, (enum ppm_event_flags)(EF_NONE), "msgget" },
	/*PPM_SC_MSGCTL*/  { EC_IPC, (enum ppm_event_flags)(EF_NONE), "msgctl" },
	/*PPM_SC_SHMDT*/  { EC_IPC, (enum ppm_event_flags)(EF_NONE), "shmdt" },
	/*PPM_SC_SHMGET*/  { EC_IPC, (enum ppm_event_flags)(EF_NONE), "shmget" },
	/*PPM_SC_SHMCTL*/  { EC_IPC, (enum ppm_event_flags)(EF_NONE), "shmctl" },
	/*PPM_SC_STATFS64*/ { EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "statfs64" },
	/*PPM_SC_FSTATFS64*/ { EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "fstatfs64" },
	/*PPM_SC_FSTATAT64*/ { EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "fstatat64" },
	/*PPM_SC_SENDFILE64*/ { EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "sendfile64" },
	/*PPM_SC_UGETRLIMIT*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "ugetrlimit" },
	/*PPM_SC_BDFLUSH*/ { EC_OTHER, (enum ppm_event_flags)(EF_NONE), "bdflush" },	/* deprecated */
	/*PPM_SC_SIGPROCMASK*/ { EC_SIGNAL, (enum ppm_event_flags)(EF_NONE), "sigprocmask" }, /* examine and change blocked signals */
	/*PPM_SC_IPC*/ { EC_IPC, (enum ppm_event_flags)(EF_NONE), "ipc" },
	/*PPM_SC_SOCKETCALL*/ { EC_NET, (enum ppm_event_flags)(EF_NONE), "socketcall" },
	/*PPM_SC_STAT64*/ { EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "stat64" },
	/*PPM_SC_LSTAT64*/ { EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "lstat64" },
	/*PPM_SC_FSTAT64*/ { EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "fstat64" },
	/*PPM_SC_FCNTL64*/ { EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "fcntl64" },
	/*PPM_SC_MMAP2*/ { EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "mmap2" },
	/*PPM_SC__NEWSELECT*/ { EC_WAIT, (enum ppm_event_flags)(EF_NONE), "newselect" },
	/*PPM_SC_SGETMASK*/ { EC_SIGNAL, (enum ppm_event_flags)(EF_NONE), "sgetmask" }, /* manipulation of signal mask (obsolete) */
	/*PPM_SC_SSETMASK*/ { EC_SIGNAL, (enum ppm_event_flags)(EF_NONE), "ssetmask" }, /* manipulation of signal mask (obsolete) */
	/*PPM_SC_SIGPENDING*/ { EC_SIGNAL, (enum ppm_event_flags)(EF_NONE), "sigpending" }, /* examine pending signals */
	/*PPM_SC_OLDUNAME*/ { EC_SYSTEM, (enum ppm_event_flags)(EF_NONE), "olduname" },
	/*PPM_SC_UMOUNT*/ { EC_FILE, (enum ppm_event_flags)(EF_NONE), "umount" },
	/*PPM_SC_SIGNAL*/ { EC_SIGNAL, (enum ppm_event_flags)(EF_NONE), "signal" },
	/*PPM_SC_NICE*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "nice" }, /* change process priority */
	/*PPM_SC_STIME*/ { EC_TIME, (enum ppm_event_flags)(EF_NONE), "stime" },
	/*PPM_SC__LLSEEK*/	{ EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "llseek" },
	/*PPM_SC_WAITPID*/ { EC_WAIT, (enum ppm_event_flags)(EF_NONE), "waitpid" },
	/*PPM_SC_PREAD64*/ { EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "pread64" },
	/*PPM_SC_PWRITE64*/ { EC_FILE, (enum ppm_event_flags)(EF_DROP_FALCO), "pwrite64" },
	/*PPM_SC_ARCH_PRCTL*/ { EC_PROCESS, (enum ppm_event_flags)(EF_NONE), "arch_prctl" },
	/*PPM_SC_SHMAT*/ { EC_IPC, (enum ppm_event_flags)(EF_NONE), "shmat" },
	/*PPM_SC_SIGRETURN*/ { EC_SIGNAL, (enum ppm_event_flags)(EF_NONE), "sigreturn" }, /* return from signal handler and cleanup stack frame */
	/*PPM_SC_FALLOCATE*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "fallocate" }, /* manipulate file space */
	/*PPM_SC_NEWFSSTAT*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "newfstatat" },
	/*PPM_SC_PROCESS_VM_READV*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "process_vm_readv" },
	/*PPM_SC_PROCESS_VM_WRITEV*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "process_vm_writev" },
	/*PPM_SC_FORK*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "fork" },
	/*PPM_SC_VFORK*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "vfork" },
	/*PPM_SC_SETUID32*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "setuid" },
	/*PPM_SC_GETUID32*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "getuid" },
	/*PPM_SC_SETGID32*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "setgid" },
	/*PPM_SC_GETEUID32*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "geteuid" },
	/*PPM_SC_GETGID32*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "getgid" },
	/*PPM_SC_SETRESUID32*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "setresuid" },
	/*PPM_SC_SETRESGID32*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "setresgid" },
	/*PPM_SC_GETRESUID32*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "getresuid" },
	/*PPM_SC_GETRESGID32*/ { EC_IO_OTHER, (enum ppm_event_flags)(EF_NONE), "getresgid" },
};

bool validate_info_table_size()
{
	return (sizeof(g_syscall_info_table) / sizeof(g_syscall_info_table[0]) == PPM_SC_MAX);
}
