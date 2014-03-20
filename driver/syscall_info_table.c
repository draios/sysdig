/*
Copyright (C) 2013-2014 Draios inc.
 
This file is part of sysdig.

sysdig is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "ppm_events_public.h"

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// SYSCALL INFO TABLE
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
const struct ppm_syscall_desc g_syscall_info_table[PPM_SC_MAX] =
{
	/*dummy*/ { EC_OTHER, "<unknown>" },
	/*PPM_SC_RESTART_SYSCALL*/ { EC_SYSTEM, "restart_syscall" },
	/*PPM_SC_EXIT*/ { EC_PROCESS, "exit" },
	/*PPM_SC_READ*/ { EC_IO_READ, "read" },
	/*PPM_SC_WRITE*/ { EC_IO_WRITE, "write" },
	/*PPM_SC_OPEN*/ { EC_FILE, "open" },
	/*PPM_SC_CLOSE*/ { EC_FILE, "close" },
	/*PPM_SC_CREAT*/ { EC_FILE, "creat" },
	/*PPM_SC_LINK*/ { EC_FILE, "link" },
	/*PPM_SC_UNLINK*/ { EC_FILE, "unlink" },
	/*PPM_SC_CHDIR*/ { EC_FILE, "chdir" },
	/*PPM_SC_TIME*/ { EC_TIME, "time" },
	/*PPM_SC_MKNOD*/ { EC_FILE, "mknod" },
	/*PPM_SC_CHMOD*/ { EC_FILE, "chmod" },
	/*PPM_SC_STAT*/ { EC_FILE, "stat" },
	/*PPM_SC_LSEEK*/ { EC_FILE, "lseek" },
	/*PPM_SC_GETPID*/ { EC_PROCESS, "getpid" },
	/*PPM_SC_MOUNT*/ { EC_FILE, "mount" },
	/*PPM_SC_PTRACE*/ { EC_OTHER, "ptrace" },
	/*PPM_SC_ALARM*/ { EC_TIME, "alarm" },
	/*PPM_SC_FSTAT*/ { EC_FILE, "fstat" },
	/*PPM_SC_PAUSE*/ { EC_WAIT, "pause" },	// WAIT UNTIL A SIGNAL ARRIVES
	/*PPM_SC_UTIME*/ { EC_TIME, "utime" },
	/*PPM_SC_ACCESS*/ { EC_FILE, "access" },	// checks whether the calling process can access the file pathname
	/*PPM_SC_SYNC*/ { EC_IO_OTHER, "sync" },	// causes all buffered modifications to file metadata and data to be written to the underlying file systems.
	/*PPM_SC_KILL*/ { EC_IPC, "kill" },
	/*PPM_SC_RENAME*/ { EC_FILE, "rename" },
	/*PPM_SC_MKDIR*/ { EC_FILE, "mkdir" },
	/*PPM_SC_RMDIR*/ { EC_FILE, "rmdir" },
	/*PPM_SC_DUP*/ { EC_IO_OTHER, "dup" },
	/*PPM_SC_PIPE*/ { EC_IPC, "pipe" },
	/*PPM_SC_TIMES*/ { EC_TIME, "times" },
	/*PPM_SC_BRK*/ { EC_MEMORY, "brk" },
	/*PPM_SC_ACCT*/ { EC_PROCESS, "acct" },
	/*PPM_SC_IOCTL*/ { EC_IO_OTHER, "ioctl" },
	/*PPM_SC_FCNTL*/ { EC_WAIT, "fcntl" },
	/*PPM_SC_SETPGID*/ { EC_PROCESS, "setpgid" },
	/*PPM_SC_UMASK*/ { EC_PROCESS, "umask" },	// sets the calling process's file mode creation mask
	/*PPM_SC_CHROOT*/ { EC_IPC, "chroot" }, //  changes the root directory of the calling process to that specified in path. This directory will be used for pathnames beginning with /. The root directory is inherited by all children of the calling process.
	/*PPM_SC_USTAT*/ { EC_FILE, "ustat" }, // returns information about a mounted file system.
	/*PPM_SC_DUP2*/ { EC_IO_OTHER, "dup2" },
	/*PPM_SC_GETPPID*/ { EC_PROCESS, "getppid" },
	/*PPM_SC_GETPGRP*/ { EC_PROCESS, "getpgrp" },
	/*PPM_SC_SETSID*/ { EC_PROCESS, "setsid" }, // creates a session and sets the process group ID
	/*PPM_SC_SETHOSTNAME*/ { EC_SYSTEM, "sethostname" },
	/*PPM_SC_SETRLIMIT*/ { EC_PROCESS, "setrlimit" }, // get/set resource (CPU, FDs, memory...) limits
	/*PPM_SC_GETRUSAGE*/ { EC_PROCESS, "getrusage" }, // returns resource usage measures for who
	/*PPM_SC_GETTIMEOFDAY*/ { EC_TIME, "gettimeofday" },
	/*PPM_SC_SETTIMEOFDAY*/ { EC_TIME, "settimeofday" },
	/*PPM_SC_SYMLINK*/ { EC_FILE, "symlink" },
	/*PPM_SC_LSTAT*/ { EC_FILE, "lstat" },
	/*PPM_SC_READLINK*/ { EC_FILE, "readlink" },
	/*PPM_SC_USELIB*/ { EC_PROCESS, "uselib" }, // load shared library
	/*PPM_SC_SWAPON*/ { EC_PROCESS, "swapon" }, // start/stop swapping to file/device
	/*PPM_SC_REBOOT*/ { EC_SYSTEM, "reboot" },
	/*PPM_SC_MMAP*/ { EC_FILE, "mmap" },
	/*PPM_SC_MUNMAP*/ { EC_FILE, "munmap" },
	/*PPM_SC_TRUNCATE*/ { EC_FILE, "truncate" }, // truncate a file to a specified length
	/*PPM_SC_FTRUNCATE*/ { EC_FILE, "ftruncate" }, // truncate a file to a specified length
	/*PPM_SC_FCHMOD*/ { EC_FILE, "fchmod" },
	/*PPM_SC_GETPRIORITY*/ { EC_PROCESS, "getpriority" }, // get/set program scheduling priority
	/*PPM_SC_SETPRIORITY*/ { EC_PROCESS, "setpriority" }, // get/set program scheduling priority
	/*PPM_SC_STATFS*/ { EC_FILE, "statfs" }, // returns information about a mounted file system
	/*PPM_SC_FSTATFS*/ { EC_FILE, "fstatfs" }, // returns information about a mounted file system
	/*PPM_SC_SYSLOG*/ { EC_SYSTEM, "syslog" }, // read and/or clear kernel message ring buffer; set console_loglevel
	/*PPM_SC_SETITIMER*/ { EC_TIME, "setitimer" },
	/*PPM_SC_GETITIMER*/ { EC_TIME, "getitimer" },
	/*PPM_SC_UNAME*/ { EC_SYSTEM, "uname" }, //get name and information about current kernel
	/*PPM_SC_VHANGUP*/ { EC_OTHER , "vhangup" }, // simulates a hangup on the current terminal. This call arranges for other users to have a "clean" terminal at login time.
	/*PPM_SC_WAIT4*/ { EC_WAIT, "wait4" }, // OBSOLETE
	/*PPM_SC_SWAPOFF*/ { EC_SYSTEM, "swapoff" }, // start/stop swapping to file/device
	/*PPM_SC_SYSINFO*/ { EC_SYSTEM, "sysinfo" }, // returns information on overall system statistics
	/*PPM_SC_FSYNC*/ { EC_IO_OTHER, "fsync" },	// sync file content
	/*PPM_SC_SETDOMAINNAME*/ { EC_SYSTEM, "setdomainname" },
	/*PPM_SC_ADJTIMEX*/ { EC_SYSTEM, "adjtimex" }, // tune kernel clock
	/*PPM_SC_MPROTECT*/ { EC_MEMORY, "mprotect" }, // set protection on a region of memory
	/*PPM_SC_INIT_MODULE*/ { EC_SYSTEM, "init_module" }, // load a kernel module
	/*PPM_SC_DELETE_MODULE*/ { EC_SYSTEM, "delete_module" },
	/*PPM_SC_QUOTACTL*/ { EC_SYSTEM, "quotactl" },
	/*PPM_SC_GETPGID*/ { EC_PROCESS, "getpgid" },
	/*PPM_SC_FCHDIR*/ { EC_FILE, "fchdir" },
	/*PPM_SC_SYSFS*/ { EC_SYSTEM, "sysfs" }, // get file system type information
	/*PPM_SC_PERSONALITY*/ { EC_PROCESS, "personality" }, // set the process execution domain
	/*PPM_SC_GETDENTS*/ { EC_FILE, "getdents" }, // get directory entries
	/*PPM_SC_SELECT*/ { EC_WAIT, "select" },
	/*PPM_SC_FLOCK*/ { EC_FILE, "flock" }, // apply or remove an advisory lock on an open file
	/*PPM_SC_MSYNC*/ { EC_IO_OTHER, "msync" }, // synchronize a file with a memory map
	/*PPM_SC_READV*/ { EC_IO_READ, "readv" },
	/*PPM_SC_WRITEV*/ { EC_IO_WRITE, "writev" },
	/*PPM_SC_GETSID*/ { EC_PROCESS, "getsid" }, // returns the session ID of the calling process
	/*PPM_SC_FDATASYNC*/ { EC_IO_OTHER, "fdatasync" }, // synchronize a file's in-core state with storage device
	/*PPM_SC_MLOCK*/ { EC_MEMORY, "mlock" }, // mlock() and mlockall() respectively lock part or all of the calling process's virtual address space into RAM
	/*PPM_SC_MUNLOCK*/ { EC_MEMORY, "munlock" }, // mlock() and mlockall() respectively lock part or all of the calling process's virtual address space into RAM
	/*PPM_SC_MLOCKALL*/ { EC_MEMORY, "mlockall" }, // mlock() and mlockall() respectively lock part or all of the calling process's virtual address space into RAM
	/*PPM_SC_MUNLOCKALL*/ { EC_MEMORY, "munlockall" }, // mlock() and mlockall() respectively lock part or all of the calling process's virtual address space into RAM
	/*PPM_SC_SCHED_SETPARAM*/ { EC_PROCESS, "sched_setparam" },
	/*PPM_SC_SCHED_GETPARAM*/ { EC_PROCESS, "sched_getparam" },
	/*PPM_SC_SCHED_SETSCHEDULER*/ { EC_PROCESS, "sched_setscheduler" },
	/*PPM_SC_SCHED_GETSCHEDULER*/ { EC_PROCESS, "sched_getscheduler" },
	/*PPM_SC_SCHED_YIELD*/ { EC_SLEEP, "sched_yield" },
	/*PPM_SC_SCHED_GET_PRIORITY_MAX*/ { EC_PROCESS, "sched_get_priority_max" },
	/*PPM_SC_SCHED_GET_PRIORITY_MIN*/ { EC_PROCESS, "sched_get_priority_min" },
	/*PPM_SC_SCHED_RR_GET_INTERVAL*/ { EC_PROCESS, "sched_rr_get_interval" },
	/*PPM_SC_NANOSLEEP*/ { EC_SLEEP, "nanosleep" },
	/*PPM_SC_MREMAP*/ { EC_FILE, "mremap" },
	/*PPM_SC_POLL*/ { EC_WAIT, "poll" },
	/*PPM_SC_PRCTL*/ { EC_PROCESS, "prctl" }, // operations on a process
	/*PPM_SC_RT_SIGACTION*/ { EC_SIGNAL, "rt_sigaction" },
	/*PPM_SC_RT_SIGPROCMASK*/ { EC_SIGNAL, "rt_sigprocmask" },
	/*PPM_SC_RT_SIGPENDING*/ { EC_SIGNAL, "rt_sigpending" },
	/*PPM_SC_RT_SIGTIMEDWAIT*/ { EC_SIGNAL, "rt_sigtimedwait" },
	/*PPM_SC_RT_SIGQUEUEINFO*/ { EC_SIGNAL, "rt_sigqueueinfo" },
	/*PPM_SC_RT_SIGSUSPEND*/ { EC_SIGNAL, "rt_sigsuspend" },
	/*PPM_SC_GETCWD*/ { EC_FILE, "getcwd" },
	/*PPM_SC_CAPGET*/ { EC_PROCESS, "capget" }, // set/get capabilities of thread(s)
	/*PPM_SC_CAPSET*/ { EC_PROCESS, "capset" }, // set/get capabilities of thread(s)
	/*PPM_SC_SENDFILE*/ { EC_FILE, "sendfile" }, // transfer data between file descriptors
	/*PPM_SC_GETRLIMIT*/ { EC_PROCESS, "getrlimit" },
	/*PPM_SC_LCHOWN*/ { EC_FILE, "lchown" },
	/*PPM_SC_GETUID*/ { EC_USER, "getuid" },
	/*PPM_SC_GETGID*/ { EC_USER, "getgid" },
	/*PPM_SC_GETEUID*/ { EC_USER, "geteuid" },
	/*PPM_SC_GETEGID*/ { EC_USER, "getegid" },
	/*PPM_SC_SETREUID*/ { EC_USER, "setreuid" },
	/*PPM_SC_SETREGID*/ { EC_USER, "setregid" },
	/*PPM_SC_GETGROUPS*/ { EC_USER, "getgroups" }, // returns the supplementary group IDs of the calling process
	/*PPM_SC_SETGROUPS*/ { EC_USER, "setgroups" }, // returns the supplementary group IDs of the calling process
	/*PPM_SC_FCHOWN*/ { EC_FILE, "fchown" },
	/*PPM_SC_SETRESUID*/ { EC_USER, "setresuid" },
	/*PPM_SC_GETRESUID*/ { EC_USER, "getresuid" },
	/*PPM_SC_SETRESGID*/ { EC_USER, "setresgid" },
	/*PPM_SC_GETRESGID*/ { EC_USER, "getresgid" },
	/*PPM_SC_CHOWN*/ { EC_FILE, "chown" },
	/*PPM_SC_SETUID*/ { EC_USER, "setuid" },
	/*PPM_SC_SETGID*/ { EC_USER, "setgid" },
	/*PPM_SC_SETFSUID*/ { EC_USER, "setfsuid" },
	/*PPM_SC_SETFSGID*/ { EC_USER, "setfsgid" },
	/*PPM_SC_PIVOT_ROOT*/ { EC_PROCESS, "pivot_root" },
	/*PPM_SC_MINCORE*/ { EC_MEMORY, "mincore" }, // determine whether pages are resident in memory
	/*PPM_SC_MADVISE*/ { EC_MEMORY, "madvise" }, // give advice about use of memory
	/*PPM_SC_GETTID*/ { EC_PROCESS, "gettid" },	// returns the caller's thread ID (TID)
	/*PPM_SC_SETXATTR*/ { EC_FILE, "setxattr" }, // set inode attribute
	/*PPM_SC_LSETXATTR*/ { EC_FILE, "lsetxattr" }, 
	/*PPM_SC_FSETXATTR*/ { EC_FILE, "fsetxattr" },
	/*PPM_SC_GETXATTR*/ { EC_FILE, "getxattr" },
	/*PPM_SC_LGETXATTR*/ { EC_FILE, "lgetxattr" },
	/*PPM_SC_FGETXATTR*/ { EC_FILE, "fgetxattr" },
	/*PPM_SC_LISTXATTR*/ { EC_FILE, "listxattr" },
	/*PPM_SC_LLISTXATTR*/ { EC_FILE, "llistxattr" },
	/*PPM_SC_FLISTXATTR*/ { EC_FILE, "flistxattr" },
	/*PPM_SC_REMOVEXATTR*/ { EC_FILE, "removexattr" },
	/*PPM_SC_LREMOVEXATTR*/ { EC_FILE, "lremovexattr" },
	/*PPM_SC_FREMOVEXATTR*/ { EC_FILE, "fremovexattr" },
	/*PPM_SC_TKILL*/ { EC_SIGNAL, "tkill" }, // send a signal to a thread
	/*PPM_SC_FUTEX*/ { EC_IPC, "futex" },
	/*PPM_SC_SCHED_SETAFFINITY*/ { EC_PROCESS, "sched_setaffinity" },
	/*PPM_SC_SCHED_GETAFFINITY*/ { EC_PROCESS, "sched_getaffinity" },
	/*PPM_SC_SET_THREAD_AREA*/ { EC_PROCESS, "set_thread_area" },
	/*PPM_SC_GET_THREAD_AREA*/ { EC_PROCESS, "get_thread_area" },
	/*PPM_SC_IO_SETUP*/ { EC_IO_OTHER, "io_setup" }, // create an asynchronous I/O context (for libaio)
	/*PPM_SC_IO_DESTROY*/ { EC_IO_OTHER, "io_destroy" },
	/*PPM_SC_IO_GETEVENTS*/ { EC_IO_OTHER, "io_getevents" },
	/*PPM_SC_IO_SUBMIT*/ { EC_IO_OTHER, "io_submit" },
	/*PPM_SC_IO_CANCEL*/ { EC_IO_OTHER, "io_cancel" },
	/*PPM_SC_EXIT_GROUP*/ { EC_IO_OTHER, "exit_group" },
	/*PPM_SC_EPOLL_CREATE*/ { EC_WAIT, "epoll_create" },
	/*PPM_SC_EPOLL_CTL*/ { EC_WAIT, "epoll_ctl" },
	/*PPM_SC_EPOLL_WAIT*/ { EC_WAIT, "epoll_wait" },
	/*PPM_SC_REMAP_FILE_PAGES*/ { EC_FILE, "remap_file_pages" }, // create a nonlinear file mapping
	/*PPM_SC_SET_TID_ADDRESS*/ { EC_PROCESS, "set_tid_address" }, // set pointer to thread ID
	/*PPM_SC_TIMER_CREATE*/ { EC_TIME, "timer_create" },
	/*PPM_SC_TIMER_SETTIME*/ { EC_TIME, "timer_settime" },
	/*PPM_SC_TIMER_GETTIME*/ { EC_TIME, "timer_gettime" },
	/*PPM_SC_TIMER_GETOVERRUN*/ { EC_TIME, "timer_getoverrun" },
	/*PPM_SC_TIMER_DELETE*/ { EC_TIME, "timer_delete" },
	/*PPM_SC_CLOCK_SETTIME*/ { EC_TIME, "clock_settime" },
	/*PPM_SC_CLOCK_GETTIME*/ { EC_TIME, "clock_gettime" },
	/*PPM_SC_CLOCK_GETRES*/ { EC_TIME, "clock_getres" },
	/*PPM_SC_CLOCK_NANOSLEEP*/ { EC_SLEEP, "clock_nanosleep" },
	/*PPM_SC_TGKILL*/ { EC_SIGNAL, "tgkill" },
	/*PPM_SC_UTIMES*/ { EC_FILE, "utimes" }, // change file last access and modification times
	/*PPM_SC_MQ_OPEN*/ { EC_IPC, "mq_open" }, // Message queues. See http://linux.die.net/man/7/mq_overview.
	/*PPM_SC_MQ_UNLINK*/ { EC_IPC, "mq_unlink" },
	/*PPM_SC_MQ_TIMEDSEND*/ { EC_IPC, "mq_timedsend" },
	/*PPM_SC_MQ_TIMEDRECEIVE*/ { EC_IPC, "mq_timedreceive" },
	/*PPM_SC_MQ_NOTIFY*/ { EC_IPC, "mq_notify" },
	/*PPM_SC_MQ_GETSETATTR*/ { EC_IPC, "mq_getsetattr" },
	/*PPM_SC_KEXEC_LOAD*/ { EC_SYSTEM, "kexec_load" }, // load a new kernel for later execution
	/*PPM_SC_WAITID*/ { EC_WAIT, "waitid" },
	/*PPM_SC_ADD_KEY*/ { EC_SYSTEM, "add_key" }, // add a key to the kernel's key management facility
	/*PPM_SC_REQUEST_KEY*/ { EC_SYSTEM, "request_key" },
	/*PPM_SC_KEYCTL*/ { EC_SYSTEM, "keyctl" },
	/*PPM_SC_IOPRIO_SET*/ { EC_PROCESS, "ioprio_set" }, // get/set I/O scheduling class and priority
	/*PPM_SC_IOPRIO_GET*/ { EC_PROCESS, "ioprio_get" }, // get/set I/O scheduling class and priority
	/*PPM_SC_INOTIFY_INIT*/ { EC_IPC, "inotify_init" }, // initialize an inotify event queue instance. See http://en.wikipedia.org/wiki/Inotify.
	/*PPM_SC_INOTIFY_ADD_WATCH*/ { EC_IPC, "inotify_add_watch" },
	/*PPM_SC_INOTIFY_RM_WATCH*/ { EC_IPC, "inotify_rm_watch" },
	/*PPM_SC_OPENAT*/ { EC_FILE, "openat" },
	/*PPM_SC_MKDIRAT*/ { EC_FILE, "mkdirat" },
	/*PPM_SC_MKNODAT*/ { EC_FILE, "mknodat" },
	/*PPM_SC_FCHOWNAT*/ { EC_FILE, "fchownat" },
	/*PPM_SC_FUTIMESAT*/ { EC_FILE, "futimesat" },
	/*PPM_SC_UNLINKAT*/ { EC_FILE, "unlinkat" },
	/*PPM_SC_RENAMEAT*/ { EC_FILE, "renameat" },
	/*PPM_SC_LINKAT*/ { EC_FILE, "linkat" },
	/*PPM_SC_SYMLINKAT*/ { EC_FILE, "symlinkat" },
	/*PPM_SC_READLINKAT*/ { EC_FILE, "readlinkat" },
	/*PPM_SC_FCHMODAT*/ { EC_FILE, "fchmodat" },
	/*PPM_SC_FACCESSAT*/ { EC_FILE, "faccessat" },
	/*PPM_SC_PSELECT6*/ { EC_WAIT, "pselect6" },
	/*PPM_SC_PPOLL*/ { EC_WAIT, "ppoll" },
	/*PPM_SC_UNSHARE*/ { EC_PROCESS, "unshare" }, // disassociate parts of the process execution context
	/*PPM_SC_SET_ROBUST_LIST*/ { EC_PROCESS, "set_robust_list" }, // get/set list of robust futexes
	/*PPM_SC_GET_ROBUST_LIST*/ { EC_PROCESS, "get_robust_list" }, // get/set list of robust futexes
	/*PPM_SC_SPLICE*/ { EC_IPC, "splice" }, // transfers up to len bytes of data from the file descriptor fd_in to the file descriptor fd_out, where one of the descriptors must refer to a pipe.
	/*PPM_SC_TEE*/ { EC_IPC, "tee" }, // tee() duplicates up to len bytes of data from the pipe referred to by the file descriptor fd_in to the pipe referred to by the file descriptor fd_out. It does not consume the data that is duplicated from fd_in.
	/*PPM_SC_VMSPLICE*/ { EC_IPC, "vmsplice" }, // splice user pages into a pipe
	/*PPM_SC_GETCPU*/ { EC_PROCESS, "getcpu" }, // determine CPU and NUMA node on which the calling thread is running
	/*PPM_SC_EPOLL_PWAIT*/ { EC_WAIT, "epoll_pwait" },
	/*PPM_SC_UTIMENSAT*/ { EC_FILE, "utimensat" }, // change file timestamps with nanosecond precision
	/*PPM_SC_SIGNALFD*/ { EC_SIGNAL, "signalfd" }, // create a pollable file descriptor for accepting signals
	/*PPM_SC_TIMERFD_CREATE*/ { EC_TIME, "timerfd_create" }, // // create and operate on a timer that delivers timer expiration notifications via a file descriptor
	/*PPM_SC_EVENTFD*/ { EC_IPC, "eventfd" }, // create a file descriptor for event notification
	/*PPM_SC_TIMERFD_SETTIME*/ { EC_TIME, "timerfd_settime" }, // create and operate on a timer that delivers timer expiration notifications via a file descriptor
	/*PPM_SC_TIMERFD_GETTIME*/ { EC_TIME, "timerfd_gettime" }, // create and operate on a timer that delivers timer expiration notifications via a file descriptor
	/*PPM_SC_SIGNALFD4*/ { EC_SIGNAL, "signalfd4" }, // create a pollable file descriptor for accepting signals
	/*PPM_SC_EVENTFD2*/ { EC_IPC, "eventfd2" }, // create a file descriptor for event notification
	/*PPM_SC_EPOLL_CREATE1*/ { EC_WAIT, "epoll_create1" }, // variant of epoll_create
	/*PPM_SC_DUP3*/ { EC_IO_OTHER, "dup3" },
	/*PPM_SC_PIPE2*/ { EC_IPC, "pipe2" },
	/*PPM_SC_INOTIFY_INIT1*/ { EC_IPC, "inotify_init1" },
	/*PPM_SC_PREADV*/ { EC_IO_READ, "preadv" },
	/*PPM_SC_PWRITEV*/ { EC_IO_WRITE, "pwritev" },
	/*PPM_SC_RT_TGSIGQUEUEINFO*/ { EC_OTHER, "rt_tgsigqueueinfo" },
	/*PPM_SC_PERF_EVENT_OPEN*/ { EC_OTHER, "perf_event_open" },
	/*PPM_SC_FANOTIFY_INIT*/ { EC_IPC, "fanotify_init" },
	/*PPM_SC_PRLIMIT64*/ { EC_PROCESS, "prlimit64" },
	/*PPM_SC_CLOCK_ADJTIME*/ { EC_OTHER, "clock_adjtime" },
	/*PPM_SC_SYNCFS*/ { EC_FILE, "syncfs" },
	/*PPM_SC_SETNS*/ { EC_PROCESS, "setns" }, // reassociate thread with a namespace
	/*PPM_SC_GETDENTS64*/  { EC_IPC, "getdents64" },
	//
	// Non-multiplexed socket family
	//
	/*PPM_SC_SOCKET*/  { EC_NET, "socket" },
	/*PPM_SC_BIND*/  	{ EC_NET, "bind" },
	/*PPM_SC_CONNECT*/  { EC_NET, "connect" },
	/*PPM_SC_LISTEN*/  { EC_NET, "listen" },
	/*PPM_SC_ACCEPT*/  { EC_NET, "accept" },
	/*PPM_SC_GETSOCKNAME*/ { EC_NET, "getsockname" },
	/*PPM_SC_GETPEERNAME*/ { EC_NET, "getpeername" },
	/*PPM_SC_SOCKETPAIR*/ { EC_NET, "socketpair" },
	/*PPM_SC_SENDTO*/  { EC_NET, "sendto" },
	/*PPM_SC_RECVFROM*/  { EC_NET, "recvfrom" },
	/*PPM_SC_SHUTDOWN*/  { EC_NET, "shutdown" },
	/*PPM_SC_SETSOCKOPT*/ { EC_NET, "setsockopt" },
	/*PPM_SC_GETSOCKOPT*/ { EC_NET, "getsockopt" },
	/*PPM_SC_SENDMSG*/  { EC_NET, "sendmsg" },
	/*PPM_SC_SENDMMSG*/  { EC_NET, "sendmmsg" },
	/*PPM_SC_RECVMSG*/  { EC_NET, "recvmsg" },
	/*PPM_SC_RECVMMSG*/  { EC_NET, "recvmmsg" },
	/*PPM_SC_ACCEPT4*/  { EC_NET, "accept4" },
	//
	// Non-multiplexed IPC family
	//
	/*PPM_SC_SEMOP*/  { EC_IPC, "semop" },
	/*PPM_SC_SEMGET*/  { EC_IPC, "semget" },
	/*PPM_SC_SEMCTL*/  { EC_IPC, "semctl" },
	/*PPM_SC_MSGSND*/  { EC_IPC, "msgsnd" },
	/*PPM_SC_MSGRCV*/  { EC_IPC, "msgrcv" },
	/*PPM_SC_MSGGET*/  { EC_IPC, "msgget" },
	/*PPM_SC_MSGCTL*/  { EC_IPC, "msgctl" },
	/*PPM_SC_SHMDT*/  { EC_IPC, "shmdt" },
	/*PPM_SC_SHMGET*/  { EC_IPC, "shmget" },
	/*PPM_SC_SHMCTL*/  { EC_IPC, "shmctl" },
	/*PPM_SC_STATFS64*/ { EC_FILE, "statfs64" },
	/*PPM_SC_FSTATFS64*/ { EC_FILE, "fstatfs64" },
	/*PPM_SC_FSTATAT64*/ { EC_FILE, "fstatat64" },
	/*PPM_SC_SENDFILE64*/ { EC_FILE, "sendfile64" },
	/*PPM_SC_UGETRLIMIT*/ { EC_PROCESS, "ugetrlimit" },
	/*PPM_SC_BDFLUSH*/ { EC_OTHER, "bdflush" },	// deprecated
	/*PPM_SC_SIGPROCMASK*/ { EC_SIGNAL, "sigprocmask" }, // examine and change blocked signals
	/*PPM_SC_IPC*/ { EC_IPC, "ipc" },
	/*PPM_SC_SOCKETCALL*/ { EC_NET, "socketcall" },
	/*PPM_SC_STAT64*/ { EC_FILE, "stat64" },
	/*PPM_SC_LSTAT64*/ { EC_FILE, "lstat64" },
	/*PPM_SC_FSTAT64*/ { EC_FILE, "fstat64" },
	/*PPM_SC_FCNTL64*/ { EC_FILE, "fcntl64" },
	/*PPM_SC_MMAP2*/ { EC_FILE, "mmap2" },
	/*PPM_SC__NEWSELECT*/ { EC_WAIT, "newselect" },
	/*PPM_SC_SGETMASK*/ { EC_SIGNAL, "sgetmask" }, //  manipulation of signal mask (obsolete)
	/*PPM_SC_SSETMASK*/ { EC_SIGNAL, "ssetmask" }, // manipulation of signal mask (obsolete)
	/*PPM_SC_SIGPENDING*/ { EC_SIGNAL, "sigpending" }, // examine pending signals
	/*PPM_SC_OLDUNAME*/ { EC_SYSTEM, "olduname" },
	/*PPM_SC_UMOUNT*/ { EC_FILE, "umount" },
	/*PPM_SC_SIGNAL*/ { EC_SIGNAL, "signal" },
	/*PPM_SC_NICE*/ { EC_PROCESS, "nice" }, // change process priority
	/*PPM_SC_STIME*/ { EC_TIME, "stime" },
	/*PPM_SC__LLSEEK*/	{ EC_FILE, "llseek" },
	/*PPM_SC_WAITPID*/ { EC_WAIT, "waitpid" },
	/*PPM_SC_PREAD64*/ { EC_FILE, "pread64" },
	/*PPM_SC_PWRITE64*/ { EC_FILE, "pwrite64" },
};
