/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KERNEL_FLAGS_H
#define __KERNEL_FLAGS_H

/* Architecture definitions from `uname -m` */

#ifdef __SYSDIG_BTF_BUILD__

// Assume that every feature is enabled in the btf context
#define IS_ENABLED(x) 1

#define UTS_RELEASE "btf"

#define NULL ((void *)0)

#define BPF_SUPPORTS_RAW_TRACEPOINTS

/* We make all the kernel flags specific for a given target architecture,
in this way we avoid incompatibilities even if some architecture might share values */
#ifdef __TARGET_ARCH_X86__

#define _64BIT_ARGS_SINGLE_REGISTER

/*
The constants/defs from here come from the Linux Kernel repository,
direct kernel headers are not used here as a workaround
to avoid clang to process x86 asm inside kernel headers.
Also, this is used in BTF builds only so we won't have access to
kernel headers anyways.
*/
// Open Flags
#define O_ACCMODE 00000003
#define O_RDONLY 00000000
#define O_WRONLY 00000001
#define O_RDWR 00000002
#ifndef O_CREAT
#define O_CREAT 00000100 /* not fcntl */
#endif
#ifndef O_EXCL
#define O_EXCL 00000200 /* not fcntl */
#endif
#ifndef O_NOCTTY
#define O_NOCTTY 00000400 /* not fcntl */
#endif
#ifndef O_TRUNC
#define O_TRUNC 00001000 /* not fcntl */
#endif
#ifndef O_APPEND
#define O_APPEND 00002000
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK 00004000
#endif
#ifndef O_DSYNC
#define O_DSYNC 00010000 /* used to be O_SYNC, see below */
#endif
#ifndef FASYNC
#define FASYNC 00020000 /* fcntl, for BSD compatibility */
#endif
#ifndef O_DIRECT
#define O_DIRECT 00040000 /* direct disk access hint */
#endif
#ifndef O_LARGEFILE
#define O_LARGEFILE 00100000
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 00200000 /* must be a directory */
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 00400000 /* don't follow links */
#endif
#ifndef O_NOATIME
#define O_NOATIME 01000000
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 02000000 /* set close_on_exec */
#endif
#ifndef O_SYNC
#define __O_SYNC 04000000
#define O_SYNC (__O_SYNC | O_DSYNC)
#endif

#ifndef O_PATH
#define O_PATH 010000000
#endif

#ifndef __O_TMPFILE
#define __O_TMPFILE 020000000
#endif

#define O_TMPFILE (__O_TMPFILE | O_DIRECTORY)
#define O_TMPFILE_MASK (__O_TMPFILE | O_DIRECTORY | O_CREAT)

// ipc flags

#define IPC_RMID 0          /* remove resource */
#define IPC_SET 1           /* set ipc_perm options */
#define IPC_STAT 2          /* get ipc_perm options */
#define IPC_INFO 3          /* see ipcs */
#define IPC_OLD 0           /* Old version (no 32-bit UID support on many \
                       architectures) */
#define IPC_64 0x0100       /* New version (support 32-bit UIDs, bigger \
                   message sizes, etc. */
#define IPC_CREAT 00001000  /* create if key is nonexistent */
#define IPC_EXCL 00002000   /* fail if key exists */
#define IPC_NOWAIT 00004000 /* return error on wait */

// Stat flags

#define S_IFMT 00170000
#define S_IFSOCK 0140000
#define S_IFLNK 0120000
#define S_IFREG 0100000
#define S_IFBLK 0060000
#define S_IFDIR 0040000
#define S_IFCHR 0020000
#define S_IFIFO 0010000
#define S_ISUID 0004000
#define S_ISGID 0002000
#define S_ISVTX 0001000

#define S_ISLNK(m) (((m)&S_IFMT) == S_IFLNK)
#define S_ISREG(m) (((m)&S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m)&S_IFMT) == S_IFDIR)
#define S_ISCHR(m) (((m)&S_IFMT) == S_IFCHR)
#define S_ISBLK(m) (((m)&S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m)&S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m)&S_IFMT) == S_IFSOCK)

#define S_IRWXU 00700
#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IXUSR 00100

#define S_IRWXG 00070
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010

#define S_IRWXO 00007
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001

// flock operations

#define LOCK_SH 1 /* shared lock */
#define LOCK_EX 2 /* exclusive lock */
#define LOCK_NB 4 /* or'd with one of the above to prevent \
             blocking */
#define LOCK_UN 8 /* remove lock */

#define LOCK_MAND 32   /* This is a mandatory flock ... */
#define LOCK_READ 64   /* which allows concurrent read operations */
#define LOCK_WRITE 128 /* which allows concurrent write operations */
#define LOCK_RW 192    /* which allows concurrent read & write ops */

// Socket flags

#define AF_UNSPEC 0
#define AF_UNIX 1      /* Unix domain sockets 		*/
#define AF_LOCAL 1     /* POSIX name for AF_UNIX	*/
#define AF_INET 2      /* Internet IP Protocol 	*/
#define AF_AX25 3      /* Amateur Radio AX.25 		*/
#define AF_IPX 4       /* Novell IPX 			*/
#define AF_APPLETALK 5 /* AppleTalk DDP 		*/
#define AF_NETROM 6    /* Amateur Radio NET/ROM 	*/
#define AF_BRIDGE 7    /* Multiprotocol bridge 	*/
#define AF_ATMPVC 8    /* ATM PVCs			*/
#define AF_X25 9       /* Reserved for X.25 project 	*/
#define AF_INET6 10    /* IP version 6			*/
#define AF_ROSE 11     /* Amateur Radio X.25 PLP	*/
#define AF_DECnet 12   /* Reserved for DECnet project	*/
#define AF_NETBEUI 13  /* Reserved for 802.2LLC project*/
#define AF_SECURITY 14 /* Security callback pseudo AF */
#define AF_KEY 15      /* PF_KEY key management API */
#define AF_NETLINK 16
#define AF_ROUTE AF_NETLINK /* Alias to emulate 4.4BSD */
#define AF_PACKET 17        /* Packet family		*/
#define AF_ASH 18           /* Ash				*/
#define AF_ECONET 19        /* Acorn Econet			*/
#define AF_ATMSVC 20        /* ATM SVCs			*/
#define AF_RDS 21           /* RDS sockets 			*/
#define AF_SNA 22           /* Linux SNA Project (nutters!) */
#define AF_IRDA 23          /* IRDA sockets			*/
#define AF_PPPOX 24         /* PPPoX sockets		*/
#define AF_WANPIPE 25       /* Wanpipe API Sockets */
#define AF_LLC 26           /* Linux LLC			*/
#define AF_IB 27            /* Native InfiniBand address	*/
#define AF_MPLS 28          /* MPLS */
#define AF_CAN 29           /* Controller Area Network      */
#define AF_TIPC 30          /* TIPC sockets			*/
#define AF_BLUETOOTH 31     /* Bluetooth sockets 		*/
#define AF_IUCV 32          /* IUCV sockets			*/
#define AF_RXRPC 33         /* RxRPC sockets 		*/
#define AF_ISDN 34          /* mISDN sockets 		*/
#define AF_PHONET 35        /* Phonet sockets		*/
#define AF_IEEE802154 36    /* IEEE802154 sockets		*/
#define AF_CAIF 37          /* CAIF sockets			*/
#define AF_ALG 38           /* Algorithm sockets		*/
#define AF_NFC 39           /* NFC sockets			*/
#define AF_VSOCK 40         /* vSockets			*/
#define AF_KCM 41           /* Kernel Connection Multiplexor*/
#define AF_QIPCRTR 42       /* Qualcomm IPC Router          */
#define AF_SMC 43           /* smc sockets: reserve number for \
                             * PF_SMC protocol family that     \
                             * reuses AF_INET address family   \
                             */
#define AF_XDP 44           /* XDP sockets			*/

#define AF_MAX 45 /* For now.. */

// Memory paging flags

#define PROT_READ 0x1             /* page can be read */
#define PROT_WRITE 0x2            /* page can be written */
#define PROT_EXEC 0x4             /* page can be executed */
#define PROT_SEM 0x8              /* page may be used for atomic ops */
#define PROT_NONE 0x0             /* page can not be accessed */
#define PROT_GROWSDOWN 0x01000000 /* mprotect flag: extend change to start of growsdown vma */
#define PROT_GROWSUP 0x02000000   /* mprotect flag: extend change to end of growsup vma */

// iops ctl sem flags

#define SEM_STAT 18
#define SEM_INFO 19
#define SEM_STAT_ANY 20

// file seek
#define SEEK_SET 0  /* seek relative to beginning of file */
#define SEEK_CUR 1  /* seek relative to current file position */
#define SEEK_END 2  /* seek relative to end of file */
#define SEEK_DATA 3 /* seek to the next data */
#define SEEK_HOLE 4 /* seek to the next hole */
#define SEEK_MAX SEEK_HOLE

// Poll flags
/* These are specified by iBCS2 */
#define POLLIN 0x0001
#define POLLPRI 0x0002
#define POLLOUT 0x0004
#define POLLERR 0x0008
#define POLLHUP 0x0010
#define POLLNVAL 0x0020

/* The rest seem to be more-or-less nonstandard. Check them! */
#define POLLRDNORM 0x0040
#define POLLRDBAND 0x0080
#ifndef POLLWRNORM
#define POLLWRNORM 0x0100
#endif
#ifndef POLLWRBAND
#define POLLWRBAND 0x0200
#endif
#ifndef POLLMSG
#define POLLMSG 0x0400
#endif
#ifndef POLLREMOVE
#define POLLREMOVE 0x1000
#endif
#ifndef POLLRDHUP
#define POLLRDHUP 0x2000
#endif

#define POLLFREE (__force __poll_t)0x4000 /* currently only for epoll */

#define POLL_BUSY_LOOP (__force __poll_t)0x8000

// Kernel thread flags
#define PF_KTHREAD 0x00200000 /* I am a kernel thread */

// File descriptor arguments
#define AT_FDCWD -100             /* Special value used to indicate        \
                                             openat should use the current \
                                             working directory. */
#define AT_SYMLINK_NOFOLLOW 0x100 /* Do not follow symbolic links.  */
#define AT_EACCESS 0x200          /* Test access permitted for \
                                             effective IDs, not real IDs.  */
#define AT_REMOVEDIR 0x200        /* Remove directory instead of \
                                         unlinking file.  */
#define AT_SYMLINK_FOLLOW 0x400   /* Follow symbolic links.  */
#define AT_NO_AUTOMOUNT 0x800     /* Suppress terminal automount traversal */
#define AT_EMPTY_PATH 0x1000      /* Allow empty relative pathname */

#define AT_STATX_SYNC_TYPE 0x6000    /* Type of synchronisation required from statx() */
#define AT_STATX_SYNC_AS_STAT 0x0000 /* - Do whatever stat() does */
#define AT_STATX_FORCE_SYNC 0x2000   /* - Force the attributes to be sync'd with the server */
#define AT_STATX_DONT_SYNC 0x4000    /* - Don't sync attributes with the server */

#define AT_RECURSIVE 0x8000 /* Apply to the entire subtree */

// Quota flags

#define IIF_BGRACE 1
#define IIF_IGRACE 2
#define IIF_FLAGS 4
#define IIF_ALL (IIF_BGRACE | IIF_IGRACE | IIF_FLAGS)

#define QIF_BLIMITS (1 << QIF_BLIMITS_B)
#define QIF_SPACE (1 << QIF_SPACE_B)
#define QIF_ILIMITS (1 << QIF_ILIMITS_B)
#define QIF_INODES (1 << QIF_INODES_B)
#define QIF_BTIME (1 << QIF_BTIME_B)
#define QIF_ITIME (1 << QIF_ITIME_B)
#define QIF_LIMITS (QIF_BLIMITS | QIF_ILIMITS)
#define QIF_USAGE (QIF_SPACE | QIF_INODES)
#define QIF_TIMES (QIF_BTIME | QIF_ITIME)
#define QIF_ALL (QIF_LIMITS | QIF_USAGE | QIF_TIMES)

// Sem flags

/* semop flags */
#define SEM_UNDO 0x1000 /* undo the operation on exit */

/* semctl Command Definitions. */
#define GETPID 11  /* get sempid */
#define GETVAL 12  /* get semval */
#define GETALL 13  /* get all semval's */
#define GETNCNT 14 /* get semncnt */
#define GETZCNT 15 /* get semzcnt */
#define SETVAL 16  /* set semval */
#define SETALL 17  /* set all semval's */

/* ipcs ctl cmds */
#define SEM_STAT 18
#define SEM_INFO 19
#define SEM_STAT_ANY 20

/*
 * si_code values
 * Digital reserves positive values for kernel-generated signals.
 */
#define SI_USER 0      /* sent by kill, sigsend, raise */
#define SI_KERNEL 0x80 /* sent by the kernel from somewhere */
#define SI_QUEUE -1    /* sent by sigqueue */
#define SI_TIMER -2    /* sent by timer expiration */
#define SI_MESGQ -3    /* sent by real time mesq state change */
#define SI_ASYNCIO -4  /* sent by AIO completion */
#define SI_SIGIO -5    /* sent by queued SIGIO */
#define SI_TKILL -6    /* sent by tkill system call */
#define SI_DETHREAD -7 /* sent by execve() killing subsidiary threads */
#define SI_ASYNCNL -60 /* sent by glibc async name lookup completion */

// Signal flag access
#define si_pid _sifields._kill._pid

// Signal

/* These can be the second arg to send_sig_info/send_group_sig_info.  */
#define SEND_SIG_NOINFO ((struct kernel_siginfo *)0)
#define SEND_SIG_PRIV ((struct kernel_siginfo *)1)

// Sockaddr storage

#define sockaddr_storage __kernel_sockaddr_storage

// User attrs

#define __user

// in6

#define s6_addr in6_u.u6_addr8

// sock attributes

#define sk_family __sk_common.skc_family
#define sk_v6_daddr __sk_common.skc_v6_daddr
#define sk_v6_rcv_saddr __sk_common.skc_v6_rcv_saddr

// inet attributes
#define inet_daddr sk.__sk_common.skc_daddr
#define inet_dport sk.__sk_common.skc_dport
#define inet_rcv_saddr sk.__sk_common.skc_rcv_saddr

// fs perm
#define MAY_EXEC 0x00000001
#define MAY_WRITE 0x00000002
#define MAY_READ 0x00000004
#define MAY_APPEND 0x00000008
#define MAY_ACCESS 0x00000010
#define MAY_OPEN 0x00000020
#define MAY_CHDIR 0x00000040
/* called from RCU mode, don't block */
#define MAY_NOT_BLOCK 0x00000080

// un
#define UNIX_PATH_MAX 108

// errno base

#define EPERM 1            /* Operation not permitted */
#define ENOENT 2           /* No such file or directory */
#define ESRCH 3            /* No such process */
#define EINTR 4            /* Interrupted system call */
#define EIO 5              /* I/O error */
#define ENXIO 6            /* No such device or address */
#define E2BIG 7            /* Argument list too long */
#define ENOEXEC 8          /* Exec format error */
#define EBADF 9            /* Bad file number */
#define ECHILD 10          /* No child processes */
#define EAGAIN 11          /* Try again */
#define ENOMEM 12          /* Out of memory */
#define EACCES 13          /* Permission denied */
#define EFAULT 14          /* Bad address */
#define ENOTBLK 15         /* Block device required */
#define EBUSY 16           /* Device or resource busy */
#define EEXIST 17          /* File exists */
#define EXDEV 18           /* Cross-device link */
#define ENODEV 19          /* No such device */
#define ENOTDIR 20         /* Not a directory */
#define EISDIR 21          /* Is a directory */
#define EINVAL 22          /* Invalid argument */
#define ENFILE 23          /* File table overflow */
#define EMFILE 24          /* Too many open files */
#define ENOTTY 25          /* Not a typewriter */
#define ETXTBSY 26         /* Text file busy */
#define EFBIG 27           /* File too large */
#define ENOSPC 28          /* No space left on device */
#define ESPIPE 29          /* Illegal seek */
#define EROFS 30           /* Read-only file system */
#define EMLINK 31          /* Too many links */
#define EPIPE 32           /* Broken pipe */
#define EDOM 33            /* Math argument out of domain of func */
#define ERANGE 34          /* Math result not representable */
#define EDEADLK 35         /* Resource deadlock would occur */
#define ENAMETOOLONG 36    /* File name too long */
#define ENOLCK 37          /* No record locks available */
#define ENOSYS 38          /* Invalid system call number */
#define ENOTEMPTY 39       /* Directory not empty */
#define ELOOP 40           /* Too many symbolic links encountered */
#define EWOULDBLOCK EAGAIN /* Operation would block */
#define ENOMSG 42          /* No message of desired type */
#define EIDRM 43           /* Identifier removed */
#define ECHRNG 44          /* Channel number out of range */
#define EL2NSYNC 45        /* Level 2 not synchronized */
#define EL3HLT 46          /* Level 3 halted */
#define EL3RST 47          /* Level 3 reset */
#define ELNRNG 48          /* Link number out of range */
#define EUNATCH 49         /* Protocol driver not attached */
#define ENOCSI 50          /* No CSI structure available */
#define EL2HLT 51          /* Level 2 halted */
#define EBADE 52           /* Invalid exchange */
#define EBADR 53           /* Invalid request descriptor */
#define EXFULL 54          /* Exchange full */
#define ENOANO 55          /* No anode */
#define EBADRQC 56         /* Invalid request code */
#define EBADSLT 57         /* Invalid slot */
#define EDEADLOCK EDEADLK
#define EBFONT 59          /* Bad font file format */
#define ENOSTR 60          /* Device not a stream */
#define ENODATA 61         /* No data available */
#define ETIME 62           /* Timer expired */
#define ENOSR 63           /* Out of streams resources */
#define ENONET 64          /* Machine is not on the network */
#define ENOPKG 65          /* Package not installed */
#define EREMOTE 66         /* Object is remote */
#define ENOLINK 67         /* Link has been severed */
#define EADV 68            /* Advertise error */
#define ESRMNT 69          /* Srmount error */
#define ECOMM 70           /* Communication error on send */
#define EPROTO 71          /* Protocol error */
#define EMULTIHOP 72       /* Multihop attempted */
#define EDOTDOT 73         /* RFS specific error */
#define EBADMSG 74         /* Not a data message */
#define EOVERFLOW 75       /* Value too large for defined data type */
#define ENOTUNIQ 76        /* Name not unique on network */
#define EBADFD 77          /* File descriptor in bad state */
#define EREMCHG 78         /* Remote address changed */
#define ELIBACC 79         /* Can not access a needed shared library */
#define ELIBBAD 80         /* Accessing a corrupted shared library */
#define ELIBSCN 81         /* .lib section in a.out corrupted */
#define ELIBMAX 82         /* Attempting to link in too many shared libraries */
#define ELIBEXEC 83        /* Cannot exec a shared library directly */
#define EILSEQ 84          /* Illegal byte sequence */
#define ERESTART 85        /* Interrupted system call should be restarted */
#define ESTRPIPE 86        /* Streams pipe error */
#define EUSERS 87          /* Too many users */
#define ENOTSOCK 88        /* Socket operation on non-socket */
#define EDESTADDRREQ 89    /* Destination address required */
#define EMSGSIZE 90        /* Message too long */
#define EPROTOTYPE 91      /* Protocol wrong type for socket */
#define ENOPROTOOPT 92     /* Protocol not available */
#define EPROTONOSUPPORT 93 /* Protocol not supported */
#define ESOCKTNOSUPPORT 94 /* Socket type not supported */
#define EOPNOTSUPP 95      /* Operation not supported on transport endpoint */
#define EPFNOSUPPORT 96    /* Protocol family not supported */
#define EAFNOSUPPORT 97    /* Address family not supported by protocol */
#define EADDRINUSE 98      /* Address already in use */
#define EADDRNOTAVAIL 99   /* Cannot assign requested address */
#define ENETDOWN 100       /* Network is down */
#define ENETUNREACH 101    /* Network is unreachable */
#define ENETRESET 102      /* Network dropped connection because of reset */
#define ECONNABORTED 103   /* Software caused connection abort */
#define ECONNRESET 104     /* Connection reset by peer */
#define ENOBUFS 105        /* No buffer space available */
#define EISCONN 106        /* Transport endpoint is already connected */
#define ENOTCONN 107       /* Transport endpoint is not connected */
#define ESHUTDOWN 108      /* Cannot send after transport endpoint shutdown */
#define ETOOMANYREFS 109   /* Too many references: cannot splice */
#define ETIMEDOUT 110      /* Connection timed out */
#define ECONNREFUSED 111   /* Connection refused */
#define EHOSTDOWN 112      /* Host is down */
#define EHOSTUNREACH 113   /* No route to host */
#define EALREADY 114       /* Operation already in progress */
#define EINPROGRESS 115    /* Operation now in progress */
#define ESTALE 116         /* Stale file handle */
#define EUCLEAN 117        /* Structure needs cleaning */
#define ENOTNAM 118        /* Not a XENIX named type file */
#define ENAVAIL 119        /* No XENIX semaphores available */
#define EISNAM 120         /* Is a named type file */
#define EREMOTEIO 121      /* Remote I/O error */
#define EDQUOT 122         /* Quota exceeded */

#define ENOMEDIUM 123    /* No medium found */
#define EMEDIUMTYPE 124  /* Wrong medium type */
#define ECANCELED 125    /* Operation Canceled */
#define ENOKEY 126       /* Required key not available */
#define EKEYEXPIRED 127  /* Key has expired */
#define EKEYREVOKED 128  /* Key has been revoked */
#define EKEYREJECTED 129 /* Key was rejected by service */

/* for robust mutexes */
#define EOWNERDEAD 130      /* Owner died */
#define ENOTRECOVERABLE 131 /* State not recoverable */

#define ERFKILL 132 /* Operation not possible due to RF-kill */

#define EHWPOISON 133 /* Memory page has hardware error */

// Futex

/* Second argument to futex syscall */

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_FD 2
#define FUTEX_REQUEUE 3
#define FUTEX_CMP_REQUEUE 4
#define FUTEX_WAKE_OP 5
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_TRYLOCK_PI 8
#define FUTEX_WAIT_BITSET 9
#define FUTEX_WAKE_BITSET 10
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI 12

#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_CLOCK_REALTIME 256
#define FUTEX_CMD_MASK ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)

#define FUTEX_WAIT_PRIVATE (FUTEX_WAIT | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAKE_PRIVATE (FUTEX_WAKE | FUTEX_PRIVATE_FLAG)
#define FUTEX_REQUEUE_PRIVATE (FUTEX_REQUEUE | FUTEX_PRIVATE_FLAG)
#define FUTEX_CMP_REQUEUE_PRIVATE (FUTEX_CMP_REQUEUE | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAKE_OP_PRIVATE (FUTEX_WAKE_OP | FUTEX_PRIVATE_FLAG)
#define FUTEX_LOCK_PI_PRIVATE (FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG)
#define FUTEX_UNLOCK_PI_PRIVATE (FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG)
#define FUTEX_TRYLOCK_PI_PRIVATE (FUTEX_TRYLOCK_PI | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAIT_BITSET_PRIVATE (FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAKE_BITSET_PRIVATE (FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAIT_REQUEUE_PI_PRIVATE (FUTEX_WAIT_REQUEUE_PI | \
                                       FUTEX_PRIVATE_FLAG)
#define FUTEX_CMP_REQUEUE_PI_PRIVATE (FUTEX_CMP_REQUEUE_PI | \
                                      FUTEX_PRIVATE_FLAG)

// Clone flags
#define CSIGNAL 0x000000ff                 /* signal mask to be sent at exit */
#define CLONE_VM 0x00000100                /* set if VM shared between processes */
#define CLONE_FS 0x00000200                /* set if fs info shared between processes */
#define CLONE_FILES 0x00000400             /* set if open files shared between processes */
#define CLONE_SIGHAND 0x00000800           /* set if signal handlers and blocked signals shared */
#define CLONE_PIDFD 0x00001000             /* set if a pidfd should be placed in parent */
#define CLONE_PTRACE 0x00002000            /* set if we want to let tracing continue on the child too */
#define CLONE_VFORK 0x00004000             /* set if the parent wants the child to wake it up on mm_release */
#define CLONE_PARENT 0x00008000            /* set if we want to have the same parent as the cloner */
#define CLONE_THREAD 0x00010000            /* Same thread group? */
#define CLONE_NEWNS 0x00020000             /* New mount namespace group */
#define CLONE_SYSVSEM 0x00040000           /* share system V SEM_UNDO semantics */
#define CLONE_SETTLS 0x00080000            /* create a new TLS for the child */
#define CLONE_PARENT_SETTID 0x00100000     /* set the TID in the parent */
#define CLONE_CHILD_CLEARTID 0x00200000    /* clear the TID in the child */
#define CLONE_DETACHED 0x00400000          /* Unused, ignored */
#define CLONE_UNTRACED 0x00800000          /* set if the tracing process can't force CLONE_PTRACE on this clone */
#define CLONE_CHILD_SETTID 0x01000000      /* set the TID in the child */
#define CLONE_NEWCGROUP 0x02000000         /* New cgroup namespace */
#define CLONE_NEWUTS 0x04000000            /* New utsname namespace */
#define CLONE_NEWIPC 0x08000000            /* New ipc namespace */
#define CLONE_NEWUSER 0x10000000           /* New user namespace */
#define CLONE_NEWPID 0x20000000            /* New pid namespace */
#define CLONE_NEWNET 0x40000000            /* New network namespace */
#define CLONE_IO 0x80000000                /* Clone io context */
#define CLONE_CLEAR_SIGHAND 0x100000000ULL /* Clear any signal handler and reset to SIG_DFL. */
#define CLONE_INTO_CGROUP 0x200000000ULL   /* Clone into a specific cgroup given the right permissions. */
#define CLONE_NEWTIME 0x00000080           /* New time namespace */

// Quota

#define SUBCMDMASK 0x00ff
#define SUBCMDSHIFT 8
#define QCMD(cmd, type) (((cmd) << SUBCMDSHIFT) | ((type)&SUBCMDMASK))

#define Q_SYNC 0x800001         /* sync disk copy of a filesystems quotas */
#define Q_QUOTAON 0x800002      /* turn quotas on */
#define Q_QUOTAOFF 0x800003     /* turn quotas off */
#define Q_GETFMT 0x800004       /* get quota format used on given filesystem */
#define Q_GETINFO 0x800005      /* get information about quota files */
#define Q_SETINFO 0x800006      /* set information about quota files */
#define Q_GETQUOTA 0x800007     /* get user quota structure */
#define Q_SETQUOTA 0x800008     /* set user quota structure */
#define Q_GETNEXTQUOTA 0x800009 /* get disk limits and usage >= ID */

/* Quota format type IDs */
#define QFMT_VFS_OLD 1
#define QFMT_VFS_V0 2
#define QFMT_OCFS2 3
#define QFMT_VFS_V1 4

/* Size of block in which space limits are passed through the quota
 * interface */
#define QIF_DQBLKSIZE_BITS 10
#define QIF_DQBLKSIZE (1 << QIF_DQBLKSIZE_BITS)

// Xfs quota disk

#define XQM_CMD(x) (('X' << 8) + (x))                      /* note: forms first QCMD argument */
#define XQM_COMMAND(x) (((x) & (0xff << 8)) == ('X' << 8)) /* test if for XFS */

#define XQM_USRQUOTA 0 /* system call user quota type */
#define XQM_GRPQUOTA 1 /* system call group quota type */
#define XQM_PRJQUOTA 2 /* system call project quota type */
#define XQM_MAXQUOTAS 3

#define Q_XQUOTAON XQM_CMD(1)      /* enable accounting/enforcement */
#define Q_XQUOTAOFF XQM_CMD(2)     /* disable accounting/enforcement */
#define Q_XGETQUOTA XQM_CMD(3)     /* get disk limits and usage */
#define Q_XSETQLIM XQM_CMD(4)      /* set disk limits */
#define Q_XGETQSTAT XQM_CMD(5)     /* get quota subsystem status */
#define Q_XQUOTARM XQM_CMD(6)      /* free disk space used by dquots */
#define Q_XQUOTASYNC XQM_CMD(7)    /* delalloc flush, updates dquots */
#define Q_XGETQSTATV XQM_CMD(8)    /* newer version of get quota */
#define Q_XGETNEXTQUOTA XQM_CMD(9) /* get disk limits and usage >= ID */

// Ptrace

#define PTRACE_TRACEME 0
#define PTRACE_PEEKTEXT 1
#define PTRACE_PEEKDATA 2
#define PTRACE_PEEKUSR 3
#define PTRACE_POKETEXT 4
#define PTRACE_POKEDATA 5
#define PTRACE_POKEUSR 6
#define PTRACE_CONT 7
#define PTRACE_KILL 8
#define PTRACE_SINGLESTEP 9
#define PTRACE_ATTACH 16
#define PTRACE_DETACH 17
#define PTRACE_SYSCALL 24
#define PTRACE_SETOPTIONS 0x4200
#define PTRACE_GETEVENTMSG 0x4201
#define PTRACE_GETSIGINFO 0x4202
#define PTRACE_SETSIGINFO 0x4203
#define PTRACE_GETREGSET 0x4204
#define PTRACE_SETREGSET 0x4205
#define PTRACE_SEIZE 0x4206
#define PTRACE_INTERRUPT 0x4207
#define PTRACE_LISTEN 0x4208

#define PTRACE_PEEKSIGINFO 0x4209

// mman
#define MAP_ANONYMOUS 0x20 /* don't use a file */
#define MAP_FIXED 0x10     /* Interpret addr exactly */

#define MAP_SHARED 0x01          /* Share changes */
#define MAP_PRIVATE 0x02         /* Changes are private */
#define MAP_SHARED_VALIDATE 0x03 /* share + validate extension flags */

#define MAP_GROWSDOWN 0x0100  /* stack-like segment */
#define MAP_DENYWRITE 0x0800  /* ETXTBSY */
#define MAP_EXECUTABLE 0x1000 /* mark it as an executable */
#define MAP_LOCKED 0x2000     /* pages are locked */
#define MAP_NORESERVE 0x4000  /* don't check for reservations */

#define MAP_FILE 0

#define MAP_POPULATE 0x008000        /* populate (prefault) pagetables */
#define MAP_NONBLOCK 0x010000        /* do not block on IO */
#define MAP_STACK 0x020000           /* give out an address that is best suited for process/thread stacks */
#define MAP_HUGETLB 0x040000         /* create a huge page mapping */
#define MAP_SYNC 0x080000            /* perform synchronous page faults for the mapping */
#define MAP_FIXED_NOREPLACE 0x100000 /* MAP_FIXED which doesn't unmap underlying mapping */

#define SOL_SOCKET 1

#define F_GETLK64 12 /*  using 'struct flock64' */

#define POLLRDHUP 0x2000

// Signals

#define _NSIG 64

#define SIGHUP 1
#define SIGINT 2
#define SIGQUIT 3
#define SIGILL 4
#define SIGTRAP 5
#define SIGABRT 6
#define SIGIOT 6
#define SIGBUS 7
#define SIGFPE 8
#define SIGKILL 9
#define SIGUSR1 10
#define SIGSEGV 11
#define SIGUSR2 12
#define SIGPIPE 13
#define SIGALRM 14
#define SIGTERM 15
#define SIGSTKFLT 16
#define SIGCHLD 17
#define SIGCONT 18
#define SIGSTOP 19
#define SIGTSTP 20
#define SIGTTIN 21
#define SIGTTOU 22
#define SIGURG 23
#define SIGXCPU 24
#define SIGXFSZ 25
#define SIGVTALRM 26
#define SIGPROF 27
#define SIGWINCH 28
#define SIGIO 29
#define SIGPOLL SIGIO
/*
#define SIGLOST		29
*/
#define SIGPWR 30
#define SIGSYS 31
#define SIGUNUSED 31

/* These should not be considered constants from userland.  */
#define SIGRTMIN 32
#ifndef SIGRTMAX
#define SIGRTMAX _NSIG
#endif

// page types
#define PAGE_SHIFT 12

// Thread synchronous status
#define TS_COMPAT 0x0002 /* 32bit syscall active (64BIT)*/

// Resource

#define RLIMIT_CPU 0   /* CPU time in sec */
#define RLIMIT_FSIZE 1 /* Maximum filesize */
#define RLIMIT_DATA 2  /* max data size */
#define RLIMIT_STACK 3 /* max stack size */
#define RLIMIT_CORE 4  /* max core file size */

#ifndef RLIMIT_RSS
#define RLIMIT_RSS 5 /* max resident set size */
#endif

#ifndef RLIMIT_NPROC
#define RLIMIT_NPROC 6 /* max number of processes */
#endif

#ifndef RLIMIT_NOFILE
#define RLIMIT_NOFILE 7 /* max number of open files */
#endif

#ifndef RLIMIT_MEMLOCK
#define RLIMIT_MEMLOCK 8 /* max locked-in-memory address space */
#endif

#ifndef RLIMIT_AS
#define RLIMIT_AS 9 /* address space limit */
#endif

#define RLIMIT_LOCKS 10      /* maximum file locks held */
#define RLIMIT_SIGPENDING 11 /* max number of pending signals */
#define RLIMIT_MSGQUEUE 12   /* maximum bytes in POSIX mqueues */
#define RLIMIT_NICE 13       /* max nice prio allowed to raise to \
                        0-39 for nice level 19 .. -20 */
#define RLIMIT_RTPRIO 14     /* maximum realtime priority */
#define RLIMIT_RTTIME 15     /* timeout for RT tasks in us */
#define RLIM_NLIMITS 16
#ifndef RLIM_INFINITY
#define RLIM_INFINITY (~0UL)
#endif

// File flags

#define F_DUPFD 0 /* dup */
#define F_GETFD 1 /* get close_on_exec */
#define F_SETFD 2 /* set/clear close_on_exec */
#define F_GETFL 3 /* get file->f_flags */
#define F_SETFL 4 /* set file->f_flags */
#ifndef F_GETLK
#define F_GETLK 5
#define F_SETLK 6
#define F_SETLKW 7
#endif
#ifndef F_SETOWN
#define F_SETOWN 8 /* for sockets. */
#define F_GETOWN 9 /* for sockets. */
#endif
#ifndef F_SETSIG
#define F_SETSIG 10 /* for sockets. */
#define F_GETSIG 11 /* for sockets. */
#endif

#define F_LINUX_SPECIFIC_BASE 1024
#define F_SETLEASE (F_LINUX_SPECIFIC_BASE + 0)
#define F_GETLEASE (F_LINUX_SPECIFIC_BASE + 1)
#define F_CANCELLK (F_LINUX_SPECIFIC_BASE + 5)
#define F_NOTIFY (F_LINUX_SPECIFIC_BASE + 2)
#define F_DUPFD_CLOEXEC (F_LINUX_SPECIFIC_BASE + 6)

#define F_GETLK64 12 /*  using 'struct flock64' */
#define F_SETLK64 13
#define F_SETLKW64 14

// bitsperlong
#define BITS_PER_LONG 64
#define BITS_PER_LONG_LONG 64

#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)

// task flags
#define TASK_COMM_LEN 16

// builtins
#define memset(s, c, n) __builtin_memset(s, c, n)
#define memcpy(t, f, n) __builtin_memcpy(t, f, n)

// device types
#define MAJOR(dev)	((dev)>>8)
#define MINOR(dev)	((dev) & 0xff)
#define MKDEV(ma,mi)	((ma)<<8 | (mi))

static inline u32 new_encode_dev(dev_t dev)
{
	unsigned major = MAJOR(dev);
	unsigned minor = MINOR(dev);
	return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}


#include <bpf/bpf_endian.h>
#define ntohs(x) __bpf_ntohs(x)

#endif // __TARGET_ARCH_X86__

#endif // __SYSDIG_BTF_BUILD__
#endif // __KERNEL_FLAGS_H
