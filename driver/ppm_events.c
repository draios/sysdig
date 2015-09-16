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
#include <linux/kobject.h>
#include <linux/cdev.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/file.h>
#include <linux/futex.h>
#include <linux/fs_struct.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/mman.h>
#include <linux/in.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 20)
#include <linux/mount.h>
#include "ppm_syscall.h"
#else
#include <asm/syscall.h>
#endif

#include "ppm_ringbuffer.h"
#include "ppm_events_public.h"
#include "ppm_events.h"
#include "ppm.h"


/*
 * The kernel patched with grsecurity makes the default access_ok trigger a
 * might_sleep(), so if present we use the one defined by them
 */
#ifdef access_ok_noprefault
#define ppm_access_ok access_ok_noprefault
#else
#define ppm_access_ok access_ok
#endif

static void memory_dump(char *p, size_t size)
{
	unsigned int j;

	for (j = 0; j < size; j += 8)
		pr_info("%*ph\n", 8, &p[j]);
}

/*
 * Globals
 */
u32 g_http_options_intval;
u32 g_http_get_intval;
u32 g_http_head_intval;
u32 g_http_post_intval;
u32 g_http_put_intval;
u32 g_http_delete_intval;
u32 g_http_trace_intval;
u32 g_http_connect_intval;
u32 g_http_resp_intval;

/*
 * What this function does is basically a special memcpy
 * so that, if the page fault handler detects the address is invalid,
 * won't kill the process but will return a positive number
 * Plus, this doesn't sleep.
 * The risk is that if the buffer is partially paged out, we get an error.
 * Returns the number of bytes NOT read.
 */
unsigned long ppm_copy_from_user(void *to, const void __user *from, unsigned long n)
{
	unsigned long res = n;

	pagefault_disable();

	if (likely(ppm_access_ok(VERIFY_READ, from, n)))
		res = __copy_from_user_inatomic(to, from, n);

	pagefault_enable();

	return res;
}

/*
 * On some kernels (e.g. 2.6.39), even with preemption disabled, the strncpy_from_user,
 * instead of returning -1 after a page fault, schedules the process, so we drop events
 * because of the preemption. This function reads the user buffer in atomic chunks, and
 * returns when there's an error or the terminator is found
 */
long ppm_strncpy_from_user(char *to, const char __user *from, unsigned long n)
{
	long string_length = 0;
	long res = -1;
	unsigned long bytes_to_read = 4;
	int j;

	pagefault_disable();

	while (n) {
		/*
		 * Read bytes_to_read bytes at a time, and look for the terminator. Should be fast
		 * since the copy_from_user is optimized for the processor
		 */
		if (n < bytes_to_read)
			bytes_to_read = n;

		if (!ppm_access_ok(VERIFY_READ, from, bytes_to_read)) {
			res = -1;
			goto strncpy_end;
		}

		if (__copy_from_user_inatomic(to, from, bytes_to_read)) {
			/*
			 * Page fault
			 */
			res = -1;
			goto strncpy_end;
		}

		n -= bytes_to_read;
		from += bytes_to_read;

		for (j = 0; j < bytes_to_read; ++j) {
			++string_length;

			if (!*to) {
				res = string_length;
				goto strncpy_end;
			}

			++to;
		}
	}

strncpy_end:
	pagefault_enable();
	return res;
}

int32_t dpi_lookahead_init(void)
{
	g_http_options_intval = (*(u32 *)HTTP_OPTIONS_STR);
	g_http_get_intval = (*(u32 *)HTTP_GET_STR);
	g_http_head_intval = (*(u32 *)HTTP_HEAD_STR);
	g_http_post_intval = (*(u32 *)HTTP_POST_STR);
	g_http_put_intval = (*(u32 *)HTTP_PUT_STR);
	g_http_delete_intval = (*(u32 *)HTTP_DELETE_STR);
	g_http_trace_intval = (*(u32 *)HTTP_TRACE_STR);
	g_http_connect_intval = (*(u32 *)HTTP_CONNECT_STR);
	g_http_resp_intval = (*(u32 *)HTTP_RESP_STR);

	return PPM_SUCCESS;
}

inline u32 compute_snaplen(struct event_filler_arguments *args, char *buf, u32 lookahead_size)
{
	u32 res = args->consumer->snaplen;
	int err;
	struct socket *sock;
	sa_family_t family;
	struct sockaddr_storage sock_address;
	struct sockaddr_storage peer_address;
	int sock_address_len;
	int peer_address_len;
	u16 sport, dport;

/*
	if (args->event_type == PPME_SYSCALL_WRITE_X) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
		struct fd f = fdget(args->fd);

		if (f.file && f.file->f_op) {
			if (THIS_MODULE == f.file->f_op->owner) {
				res = RW_SNAPLEN_EVENT;
				fdput(f);
				return res;
			}

			fdput(f);
		}
#else
		struct file* file = fget(args->fd);
		if (file && file->f_op) {
			if (THIS_MODULE == file->f_op->owner) {
				res = RW_SNAPLEN_EVENT;
				fput(file);
				return res;
			}

			fput(file);
		}
#endif
	}
*/

	if (!args->consumer->do_dynamic_snaplen)
		return res;

	sock = sockfd_lookup(args->fd, &err);

	if (sock) {

		if (sock->sk) {
			err = sock->ops->getname(sock, (struct sockaddr *)&sock_address, &sock_address_len, 0);

			if (err == 0) {
				err = sock->ops->getname(sock, (struct sockaddr *)&peer_address, &peer_address_len, 1);

				if (err == 0) {
					family = sock->sk->sk_family;

					if (family == AF_INET) {
						sport = ntohs(((struct sockaddr_in *) &sock_address)->sin_port);
						dport = ntohs(((struct sockaddr_in *) &peer_address)->sin_port);
					} else if (family == AF_INET6) {
						sport = ntohs(((struct sockaddr_in6 *) &sock_address)->sin6_port);
						dport = ntohs(((struct sockaddr_in6 *) &peer_address)->sin6_port);
					} else {
						sport = 0;
						dport = 0;
					}

					if (sport == PPM_PORT_MYSQL || dport == PPM_PORT_MYSQL) {
						if (lookahead_size >= 5) {
							if (buf[0] == 3 || buf[1] == 3 || buf[2] == 3 || buf[3] == 3 || buf[4] == 3) {
								sockfd_put(sock);
								return 2000;
							} else if (buf[2] == 0 && buf[3] == 0) {
								sockfd_put(sock);
								return 2000;
							}
						}
					} else if (sport == PPM_PORT_POSTGRES || dport == PPM_PORT_POSTGRES) {
						if (lookahead_size >= 2) {
							if ((buf[0] == 'Q' && buf[1] == 0) || /* SimpleQuery command */
								(buf[0] == 'P' && buf[1] == 0) || /* Prepare statement commmand */
								 (buf[4] == 0 && buf[5] == 3 && buf[6] == 0) || /* startup command */
								 (buf[0] == 'E' && buf[1] == 0) /* error or execute command */
							) {
								sockfd_put(sock);
								return 2000;
							}
						}
					} else if ((lookahead_size >= 4 && buf[1] == 0 && buf[2] == 0 && buf[2] == 0) || /* matches command */
							   (lookahead_size >= 16 && (*(int32_t *)(buf+12) == 1 || /* matches header */
									   *(int32_t *)(buf+12) == 2001 ||
									   *(int32_t *)(buf+12) == 2002 ||
									   *(int32_t *)(buf+12) == 2003 ||
									   *(int32_t *)(buf+12) == 2004 ||
									   *(int32_t *)(buf+12) == 2005 ||
									   *(int32_t *)(buf+12) == 2006 ||
									   *(int32_t *)(buf+12) == 2007)
							   )
							) {
						sockfd_put(sock);
						return 2000;
					} else if (dport == PPM_PORT_STATSD) {
						sockfd_put(sock);
						return 2000;
					} else {
						if (lookahead_size >= 5) {
							if (*(u32 *)buf == g_http_get_intval ||
								*(u32 *)buf == g_http_post_intval ||
								*(u32 *)buf == g_http_put_intval ||
								*(u32 *)buf == g_http_delete_intval ||
								*(u32 *)buf == g_http_trace_intval ||
								*(u32 *)buf == g_http_connect_intval ||
								*(u32 *)buf == g_http_options_intval ||
								((*(u32 *)buf == g_http_resp_intval) && (buf[4] == '/'))
							) {
								sockfd_put(sock);
								return 2000;
							}
						}
					}
				}
			}
		}

		sockfd_put(sock);
	}

	return res;
}

/*
 * NOTES:
 * - val_len is ignored for everything other than PT_BYTEBUF.
 * - fromuser is ignored for numeric types
 * - dyn_idx is ignored for everything other than PT_DYN
 */
int val_to_ring(struct event_filler_arguments *args, uint64_t val, u16 val_len, bool fromuser, u8 dyn_idx)
{
	const struct ppm_param_info *param_info;
	int len = -1;
	u16 *psize = (u16 *)(args->buffer + args->curarg * sizeof(u16));

	if (unlikely(args->curarg >= args->nargs)) {
		pr_err("(%u)val_to_ring: too many arguments for event #%u, type=%u, curarg=%u, nargs=%u tid:%u\n",
		       smp_processor_id(),
		       args->nevents,
		       (u32)args->event_type,
		       args->curarg,
		       args->nargs,
		       current->pid);
		memory_dump(args->buffer - sizeof(struct ppm_evt_hdr), 32);
		ASSERT(0);
		return PPM_FAILURE_BUG;
	}

	if (unlikely(args->arg_data_size == 0))
		return PPM_FAILURE_BUFFER_FULL;

	param_info = &(g_event_info[args->event_type].params[args->curarg]);
	if (param_info->type == PT_DYN && param_info->info != NULL) {
		const struct ppm_param_info *dyn_params;

		if (unlikely(dyn_idx >= param_info->ninfo)) {
			ASSERT(0);
			return PPM_FAILURE_BUG;
		}

		dyn_params = (const struct ppm_param_info *)param_info->info;

		param_info = &dyn_params[dyn_idx];
		if (likely(args->arg_data_size >= sizeof(u8)))	{
			*(u8 *)(args->buffer + args->arg_data_offset) = dyn_idx;
			len = sizeof(u8);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}
		args->arg_data_offset += len;
		args->arg_data_size -= len;
		*psize = (u16)len;
	} else {
		*psize = 0;
	}

	switch (param_info->type) {
	case PT_CHARBUF:
	case PT_FSPATH:
		if (likely(val != 0)) {
			if (fromuser) {
				len = ppm_strncpy_from_user(args->buffer + args->arg_data_offset,
					(const char __user *)(unsigned long)val, args->arg_data_size);

				if (unlikely(len < 0))
					return PPM_FAILURE_INVALID_USER_MEMORY;
			} else {
				len = strlcpy(args->buffer + args->arg_data_offset,
								(const char *)(unsigned long)val,
								args->arg_data_size);

				if (++len > args->arg_data_size)
					len = args->arg_data_size;
			}

			/*
			 * Make sure the string is null-terminated
			 */
			*(char *)(args->buffer + args->arg_data_offset + len) = 0;
		} else {
			/*
			 * Handle NULL pointers
			 */
			len = strlcpy(args->buffer + args->arg_data_offset,
			       "(NULL)",
			       args->arg_data_size);

			if (++len > args->arg_data_size)
				len = args->arg_data_size;
		}

		break;
	case PT_BYTEBUF:
		if (likely(val != 0)) {
			if (fromuser) {
				/*
				 * Copy the lookahead portion of the buffer that we will use DPI-based
				 * snaplen calculation
				 */
				u32 dpi_lookahead_size = DPI_LOOKAHED_SIZE;

				if (dpi_lookahead_size > val_len)
					dpi_lookahead_size = val_len;

				if (unlikely(dpi_lookahead_size >= args->arg_data_size))
					return PPM_FAILURE_BUFFER_FULL;

				len = (int)ppm_copy_from_user(args->buffer + args->arg_data_offset,
						(const void __user *)(unsigned long)val,
						dpi_lookahead_size);

				if (unlikely(len != 0))
					return PPM_FAILURE_INVALID_USER_MEMORY;

				/*
				 * Check if there's more to copy
				 */
				if (likely((dpi_lookahead_size != val_len))) {
					/*
					 * Calculate the snaplen
					 */
					if (likely(args->enforce_snaplen)) {
						u32 sl = args->consumer->snaplen;

						sl = compute_snaplen(args, args->buffer + args->arg_data_offset, dpi_lookahead_size);

						if (val_len > sl)
							val_len = sl;
					}

					if (unlikely((val_len) >= args->arg_data_size))
						val_len = args->arg_data_size;

					if (val_len > dpi_lookahead_size) {
						len = (int)ppm_copy_from_user(args->buffer + args->arg_data_offset + dpi_lookahead_size,
								(const void __user *)(unsigned long)val + dpi_lookahead_size,
								val_len - dpi_lookahead_size);

						if (unlikely(len != 0))
							return PPM_FAILURE_INVALID_USER_MEMORY;
					}
				}

				len = val_len;
			} else {
				if (likely(args->enforce_snaplen)) {
					u32 sl = compute_snaplen(args, (char *)(unsigned long)val, val_len);

					if (val_len > sl)
						val_len = sl;
				}

				if (unlikely(val_len >= args->arg_data_size))
					return PPM_FAILURE_BUFFER_FULL;

				memcpy(args->buffer + args->arg_data_offset,
					(void *)(unsigned long)val, val_len);

				len = val_len;
			}
		} else {
			/*
			 * Handle NULL pointers
			 */
			len = 0;
		}

		break;
	case PT_SOCKADDR:
	case PT_SOCKTUPLE:
	case PT_FDLIST:
		if (likely(val != 0)) {
			if (unlikely(val_len >= args->arg_data_size))
				return PPM_FAILURE_BUFFER_FULL;

			if (fromuser) {
				len = (int)ppm_copy_from_user(args->buffer + args->arg_data_offset,
						(const void __user *)(unsigned long)val,
						val_len);

				if (unlikely(len != 0))
					return PPM_FAILURE_INVALID_USER_MEMORY;

				len = val_len;
			} else {
				memcpy(args->buffer + args->arg_data_offset,
					(void *)(unsigned long)val, val_len);

				len = val_len;
			}
		} else {
			/*
			 * Handle NULL pointers
			 */
			len = 0;
		}

		break;
	case PT_FLAGS8:
	case PT_UINT8:
	case PT_SIGTYPE:
		if (likely(args->arg_data_size >= sizeof(u8)))	{
			*(u8 *)(args->buffer + args->arg_data_offset) = (u8)val;
			len = sizeof(u8);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_FLAGS16:
	case PT_UINT16:
	case PT_SYSCALLID:
		if (likely(args->arg_data_size >= sizeof(u16))) {
			*(u16 *)(args->buffer + args->arg_data_offset) = (u16)val;
			len = sizeof(u16);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_FLAGS32:
	case PT_UINT32:
	case PT_UID:
	case PT_GID:
	case PT_SIGSET:
		if (likely(args->arg_data_size >= sizeof(u32))) {
			*(u32 *)(args->buffer + args->arg_data_offset) = (u32)val;
			len = sizeof(u32);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_RELTIME:
	case PT_ABSTIME:
	case PT_UINT64:
		if (likely(args->arg_data_size >= sizeof(u64))) {
			*(u64 *)(args->buffer + args->arg_data_offset) = (u64)val;
			len = sizeof(u64);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_INT8:
		if (likely(args->arg_data_size >= sizeof(s8))) {
			*(s8 *)(args->buffer + args->arg_data_offset) = (s8)(long)val;
			len = sizeof(s8);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_INT16:
		if (likely(args->arg_data_size >= sizeof(s16))) {
			*(s16 *)(args->buffer + args->arg_data_offset) = (s16)(long)val;
			len = sizeof(s16);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_INT32:
		if (likely(args->arg_data_size >= sizeof(s32))) {
			*(s32 *)(args->buffer + args->arg_data_offset) = (s32)(long)val;
			len = sizeof(s32);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_INT64:
	case PT_ERRNO:
	case PT_FD:
	case PT_PID:
		if (likely(args->arg_data_size >= sizeof(s64))) {
			*(s64 *)(args->buffer + args->arg_data_offset) = (s64)(long)val;
			len = sizeof(s64);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	default:
		ASSERT(0);
		pr_err("val_to_ring: invalid argument type %d. Event %u (%s) might have less parameters than what has been declared in nparams\n",
		       (int)g_event_info[args->event_type].params[args->curarg].type,
		       (u32)args->event_type,
		       g_event_info[args->event_type].name);
		return PPM_FAILURE_BUG;
	}

	ASSERT(len <= 65535);
	ASSERT(len <= args->arg_data_size);

	*psize += (u16)len;
	args->curarg++;
	args->arg_data_offset += len;
	args->arg_data_size -= len;

	return PPM_SUCCESS;
}

/*
 * Get the current working directory for the current process.
 * Returns the pointer to the string, which is NOT going to be at the beginning
 * of buf.
 * Buf must be at least 1 page in size.
 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
char *npm_getcwd(char *buf, unsigned long bufsize)
{
	struct path pwd;
	char *res;

	ASSERT(bufsize >= PAGE_SIZE - 1);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36) || defined CONFIG_VE
	get_fs_pwd(current->fs, &pwd);
#else
	read_lock(&current->fs->lock);
	pwd = current->fs->pwd;
	path_get(&pwd);
	read_unlock(&current->fs->lock);
#endif

	res = d_path(&pwd, buf, bufsize);

	if (IS_ERR(res))
		res = NULL;

	path_put(&pwd);

	return res;
}
#else /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20) */
char *npm_getcwd(char *buf, unsigned long bufsize)
{
	struct dentry *dentry;
	struct vfsmount *mnt;
	char *res;

	ASSERT(bufsize >= PAGE_SIZE - 1);

	read_lock(&current->fs->lock);
	mnt = mntget(current->fs->pwdmnt);
	dentry = dget(current->fs->pwd);
	read_unlock(&current->fs->lock);

	res = d_path(dentry, mnt, buf, bufsize);

	if (IS_ERR(res))
		res = NULL;

	return res;
}
#endif

static inline u8 socket_family_to_scap(u8 family)
{
	if (family == AF_INET) {
		return PPM_AF_INET;
	} else if (family == AF_INET6) {
		return PPM_AF_INET6;
	} else if (family == AF_UNIX) {
		return PPM_AF_UNIX;
	} else if (family == AF_NETLINK) {
		return PPM_AF_NETLINK;
	} else if (family == AF_PACKET) {
		return PPM_AF_PACKET;
	} else if (family == AF_UNSPEC) {
		return PPM_AF_UNSPEC;
	} else if (family == AF_AX25) {
		return PPM_AF_AX25;
	} else if (family == AF_IPX) {
		return PPM_AF_IPX;
	} else if (family == AF_APPLETALK) {
		return PPM_AF_APPLETALK;
	} else if (family == AF_NETROM) {
		return PPM_AF_NETROM;
	} else if (family == AF_BRIDGE) {
		return PPM_AF_BRIDGE;
	} else if (family == AF_ATMPVC) {
		return PPM_AF_ATMPVC;
	} else if (family == AF_X25) {
		return PPM_AF_X25;
	} else if (family == AF_ROSE) {
		return PPM_AF_ROSE;
	} else if (family == AF_DECnet) {
		return PPM_AF_DECnet;
	} else if (family == AF_NETBEUI) {
		return PPM_AF_NETBEUI;
	} else if (family == AF_SECURITY) {
		return PPM_AF_SECURITY;
	} else if (family == AF_KEY) {
		return PPM_AF_KEY;
	} else if (family == AF_ROUTE) {
		return PPM_AF_ROUTE;
	} else if (family == AF_ASH) {
		return PPM_AF_ASH;
	} else if (family == AF_ECONET) {
		return PPM_AF_ECONET;
	} else if (family == AF_ATMSVC) {
		return PPM_AF_ATMSVC;
	}
#ifdef AF_RDS
	else if (family == AF_RDS) {
		return PPM_AF_RDS;
	}
#endif
	else if (family == AF_SNA) {
		return PPM_AF_SNA;
	} else if (family == AF_IRDA) {
		return PPM_AF_IRDA;
	} else if (family == AF_PPPOX) {
		return PPM_AF_PPPOX;
	} else if (family == AF_WANPIPE) {
		return PPM_AF_WANPIPE;
	} else if (family == AF_LLC) {
		return PPM_AF_LLC;
	}
#ifdef AF_CAN
	else if (family == AF_CAN) {
		return PPM_AF_CAN;
	}
#endif
	 else if (family == AF_TIPC) {
		return PPM_AF_TIPC;
	} else if (family == AF_BLUETOOTH) {
		return PPM_AF_BLUETOOTH;
	} else if (family == AF_IUCV) {
		return PPM_AF_IUCV;
	}
#ifdef AF_RXRPC
	else if (family == AF_RXRPC) {
		return PPM_AF_RXRPC;
	}
#endif
#ifdef AF_ISDN
	else if (family == AF_ISDN) {
		return PPM_AF_ISDN;
	}
#endif
#ifdef AF_PHONET
	else if (family == AF_PHONET) {
		return PPM_AF_PHONET;
	}
#endif
#ifdef AF_IEEE802154
	else if (family == AF_IEEE802154) {
		return PPM_AF_IEEE802154;
	}
#endif
#ifdef AF_CAIF
	else if (family == AF_CAIF) {
		return PPM_AF_CAIF;
	}
#endif
#ifdef AF_ALG
	else if (family == AF_ALG) {
		return PPM_AF_ALG;
	}
#endif
#ifdef AF_NFC
	else if (family == AF_NFC) {
		return PPM_AF_NFC;
	}
#endif
	else {
		ASSERT(false);
		return PPM_AF_UNSPEC;
	}
}

/*
static struct socket *ppm_sockfd_lookup_light(int fd, int *err, int *fput_needed)
{
	struct file *file;
	struct socket *sock;

	*err = -EBADF;
	file = fget_light(fd, fput_needed);
	if (file) {
		sock = sock_from_file(file, err);
		if (sock)
			return sock;
		fput_light(file, *fput_needed);
	}
	return NULL;
}
*/

/*
 * Convert a sockaddr into our address representation and copy it to
 * targetbuf
 */
u16 pack_addr(struct sockaddr *usrsockaddr,
	int ulen,
	char *targetbuf,
	u16 targetbufsize)
{
	u32 ip;
	u16 port;
	sa_family_t family = usrsockaddr->sa_family;
	struct sockaddr_in *usrsockaddr_in;
	struct sockaddr_in6 *usrsockaddr_in6;
	struct sockaddr_un *usrsockaddr_un;
	u16 size;
	char *dest;

	switch (family) {
	case AF_INET:
		/*
		 * Map the user-provided address to a sockaddr_in
		 */
		usrsockaddr_in = (struct sockaddr_in *)usrsockaddr;

		/*
		 * Retrieve the src address
		 */
		ip = usrsockaddr_in->sin_addr.s_addr;
		port = ntohs(usrsockaddr_in->sin_port);

		/*
		 * Pack the tuple info in the temporary buffer
		 */
		size = 1 + 4 + 2; /* family + ip + port */

		*targetbuf = socket_family_to_scap(family);
		*(u32 *)(targetbuf + 1) = ip;
		*(u16 *)(targetbuf + 5) = port;

		break;
	case AF_INET6:
		/*
		 * Map the user-provided address to a sockaddr_in
		 */
		usrsockaddr_in6 = (struct sockaddr_in6 *)usrsockaddr;

		/*
		 * Retrieve the src address
		 */
		port = ntohs(usrsockaddr_in6->sin6_port);

		/*
		 * Pack the tuple info in the temporary buffer
		 */
		size = 1 + 16 + 2; /* family + ip + port */

		*targetbuf = socket_family_to_scap(family);
		memcpy(targetbuf + 1,
			usrsockaddr_in6->sin6_addr.s6_addr,
			16);
		*(u16 *)(targetbuf + 17) = port;

		break;
	case AF_UNIX:
		/*
		 * Map the user-provided address to a sockaddr_in
		 */
		usrsockaddr_un = (struct sockaddr_un *)usrsockaddr;

		/*
		 * Put a 0 at the end of struct sockaddr_un because
		 * the user might not have considered it in the length
		 */
		if (ulen == sizeof(struct sockaddr_storage))
			*(((char *)usrsockaddr_un) + ulen - 1) = 0;
		else
			*(((char *)usrsockaddr_un) + ulen) = 0;

		/*
		 * Pack the data into the target buffer
		 */
		size = 1;

		*targetbuf = socket_family_to_scap(family);
		dest = strncpy(targetbuf + 1,
					usrsockaddr_un->sun_path,
					UNIX_PATH_MAX);	/* we assume this will be smaller than (targetbufsize - (1 + 8 + 8)) */

		dest[UNIX_PATH_MAX - 1] = 0;
		size += strlen(dest) + 1;

		break;
	default:
		size = 0;
		break;
	}

	return size;
}

/*
 * Convert a connection tuple into our tuple representation and copy it to
 * targetbuf
 */
u16 fd_to_socktuple(int fd,
	struct sockaddr *usrsockaddr,
	int ulen,
	bool use_userdata,
	bool is_inbound,
	char *targetbuf,
	u16 targetbufsize)
{
	struct socket *sock;
	int err = 0;
	sa_family_t family;
	struct unix_sock *us;
	char *us_name;
	struct sock *speer;
	u32 sip;
	u32 dip;
	u8 *sip6;
	u8 *dip6;
	u16 sport;
	u16 dport;
	struct sockaddr_in *usrsockaddr_in;
	struct sockaddr_in6 *usrsockaddr_in6;
	struct sockaddr_un *usrsockaddr_un;
	u16 size;
	char *dest;
	struct sockaddr_storage sock_address;
	struct sockaddr_storage peer_address;
	int sock_address_len;
	int peer_address_len;

	/*
	 * Get the socket from the fd
	 * NOTE: sockfd_lookup() locks the socket, so we don't need to worry when we dig in it
	 */
	sock = sockfd_lookup(fd, &err);

	if (unlikely(!sock || !(sock->sk))) {
		/*
		 * This usually happens if the call failed without being able to establish a connection,
		 * i.e. if it didn't return something like SE_EINPROGRESS.
		 */
		if (sock)
			sockfd_put(sock);
		return 0;
	}

	err = sock->ops->getname(sock, (struct sockaddr *)&sock_address, &sock_address_len, 0);
	ASSERT(err == 0);

	family = sock->sk->sk_family;

	/*
	 * Extract and pack the info, based on the family
	 */
	switch (family) {
	case AF_INET:
		if (!use_userdata) {
			err = sock->ops->getname(sock, (struct sockaddr *)&peer_address, &peer_address_len, 1);
			if (err == 0) {
				if (is_inbound) {
					sip = ((struct sockaddr_in *) &peer_address)->sin_addr.s_addr;
					sport = ntohs(((struct sockaddr_in *) &peer_address)->sin_port);
					dip = ((struct sockaddr_in *) &sock_address)->sin_addr.s_addr;
					dport = ntohs(((struct sockaddr_in *) &sock_address)->sin_port);
				} else {
					sip = ((struct sockaddr_in *) &sock_address)->sin_addr.s_addr;
					sport = ntohs(((struct sockaddr_in *) &sock_address)->sin_port);
					dip = ((struct sockaddr_in *) &peer_address)->sin_addr.s_addr;
					dport = ntohs(((struct sockaddr_in *) &peer_address)->sin_port);
				}
			} else {
				sip = 0;
				sport = 0;
				dip = 0;
				dport = 0;
			}
		} else {
			/*
			 * Map the user-provided address to a sockaddr_in
			 */
			usrsockaddr_in = (struct sockaddr_in *)usrsockaddr;

			if (is_inbound) {
				sip = usrsockaddr_in->sin_addr.s_addr;
				sport = ntohs(usrsockaddr_in->sin_port);
				dip = ((struct sockaddr_in *) &sock_address)->sin_addr.s_addr;
				dport = ntohs(((struct sockaddr_in *) &sock_address)->sin_port);
			} else {
				sip = ((struct sockaddr_in *) &sock_address)->sin_addr.s_addr;
				sport = ntohs(((struct sockaddr_in *) &sock_address)->sin_port);
				dip = usrsockaddr_in->sin_addr.s_addr;
				dport = ntohs(usrsockaddr_in->sin_port);
			}
		}

		/*
		 * Pack the tuple info in the temporary buffer
		 */
		size = 1 + 4 + 4 + 2 + 2; /* family + sip + dip + sport + dport */

		*targetbuf = socket_family_to_scap(family);
		*(u32 *)(targetbuf + 1) = sip;
		*(u16 *)(targetbuf + 5) = sport;
		*(u32 *)(targetbuf + 7) = dip;
		*(u16 *)(targetbuf + 11) = dport;

		break;
	case AF_INET6:
		if (!use_userdata) {
			err = sock->ops->getname(sock, (struct sockaddr *)&peer_address, &peer_address_len, 1);
			ASSERT(err == 0);

			if (is_inbound) {
				sip6 = ((struct sockaddr_in6 *) &peer_address)->sin6_addr.s6_addr;
				sport = ntohs(((struct sockaddr_in6 *) &peer_address)->sin6_port);
				dip6 = ((struct sockaddr_in6 *) &sock_address)->sin6_addr.s6_addr;
				dport = ntohs(((struct sockaddr_in6 *) &sock_address)->sin6_port);
			} else {
				sip6 = ((struct sockaddr_in6 *) &sock_address)->sin6_addr.s6_addr;
				sport = ntohs(((struct sockaddr_in6 *) &sock_address)->sin6_port);
				dip6 = ((struct sockaddr_in6 *) &peer_address)->sin6_addr.s6_addr;
				dport = ntohs(((struct sockaddr_in6 *) &peer_address)->sin6_port);
			}
		} else {
			/*
			 * Map the user-provided address to a sockaddr_in6
			 */
			usrsockaddr_in6 = (struct sockaddr_in6 *)usrsockaddr;

			if (is_inbound) {
				sip6 = usrsockaddr_in6->sin6_addr.s6_addr;
				sport = ntohs(usrsockaddr_in6->sin6_port);
				dip6 = ((struct sockaddr_in6 *) &sock_address)->sin6_addr.s6_addr;
				dport = ntohs(((struct sockaddr_in6 *) &sock_address)->sin6_port);
			} else {
				sip6 = ((struct sockaddr_in6 *) &sock_address)->sin6_addr.s6_addr;
				sport = ntohs(((struct sockaddr_in6 *) &sock_address)->sin6_port);
				dip6 = usrsockaddr_in6->sin6_addr.s6_addr;
				dport = ntohs(usrsockaddr_in6->sin6_port);
			}
		}

		/*
		 * Pack the tuple info in the temporary buffer
		 */
		size = 1 + 16 + 16 + 2 + 2; /* family + sip + dip + sport + dport */

		*targetbuf = socket_family_to_scap(family);
		memcpy(targetbuf + 1,
			sip6,
			16);
		*(u16 *)(targetbuf + 17) = sport;
		memcpy(targetbuf + 19,
			dip6,
			16);
		*(u16 *)(targetbuf + 35) = dport;

		break;
	case AF_UNIX:
		/*
		 * Retrieve the addresses
		 */
		us = unix_sk(sock->sk);
		speer = us->peer;

		*targetbuf = socket_family_to_scap(family);

		if (is_inbound) {
			*(uint64_t *)(targetbuf + 1) = (uint64_t)(unsigned long)us;
			*(uint64_t *)(targetbuf + 1 + 8) = (uint64_t)(unsigned long)speer;
		} else {
			*(uint64_t *)(targetbuf + 1) = (uint64_t)(unsigned long)speer;
			*(uint64_t *)(targetbuf + 1 + 8) = (uint64_t)(unsigned long)us;
		}

		/*
		 * Pack the data into the target buffer
		 */
		size = 1 + 8 + 8;

		if (!use_userdata) {
			if (is_inbound) {
				us_name = ((struct sockaddr_un *) &sock_address)->sun_path;
			} else {
				err = sock->ops->getname(sock, (struct sockaddr *)&peer_address, &peer_address_len, 1);
				ASSERT(err == 0);

				us_name = ((struct sockaddr_un *) &peer_address)->sun_path;
			}
		} else {
			/*
			 * Map the user-provided address to a sockaddr_in
			 */
			usrsockaddr_un = (struct sockaddr_un *)usrsockaddr;

			/*
			 * Put a 0 at the end of struct sockaddr_un because
			 * the user might not have considered it in the length
			 */
			if (ulen == sizeof(struct sockaddr_storage))
				*(((char *)usrsockaddr_un) + ulen - 1) = 0;
			else
				*(((char *)usrsockaddr_un) + ulen) = 0;

			if (is_inbound)
				us_name = ((struct sockaddr_un *) &sock_address)->sun_path;
			else
				us_name = usrsockaddr_un->sun_path;
		}

		ASSERT(us_name);
		dest = strncpy(targetbuf + 1 + 8 + 8,
					(char *)us_name,
					UNIX_PATH_MAX);	/* we assume this will be smaller than (targetbufsize - (1 + 8 + 8)) */

		dest[UNIX_PATH_MAX - 1] = 0;
		size += strlen(dest) + 1;
		break;
	default:
		size = 0;
		break;
	}

	/*
	 * Digging finished. We can release the fd.
	 */
	sockfd_put(sock);

	return size;
}

int addr_to_kernel(void __user *uaddr, int ulen, struct sockaddr *kaddr)
{
	if (unlikely(ulen < 0 || ulen > sizeof(struct sockaddr_storage)))
		return -EINVAL;

	if (unlikely(ulen == 0))
		return 0;

	if (unlikely(ppm_copy_from_user(kaddr, uaddr, ulen)))
		return -EFAULT;

	return 0;
}

/*
 * Parses the list of buffers of a xreadv or xwritev call, and pushes the size
 * (and optionally the data) to the ring.
 */
int32_t parse_readv_writev_bufs(struct event_filler_arguments *args, const struct iovec __user *iovsrc, unsigned long iovcnt, int64_t retval, int flags)
{
	int32_t res;
	const struct iovec *iov;
	u32 copylen;
	u32 j;
	u64 size = 0;
	unsigned long bufsize;
	char *targetbuf = args->str_storage;
	u32 targetbuflen = STR_STORAGE_SIZE;
	unsigned long val;
	u32 notcopied_len;
	size_t tocopy_len;

	copylen = iovcnt * sizeof(struct iovec);

	if (unlikely(copylen >= STR_STORAGE_SIZE))
		return PPM_FAILURE_BUFFER_FULL;

	if (unlikely(ppm_copy_from_user(args->str_storage, iovsrc, copylen)))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	iov = (const struct iovec *)(args->str_storage);

	targetbuf += copylen;
	targetbuflen -= copylen;

	/*
	 * Size
	 */
	if (flags & PRB_FLAG_PUSH_SIZE) {
		for (j = 0; j < iovcnt; j++)
			size += iov[j].iov_len;

		/*
		 * Size is the total size of the buffers provided by the user. The number of
		 * received bytes can be smaller
		 */
		if ((flags & PRB_FLAG_IS_WRITE) == 0)
			if (size > retval)
				size = retval;

		res = val_to_ring(args, size, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	/*
	 * data
	 */
	if (flags & PRB_FLAG_PUSH_DATA) {
		if (retval > 0 && iovcnt > 0) {
			/*
			 * Retrieve the FD. It will be used for dynamic snaplen calculation.
			 */
			syscall_get_arguments(current, args->regs, 0, 1, &val);
			args->fd = (int)val;

			/*
			 * Merge the buffers
			 */
			bufsize = 0;

			for (j = 0; j < iovcnt; j++) {
				if ((flags & PRB_FLAG_IS_WRITE) == 0) {
					if (bufsize >= retval) {
						ASSERT(bufsize >= retval);

						/*
						 * Copied all the data even if we haven't reached the
						 * end of the buffer.
						 * Copy must stop here.
						 */
						break;
					}

					tocopy_len = min(iov[j].iov_len, (size_t)retval - bufsize);
					tocopy_len = min(tocopy_len, (size_t)targetbuflen - bufsize - 1);
				} else {
					tocopy_len = min(iov[j].iov_len, targetbuflen - bufsize - 1);
				}

				notcopied_len = (int)ppm_copy_from_user(targetbuf + bufsize,
						iov[j].iov_base,
						tocopy_len);

				if (unlikely(notcopied_len != 0)) {
					/*
					 * This means we had a page fault. Skip this event.
					 */
					return PPM_FAILURE_INVALID_USER_MEMORY;
				}

				bufsize += tocopy_len;

				if (tocopy_len != iov[j].iov_len) {
					/*
					 * No space left in the args->str_storage buffer.
					 * Copy must stop here.
					 */
					break;
				}
			}

			args->enforce_snaplen = true;

			res = val_to_ring(args,
				(unsigned long)targetbuf,
				bufsize,
				false,
				0);
			if (unlikely(res != PPM_SUCCESS))
				return res;
		} else {
			res = val_to_ring(args, 0, 0, false, 0);
			if (unlikely(res != PPM_SUCCESS))
				return res;
		}
	}

	return PPM_SUCCESS;
}

#ifdef CONFIG_COMPAT
/*
 * Parses the list of buffers of a xreadv or xwritev call, and pushes the size
 * (and optionally the data) to the ring.
 */
int32_t compat_parse_readv_writev_bufs(struct event_filler_arguments *args, const struct compat_iovec __user *iovsrc, unsigned long iovcnt, int64_t retval, int flags)
{
	int32_t res;
	const struct compat_iovec *iov;
	u32 copylen;
	u32 j;
	u64 size = 0;
	unsigned long bufsize;
	char *targetbuf = args->str_storage;
	u32 targetbuflen = STR_STORAGE_SIZE;
	unsigned long val;
	u32 notcopied_len;
	compat_size_t tocopy_len;

	copylen = iovcnt * sizeof(struct compat_iovec);

	if (unlikely(copylen >= STR_STORAGE_SIZE))
		return PPM_FAILURE_BUFFER_FULL;

	if (unlikely(ppm_copy_from_user(args->str_storage, iovsrc, copylen)))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	iov = (const struct compat_iovec *)(args->str_storage);

	targetbuf += copylen;
	targetbuflen -= copylen;

	/*
	 * Size
	 */
	if (flags & PRB_FLAG_PUSH_SIZE) {
		for (j = 0; j < iovcnt; j++)
			size += iov[j].iov_len;

		/*
		 * Size is the total size of the buffers provided by the user. The number of
		 * received bytes can be smaller
		 */
		if ((flags & PRB_FLAG_IS_WRITE) == 0)
			if (size > retval)
				size = retval;

		res = val_to_ring(args, size, 0, false, 0);
		if (unlikely(res != PPM_SUCCESS))
			return res;
	}

	/*
	 * data
	 */
	if (flags & PRB_FLAG_PUSH_DATA) {
		if (retval > 0 && iovcnt > 0) {
			/*
			 * Retrieve the FD. It will be used for dynamic snaplen calculation.
			 */
			syscall_get_arguments(current, args->regs, 0, 1, &val);
			args->fd = (int)val;

			/*
			 * Merge the buffers
			 */
			bufsize = 0;

			for (j = 0; j < iovcnt; j++) {
				if ((flags & PRB_FLAG_IS_WRITE) == 0) {
					if (bufsize >= retval) {
						ASSERT(bufsize >= retval);

						/*
						 * Copied all the data even if we haven't reached the
						 * end of the buffer.
						 * Copy must stop here.
						 */
						break;
					}

					tocopy_len = min(iov[j].iov_len, (compat_size_t)((size_t)retval - bufsize));
					tocopy_len = min(tocopy_len, (compat_size_t)(targetbuflen - bufsize - 1));
				} else {
					tocopy_len = min(iov[j].iov_len, (compat_size_t)(targetbuflen - bufsize - 1));
				}

				notcopied_len = (int)ppm_copy_from_user(targetbuf + bufsize,
									compat_ptr(iov[j].iov_base),
						tocopy_len);

				if (unlikely(notcopied_len != 0)) {
					/*
					 * This means we had a page fault. Skip this event.
					 */
					return PPM_FAILURE_INVALID_USER_MEMORY;
				}

				bufsize += tocopy_len;

				if (tocopy_len != iov[j].iov_len) {
					/*
					 * No space left in the args->str_storage buffer.
					 * Copy must stop here.
					 */
					break;
				}
			}

			args->enforce_snaplen = true;

			res = val_to_ring(args,
				(unsigned long)targetbuf,
				bufsize,
				false,
				0);
			if (unlikely(res != PPM_SUCCESS))
				return res;
		} else {
			res = val_to_ring(args, 0, 0, false, 0);
			if (unlikely(res != PPM_SUCCESS))
				return res;
		}
	}

	return PPM_SUCCESS;
}
#endif /* CONFIG_COMPAT */

/*
 * STANDARD FILLERS
 */

/*
 * AUTOFILLER
 * In simple cases in which extracting an event is just a matter of moving the
 * arguments to the buffer, this filler can be used instead of writing a
 * filler function.
 * The arguments to extract are be specified in g_ppm_events.
 */
int f_sys_autofill(struct event_filler_arguments *args, const struct ppm_event_entry *evinfo)
{
	int res;
	unsigned long val;
	u32 j;
	int64_t retval;

	ASSERT(evinfo->n_autofill_args <= PPM_MAX_AUTOFILL_ARGS);

	for (j = 0; j < evinfo->n_autofill_args; j++) {
		if (evinfo->autofill_args[j].id >= 0) {
#ifdef _HAS_SOCKETCALL
			if (args->is_socketcall && evinfo->paramtype == APT_SOCK) {
				val = args->socketcall_args[evinfo->autofill_args[j].id];
			} else
#endif
			{
				/*
				 * Regular argument
				 */
				syscall_get_arguments(current,
						args->regs,
						evinfo->autofill_args[j].id,
						1,
						&val);
			}

			res = val_to_ring(args, val, 0, true, 0);
			if (unlikely(res != PPM_SUCCESS))
				return res;
		} else if (evinfo->autofill_args[j].id == AF_ID_RETVAL) {
			/*
			 * Return value
			 */
			retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
			res = val_to_ring(args, retval, 0, false, 0);
			if (unlikely(res != PPM_SUCCESS))
				return res;
		} else if (evinfo->autofill_args[j].id == AF_ID_USEDEFAULT) {
			/*
			 * Default Value
			 */
			res = val_to_ring(args, evinfo->autofill_args[j].default_val, 0, false, 0);
			if (unlikely(res != PPM_SUCCESS))
				return res;
		} else {
			ASSERT(false);
		}
	}

	return add_sentinel(args);
}
