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

#ifndef EVENTS_H_
#define EVENTS_H_

#include "ppm.h"

/*
 * Various crap that a callback might need
 */
struct event_filler_arguments {
	char *buffer;	/* the buffer that will be filled with the data */
	uint32_t buffer_size;	/* the space in the ring buffer available for this event */
	uint32_t syscall_id;	/* the system call ID */
#ifdef PPM_ENABLE_SENTINEL
	uint32_t sentinel;
#endif
	uint32_t nevents;
	uint32_t curarg;
	uint32_t nargs;
	uint32_t arg_data_offset;
	uint32_t arg_data_size;
	enum ppm_event_type event_type;	/* the event type */
	struct pt_regs *regs; /* the registers containing the call arguments */
	struct task_struct *sched_prev; /* for context switch events, the task that is being schduled out */
	struct task_struct *sched_next; /* for context switch events, the task that is being schduled in */
	char *str_storage; /* String storage. Size is one page. */
#ifndef __x86_64__
	unsigned long socketcall_args[6];
#endif
};

/*
 * Filler table-related definitions
 */
#define PPM_AUTOFILL NULL
#define PPM_MAX_AUTOFILL_ARGS 4

/*
 * Return codes
 */
#define PPM_SUCCESS 0
#define PPM_FAILURE_BUFFER_FULL -1
#define PPM_FAILURE_INVALID_USER_MEMORY -2
#define PPM_FAILURE_BUG -3

typedef int32_t (*filler_callback) (struct event_filler_arguments *args);

struct ppm_autofill_arg {
#define AF_ID_RETVAL -1
#define AF_ID_USEDEFAULT -2
	int16_t id;
	long default_val;
};

enum autofill_paramtype {
	APT_REG,
	APT_SOCK,
};

struct ppm_event_entry {
	filler_callback filler_callback;
	uint16_t n_autofill_args;
	enum autofill_paramtype paramtype;
	struct ppm_autofill_arg autofill_args[PPM_MAX_AUTOFILL_ARGS];
};

extern const struct ppm_event_entry g_ppm_events[];
extern const enum ppm_param_type sockopt_optnames_info[];

/*
 * parse_readv_writev_bufs flags
 */
#define PRB_FLAG_PUSH_SIZE	1
#define PRB_FLAG_PUSH_DATA	2
#define PRB_FLAG_PUSH_ALL	(PRB_FLAG_PUSH_SIZE | PRB_FLAG_PUSH_DATA)

/*
 * Functions
 */
int32_t f_sys_autofill(struct event_filler_arguments *args, const struct ppm_event_entry *evinfo);
int32_t val_to_ring(struct event_filler_arguments *args, uint64_t val, uint16_t val_len, bool fromuser);
char *npm_getcwd(char *buf, unsigned long bufsize);
uint16_t pack_addr(struct sockaddr *usrsockaddr, int ulen, char *targetbuf, uint16_t targetbufsize);
uint16_t fd_to_socktuple(int fd, struct sockaddr *usrsockaddr, int ulen, bool use_userdata, bool is_inbound, char *targetbuf, uint16_t targetbufsize);
int addr_to_kernel(void __user *uaddr, int ulen, struct sockaddr *kaddr);
int32_t parse_readv_writev_bufs(struct event_filler_arguments *args, const struct iovec __user *iovsrc, unsigned long iovcnt, int64_t retval, int flags);

static inline uint8_t socket_family_to_scap(uint8_t family)
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
	} else if (family == AF_RDS) {
		return PPM_AF_RDS;
	} else if (family == AF_SNA) {
		return PPM_AF_SNA;
	} else if (family == AF_IRDA) {
		return PPM_AF_IRDA;
	} else if (family == AF_PPPOX) {
		return PPM_AF_PPPOX;
	} else if (family == AF_WANPIPE) {
		return PPM_AF_WANPIPE;
	} else if (family == AF_LLC) {
		return PPM_AF_LLC;
	} else if (family == AF_CAN) {
		return PPM_AF_CAN;
	} else if (family == AF_TIPC) {
		return PPM_AF_TIPC;
	} else if (family == AF_BLUETOOTH) {
		return PPM_AF_BLUETOOTH;
	} else if (family == AF_IUCV) {
		return PPM_AF_IUCV;
	} else if (family == AF_RXRPC) {
		return PPM_AF_RXRPC;
	} else if (family == AF_ISDN) {
		return PPM_AF_ISDN;
	} else if (family == AF_PHONET) {
		return PPM_AF_PHONET;
	} else if (family == AF_IEEE802154) {
		return PPM_AF_IEEE802154;
	}
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

static inline int32_t add_sentinel(struct event_filler_arguments *args)
{
#ifdef PPM_ENABLE_SENTINEL
	if (likely(args->arg_data_size >= sizeof(uint32_t))) {
		*(uint32_t *)(args->buffer + args->arg_data_offset) = args->sentinel;
		args->arg_data_offset += 4;
		args->arg_data_size -= 4;
		return PPM_SUCCESS;
	} else {
		return PPM_FAILURE_BUFFER_FULL;
	}
#else
	return PPM_SUCCESS;
#endif
}

#endif /* EVENTS_H_ */
