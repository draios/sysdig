#ifndef __FILLERS_H
#define __FILLERS_H

#include "../ppm_flag_helpers.h"

#include <linux/tty.h>

#define FILLER_RAW(x)							\
static __always_inline int __bpf_##x(struct filler_data *data);		\
									\
__bpf_section(TP_NAME "filler/" #x)					\
static __always_inline int bpf_##x(void *ctx)				\

#define FILLER(x, is_syscall)						\
static __always_inline int __bpf_##x(struct filler_data *data);		\
									\
__bpf_section(TP_NAME "filler/" #x)					\
static __always_inline int bpf_##x(void *ctx)				\
{									\
	struct filler_data data;					\
	int res;							\
									\
	res = init_filler_data(ctx, &data, is_syscall);			\
	if (res == PPM_SUCCESS) {					\
		if (!data.state->tail_ctx.len)				\
			write_evt_hdr(&data);				\
		res = __bpf_##x(&data);					\
	}								\
									\
	if (res == PPM_SUCCESS)						\
		res = push_evt_frame(ctx, &data);			\
									\
	if (data.state)							\
		data.state->tail_ctx.prev_res = res;			\
									\
	bpf_tail_call(ctx, &tail_map, PPM_FILLER_terminate_filler);	\
	bpf_printk("Can't tail call terminate filler\n");		\
	return 0;							\
}									\
									\
static __always_inline int __bpf_##x(struct filler_data *data)		\

FILLER_RAW(terminate_filler)
{
	struct sysdig_bpf_per_cpu_state *state;

	state = get_local_state(bpf_get_smp_processor_id());
	if (!state)
		return 0;

	switch (state->tail_ctx.prev_res) {
	case PPM_SUCCESS:
		break;
	case PPM_FAILURE_BUFFER_FULL:
		bpf_printk("PPM_FAILURE_BUFFER_FULL event=%d curarg=%d\n",
			   state->tail_ctx.evt_type,
			   state->tail_ctx.curarg);
		++state->n_drops_buffer;
		break;
	case PPM_FAILURE_INVALID_USER_MEMORY:
		bpf_printk("PPM_FAILURE_INVALID_USER_MEMORY event=%d curarg=%d\n",
			   state->tail_ctx.evt_type,
			   state->tail_ctx.curarg);
		++state->n_drops_pf;
		break;
	case PPM_FAILURE_BUG:
		bpf_printk("PPM_FAILURE_BUG event=%d curarg=%d\n",
			   state->tail_ctx.evt_type,
			   state->tail_ctx.curarg);
		++state->n_drops_bug;
		break;
	case PPM_SKIP_EVENT:
		break;
	default:
		bpf_printk("Unknown filler res=%d event=%d curarg=%d\n",
			   state->tail_ctx.prev_res,
			   state->tail_ctx.evt_type,
			   state->tail_ctx.curarg);
		break;
	}

	release_local_state(state);
	return 0;
}

FILLER(sys_empty, true)
{
	return PPM_SUCCESS;
}

FILLER(sys_single, true)
{
	unsigned long val;
	int res;

	val = bpf_syscall_get_argument(data, 0);
	res = bpf_val_to_ring(data, val);

	return res;
}

FILLER(sys_single_x, true)
{
	int res;
	long retval;

	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring(data, retval);

	return res;
}

FILLER(sys_open_x, true)
{
	unsigned int flags;
	unsigned int mode;
	unsigned long val;
	long retval;
	int res;

	/*
	 * fd
	 */
	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring(data, retval);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * Name
	 */
	val = bpf_syscall_get_argument(data, 0);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * Flags
	 */
	val = bpf_syscall_get_argument(data, 1);
	flags = open_flags_to_scap(val);
	res = bpf_val_to_ring(data, flags);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * Mode
	 */
	mode = bpf_syscall_get_argument(data, 2);
	mode = open_modes_to_scap(val, mode);
	res = bpf_val_to_ring(data, mode);

	return res;
}

FILLER(sys_read_x, true)
{
	unsigned long bufsize;
	unsigned long val;
	long retval;
	int res;

	/*
	 * res
	 */
	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring(data, retval);
	if (res != PPM_SUCCESS)
		return res;

	if (retval < 0) {
		val = 0;
		bufsize = 0;
	} else {
		val = bpf_syscall_get_argument(data, 1);
		bufsize = retval;
	}

	/*
	 * data
	 */
	data->fd = bpf_syscall_get_argument(data, 0);
	res = __bpf_val_to_ring(data, val, bufsize, PT_BYTEBUF, -1, true);

	return res;
}

FILLER(sys_write_x, true)
{
	unsigned long bufsize;
	unsigned long val;
	long retval;
	int res;

	/*
	 * res
	 */
	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring(data, retval);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * data
	 */
	data->fd = bpf_syscall_get_argument(data, 0);

	val = bpf_syscall_get_argument(data, 1);
	bufsize = bpf_syscall_get_argument(data, 2);

	res = __bpf_val_to_ring(data, val, bufsize, PT_BYTEBUF, -1, true);

	return res;
}

#define POLL_MAXFDS 16

static __always_inline int bpf_poll_parse_fds(struct filler_data *data,
					      bool enter_event)
{
	unsigned int read_size;
	unsigned int fds_count;
	int res = PPM_SUCCESS;
	unsigned long nfds;
	struct pollfd *fds;
	unsigned long val;
	unsigned long off;
	int j;

	nfds = bpf_syscall_get_argument(data, 1);
	fds = (struct pollfd *)data->tmp_scratch;
	read_size = nfds * sizeof(struct pollfd);
	if (read_size > SCRATCH_SIZE_MAX)
		return PPM_FAILURE_BUFFER_FULL;

	val = bpf_syscall_get_argument(data, 0);
#ifdef BPF_FORBIDS_ZERO_ACCESS
	if (read_size)
		if (bpf_probe_read(fds,
				   ((read_size - 1) & SCRATCH_SIZE_MAX) + 1,
				   (void *)val))
#else
	if (bpf_probe_read(fds, read_size & SCRATCH_SIZE_MAX, (void *)val))
#endif
		return PPM_FAILURE_INVALID_USER_MEMORY;

	off = data->state->tail_ctx.curoff + sizeof(u16);
	fds_count = 0;

	#pragma unroll
	for (j = 0; j < POLL_MAXFDS; ++j) {
		u16 flags;

		if (j == nfds)
			break;

		if (enter_event) {
			flags = poll_events_to_scap(fds[j].events);
		} else {
			if (!fds[j].revents)
				continue;

			flags = poll_events_to_scap(fds[j].revents);
		}

		if (off > SCRATCH_SIZE_HALF)
			return PPM_FAILURE_BUFFER_FULL;

		*(s64 *)&data->buf[off & SCRATCH_SIZE_HALF] = fds[j].fd;
		off += sizeof(s64);

		if (off > SCRATCH_SIZE_HALF)
			return PPM_FAILURE_BUFFER_FULL;

		*(s16 *)&data->buf[off & SCRATCH_SIZE_HALF] = flags;
		off += sizeof(s16);
		++fds_count;
	}

	*((u16 *)&data->buf[data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF]) = fds_count;
	data->curarg_already_on_frame = true;
	return __bpf_val_to_ring(data, 0, off - data->state->tail_ctx.curoff, PT_FDLIST, -1, false);
}

FILLER(sys_poll_e, true)
{
	unsigned long val;
	int res;

	/*
	 * fds
	 */
	res = bpf_poll_parse_fds(data, true);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * timeout
	 */
	val = bpf_syscall_get_argument(data, 2);
	res = bpf_val_to_ring(data, val);

	return res;
}

FILLER(sys_poll_x, true)
{
	long retval;
	int res;

	/*
	 * res
	 */
	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring_type(data, retval, PT_ERRNO);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * fds
	 */
	res = bpf_poll_parse_fds(data, false);

	return res;
}

#define MAX_IOVCNT 8

static __always_inline int bpf_parse_readv_writev_bufs(struct filler_data *data,
						       const struct iovec __user *iovsrc,
						       unsigned long iovcnt,
						       long retval,
						       int flags)
{
	const struct iovec *iov;
	int res = PPM_SUCCESS;
	unsigned int copylen;
	long size = 0;
	int j;

	copylen = iovcnt * sizeof(struct iovec);
	iov = (const struct iovec *)data->tmp_scratch;

	if (copylen > SCRATCH_SIZE_MAX)
		return PPM_FAILURE_BUFFER_FULL;

#ifdef BPF_FORBIDS_ZERO_ACCESS
	if (copylen)
		if (bpf_probe_read((void *)iov,
				   ((copylen - 1) & SCRATCH_SIZE_MAX) + 1,
				   (void *)iovsrc))
#else
	if (bpf_probe_read((void *)iov,
			   copylen & SCRATCH_SIZE_MAX,
			   (void *)iovsrc))
#endif
		return PPM_FAILURE_INVALID_USER_MEMORY;

	#pragma unroll
	for (j = 0; j < MAX_IOVCNT; ++j) {
		if (j == iovcnt)
			break;

		size += iov[j].iov_len;
	}

	if ((flags & PRB_FLAG_IS_WRITE) == 0)
		if (size > retval)
			size = retval;

	if (flags & PRB_FLAG_PUSH_SIZE) {
		res = bpf_val_to_ring_type(data, size, PT_UINT32);
		if (res != PPM_SUCCESS)
			return res;
	}

	if (flags & PRB_FLAG_PUSH_DATA) {
		if (size > 0) {
			unsigned long off = data->state->tail_ctx.curoff;
			unsigned long remaining = size;
			int j;

			#pragma unroll
			for (j = 0; j < MAX_IOVCNT; ++j) {
				unsigned int to_read;

				if (j == iovcnt)
					break;

				if (iov[j].iov_len <= remaining)
					to_read = iov[j].iov_len;
				else
					to_read = remaining;

				if (to_read > SCRATCH_SIZE_HALF)
					return PPM_FAILURE_BUFFER_FULL;

#ifdef BPF_FORBIDS_ZERO_ACCESS
				if (to_read)
					if (bpf_probe_read(&data->buf[off & SCRATCH_SIZE_HALF],
							   ((to_read - 1) & SCRATCH_SIZE_HALF) + 1,
							   iov[j].iov_base))
#else
				if (bpf_probe_read(&data->buf[off & SCRATCH_SIZE_HALF],
						   to_read & SCRATCH_SIZE_HALF,
						   iov[j].iov_base))
#endif
					return PPM_FAILURE_INVALID_USER_MEMORY;

				remaining -= to_read;
				off += to_read;
			}
		} else {
			size = 0;
		}

		data->fd = bpf_syscall_get_argument(data, 0);
		data->curarg_already_on_frame = true;
		return __bpf_val_to_ring(data, 0, size, PT_BYTEBUF, -1, true);
	}

	return res;
}

FILLER(sys_readv_preadv_x, true)
{
	const struct iovec __user *iov;
	unsigned long iovcnt;
	long retval;
	int res;

	/*
	 * res
	 */
	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring_type(data, retval, PT_ERRNO);
	if (res != PPM_SUCCESS)
		return res;

	iov = (const struct iovec __user *)bpf_syscall_get_argument(data, 1);
	iovcnt = bpf_syscall_get_argument(data, 2);

	res = bpf_parse_readv_writev_bufs(data,
					  iov,
					  iovcnt,
					  retval,
					  PRB_FLAG_PUSH_ALL);

	return res;
}

FILLER(sys_writev_e, true)
{
	unsigned long iovcnt;
	unsigned long val;
	int res;

	/*
	 * fd
	 */
	val = bpf_syscall_get_argument(data, 0);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	val = bpf_syscall_get_argument(data, 1);
	iovcnt = bpf_syscall_get_argument(data, 2);
	res = bpf_parse_readv_writev_bufs(data,
					  (const struct iovec __user *)val,
					  iovcnt,
					  0,
					  PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);

	return res;
}

FILLER(sys_writev_pwritev_x, true)
{
	unsigned long iovcnt;
	unsigned long val;
	long retval;
	int res;

	/*
	 * res
	 */
	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring(data, retval);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * data and size
	 */
	val = bpf_syscall_get_argument(data, 1);
	iovcnt = bpf_syscall_get_argument(data, 2);
	res = bpf_parse_readv_writev_bufs(data,
					  (const struct iovec __user *)val,
					  iovcnt,
					  0,
					  PRB_FLAG_PUSH_DATA | PRB_FLAG_IS_WRITE);

	return res;
}

static __always_inline int timespec_parse(struct filler_data *data,
					  unsigned long val)
{
	u64 longtime;
	struct timespec ts;

	if (bpf_probe_read(&ts, sizeof(ts), (void *)val))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	longtime = ((u64)ts.tv_sec) * 1000000000 + ts.tv_nsec;

	return bpf_val_to_ring_type(data, longtime, PT_RELTIME);
}

FILLER(sys_nanosleep_e, true)
{
	unsigned long val;
	int res;

	val = bpf_syscall_get_argument(data, 0);
	res = timespec_parse(data, val);

	return res;
}

FILLER(sys_futex_e, true)
{
	unsigned long val;
	int res;

	/*
	 * addr
	 */
	val = bpf_syscall_get_argument(data, 0);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * op
	 */
	val = bpf_syscall_get_argument(data, 1);
	res = bpf_val_to_ring(data, futex_op_to_scap(val));
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * val
	 */
	val = bpf_syscall_get_argument(data, 2);
	res = bpf_val_to_ring(data, val);

	return res;
}

static __always_inline unsigned long bpf_get_mm_counter(struct mm_struct *mm,
							int member)
{
	long val;

	bpf_probe_read(&val, sizeof(val), &mm->rss_stat.count[member]);
	if (val < 0)
		val = 0;

	return (unsigned long)val;
}

static __always_inline unsigned long bpf_get_mm_rss(struct mm_struct *mm)
{
	return bpf_get_mm_counter(mm, MM_FILEPAGES) +
		bpf_get_mm_counter(mm, MM_ANONPAGES) +
		bpf_get_mm_counter(mm, MM_SHMEMPAGES);
}

static __always_inline unsigned long bpf_get_mm_swap(struct mm_struct *mm)
{
	return bpf_get_mm_counter(mm, MM_SWAPENTS);
}

FILLER(sys_brk_munmap_mmap_x, true)
{
	struct task_struct *task;
	unsigned long total_vm = 0;
	struct mm_struct *mm;
	long total_rss = 0;
	long swap = 0;
	long retval;
	int res;

	task = (struct task_struct *)bpf_get_current_task();
	mm = NULL;
	bpf_probe_read(&mm, sizeof(mm), &task->mm);

	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring_type(data, retval, PT_UINT64);
	if (res != PPM_SUCCESS)
		return res;

	if (mm) {
		total_vm = _READ(mm->total_vm);
		total_vm <<= (PAGE_SHIFT - 10);
		total_rss = bpf_get_mm_rss(mm) << (PAGE_SHIFT - 10);
		swap = bpf_get_mm_swap(mm) << (PAGE_SHIFT - 10);
	}

	/*
	 * vm_size
	 */
	res = bpf_val_to_ring_type(data, total_vm, PT_UINT32);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * vm_rss
	 */
	res = bpf_val_to_ring_type(data, total_rss, PT_UINT32);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * vm_swap
	 */
	res = bpf_val_to_ring_type(data, swap, PT_UINT32);

	return res;
}

FILLER(sys_mmap_e, true)
{
	unsigned long val;
	int res;

	/*
	 * addr
	 */
	val = bpf_syscall_get_argument(data, 0);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * length
	 */
	val = bpf_syscall_get_argument(data, 1);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * prot
	 */
	val = bpf_syscall_get_argument(data, 2);
	res = bpf_val_to_ring(data, prot_flags_to_scap(val));
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * flags
	 */
	val = bpf_syscall_get_argument(data, 3);
	res = bpf_val_to_ring(data, mmap_flags_to_scap(val));
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * fd
	 */
	val = bpf_syscall_get_argument(data, 4);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * offset/pgoffset
	 */
	val = bpf_syscall_get_argument(data, 5);
	res = bpf_val_to_ring(data, val);

	return res;
}

FILLER(sys_fcntl_e, true)
{
	unsigned long val;
	long cmd;
	int res;

	/*
	 * fd
	 */
	val = bpf_syscall_get_argument(data, 0);
	res = bpf_val_to_ring_type(data, val, PT_FD);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * cmd
	 */
	val = bpf_syscall_get_argument(data, 1);
	cmd = fcntl_cmd_to_scap(val);
	res = bpf_val_to_ring_type(data, cmd, PT_FLAGS8);

	return res;
}

FILLER(sys_access_e, true)
{
	unsigned long val;
	int res;

	/*
	 * mode
	 */
	val = bpf_syscall_get_argument(data, 1);
	res = bpf_val_to_ring(data, access_flags_to_scap(val));

	return res;
}

FILLER(sys_getrlimit_setrlimit_e, true)
{
	unsigned long val;
	int res;

	/*
	 * resource
	 */
	val = bpf_syscall_get_argument(data, 0);
	res = bpf_val_to_ring_type(data, rlimit_resource_to_scap(val), PT_FLAGS8);

	return res;
}

FILLER(sys_getrlimit_setrlrimit_x, true)
{
	unsigned long val;
	long retval;
	s64 cur;
	s64 max;
	int res;

	/*
	 * res
	 */
	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring(data, retval);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * Copy the user structure and extract cur and max
	 */
	if (retval >= 0 ||
	    data->state->tail_ctx.evt_type == PPME_SYSCALL_SETRLIMIT_X) {
		struct rlimit rl;

		val = bpf_syscall_get_argument(data, 1);
		if (bpf_probe_read(&rl, sizeof(rl), (void *)val))
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
	res = bpf_val_to_ring(data, cur);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * max
	 */
	res = bpf_val_to_ring(data, max);

	return res;
}

FILLER(sys_connect_x, true)
{
	struct sockaddr *usrsockaddr;
	unsigned long val;
	long size = 0;
	long retval;
	int err;
	int res;
	int fd;

	/*
	 * Push the result
	 */
	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring(data, retval);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * Retrieve the fd and push it to the ring.
	 * Note that, even if we are in the exit callback, the arguments are still
	 * in the stack, and therefore we can consume them.
	 */
	fd = bpf_syscall_get_argument(data, 0);
	if (fd >= 0) {
		usrsockaddr = (struct sockaddr *)bpf_syscall_get_argument(data, 1);
		val = bpf_syscall_get_argument(data, 2);

		if (usrsockaddr && val != 0) {
			/*
			 * Copy the address
			 */
			err = bpf_addr_to_kernel(usrsockaddr, val,
						 (struct sockaddr *)data->tmp_scratch);
			if (err >= 0) {
				/*
				 * Convert the fd into socket endpoint information
				 */
				size = bpf_fd_to_socktuple(data,
							   fd,
							   (struct sockaddr *)data->tmp_scratch,
							   val,
							   true,
							   false,
							   data->tmp_scratch + sizeof(struct sockaddr_storage));
			}
		}
	}

	/*
	 * Copy the endpoint info into the ring
	 */
	data->curarg_already_on_frame = true;
	res = bpf_val_to_ring_len(data, 0, size);

	return res;
}

FILLER(sys_socketpair_x, true)
{
	struct unix_sock *us = NULL;
	struct sock *speer = NULL;
	int fds[2] = { 0 };
	unsigned long val;
	long retval;
	int res;

	/* ret */
	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring_type(data, retval, PT_ERRNO);
	if (res != PPM_SUCCESS)
		return res;

	if (retval >= 0) {
		val = bpf_syscall_get_argument(data, 3);
		if (bpf_probe_read(fds, 2 * sizeof(int), (void *)val))
			return PPM_FAILURE_INVALID_USER_MEMORY;

		struct socket *sock = bpf_sockfd_lookup(data, fds[0]);

		if (sock) {
			us = (struct unix_sock *)_READ(sock->sk);
			speer = _READ(us->peer);
		}
	}
	/* fd1 */
	res = bpf_val_to_ring_type(data, fds[0], PT_FD);
	if (res != PPM_SUCCESS)
		return res;
	/* fd2 */
	res = bpf_val_to_ring_type(data, fds[1], PT_FD);
	if (res != PPM_SUCCESS)
		return res;
	/* source */
	res = bpf_val_to_ring_type(data, (unsigned long)us, PT_UINT64);
	if (res != PPM_SUCCESS)
		return res;
	/* peer */
	res = bpf_val_to_ring_type(data, (unsigned long)speer, PT_UINT64);

	return res;
}

static __always_inline int f_sys_send_e_common(struct filler_data *data, int fd)
{
	unsigned long val;
	int res;

	/*
	 * fd
	 */
	res = bpf_val_to_ring(data, fd);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * size
	 */
	val = bpf_syscall_get_argument(data, 2);
	res = bpf_val_to_ring(data, val);

	return res;
}

FILLER(sys_send_e, true)
{
	int res;
	int fd;

	/*
	 * Push the common params to the ring
	 */
	fd = bpf_syscall_get_argument(data, 0);
	res = f_sys_send_e_common(data, fd);

	return res;
}

FILLER(sys_sendto_e, true)
{
	struct sockaddr __user *usrsockaddr;
	unsigned long val;
	long size = 0;
	int err = 0;
	int res;
	int fd;

	/*
	 * Push the common params to the ring
	 */
	fd = bpf_syscall_get_argument(data, 0);
	res = f_sys_send_e_common(data, fd);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * Get the address
	 */
	val = bpf_syscall_get_argument(data, 4);
	usrsockaddr = (struct sockaddr __user *)val;

	/*
	 * Get the address len
	 */
	val = bpf_syscall_get_argument(data, 5);

	if (usrsockaddr && val != 0) {
		/*
		 * Copy the address
		 */
		err = bpf_addr_to_kernel(usrsockaddr, val,
					 (struct sockaddr *)data->tmp_scratch);
		if (err >= 0) {
			/*
			 * Convert the fd into socket endpoint information
			 */
			size = bpf_fd_to_socktuple(data,
						   fd,
						   (struct sockaddr *)data->tmp_scratch,
						   val,
						   true,
						   false,
						   data->tmp_scratch + sizeof(struct sockaddr_storage));
		}
	}

	/*
	 * Copy the endpoint info into the ring
	 */
	data->curarg_already_on_frame = true;
	res = bpf_val_to_ring_len(data, 0, size);

	return res;
}

FILLER(sys_send_x, true)
{
	unsigned long bufsize;
	unsigned long val;
	long retval;
	int res;

	/*
	 * res
	 */
	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring_type(data, retval, PT_ERRNO);
	if (res != PPM_SUCCESS)
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
		val = bpf_syscall_get_argument(data, 1);

		/*
		 * The return value can be lower than the value provided by the user,
		 * and we take that into account.
		 */
		bufsize = retval;
	}

	data->fd = bpf_syscall_get_argument(data, 0);
	res = __bpf_val_to_ring(data, val, bufsize, PT_BYTEBUF, -1, true);

	return res;
}

FILLER(sys_execve_e, true)
{
	unsigned long val;
	int res;

	/*
	 * filename
	 */
	val = bpf_syscall_get_argument(data, 0);
	res = bpf_val_to_ring(data, val);
	if (res == PPM_FAILURE_INVALID_USER_MEMORY) {
		char na[] = "<NA>";

		res = bpf_val_to_ring(data, (unsigned long)na);
	}

	return res;
}

static __always_inline int bpf_ppm_get_tty(struct task_struct *task)
{
	struct signal_struct *sig;
	struct tty_struct *tty;
	struct tty_driver *driver;
	int major;
	int minor_start;
	int index;
	int tty_nr = 0;

	sig = _READ(task->signal);
	if (!sig)
		return 0;

	tty = _READ(sig->tty);
	if (!tty)
		return 0;

	index = _READ(tty->index);

	driver = _READ(tty->driver);
	if (!driver)
		return 0;

	major = _READ(driver->major);
	minor_start = _READ(driver->minor_start);

	tty_nr = new_encode_dev(MKDEV(major, minor_start) + index);

	return tty_nr;
}

enum bpf_pid_type {
	BPF_PIDTYPE_PID,
	BPF_PIDTYPE_PGID,
	BPF_PIDTYPE_SID,
	BPF_PIDTYPE_MAX,
	BPF__PIDTYPE_TGID
};

static __always_inline pid_t bpf_task_pid_nr_ns(struct task_struct *task,
						enum bpf_pid_type type)
{
	pid_t nr = 0;
	struct pid *pid = _READ(task->pids[PIDTYPE_PID].pid);
	unsigned int pid_level = _READ(pid->level);
	struct pid_namespace *ns = _READ(pid->numbers[pid_level].ns);
	unsigned int ns_level = _READ(ns->level);

	if (type != BPF_PIDTYPE_PID) {
		if (type == BPF__PIDTYPE_TGID)
			type = BPF_PIDTYPE_PID;

		task = _READ(task->group_leader);
	}

	pid = _READ(task->pids[type].pid);
	pid_level = _READ(pid->level);

	if (pid && ns_level <= pid_level) {
		struct upid *upid = &pid->numbers[ns_level];
		struct pid_namespace *upid_ns = _READ(upid->ns);

		if (upid_ns == ns)
			nr = _READ(upid->nr);
	}

	return nr;
}

static __always_inline pid_t bpf_task_pid_vnr(struct task_struct *task)
{
	return bpf_task_pid_nr_ns(task, BPF_PIDTYPE_PID);
}

static __always_inline pid_t bpf_task_tgid_vnr(struct task_struct *task)
{
	return bpf_task_pid_nr_ns(task, BPF__PIDTYPE_TGID);
}

static __always_inline pid_t bpf_task_pgrp_vnr(struct task_struct *task)
{
	return bpf_task_pid_nr_ns(task, BPF_PIDTYPE_PGID);
}

#define MAX_CGROUP_PATHS 6

static __always_inline bool __bpf_append_cgroup(struct css_set *cgroups,
						int subsys_id,
						char *buf,
						int *len)
{
	struct cgroup_subsys_state *css = _READ(cgroups->subsys[subsys_id]);
	struct cgroup_subsys *ss = _READ(css->ss);
	char *subsys_name = (char *)_READ(ss->name);
	struct cgroup *cgroup = _READ(css->cgroup);
	struct kernfs_node *kn = _READ(cgroup->kn);
	char *cgroup_path[MAX_CGROUP_PATHS];
	bool prev_empty = false;

	int res = bpf_probe_read_str(&buf[(*len) & SCRATCH_SIZE_HALF],
				     SCRATCH_SIZE_HALF,
				     subsys_name);
	if (res < 0)
		return false;

	(*len) += res - 1;
	buf[(*len) & SCRATCH_SIZE_HALF] = '=';
	++(*len);

	#pragma unroll MAX_CGROUP_PATHS
	for (int k = 0; k < MAX_CGROUP_PATHS; ++k) {
		if (kn) {
			cgroup_path[k] = (char *)_READ(kn->name);
			kn = _READ(kn->parent);
		} else {
			cgroup_path[k] = NULL;
		}
	}

	#pragma unroll MAX_CGROUP_PATHS
	for (int k = MAX_CGROUP_PATHS - 1; k >= 0 ; --k) {
		if (cgroup_path[k]) {
			if (!prev_empty) {
				buf[(*len) & SCRATCH_SIZE_HALF] = '/';
				++(*len);
			}

			prev_empty = false;

			res = bpf_probe_read_str(&buf[(*len) & SCRATCH_SIZE_HALF],
						 SCRATCH_SIZE_HALF,
						 cgroup_path[k]);
			if (res > 1)
				(*len) += res - 1;
			else if (res == 1)
				prev_empty = true;
			else
				return false;
		}
	}

	buf[(*len) & SCRATCH_SIZE_HALF] = 0;
	++(*len);

	return true;
}

static __always_inline bool bpf_append_cgroup(struct task_struct *task,
					      char *buf, int *len)
{
	struct css_set *cgroups = _READ(task->cgroups);

#if IS_ENABLED(CONFIG_CPUSETS)
	if (!__bpf_append_cgroup(cgroups, cpuset_cgrp_id, buf, len))
		return false;
#endif

#if IS_ENABLED(CONFIG_CGROUP_SCHED)
	if (!__bpf_append_cgroup(cgroups, cpu_cgrp_id, buf, len))
		return false;
#endif

#if IS_ENABLED(CONFIG_CGROUP_CPUACCT)
	if (!__bpf_append_cgroup(cgroups, cpuacct_cgrp_id, buf, len))
		return false;
#endif

#if IS_ENABLED(CONFIG_BLK_CGROUP)
	if (!__bpf_append_cgroup(cgroups, io_cgrp_id, buf, len))
		return false;
#endif

#if IS_ENABLED(CONFIG_MEMCG)
	if (!__bpf_append_cgroup(cgroups, memory_cgrp_id, buf, len))
		return false;
#endif

	return true;
}

#define ARGS_ENV_SIZE_MAX 4096

FILLER(proc_startupdate, true)
{
	struct task_struct *real_parent;
	struct signal_struct *signal;
	struct task_struct *task;
	unsigned long total_vm;
	unsigned long min_flt;
	unsigned long maj_flt;
	unsigned long fdlimit;
	struct mm_struct *mm;
	long total_rss;
	char empty = 0;
	long retval;
	pid_t tgid;
	long swap;
	pid_t pid;
	int res;

	/*
	 * Make sure the operation was successful
	 */
	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring_type(data, retval, PT_ERRNO);
	if (res != PPM_SUCCESS)
		return res;

	task = (struct task_struct *)bpf_get_current_task();
	mm = _READ(task->mm);
	if (!mm)
		return PPM_FAILURE_BUG;

	if (retval < 0 &&
	    data->state->tail_ctx.evt_type != PPME_SYSCALL_EXECVE_19_X) {
		/* The call failed, but this syscall has no exe, args
		 * anyway, so I report empty ones
		 */

		/*
		 * exe
		 */
		res = bpf_val_to_ring_type(data, (unsigned long)&empty, PT_CHARBUF);
		if (res != PPM_SUCCESS)
			return res;

		/*
		 * Args
		 */
		res = bpf_val_to_ring_type(data, 0, PT_BYTEBUF);
		if (res != PPM_SUCCESS)
			return res;
	} else {
		long args_len;
		int exe_len;

		if (retval >= 0) {
			/*
			 * The call succeeded. Get exe, args from the current
			 * process; put one \0-separated exe-args string into
			 * str_storage
			 */
			unsigned long arg_start;
			unsigned long arg_end;

			arg_end = _READ(mm->arg_end);
			if (!arg_end)
				return PPM_FAILURE_BUG;

			arg_start = _READ(mm->arg_start);
			args_len = arg_end - arg_start;

			if (args_len) {
				if (args_len > ARGS_ENV_SIZE_MAX)
					args_len = ARGS_ENV_SIZE_MAX;

#ifdef BPF_FORBIDS_ZERO_ACCESS
				if (bpf_probe_read(&data->buf[data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF],
						   ((args_len - 1) & SCRATCH_SIZE_HALF) + 1,
						   (void *)arg_start))
#else
				if (bpf_probe_read(&data->buf[data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF],
						   args_len & SCRATCH_SIZE_HALF,
						   (void *)arg_start))
#endif
					args_len = 0;
				else
					data->buf[(data->state->tail_ctx.curoff + args_len - 1) & SCRATCH_SIZE_MAX] = 0;
			}
		} else {
			/* Deal with this! */
			args_len = 0;
		}

		if (args_len == 0) {
			exe_len = 0;
		} else {
			exe_len = bpf_probe_read_str(&data->buf[data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF],
						     SCRATCH_SIZE_HALF,
						     &data->buf[data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF]);

			if (exe_len < 0)
				return PPM_FAILURE_INVALID_USER_MEMORY;
		}

		/*
		 * exe
		 */
		data->curarg_already_on_frame = true;
		res = __bpf_val_to_ring(data, 0, exe_len, PT_CHARBUF, -1, false);
		if (res != PPM_SUCCESS)
			return res;

		/*
		 * Args
		 */
		data->curarg_already_on_frame = true;
		res = __bpf_val_to_ring(data, 0, args_len - exe_len, PT_BYTEBUF, -1, false);
		if (res != PPM_SUCCESS)
			return res;
	}

	/*
	 * tid
	 */
	pid = _READ(task->pid);

	res = bpf_val_to_ring_type(data, pid, PT_PID);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * pid
	 */
	tgid = _READ(task->tgid);

	res = bpf_val_to_ring_type(data, tgid, PT_PID);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * ptid
	 */
	real_parent = _READ(task->real_parent);
	pid_t ptid = _READ(real_parent->pid);

	res = bpf_val_to_ring_type(data, ptid, PT_PID);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * cwd, pushed empty to avoid breaking compatibility
	 * with the older event format
	 */
	res = bpf_val_to_ring_type(data, (unsigned long)&empty, PT_CHARBUF);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * fdlimit
	 */
	signal = _READ(task->signal);
	fdlimit = _READ(signal->rlim[RLIMIT_NOFILE].rlim_cur);

	res = bpf_val_to_ring_type(data, fdlimit, PT_UINT64);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * pgft_maj
	 */
	maj_flt = _READ(task->maj_flt);

	res = bpf_val_to_ring_type(data, maj_flt, PT_UINT64);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * pgft_min
	 */
	min_flt = _READ(task->min_flt);

	res = bpf_val_to_ring_type(data, min_flt, PT_UINT64);
	if (res != PPM_SUCCESS)
		return res;

	total_vm = 0;
	total_rss = 0;
	swap = 0;

	if (mm) {
		total_vm = _READ(mm->total_vm);
		total_vm <<= (PAGE_SHIFT - 10);
		total_rss = bpf_get_mm_rss(mm) << (PAGE_SHIFT - 10);
		swap = bpf_get_mm_swap(mm) << (PAGE_SHIFT - 10);
	}

	/*
	 * vm_size
	 */
	res = bpf_val_to_ring_type(data, total_vm, PT_UINT32);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * vm_rss
	 */
	res = bpf_val_to_ring_type(data, total_rss, PT_UINT32);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * vm_swap
	 */
	res = bpf_val_to_ring_type(data, swap, PT_UINT32);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * comm
	 */
	res = bpf_val_to_ring_type(data, (unsigned long)task->comm, PT_CHARBUF);
	if (res != PPM_SUCCESS)
		return res;

	bpf_tail_call(data->ctx, &tail_map, PPM_FILLER_proc_startupdate_2);
	bpf_printk("Can't tail call f_proc_startupdate_2 filler\n");
	return PPM_FAILURE_BUG;
}

FILLER(proc_startupdate_2, true)
{
	struct task_struct *task;
	int cgroups_len = 0;
	int res;

	task = (struct task_struct *)bpf_get_current_task();

	/*
	 * cgroups
	 */
	if (!bpf_append_cgroup(task, data->tmp_scratch, &cgroups_len))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	res = __bpf_val_to_ring(data, (unsigned long)data->tmp_scratch, cgroups_len, PT_BYTEBUF, -1, false);
	if (res != PPM_SUCCESS)
		return res;

	bpf_tail_call(data->ctx, &tail_map, PPM_FILLER_proc_startupdate_3);
	bpf_printk("Can't tail call f_proc_startupdate_3 filler\n");
	return PPM_FAILURE_BUG;
}

FILLER(proc_startupdate_3, true)
{
	struct task_struct *task;
	struct mm_struct *mm;
	long retval;
	int res;

	retval = bpf_syscall_get_retval(data->ctx);

	task = (struct task_struct *)bpf_get_current_task();
	mm = _READ(task->mm);
	if (!mm)
		return PPM_FAILURE_BUG;

	if (data->state->tail_ctx.evt_type == PPME_SYSCALL_CLONE_20_X ||
	    data->state->tail_ctx.evt_type == PPME_SYSCALL_FORK_20_X ||
	    data->state->tail_ctx.evt_type == PPME_SYSCALL_VFORK_20_X) {
		/*
		 * clone-only parameters
		 */
		unsigned long flags;
		struct cred *cred;
		kuid_t euid;
		kgid_t egid;
		pid_t vtid;
		pid_t vpid;

		/*
		 * flags
		 */
		if (data->state->tail_ctx.evt_type == PPME_SYSCALL_CLONE_20_X)
			flags = bpf_syscall_get_argument(data, 0);
		else
			flags = 0;

		flags = clone_flags_to_scap(flags);

		res = bpf_val_to_ring_type(data, flags, PT_FLAGS32);
		if (res != PPM_SUCCESS)
			return res;

		/*
		 * This logic is wrong and doesn't account for user
		 * namespaces.
		 * Fix this at some point, maybe with a custom BPF
		 * helper.
		 */
		cred = (struct cred *)_READ(task->cred);

		euid = _READ(cred->euid);

		/*
		 * uid
		 */
		res = bpf_val_to_ring_type(data, euid.val, PT_UINT32);
		if (res != PPM_SUCCESS)
			return res;

		egid = _READ(cred->egid);

		/*
		 * gid
		 */
		res = bpf_val_to_ring_type(data, egid.val, PT_UINT32);
		if (res != PPM_SUCCESS)
			return res;

		/*
		 * vtid
		 */
		vtid = bpf_task_pid_vnr(task);
		res = bpf_val_to_ring_type(data, vtid, PT_PID);
		if (res != PPM_SUCCESS)
			return res;

		/*
		 * vpid
		 */
		vpid = bpf_task_tgid_vnr(task);
		res = bpf_val_to_ring_type(data, vpid, PT_PID);

	} else if (data->state->tail_ctx.evt_type == PPME_SYSCALL_EXECVE_19_X) {
		/*
		 * execve-only parameters
		 */
		long env_len = 0;
		int tty;

		/*
		 * environ
		 */
		if (retval >= 0) {
			/*
			 * Already checked for mm validity
			 */
			unsigned long env_end = _READ(mm->env_end);
			unsigned long env_start = _READ(mm->env_start);

			env_len = env_end - env_start;

			if (env_len) {
				if (env_len > ARGS_ENV_SIZE_MAX)
					env_len = ARGS_ENV_SIZE_MAX;

#ifdef BPF_FORBIDS_ZERO_ACCESS
				if (bpf_probe_read(&data->buf[data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF],
						   ((env_len - 1) & SCRATCH_SIZE_HALF) + 1,
						   (void *)env_start))
#else
				if (bpf_probe_read(&data->buf[data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF],
						   env_len & SCRATCH_SIZE_HALF,
						   (void *)env_start))
#endif
					env_len = 0;
				else
					data->buf[(data->state->tail_ctx.curoff + env_len - 1) & SCRATCH_SIZE_MAX] = 0;
			}
		} else {
			/* Deal with this! */
			env_len = 0;
		}

		data->curarg_already_on_frame = true;
		res = __bpf_val_to_ring(data, 0, env_len, PT_BYTEBUF, -1, false);
		if (res != PPM_SUCCESS)
			return res;

		/*
		 * tty
		 */
		tty = bpf_ppm_get_tty(task);

		res = bpf_val_to_ring_type(data, tty, PT_INT32);
		if (res != PPM_SUCCESS)
			return res;

		/*
		 * pgid
		 */
		res = bpf_val_to_ring_type(data, bpf_task_pgrp_vnr(task), PT_PID);
	}

	return res;
}

FILLER(sys_accept4_e, true)
{
	int res;

	/*
	 * push the flags into the ring.
	 * XXX we don't support flags yet and so we just return zero
	 */
	res = bpf_val_to_ring(data, 0);

	return res;
}

FILLER(sys_accept_x, true)
{
	unsigned long max_ack_backlog = 0;
	unsigned long ack_backlog = 0;
	unsigned long queuepct = 0;
	struct socket *sock;
	long size = 0;
	int res;
	int fd;

	/*
	 * Retrieve the fd and push it to the ring.
	 * Note that, even if we are in the exit callback, the arguments are still
	 * in the stack, and therefore we can consume them.
	 */
	fd = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring_type(data, fd, PT_FD);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * Convert the fd into socket endpoint information
	 */
	size = bpf_fd_to_socktuple(data, fd, NULL, 0, false, true,
				   data->tmp_scratch);

	/*
	 * Copy the endpoint info into the ring
	 */
	data->curarg_already_on_frame = true;
	res = __bpf_val_to_ring(data, 0, size, PT_SOCKTUPLE, -1, false);
	if (res != PPM_SUCCESS)
		return res;

	sock = bpf_sockfd_lookup(data, fd);
	if (sock) {
		struct sock *sk = _READ(sock->sk);

		if (sk) {
			ack_backlog = _READ(sk->sk_ack_backlog);
			max_ack_backlog = _READ(sk->sk_max_ack_backlog);

			if (max_ack_backlog)
				queuepct = (unsigned long)ack_backlog * 100 / max_ack_backlog;
		}
	}

	/* queuepct */
	res = bpf_val_to_ring_type(data, queuepct, PT_UINT8);
	if (res != PPM_SUCCESS)
		return res;

	/* queuelen */
	res = bpf_val_to_ring_type(data, ack_backlog, PT_UINT32);
	if (res != PPM_SUCCESS)
		return res;

	/* queuemax */
	res = bpf_val_to_ring_type(data, max_ack_backlog, PT_UINT32);

	return res;
}

FILLER(sys_setns_e, true)
{
	unsigned long val;
	u32 flags;
	int res;

	val = bpf_syscall_get_argument(data, 0);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	val = bpf_syscall_get_argument(data, 1);
	flags = clone_flags_to_scap(val);
	res = bpf_val_to_ring(data, flags);

	return res;
}

FILLER(sys_unshare_e, true)
{
	unsigned long val;
	u32 flags;
	int res;

	val = bpf_syscall_get_argument(data, 0);
	flags = clone_flags_to_scap(val);
	res = bpf_val_to_ring(data, flags);

	return res;
}

FILLER(sys_generic, true)
{
	long *sysdig_id;
	int native_id;
	int res;

	native_id = bpf_syscall_get_nr(data->ctx);
	sysdig_id = bpf_map_lookup_elem(&syscall_code_routing_table, &native_id);
	if (!sysdig_id) {
		bpf_printk("no routing for syscall %d\n", native_id);
		return PPM_FAILURE_BUG;
	}

	if (*sysdig_id == PPM_SC_UNKNOWN)
		bpf_printk("no syscall for id %d\n", native_id);

	/*
	 * id
	 */
	res = bpf_val_to_ring(data, *sysdig_id);
	if (res != PPM_SUCCESS)
		return res;

	if (data->state->tail_ctx.evt_type == PPME_GENERIC_E) {
		/*
		 * native id
		 */
		res = bpf_val_to_ring(data, native_id);
	}

	return res;
}

FILLER(sys_openat_e, true)
{
	unsigned long flags;
	unsigned long val;
	unsigned long mode;
	int res;

	/*
	 * dirfd
	 */
	val = bpf_syscall_get_argument(data, 0);
	if ((int)val == AT_FDCWD)
		val = PPM_AT_FDCWD;

	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * name
	 */
	val = bpf_syscall_get_argument(data, 1);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * Flags
	 * Note that we convert them into the ppm portable representation before pushing them to the ring
	 */
	val = bpf_syscall_get_argument(data, 2);
	flags = open_flags_to_scap(val);
	res = bpf_val_to_ring(data, flags);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * mode
	 */
	mode = bpf_syscall_get_argument(data, 3);
	mode = open_modes_to_scap(val, mode);
	res = bpf_val_to_ring(data, mode);

	return res;
}

FILLER(sys_sendfile_e, true)
{
	unsigned long val;
	off_t *offp;
	off_t off;
	int res;

	/*
	 * out_fd
	 */
	val = bpf_syscall_get_argument(data, 0);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * in_fd
	 */
	val = bpf_syscall_get_argument(data, 1);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * offset
	 */
	offp = (off_t *)bpf_syscall_get_argument(data, 2);
	off = _READ(*offp);
	res = bpf_val_to_ring(data, off);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * size
	 */
	val = bpf_syscall_get_argument(data, 3);
	res = bpf_val_to_ring(data, val);

	return res;
}

FILLER(sys_sendfile_x, true)
{
	long retval;
	off_t *offp;
	off_t off;
	int res;

	/*
	 * res
	 */
	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring(data, retval);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * offset
	 */
	offp = (off_t *)bpf_syscall_get_argument(data, 2);
	off = _READ(*offp);
	res = bpf_val_to_ring(data, off);

	return res;
}

FILLER(sys_prlimit_e, true)
{
	unsigned long val;
	u8 ppm_resource;
	int res;

	/*
	 * pid
	 */
	val = bpf_syscall_get_argument(data, 0);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * resource
	 */
	val = bpf_syscall_get_argument(data, 1);
	ppm_resource = rlimit_resource_to_scap(val);
	res = bpf_val_to_ring(data, ppm_resource);

	return res;
}

FILLER(sys_prlimit_x, true)
{
	unsigned long val;
	struct rlimit rl;
	long retval;
	s64 newcur;
	s64 newmax;
	s64 oldcur;
	s64 oldmax;
	int res;

	/*
	 * res
	 */
	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring_type(data, retval, PT_ERRNO);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * Copy the user structure and extract cur and max
	 */
	if (retval >= 0) {
		val = bpf_syscall_get_argument(data, 2);
		if (bpf_probe_read(&rl, sizeof(rl), (void *)val)) {
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

	val = bpf_syscall_get_argument(data, 3);
	if (bpf_probe_read(&rl, sizeof(rl), (void *)val)) {
		oldcur = -1;
		oldmax = -1;
	} else {
		oldcur = rl.rlim_cur;
		oldmax = rl.rlim_max;
	}

	/*
	 * newcur
	 */
	res = bpf_val_to_ring_type(data, newcur, PT_INT64);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * newmax
	 */
	res = bpf_val_to_ring_type(data, newmax, PT_INT64);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * oldcur
	 */
	res = bpf_val_to_ring_type(data, oldcur, PT_INT64);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * oldmax
	 */
	res = bpf_val_to_ring_type(data, oldmax, PT_INT64);

	return res;
}

FILLER(sys_pwritev_e, true)
{
	const struct iovec __user *iov;
	unsigned long iovcnt;
	unsigned long val;
	int res;

	/*
	 * fd
	 */
	val = bpf_syscall_get_argument(data, 0);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	iov = (const struct iovec __user *)bpf_syscall_get_argument(data, 1);
	iovcnt = bpf_syscall_get_argument(data, 2);

	res = bpf_parse_readv_writev_bufs(data,
					  iov,
					  iovcnt,
					  0,
					  PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);
	if (res != PPM_SUCCESS)
		return res;

	val = bpf_syscall_get_argument(data, 3);
	res = bpf_val_to_ring_type(data, val, PT_UINT64);

	return res;
}

FILLER(sys_getresuid_and_gid_x, true)
{
	long retval;
	u32 *idp;
	int res;
	u32 id;

	/*
	 * return value
	 */
	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring(data, retval);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * ruid
	 */
	idp = (u32 *)bpf_syscall_get_argument(data, 0);
	id = _READ(*idp);

	res = bpf_val_to_ring(data, id);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * euid
	 */
	idp = (u32 *)bpf_syscall_get_argument(data, 1);
	id = _READ(*idp);

	res = bpf_val_to_ring(data, id);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * suid
	 */
	idp = (u32 *)bpf_syscall_get_argument(data, 2);
	id = _READ(*idp);

	res = bpf_val_to_ring(data, id);

	return res;
}

FILLER(sys_socket_bind_x, true)
{
	struct sockaddr *usrsockaddr;
	unsigned long val;
	u16 size = 0;
	int err = 0;
	long retval;
	int res;

	/*
	 * res
	 */
	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring(data, retval);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * addr
	 */
	usrsockaddr = (struct sockaddr __user *)bpf_syscall_get_argument(data, 1);
	val = bpf_syscall_get_argument(data, 2);

	if (usrsockaddr && val != 0) {
		/*
		 * Copy the address
		 */
		err = bpf_addr_to_kernel(usrsockaddr, val,
					 (struct sockaddr *)data->tmp_scratch);
		if (err >= 0) {
			/*
			 * Convert the fd into socket endpoint information
			 */
			size = bpf_pack_addr(data,
					     (struct sockaddr *)data->tmp_scratch,
					     val);
		}
	}

	/*
	 * Copy the endpoint info into the ring
	 */
	data->curarg_already_on_frame = true;
	res = bpf_val_to_ring_len(data, 0, size);

	return res;
}

static __always_inline int f_sys_recv_x_common(struct filler_data *data, long retval)
{
	unsigned long bufsize;
	unsigned long val;
	int res;

	/*
	 * res
	 */
	res = bpf_val_to_ring_type(data, retval, PT_ERRNO);
	if (res != PPM_SUCCESS)
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
		val = bpf_syscall_get_argument(data, 1);

		/*
		 * The return value can be lower than the value provided by the user,
		 * and we take that into account.
		 */
		bufsize = retval;
	}

	data->fd = bpf_syscall_get_argument(data, 0);
	res = __bpf_val_to_ring(data, val, bufsize, PT_BYTEBUF, -1, true);

	return res;
}

FILLER(sys_recv_x, true)
{
	long retval;
	int res;

	retval = bpf_syscall_get_retval(data->ctx);
	res = f_sys_recv_x_common(data, retval);

	return res;
}

FILLER(sys_recvfrom_x, true)
{
	struct sockaddr *usrsockaddr;
	unsigned long val;
	u16 size = 0;
	long retval;
	int addrlen;
	int err = 0;
	int res;
	int fd;

	/*
	 * Push the common params to the ring
	 */
	retval = bpf_syscall_get_retval(data->ctx);
	res = f_sys_recv_x_common(data, retval);
	if (res != PPM_SUCCESS)
		return res;

	if (retval >= 0) {
		/*
		 * Get the address
		 */
		usrsockaddr = (struct sockaddr *)bpf_syscall_get_argument(data, 4);

		/*
		 * Get the address len
		 */
		val = bpf_syscall_get_argument(data, 5);

		if (usrsockaddr && val != 0) {
			if (bpf_probe_read(&addrlen, sizeof(addrlen),
					   (void *)val))
				return PPM_FAILURE_INVALID_USER_MEMORY;

			/*
			 * Copy the address
			 */
			err = bpf_addr_to_kernel(usrsockaddr, addrlen,
						 (struct sockaddr *)data->tmp_scratch);
			if (err >= 0) {
				fd = bpf_syscall_get_argument(data, 0);

				/*
				 * Convert the fd into socket endpoint information
				 */
				size = bpf_fd_to_socktuple(data,
							   fd,
							   (struct sockaddr *)data->tmp_scratch,
							   addrlen,
							   true,
							   true,
							   data->tmp_scratch + sizeof(struct sockaddr_storage));
			}
		}
	}

	/*
	 * Copy the endpoint info into the ring
	 */
	data->curarg_already_on_frame = true;
	res = __bpf_val_to_ring(data, 0, size, PT_SOCKTUPLE, -1, false);

	return res;
}

FILLER(sys_shutdown_e, true)
{
	unsigned int flags;
	unsigned long val;
	int res;

	/*
	 * fd
	 */
	val = bpf_syscall_get_argument(data, 0);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * how
	 */
	val = bpf_syscall_get_argument(data, 1);
	flags = shutdown_how_to_scap(val);
	res = bpf_val_to_ring(data, flags);

	return res;
}

FILLER(sys_recvmsg_x, true)
{
	const struct iovec *iov;
	struct user_msghdr mh;
	unsigned long iovcnt;
	unsigned long val;
	long retval;
	int res;

	/*
	 * res
	 */
	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring_type(data, retval, PT_ERRNO);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * Retrieve the message header
	 */
	val = bpf_syscall_get_argument(data, 1);
	if (bpf_probe_read(&mh, sizeof(mh), (void *)val))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	/*
	 * data and size
	 */
	iov = (const struct iovec *)mh.msg_iov;
	iovcnt = mh.msg_iovlen;

	res = bpf_parse_readv_writev_bufs(data, iov, iovcnt, retval, PRB_FLAG_PUSH_ALL);
	if (res != PPM_SUCCESS)
		return res;

	bpf_tail_call(data->ctx, &tail_map, PPM_FILLER_sys_recvmsg_x_2);
	bpf_printk("Can't tail call f_sys_recvmsg_x_2 filler\n");
	return PPM_FAILURE_BUG;
}

FILLER(sys_recvmsg_x_2, true)
{
	struct sockaddr *usrsockaddr;
	struct user_msghdr mh;
	unsigned long val;
	u16 size = 0;
	long retval;
	int addrlen;
	int res;
	int fd;

	retval = bpf_syscall_get_retval(data->ctx);

	/*
	 * tuple
	 */
	if (retval >= 0) {
		/*
		 * Retrieve the message header
		 */
		val = bpf_syscall_get_argument(data, 1);
		if (bpf_probe_read(&mh, sizeof(mh), (void *)val))
			return PPM_FAILURE_INVALID_USER_MEMORY;

		/*
		 * Get the address
		 */
		usrsockaddr = (struct sockaddr *)mh.msg_name;
		addrlen = mh.msg_namelen;

		if (usrsockaddr && addrlen != 0) {
			/*
			 * Copy the address
			 */
			res = bpf_addr_to_kernel(usrsockaddr,
						 addrlen,
						 (struct sockaddr *)data->tmp_scratch);

			if (res >= 0) {
				fd = bpf_syscall_get_argument(data, 0);

				/*
				 * Convert the fd into socket endpoint information
				 */
				size = bpf_fd_to_socktuple(data,
							   fd,
							   (struct sockaddr *)data->tmp_scratch,
							   addrlen,
							   true,
							   true,
							   data->tmp_scratch + sizeof(struct sockaddr_storage));
			}
		}
	}

	data->curarg_already_on_frame = true;
	res = __bpf_val_to_ring(data, 0, size, PT_SOCKTUPLE, -1, false);

	return res;
}

FILLER(sys_sendmsg_e, true)
{
	struct sockaddr *usrsockaddr;
	const struct iovec *iov;
	struct user_msghdr mh;
	unsigned long iovcnt;
	unsigned long val;
	u16 size = 0;
	int addrlen;
	int err = 0;
	int res;
	int fd;

	/*
	 * fd
	 */
	fd = bpf_syscall_get_argument(data, 0);
	res = bpf_val_to_ring_type(data, fd, PT_FD);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * Retrieve the message header
	 */
	val = bpf_syscall_get_argument(data, 1);
	if (bpf_probe_read(&mh, sizeof(mh), (void *)val))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	/*
	 * size
	 */
	iov = (const struct iovec *)mh.msg_iov;
	iovcnt = mh.msg_iovlen;

	res = bpf_parse_readv_writev_bufs(data, iov, iovcnt, 0,
					  PRB_FLAG_PUSH_SIZE | PRB_FLAG_IS_WRITE);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * tuple
	 */
	usrsockaddr = (struct sockaddr *)mh.msg_name;
	addrlen = mh.msg_namelen;

	if (usrsockaddr && addrlen != 0) {
		/*
		 * Copy the address
		 */
		err = bpf_addr_to_kernel(usrsockaddr,
					 addrlen,
					 (struct sockaddr *)data->tmp_scratch);

		if (err >= 0) {
			/*
			 * Convert the fd into socket endpoint information
			 */
			size = bpf_fd_to_socktuple(data,
						   fd,
						   (struct sockaddr *)data->tmp_scratch,
						   addrlen,
						   true,
						   false,
						   data->tmp_scratch + sizeof(struct sockaddr_storage));
		}
	}

	data->curarg_already_on_frame = true;
	res = __bpf_val_to_ring(data, 0, size, PT_SOCKTUPLE, -1, false);

	return res;
}

FILLER(sys_sendmsg_x, true)
{
	const struct iovec *iov;
	struct user_msghdr mh;
	unsigned long iovcnt;
	unsigned long val;
	long retval;
	int res;

	/*
	 * res
	 */
	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring_type(data, retval, PT_ERRNO);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * data
	 */
	val = bpf_syscall_get_argument(data, 1);
	if (bpf_probe_read(&mh, sizeof(mh), (void *)val))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	iov = (const struct iovec *)mh.msg_iov;
	iovcnt = mh.msg_iovlen;

	res = bpf_parse_readv_writev_bufs(data, iov, iovcnt, retval,
					  PRB_FLAG_PUSH_DATA | PRB_FLAG_IS_WRITE);

	return res;
}

FILLER(sys_pipe_x, true)
{
	unsigned long ino;
	unsigned long val;
	long retval;
	int fds[2];
	int res;

	/*
	 * retval
	 */
	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring(data, retval);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * fds
	 */
	val = bpf_syscall_get_argument(data, 0);
	if (bpf_probe_read(fds, sizeof(fds), (void *)val))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	res = bpf_val_to_ring(data, fds[0]);
	if (res != PPM_SUCCESS)
		return res;

	res = bpf_val_to_ring(data, fds[1]);
	if (res != PPM_SUCCESS)
		return res;

	if (!bpf_get_ino_fd(fds[0], &ino))
		ino = 0;

	res = bpf_val_to_ring(data, ino);

	return res;
}

FILLER(sys_lseek_e, true)
{
	unsigned long flags;
	unsigned long val;
	int res;

	/*
	 * fd
	 */
	val = bpf_syscall_get_argument(data, 0);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * offset
	 */
	val = bpf_syscall_get_argument(data, 1);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * whence
	 */
	val = bpf_syscall_get_argument(data, 2);
	flags = lseek_whence_to_scap(val);
	res = bpf_val_to_ring(data, flags);

	return res;
}

FILLER(sys_llseek_e, true)
{
	unsigned long flags;
	unsigned long val;
	unsigned long oh;
	unsigned long ol;
	u64 offset;
	int res;

	/*
	 * fd
	 */
	val = bpf_syscall_get_argument(data, 0);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * offset
	 * We build it by combining the offset_high and offset_low
	 * system call arguments
	 */
	oh = bpf_syscall_get_argument(data, 1);
	ol = bpf_syscall_get_argument(data, 2);
	offset = (((u64)oh) << 32) + ((u64)ol);
	res = bpf_val_to_ring(data, offset);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * whence
	 */
	val = bpf_syscall_get_argument(data, 4);
	flags = lseek_whence_to_scap(val);
	res = bpf_val_to_ring(data, flags);

	return res;
}

FILLER(sys_eventfd_e, true)
{
	unsigned long val;
	int res;

	/*
	 * initval
	 */
	val = bpf_syscall_get_argument(data, 0);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * flags
	 * XXX not implemented yet
	 */
	res = bpf_val_to_ring(data, 0);

	return res;
}

FILLER(sys_mount_e, true)
{
	unsigned long val;
	int res;

	/*
	 * Fix mount flags in arg 3.
	 * See http://lxr.free-electrons.com/source/fs/namespace.c?v=4.2#L2650
	 */
	val = bpf_syscall_get_argument(data, 3);
	if ((val & PPM_MS_MGC_MSK) == PPM_MS_MGC_VAL)
		val &= ~PPM_MS_MGC_MSK;

	res = bpf_val_to_ring(data, val);

	return res;
}

FILLER(sys_ppoll_e, true)
{
	unsigned long val;
	int res;

	res = bpf_poll_parse_fds(data, true);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * timeout
	 */
	val = bpf_syscall_get_argument(data, 2);

	/* NULL timeout specified as 0xFFFFFF.... */
	if (val == (unsigned long)NULL) {
		res = bpf_val_to_ring_type(data, (u64)(-1), PT_RELTIME);
		if (res != PPM_SUCCESS)
			return res;
	} else {
		res = timespec_parse(data, val);
		if (res != PPM_SUCCESS)
			return res;
	}

	/*
	 * sigmask
	 */
	val = bpf_syscall_get_argument(data, 3);
	if (val != (unsigned long)NULL)
		if (bpf_probe_read(&val, sizeof(val), (void *)val))
			return PPM_FAILURE_INVALID_USER_MEMORY;

	res = bpf_val_to_ring_type(data, val, PT_SIGSET);

	return res;
}

FILLER(sys_semop_x, true)
{
	unsigned long nsops;
	struct sembuf *ptr;
	long retval;
	int res;

	/*
	 * return value
	 */
	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring_type(data, retval, PT_ERRNO);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * nsops
	 * actually this could be read in the enter function but
	 * we also need to know the value to access the sembuf structs
	 */
	nsops = bpf_syscall_get_argument(data, 2);
	res = bpf_val_to_ring_type(data, nsops, PT_UINT32);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * sembuf
	 */
	ptr = (struct sembuf *)bpf_syscall_get_argument(data, 1);

	if (nsops && ptr) {
		int j;

		#pragma unroll 2
		for (j = 0; j < 2; j++) {
			struct sembuf sops = {0, 0, 0};

			if (nsops--)
				if (bpf_probe_read(&sops, sizeof(sops),
						   (void *)&ptr[j]))
					return PPM_FAILURE_INVALID_USER_MEMORY;

			res = bpf_val_to_ring_type(data, sops.sem_num, PT_UINT16);
			if (res != PPM_SUCCESS)
				return res;

			res = bpf_val_to_ring_type(data, sops.sem_op, PT_INT16);
			if (res != PPM_SUCCESS)
				return res;

			res = bpf_val_to_ring_type(data, semop_flags_to_scap(sops.sem_flg), PT_FLAGS16);
			if (res != PPM_SUCCESS)
				return res;
		}
	}

	return res;
}

FILLER(sys_socket_x, true)
{
	long retval;
	int res;

	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring(data, retval);
	if (res != PPM_SUCCESS)
		return res;

	if (retval > 0 &&
	    !data->settings->socket_file_ops) {
		struct file *file = bpf_fget(retval);

		if (file) {
			const struct file_operations *f_op = _READ(file->f_op);

			data->settings->socket_file_ops = (void *)f_op;
		}
	}

	return res;
}

FILLER(sys_flock_e, true)
{
	unsigned int flags;
	unsigned long val;
	int res;

	val = bpf_syscall_get_argument(data, 0);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	val = bpf_syscall_get_argument(data, 1);
	flags = flock_flags_to_scap(val);
	res = bpf_val_to_ring(data, flags);

	return res;
}

FILLER(sys_pread64_e, true)
{
#ifndef _64BIT_ARGS_SINGLE_REGISTER
#error Implement this
#endif
	return PPM_FAILURE_BUG;
}

FILLER(sys_preadv64_e, true)
{
#ifndef _64BIT_ARGS_SINGLE_REGISTER
#error Implement this
#endif
	return PPM_FAILURE_BUG;
}

FILLER(sys_pwrite64_e, true)
{
#ifndef _64BIT_ARGS_SINGLE_REGISTER
#error Implement this
#endif
	return PPM_FAILURE_BUG;
}

FILLER(sys_renameat_x, true)
{
	unsigned long val;
	long retval;
	int res;

	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring(data, retval);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * olddirfd
	 */
	val = bpf_syscall_get_argument(data, 0);

	if ((int)val == AT_FDCWD)
		val = PPM_AT_FDCWD;

	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * oldpath
	 */
	val = bpf_syscall_get_argument(data, 1);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * newdirfd
	 */
	val = bpf_syscall_get_argument(data, 2);

	if ((int)val == AT_FDCWD)
		val = PPM_AT_FDCWD;

	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * newpath
	 */
	val = bpf_syscall_get_argument(data, 3);
	res = bpf_val_to_ring(data, val);

	return res;
}

FILLER(sys_symlinkat_x, true)
{
	unsigned long val;
	long retval;
	int res;

	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring_type(data, retval, PT_ERRNO);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * oldpath
	 */
	val = bpf_syscall_get_argument(data, 0);
	res = bpf_val_to_ring_type(data, val, PT_CHARBUF);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * newdirfd
	 */
	val = bpf_syscall_get_argument(data, 1);

	if ((int)val == AT_FDCWD)
		val = PPM_AT_FDCWD;

	res = bpf_val_to_ring_type(data, val, PT_FD);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * newpath
	 */
	val = bpf_syscall_get_argument(data, 2);
	res = bpf_val_to_ring_type(data, val, PT_CHARBUF);

	return res;
}

FILLER(sys_sysdigevent_e, false)
{
	bpf_printk("f_sys_sysdigevent_e should never be called\n");
	return PPM_FAILURE_BUG;
}

FILLER(cpu_hotplug_e, false)
{
	int res;

	res = bpf_val_to_ring(data, data->state->hotplug_cpu);
	if (res != PPM_SUCCESS)
		return res;

	res = bpf_val_to_ring(data, 0);
	if (res != PPM_SUCCESS)
		return res;

	data->state->hotplug_cpu = 0;

	return res;
}

FILLER(sched_drop, false)
{
	int res;

	/*
	 * ratio
	 */
	res = bpf_val_to_ring(data, data->settings->sampling_ratio);

	return res;
}

FILLER(sys_procexit_e, false)
{
	struct task_struct *task;
	unsigned int flags;
	int exit_code;
	int res;

	task = (struct task_struct *)bpf_get_current_task();

	exit_code = _READ(task->exit_code);

	res = bpf_val_to_ring(data, exit_code);
	if (res != PPM_SUCCESS)
		return res;

#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS
	delete_args();
#endif
	return res;
}

FILLER(sched_switch_e, false)
{
	struct sched_switch_args *ctx;
	struct task_struct *task;
	unsigned long total_vm;
	unsigned long maj_flt;
	unsigned long min_flt;
	struct mm_struct *mm;
	pid_t next_pid;
	long total_rss;
	long swap;
	int res;

	ctx = (struct sched_switch_args *)data->ctx;
#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
	struct task_struct *next_task = (struct task_struct *)ctx->next;

	next_pid = _READ(next_task->pid);
#else
	next_pid = ctx->next_pid;
#endif

	/*
	 * next
	 */
	res = bpf_val_to_ring_type(data, next_pid, PT_PID);
	if (res != PPM_SUCCESS)
		return res;

	task = (struct task_struct *)bpf_get_current_task();

	/*
	 * pgft_maj
	 */
	maj_flt = _READ(task->maj_flt);
	res = bpf_val_to_ring_type(data, maj_flt, PT_UINT64);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * pgft_min
	 */
	min_flt = _READ(task->min_flt);
	res = bpf_val_to_ring_type(data, min_flt, PT_UINT64);
	if (res != PPM_SUCCESS)
		return res;

	total_vm = 0;
	total_rss = 0;
	swap = 0;

	mm = _READ(task->mm);
	if (mm) {
		total_vm = _READ(mm->total_vm);
		total_vm <<= (PAGE_SHIFT - 10);
		total_rss = bpf_get_mm_rss(mm) << (PAGE_SHIFT - 10);
		swap = bpf_get_mm_swap(mm) << (PAGE_SHIFT - 10);
	}

	/*
	 * vm_size
	 */
	res = bpf_val_to_ring_type(data, total_vm, PT_UINT32);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * vm_rss
	 */
	res = bpf_val_to_ring_type(data, total_rss, PT_UINT32);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * vm_swap
	 */
	res = bpf_val_to_ring_type(data, swap, PT_UINT32);

	return res;
}

FILLER(sys_pagefault_e, false)
{
	struct page_fault_args *ctx;
	unsigned long error_code;
	unsigned long address;
	unsigned long ip;
	u32 flags;
	int res;

	ctx = (struct page_fault_args *)data->ctx;
#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
	struct pt_regs *regs = (struct pt_regs *)ctx->regs;

	address = ctx->address;
	ip = _READ(regs->ip);
	error_code = ctx->error_code;
#else
	address = ctx->address;
	ip = ctx->ip;
	error_code = ctx->error_code;
#endif

	res = bpf_val_to_ring(data, address);
	if (res != PPM_SUCCESS)
		return res;

	res = bpf_val_to_ring(data, ip);
	if (res != PPM_SUCCESS)
		return res;

	flags = pf_flags_to_scap(error_code);
	res = bpf_val_to_ring(data, flags);

	return res;
}

FILLER(sys_signaldeliver_e, false)
{
	struct signal_deliver_args *ctx;
	pid_t spid = 0;
	int sig;
	int res;

	ctx = (struct signal_deliver_args *)data->ctx;
#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
	struct siginfo *info = (struct siginfo *)ctx->info;

	sig = ctx->sig;
	if (sig == SIGKILL) {
		spid = _READ(info->_sifields._kill._pid);
	} else if (sig == SIGTERM || sig == SIGHUP || sig == SIGINT ||
		   sig == SIGTSTP || sig == SIGQUIT) {
		int si_code = _READ(info->si_code);

		if (si_code == SI_USER ||
		    si_code == SI_QUEUE ||
		    si_code <= 0) {
			spid = _READ(info->si_pid);
		}
	} else if (sig == SIGCHLD) {
		spid = _READ(info->_sifields._sigchld._pid);
	} else if (sig >= SIGRTMIN && sig <= SIGRTMAX) {
		spid = _READ(info->_sifields._rt._pid);
	}
#else
	sig = ctx->sig;
#endif

	/*
	 * source pid
	 */
	res = bpf_val_to_ring(data, spid);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * destination pid
	 */
	res = bpf_val_to_ring(data, bpf_get_current_pid_tgid() & 0xffffffff);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * signal number
	 */
	res = bpf_val_to_ring(data, sig);

	return res;
}

FILLER(sys_quotactl_e, true)
{
	unsigned long val;
	int res;

	u32 id;
	u8 quota_fmt;
	u16 cmd;

	/*
	 * extract cmd
	 */
	val = bpf_syscall_get_argument(data, 0);
	cmd = quotactl_cmd_to_scap(val);
	res = bpf_val_to_ring_type(data, cmd, PT_FLAGS16);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * extract type
	 */
	res = bpf_val_to_ring_type(data, quotactl_type_to_scap(val), PT_FLAGS8);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 *  extract id
	 */
	id = 0;
	val = bpf_syscall_get_argument(data, 2);
	if (cmd == PPM_Q_GETQUOTA ||
	    cmd == PPM_Q_SETQUOTA ||
	    cmd == PPM_Q_XGETQUOTA ||
	    cmd == PPM_Q_XSETQLIM) {
		/*
		 * in this case id represent an userid or groupid so add it
		 */
		id = val;
	}
	res = bpf_val_to_ring_type(data, id, PT_UINT32);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * extract quota_fmt from id
	 */
	quota_fmt = PPM_QFMT_NOT_USED;
	if (cmd == PPM_Q_QUOTAON)
		quota_fmt = quotactl_fmt_to_scap(val);

	res = bpf_val_to_ring_type(data, quota_fmt, PT_FLAGS8);

	return res;
}

FILLER(sys_quotactl_x, true)
{
	struct if_dqinfo dqinfo = {0};
	struct if_dqblk dqblk = {0};
	const char empty[] = "";
	u32 quota_fmt_out;
	unsigned long val;
	long retval;
	int res;
	u16 cmd;

	/*
	 * extract cmd
	 */
	val = bpf_syscall_get_argument(data, 0);
	cmd = quotactl_cmd_to_scap(val);

	/*
	 * return value
	 */
	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring_type(data, retval, PT_ERRNO);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * Add special
	 */
	val = bpf_syscall_get_argument(data, 1);
	res = bpf_val_to_ring_type(data, val, PT_CHARBUF);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * get addr
	 */
	val = bpf_syscall_get_argument(data, 3);

	/*
	 * get quotafilepath only for QUOTAON
	 */
	if (cmd == PPM_Q_QUOTAON) {
		res = bpf_val_to_ring_type(data, val, PT_CHARBUF);
		if (res != PPM_SUCCESS)
			return res;
	} else {
		res = bpf_val_to_ring_type(data, (unsigned long)empty, PT_CHARBUF);
		if (res != PPM_SUCCESS)
			return res;
	}

	/*
	 * dqblk fields if present
	 */
	if (cmd == PPM_Q_GETQUOTA || cmd == PPM_Q_SETQUOTA) {
		if (bpf_probe_read(&dqblk, sizeof(dqblk),
				   (void *)val))
			return PPM_FAILURE_INVALID_USER_MEMORY;
	}
	if (dqblk.dqb_valid & QIF_BLIMITS) {
		res = bpf_val_to_ring_type(data, dqblk.dqb_bhardlimit, PT_UINT64);
		if (res != PPM_SUCCESS)
			return res;

		res = bpf_val_to_ring_type(data, dqblk.dqb_bsoftlimit, PT_UINT64);
		if (res != PPM_SUCCESS)
			return res;
	} else {
		res = bpf_val_to_ring_type(data, 0, PT_UINT64);
		if (res != PPM_SUCCESS)
			return res;

		res = bpf_val_to_ring_type(data, 0, PT_UINT64);
		if (res != PPM_SUCCESS)
			return res;
	}

	if (dqblk.dqb_valid & QIF_SPACE) {
		res = bpf_val_to_ring_type(data, dqblk.dqb_curspace, PT_UINT64);
		if (res != PPM_SUCCESS)
			return res;
	} else {
		res = bpf_val_to_ring_type(data, 0, PT_UINT64);
		if (res != PPM_SUCCESS)
			return res;
	}

	if (dqblk.dqb_valid & QIF_ILIMITS) {
		res = bpf_val_to_ring_type(data, dqblk.dqb_ihardlimit, PT_UINT64);
		if (res != PPM_SUCCESS)
			return res;
		res = bpf_val_to_ring_type(data, dqblk.dqb_isoftlimit, PT_UINT64);
		if (res != PPM_SUCCESS)
			return res;
	} else {
		res = bpf_val_to_ring_type(data, 0, PT_UINT64);
		if (res != PPM_SUCCESS)
			return res;
		res = bpf_val_to_ring_type(data, 0, PT_UINT64);
		if (res != PPM_SUCCESS)
			return res;
	}

	if (dqblk.dqb_valid & QIF_BTIME) {
		res = bpf_val_to_ring_type(data, dqblk.dqb_btime, PT_RELTIME);
		if (res != PPM_SUCCESS)
			return res;
	} else {
		res = bpf_val_to_ring_type(data, 0, PT_RELTIME);
		if (res != PPM_SUCCESS)
			return res;
	}

	if (dqblk.dqb_valid & QIF_ITIME) {
		res = bpf_val_to_ring_type(data, dqblk.dqb_itime, PT_RELTIME);
		if (res != PPM_SUCCESS)
			return res;
	} else {
		res = bpf_val_to_ring_type(data, 0, PT_RELTIME);
		if (res != PPM_SUCCESS)
			return res;
	}

	/*
	 * dqinfo fields if present
	 */
	if (cmd == PPM_Q_GETINFO || cmd == PPM_Q_SETINFO) {
		if (bpf_probe_read(&dqinfo, sizeof(dqinfo),
				   (void *)val))
			return PPM_FAILURE_INVALID_USER_MEMORY;
	}

	if (dqinfo.dqi_valid & IIF_BGRACE) {
		res = bpf_val_to_ring_type(data, dqinfo.dqi_bgrace, PT_RELTIME);
		if (res != PPM_SUCCESS)
			return res;
	} else {
		res = bpf_val_to_ring_type(data, 0, PT_RELTIME);
		if (res != PPM_SUCCESS)
			return res;
	}

	if (dqinfo.dqi_valid & IIF_IGRACE) {
		res = bpf_val_to_ring_type(data, dqinfo.dqi_igrace, PT_RELTIME);
		if (res != PPM_SUCCESS)
			return res;
	} else {
		res = bpf_val_to_ring_type(data, 0, PT_RELTIME);
		if (res != PPM_SUCCESS)
			return res;
	}

	if (dqinfo.dqi_valid & IIF_FLAGS) {
		res = bpf_val_to_ring_type(data, dqinfo.dqi_flags, PT_FLAGS8);
		if (res != PPM_SUCCESS)
			return res;
	} else {
		res = bpf_val_to_ring_type(data, 0, PT_FLAGS8);
		if (res != PPM_SUCCESS)
			return res;
	}

	quota_fmt_out = PPM_QFMT_NOT_USED;
	if (cmd == PPM_Q_GETFMT) {
		u32 tmp;

		if (bpf_probe_read(&tmp, sizeof(tmp), (void *)val))
			return PPM_FAILURE_INVALID_USER_MEMORY;
		quota_fmt_out = quotactl_fmt_to_scap(tmp);
	}

	res = bpf_val_to_ring_type(data, quota_fmt_out, PT_FLAGS8);

	return res;
}

FILLER(sys_semget_e, true)
{
	unsigned long val;
	int res;

	/*
	 * key
	 */
	val = bpf_syscall_get_argument(data, 0);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * nsems
	 */
	val = bpf_syscall_get_argument(data, 1);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * semflg
	 */
	val = bpf_syscall_get_argument(data, 2);
	res = bpf_val_to_ring(data, semget_flags_to_scap(val));

	return res;
}

FILLER(sys_semctl_e, true)
{
	unsigned long val;
	int res;

	/*
	 * semid
	 */
	val = bpf_syscall_get_argument(data, 0);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * semnum
	 */
	val = bpf_syscall_get_argument(data, 1);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * cmd
	 */
	val = bpf_syscall_get_argument(data, 2);
	res = bpf_val_to_ring(data, semctl_cmd_to_scap(val));
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * optional argument semun/val
	 */
	if (val == SETVAL)
		val = bpf_syscall_get_argument(data, 3);
	else
		val = 0;

	res = bpf_val_to_ring(data, val);

	return res;
}

FILLER(sys_ptrace_e, true)
{
	unsigned long val;
	int res;

	/*
	 * request
	 */
	val = bpf_syscall_get_argument(data, 0);
	res = bpf_val_to_ring(data, ptrace_requests_to_scap(val));
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * pid
	 */
	val = bpf_syscall_get_argument(data, 1);
	res = bpf_val_to_ring(data, val);

	return res;
}

static __always_inline int bpf_parse_ptrace_addr(struct filler_data *data, u16 request)
{
	enum ppm_param_type type;
	unsigned long val;
	u8 idx;

	val = bpf_syscall_get_argument(data, 2);
	switch (request) {
	default:
		idx = PPM_PTRACE_IDX_UINT64;
		type = PT_UINT64;
	}

	return bpf_val_to_ring_dyn(data, val, type, idx);
}

static __always_inline int bpf_parse_ptrace_data(struct filler_data *data, u16 request)
{
	enum ppm_param_type type;
	unsigned long val;
	u64 dst;
	u8 idx;

	val = bpf_syscall_get_argument(data, 3);
	switch (request) {
	case PPM_PTRACE_PEEKTEXT:
	case PPM_PTRACE_PEEKDATA:
	case PPM_PTRACE_PEEKUSR:
		idx = PPM_PTRACE_IDX_UINT64;
		type = PT_UINT64;
		if (bpf_probe_read(&dst, sizeof(long), (void *)val))
			return PPM_FAILURE_INVALID_USER_MEMORY;

		break;
	case PPM_PTRACE_CONT:
	case PPM_PTRACE_SINGLESTEP:
	case PPM_PTRACE_DETACH:
	case PPM_PTRACE_SYSCALL:
		idx = PPM_PTRACE_IDX_SIGTYPE;
		type = PT_SIGTYPE;
		dst = (u64)val;
		break;
	case PPM_PTRACE_ATTACH:
	case PPM_PTRACE_TRACEME:
	case PPM_PTRACE_POKETEXT:
	case PPM_PTRACE_POKEDATA:
	case PPM_PTRACE_POKEUSR:
	default:
		idx = PPM_PTRACE_IDX_UINT64;
		type = PT_UINT64;
		dst = (u64)val;
		break;
	}

	return bpf_val_to_ring_dyn(data, dst, type, idx);
}

FILLER(sys_ptrace_x, true)
{
	unsigned long val;
	u16 request;
	long retval;
	int res;

	/*
	 * res
	 */
	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring_type(data, retval, PT_ERRNO);
	if (res != PPM_SUCCESS)
		return res;

	if (retval < 0) {
		res = bpf_val_to_ring_dyn(data, 0, PT_UINT64, 0);
		if (res != PPM_SUCCESS)
			return res;

		res = bpf_val_to_ring_dyn(data, 0, PT_UINT64, 0);
		if (res != PPM_SUCCESS)
			return res;
	}

	val = bpf_syscall_get_argument(data, 0);
	request = ptrace_requests_to_scap(val);

	res = bpf_parse_ptrace_addr(data, request);
	if (res != PPM_SUCCESS)
		return res;

	res = bpf_parse_ptrace_data(data, request);

	return res;
}

FILLER(sys_bpf_x, true)
{
	unsigned long cmd;
	s64 retval;
	int res;

	retval = bpf_syscall_get_retval(data->ctx);
	cmd = bpf_syscall_get_argument(data, 0);

	/*
	 * fd, depending on cmd
	 */
	if (retval >= 0 && (cmd == BPF_MAP_CREATE || cmd == BPF_PROG_LOAD))
		res = bpf_val_to_ring_dyn(data, retval, PT_FD, PPM_BPF_IDX_FD);
	else
		res = bpf_val_to_ring_dyn(data, retval, PT_ERRNO, PPM_BPF_IDX_RES);

	return res;
}

FILLER(sys_unlinkat_x, true)
{
	unsigned long val;
	long retval;
	int res;

	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring(data, retval);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * dirfd
	 */
	val = bpf_syscall_get_argument(data, 0);
	if ((int)val == AT_FDCWD)
		val = PPM_AT_FDCWD;

	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * name
	 */
	val = bpf_syscall_get_argument(data, 1);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * flags
	 */
	val = bpf_syscall_get_argument(data, 2);
	res = bpf_val_to_ring(data, unlinkat_flags_to_scap(val));

	return res;
}

FILLER(sys_mkdirat_x, true)
{
	unsigned long val;
	long retval;
	int res;

	retval = bpf_syscall_get_retval(data->ctx);
	res = bpf_val_to_ring(data, retval);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * dirfd
	 */
	val = bpf_syscall_get_argument(data, 0);
	if ((int)val == AT_FDCWD)
		val = PPM_AT_FDCWD;

	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * path
	 */
	val = bpf_syscall_get_argument(data, 1);
	res = bpf_val_to_ring(data, val);
	if (res != PPM_SUCCESS)
		return res;

	/*
	 * mode
	 */
	val = bpf_syscall_get_argument(data, 2);
	res = bpf_val_to_ring(data, val);

	return res;
}

FILLER(sys_autofill, true)
{
	const struct ppm_event_entry *evinfo;
	int res;
	int j;

	evinfo = data->filler_info;

	#pragma unroll
	for (j = 0; j < PPM_MAX_AUTOFILL_ARGS; j++) {
		struct ppm_autofill_arg arg = evinfo->autofill_args[j];
		unsigned long val;

		if (j == evinfo->n_autofill_args)
			break;

		if (arg.id >= 0)
			val = bpf_syscall_get_argument(data, arg.id);
		else if (arg.id == AF_ID_RETVAL)
			val = bpf_syscall_get_retval(data->ctx);
		else if (arg.id == AF_ID_USEDEFAULT)
			val = arg.default_val;

		res = bpf_val_to_ring(data, val);
		if (res != PPM_SUCCESS)
			return res;
	}

	return res;
}

#endif
