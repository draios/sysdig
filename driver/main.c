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

#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37))
#include <asm/atomic.h>
#else
#include <linux/atomic.h>
#endif
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kdev_t.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/tracepoint.h>
#include <asm/syscall.h>
#include <net/sock.h>

#include <asm/unistd.h>

#include "ppm_ringbuffer.h"
#include "ppm_events_public.h"
#include "ppm_events.h"
#include "ppm.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Draios");

#define PPM_DEVICE_NAME "sysdig"
#define PPE_DEVICE_NAME PPM_DEVICE_NAME "-events"

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35))
    #define TRACEPOINT_PROBE_REGISTER(p1, p2) tracepoint_probe_register(p1, p2)
    #define TRACEPOINT_PROBE_UNREGISTER(p1, p2) tracepoint_probe_unregister(p1, p2)
    #define TRACEPOINT_PROBE(probe, args...) static void probe(args)
#else
    #define TRACEPOINT_PROBE_REGISTER(p1, p2) tracepoint_probe_register(p1, p2, NULL)
    #define TRACEPOINT_PROBE_UNREGISTER(p1, p2) tracepoint_probe_unregister(p1, p2, NULL)
    #define TRACEPOINT_PROBE(probe, args...) static void probe(void *__data, args)
#endif

struct ppm_device {
	dev_t dev;
	struct cdev cdev;
	wait_queue_head_t read_queue;
};

/*
 * The ring descriptor.
 * We have one of these for each CPU.
 */
struct ppm_ring_buffer_context {
	bool open;
	bool capture_enabled;
	struct ppm_ring_buffer_info *info;
	char *buffer;
	struct timespec last_print_time;
	u32 nevents;
	atomic_t preempt_count;
	char *str_storage;	/* String storage. Size is one page. */
};

/*
 * FORWARD DECLARATIONS
 */
static int ppm_open(struct inode *inode, struct file *filp);
static int ppm_release(struct inode *inode, struct file *filp);
static long ppm_ioctl(struct file *f, unsigned int cmd, unsigned long arg);
static int ppm_mmap(struct file *filp, struct vm_area_struct *vma);
static int record_event(enum ppm_event_type event_type,
	struct pt_regs *regs,
	long id,
	enum syscall_flags drop_flags,
	struct task_struct *sched_prev,
	struct task_struct *sched_next);

static ssize_t ppe_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos);

#ifndef CONFIG_HAVE_SYSCALL_TRACEPOINTS
 #error The kernel must have HAVE_SYSCALL_TRACEPOINTS in order for sysdig to be useful
#endif

TRACEPOINT_PROBE(syscall_enter_probe, struct pt_regs *regs, long id);
TRACEPOINT_PROBE(syscall_exit_probe, struct pt_regs *regs, long ret);
TRACEPOINT_PROBE(syscall_procexit_probe, struct task_struct *p);
#ifdef CAPTURE_CONTEXT_SWITCHES
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35))
TRACEPOINT_PROBE(sched_switch_probe, struct rq *rq, struct task_struct *prev, struct task_struct *next);
#else
TRACEPOINT_PROBE(sched_switch_probe, struct task_struct *prev, struct task_struct *next);
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)) */
#endif /* CAPTURE_CONTEXT_SWITCHES */

DECLARE_BITMAP(g_events_mask, PPM_EVENT_MAX);
static struct ppm_device *g_ppm_devs;
static struct class *g_ppm_class;
static unsigned int g_ppm_numdevs;
static int g_ppm_major;
static const struct file_operations g_ppm_fops = {
	.open = ppm_open,
	.release = ppm_release,
	.mmap = ppm_mmap,
	.unlocked_ioctl = ppm_ioctl,
	.owner = THIS_MODULE,
};

/* Events file operations */
static const struct file_operations g_ppe_fops = {
	.write = ppe_write,
	.owner = THIS_MODULE,
};

/*
 * GLOBALS
 */

static DEFINE_PER_CPU(struct ppm_ring_buffer_context*, g_ring_buffers);
static DEFINE_MUTEX(g_open_mutex);
static u32 g_open_count;
u32 g_snaplen = RW_SNAPLEN;
u32 g_sampling_ratio = 1;
bool g_do_dynamic_snaplen = false;
static u32 g_sampling_interval;
static int g_is_dropping;
static int g_dropping_mode;
static bool g_tracepoint_registered;
static volatile int g_need_to_insert_drop_e = 0;
static volatile int g_need_to_insert_drop_x = 0;

struct cdev *g_ppe_cdev = NULL;
struct device *g_ppe_dev = NULL;

static struct tracepoint *tp_sys_enter;
static struct tracepoint *tp_sys_exit;
static struct tracepoint *tp_sched_process_exit;
#ifdef CAPTURE_CONTEXT_SWITCHES
static struct tracepoint *tp_sched_switch;
#endif

#ifdef _DEBUG
static bool verbose = 1;
#else
static bool verbose = 0;
#endif

#define vpr_info(fmt, ...)					\
do {								\
	if (verbose)						\
		pr_info(fmt, ##__VA_ARGS__);			\
} while (0)

/* compat tracepoint functions */
static int compat_register_trace(void *func, const char *probename, struct tracepoint *tp)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0))
	return TRACEPOINT_PROBE_REGISTER(probename, func);
#else
	return tracepoint_probe_register(tp, func, NULL);
#endif
}

static void compat_unregister_trace(void *func, const char *probename, struct tracepoint *tp)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0))
	TRACEPOINT_PROBE_UNREGISTER(probename, func);
#else
	tracepoint_probe_unregister(tp, func, NULL);
#endif
}

/*
 * user I/O functions
 */
static int ppm_open(struct inode *inode, struct file *filp)
{
	int ret;
	struct ppm_ring_buffer_context *ring;
	int ring_no = iminor(filp->f_dentry->d_inode);

	mutex_lock(&g_open_mutex);

	ring = per_cpu(g_ring_buffers, ring_no);

	if (ring->open) {
		pr_err("invalid operation: attempting to open device %d multiple times\n", ring_no);
		ret = -EBUSY;
		goto cleanup_open;
	}

	vpr_info("opening ring %d\n", ring_no);

	/*
	 * ring->preempt_count is not reset to 0 on purpose, to prevent a race condition:
	 * if the same device is quickly closed and then reopened, record_event() might still be executing 
	 * (with ring->preempt_count to 1) while ppm_open() resets ring->preempt_count to 0. 
	 * When record_event() will exit, it will decrease 
	 * ring->preempt_count which will become < 0, leading to the complete loss of all the events for that CPU.
	 */
	g_dropping_mode = 0;
	g_snaplen = RW_SNAPLEN;
	g_sampling_ratio = 1;
	g_sampling_interval = 0;
	g_is_dropping = 0;
	bitmap_fill(g_events_mask, PPM_EVENT_MAX); /* Enable all syscall to be passed to userspace */
	ring->info->head = 0;
	ring->info->tail = 0;
	ring->nevents = 0;
	ring->info->n_evts = 0;
	ring->info->n_drops_buffer = 0;
	ring->info->n_drops_pf = 0;
	ring->info->n_preemptions = 0;
	ring->info->n_context_switches = 0;
	ring->capture_enabled = true;
	getnstimeofday(&ring->last_print_time);
	ring->open = true;

	if (!g_tracepoint_registered) {
		vpr_info("starting capture\n");
		/*
		 * Enable the tracepoints
		 */
		ret = compat_register_trace(syscall_exit_probe, "sys_exit", tp_sys_exit);
		if (ret) {
			pr_err("can't create the sys_exit tracepoint\n");
			goto err_sys_exit;
		}

		ret = compat_register_trace(syscall_enter_probe, "sys_enter", tp_sys_enter);
		if (ret) {
			pr_err("can't create the sys_enter tracepoint\n");
			goto err_sys_enter;
		}

		ret = compat_register_trace(syscall_procexit_probe, "sched_process_exit", tp_sched_process_exit);
		if (ret) {
			pr_err("can't create the sched_process_exit tracepoint\n");
			goto err_sched_procexit;
		}

#ifdef CAPTURE_CONTEXT_SWITCHES
		ret = compat_register_trace(sched_switch_probe, "sched_switch", tp_sched_switch);
		if (ret) {
			pr_err("can't create the sched_switch tracepoint\n");
			goto err_sched_switch;
		}
#endif
		g_tracepoint_registered = true;
	}

	++g_open_count;
	ret = 0;
	
	goto cleanup_open;

err_sched_switch:
	compat_unregister_trace(syscall_procexit_probe, "sched_process_exit", tp_sched_process_exit);
err_sched_procexit:
	compat_unregister_trace(syscall_enter_probe, "sys_enter", tp_sys_enter);
err_sys_enter:
	compat_unregister_trace(syscall_exit_probe, "sys_exit", tp_sys_exit);
err_sys_exit:
	ring->open = false;
cleanup_open:
	mutex_unlock(&g_open_mutex);

	return ret;
}

static int ppm_release(struct inode *inode, struct file *filp)
{
	int ret;
	struct ppm_ring_buffer_context *ring;
	int ring_no = iminor(filp->f_dentry->d_inode);

	mutex_lock(&g_open_mutex);

	ring = per_cpu(g_ring_buffers, ring_no);

	if (!ring->open) {
		pr_err("attempting to close unopened device %d\n", ring_no);
		ret = -EBUSY;
		goto cleanup_release;
	}

	ring->capture_enabled = false;

	vpr_info("closing ring %d, evt:%llu, dr_buf:%llu, dr_pf:%llu, pr:%llu, cs:%llu\n",
	       ring_no,
	       ring->info->n_evts,
	       ring->info->n_drops_buffer,
	       ring->info->n_drops_pf,
	       ring->info->n_preemptions,
	       ring->info->n_context_switches);

	/*
	 * The last closed device stops event collection
	 */
	--g_open_count;
	if (g_open_count == 0) {
		if (g_tracepoint_registered) {
			vpr_info("stopping capture\n");

			compat_unregister_trace(syscall_exit_probe, "sys_exit", tp_sys_exit);
			compat_unregister_trace(syscall_enter_probe, "sys_enter", tp_sys_enter);
			compat_unregister_trace(syscall_procexit_probe, "sched_process_exit", tp_sched_process_exit);

#ifdef CAPTURE_CONTEXT_SWITCHES
			compat_unregister_trace(sched_switch_probe, "sched_switch", tp_sched_switch);
#endif
			tracepoint_synchronize_unregister();
			g_tracepoint_registered = false;
		} else {
			ASSERT(false);
		}
	}

	ring->open = false;
	ret = 0;

cleanup_release:
	mutex_unlock(&g_open_mutex);

	return ret;
}

static long ppm_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case PPM_IOCTL_DISABLE_CAPTURE:
	{
		int ring_no = iminor(filp->f_dentry->d_inode);
		struct ppm_ring_buffer_context *ring = per_cpu(g_ring_buffers, ring_no);

		mutex_lock(&g_open_mutex);
		ring->capture_enabled = false;
		mutex_unlock(&g_open_mutex);

		vpr_info("PPM_IOCTL_DISABLE_CAPTURE for ring %d\n", ring_no);

		return 0;
	}
	case PPM_IOCTL_ENABLE_CAPTURE:
	{
		int ring_no = iminor(filp->f_dentry->d_inode);
		struct ppm_ring_buffer_context *ring = per_cpu(g_ring_buffers, ring_no);

		mutex_lock(&g_open_mutex);
		ring->capture_enabled = true;
		mutex_unlock(&g_open_mutex);

		vpr_info("PPM_IOCTL_ENABLE_CAPTURE for ring %d\n", ring_no);

		return 0;
	}
	case PPM_IOCTL_DISABLE_DROPPING_MODE:
	{
		g_dropping_mode = 0;
		vpr_info("PPM_IOCTL_DISABLE_DROPPING_MODE\n");
		g_sampling_interval = 1000000000;
		g_sampling_ratio = 1;
		return 0;
	}
	case PPM_IOCTL_ENABLE_DROPPING_MODE:
	{
		u32 new_sampling_ratio;

		g_dropping_mode = 1;
		vpr_info("PPM_IOCTL_ENABLE_DROPPING_MODE\n");

		new_sampling_ratio = (u32)arg;

		if (new_sampling_ratio != 1 &&
			new_sampling_ratio != 2 &&
			new_sampling_ratio != 4 &&
			new_sampling_ratio != 8 &&
			new_sampling_ratio != 16 &&
			new_sampling_ratio != 32 &&
			new_sampling_ratio != 64 &&
			new_sampling_ratio != 128) {
			pr_err("invalid sampling ratio %u\n", new_sampling_ratio);
			return -EINVAL;
		}

		g_sampling_interval = 1000000000 / new_sampling_ratio;
		g_sampling_ratio = new_sampling_ratio;

		vpr_info("new sampling ratio: %d\n", new_sampling_ratio);
		return 0;
	}
	case PPM_IOCTL_SET_SNAPLEN:
	{
		u32 new_snaplen;

		vpr_info("PPM_IOCTL_SET_SNAPLEN\n");
		new_snaplen = (u32)arg;

		if (new_snaplen > RW_MAX_SNAPLEN) {
			pr_err("invalid snaplen %u\n", new_snaplen);
			return -EINVAL;
		}

		g_snaplen = new_snaplen;

		vpr_info("new snaplen: %d\n", g_snaplen);
		return 0;
	}
	case PPM_IOCTL_MASK_ZERO_EVENTS:
	{
		vpr_info("PPM_IOCTL_MASK_ZERO_EVENTS\n");

		bitmap_zero(g_events_mask, PPM_EVENT_MAX);

		/* Used for dropping events so they must stay on */
		set_bit(PPME_DROP_E, g_events_mask);
		set_bit(PPME_DROP_X, g_events_mask);
		return 0;
	}
	case PPM_IOCTL_MASK_SET_EVENT:
	{
		u32 syscall_to_set = (u32)arg;

		vpr_info("PPM_IOCTL_MASK_SET_EVENT (%u)\n", syscall_to_set);

		if (syscall_to_set > PPM_EVENT_MAX) {
			pr_err("invalid syscall %u\n", syscall_to_set);
			return -EINVAL;
		}

		set_bit(syscall_to_set, g_events_mask);
		return 0;
	}
	case PPM_IOCTL_MASK_UNSET_EVENT:
	{
		u32 syscall_to_unset = (u32)arg;

		vpr_info("PPM_IOCTL_MASK_UNSET_EVENT (%u)\n", syscall_to_unset);

		if (syscall_to_unset > NR_syscalls) {
			pr_err("invalid syscall %u\n", syscall_to_unset);
			return -EINVAL;
		}

		clear_bit(syscall_to_unset, g_events_mask);
		return 0;
	}
	case PPM_IOCTL_DISABLE_DYNAMIC_SNAPLEN:
	{
		g_do_dynamic_snaplen = false;
		return 0;
	}
	case PPM_IOCTL_ENABLE_DYNAMIC_SNAPLEN:
	{
		g_do_dynamic_snaplen = true;
		return 0;
	}

	default:
		return -ENOTTY;
	}
}

static int ppm_mmap(struct file *filp, struct vm_area_struct *vma)
{
	if (vma->vm_pgoff == 0) {
		int ret;
		long length = vma->vm_end - vma->vm_start;
		unsigned long useraddr = vma->vm_start;
		unsigned long pfn;
		char *vmalloc_area_ptr;
		char *orig_vmalloc_area_ptr;
		int ring_no = iminor(filp->f_dentry->d_inode);
		struct ppm_ring_buffer_context *ring;

		vpr_info("mmap for CPU %d, start=%lu len=%ld page_size=%lu\n",
		       ring_no,
		       useraddr,
		       length,
		       PAGE_SIZE);

		/*
		 * Enforce ring buffer size
		 */
		if (RING_BUF_SIZE < 2 * PAGE_SIZE) {
			pr_err("Ring buffer size too small (%ld bytes, must be at least %ld bytes\n",
			       (long)RING_BUF_SIZE,
			       (long)PAGE_SIZE);
			return -EIO;
		}

		if (RING_BUF_SIZE / PAGE_SIZE * PAGE_SIZE != RING_BUF_SIZE) {
			pr_err("Ring buffer size is not a multiple of the page size\n");
			return -EIO;
		}

		/*
		 * Retrieve the ring structure for this CPU
		 */
		ring = per_cpu(g_ring_buffers, ring_no);

		if (length <= PAGE_SIZE) {
			/*
			 * When the size requested by the user is smaller than a page, we assume
			 * she's mapping the ring info structure
			 */
			vpr_info("mapping the ring info\n");

			vmalloc_area_ptr = (char *)ring->info;
			orig_vmalloc_area_ptr = vmalloc_area_ptr;

			pfn = vmalloc_to_pfn(vmalloc_area_ptr);

			ret = remap_pfn_range(vma, useraddr, pfn,
					      PAGE_SIZE, PAGE_SHARED);
			if (ret < 0) {
				pr_err("remap_pfn_range failed (1)\n");
				return ret;
			}

			return 0;
		} else if (length == RING_BUF_SIZE * 2) {
			long mlength;

			/*
			 * When the size requested by the user equals the ring buffer size, we map the full
			 * buffer
			 */
			vpr_info("mapping the data buffer\n");

			vmalloc_area_ptr = (char *)ring->buffer;
			orig_vmalloc_area_ptr = vmalloc_area_ptr;

			/*
			 * Validate that the buffer access is read only
			 */
			if (vma->vm_flags & VM_WRITE) {
				pr_err("invalid mmap flags 0x%lx\n", vma->vm_flags);
				return -EIO;
			}

			/*
			 * Map each single page of the buffer
			 */
			mlength = length / 2;

			while (mlength > 0) {
				pfn = vmalloc_to_pfn(vmalloc_area_ptr);

				ret = remap_pfn_range(vma, useraddr, pfn,
						      PAGE_SIZE, PAGE_SHARED);
				if (ret < 0) {
					pr_err("remap_pfn_range failed (1)\n");
					return ret;
				}

				useraddr += PAGE_SIZE;
				vmalloc_area_ptr += PAGE_SIZE;
				mlength -= PAGE_SIZE;
			}

			/*
			 * Remap a second copy of the buffer pages at the end of the buffer.
			 * This effectively mirrors the buffer at its end and helps simplify buffer management in userland.
			 */
			vmalloc_area_ptr = orig_vmalloc_area_ptr;
			mlength = length / 2;

			while (mlength > 0) {
				pfn = vmalloc_to_pfn(vmalloc_area_ptr);

				ret = remap_pfn_range(vma, useraddr, pfn,
						      PAGE_SIZE, PAGE_SHARED);
				if (ret < 0) {
					pr_err("remap_pfn_range failed (1)\n");
					return ret;
				}

				useraddr += PAGE_SIZE;
				vmalloc_area_ptr += PAGE_SIZE;
				mlength -= PAGE_SIZE;
			}

			return 0;
		} else {
			pr_err("Invalid mmap size %ld\n", length);
			return -EIO;
		}
	}

	pr_err("invalid pgoff %lu, must be 0\n", vma->vm_pgoff);
	return -EIO;
}

static ssize_t ppe_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
	return count;
}

/* Argument list sizes for sys_socketcall */
#define AL(x) ((x) * sizeof(unsigned long))
static const unsigned char nas[21] = {
	AL(0), AL(3), AL(3), AL(3), AL(2), AL(3),
	AL(3), AL(3), AL(4), AL(4), AL(4), AL(6),
	AL(6), AL(2), AL(5), AL(5), AL(3), AL(3),
	AL(4), AL(5), AL(4)
};
#undef AL

#ifdef __NR_socketcall
static enum ppm_event_type parse_socketcall(struct event_filler_arguments *filler_args, struct pt_regs *regs)
{
	unsigned long __user args[2];
	unsigned long __user *scargs;
	int socketcall_id;

	syscall_get_arguments(current, regs, 0, 2, args);
	socketcall_id = args[0];
	scargs = (unsigned long __user *)args[1];

	if (unlikely(socketcall_id < SYS_SOCKET ||
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
		socketcall_id > SYS_SENDMMSG))
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
		socketcall_id > SYS_RECVMMSG))
#else
		socketcall_id > SYS_ACCEPT4))
#endif
		return PPME_GENERIC_E;

	if (unlikely(ppm_copy_from_user(filler_args->socketcall_args, scargs, nas[socketcall_id])))
		return PPME_GENERIC_E;

	switch (socketcall_id) {
	case SYS_SOCKET:
		return PPME_SOCKET_SOCKET_E;
	case SYS_BIND:
		return PPME_SOCKET_BIND_E;
	case SYS_CONNECT:
		return PPME_SOCKET_CONNECT_E;
	case SYS_LISTEN:
		return PPME_SOCKET_LISTEN_E;
	case SYS_ACCEPT:
		return PPME_SOCKET_ACCEPT_E;
	case SYS_GETSOCKNAME:
		return PPME_SOCKET_GETSOCKNAME_E;
	case SYS_GETPEERNAME:
		return PPME_SOCKET_GETPEERNAME_E;
	case SYS_SOCKETPAIR:
		return PPME_SOCKET_SOCKETPAIR_E;
	case SYS_SEND:
		return PPME_SOCKET_SEND_E;
	case SYS_SENDTO:
		return PPME_SOCKET_SENDTO_E;
	case SYS_RECV:
		return PPME_SOCKET_RECV_E;
	case SYS_RECVFROM:
		return PPME_SOCKET_RECVFROM_E;
	case SYS_SHUTDOWN:
		return PPME_SOCKET_SHUTDOWN_E;
	case SYS_SETSOCKOPT:
		return PPME_SOCKET_SETSOCKOPT_E;
	case SYS_GETSOCKOPT:
		return PPME_SOCKET_GETSOCKOPT_E;
	case SYS_SENDMSG:
		return PPME_SOCKET_SENDMSG_E;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
	case SYS_SENDMMSG:
		return PPME_SOCKET_SENDMMSG_E;
#endif
	case SYS_RECVMSG:
		return PPME_SOCKET_RECVMSG_E;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	case SYS_RECVMMSG:
		return PPME_SOCKET_RECVMMSG_E;
#endif
	case SYS_ACCEPT4:
		return PPME_SOCKET_ACCEPT4_E;
	default:
		ASSERT(false);
		return PPME_GENERIC_E;
	}
}
#endif /* __NR_socketcall */

static inline void record_drop_e(void){
	if (record_event(PPME_DROP_E, NULL, -1, UF_NEVER_DROP, NULL, NULL) == 0) {
		g_need_to_insert_drop_e = 1;
	} else {
		if (g_need_to_insert_drop_e == 1) {
			pr_err("drop enter event delayed insert\n");
		}

		g_need_to_insert_drop_e = 0;
	}
}

static inline void record_drop_x(void){
	if (record_event(PPME_DROP_X, NULL, -1, UF_NEVER_DROP, NULL, NULL) == 0) {
		g_need_to_insert_drop_x = 1;
	} else {
		if (g_need_to_insert_drop_x == 1) {
			pr_err("drop exit event delayed insert\n");
		}

		g_need_to_insert_drop_x = 0;
	}
}

static inline int drop_event(enum ppm_event_type event_type, enum syscall_flags drop_flags, struct timespec *ts)
{
	if (drop_flags & UF_NEVER_DROP) {
		ASSERT((drop_flags & UF_ALWAYS_DROP) == 0);
		return 0;
	}

	if (g_dropping_mode) {
		if (drop_flags & UF_ALWAYS_DROP) {
			ASSERT((drop_flags & UF_NEVER_DROP) == 0);
			return 1;
		}
	
		if (ts->tv_nsec >= g_sampling_interval) {
			if (g_is_dropping == 0) {
				g_is_dropping = 1;
					record_drop_e();
			}

			return 1;
		} else {
			if (g_is_dropping == 1) {
				g_is_dropping = 0;
					record_drop_x();
			}
		}
	}

	return 0;
}

/*
 * Returns 0 if the event is dropped
 */
static int record_event(enum ppm_event_type event_type,
	struct pt_regs *regs,
	long id,
	enum syscall_flags drop_flags,
	struct task_struct *sched_prev,
	struct task_struct *sched_next)
{
	int res = 0;
	size_t event_size;
	int next;
	u32 freespace;
	u32 usedspace;
	struct event_filler_arguments args;
	u32 ttail;
	u32 head;
	struct ppm_ring_buffer_context *ring;
	struct ppm_ring_buffer_info *ring_info;
	int drop = 1;
	int32_t cbres = PPM_SUCCESS;
	struct timespec ts;

	getnstimeofday(&ts);

	if (!test_bit(event_type, g_events_mask))
		return res;

	if (event_type != PPME_DROP_E && event_type != PPME_DROP_X) {
		if (g_need_to_insert_drop_e == 1) {
			record_drop_e();
		} else if(g_need_to_insert_drop_x == 1) {
			record_drop_x();
		}

		if (drop_event(event_type, drop_flags, &ts))
			return res;
	}

	/*
	 * FROM THIS MOMENT ON, WE HAVE TO BE SUPER FAST
	 */
	ring = get_cpu_var(g_ring_buffers);
	ring_info = ring->info;

	if (!ring->capture_enabled) {
		put_cpu_var(g_ring_buffers);
		return res;
	}

	ring_info->n_evts++;
	if (sched_prev != NULL) {
		ASSERT(sched_prev != NULL);
		ASSERT(sched_next != NULL);
		ASSERT(regs == NULL);
		ring_info->n_context_switches++;
	}

	/*
	 * Preemption gate
	 */
	if (unlikely(atomic_inc_return(&ring->preempt_count) != 1)) {
		atomic_dec(&ring->preempt_count);
		put_cpu_var(g_ring_buffers);
		ring_info->n_preemptions++;
		ASSERT(false);
		return res;
	}

	/*
	 * Calculate the space currently available in the buffer
	 */
	head = ring_info->head;
	ttail = ring_info->tail;

	if (ttail > head)
		freespace = ttail - head - 1;
	else
		freespace = RING_BUF_SIZE + ttail - head - 1;

	usedspace = RING_BUF_SIZE - freespace - 1;

	ASSERT(freespace <= RING_BUF_SIZE);
	ASSERT(usedspace <= RING_BUF_SIZE);
	ASSERT(ttail <= RING_BUF_SIZE);
	ASSERT(head <= RING_BUF_SIZE);

#ifdef __NR_socketcall
	/*
	 * If this is a socketcall system call, determine the correct event type
	 * by parsing the arguments and patch event_type accordingly
	 * A bit of explanation: most linux architectures don't have a separate
	 * syscall for each of the socket functions (bind, connect...). Instead,
	 * the socket functions are aggregated into a single syscall, called
	 * socketcall. The first socketcall argument is the call type, while the
	 * second argument contains a pointer to the arguments of the original
	 * call. I guess this was done to reduce the number of syscalls...
	 */
	if (regs && id == __NR_socketcall) {
		enum ppm_event_type tet;

		tet = parse_socketcall(&args, regs);

		if (event_type == PPME_GENERIC_E)
			event_type = tet;
		else
			event_type = tet + 1;
	}
#endif

	ASSERT(event_type < PPM_EVENT_MAX);

	/*
	 * Determine how many arguments this event has
	 */
	args.nargs = g_event_info[event_type].nparams;
	args.arg_data_offset = args.nargs * sizeof(u16);

	/*
	 * Make sure we have enough space for the event header.
	 * We need at least space for the header plus 16 bit per parameter for the lengths.
	 */
	if (likely(freespace >= sizeof(struct ppm_evt_hdr) + args.arg_data_offset)) {
		/*
		 * Populate the header
		 */
		struct ppm_evt_hdr *hdr = (struct ppm_evt_hdr *)(ring->buffer + head);

#ifdef PPM_ENABLE_SENTINEL
		hdr->sentinel_begin = ring->nevents;
#endif
		hdr->ts = timespec_to_ns(&ts);
		hdr->tid = current->pid;
		hdr->type = event_type;

		/*
		 * Populate the parameters for the filler callback
		 */
		args.buffer = ring->buffer + head + sizeof(struct ppm_evt_hdr);
#ifdef PPM_ENABLE_SENTINEL
		args.sentinel = ring->nevents;
#endif
		args.buffer_size = min(freespace, (u32)(2 * PAGE_SIZE)) - sizeof(struct ppm_evt_hdr); /* freespace is guaranteed to be bigger than sizeof(struct ppm_evt_hdr) */
		args.event_type = event_type;
		args.regs = regs;
		args.sched_prev = sched_prev;
		args.sched_next = sched_next;
		args.syscall_id = id;
		args.curarg = 0;
		args.arg_data_size = args.buffer_size - args.arg_data_offset;
		args.nevents = ring->nevents;
		args.str_storage = ring->str_storage;
		args.enforce_snaplen = false;

		/*
		 * Fire the filler callback
		 */
		if (g_ppm_events[event_type].filler_callback == PPM_AUTOFILL) {
			/*
			 * This event is automatically filled. Hand it to f_sys_autofill.
			 */
			cbres = f_sys_autofill(&args, &g_ppm_events[event_type]);
		} else {
			/*
			 * There's a callback function for this event
			 */
			cbres = g_ppm_events[event_type].filler_callback(&args);
		}

		if (likely(cbres == PPM_SUCCESS)) {			
			/*
			 * Validate that the filler added the right number of parameters
			 */
			if (likely(args.curarg == args.nargs)) {
				/*
				 * The event was successfully insterted in the buffer
				 */
				event_size = sizeof(struct ppm_evt_hdr) + args.arg_data_offset;
				hdr->len = event_size;
				drop = 0;
			} else {
				pr_err("corrupted filler for event type %d (added %u args, should have added %u)\n",
				       event_type,
				       args.curarg,
				       args.nargs);
				ASSERT(0);
			}
		}
	}

	if (likely(!drop)) {
		res = 1;

		next = head + event_size;

		if (unlikely(next >= RING_BUF_SIZE)) {
			/*
			 * If something has been written in the cushion space at the end of
			 * the buffer, copy it to the beginning and wrap the head around.
			 * Note, we don't check that the copy fits because we assume that
			 * filler_callback failed if the space was not enough.
			 */
			if (next > RING_BUF_SIZE) {
				memcpy(ring->buffer,
				ring->buffer + RING_BUF_SIZE,
				next - RING_BUF_SIZE);
			}

			next -= RING_BUF_SIZE;
		}

		/*
		 * Make sure all the memory has been written in real memory before
		 * we update the head and the user space process (on another CPU)
		 * can access the buffer.
		 */
		smp_wmb();

		ring_info->head = next;

		++ring->nevents;
	} else {
		if (cbres == PPM_SUCCESS) {
			ASSERT(freespace < sizeof(struct ppm_evt_hdr) + args.arg_data_offset);
			ring_info->n_drops_buffer++;
		} else if (cbres == PPM_FAILURE_INVALID_USER_MEMORY) {
#ifdef _DEBUG
			pr_err("Invalid read from user for event %d\n", event_type);
#endif
			ring_info->n_drops_pf++;
		} else if (cbres == PPM_FAILURE_BUFFER_FULL) {
			ring_info->n_drops_buffer++;
		} else {
			ASSERT(false);
		}
	}

#ifdef _DEBUG
	if (ts.tv_sec > ring->last_print_time.tv_sec + 1) {
		vpr_info("CPU%d, use:%d%%, ev:%llu, dr_buf:%llu, dr_pf:%llu, pr:%llu, cs:%llu\n",
		       smp_processor_id(),
		       (usedspace * 100) / RING_BUF_SIZE,
		       ring_info->n_evts,
		       ring_info->n_drops_buffer,
		       ring_info->n_drops_pf,
		       ring_info->n_preemptions,
		       ring->info->n_context_switches);

		ring->last_print_time = ts;
	}
#endif

	atomic_dec(&ring->preempt_count);
	put_cpu_var(g_ring_buffers);

	return res;
}

TRACEPOINT_PROBE(syscall_enter_probe, struct pt_regs *regs, long id)
{
	long table_index;

#ifdef CONFIG_X86_64
	/*
	 * If this is a 32bit process running on a 64bit kernel (see the CONFIG_IA32_EMULATION
	 * kernel flag), we skip its events.
	 * XXX Decide what to do about this.
	 */
	if (unlikely(test_tsk_thread_flag(current, TIF_IA32)))
		return;
#endif

	table_index = id - SYSCALL_TABLE_ID0;
	if (likely(table_index >= 0 && table_index < SYSCALL_TABLE_SIZE)) {
		int used = g_syscall_table[table_index].flags & UF_USED;
		enum syscall_flags drop_flags = g_syscall_table[table_index].flags;

		if (used)
			record_event(g_syscall_table[table_index].enter_event_type, regs, id, drop_flags, NULL, NULL);
		else
			record_event(PPME_GENERIC_E, regs, id, UF_ALWAYS_DROP, NULL, NULL);
	}
}

TRACEPOINT_PROBE(syscall_exit_probe, struct pt_regs *regs, long ret)
{
	int id;
	long table_index;

#ifdef CONFIG_X86_64
	/*
     * If this is a 32bit process running on a 64bit kernel (see the CONFIG_IA32_EMULATION
	 * kernel flag), we skip its events.
	 * XXX Decide what to do about this.
	 */
	if (unlikely(test_tsk_thread_flag(current, TIF_IA32)))
		return;
#endif

	id = syscall_get_nr(current, regs);

	table_index = id - SYSCALL_TABLE_ID0;
	if (likely(table_index >= 0 && table_index < SYSCALL_TABLE_SIZE)) {
		int used = g_syscall_table[table_index].flags & UF_USED;
		enum syscall_flags drop_flags = g_syscall_table[table_index].flags;

		if (used)
			record_event(g_syscall_table[table_index].exit_event_type, regs, id, drop_flags, NULL, NULL);
		else
			record_event(PPME_GENERIC_X, regs, id, UF_ALWAYS_DROP, NULL, NULL);
	}
}

int __access_remote_vm(struct task_struct *t, struct mm_struct *mm, unsigned long addr,
		       void *buf, int len, int write);

TRACEPOINT_PROBE(syscall_procexit_probe, struct task_struct *p)
{
	if (unlikely(current->flags & PF_KTHREAD)) {
		/*
		 * We are not interested in kernel threads
		 */
		return;
	}

	record_event(PPME_PROCEXIT_E, NULL, -1, UF_NEVER_DROP, NULL, NULL);
}

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#ifdef CAPTURE_CONTEXT_SWITCHES
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35))
TRACEPOINT_PROBE(sched_switch_probe, struct rq *rq, struct task_struct *prev, struct task_struct *next)
#else
TRACEPOINT_PROBE(sched_switch_probe, struct task_struct *prev, struct task_struct *next)
#endif
{
	record_event(PPME_SCHEDSWITCH_6_E,
		NULL,
		-1,
		UF_USED,
		prev,
		next);
}
#endif

static struct ppm_ring_buffer_context *alloc_ring_buffer(struct ppm_ring_buffer_context **ring)
{
	unsigned int j;

	/*
	 * Allocate the ring descriptor
	 */
	*ring = vmalloc(sizeof(struct ppm_ring_buffer_context));
	if (*ring == NULL) {
		pr_err("Error allocating ring memory\n");
		return NULL;
	}

	/*
	 * Allocate the string storage in the ring descriptor
	 */
	(*ring)->str_storage = (char *)__get_free_page(GFP_USER);
	if (!(*ring)->str_storage) {
		pr_err("Error allocating the string storage\n");
		goto err_str_storage;
	}

	/*
	 * Allocate the buffer.
	 * Note how we allocate 2 additional pages: they are used as additional overflow space for
	 * the event data generation functions, so that they always operate on a contiguous buffer.
	 */
	(*ring)->buffer = vmalloc(RING_BUF_SIZE + 2 * PAGE_SIZE);
	if ((*ring)->buffer == NULL) {
		pr_err("Error allocating ring memory\n");
		goto err_buffer;
	}

	for (j = 0; j < RING_BUF_SIZE + 2 * PAGE_SIZE; j++)
		(*ring)->buffer[j] = 0;

	/*
	 * Allocate the buffer info structure
	 */
	(*ring)->info = vmalloc(sizeof(struct ppm_ring_buffer_info));
	if ((*ring)->info == NULL) {
		pr_err("Error allocating ring memory\n");
		goto err_ring_info;
	}

	/*
	 * Initialize the buffer info structure
	 */
	(*ring)->open = false;
	(*ring)->capture_enabled = false;
	(*ring)->info->head = 0;
	(*ring)->info->tail = 0;
	(*ring)->nevents = 0;
	(*ring)->info->n_evts = 0;
	(*ring)->info->n_drops_buffer = 0;
	(*ring)->info->n_drops_pf = 0;
	(*ring)->info->n_preemptions = 0;
	(*ring)->info->n_context_switches = 0;
	atomic_set(&(*ring)->preempt_count, 0);
	getnstimeofday(&(*ring)->last_print_time);

	pr_info("CPU buffer initialized, size=%d\n", RING_BUF_SIZE);

	return *ring;

err_ring_info:
	vfree((void *)(*ring)->buffer);
err_buffer:
	free_page((unsigned long)(*ring)->str_storage);
err_str_storage:
	vfree(*ring);

	return NULL;
}

static void free_ring_buffer(struct ppm_ring_buffer_context *ring)
{
	vfree(ring->info);
	vfree((void *)ring->buffer);
	free_page((unsigned long)ring->str_storage);
	vfree(ring);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0))
static void visit_tracepoint(struct tracepoint *tp, void *priv)
{
	if (!strcmp(tp->name, "sys_enter"))
		tp_sys_enter = tp;
	else if (!strcmp(tp->name, "sys_exit"))
		tp_sys_exit = tp;
	else if (!strcmp(tp->name, "sched_process_exit"))
		tp_sched_process_exit = tp;
#ifdef CAPTURE_CONTEXT_SWITCHES
	else if (!strcmp(tp->name, "sched_switch"))
		tp_sched_switch = tp;
#endif
}

static int get_tracepoint_handles(void)
{
	for_each_kernel_tracepoint(visit_tracepoint, NULL);

	if (!tp_sys_enter) {
		pr_err("failed to find sys_enter tracepoint\n");
		return -ENOENT;
	}
	if (!tp_sys_exit) {
		pr_err("failed to find sys_exit tracepoint\n");
		return -ENOENT;
	}
	if (!tp_sched_process_exit) {
		pr_err("failed to find sched_process_exit tracepoint\n");
		return -ENOENT;
	}
#ifdef CAPTURE_CONTEXT_SWITCHES
	if (!tp_sched_switch) {
		pr_err("failed to find sched_switch tracepoint\n");
		return -ENOENT;
	}
#endif

	return 0;
}
#else
static int get_tracepoint_handles(void)
{
	return 0;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
static char *ppm_devnode(struct device *dev, umode_t *mode)
#else
static char *ppm_devnode(struct device *dev, mode_t *mode)
#endif
{
	if (mode) {
		*mode = 0400;

		if (dev)
			if (MINOR(dev->devt) == g_ppm_numdevs)
				*mode = 0222;
	}

	return NULL;
}

int sysdig_init(void)
{
	dev_t dev;
	unsigned int cpu;
	unsigned int num_cpus;
	int ret;
	int acrret = 0;
	int j;
	int n_created_devices = 0;
	struct device *device = NULL;

	pr_info("driver loading\n");

	ret = get_tracepoint_handles();
	if (ret < 0)
		goto init_module_err;

	/*
	 * Initialize the ring buffers array
	 */
	num_cpus = 0;
	for_each_online_cpu(cpu) {
		per_cpu(g_ring_buffers, cpu) = NULL;
		++num_cpus;
	}

	for_each_online_cpu(cpu) {
		pr_info("initializing ring buffer for CPU %u\n", cpu);

		alloc_ring_buffer(&per_cpu(g_ring_buffers, cpu));
		if (per_cpu(g_ring_buffers, cpu) == NULL) {
			pr_err("can't initialize the ring buffer for CPU %u\n", cpu);
			ret = -ENOMEM;
			goto init_module_err;
		}
	}

	/*
	 * Initialize the user I/O
	 * ( + 1 for sysdig-events)
	 */
	acrret = alloc_chrdev_region(&dev, 0, num_cpus + 1, PPM_DEVICE_NAME);
	if (acrret < 0) {
		pr_err("could not allocate major number for %s\n", PPM_DEVICE_NAME);
		ret = -ENOMEM;
		goto init_module_err;
	}

	g_ppm_class = class_create(THIS_MODULE, PPM_DEVICE_NAME);
	if (IS_ERR(g_ppm_class)) {
		pr_err("can't allocate device class\n");
		ret = -EFAULT;
		goto init_module_err;
	}

	g_ppm_class->devnode = ppm_devnode;

	g_ppm_major = MAJOR(dev);
	g_ppm_numdevs = num_cpus;
	g_ppm_devs = kmalloc(g_ppm_numdevs * sizeof(struct ppm_device), GFP_KERNEL);
	if (!g_ppm_devs) {
		pr_err("can't allocate devices\n");
		ret = -ENOMEM;
		goto init_module_err;
	}

	/*
	 * We create a unique user level device for each of the ring buffers
	 */
	for (j = 0; j < g_ppm_numdevs; ++j) {
		cdev_init(&g_ppm_devs[j].cdev, &g_ppm_fops);
		g_ppm_devs[j].dev = MKDEV(g_ppm_major, j);

		if (cdev_add(&g_ppm_devs[j].cdev, g_ppm_devs[j].dev, 1) < 0) {
			pr_err("could not allocate chrdev for %s\n", PPM_DEVICE_NAME);
			ret = -EFAULT;
			goto init_module_err;
		}

		device = device_create(g_ppm_class, NULL, /* no parent device */
				       g_ppm_devs[j].dev,
				       NULL, /* no additional data */
				       PPM_DEVICE_NAME "%d",
				       j);

		if (IS_ERR(device)) {
			pr_err("error creating the device for  %s\n", PPM_DEVICE_NAME);
			cdev_del(&g_ppm_devs[j].cdev);
			ret = -EFAULT;
			goto init_module_err;
		}

		init_waitqueue_head(&g_ppm_devs[j].read_queue);
		n_created_devices++;
	}

	/* create_proc_read_entry(PPM_DEVICE_NAME, 0, NULL, ppm_read_proc, NULL); */

	g_ppe_cdev = cdev_alloc();
	if (g_ppe_cdev == NULL) {
		pr_err("error allocating the device %s\n", PPE_DEVICE_NAME);
		ret = -ENOMEM;
		goto init_module_err;
	}

	cdev_init(g_ppe_cdev, &g_ppe_fops);

	if (cdev_add(g_ppe_cdev, MKDEV(g_ppm_major, g_ppm_numdevs), 1) < 0) {
		pr_err("could not allocate chrdev for %s\n", PPE_DEVICE_NAME);
		ret = -EFAULT;
		goto init_module_err;
	}

	g_ppe_dev = device_create(g_ppm_class, NULL,
			MKDEV(g_ppm_major, g_ppm_numdevs),
			NULL, /* no additional data */
			PPE_DEVICE_NAME);

	if (IS_ERR(g_ppe_dev)) {
		pr_err("error creating the device for  %s\n", PPE_DEVICE_NAME);
		ret = -EFAULT;
		goto init_module_err;
	}

	/*
	 * Snaplen lookahead initialization
	 */
	if (dpi_lookahead_init() != PPM_SUCCESS) {
		pr_err("initializing lookahead-based snaplen  %s\n", PPE_DEVICE_NAME);
		ret = -EFAULT;
		goto init_module_err;
	}

	/*
	 * All ok. Final initalizations.
	 */
	g_open_count = 0;
	g_tracepoint_registered = false;
	g_dropping_mode = 0;

	return 0;

init_module_err:
	for_each_online_cpu(cpu)
		if (per_cpu(g_ring_buffers, cpu) != NULL)
			free_ring_buffer(per_cpu(g_ring_buffers, cpu));

	/* remove_proc_entry(PPM_DEVICE_NAME, NULL); */

	if (g_ppe_dev != NULL)
		device_destroy(g_ppm_class, MKDEV(g_ppm_major, g_ppm_numdevs));

	if (g_ppe_cdev != NULL)
		cdev_del(g_ppe_cdev);

	for (j = 0; j < n_created_devices; ++j) {
		device_destroy(g_ppm_class, g_ppm_devs[j].dev);
		cdev_del(&g_ppm_devs[j].cdev);
	}

	if (g_ppm_class)
		class_destroy(g_ppm_class);

	if (acrret == 0)
		unregister_chrdev_region(dev, g_ppm_numdevs);

	kfree(g_ppm_devs);

	return ret;
}

void sysdig_exit(void)
{
	int j;
	int cpu;

	pr_info("driver unloading\n");

	/* remove_proc_entry(PPM_DEVICE_NAME, NULL); */

	for_each_online_cpu(cpu)
		free_ring_buffer(per_cpu(g_ring_buffers, cpu));

	for (j = 0; j < g_ppm_numdevs; ++j) {
		device_destroy(g_ppm_class, g_ppm_devs[j].dev);
		cdev_del(&g_ppm_devs[j].cdev);
	}

	if (g_ppe_dev != NULL)
		device_destroy(g_ppm_class, MKDEV(g_ppm_major, g_ppm_numdevs));

	if (g_ppe_cdev != NULL)
		cdev_del(g_ppe_cdev);

	if (g_ppm_class)
		class_destroy(g_ppm_class);

	/* + 1 for sysdig-events */
	unregister_chrdev_region(MKDEV(g_ppm_major, 0), g_ppm_numdevs + 1);

	kfree(g_ppm_devs);

	tracepoint_synchronize_unregister();
}

module_init(sysdig_init);
module_exit(sysdig_exit);
module_param(verbose, bool, 0);
