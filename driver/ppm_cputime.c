#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0))

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

#define cmpxchg_cputime(ptr, old, new) cmpxchg(ptr, old, new)

#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN
static unsigned long long vtime_delta(struct task_struct *tsk)
{
	unsigned long long clock;

	clock = local_clock();
	if (clock < tsk->vtime_snap)
		return 0;

	return clock - tsk->vtime_snap;
}

static void
fetch_task_cputime(struct task_struct *t,
		   cputime_t *u_dst, cputime_t *s_dst,
		   cputime_t *u_src, cputime_t *s_src,
		   cputime_t *udelta, cputime_t *sdelta)
{
	unsigned int seq;
	unsigned long long delta;

	do {
		*udelta = 0;
		*sdelta = 0;

		seq = read_seqbegin(&t->vtime_seqlock);

		if (u_dst)
			*u_dst = *u_src;
		if (s_dst)
			*s_dst = *s_src;

		/* Task is sleeping, nothing to add */
		if (t->vtime_snap_whence == VTIME_SLEEPING ||
		    is_idle_task(t))
			continue;

		delta = vtime_delta(t);

		/*
		 * Task runs either in user or kernel space, add pending nohz time to
		 * the right place.
		 */
		if (t->vtime_snap_whence == VTIME_USER || t->flags & PF_VCPU) {
			*udelta = delta;
		} else {
			if (t->vtime_snap_whence == VTIME_SYS)
				*sdelta = delta;
		}
	} while (read_seqretry(&t->vtime_seqlock, seq));
}

void task_cputime(struct task_struct *t, cputime_t *utime, cputime_t *stime)
{
	cputime_t udelta, sdelta;

	fetch_task_cputime(t, utime, stime, &t->utime,
			   &t->stime, &udelta, &sdelta);
	if (utime)
		*utime += udelta;
	if (stime)
		*stime += sdelta;
}
#endif

#ifdef CONFIG_VIRT_CPU_ACCOUNTING_NATIVE
void task_cputime_adjusted(struct task_struct *p, cputime_t *ut, cputime_t *st)
{
	*ut = p->utime;
	*st = p->stime;
}
#else /* !CONFIG_VIRT_CPU_ACCOUNTING_NATIVE */
/*
 * Perform (stime * rtime) / total, but avoid multiplication overflow by
 * loosing precision when the numbers are big.
 */
static cputime_t scale_stime(u64 stime, u64 rtime, u64 total)
{
	u64 scaled;

	for (;;) {
		/* Make sure "rtime" is the bigger of stime/rtime */
		if (stime > rtime)
			swap(rtime, stime);

		/* Make sure 'total' fits in 32 bits */
		if (total >> 32)
			goto drop_precision;

		/* Does rtime (and thus stime) fit in 32 bits? */
		if (!(rtime >> 32))
			break;

		/* Can we just balance rtime/stime rather than dropping bits? */
		if (stime >> 31)
			goto drop_precision;

		/* We can grow stime and shrink rtime and try to make them both fit */
		stime <<= 1;
		rtime >>= 1;
		continue;

drop_precision:
		/* We drop from rtime, it has more bits than stime */
		rtime >>= 1;
		total >>= 1;
	}

	/*
	 * Make sure gcc understands that this is a 32x32->64 multiply,
	 * followed by a 64/32->64 divide.
	 */
	scaled = div_u64((u64) (u32) stime * (u64) (u32) rtime, (u32)total);
	return (__force cputime_t) scaled;
}

/*
 * Atomically advance counter to the new value. Interrupts, vcpu
 * scheduling, and scaling inaccuracies can cause cputime_advance
 * to be occasionally called with a new value smaller than counter.
 * Let's enforce atomicity.
 *
 * Normally a caller will only go through this loop once, or not
 * at all in case a previous caller updated counter the same jiffy.
 */
static void cputime_advance(cputime_t *counter, cputime_t new)
{
	cputime_t old;

	while (new > (old = ACCESS_ONCE(*counter)))
		cmpxchg_cputime(counter, old, new);
}

u64 nsecs_to_jiffies64(u64 n)
{
#if (NSEC_PER_SEC % HZ) == 0
		/* Common case, HZ = 100, 128, 200, 250, 256, 500, 512, 1000 etc. */
		return div_u64(n, NSEC_PER_SEC / HZ);
#elif (HZ % 512) == 0
		/* overflow after 292 years if HZ = 1024 */
		return div_u64(n * HZ / 512, NSEC_PER_SEC / 512);
#else
		/*
		 * Generic case - optimized for cases where HZ is a multiple of 3.
		 * overflow after 64.99 years, exact for HZ = 60, 72, 90, 120 etc.
		 */
		return div_u64(n * 9, (9ull * NSEC_PER_SEC + HZ / 2) / HZ);
#endif
}

unsigned long nsecs_to_jiffies(u64 n)
{
		return (unsigned long)nsecs_to_jiffies64(n);
}

/*
 * Adjust tick based cputime random precision against scheduler
 * runtime accounting.
 */
static void cputime_adjust(struct task_cputime *curr,
			   struct cputime *prev,
			   cputime_t *ut, cputime_t *st)
{
	cputime_t rtime, stime, utime;

	/*
	 * Tick based cputime accounting depend on random scheduling
	 * timeslices of a task to be interrupted or not by the timer.
	 * Depending on these circumstances, the number of these interrupts
	 * may be over or under-optimistic, matching the real user and system
	 * cputime with a variable precision.
	 *
	 * Fix this by scaling these tick based values against the total
	 * runtime accounted by the CFS scheduler.
	 */
	rtime = nsecs_to_cputime(curr->sum_exec_runtime);

	/*
	 * Update userspace visible utime/stime values only if actual execution
	 * time is bigger than already exported. Note that can happen, that we
	 * provided bigger values due to scaling inaccuracy on big numbers.
	 */
	if (prev->stime + prev->utime >= rtime)
		goto out;

	stime = curr->stime;
	utime = curr->utime;

	if (utime == 0) {
		stime = rtime;
	} else if (stime == 0) {
		utime = rtime;
	} else {
		cputime_t total = stime + utime;

		stime = scale_stime((__force u64)stime,
				    (__force u64)rtime, (__force u64)total);
		utime = rtime - stime;
	}

	cputime_advance(&prev->stime, stime);
	cputime_advance(&prev->utime, utime);

out:
	*ut = prev->utime;
	*st = prev->stime;
}

void ppm_task_cputime_adjusted(struct task_struct *p, cputime_t *ut, cputime_t *st)
{
	struct task_cputime cputime = {
		.sum_exec_runtime = p->se.sum_exec_runtime,
	};

	task_cputime(p, &cputime.utime, &cputime.stime);
	cputime_adjust(&cputime, &p->prev_cputime, ut, st);
}
#endif /* !CONFIG_VIRT_CPU_ACCOUNTING_NATIVE */

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0) */