#ifndef __PLUMBING_HELPERS_H
#define __PLUMBING_HELPERS_H

#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/fdtable.h>

#include "types.h"

#define _READ(P) ({ typeof(P) _val;				\
		    memset(&_val, 0, sizeof(_val));		\
		    bpf_probe_read(&_val, sizeof(_val), &P);	\
		    _val;					\
		 })

#define PRINTK(fmt, ...)					\
	do {							\
		char s[] = fmt;					\
		bpf_trace_printk(s, sizeof(s), ##__VA_ARGS__);	\
	} while (0)

#ifdef BPF_DEBUG
#define VPRINTK PRINTK
#else
#define VPRINTK(fmt, ...)
#endif

static __always_inline int __stash_args(unsigned long long id,
					unsigned long *args)
{
	int ret = bpf_map_update_elem(&stash_map, &id, args, BPF_ANY);

	if (ret)
		PRINTK("error stashing arguments for %d:%d\n", id, ret);

	return ret;
}

static __always_inline int stash_args(unsigned long *args)
{
	unsigned long long id = bpf_get_current_pid_tgid() & 0xffffffff;

	return __stash_args(id, args);
}

static __always_inline unsigned long *__unstash_args(unsigned long long id)
{
	struct sys_stash_args *args;

	args = bpf_map_lookup_elem(&stash_map, &id);
	if (!args)
		return NULL;

	return args->args;
}

static __always_inline unsigned long *unstash_args(void)
{
	unsigned long long id = bpf_get_current_pid_tgid() & 0xffffffff;

	return __unstash_args(id);
}

static __always_inline void delete_args(void)
{
	unsigned long long id = bpf_get_current_pid_tgid() & 0xffffffff;

	bpf_map_delete_elem(&stash_map, &id);
}

static __always_inline char *get_frame_scratch_area(void)
{
	char *scratchp;
	int id = 0;

	scratchp = bpf_map_lookup_elem(&frame_scratch_map, &id);
	if (!scratchp)
		PRINTK("frame scratch NULL\n");

	return scratchp;
}

static __always_inline char *get_tmp_scratch_area(void)
{
	char *scratchp;
	int id = 0;

	scratchp = bpf_map_lookup_elem(&tmp_scratch_map, &id);
	if (!scratchp)
		PRINTK("tmp scratch NULL\n");

	return scratchp;
}

static __always_inline bool acquire_tmp_scratch(struct filler_data *data)
{
	if (data->tmp_scratch_in_use) {
		PRINTK("acquire_tmp_scratch: already in use, evt_type %d\n",
		       data->tail_ctx.evt_type);
		return false;
	}

	data->tmp_scratch_in_use = true;
	return true;
}

static __always_inline bool release_tmp_scratch(struct filler_data *data)
{
	if (!data->tmp_scratch_in_use) {
		PRINTK("release_tmp_scratch: already not in use, evt_type %d\n",
		       data->tail_ctx.evt_type);
		return false;
	}

	data->tmp_scratch_in_use = false;
	return true;
}

static __always_inline const struct syscall_evt_pair *get_syscall_info(int id)
{
	const struct syscall_evt_pair *p =
			bpf_map_lookup_elem(&syscall_table, &id);

	if (!p)
		PRINTK("no syscall_info for %d\n", id);

	return p;
}

static __always_inline const struct ppm_event_info *get_event_info(enum ppm_event_type event_type)
{
	const struct ppm_event_info *e =
		bpf_map_lookup_elem(&event_info_table, &event_type);

	if (!e)
		PRINTK("no event info for %d\n", event_type);

	return e;
}

static __always_inline const struct ppm_event_entry *get_event_filler_info(enum ppm_event_type event_type)
{
	const struct ppm_event_entry *e;

	e = bpf_map_lookup_elem(&fillers_table, &event_type);
	if (!e)
		PRINTK("no filler info for %d\n", event_type);

	return e;
}

static __always_inline struct sysdig_bpf_settings *get_bpf_settings(void)
{
	struct sysdig_bpf_settings *settings;
	int id = 0;

	settings = bpf_map_lookup_elem(&settings_map, &id);
	if (!settings)
		PRINTK("settings NULL\n");

	return settings;
}

static __always_inline struct sysdig_bpf_per_cpu_state *get_local_state(void)
{
	struct sysdig_bpf_per_cpu_state *state;
	int id = bpf_get_smp_processor_id();

	state = bpf_map_lookup_elem(&local_state_map, &id);
	if (!state)
		PRINTK("state NULL\n");

	return state;
}

static __always_inline int init_filler_data(struct filler_data *data,
					    bool is_syscall)
{
	char *scratchp;

	data->tail_ctx.evt_type = 0;

	scratchp = get_frame_scratch_area();
	if (!scratchp)
		return PPM_FAILURE_BUG;

	data->tail_ctx = *(struct tail_context *)scratchp;

	if (is_syscall) {
		data->args = unstash_args();
		if (!data->args)
			return PPM_SKIP_EVENT;
	}

	data->buf = scratchp;

	data->settings = get_bpf_settings();
	if (!data->settings)
		return PPM_FAILURE_BUG;

	data->tmp_scratch = get_tmp_scratch_area();
	if (!data->tmp_scratch)
		return PPM_FAILURE_BUG;

	data->tmp_scratch_in_use = false;

	data->evt = get_event_info(data->tail_ctx.evt_type);
	if (!data->evt)
		return PPM_FAILURE_BUG;

	data->filler_info = get_event_filler_info(data->tail_ctx.evt_type);
	if (!data->filler_info)
		return PPM_FAILURE_BUG;

	data->fd = -1;

	return PPM_SUCCESS;
}

static __always_inline int bpf_test_bit(int nr, unsigned long *addr)
{
	return 1UL & (_READ(addr[BIT_WORD(nr)]) >> (nr & (BITS_PER_LONG - 1)));
}

static __always_inline bool drop_event(void *stack_ctx,
				       struct tail_context *tail_ctx,
				       struct sysdig_bpf_settings *settings,
				       enum syscall_flags drop_flags)
{
	if (!settings->dropping_mode)
		return false;

	if (tail_ctx->evt_type == PPME_SYSCALL_CLOSE_X) {
		if (((struct sys_exit_args *)stack_ctx)->ret < 0)
			return true;
	} else if (tail_ctx->evt_type == PPME_SYSCALL_CLOSE_E) {
		struct files_struct *files;
		struct task_struct *task;
		unsigned long *open_fds;
		struct fdtable *fdt;
		int close_fd;
		int max_fds;

		close_fd = ((struct sys_enter_args *)stack_ctx)->args[0];
		if (close_fd < 0)
			return true;

		task = (struct task_struct *)bpf_get_current_task();
		if (!task)
			return false;

		files = _READ(task->files);
		if (!files)
			return false;

		fdt = _READ(files->fdt);
		if (!fdt)
			return false;

		max_fds = _READ(fdt->max_fds);
		if (close_fd >= max_fds)
			return true;

		open_fds = _READ(fdt->open_fds);
		if (!open_fds)
			return false;

		if (!bpf_test_bit(close_fd, open_fds))
			return true;
	}

	if (drop_flags & UF_NEVER_DROP)
		return false;

	if (drop_flags & UF_ALWAYS_DROP)
		return true;

	if (tail_ctx->ts % 1000000000 >= 1000000000 /
	    settings->sampling_ratio) {
		if (!settings->is_dropping) {
			settings->is_dropping = true;
			tail_ctx->evt_type = PPME_DROP_E;
			return false;
		}

		return true;
	}

	if (settings->is_dropping) {
		settings->is_dropping = false;
		tail_ctx->evt_type = PPME_DROP_X;
		return false;
	}

	return false;
}

static __always_inline int call_filler(void *ctx,
				       void *stack_ctx,
				       struct tail_context *tail_ctx,
				       struct sysdig_bpf_settings *settings,
				       struct sysdig_bpf_per_cpu_state *state,
				       enum syscall_flags drop_flags)
{
	const struct ppm_event_entry *filler_info;
	unsigned long long pid;

	tail_ctx->ts = settings->boot_time + bpf_ktime_get_ns();

	if (drop_event(stack_ctx, tail_ctx, settings, drop_flags))
		return 0;

	++state->n_evts;

	filler_info = get_event_filler_info(tail_ctx->evt_type);
	if (!filler_info)
		return 0;

	bpf_tail_call(ctx, &tail_map, filler_info->bpf_filler_id);

	pid = bpf_get_current_pid_tgid() & 0xffffffff;
	PRINTK("Can't tail call filler for pid %llu, evt %d, filler %d\n",
	       pid,
	       tail_ctx->evt_type,
	       filler_info->bpf_filler_id);
	return 0;
}

#endif
