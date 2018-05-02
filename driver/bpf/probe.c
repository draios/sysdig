#include <linux/version.h>
#include <generated/utsrelease.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#define randomized_struct_fields_start  struct {
#define randomized_struct_fields_end    };
#endif

#include <uapi/linux/bpf.h>
#include <linux/sched.h>

#include "../ppm_events_public.h"
#include "../ppm_fillers.h"
#include "bpf_helpers.h"
#include "maps.h"
#include "plumbing_helpers.h"
#include "ring_helpers.h"
#include "filler_helpers.h"
#include "fillers.h"

__bpf_section("tracepoint/raw_syscalls/sys_enter")
int bpf_sys_enter(struct sys_enter_args *ctx)
{
	struct sysdig_bpf_per_cpu_state *state;
	const struct syscall_evt_pair *sc_evt;
	struct sysdig_bpf_settings *settings;
	/* Duplicated here to avoid verifier madness */
	struct sys_enter_args stack_ctx;
	struct tail_context *tail_ctx;
	char *scratchp;
	int drop_flags;

	if (ctx->id < 0 || ctx->id >= SYSCALL_TABLE_SIZE)
		return 0;

	settings = get_bpf_settings();
	if (!settings)
		return 0;

	if (!settings->capture_enabled)
		return 0;

	sc_evt = get_syscall_info(ctx->id);
	if (!sc_evt)
		return 0;

	state = get_local_state();
	if (!state)
		return 0;

	if (state->preempt_count) {
		PRINTK("preempt %d\n", state->preempt_count);
		return 0;
	}

	__sync_fetch_and_add(&state->preempt_count, 1);

	scratchp = get_frame_scratch_area();
	if (!scratchp)
		goto cleanup;

	memcpy(stack_ctx.args, ctx->args, sizeof(ctx->args));

	tail_ctx = (struct tail_context *)scratchp;
	tail_ctx->event_data.syscall_data.syscall_id = ctx->id;

	if (sc_evt->flags & UF_USED) {
		tail_ctx->evt_type = sc_evt->enter_event_type;
		drop_flags = sc_evt->flags;
	} else {
		tail_ctx->evt_type = PPME_GENERIC_E;
		drop_flags = UF_ALWAYS_DROP;
	}

	if (stash_args(stack_ctx.args))
		goto cleanup;

	call_filler(ctx, &stack_ctx, tail_ctx, settings, state, drop_flags);

cleanup:
	__sync_fetch_and_add(&state->preempt_count, -1);
	return 0;
}

__bpf_section("tracepoint/raw_syscalls/sys_exit")
int bpf_sys_exit(struct sys_exit_args *ctx)
{
	struct sysdig_bpf_per_cpu_state *state;
	const struct syscall_evt_pair *sc_evt;
	struct sysdig_bpf_settings *settings;
	struct tail_context *tail_ctx;
	char *scratchp;
	int drop_flags;

	if (ctx->id < 0 || ctx->id >= SYSCALL_TABLE_SIZE)
		return 0;

	settings = get_bpf_settings();
	if (!settings)
		return 0;

	if (!settings->capture_enabled)
		return 0;

	sc_evt = get_syscall_info(ctx->id);
	if (!sc_evt)
		return 0;

	state = get_local_state();
	if (!state)
		return 0;

	if (state->preempt_count) {
		PRINTK("preempt %d\n", state->preempt_count);
		return 0;
	}

	__sync_fetch_and_add(&state->preempt_count, 1);

	scratchp = get_frame_scratch_area();
	if (!scratchp)
		goto cleanup;

	tail_ctx = (struct tail_context *)scratchp;
	tail_ctx->event_data.syscall_data.syscall_id = ctx->id;
	tail_ctx->event_data.syscall_data.ret = ctx->ret;

	if (sc_evt->flags & UF_USED) {
		tail_ctx->evt_type = sc_evt->exit_event_type;
		drop_flags = sc_evt->flags;
	} else {
		tail_ctx->evt_type = PPME_GENERIC_X;
		drop_flags = UF_ALWAYS_DROP;
	}

	call_filler(ctx, ctx, tail_ctx, settings, state, drop_flags);

cleanup:
	__sync_fetch_and_add(&state->preempt_count, -1);
	return 0;
}

__bpf_section("tracepoint/sched/sched_process_exit")
int bpf_sched_process_exit(struct sched_process_exit_args *ctx)
{
	struct sysdig_bpf_per_cpu_state *state;
	struct sysdig_bpf_settings *settings;
	struct tail_context *tail_ctx;
	struct task_struct *task;
	unsigned int flags;
	char *scratchp;

	task = (struct task_struct *)bpf_get_current_task();

	flags = _READ(task->flags);
	if (flags & PF_KTHREAD)
		return 0;

	settings = get_bpf_settings();
	if (!settings)
		return 0;

	if (!settings->capture_enabled)
		return 0;

	state = get_local_state();
	if (!state)
		return 0;

	if (state->preempt_count) {
		PRINTK("preempt %d\n", state->preempt_count);
		return 0;
	}

	__sync_fetch_and_add(&state->preempt_count, 1);

	scratchp = get_frame_scratch_area();
	if (!scratchp)
		goto cleanup;

	tail_ctx = (struct tail_context *)scratchp;

	tail_ctx->evt_type = PPME_PROCEXIT_1_E;

	call_filler(ctx, ctx, tail_ctx, settings, state, UF_NEVER_DROP);

cleanup:
	__sync_fetch_and_add(&state->preempt_count, -1);
	return 0;
}

__bpf_section("tracepoint/sched/sched_switch")
int bpf_sched_switch(struct sched_switch_args *ctx)
{
	struct sysdig_bpf_per_cpu_state *state;
	struct sysdig_bpf_settings *settings;
	struct tail_context *tail_ctx;
	char *scratchp;

	settings = get_bpf_settings();
	if (!settings)
		return 0;

	if (!settings->capture_enabled)
		return 0;

	state = get_local_state();
	if (!state)
		return 0;

	if (state->preempt_count) {
		PRINTK("preempt %d\n", state->preempt_count);
		return 0;
	}

	__sync_fetch_and_add(&state->preempt_count, 1);

	scratchp = get_frame_scratch_area();
	if (!scratchp)
		goto cleanup;

	tail_ctx = (struct tail_context *)scratchp;

	tail_ctx->evt_type = PPME_SCHEDSWITCH_6_E;
	tail_ctx->event_data.sched_switch_data.next_pid = ctx->next_pid;

	++state->n_context_switches;

	call_filler(ctx, ctx, tail_ctx, settings, state, 0);

cleanup:
	__sync_fetch_and_add(&state->preempt_count, -1);
	return 0;
}

static __always_inline int bpf_page_fault(struct page_fault_args *ctx)
{
	struct sysdig_bpf_per_cpu_state *state;
	struct sysdig_bpf_settings *settings;
	struct tail_context *tail_ctx;
	char *scratchp;

	settings = get_bpf_settings();
	if (!settings)
		return 0;

	if (!settings->page_faults)
		return 0;

	if (!settings->capture_enabled)
		return 0;

	state = get_local_state();
	if (!state)
		return 0;

	if (state->preempt_count) {
		PRINTK("preempt %d\n", state->preempt_count);
		return 0;
	}

	__sync_fetch_and_add(&state->preempt_count, 1);

	scratchp = get_frame_scratch_area();
	if (!scratchp)
		goto cleanup;

	tail_ctx = (struct tail_context *)scratchp;

	tail_ctx->evt_type = PPME_PAGE_FAULT_E;
	tail_ctx->event_data.page_fault_data.address = ctx->address;
	tail_ctx->event_data.page_fault_data.ip = ctx->ip;
	tail_ctx->event_data.page_fault_data.error_code = ctx->error_code;

	call_filler(ctx, ctx, tail_ctx, settings, state, UF_ALWAYS_DROP);

cleanup:
	__sync_fetch_and_add(&state->preempt_count, -1);
	return 0;
}

__bpf_section("tracepoint/exceptions/page_fault_user")
int bpf_page_fault_user(struct page_fault_args *ctx)
{
	return bpf_page_fault(ctx);
}

__bpf_section("tracepoint/exceptions/page_fault_kernel")
int bpf_page_fault_kernel(struct page_fault_args *ctx)
{
	return bpf_page_fault(ctx);
}

__bpf_section("tracepoint/signal/signal_deliver")
int bpf_signal_deliver(struct signal_deliver_args *ctx)
{
	struct sysdig_bpf_per_cpu_state *state;
	struct sysdig_bpf_settings *settings;
	struct tail_context *tail_ctx;
	char *scratchp;

	settings = get_bpf_settings();
	if (!settings)
		return 0;

	if (!settings->capture_enabled)
		return 0;

	state = get_local_state();
	if (!state)
		return 0;

	if (state->preempt_count) {
		PRINTK("preempt %d\n", state->preempt_count);
		return 0;
	}

	__sync_fetch_and_add(&state->preempt_count, 1);

	scratchp = get_frame_scratch_area();
	if (!scratchp)
		goto cleanup;

	tail_ctx = (struct tail_context *)scratchp;

	tail_ctx->evt_type = PPME_SIGNALDELIVER_E;
	tail_ctx->event_data.signal_data.sig = ctx->sig;

	call_filler(ctx, ctx, tail_ctx, settings, state, UF_ALWAYS_DROP);

cleanup:
	__sync_fetch_and_add(&state->preempt_count, -1);
	return 0;
}

__bpf_section("tracepoint/sched/sched_process_fork")
int bpf_sched_process_fork(struct sched_process_fork_args *ctx)
{
	struct sys_stash_args args;
	unsigned long *argsp;

	argsp = __unstash_args(ctx->parent_pid);
	if (!argsp)
		return 0;

	memcpy(&args, argsp, sizeof(args));

	__stash_args(ctx->child_pid, args.args);

	return 0;
}

char release[] __bpf_section("version") = UTS_RELEASE;
