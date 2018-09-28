/*

Copyright (c) 2013-2018 Draios Inc. dba Sysdig.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#include "ppm_events_public.h"

const struct ppm_param_info ptrace_dynamic_param[PPM_PTRACE_IDX_MAX] = {
	[PPM_PTRACE_IDX_UINT64] = {{0}, PT_UINT64, PF_HEX},
	[PPM_PTRACE_IDX_SIGTYPE] = {{0}, PT_SIGTYPE, PF_DEC},
};

const struct ppm_param_info bpf_dynamic_param[PPM_BPF_IDX_MAX] = {
	[PPM_BPF_IDX_FD] = {{0}, PT_FD, PF_DEC},
	[PPM_BPF_IDX_RES] = {{0}, PT_ERRNO, PF_DEC},
};
