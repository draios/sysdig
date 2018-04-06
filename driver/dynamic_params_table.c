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

#include "ppm_events_public.h"

const struct ppm_param_info ptrace_dynamic_param[PPM_PTRACE_IDX_MAX] = {
	[PPM_PTRACE_IDX_UINT64] = {{0}, PT_UINT64, PF_HEX},
	[PPM_PTRACE_IDX_SIGTYPE] = {{0}, PT_SIGTYPE, PF_DEC},
};

const struct ppm_param_info bpf_dynamic_param[PPM_BPF_IDX_MAX] = {
	[PPM_BPF_IDX_FD] = {{0}, PT_FD, PF_DEC},
	[PPM_BPF_IDX_RES] = {{0}, PT_ERRNO, PF_DEC},
};
