/*

Copyright (c) 2013-2018 Draios Inc. dba Sysdig.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#ifndef __QUIRKS_H
#define __QUIRKS_H

#include <linux/version.h>

#ifdef RHEL_RELEASE_CODE

#if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7, 6)
#error RHEL version must be >= 7.6
#endif

/* RHEL has its own backported eBPF version, so the other defines in
 * quirks don't quite apply. In particular, as of 7.6:
 * - BPF_FORBIDS_ZERO_ACCESS is not necessary
 * - BPF_SUPPORTS_RAW_TRACEPOINTS is defined in the uapi but not actually
 *   implemented in the kernel
 */

#else /* RHEL_RELEASE_CODE */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#error Kernel version must be >= 4.14 with eBPF enabled
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 4)
#define randomized_struct_fields_start  struct {
#define randomized_struct_fields_end    };
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
#define BPF_FORBIDS_ZERO_ACCESS
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
#define BPF_SUPPORTS_RAW_TRACEPOINTS
#endif

#endif /* RHEL_RELEASE_CODE */

#endif
