#ifndef __QUIRKS_H
#define __QUIRKS_H

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#error Kernel version must be >= 4.14 with eBPF enabled
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#define randomized_struct_fields_start  struct {
#define randomized_struct_fields_end    };
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
#define BPF_FORBIDS_ZERO_ACCESS
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
#define BPF_SUPPORTS_RAW_TRACEPOINTS
#endif

#endif
