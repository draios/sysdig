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

/*
 * Our Own ASSERT implementation, so we can easily switch among BUG_ON, WARN_ON and nothing
 */
#ifdef _DEBUG
#define ASSERT(expr) WARN_ON(!(expr))
#else
#define ASSERT(expr)
#endif

/*
 * Global defines
 */
#define CAPTURE_CONTEXT_SWITCHES
#define RW_SNAPLEN 80
#define RW_MAX_SNAPLEN (256 * 1024 * 1024)
/* Make sure to use a power of two constant for this */
extern u32 g_snaplen;

/*
 * Global enums
 */
enum ppm_capture_state {
	CS_STOPPED = 0,		/* Not capturing. Either uninitialized or closed. */
	CS_STARTED = 1,		/* Capturing. */
	CS_INACTIVE = 2,	/* Not Capturing but active, returning the packets in the buffer to the user. */
};

enum syscall_flags {
	UF_NONE = 0,
	UF_USED = (1 << 0),
	UF_NEVER_DROP = (1 << 1),
};

/*
 * Global structs
 */
struct syscall_evt_pair {
	int flags;
	enum ppm_event_type enter_event_type;
	enum ppm_event_type exit_event_type;
};

#define STR_STORAGE_SIZE PAGE_SIZE

/*
 * Global functions
 */
unsigned long ppm_copy_from_user(void *to, const void __user *from, unsigned long n);
long ppm_strncpy_from_user(char *to, const char __user *from, unsigned long n);

/*
 * Global tables
 */

#ifdef CONFIG_MIPS
  #define SYSCALL_TABLE_ID0 __NR_Linux
#elif defined CONFIG_ARM
  #define SYSCALL_TABLE_ID0 __NR_SYSCALL_BASE
#elif defined CONFIG_X86 || defined CONFIG_SUPERH
  #define SYSCALL_TABLE_ID0 0
#endif

#define SYSCALL_TABLE_SIZE 512

extern const struct syscall_evt_pair g_syscall_table[];
extern const struct ppm_event_info g_event_info[];
extern const enum ppm_syscall_code g_syscall_code_routing_table[];
extern u32 g_sampling_ratio;
