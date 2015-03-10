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

#include<linux/version.h>

/*
 * Our Own ASSERT implementation, so we can easily switch among BUG_ON, WARN_ON and nothing
 */
#ifdef _DEBUG
#define ASSERT(expr) WARN_ON(!(expr))
#else
#define ASSERT(expr)
#endif

#include <linux/time.h>

/*
 * Global defines
 */
#define CAPTURE_CONTEXT_SWITCHES
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32))
#define CAPTURE_SIGNAL_DELIVERIES
#endif
#define RW_SNAPLEN 80
#define RW_SNAPLEN_EVENT 4096
#define RW_MAX_SNAPLEN (256 * 1024 * 1024)
#define DPI_LOOKAHED_SIZE 5
#define MAX_CONSUMERS 5

/*
 * Global enums
 */
enum syscall_flags {
	UF_NONE = 0,
	UF_USED = (1 << 0),
	UF_NEVER_DROP = (1 << 1),
	UF_ALWAYS_DROP = (1 << 2),
};

/*
 * Global structs
 */
struct syscall_evt_pair {
	int flags;
	enum ppm_event_type enter_event_type;
	enum ppm_event_type exit_event_type;
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

struct ppm_consumer_t {
	struct task_struct *consumer_id;
	struct ppm_ring_buffer_context __percpu *ring_buffers;
	u32 snaplen;
	u32 sampling_ratio;
	bool do_dynamic_snaplen;
	u32 sampling_interval;
	int is_dropping;
	int dropping_mode;
	volatile int need_to_insert_drop_e;
	volatile int need_to_insert_drop_x;
	struct list_head node;
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

#define PPM_PORT_MYSQL 3306
#define PPM_PORT_POSTGRES 5432
#define PPM_START_PORT_MONGODB 27000
#define PPM_END_PORT_MONGODB 27018
