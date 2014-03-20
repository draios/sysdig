/*
Copyright (C) 2013-2014 Draios inc.
 
This file is part of sysdig.

sysdig is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

///////////////////////////////////////////////////////////////////////
// Driver output definitions
///////////////////////////////////////////////////////////////////////

//
// Driver Chattiness
//
#define OUTPUT_VERBOSE 4
#define OUTPUT_INFO 2
#define OUTPUT_ERRORS 1
#define OUTPUT_NONE 0

#define OUTPUT_LEVEL OUTPUT_INFO

//
// Our Own ASSERT implementation, so we can easily switch among BUG_ON, WARN_ON and nothing
//
#ifdef _DEBUG
#define ASSERT(expr) WARN_ON(!(expr))
#else
#define ASSERT(expr)
#endif

//
// Tracing and debug printing
//

#if (OUTPUT_LEVEL >= OUTPUT_VERBOSE)
#define dbgprint(a) printk(KERN_INFO a "\n")
#define trace_enter() printk(KERN_INFO "> %s\n", __FUNCTION__)
#define trace_exit() printk(KERN_INFO "< %s\n", __FUNCTION__)
#else
#define dbgprint(a)
#define trace_exit()
#define trace_enter()
#endif

///////////////////////////////////////////////////////////////////////
// Global defines
///////////////////////////////////////////////////////////////////////
#define CAPTURE_CONTEXT_SWITCHES
#define RW_SNAPLEN 80
#define RW_MAX_SNAPLEN (256 * 1024 * 1024)
// Make sure to use a power of two constant for this
extern uint32_t g_snaplen;

///////////////////////////////////////////////////////////////////////
// Global enums
///////////////////////////////////////////////////////////////////////
typedef enum ppm_capture_state
{
	CS_STOPPED = 0,		// Not capturing. Either uninitialized or closed.
	CS_STARTED = 1,		// Capturing.
	CS_INACTIVE = 2,	// Not Capturing but active, returning the packets in the buffer to the user.
}ppm_capture_state;

enum syscall_flags
{
	UF_NONE = 0,
	UF_USED = (1 << 0),
	UF_NEVER_DROP = (1 << 1),
};

///////////////////////////////////////////////////////////////////////
// Global structs
///////////////////////////////////////////////////////////////////////
struct syscall_evt_pair
{
	int flags;
	enum ppm_event_type enter_event_type;
	enum ppm_event_type exit_event_type;
};

struct ppm_device
{
	dev_t dev;
	struct cdev cdev;
	wait_queue_head_t read_queue;
};

#define STR_STORAGE_SIZE PAGE_SIZE

//
// The ring descriptor.
// We have one of these for each CPU.
//
struct ppm_ring_buffer_context
{
	atomic_t state;
	struct ppm_ring_buffer_info* info;
	char* buffer;
	struct timespec last_print_time;
	uint32_t nevents;
	atomic_t preempt_count;
	char* str_storage;	// String storage. Size is one page.
};

///////////////////////////////////////////////////////////////////////
// Global functions
///////////////////////////////////////////////////////////////////////
unsigned long ppm_copy_from_user(void *to, const void __user *from, unsigned long n);
long ppm_strncpy_from_user(char *to, const char __user *from, unsigned long n);

///////////////////////////////////////////////////////////////////////
// Global tables
///////////////////////////////////////////////////////////////////////
#define SYSCALL_TABLE_SIZE 512

extern const struct syscall_evt_pair g_syscall_table[];
extern const struct ppm_event_info g_event_info[];
extern const struct ppm_syscall_desc g_syscall_info_table[];
extern const ppm_syscall_code g_syscall_code_routing_table[];
