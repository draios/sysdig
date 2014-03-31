/*
 * Driver output definitions
 */

/*
 * Driver Chattiness
 */
#define OUTPUT_VERBOSE 4
#define OUTPUT_INFO 2
#define OUTPUT_ERRORS 1
#define OUTPUT_NONE 0

#define OUTPUT_LEVEL OUTPUT_INFO

/*
 * Our Own ASSERT implementation, so we can easily switch among BUG_ON, WARN_ON and nothing
 */
#ifdef _DEBUG
#define ASSERT(expr) WARN_ON(!(expr))
#else
#define ASSERT(expr)
#endif

/*
 * Tracing and debug printing
 */
#if (OUTPUT_LEVEL >= OUTPUT_VERBOSE)
#define dbgprint(a) pr_info(a "\n")
#define trace_enter() pr_info("> %s\n", __func__)
#define trace_exit() pr_info("< %s\n", __func__)
#else
#define dbgprint(a)
#define trace_exit()
#define trace_enter()
#endif

/*
 * Global defines
 */
#define CAPTURE_CONTEXT_SWITCHES
#define RW_SNAPLEN 80
#define RW_MAX_SNAPLEN (256 * 1024 * 1024)
/* Make sure to use a power of two constant for this */
extern uint32_t g_snaplen;

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
#define SYSCALL_TABLE_SIZE 512

extern const struct syscall_evt_pair g_syscall_table[];
extern const struct ppm_event_info g_event_info[];
extern const enum ppm_syscall_code g_syscall_code_routing_table[];
extern uint32_t g_sampling_ratio;
