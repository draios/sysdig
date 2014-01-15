//
// This flag can be used to include unsupported or unrecognized sockets
// in the fd tables. It's useful to debug close() leaks
//
#define INCLUDE_UNKNOWN_SOCKET_FDS

//
// Memory storage size for an entry in the event storage LIFO.
// Events bigger than SP_STORAGE_EVT_BUF_SIZE won't be be stored in the LIFO.
//
#define SP_EVT_BUF_SIZE 4096

//
// If defined, the filtering system is compiled
//
#define HAS_FILTERING
#define HAS_CAPTURE_FILTERING

//
// Controls if assertions break execution or if they are just printed to the
// log
//
#define ASSERT_TO_LOG

//
// Controls if the library collects internal performance stats.
//
#undef GATHER_INTERNAL_STATS

//
// Read timeout specified when doing scap_open
//
#define SCAP_TIMEOUT_MS 30

//
// Max size that the thread table can reach
//
#define MAX_THREAD_TABLE_SIZE 65536

//
// The time after an inactive thread is removed.
//
#define DEFAULT_THREAD_TIMEOUT_SEC 1800

//
// How often the thread table is sacnned for inactive threads
//
#define DEFAULT_INACTIVE_THREAD_SCAN_TIME 600

//
// FD class customized with the storage we need
//
#ifdef HAS_ANALYZER
#include "analyzer_settings.h"
#else
template<class T> class sinsp_fdinfo;
typedef sinsp_fdinfo<int> sinsp_fdinfo_t;
#endif // HAS_ANALYZER
