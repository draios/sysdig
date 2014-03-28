/*
















*/

#ifdef _WIN32
#include <inttypes_win.h>
#ifndef __cplusplus
#define	bool int
#define false 0
#define true (!false)
#define inline inline
#endif /* __cplusplus */
#define snprintf _snprintf
#elif defined(__APPLE__) /* _WIN32 */
#include <inttypes.h>
#include <stdbool.h>
#else
#ifndef __KERNEL__
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#endif /* __KERNEL__ */
#include <linux/types.h>
#include <stdbool.h> /* for true/false */
#endif /* _WIN32 */
