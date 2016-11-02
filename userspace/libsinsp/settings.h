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

#pragma once
//
// This flag can be used to include unsupported or unrecognized sockets
// in the fd tables. It's useful to debug close() leaks
//
#define INCLUDE_UNKNOWN_SOCKET_FDS

//
// Memory storage size for an entry in the event storage LIFO.
// Events bigger than SP_EVT_BUF_SIZE won't be be stored in the LIFO.
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
#define MAX_THREAD_TABLE_SIZE 32768

//
// Max size that the FD table of a process can reach
//
#define MAX_FD_TABLE_SIZE 4096

//
// The time after an inactive thread is removed.
//
#define DEFAULT_THREAD_TIMEOUT_S 1800

//
// How often the thread table is sacnned for inactive threads
//
#define DEFAULT_INACTIVE_THREAD_SCAN_TIME_S 1200

//
// How often the thread table is sacnned for inactive threads
//
#define DEFAULT_INACTIVE_CONTAINER_SCAN_TIME_S DEFAULT_INACTIVE_THREAD_SCAN_TIME_S

//
// Enables Lua chisel scripts support
//
#define HAS_CHISELS

//
// Relative path to chisels
//
#define CHISELS_INSTALLATION_DIR "/share/sysdig/chisels"

//
// Default snaplen
//
#define DEFAULT_SNAPLEN 80

//
// Maximum user event buffer size
//
#define MAX_USER_EVT_BUFFER 65536

//
// Size the user event buffer is brought back once in a while 
//
#define MIN_USER_EVT_BUFFER 256
 
//
// Is csysdig functionality included?
//
#define CSYSDIG

#ifdef _WIN32
#define NOCURSESUI
#endif

//
// Name of the device used for tracer injection
//
#define USER_EVT_DEVICE_NAME "/dev/null"

//
// For internal use
//
#define FALCOBL_FULL_PROCESSING

//
// FD class customized with the storage we need
//
#ifdef HAS_ANALYZER
#include "analyzer_settings.h"
#else
template<class T> class sinsp_fdinfo;
typedef sinsp_fdinfo<int> sinsp_fdinfo_t;
#endif // HAS_ANALYZER

// Max JSON we can parse from docker API or others
// Added because older docker versions have a bug that causes
// very big JSONs returned by container inspect call
static const unsigned MAX_JSON_SIZE_B = 500 * 1024; // 500 kiB