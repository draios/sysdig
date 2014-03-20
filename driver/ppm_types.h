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

#ifdef _WIN32
#include <inttypes_win.h>
#ifndef __cplusplus
#define	bool int
#define false 0
#define true (!false)
#define inline __inline
#endif // __cplusplus
#define snprintf _snprintf
#elif defined(__APPLE__) // _WIN32
#include <inttypes.h>
#include <stdbool.h>
#else
#ifndef __KERNEL__
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#endif // __KERNEL__
#include <linux/types.h>
#include <stdbool.h> // for true/false
#endif // _WIN32
