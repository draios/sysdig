/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/
#ifndef __COMPAT_MISC_H
#define __COMPAT_MISC_H

#ifndef __NR_bpf
#ifdef __x86_64__
#define __NR_bpf 321
#else
#define __NR_bpf 357
#endif /* __x86_64__ */
#endif /* __NR_bpf */

#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME 7
#endif

/*
	O_TMPFILE was introduced in Linux >= 3.11 and defined as (__O_TMPFILE | O_DIRECTORY).
	To maintain compatiblity with different build environments, the below is added.   
*/
#ifndef O_TMPFILE
#define O_TMPFILE 020200000
#endif

#endif
