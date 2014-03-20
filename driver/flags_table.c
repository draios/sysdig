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

#include "ppm_events_public.h"

const struct ppm_name_value socket_families[] =
{
	{"AF_NFC", 39},
	{"AF_ALG", 38},
	{"AF_CAIF", 37},
	{"AF_IEEE802154", 36},
	{"AF_PHONET", 35},
	{"AF_ISDN", 34},
	{"AF_RXRPC", 33},
	{"AF_IUCV", 32},
	{"AF_BLUETOOTH", 31},
	{"AF_TIPC", 30},
	{"AF_CAN", 29},
	{"AF_LLC", 26},
	{"AF_WANPIPE", 25},
	{"AF_PPPOX", 24},
	{"AF_IRDA", 23},
	{"AF_SNA", 22},
	{"AF_RDS", 21},
	{"AF_ATMSVC", 20},
	{"AF_ECONET", 19},
	{"AF_ASH", 18},
	{"AF_PACKET", 17},
	{"AF_ROUTE", PPM_AF_NETLINK},
	{"AF_NETLINK", 16},
	{"AF_KEY", 15},
	{"AF_SECURITY", 14},
	{"AF_NETBEUI", 13},
	{"AF_DECnet", 12},
	{"AF_ROSE", 11},
	{"AF_INET6", 10},
	{"AF_X25", 9},
	{"AF_ATMPVC", 8},
	{"AF_BRIDGE", 7},
	{"AF_NETROM", 6},
	{"AF_APPLETALK", 5},
	{"AF_IPX", 4},
	{"AF_AX25", 3},
	{"AF_INET", 2},
	{"AF_LOCAL", 1},
	{"AF_UNIX", 1},
	{"AF_UNSPEC", 0},
	{0, 0},
};

const struct ppm_name_value file_flags[] =
{
	{"O_LARGEFILE", (1 << 11)},
	{"O_DIRECTORY", (1 << 10)},
	{"O_DIRECT", (1 << 9)},
	{"O_TRUNC", (1 << 8)},
	{"O_SYNC", (1 << 7)},
	{"O_NONBLOCK", (1 << 6)},
	{"O_EXCL", (1 << 5)},
	{"O_DSYNC", (1 << 4)},
	{"O_APPEND", (1 << 3)},
	{"O_CREAT", (1 << 2)},
	{"O_RDWR", (PPM_O_RDONLY | PPM_O_WRONLY)},
	{"O_WRONLY", (1 << 1)},
	{"O_RDONLY", (1 << 0)},
	{"O_NONE", 0},
	{0, 0},
};

const struct ppm_name_value clone_flags[] =
{
	{"CLONE_FILES", (1 << 0)},
	{"CLONE_FS", (1 << 1)},
	{"CLONE_IO", (1 << 2)},
	{"CLONE_NEWIPC", (1 << 3)},
	{"CLONE_NEWNET", (1 << 4)},
	{"CLONE_NEWNS", (1 << 5)},
	{"CLONE_NEWPID", (1 << 6)},
	{"CLONE_NEWUTS", (1 << 7)},
	{"CLONE_PARENT", (1 << 8)},
	{"CLONE_PARENT_SETTID", (1 << 9)},
	{"CLONE_PTRACE", (1 << 10)},
	{"CLONE_SIGHAND", (1 << 11)},
	{"CLONE_SYSVSEM", (1 << 12)},
	{"CLONE_THREAD", (1 << 13)},
	{"CLONE_UNTRACED", (1 << 14)},
	{"CLONE_VM", (1 << 15)},
	{"CLONE_INVERTED", (1 << 16)},
	{"NAME_CHANGED", (1 << 17)},
	{"CLOSED", (1 << 18)},
	{0, 0},
};

const struct ppm_name_value futex_operations[] =
{
	{"FUTEX_CLOCK_REALTIME", 256},
	{"FUTEX_PRIVATE_FLAG", 128},
	{"FUTEX_CMP_REQUEUE_PI", 12},
	{"FUTEX_WAIT_REQUEUE_PI", 11},
	{"FUTEX_WAKE_BITSET", 10},
	{"FUTEX_WAIT_BITSET", 9},
	{"FUTEX_TRYLOCK_PI", 8},
	{"FUTEX_UNLOCK_PI", 7},
	{"FUTEX_LOCK_PI", 6},
	{"FUTEX_WAKE_OP", 5},
	{"FUTEX_CMP_REQUEUE", 4},
	{"FUTEX_REQUEUE", 3},
	{"FUTEX_FD", 2},
	{"FUTEX_WAKE", 1},
	{"FUTEX_WAIT", 0},
	{0, 0},
};

const struct ppm_name_value poll_flags[] =
{
	{"POLLIN", (1 << 0)},
	{"POLLPRI", (1 << 1)},
	{"POLLOUT", (1 << 2)},
	{"POLLRDHUP", (1 << 3)},
	{"POLLERR", (1 << 4)},
	{"POLLHUP", (1 << 5)},
	{"POLLNVAL", (1 << 6)},
	{"POLLRDNORM", (1 << 7)},
	{"POLLRDBAND", (1 << 8)},
	{"POLLWRNORM", (1 << 9)},
	{"POLLWRBAND", (1 << 10)},
	{0, 0},
};

const struct ppm_name_value lseek_whence[] =
{
	{"SEEK_END", 2},
	{"SEEK_CUR", 1},
	{"SEEK_SET", 0},
	{0, 0},
};

const struct ppm_name_value shutdown_how[] =
{
	{"SHUT_RDWR", 2},
	{"SHUT_WR", 1},
	{"SHUT_RD", 0},
	{0, 0},
};

const struct ppm_name_value openat_flags[] =
{
	{"AT_FDCWD", -100},
	{0, 0},
};

const struct ppm_name_value rlimit_resources[] =
{
	{"RLIMIT_UNKNOWN", 255},
	{"RLIMIT_RTTIME", 15},
	{"RLIMIT_RTPRIO", 14},
	{"RLIMIT_NICE", 13},
	{"RLIMIT_MSGQUEUE", 12},
	{"RLIMIT_SIGPENDING", 11},
	{"RLIMIT_LOCKS", 10},
	{"RLIMIT_AS", 9},
	{"RLIMIT_MEMLOCK", 8},
	{"RLIMIT_NOFILE", 7},
	{"RLIMIT_NPROC", 6},
	{"RLIMIT_RSS", 5},
	{"RLIMIT_CORE", 4},
	{"RLIMIT_STACK", 3},
	{"RLIMIT_DATA", 2},
	{"RLIMIT_FSIZE", 1},
	{"RLIMIT_CPU", 0},
	{0, 0},
};

const struct ppm_name_value fcntl_commands[] =
{
	{"F_GETPIPE_SZ", 29},
	{"F_SETPIPE_SZ", 28},
	{"F_NOTIFY", 27},
	{"F_DUPFD_CLOEXEC", 26},
	{"F_CANCELLK", 25},
	{"F_GETLEASE", 24},
	{"F_SETLEASE", 23},
	{"F_GETOWN_EX", 22},
	{"F_SETOWN_EX", 21},
	{"F_SETLKW64", 19},
	{"F_SETLK64", 18},
	{"F_GETLK64", 17},
	{"F_GETSIG", 15},
	{"F_SETSIG", 13},
	{"F_GETOWN", 12},
	{"F_SETOWN", 10},
	{"F_SETLKW", 9},
	{"F_SETLK", 8},
	{"F_GETLK", 6},
	{"F_SETFL", 5},
	{"F_GETFL", 4},
	{"F_SETFD", 3},
	{"F_GETFD", 2},
	{"F_DUPFD", 1},
	{"UNKNOWN", 0},
	{0, 0},
};
