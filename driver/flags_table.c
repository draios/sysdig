/*
Copyright (C) 2013-2014 Draios inc.
 
This file is part of sysdig.

sysdig is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
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
	{"PPM_AF_NFC", 39},
	{"PPM_AF_ALG", 38},
	{"PPM_AF_CAIF", 37},
	{"PPM_AF_IEEE802154", 36},
	{"PPM_AF_PHONET", 35},
	{"PPM_AF_ISDN", 34},
	{"PPM_AF_RXRPC", 33},
	{"PPM_AF_IUCV", 32},
	{"PPM_AF_BLUETOOTH", 31},
	{"PPM_AF_TIPC", 30},
	{"PPM_AF_CAN", 29},
	{"PPM_AF_LLC", 26},
	{"PPM_AF_WANPIPE", 25},
	{"PPM_AF_PPPOX", 24},
	{"PPM_AF_IRDA", 23},
	{"PPM_AF_SNA", 22},
	{"PPM_AF_RDS", 21},
	{"PPM_AF_ATMSVC", 20},
	{"PPM_AF_ECONET", 19},
	{"PPM_AF_ASH", 18},
	{"PPM_AF_PACKET", 17},
	{"PPM_AF_ROUTE", PPM_AF_NETLINK},
	{"PPM_AF_NETLINK", 16},
	{"PPM_AF_KEY", 15},
	{"PPM_AF_SECURITY", 14},
	{"PPM_AF_NETBEUI", 13},
	{"PPM_AF_DECnet", 12},
	{"PPM_AF_ROSE", 11},
	{"PPM_AF_INET6", 10},
	{"PPM_AF_X25", 9},
	{"PPM_AF_ATMPVC", 8},
	{"PPM_AF_BRIDGE", 7},
	{"PPM_AF_NETROM", 6},
	{"PPM_AF_APPLETALK", 5},
	{"PPM_AF_IPX", 4},
	{"PPM_AF_AX25", 3},
	{"PPM_AF_INET", 2},
	{"PPM_AF_LOCAL", 1},
	{"PPM_AF_UNIX", 1},
	{"PPM_AF_UNSPEC", 0},
	{0, 0},
};

const struct ppm_name_value file_flags[] =
{
	{"PPM_O_LARGEFILE", (1 << 11)},
	{"PPM_O_DIRECTORY", (1 << 10)},
	{"PPM_O_DIRECT", (1 << 9)},
	{"PPM_O_TRUNC", (1 << 8)},
	{"PPM_O_SYNC", (1 << 7)},
	{"PPM_O_NONBLOCK", (1 << 6)},
	{"PPM_O_EXCL", (1 << 5)},
	{"PPM_O_DSYNC", (1 << 4)},
	{"PPM_O_APPEND", (1 << 3)},
	{"PPM_O_CREAT", (1 << 2)},
	{"PPM_O_RDWR", (PPM_O_RDONLY | PPM_O_WRONLY)},
	{"PPM_O_WRONLY", (1 << 1)},
	{"PPM_O_RDONLY", (1 << 0)},
	{"PPM_O_NONE", 0},
	{0, 0},
};

const struct ppm_name_value clone_flags[] =
{
	{"PPM_CL_CLONE_FILES", (1 << 0)},
	{"PPM_CL_CLONE_FS", (1 << 1)},
	{"PPM_CL_CLONE_IO", (1 << 2)},
	{"PPM_CL_CLONE_NEWIPC", (1 << 3)},
	{"PPM_CL_CLONE_NEWNET", (1 << 4)},
	{"PPM_CL_CLONE_NEWNS", (1 << 5)},
	{"PPM_CL_CLONE_NEWPID", (1 << 6)},
	{"PPM_CL_CLONE_NEWUTS", (1 << 7)},
	{"PPM_CL_CLONE_PARENT", (1 << 8)},
	{"PPM_CL_CLONE_PARENT_SETTID", (1 << 9)},
	{"PPM_CL_CLONE_PTRACE", (1 << 10)},
	{"PPM_CL_CLONE_SIGHAND", (1 << 11)},
	{"PPM_CL_CLONE_SYSVSEM", (1 << 12)},
	{"PPM_CL_CLONE_THREAD", (1 << 13)},
	{"PPM_CL_CLONE_UNTRACED", (1 << 14)},
	{"PPM_CL_CLONE_VM", (1 << 15)},
	{"PPM_CL_CLONE_INVERTED", (1 << 16)},
	{"PPM_CL_NAME_CHANGED", (1 << 17)},
	{"PPM_CL_CLOSED", (1 << 18)},
	{0, 0},
};

const struct ppm_name_value futex_operations[] =
{
	{"PPM_FU_FUTEX_CLOCK_REALTIME", 256},
	{"PPM_FU_FUTEX_PRIVATE_FLAG", 128},
	{"PPM_FU_FUTEX_CMP_REQUEUE_PI", 12},
	{"PPM_FU_FUTEX_WAIT_REQUEUE_PI", 11},
	{"PPM_FU_FUTEX_WAKE_BITSET", 10},
	{"PPM_FU_FUTEX_WAIT_BITSET", 9},
	{"PPM_FU_FUTEX_TRYLOCK_PI", 8},
	{"PPM_FU_FUTEX_UNLOCK_PI", 7},
	{"PPM_FU_FUTEX_LOCK_PI", 6},
	{"PPM_FU_FUTEX_WAKE_OP", 5},
	{"PPM_FU_FUTEX_CMP_REQUEUE", 4},
	{"PPM_FU_FUTEX_REQUEUE", 3},
	{"PPM_FU_FUTEX_FD", 2},
	{"PPM_FU_FUTEX_WAKE", 1},
	{"PPM_FU_FUTEX_WAIT", 0},
	{0, 0},
};

const struct ppm_name_value poll_flags[] =
{
	{"PPM_POLLIN", (1 << 0)},
	{"PPM_POLLPRI", (1 << 1)},
	{"PPM_POLLOUT", (1 << 2)},
	{"PPM_POLLRDHUP", (1 << 3)},
	{"PPM_POLLERR", (1 << 4)},
	{"PPM_POLLHUP", (1 << 5)},
	{"PPM_POLLNVAL", (1 << 6)},
	{"PPM_POLLRDNORM", (1 << 7)},
	{"PPM_POLLRDBAND", (1 << 8)},
	{"PPM_POLLWRNORM", (1 << 9)},
	{"PPM_POLLWRBAND", (1 << 10)},
	{0, 0},
};

const struct ppm_name_value lseek_whence[] =
{
	{"PPM_SEEK_END", 2},
	{"PPM_SEEK_CUR", 1},
	{"PPM_SEEK_SET", 0},
	{0, 0},
};

const struct ppm_name_value shutdown_how[] =
{
	{"PPM_SHUT_RDWR", 2},
	{"PPM_SHUT_WR", 1},
	{"PPM_SHUT_RD", 0},
	{0, 0},
};

const struct ppm_name_value openat_flags[] =
{
	{"PPM_AT_FDCWD", -100},
	{0, 0},
};

const struct ppm_name_value rlimit_resources[] =
{
	{"PPM_RLIMIT_UNKNOWN", 255},
	{"PPM_RLIMIT_RTTIME", 15},
	{"PPM_RLIMIT_RTPRIO", 14},
	{"PPM_RLIMIT_NICE", 13},
	{"PPM_RLIMIT_MSGQUEUE", 12},
	{"PPM_RLIMIT_SIGPENDING", 11},
	{"PPM_RLIMIT_LOCKS", 10},
	{"PPM_RLIMIT_AS", 9},
	{"PPM_RLIMIT_MEMLOCK", 8},
	{"PPM_RLIMIT_NOFILE", 7},
	{"PPM_RLIMIT_NPROC", 6},
	{"PPM_RLIMIT_RSS", 5},
	{"PPM_RLIMIT_CORE", 4},
	{"PPM_RLIMIT_STACK", 3},
	{"PPM_RLIMIT_DATA", 2},
	{"PPM_RLIMIT_FSIZE", 1},
	{"PPM_RLIMIT_CPU", 0},
	{0, 0},
};

const struct ppm_name_value fcntl_commands[] =
{
	{"PPM_FCNTL_F_GETPIPE_SZ", 29},
	{"PPM_FCNTL_F_SETPIPE_SZ", 28},
	{"PPM_FCNTL_F_NOTIFY", 27},
	{"PPM_FCNTL_F_DUPFD_CLOEXEC", 26},
	{"PPM_FCNTL_F_CANCELLK", 25},
	{"PPM_FCNTL_F_GETLEASE", 24},
	{"PPM_FCNTL_F_SETLEASE", 23},
	{"PPM_FCNTL_F_GETOWN_EX", 22},
	{"PPM_FCNTL_F_SETOWN_EX", 21},
	{"PPM_FCNTL_F_SETLKW64", 19},
	{"PPM_FCNTL_F_SETLK64", 18},
	{"PPM_FCNTL_F_GETLK64", 17},
	{"PPM_FCNTL_F_GETSIG", 15},
	{"PPM_FCNTL_F_SETSIG", 13},
	{"PPM_FCNTL_F_GETOWN", 12},
	{"PPM_FCNTL_F_SETOWN", 10},
	{"PPM_FCNTL_F_SETLKW", 9},
	{"PPM_FCNTL_F_SETLK", 8},
	{"PPM_FCNTL_F_GETLK", 6},
	{"PPM_FCNTL_F_SETFL", 5},
	{"PPM_FCNTL_F_GETFL", 4},
	{"PPM_FCNTL_F_SETFD", 3},
	{"PPM_FCNTL_F_GETFD", 2},
	{"PPM_FCNTL_F_DUPFD", 1},
	{"PPM_FCNTL_UNKNOWN", 0},
	{0, 0},
};
