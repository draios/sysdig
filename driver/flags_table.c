/*

 














*/

#include "ppm_events_public.h"

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

const struct ppm_name_value openat_flags[] =
{
	{"PPM_AT_FDCWD", -100},
	{0, 0},
};
