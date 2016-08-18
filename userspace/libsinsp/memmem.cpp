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

#ifndef _GNU_SOURCE
#include <string.h>

void *memmem(const void *haystack, size_t haystacklen,
	const void *needle, size_t needlelen)
{
	const unsigned char *ptr;
	const unsigned char *end;

	if(needlelen == 0)
	{
		return (void *)haystack;
	}

	if(haystacklen < needlelen)
	{
		return NULL;
	}

	end = (const unsigned char *)haystack + haystacklen - needlelen;
	for(ptr = (const unsigned char *)haystack; ptr <= end; ptr++)
	{
		if(!memcmp(ptr, needle, needlelen))
		{
			return (void *)ptr;
		}
	}

	return NULL;
}
#endif
