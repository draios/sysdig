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

void *memmem(const void *haystack, size_t haystack_len,
	const void *needle, size_t needle_len)
{
	const char *begin = (const char *)haystack;
	const char *last_possible = begin + haystack_len - needle_len;
	const char *tail = (const char *)needle;
	char point;

	//
	// The first occurrence of the empty string is deemed to occur at
	// the beginning of the string.
	//
	if(needle_len == 0)
	{
		return (void *)begin;
	}

	//
	// Sanity check, otherwise the loop might search through the whole
	// memory.
	//
	if(haystack_len < needle_len)
	{
		return NULL;
	}

	point = *tail++;
	for(; begin <= last_possible; begin++)
	{
		if(*begin == point && !memcmp(begin + 1, tail, needle_len - 1))
		{
		        return (void *)begin;
		}
	}

	return NULL;
}
#endif
