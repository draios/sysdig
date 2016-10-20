/*
Copyright (C) 2013-2016 Draios inc.

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

#include <string.h>
#include <utility>

// Used for CO_IN/CO_PMATCH filterchecks using PT_CHARBUFs to allow
// for quick multi-value comparisons. Should also work for any
// filtercheck with a buffer and length. When compiling with gnu
// compilers, use the built in but not standard _hash_impl::hash
// function, which uses murmurhash2 and is quite fast. Otherwise, uses
// http://www.cse.yorku.ca/~oz/hash.html.

typedef std::pair<uint8_t *, uint32_t> filter_value_t;

struct g_hash_membuf
{
	size_t operator()(filter_value_t val) const
	{
#if defined(__GNUC__) && !defined(__clang__)
		return std::_Hash_impl::hash(val.first, val.second);
#else
		size_t hash = 5381;
		for(uint8_t *p = val.first; p-val.first < val.second; p++)
		{
			int c = *p;

			hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
		}
		return hash;
#endif
	}
};

struct g_equal_to_membuf
{
	bool operator()(filter_value_t a, filter_value_t b) const
	{
		return (a.second == b.second &&
			memcmp(a.first, b.first, a.second) == 0);
	}
};

