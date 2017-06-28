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

#include <string>
#include <unordered_map>

#include "filter_value.h"

//
// A data structure that allows testing a path P against a set of
// search paths S. The search succeeds if any of the search paths Si
// is a prefix of the path P.
//
// Here are some examples:
// - search(/var/run/docker, [/var/run, /etc, /lib, /usr/lib])
//         succeeds because /var/run is a prefix of /var/run/docker.
// - search(/boot, [/var/run, /etc, /lib, /usr/lib])
//         does not succeed because no path is a prefix of /boot.
// - search(/var/lib/messages, [/var/run, /etc, /lib, /usr/lib])
//         does not succeed because no path is a prefix of /var/lib/messages.
//         /var is a partial match but not /var/run.
// - search(/var, [/var/run, /etc, /lib, /usr/lib])
//         does not succeed because no path is a prefix of /var
//         /var is a partial match but the search path is /var/run, not /var.

class path_prefix_search
{
public:
	path_prefix_search();
	~path_prefix_search();

	void add_search_path(const char *path);
	void add_search_path(const filter_value_t &path);

	bool match(const char *path);
	bool match(const filter_value_t &path);

	std::string as_string();

private:

	std::string as_string(const std::string &prefix);

	static void split_path(const filter_value_t &path, filter_value_t &dirent, filter_value_t &remainder);

	// Maps from the path component at the current level to a
	// prefix search for the sub-path below the current level.
	// For example, if the set of search paths is (/var/run, /etc,
	// /lib, /usr, /usr/lib, /var/lib, /var/run), m_dirs contains:
	//   - (var, path_prefix_search(/run)
	//   - (etc, NULL)
	//   - (lib, NULL)
	//   - (usr, NULL)
	//   - (var, path_prefix_search(/lib, /run)
	// Note that because usr is a prefix of /usr/lib, the /usr/lib
	// path is dropped and only /usr is kept.  Also note that
	// terminator paths have a NULL path_prefix_search object.
	std::unordered_map<filter_value_t,
		path_prefix_search *,
		g_hash_membuf,
		g_equal_to_membuf> m_dirs;
};


