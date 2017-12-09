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

#include <string>
#include <sstream>
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

template<class Value>
class path_prefix_map
{
public:
	path_prefix_map();
	virtual ~path_prefix_map();

	void add_search_path(const char *path, Value &v);
	void add_search_path(const filter_value_t &path, Value &v);

	// If non-NULL, Value is not allocated. It points to memory
	// held within this path_prefix_map() and is only valid as
	// long as the map exists.
	Value * match(const char *path);
	Value * match(const filter_value_t &path);

	std::string as_string(bool include_vals);

private:
	std::string as_string(const std::string &prefix, bool include_vals);

	static void split_path(const filter_value_t &path, filter_value_t &dirent, filter_value_t &remainder);

	// Maps from the path component at the current level to a
	// prefix search for the sub-path below the current level.
	// For example, if the set of search paths is (/var/run, /etc,
	// /lib, /usr, /usr/lib, /var/lib, /var/run), m_dirs contains:
	//   - (var, path_prefix_map(/run)
	//   - (etc, NULL)
	//   - (lib, NULL)
	//   - (usr, NULL)
	//   - (var, path_prefix_map(/lib, /run)
	// Note that because usr is a prefix of /usr/lib, the /usr/lib
	// path is dropped and only /usr is kept.  Also note that
	// terminator paths have a NULL path_prefix_map object.
	std::unordered_map<filter_value_t,
		std::pair<path_prefix_map *, Value *>,
		g_hash_membuf,
		g_equal_to_membuf> m_dirs;
};

template<class Value>
path_prefix_map<Value>::path_prefix_map()
{
}

template<class Value>
path_prefix_map<Value>::~path_prefix_map()
{
	for (auto &ent : m_dirs)
	{
		delete(ent.second.first);
		delete(ent.second.second);
	}
}

// Split path /var/log/messages into dirent (var) and remainder (/log/messages)
template<class Value>
void path_prefix_map<Value>::split_path(const filter_value_t &path, filter_value_t &dirent, filter_value_t &remainder)
{
	uint32_t length = path.second;

	if(path.second == 0)
	{
		// The result of splitting an empty string is 2 empty strings
		return;
	}

	// Skip any trailing /, not needed
	if (path.first[path.second-1] == '/')
	{
		length--;
	}

	uint32_t start = 0;

	// Also skip any leading '/', not needed.
	if(path.first[0] == '/')
	{
		start++;
	}

	uint8_t* pos = path.first + start;
	uint32_t counter = 0;
	while(counter < path.second)
	{
		if (*pos == 0x2F) // '/'
		{
			break;
		}
		++pos;
		if(++counter >= path.second)
		{
			pos = NULL;
			break;
		}
	}

	if(pos == NULL || pos >= (path.first + length))
	{
		dirent.first = path.first + start;
		dirent.second = length-start;
	}
	else
	{
		dirent.first = path.first + start;
		dirent.second = (uint8_t *) pos-dirent.first;

		remainder.first = (uint8_t *) pos;
		remainder.second = length-dirent.second-start;
	}
}

// NOTE: this does not copy, so it is only valid as long as path is valid.
template<class Value>
void path_prefix_map<Value>::add_search_path(const char *path, Value &v)
{
	filter_value_t mem((uint8_t *) path, (uint32_t) strlen(path));
	return add_search_path(mem, v);
}

template<class Value>
void path_prefix_map<Value>::add_search_path(const filter_value_t &path, Value &v)
{
	filter_value_t dirent, remainder;
	path_prefix_map *subtree = NULL;
	path_prefix_map<Value>::split_path(path, dirent, remainder);
	auto it = m_dirs.find(dirent);

	if(it == m_dirs.end())
	{
		// This path component doesn't match any existing
		// dirent. We need to add one and its subtree.
		if(remainder.second > 0)
		{
			subtree = new path_prefix_map();
			subtree->add_search_path(remainder, v);
		}

		// If the path doesn't have anything remaining, we
		// also add the value here.
		m_dirs[dirent] = std::pair<path_prefix_map*,Value *>(subtree, (remainder.second == 0 ? new Value(v) : NULL));
	}
	else
	{
		// An entry for this dirent already exists. We will
		// either add a new entry to the subtree, do nothing,
		// or get rid of the existing subtree.
		if(remainder.second == 0)
		{
			// This path is a prefix of the current path and we
			// can drop the existing subtree. For example, we can
			// drop /usr/lib when adding /usr.
			delete(it->second.first);
			m_dirs.erase(dirent);
			m_dirs[dirent] = std::pair<path_prefix_map*,Value*>(NULL, new Value(v));
		}
		else if(it->second.first == NULL)
		{
			// The existing path is shorter than the
			// current path, in which case we don't have
			// to do anything. For example, no need to add
			// /usr/lib when /usr exists.
		}
		else
		{
			// We need to add the remainder to the
			// sub-tree's search path.
			it->second.first->add_search_path(remainder, v);
		}
	}
}

// NOTE: this does not copy, so it is only valid as long as path is valid.
template<class Value>
Value *path_prefix_map<Value>::match(const char *path)
{
	filter_value_t mem((uint8_t *) path, (uint32_t) strlen(path));
	return match(mem);
}

template<class Value>
Value *path_prefix_map<Value>::match(const filter_value_t &path)
{
	filter_value_t dirent, remainder;
	path_prefix_map<Value>::split_path(path, dirent, remainder);
	auto it = m_dirs.find(dirent);

	if(it == m_dirs.end())
	{
		return NULL;
	}
	else
	{
		// If there is nothing left in the match path, the
		// subtree must be null. This ensures that /var
		// matches only /var and not /var/lib
		if(remainder.second == 0)
		{
			if(it->second.first == NULL)
			{
				return it->second.second;
			}
			else
			{
				return NULL;
			}
		}
		else if(it->second.first == NULL)
		{
			// /foo/bar matched a prefix /foo, so we're
			// done.
			return it->second.second;
		}
		else
		{
			return it->second.first->match(remainder);
		}
	}
}

template<class Value>
std::string path_prefix_map<Value>::as_string(bool include_vals)
{
	return as_string(std::string(""), include_vals);
}

// Unlike all the other methods, this does perform copies.
template<class Value>
std::string path_prefix_map<Value>::as_string(const std::string &prefix, bool include_vals)
{
	std::ostringstream os;

	for (auto &it : m_dirs)
	{
		std::string dirent((const char *) it.first.first, it.first.second);

		os << prefix << dirent << " -> ";
		if (include_vals && it.second.first == NULL)
		{
			os << "v=" << (*it.second.second);
		}

		os << std::endl;

		if(it.second.first)
		{
			std::string indent = prefix;
			indent += "    ";
			os << it.second.first->as_string(indent, include_vals);
		}
	}

	return os.str();
}

class path_prefix_search : public path_prefix_map<bool>
{
public:
	path_prefix_search();
	~path_prefix_search();

	void add_search_path(const char *path);
	void add_search_path(const filter_value_t &path);

	// If non-NULL, Value is not allocated. It points to memory
	// held within this path_prefix_map() and is only valid as
	// long as the map exists.
	bool match(const char *path);
	bool match(const filter_value_t &path);

	std::string as_string();
};
