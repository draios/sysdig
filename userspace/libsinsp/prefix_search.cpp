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

#include <sstream>
#include <string.h>

#include "prefix_search.h"

using namespace std;

path_prefix_search::path_prefix_search()
{
}

path_prefix_search::~path_prefix_search()
{
	for (auto &ent : m_dirs)
	{
		delete(ent.second);
	}
}

// Split path /var/log/messages into dirent (var) and remainder (/log/messages)
void path_prefix_search::split_path(const filter_value_t &path, filter_value_t &dirent, filter_value_t &remainder)
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
void path_prefix_search::add_search_path(const char *path)
{
	filter_value_t mem((uint8_t *) path, (uint32_t) strlen(path));
	return add_search_path(mem);
}

void path_prefix_search::add_search_path(const filter_value_t &path)
{
	filter_value_t dirent, remainder;
	path_prefix_search *subtree = NULL;
	path_prefix_search::split_path(path, dirent, remainder);
	auto it = m_dirs.find(dirent);

	if(it == m_dirs.end())
	{
		// This path component doesn't match any existing
		// dirent. We need to add one and its subtree.
		if(remainder.second > 0)
		{
			subtree = new path_prefix_search();
			subtree->add_search_path(remainder);
		}

		m_dirs[dirent] = subtree;
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
			delete(it->second);
			m_dirs.erase(dirent);
			m_dirs[dirent] = NULL;
		}
		else if(it->second == NULL)
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
			it->second->add_search_path(remainder);
		}
	}
}

// NOTE: this does not copy, so it is only valid as long as path is valid.
bool path_prefix_search::match(const char *path)
{
	filter_value_t mem((uint8_t *) path, (uint32_t) strlen(path));
	return match(mem);
}

bool path_prefix_search::match(const filter_value_t &path)
{
	filter_value_t dirent, remainder;
	path_prefix_search::split_path(path, dirent, remainder);
	auto it = m_dirs.find(dirent);

	if(it == m_dirs.end())
	{
		return false;
	}
	else
	{
		// If there is nothing left in the match path, the
		// subtree must be null. This ensures that /var
		// matches only /var and not /var/lib
		if(remainder.second == 0)
		{
			return (it->second == NULL);
		}
		else if(it->second == NULL)
		{
			// /foo/bar matched a prefix /foo, so we're
			// done.
			return true;
		}
		else
		{
			return it->second->match(remainder);
		}
	}
}

std::string path_prefix_search::as_string()
{
	return as_string(string(""));
}

// Unlike all the other methods, this does perform copies.
std::string path_prefix_search::as_string(const std::string &prefix)
{
	std::ostringstream os;

	for (auto &it : m_dirs)
	{
		string dirent((const char *) it.first.first, it.first.second);
		os << prefix << dirent << " -> " << endl;
		if(it.second)
		{
			std::string indent = prefix;
			indent += "    ";
			os << it.second->as_string(indent);
		}
	}

	return os.str();
}
