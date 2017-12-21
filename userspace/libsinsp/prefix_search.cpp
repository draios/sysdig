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

#include "prefix_search.h"

using namespace std;

path_prefix_search::path_prefix_search()
{
}

path_prefix_search::~path_prefix_search()
{
}

void path_prefix_search::add_search_path(const char *path)
{
	bool dummy = true;
	return path_prefix_map<bool>::add_search_path(path, dummy);
}

void path_prefix_search::add_search_path(const filter_value_t &path)
{
	bool dummy = true;
	return path_prefix_map<bool>::add_search_path(path, dummy);
}

bool path_prefix_search::match(const char *path)
{
	const bool *val = path_prefix_map<bool>::match(path);
	return (val != NULL);
}

bool path_prefix_search::match(const filter_value_t &path)
{
	const bool *val = path_prefix_map<bool>::match(path);
	return (val != NULL);
}

std::string path_prefix_search::as_string()
{
	return path_prefix_map<bool>::as_string(false);
}


