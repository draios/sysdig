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

#pragma once
//
// If this check is used by a filter, extract the constant to compare it to
// Doesn't return the field length because the filtering engine can calculate it.
//

class sinsp_filter_value_parser
{
 public:
	static void string_to_rawval(const char* str, uint32_t len, uint8_t *storage, string::size_type max_len, ppm_param_type ptype);
};
