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

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

class lua_parser_cbacks
{
public:
	// filter.rel_expr(field_name, cmpop, value, index)
	// field_name and cmpop are mandatory
	// value is mandatory unless cmpop=="exists"
	// index is an optional index (integer) that will be written
	// into events matching this expression (internal use).
	static int rel_expr(lua_State *ls);

	// filter.bool_op(op)
	static int bool_op(lua_State *ls);

	// filter.nest()
	static int nest(lua_State *ls);

	// filter.unnest()
	static int unnest(lua_State *ls);
};

