/*
Copyright (C) 2018 Draios inc.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

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

