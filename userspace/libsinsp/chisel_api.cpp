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

#include <iostream>
#include <fstream>
#include <cctype>
#include <locale>
#ifndef _WIN32
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#endif
#include <third-party/tinydir.h>
#include <json/json.h>

#include "sinsp.h"
#include "sinsp_int.h"
#include "chisel.h"
#include "chisel_api.h"
#include "filter.h"
#include "filterchecks.h"

#ifdef HAS_CHISELS
#define HAS_LUA_CHISELS

#ifdef HAS_LUA_CHISELS
extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}
#endif

extern vector<chiseldir_info>* g_chisel_dirs;
extern sinsp_filter_check_list g_filterlist;
extern sinsp_evttables g_infotables;

///////////////////////////////////////////////////////////////////////////////
// Lua callbacks
///////////////////////////////////////////////////////////////////////////////
#ifdef HAS_LUA_CHISELS

uint32_t lua_cbacks::rawval_to_lua_stack(lua_State *ls, uint8_t* rawval, const filtercheck_field_info* finfo, uint32_t len)
{
	ASSERT(rawval != NULL);
	ASSERT(finfo != NULL);

	switch(finfo->m_type)
	{
		case PT_INT8:
			lua_pushnumber(ls, *(int8_t*)rawval);
			return 1;
		case PT_INT16:
			lua_pushnumber(ls, *(int16_t*)rawval);
			return 1;
		case PT_INT32:
			lua_pushnumber(ls, *(int32_t*)rawval);
			return 1;
		case PT_INT64:
		case PT_ERRNO:
		case PT_PID:
			lua_pushnumber(ls, (double)*(int64_t*)rawval);
			return 1;
		case PT_L4PROTO: // This can be resolved in the future
		case PT_FLAGS8:
		case PT_UINT8:
			lua_pushnumber(ls, *(uint8_t*)rawval);
			return 1;
		case PT_PORT: // This can be resolved in the future
		case PT_FLAGS16:
		case PT_UINT16:
			lua_pushnumber(ls, *(uint16_t*)rawval);
			return 1;
		case PT_FLAGS32:
		case PT_UINT32:
			lua_pushnumber(ls, *(uint32_t*)rawval);
			return 1;
		case PT_UINT64:
		case PT_RELTIME:
		case PT_ABSTIME:
			lua_pushnumber(ls, (double)*(uint64_t*)rawval);
			return 1;
		case PT_CHARBUF:
			lua_pushstring(ls, (char*)rawval);
			return 1;
		case PT_BYTEBUF:
			if(rawval[len] == 0)
			{
				lua_pushstring(ls, (char*)rawval);
				return 1;
			}
			else
			{
				lua_getglobal(ls, "sichisel");
				sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
				lua_pop(ls, 1);

				uint32_t max_len = len < sizeof(ch->m_lua_fld_storage) ?
					len : sizeof(ch->m_lua_fld_storage) - 1;

				memcpy(ch->m_lua_fld_storage, rawval, max_len);
				ch->m_lua_fld_storage[max_len] = 0;
				lua_pushstring(ls, (char*)ch->m_lua_fld_storage);
				return 1;
			}
		case PT_SOCKADDR:
			ASSERT(false);
			return 0;
		case PT_SOCKFAMILY:
			ASSERT(false);
			return 0;
		case PT_BOOL:
			lua_pushboolean(ls, (*(uint32_t*)rawval != 0));
			return 1;
		case PT_IPV4ADDR:
			{
				lua_getglobal(ls, "sichisel");
				sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
				lua_pop(ls, 1);

				snprintf(ch->m_lua_fld_storage,
							sizeof(ch->m_lua_fld_storage),
							"%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8,
							rawval[0],
							rawval[1],
							rawval[2],
							rawval[3]);

				lua_pushstring(ls, ch->m_lua_fld_storage);
				return 1;
			}
		default:
			ASSERT(false);
			string err = "wrong event type " + to_string((long long) finfo->m_type);
			fprintf(stderr, "%s\n", err.c_str());
			throw sinsp_exception("chisel error");
	}
}

int lua_cbacks::get_num(lua_State *ls) 
{
	lua_getglobal(ls, "sievt");
	sinsp_evt* evt = (sinsp_evt*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	if(evt == NULL)
	{
		string err = "invalid call to evt.get_num()";
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("chisel error");
	}

	lua_pushnumber(ls, (double)evt->get_num());
	return 1;
}

int lua_cbacks::get_ts(lua_State *ls) 
{
	lua_getglobal(ls, "sievt");
	sinsp_evt* evt = (sinsp_evt*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	if(evt == NULL)
	{
		string err = "invalid call to evt.get_ts()";
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("chisel error");
	}

	uint64_t ts = evt->get_ts();

	lua_pushinteger(ls, (uint32_t)(ts / 1000000000));
	lua_pushinteger(ls, (uint32_t)(ts % 1000000000));
	return 2;
}

int lua_cbacks::get_type(lua_State *ls) 
{
	lua_getglobal(ls, "sievt");
	sinsp_evt* evt = (sinsp_evt*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	if(evt == NULL)
	{
		string err = "invalid call to evt.get_type()";
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("chisel error");
	}

	const char* evname;
	uint16_t etype = evt->get_type();

	if(etype == PPME_GENERIC_E || etype == PPME_GENERIC_X)
	{
		sinsp_evt_param *parinfo = evt->get_param(0);
		ASSERT(parinfo->m_len == sizeof(uint16_t));
		uint16_t evid = *(uint16_t *)parinfo->m_val;

		evname = g_infotables.m_syscall_info_table[evid].name;
	}
	else
	{
		evname = evt->get_name();
	}

	lua_pushstring(ls, evname);

	return 1;
}

int lua_cbacks::get_cpuid(lua_State *ls) 
{
	lua_getglobal(ls, "sievt");
	sinsp_evt* evt = (sinsp_evt*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	if(evt == NULL)
	{
		string err = "invalid call to evt.get_cpuid()";
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("chisel error");
	}

	uint32_t cpuid = evt->get_cpuid();

	lua_pushinteger(ls, cpuid);
	return 1;
}

int lua_cbacks::request_field(lua_State *ls) 
{
	lua_getglobal(ls, "sichisel");

	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	sinsp* inspector = ch->m_inspector;

	const char* fld = lua_tostring(ls, 1); 

	if(fld == NULL)
	{
		string err = "chisel requesting nil field";
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("chisel error");
	}

	sinsp_filter_check* chk = g_filterlist.new_filter_check_from_fldname(fld,
		inspector, 
		false);

	if(chk == NULL)
	{
		string err = "chisel requesting nonexistent field " + string(fld);
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("chisel error");
	}

	chk->parse_field_name(fld);

	lua_pushlightuserdata(ls, chk);

	ch->m_allocated_fltchecks.push_back(chk);

	return 1;
}

int lua_cbacks::field(lua_State *ls) 
{
	lua_getglobal(ls, "sievt");
	sinsp_evt* evt = (sinsp_evt*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	if(evt == NULL)
	{
		string err = "invalid call to evt.field()";
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("chisel error");
	}

	sinsp_filter_check* chk = (sinsp_filter_check*)lua_topointer(ls, 1);
	if(chk == NULL)
	{
		//
		// This happens if the lua code is calling field() without invoking 
		// sysdig.request_field() before. 
		//
		lua_pushnil(ls);
		return 1;
	}

	uint32_t vlen;
	uint8_t* rawval = chk->extract(evt, &vlen);

	if(rawval != NULL)
	{
		return rawval_to_lua_stack(ls, rawval, chk->get_field_info(), vlen);
	}
	else
	{
		lua_pushnil(ls);
		return 1;
	}
}

int lua_cbacks::set_global_filter(lua_State *ls) 
{
	lua_getglobal(ls, "sichisel");

	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	const char* filter = lua_tostring(ls, 1); 

	ASSERT(ch);
	ASSERT(ch->m_lua_cinfo);

	try
	{
		ch->m_inspector->set_filter(filter);
	}
	catch(sinsp_exception& e)
	{
		string err = "invalid filter in chisel " + ch->m_filename + ": " + e.what();
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("chisel error");
	}

	return 0;
}

int lua_cbacks::set_filter(lua_State *ls) 
{
	lua_getglobal(ls, "sichisel");

	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	const char* filter = lua_tostring(ls, 1); 

	ASSERT(ch);
	ASSERT(ch->m_lua_cinfo);

	try
	{
		ch->m_lua_cinfo->set_filter(filter);
	}
	catch(sinsp_exception& e)
	{
		string err = "invalid filter in chisel " + ch->m_filename + ": " + e.what();
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("chisel error");
	}

	return 0;
}

int lua_cbacks::set_snaplen(lua_State *ls) 
{
	lua_getglobal(ls, "sichisel");

	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	const uint32_t snaplen = (uint32_t)lua_tointeger(ls, 1); 

	ASSERT(ch);
	ASSERT(ch->m_lua_cinfo);

	ch->m_inspector->set_snaplen(snaplen);

	return 0;
}

int lua_cbacks::set_output_format(lua_State *ls) 
{
	lua_getglobal(ls, "sichisel");

	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	ASSERT(ch);
	ASSERT(ch->m_lua_cinfo);

	if(ch->m_inspector->get_buffer_format() != sinsp_evt::PF_NORMAL)
	{
		//
		// This means that the user has forced the format on the command line.
		// We give that priority and we do nothing.
		//
		return 0;
	}

	const char* fmt = lua_tostring(ls, 1); 

	if(string(fmt) == "normal")
	{
		ch->m_inspector->set_buffer_format(sinsp_evt::PF_NORMAL);
	}
	else if(string(fmt) == "json")
	{
		ch->m_inspector->set_buffer_format(sinsp_evt::PF_JSON);
	}
	else if(string(fmt) == "simple")
	{
		ch->m_inspector->set_buffer_format(sinsp_evt::PF_SIMPLE);
	}
	else if(string(fmt) == "hex")
	{
		ch->m_inspector->set_buffer_format(sinsp_evt::PF_HEX);
	}
	else if(string(fmt) == "hexascii")
	{
		ch->m_inspector->set_buffer_format(sinsp_evt::PF_HEXASCII);
	}
	else if(string(fmt) == "ascii")
	{
		ch->m_inspector->set_buffer_format(sinsp_evt::PF_EOLS);
	}
	else
	{
		string err = "invalid set_output_format value in chisel " + ch->m_filename;
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("chisel error");
	}

	return 0;
}

int lua_cbacks::set_fatfile_dump_mode(lua_State *ls) 
{
	lua_getglobal(ls, "sichisel");

	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	int mode = lua_toboolean(ls, 1); 

	ASSERT(ch);
	ASSERT(ch->m_lua_cinfo);

	ch->m_inspector->set_fatfile_dump_mode(mode != 0);

	return 0;
}

int lua_cbacks::make_ts(lua_State *ls) 
{
	lua_getglobal(ls, "sichisel");

	uint32_t op1 = (uint32_t)lua_tointeger(ls, 1);
	lua_pop(ls, 1);
	uint32_t op2 = (uint32_t)lua_tointeger(ls, 2);
	lua_pop(ls, 1);

	uint64_t sum = (uint64_t)op1 * ONE_SECOND_IN_NS + op2;

	lua_pushstring(ls, to_string((long long) sum).c_str());
	return 1;
}

int lua_cbacks::run_sysdig(lua_State *ls) 
{
	lua_getglobal(ls, "sichisel");

	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	const char* args = lua_tostring(ls, 1); 

	ASSERT(ch);
	ASSERT(ch->m_lua_cinfo);

	ch->m_lua_cinfo->m_has_nextrun_args = true;
	ch->m_lua_cinfo->m_nextrun_args = args;

	return 0;
}

int lua_cbacks::is_live(lua_State *ls) 
{
	lua_getglobal(ls, "sichisel");

	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	ASSERT(ch);
	ASSERT(ch->m_lua_cinfo);

	lua_pushboolean(ls, ch->m_inspector->is_live());
	return 1;
}

int lua_cbacks::is_tty(lua_State *ls) 
{
#ifdef _WIN32
	int use_color = false;
#else
	int use_color = isatty(1);
#endif

	lua_pushboolean(ls, use_color);
	return 1;
}

int lua_cbacks::get_machine_info(lua_State *ls) 
{
	lua_getglobal(ls, "sichisel");

	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	ASSERT(ch);
	ASSERT(ch->m_lua_cinfo);

	const scap_machine_info* minfo = ch->m_inspector->get_machine_info();

	lua_newtable(ls);
	lua_pushstring(ls, "num_cpus");
	lua_pushnumber(ls, minfo->num_cpus);
	lua_settable(ls, -3);
	lua_pushstring(ls, "memory_size_bytes");
	lua_pushnumber(ls, (double)minfo->memory_size_bytes);
	lua_settable(ls, -3);
	lua_pushstring(ls, "max_pid");
	lua_pushnumber(ls, (double)minfo->max_pid);
	lua_settable(ls, -3);
	lua_pushstring(ls, "hostname");
	lua_pushstring(ls, minfo->hostname);
	lua_settable(ls, -3);

	return 1;
}

int lua_cbacks::get_output_format(lua_State *ls) 
{
	lua_getglobal(ls, "sichisel");

	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	ASSERT(ch);
	ASSERT(ch->m_lua_cinfo);

	sinsp_evt::param_fmt fmt = ch->m_inspector->get_buffer_format();

	if(fmt & sinsp_evt::PF_JSON)
	{
		lua_pushstring(ls, "json");
	}
	else
	{
		lua_pushstring(ls, "normal");
	}

	return 1;
}

int lua_cbacks::get_evtsource_name(lua_State *ls) 
{
	lua_getglobal(ls, "sichisel");

	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	ASSERT(ch);
	ASSERT(ch->m_lua_cinfo);

	if(ch->m_inspector->is_live())
	{
		lua_pushstring(ls, "");
	}
	else
	{
		lua_pushstring(ls, ch->m_inspector->get_input_filename().c_str());
	}

	return 1;
}

int lua_cbacks::set_event_formatter(lua_State *ls) 
{
	lua_getglobal(ls, "sichisel");

	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	const char* formatter = lua_tostring(ls, 1); 

	ASSERT(ch);
	ASSERT(ch->m_lua_cinfo);

	ch->m_lua_cinfo->set_formatter(formatter);

	return 0;
}

int lua_cbacks::set_interval_ns(lua_State *ls) 
{
	lua_getglobal(ls, "sichisel");

	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	uint64_t interval = (uint64_t)lua_tonumber(ls, 1);

	ASSERT(ch);
	ASSERT(ch->m_lua_cinfo);

	ch->m_lua_cinfo->set_callback_interval(interval);

	return 0;
}

int lua_cbacks::set_interval_s(lua_State *ls) 
{
	lua_getglobal(ls, "sichisel");

	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	uint64_t interval = (uint64_t)lua_tonumber(ls, 1);

	ASSERT(ch);
	ASSERT(ch->m_lua_cinfo);

	ch->m_lua_cinfo->set_callback_interval(interval * 1000000000);

	return 0;
}

int lua_cbacks::exec(lua_State *ls) 
{
	lua_getglobal(ls, "sichisel");

	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	ASSERT(ch);
	ASSERT(ch->m_lua_cinfo);

	const char* chname = lua_tostring(ls, 1);
	if(chname == NULL)
	{
		string err = "invalid exec field name in chisel " + ch->m_filename;
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("chisel error");
	}

	ch->m_new_chisel_to_exec = chname;

	ch->m_argvals.clear();
	uint32_t stackpos = 2;

	while(true)
	{
		const char* argval = lua_tostring(ls, stackpos++);
		if(argval == NULL)
		{
			break;
		}

		ch->m_argvals.push_back(argval);
	}

	return 0;
}

#endif // HAS_LUA_CHISELS
#endif // HAS_CHISELS
