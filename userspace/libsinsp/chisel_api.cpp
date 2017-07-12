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
#ifdef _WIN32
#include <io.h>
#else
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#endif
#include <third-party/tinydir.h>
#include <json/json.h>

#include "sinsp.h"
#include "sinsp_int.h"
#include "chisel.h"
#include "chisel_api.h"
#include "filter.h"
#include "filterchecks.h"
#ifdef HAS_ANALYZER
#include "analyzer.h"
#endif

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
void lua_stackdump(lua_State *L);

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
		case PT_FD:
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
		case PT_UID:
		case PT_GID:
			lua_pushnumber(ls, *(uint32_t*)rawval);
			return 1;
		case PT_UINT64:
		case PT_RELTIME:
		case PT_ABSTIME:
			lua_pushnumber(ls, (double)*(uint64_t*)rawval);
			return 1;
		case PT_DOUBLE:
			lua_pushnumber(ls, *(double*)rawval);
			return 1;
		case PT_CHARBUF:
		case PT_FSPATH:
			lua_pushlstring(ls, (char*)rawval, len);
			return 1;
		case PT_BYTEBUF:
			if(rawval[len] == 0)
			{
				lua_pushlstring(ls, (char*)rawval, len);
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
				lua_pushlstring(ls, (char*)ch->m_lua_fld_storage, max_len);
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

	chk->parse_field_name(fld, true, false);

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
	else if(string(fmt) == "base64")
	{
		ch->m_inspector->set_buffer_format(sinsp_evt::PF_BASE64);
	}
	else if(string(fmt) == "jsonbase64")
	{
		ch->m_inspector->set_buffer_format(sinsp_evt::PF_JSONBASE64);
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

int lua_cbacks::end_capture(lua_State *ls)
{
	lua_getglobal(ls, "sichisel");

	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	ASSERT(ch);
	ASSERT(ch->m_lua_cinfo);

	ch->m_lua_cinfo->m_end_capture = true;

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

int lua_cbacks::get_terminal_info(lua_State *ls)
{
	int32_t width = -1;
	int32_t height = -1;
#ifndef _WIN32
	struct winsize w;

	if(ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != -1)
	{
		width = w.ws_col;
		height = w.ws_row;
	}
#endif

	lua_newtable(ls);
	lua_pushstring(ls, "width");
	lua_pushnumber(ls, width);
	lua_settable(ls, -3);
	lua_pushstring(ls, "height");
	lua_pushnumber(ls, height);
	lua_settable(ls, -3);

	return 1;
}

int lua_cbacks::get_filter(lua_State *ls)
{
	lua_getglobal(ls, "sichisel");

	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	ASSERT(ch);
	ASSERT(ch->m_inspector);

	string flts = ch->m_inspector->get_filter();

	lua_pushstring(ls, flts.c_str());

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

	if(minfo == NULL)
	{
		string err = "get_machine_info can only be called from the on_capture_start callback";
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("chisel error");
	}

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

int lua_cbacks::get_thread_table(lua_State *ls)
{
	threadinfo_map_iterator_t it;
	unordered_map<int64_t, sinsp_fdinfo_t>::iterator fdit;
	uint32_t j;
	sinsp_filter_compiler* compiler = NULL;
	sinsp_filter* filter = NULL;
	sinsp_evt tevt;
	scap_evt tscapevt;
	char ipbuf[128];

	//
	// Get the chisel state
	//
	lua_getglobal(ls, "sichisel");

	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	ASSERT(ch);
	ASSERT(ch->m_lua_cinfo);
	ASSERT(ch->m_inspector);

	//
	// If the caller specified a filter, compile it
	//
	if(lua_isstring(ls, 1))
	{
		string filterstr = lua_tostring(ls, 1);
		lua_pop(ls, 1);

		try
		{
			compiler = new sinsp_filter_compiler(ch->m_inspector, filterstr, true);
			filter = compiler->compile();
		}
		catch(sinsp_exception& e)
		{
			string err = "invalid filter argument for get_thread_table in chisel " + ch->m_filename + ": " + e.what();
			fprintf(stderr, "%s\n", err.c_str());
			throw sinsp_exception("chisel error");
		}

		tscapevt.ts = 0;
		tscapevt.type = PPME_SYSCALL_READ_X;
		tscapevt.len = 0;

		tevt.m_inspector = ch->m_inspector;
		tevt.m_info = &(g_infotables.m_event_info[PPME_SYSCALL_READ_X]);
		tevt.m_pevt = NULL;
		tevt.m_cpuid = 0;
		tevt.m_evtnum = 0;
		tevt.m_pevt = &tscapevt;
	}

	threadinfo_map_t* threadtable  = ch->m_inspector->m_thread_manager->get_threads();

	ASSERT(threadtable != NULL);

	lua_newtable(ls);

	for(it = threadtable->begin(); it != threadtable->end(); ++it)
	{
		//
		// Check if there's at least an fd that matches the filter.
		// If not, skip this thread
		//
		sinsp_fdtable* fdtable = it->second.get_fd_table();

		if(filter != NULL)
		{
			bool match = false;

			for(fdit = fdtable->m_table.begin(); fdit != fdtable->m_table.end(); ++fdit)
			{
				tevt.m_tinfo = &(it->second);
				tevt.m_fdinfo = &(fdit->second);
				tscapevt.tid = it->first;
				int64_t tlefd = tevt.m_tinfo->m_lastevent_fd;
				tevt.m_tinfo->m_lastevent_fd = fdit->first;

				if(filter->run(&tevt))
				{
					match = true;
					break;
				}

				tevt.m_tinfo->m_lastevent_fd = tlefd;
			}

			if(!match)
			{
				continue;
			}
		}

		//
		// Set the thread properties
		//
		lua_newtable(ls);
		lua_pushliteral(ls, "tid");
		lua_pushnumber(ls, (uint32_t)it->second.m_tid);
		lua_settable(ls, -3);
		lua_pushliteral(ls, "pid");
		lua_pushnumber(ls, (uint32_t)it->second.m_pid);
		lua_settable(ls, -3);
		lua_pushliteral(ls, "ptid");
		lua_pushnumber(ls, (uint32_t)it->second.m_ptid);
		lua_settable(ls, -3);
		lua_pushliteral(ls, "comm");
		lua_pushstring(ls, it->second.m_comm.c_str());
		lua_settable(ls, -3);
		lua_pushliteral(ls, "exe");
		lua_pushstring(ls, it->second.m_exe.c_str());
		lua_settable(ls, -3);
		lua_pushliteral(ls, "flags");
		lua_pushnumber(ls, (uint32_t)it->second.m_flags);
		lua_settable(ls, -3);
		lua_pushliteral(ls, "fdlimit");
		lua_pushnumber(ls, (uint32_t)it->second.m_fdlimit);
		lua_settable(ls, -3);
		lua_pushliteral(ls, "uid");
		lua_pushnumber(ls, (uint32_t)it->second.m_uid);
		lua_settable(ls, -3);
		lua_pushliteral(ls, "gid");
		lua_pushnumber(ls, (uint32_t)it->second.m_gid);
		lua_settable(ls, -3);
		lua_pushliteral(ls, "nchilds");
		lua_pushnumber(ls, (uint32_t)it->second.m_nchilds);
		lua_settable(ls, -3);
		lua_pushliteral(ls, "vmsize_kb");
		lua_pushnumber(ls, (uint32_t)it->second.m_vmsize_kb);
		lua_settable(ls, -3);
		lua_pushliteral(ls, "vmrss_kb");
		lua_pushnumber(ls, (uint32_t)it->second.m_vmrss_kb);
		lua_settable(ls, -3);
		lua_pushliteral(ls, "vmswap_kb");
		lua_pushnumber(ls, (uint32_t)it->second.m_vmswap_kb);
		lua_settable(ls, -3);
		lua_pushliteral(ls, "pfmajor");
		lua_pushnumber(ls, (uint32_t)it->second.m_pfmajor);
		lua_settable(ls, -3);
		lua_pushliteral(ls, "pfminor");
		lua_pushnumber(ls, (uint32_t)it->second.m_pfminor);
		lua_settable(ls, -3);
		lua_pushliteral(ls, "clone_ts");
		lua_pushstring(ls, to_string((long long int)it->second.m_clone_ts).c_str());
		lua_settable(ls, -3);

		//
		// Extract the user name
		//
		string username;
		unordered_map<uint32_t, scap_userinfo*>::const_iterator uit;

		const unordered_map<uint32_t, scap_userinfo*>* userlist = ch->m_inspector->get_userlist();
		ASSERT(userlist->size() != 0);

		if(it->second.m_uid == 0xffffffff)
		{
			username = "<NA>";
		}
		else
		{
			uit = userlist->find(it->second.m_uid);
			if(uit == userlist->end())
			{
				username = "<NA>";
			}
			else
			{
				ASSERT(uit->second != NULL);
				username = uit->second->name;
			}
		}

		lua_pushliteral(ls, "username");
		lua_pushstring(ls, username.c_str());
		lua_settable(ls, -3);

		//
		// Create the arguments sub-table
		//
		lua_pushstring(ls, "args");

		vector<string>* args = &(it->second.m_args);
		lua_newtable(ls);
		for(j = 0; j < args->size(); j++)
		{
			lua_pushinteger(ls, j + 1);
			lua_pushstring(ls, args->at(j).c_str());
			lua_settable(ls, -3);
		}
		lua_settable(ls,-3);

		//
		// Create the environment variables sub-table
		//
		lua_pushstring(ls, "env");

		const auto& env = it->second.get_env();
		lua_newtable(ls);
		for(j = 0; j < env.size(); j++)
		{
			lua_pushinteger(ls, j + 1);
			lua_pushstring(ls, env.at(j).c_str());
			lua_settable(ls, -3);
		}
		lua_settable(ls,-3);

		//
		// Create and populate the FD table
		//
		lua_pushstring(ls, "fdtable");
		lua_newtable(ls);
		for(fdit = fdtable->m_table.begin(); fdit != fdtable->m_table.end(); ++fdit)
		{
			tevt.m_tinfo = &(it->second);
			tevt.m_fdinfo = &(fdit->second);
			tscapevt.tid = it->first;
			int64_t tlefd = tevt.m_tinfo->m_lastevent_fd;
			tevt.m_tinfo->m_lastevent_fd = fdit->first;

			if(filter != NULL)
			{
				if(filter->run(&tevt) == false)
				{
					continue;
				}
			}

			tevt.m_tinfo->m_lastevent_fd = tlefd;

			lua_newtable(ls);
			lua_pushliteral(ls, "name");
			lua_pushstring(ls, fdit->second.tostring_clean().c_str());
			lua_settable(ls, -3);
			lua_pushliteral(ls, "type");
			lua_pushstring(ls, fdit->second.get_typestring());
			lua_settable(ls, -3);

			scap_fd_type evt_type = fdit->second.m_type;
			if(evt_type == SCAP_FD_IPV4_SOCK || evt_type == SCAP_FD_IPV4_SERVSOCK)
			{
				uint8_t* pip4;

				if(evt_type == SCAP_FD_IPV4_SOCK)
				{
					// cip
					pip4 = (uint8_t*)&(fdit->second.m_sockinfo.m_ipv4info.m_fields.m_sip);
					snprintf(ipbuf,
						sizeof(ipbuf),
						"%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8,
						pip4[0],
						pip4[1],
						pip4[2],
						pip4[3]);

					lua_pushliteral(ls, "cip");
					lua_pushstring(ls, ipbuf);
					lua_settable(ls, -3);

					// sip
					pip4 = (uint8_t*)&(fdit->second.m_sockinfo.m_ipv4info.m_fields.m_dip);
					snprintf(ipbuf,
						sizeof(ipbuf),
						"%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8,
						pip4[0],
						pip4[1],
						pip4[2],
						pip4[3]);

					lua_pushliteral(ls, "sip");
					lua_pushstring(ls, ipbuf);
					lua_settable(ls, -3);

					// cport
					lua_pushliteral(ls, "cport");
					lua_pushnumber(ls, fdit->second.m_sockinfo.m_ipv4info.m_fields.m_sport);
					lua_settable(ls, -3);

					// sport
					lua_pushliteral(ls, "sport");
					lua_pushnumber(ls, fdit->second.m_sockinfo.m_ipv4info.m_fields.m_dport);
					lua_settable(ls, -3);

					// is_server
					lua_pushliteral(ls, "is_server");
					lua_pushboolean(ls, fdit->second.is_role_server());
					lua_settable(ls, -3);
				}
				else
				{
					// sip
					pip4 = (uint8_t*)&(fdit->second.m_sockinfo.m_ipv4serverinfo.m_ip);
					snprintf(ipbuf,
						sizeof(ipbuf),
						"%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8,
						pip4[0],
						pip4[1],
						pip4[2],
						pip4[3]);

					lua_pushliteral(ls, "sip");
					lua_pushstring(ls, ipbuf);
					lua_settable(ls, -3);

					// sport
					lua_pushliteral(ls, "sport");
					lua_pushnumber(ls, fdit->second.m_sockinfo.m_ipv4serverinfo.m_port);
					lua_settable(ls, -3);

					// is_server
					lua_pushliteral(ls, "is_server");
					lua_pushboolean(ls, 1);
					lua_settable(ls, -3);
				}

				// l4proto
				const char* l4ps;
				scap_l4_proto l4p = fdit->second.get_l4proto();

				switch(l4p)
				{
				case SCAP_L4_TCP:
					l4ps = "tcp";
					break;
				case SCAP_L4_UDP:
					l4ps = "udp";
					break;
				case SCAP_L4_ICMP:
					l4ps = "icmp";
					break;
				case SCAP_L4_RAW:
					l4ps = "raw";
					break;
				default:
					l4ps = "<NA>";
					break;
				}

				// l4proto
				lua_pushliteral(ls, "l4proto");
				lua_pushstring(ls, l4ps);
				lua_settable(ls, -3);
			}

			// is_server
			string l4proto;

			lua_rawseti(ls,-2, (uint32_t)fdit->first);
		}
		lua_settable(ls,-3);

		//
		// Set the key for this entry
		//
		lua_rawseti(ls,-2, (uint32_t)it->first);
	}

	if(filter)
	{
		delete filter;
	}

	return 1;
}

int lua_cbacks::get_container_table(lua_State *ls)
{
	unordered_map<int64_t, sinsp_fdinfo_t>::iterator fdit;
	uint32_t j;
	sinsp_evt tevt;

	//
	// Get the chisel state
	//
	lua_getglobal(ls, "sichisel");

	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	ASSERT(ch);
	ASSERT(ch->m_lua_cinfo);
	ASSERT(ch->m_inspector);

	//
	// Retrieve the container list
	//
	const unordered_map<string, sinsp_container_info>* ctable  = ch->m_inspector->m_container_manager.get_containers();

	ASSERT(ctable != NULL);

	lua_newtable(ls);

	//
	// Go through the list
	//
	j = 0;
	for(auto it = ctable->begin(); it != ctable->end(); ++it)
	{
		lua_newtable(ls);
		lua_pushliteral(ls, "id");
		lua_pushstring(ls, it->second.m_id.c_str());
		lua_settable(ls, -3);
		lua_pushliteral(ls, "name");
		lua_pushstring(ls, it->second.m_name.c_str());
		lua_settable(ls, -3);
		lua_pushliteral(ls, "image");
		lua_pushstring(ls, it->second.m_image.c_str());
		lua_settable(ls, -3);

		lua_pushliteral(ls, "type");
		if(it->second.m_type == CT_DOCKER)
		{
			lua_pushstring(ls, "docker");
		}
		else if(it->second.m_type == CT_LXC)
		{
			lua_pushstring(ls, "lxc");
		}
		else if(it->second.m_type == CT_LIBVIRT_LXC)
		{
			lua_pushstring(ls, "libvirt_lxc");
		}
		else if(it->second.m_type == CT_MESOS)
		{
			lua_pushstring(ls, "mesos");
		}
		else if(it->second.m_type == CT_RKT)
		{
			lua_pushstring(ls, "rkt");
		}
		else
		{
			ASSERT(false);
			lua_pushstring(ls, "unknown");
		}
		lua_settable(ls, -3);

		//
		// Set the key for this entry
		//
		lua_rawseti(ls,-2, (uint32_t)++j);
	}

	return 1;
}

int lua_cbacks::is_print_container_data(lua_State *ls)
{
        lua_getglobal(ls, "sichisel");

        sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
        lua_pop(ls, 1);

        ASSERT(ch);
        ASSERT(ch->m_lua_cinfo);

        lua_pushboolean(ls, ch->m_inspector->is_print_container_data());
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

int lua_cbacks::log(lua_State *ls)
{
	lua_getglobal(ls, "sichisel");

	string message(lua_tostring(ls, 1));
	string sevstr(lua_tostring(ls, 2));

	sinsp_logger::severity sevcode = sinsp_logger::SEV_INFO;

	if(sevstr == "debug")
	{
		sevcode = sinsp_logger::SEV_DEBUG;
	}
	else if(sevstr == "info")
	{
		sevcode = sinsp_logger::SEV_INFO;
	}
	else if(sevstr == "warning")
	{
		sevcode = sinsp_logger::SEV_WARNING;
	}
	else if(sevstr == "error")
	{
		sevcode = sinsp_logger::SEV_ERROR;
	}
	else if(sevstr == "critical")
	{
		sevcode = sinsp_logger::SEV_CRITICAL;
	}

	g_logger.log(message, sevcode);

	return 0;
}

int lua_cbacks::udp_setpeername(lua_State *ls)
{
	lua_getglobal(ls, "sichisel");
	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);

	string addr(lua_tostring(ls, 1));
	string ports(lua_tostring(ls, 2));
	uint16_t port = htons(sinsp_numparser::parseu16(ports));

	ch->m_udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if(ch->m_udp_socket < 0)
	{
		string err = "udp_setpeername error: unable to create the socket";
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("chisel error");
	}

	memset(&ch->m_serveraddr, 0, sizeof(ch->m_serveraddr));
	ch->m_serveraddr.sin_family = AF_INET;
	ch->m_serveraddr.sin_port = port;
	if(inet_pton(AF_INET, addr.c_str(), &ch->m_serveraddr.sin_addr) <= 0)
	{
		string err = "inet_pton error occurred";
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("chisel error");
	}

	return 0;
}

int lua_cbacks::udp_send(lua_State *ls)
{
	lua_getglobal(ls, "sichisel");
	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);

	string message(lua_tostring(ls, 1));

	if(sendto(ch->m_udp_socket, message.c_str(), message.size(), 0,
		(struct sockaddr *)&ch->m_serveraddr, sizeof(ch->m_serveraddr)) < 0)
	{
		string err = "udp_send error: cannot send the buffer: ";
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("chisel error");
	}

	return 0;
}

#ifdef HAS_ANALYZER
int lua_cbacks::push_metric(lua_State *ls)
{
	statsd_metric metric;
	metric.m_type = statsd_metric::type_t::GAUGE;

	lua_getglobal(ls, "sichisel");

	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	ASSERT(ch);
	ASSERT(ch->m_lua_cinfo);

	sinsp* inspector = ch->m_inspector;

	//
	// tags
	//
	if(lua_istable(ls, 3))
	{
		lua_pushnil(ls);

		while(lua_next(ls, 3) != 0)
		{
			string tag = lua_tostring(ls, -1);
			metric.m_tags[tag] = "";
			lua_pop(ls, 1);
		}

		lua_pop(ls, 1);
	}
	else
	{
		string err = "error in chisel " + ch->m_filename + ": third argument must be a table";
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("chisel error");
	}

	//
	// Name
	//
	if(lua_isstring(ls, 1))
	{
		metric.m_name = lua_tostring(ls, 1);
	}
	else
	{
		string err = "errord in chisel " + ch->m_filename + ": first argument must be a string";
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("chisel error");
	}

	//
	// Value
	//
	if(lua_isnumber(ls, 2))
	{
		metric.m_value = lua_tonumber(ls, 2);
	}
	else
	{
		string err = "errord in chisel " + ch->m_filename + ": second argument must be a number";
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("chisel error");
	}

	inspector->m_analyzer->add_chisel_metric(&metric);

	return 0;
}

#endif // HAS_ANALYZER
#endif // HAS_LUA_CHISELS
#endif // HAS_CHISELS
