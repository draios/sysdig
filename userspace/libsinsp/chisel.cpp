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
#endif
#include <third-party/tinydir.h>
#include <json/json.h>

#include "sinsp.h"
#include "sinsp_int.h"
#include "chisel.h"
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
// For Lua debugging
///////////////////////////////////////////////////////////////////////////////
#ifdef HAS_LUA_CHISELS
void lua_stackdump(lua_State *L) 
{
	int i;
	int top = lua_gettop(L);
	for (i = 1; i <= top; i++) 
	{
		int t = lua_type(L, i);
		switch (t) 
		{

		case LUA_TSTRING:  // strings
			printf("`%s'", lua_tostring(L, i));
			break;

		case LUA_TBOOLEAN:  // booleans
			printf(lua_toboolean(L, i) ? "true" : "false");
			break;

		case LUA_TNUMBER:  // numbers
			printf("%g", lua_tonumber(L, i));
			break;

		default:  // other values
			printf("%s", lua_typename(L, t));
			break;
		}

		printf("  ");  // put a separator
	}

	printf("\n");  // end the listing
}
#endif

///////////////////////////////////////////////////////////////////////////////
// Lua callbacks
///////////////////////////////////////////////////////////////////////////////
#ifdef HAS_LUA_CHISELS
class lua_cbacks
{
public:
	static uint32_t rawval_to_lua_stack(lua_State *ls, uint8_t* rawval, const filtercheck_field_info* finfo, uint32_t len)
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
				throw sinsp_exception("wrong event type " + to_string((long long) finfo->m_type));
		}
	}

	static int get_num(lua_State *ls) 
	{
		lua_getglobal(ls, "sievt");
		sinsp_evt* evt = (sinsp_evt*)lua_touserdata(ls, -1);
		lua_pop(ls, 1);

		if(evt == NULL)
		{
			throw sinsp_exception("invalid call to evt.get_num()");
		}

		lua_pushnumber(ls, (double)evt->get_num());
		return 1;
	}

	static int get_ts(lua_State *ls) 
	{
		lua_getglobal(ls, "sievt");
		sinsp_evt* evt = (sinsp_evt*)lua_touserdata(ls, -1);
		lua_pop(ls, 1);

		if(evt == NULL)
		{
			throw sinsp_exception("invalid call to evt.get_ts()");
		}

		uint64_t ts = evt->get_ts();

		lua_pushinteger(ls, (uint32_t)(ts / 1000000000));
		lua_pushinteger(ls, (uint32_t)(ts % 1000000000));
		return 2;
	}

	static int get_type(lua_State *ls) 
	{
		lua_getglobal(ls, "sievt");
		sinsp_evt* evt = (sinsp_evt*)lua_touserdata(ls, -1);
		lua_pop(ls, 1);

		if(evt == NULL)
		{
			throw sinsp_exception("invalid call to evt.get_type()");
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

	static int get_cpuid(lua_State *ls) 
	{
		lua_getglobal(ls, "sievt");
		sinsp_evt* evt = (sinsp_evt*)lua_touserdata(ls, -1);
		lua_pop(ls, 1);

		if(evt == NULL)
		{
			throw sinsp_exception("invalid call to evt.get_cpuid()");
		}

		uint32_t cpuid = evt->get_cpuid();

		lua_pushinteger(ls, cpuid);
		return 1;
	}

	static int request_field(lua_State *ls) 
	{
		lua_getglobal(ls, "sichisel");

		sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
		lua_pop(ls, 1);

		sinsp* inspector = ch->m_inspector;

		const char* fld = lua_tostring(ls, 1); 

		if(fld == NULL)
		{
			throw sinsp_exception("chisel requesting nil field");
		}

		sinsp_filter_check* chk = g_filterlist.new_filter_check_from_fldname(fld,
			inspector, 
			false);

		if(chk == NULL)
		{
			throw sinsp_exception("chisel requesting nonexistent field " + string(fld));
		}

		chk->parse_field_name(fld);

		lua_pushlightuserdata(ls, chk);

		ch->m_allocated_fltchecks.push_back(chk);

		return 1;
	}

	static int field(lua_State *ls) 
	{
		lua_getglobal(ls, "sievt");
		sinsp_evt* evt = (sinsp_evt*)lua_touserdata(ls, -1);
		lua_pop(ls, 1);

		if(evt == NULL)
		{
			throw sinsp_exception("invalid call to evt.field()");
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

	static int set_global_filter(lua_State *ls) 
	{
		lua_getglobal(ls, "sichisel");

		sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
		lua_pop(ls, 1);

		const char* filter = lua_tostring(ls, 1); 

		ASSERT(ch);
		ASSERT(ch->m_lua_cinfo);

		ch->m_inspector->set_filter(filter);

		return 0;
	}

	static int set_filter(lua_State *ls) 
	{
		lua_getglobal(ls, "sichisel");

		sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
		lua_pop(ls, 1);

		const char* filter = lua_tostring(ls, 1); 

		ASSERT(ch);
		ASSERT(ch->m_lua_cinfo);

		ch->m_lua_cinfo->set_filter(filter);

		return 0;
	}

	static int set_snaplen(lua_State *ls) 
	{
		lua_getglobal(ls, "sichisel");

		sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
		lua_pop(ls, 1);

		const uint32_t snaplen = lua_tointeger(ls, 1); 

		ASSERT(ch);
		ASSERT(ch->m_lua_cinfo);

		ch->m_inspector->set_snaplen(snaplen);

		return 0;
	}

	static int make_ts(lua_State *ls) 
	{
		lua_getglobal(ls, "sichisel");

		uint32_t op1 = lua_tointeger(ls, 1);
		lua_pop(ls, 1);
		uint32_t op2 = lua_tointeger(ls, 2);
		lua_pop(ls, 1);

		uint64_t sum = (uint64_t)op1 * ONE_SECOND_IN_NS + op2;

		lua_pushstring(ls, to_string((long long) sum).c_str());
		return 1;
	}

	static int is_live(lua_State *ls) 
	{
		lua_getglobal(ls, "sichisel");

		sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
		lua_pop(ls, 1);

		ASSERT(ch);
		ASSERT(ch->m_lua_cinfo);

		lua_pushboolean(ls, ch->m_inspector->is_live());
		return 1;
	}

	static int get_machine_info(lua_State *ls) 
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

	static int get_output_format(lua_State *ls) 
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

	static int set_event_formatter(lua_State *ls) 
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

	static int set_interval_ns(lua_State *ls) 
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

	static int set_interval_s(lua_State *ls) 
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

	static int exec(lua_State *ls) 
	{
		lua_getglobal(ls, "sichisel");

		sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
		lua_pop(ls, 1);

		ASSERT(ch);
		ASSERT(ch->m_lua_cinfo);

		const char* chname = lua_tostring(ls, 1);
		if(chname == NULL)
		{
			throw sinsp_exception("invalid exec field name in chisel " + ch->m_filename);
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
};

const static struct luaL_reg ll_sysdig [] = 
{
	{"set_filter", &lua_cbacks::set_global_filter},
	{"set_snaplen", &lua_cbacks::set_snaplen},
	{"is_live", &lua_cbacks::is_live},
	{"get_machine_info", &lua_cbacks::get_machine_info},
	{"get_output_format", &lua_cbacks::get_output_format},
	{"make_ts", &lua_cbacks::make_ts},
	{NULL,NULL}
};

const static struct luaL_reg ll_chisel [] = 
{
	{"request_field", &lua_cbacks::request_field},
	{"set_filter", &lua_cbacks::set_filter},
	{"set_event_formatter", &lua_cbacks::set_event_formatter},
	{"set_interval_ns", &lua_cbacks::set_interval_ns},
	{"set_interval_s", &lua_cbacks::set_interval_s},
	{"exec", &lua_cbacks::exec},
	{NULL,NULL}
};

const static struct luaL_reg ll_evt [] = 
{
	{"field", &lua_cbacks::field},
	{"get_num", &lua_cbacks::get_num},
	{"get_ts", &lua_cbacks::get_ts},
	{"get_type", &lua_cbacks::get_type},
	{"get_cpuid", &lua_cbacks::get_cpuid},
	{NULL,NULL}
};
#endif // HAS_LUA_CHISELS

///////////////////////////////////////////////////////////////////////////////
// chiselinfo implementation
///////////////////////////////////////////////////////////////////////////////
chiselinfo::chiselinfo(sinsp* inspector)
{
	m_filter = NULL;
	m_formatter = NULL;
	m_dumper = NULL;
	m_inspector = inspector;

#ifdef HAS_LUA_CHISELS
	m_callback_interval = 0;
#endif
}

chiselinfo::~chiselinfo()
{
	if(m_filter)
	{
		delete m_filter;
	}

	if(m_formatter)
	{
		delete m_formatter;
	}

	if(m_dumper)
	{
		delete m_dumper;
	}
}

void chiselinfo::init(string filterstr, string formatterstr)
{
	set_filter(filterstr);
	set_formatter(formatterstr);
}

void chiselinfo::set_filter(string filterstr)
{
	if(m_filter)
	{
		delete m_filter;
		m_filter = NULL;
	}

	if(filterstr != "")
	{
		m_filter = new sinsp_filter(m_inspector, filterstr);
	}
}

void chiselinfo::set_formatter(string formatterstr)
{
	if(m_formatter)
	{
		delete m_formatter;
		m_formatter = NULL;
	}

	if(formatterstr == "" || formatterstr == "default")
	{
		m_formatter = new sinsp_evt_formatter(m_inspector, DEFAULT_OUTPUT_STR);
	}
	else
	{
		m_formatter = new sinsp_evt_formatter(m_inspector, formatterstr);
	}
}

#ifdef HAS_LUA_CHISELS
void chiselinfo::set_callback_interval(uint64_t interval)
{
	m_callback_interval = interval;
}
#endif

///////////////////////////////////////////////////////////////////////////////
// chisel implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_chisel::sinsp_chisel(sinsp* inspector, string filename)
{
	m_inspector = inspector;
	m_ls = NULL;
	m_lua_has_handle_evt = false;
	m_lua_is_first_evt = true;
	m_lua_cinfo = NULL;
	m_lua_last_interval_sample_time = 0;
	m_lua_last_interval_ts = 0;

	load(filename);
}

sinsp_chisel::~sinsp_chisel()
{
	free_lua_chisel();
}

void sinsp_chisel::free_lua_chisel()
{
#ifdef HAS_LUA_CHISELS
	if(m_ls)
	{
		lua_close(m_ls);
		m_ls = NULL;
	}

	for(uint32_t j = 0; j < m_allocated_fltchecks.size(); j++)
	{
		delete m_allocated_fltchecks[j];
	}
	m_allocated_fltchecks.clear();

	if(m_lua_cinfo != NULL)
	{
		delete m_lua_cinfo; 
		m_lua_cinfo = NULL;
	}

	m_lua_script_info.reset();
#endif
}

#ifdef HAS_LUA_CHISELS
void parse_lua_chisel_arg(lua_State *ls, OUT chisel_desc* cd)
{
	lua_pushnil(ls);
	string name;
	string type;
	string desc;
	bool optional = false;

	while(lua_next(ls, -2) != 0)
	{
		if(lua_isstring(ls, -1))
		{
			if(string(lua_tostring(ls, -2)) == "name")
			{
				name = lua_tostring(ls, -1);
			}
			else if(string(lua_tostring(ls, -2)) == "argtype")
			{
				type = lua_tostring(ls, -1);
			}
			else if(string(lua_tostring(ls, -2)) == "description")
			{
				desc = lua_tostring(ls, -1);
			}
		}
		else if(lua_isboolean(ls, -1))
		{
			if(string(lua_tostring(ls, -2)) == "optional")
			{
				optional = (lua_toboolean(ls, -1) != 0);
			}
		}
		else
		{
			throw sinsp_exception(string(lua_tostring(ls, -2)) + " is not a string");
		}

		lua_pop(ls, 1);
	}

	cd->m_args.push_back(chiselarg_desc(name, type, desc, optional));
}

void parse_lua_chisel_args(lua_State *ls, OUT chisel_desc* cd)
{
	lua_pushnil(ls);

	while(lua_next(ls, -2) != 0)
	{
		if(lua_isstring(ls, -1))
		{
			printf("%s = %s\n", lua_tostring(ls, -2), lua_tostring(ls, -1));
			cd->m_description = lua_tostring(ls, -1);
		}
		else if(lua_istable(ls, -1))
		{
			parse_lua_chisel_arg(ls, cd);
		}
		else
		{
			throw sinsp_exception(string(lua_tostring(ls, -2)) + " is not a string");
		}

		lua_pop(ls, 1);
	}
}

void sinsp_chisel::add_lua_package_path(lua_State* ls, const char* path)
{
	lua_getglobal(ls, "package");
	lua_getfield(ls, -1, "path"); 

	string cur_path = lua_tostring(ls, -1 );
	cur_path += ';';
	cur_path.append(path);
	lua_pop(ls, 1);

	lua_pushstring(ls, cur_path.c_str());
	lua_setfield(ls, -2, "path");
	lua_pop(ls, 1);
}
#endif

#ifdef HAS_LUA_CHISELS
// Initializes a lua chisel
bool sinsp_chisel::init_lua_chisel(chisel_desc &cd, string const &fpath)
{
	lua_State* ls = lua_open();
	luaL_openlibs(ls);

	//
	// Load our own lua libs
	//
	luaL_openlib(ls, "sysdig", ll_sysdig, 0);
	luaL_openlib(ls, "chisel", ll_chisel, 0);
	luaL_openlib(ls, "evt", ll_evt, 0);

	//
	// Add our chisel paths to package.path
	//
	for(vector<chiseldir_info>::const_iterator it = g_chisel_dirs->begin();
		it != g_chisel_dirs->end(); ++it)
	{
		string path(it->m_dir);
		path += "?.lua";
		add_lua_package_path(ls, path.c_str());
	}

	//
	// Load the script
	//
	if(luaL_loadfile(ls, fpath.c_str()) || lua_pcall(ls, 0, 0, 0))
	{
		goto failure;
	}

	//
	// Extract the description
	//
	lua_getglobal(ls, "description");
	if(!lua_isstring(ls, -1))
	{
		goto failure;
	}
	cd.m_description = lua_tostring(ls, -1);

	//
	// Extract the short description
	//
	lua_getglobal(ls, "short_description");
	if(!lua_isstring(ls, -1))
	{
		goto failure;
	}
	cd.m_shortdesc = lua_tostring(ls, -1);

	//
	// Extract the category
	//
	cd.m_category = "";
	lua_getglobal(ls, "category");
	if(lua_isstring(ls, -1))
	{
		cd.m_category = lua_tostring(ls, -1);
	}

	//
	// Extract the hidden flag and skip the chisel if it's set
	//
	lua_getglobal(ls, "hidden");
	if(lua_isboolean(ls, -1))
	{
		int sares = lua_toboolean(ls, -1);
		if(sares)
		{
			goto failure;
		}
	}

	//
	// Extract the args
	//
	lua_getglobal(ls, "args");
	try
	{
		parse_lua_chisel_args(ls, &cd);
	}
	catch(...)
	{
		goto failure;
	}
	return true;

failure:
	lua_close(ls);
	return false;
}
#endif

struct filename
{
    bool valid;
    string name;
    string ext;
};

static filename split_filename(string const &fname)
{
	filename res;
	string::size_type idx = fname.rfind('.');
	if(idx == std::string::npos)
	{
		res.valid = false;
	}
	else
	{
		res.valid = true;
		res.name = fname.substr(0, idx);
		res.ext = fname.substr(idx+1);
	}
	return res;
}

//
// 1. Iterates through the chisel files on disk (.sc and .lua)
// 2. Opens them and extracts the fields (name, description, etc)
// 3. Adds them to the chisel_descs vector.
//
void sinsp_chisel::get_chisel_list(vector<chisel_desc>* chisel_descs)
{
	for(vector<chiseldir_info>::const_iterator it = g_chisel_dirs->begin();
		it != g_chisel_dirs->end(); ++it)
	{
		if(string(it->m_dir).empty())
		{
			continue;
		}
		tinydir_dir dir;
		tinydir_open(&dir, it->m_dir);
		while(dir.has_next)
		{
			tinydir_file file;
			tinydir_readfile(&dir, &file);

			string fpath(file.path);
			bool add_to_vector = false;
			chisel_desc cd;

			filename fn = split_filename(string(file.name));
			if(fn.ext != "sc" && fn.ext != "lua")
			{
				goto next_file;
			}

			for(vector<chisel_desc>::const_iterator it_desc = chisel_descs->begin();
				it_desc != chisel_descs->end(); ++it_desc)
			{
				if(fn.name == it_desc->m_name)
				{
					goto next_file;
				}
			}
			cd.m_name = fn.name;
			
#ifdef HAS_LUA_CHISELS
			if(fn.ext == "lua")
			{
				add_to_vector = init_lua_chisel(cd, fpath);
			}
			
			if(add_to_vector)
			{
				chisel_descs->push_back(cd);
			}
#endif
next_file:
			tinydir_next(&dir);
		}
		tinydir_close(&dir);
	}
}

//
// If the function succeeds, is is initialized to point to the file.
// Otherwise, the return value is "false".
//
bool sinsp_chisel::openfile(string filename, OUT ifstream* is)
{
	uint32_t j;

	for(j = 0; j < g_chisel_dirs->size(); j++)
	{
		is->open(string(g_chisel_dirs->at(j).m_dir) + filename);
		if(is->is_open())
		{
			return true;
		}
	}

	return false;
}

void sinsp_chisel::load(string cmdstr)
{
	m_filename = cmdstr;
	trim(cmdstr);

	ifstream is;

	//
	// Try to open the file as is
	//
	if(!openfile(m_filename, &is))
	{
		//
		// Try to add the .sc extension
		//
		if(!openfile(m_filename + ".sc", &is))
		{
			if(!openfile(m_filename + ".lua", &is))
			{
				throw sinsp_exception("can't open file " + m_filename);
			}
		}
	}

	//
	// Bring the file into a string
	//
	string docstr((istreambuf_iterator<char>(is)),
		istreambuf_iterator<char>());

#ifdef HAS_LUA_CHISELS
	//
	// Rewind the stream
	//
	is.seekg(0);

	//
	// Load the file
	//
	std::istreambuf_iterator<char> eos;
	std::string scriptstr(std::istreambuf_iterator<char>(is), eos);

	//
	// Open the script
	//
	m_ls = lua_open();
 
	luaL_openlibs(m_ls);

	//
	// Load our own lua libs
	//
	luaL_openlib(m_ls, "sysdig", ll_sysdig, 0);
	luaL_openlib(m_ls, "chisel", ll_chisel, 0);
	luaL_openlib(m_ls, "evt", ll_evt, 0);

	//
	// Add our chisel paths to package.path
	//
	for(uint32_t j = 0; j < g_chisel_dirs->size(); j++)
	{
		string path(g_chisel_dirs->at(j).m_dir);
		path += "?.lua";
		add_lua_package_path(m_ls, path.c_str());
	}

	//
	// Load the script
	//
	if(luaL_loadstring(m_ls, scriptstr.c_str()) || lua_pcall(m_ls, 0, 0, 0)) 
	{
		throw sinsp_exception("Failed to load chisel " + 
			m_filename + ": " + lua_tostring(m_ls, -1));
	}

	//
	// Allocate the chisel context for the script
	//
	m_lua_cinfo = new chiselinfo(m_inspector);

	//
	// Set the context globals
	//
	lua_pushlightuserdata(m_ls, this);
	lua_setglobal(m_ls, "sichisel");

	//
	// Extract the args
	//
	lua_getglobal(m_ls, "args");
	if(!lua_istable(m_ls, -1))
	{
		throw sinsp_exception("Failed to load chisel " + 
			m_filename + ": args table missing");
	}

	try
	{
		parse_lua_chisel_args(m_ls, &m_lua_script_info);
	}
	catch(sinsp_exception& e)
	{
		throw e;
	}

	//
	// Check if the script has an on_event
	//
	lua_getglobal(m_ls, "on_event");
	if(lua_isfunction(m_ls, -1))
	{
		m_lua_has_handle_evt = true;
		lua_pop(m_ls, 1);
	}
#endif

	is.close();
}

uint32_t sinsp_chisel::get_n_args()
{
	ASSERT(m_ls);

#ifdef HAS_LUA_CHISELS
	return m_lua_script_info.m_args.size();
#else
	return 0;
#endif
}

void sinsp_chisel::set_args(string args)
{
#ifdef HAS_LUA_CHISELS
	uint32_t j;
	uint32_t n_required_args = 0;
	uint32_t n_optional_args = 0;

	for(j = 0; j < m_lua_script_info.m_args.size(); j++)
	{
		if(m_lua_script_info.m_args[j].m_optional)
		{
			n_optional_args++;
		}
		else
		{
			n_required_args++;
		}
	}

	ASSERT(m_ls);

	//
	// Split the argument string into tokens
	//
	uint32_t token_begin = 0;
	bool inquotes = false;
	uint32_t quote_correction = 0;

	trim(args);

	for(j = 0; j < args.size(); j++)
	{
		if(args[j] == ' ' && !inquotes)
		{
			m_argvals.push_back(args.substr(token_begin, j - quote_correction - token_begin));
			token_begin = j + 1;
			quote_correction = 0;
		}
		else if(args[j] == '\'' || args[j] == '`')
		{
			if(inquotes)
			{
				quote_correction = 1;
				inquotes = false;
			}			
			else {
				token_begin++;
				inquotes = true;
			}			
		}
	}
	
	if(inquotes)
	{
		throw sinsp_exception("corrupted parameters for chisel " + m_filename);
	}

	m_argvals.push_back(args.substr(token_begin, j));

	//
	// Validate the arguments
	//
	if(m_argvals.size() < n_required_args)
	{
		throw sinsp_exception("wrong number of parameters for chisel " + m_filename +
			", " + to_string(n_required_args) + " required, " + to_string(m_argvals.size()) + "given");
	}
	else if(m_argvals.size() > n_optional_args + n_required_args)
	{
		throw sinsp_exception("too many parameters for chisel " + m_filename +
			", " + to_string(n_optional_args + n_required_args) + " required, " + 
			to_string(m_argvals.size()) + "given");
	}

	//
	// Push the arguments
	//
	for(j = 0; j < m_lua_script_info.m_args.size(); j++)
	{
		lua_getglobal(m_ls, "on_set_arg");
		if(!lua_isfunction(m_ls, -1))
		{
			lua_pop(m_ls, 1);
			throw sinsp_exception("chisel " + m_filename + " misses a set_arg() function.");
		}

		lua_pushstring(m_ls, m_lua_script_info.m_args[j].m_name.c_str()); 
		lua_pushstring(m_ls, m_argvals[j].c_str());

		//
		// call get_info()
		//
		if(lua_pcall(m_ls, 2, 1, 0) != 0) 
		{
			throw sinsp_exception(m_filename + " chisel error: " + lua_tostring(m_ls, -1));
		}

		if(!lua_isboolean(m_ls, -1)) 
		{
			throw sinsp_exception(m_filename + " chisel error: wrong set_arg() return value.");
		}

		int sares = lua_toboolean(m_ls, -1);

		if(!sares)
		{
			throw sinsp_exception("set_arg() for chisel " + m_filename + " failed.");
		}

		lua_pop(m_ls, 1);
	}
#endif
}

void sinsp_chisel::on_init()
{
	//
	// Done with the arguments, call init()
	//
	lua_getglobal(m_ls, "on_init");

	if(!lua_isfunction(m_ls, -1)) 
	{
		//
		// No on_init. 
		// That's ok. Just return.
		//
		return;
	}

	if(lua_pcall(m_ls, 0, 1, 0) != 0) 
	{
		//
		// Exception running init
		//
		const char* err = lua_tostring(m_ls, -1);
		throw sinsp_exception(m_filename + " chisel error: " + err);
	}

	if(m_new_chisel_to_exec == "")
	{
		if(!lua_isboolean(m_ls, -1)) 
		{
			throw sinsp_exception(m_filename + " chisel error: wrong init() return value.");
		}

		if(!lua_toboolean(m_ls, -1))
		{
			throw sinsp_exception("init() for chisel " + m_filename + " failed.");
		}
	}

	lua_pop(m_ls, 1);

	//
	// If the chisel called chisel.exec(), free this chisel and load the new one
	//
	if(m_new_chisel_to_exec != "")
	{
		free_lua_chisel();
		load(m_new_chisel_to_exec);
		m_new_chisel_to_exec = "";

		string args;
		for(uint32_t j = 0; j < m_argvals.size(); j++)
		{
			if(m_argvals[j].find(" ") == string::npos)
			{
				args += m_argvals[j];
			}
			else
			{
				args += string("'") + m_argvals[j] + "'";
			}

			if(j < m_argvals.size() - 1)
			{
				args += " ";
			}
		}

		m_argvals.clear();
		set_args(args);

		on_init();
	}
}

void sinsp_chisel::first_event_inits(sinsp_evt* evt)
{
	lua_pushlightuserdata(m_ls, evt);
	lua_setglobal(m_ls, "sievt");

	uint64_t ts = evt->get_ts();
	if(m_lua_cinfo->m_callback_interval != 0)
	{
		m_lua_last_interval_sample_time = ts - ts % m_lua_cinfo->m_callback_interval;
	}

	m_lua_is_first_evt = false;
}

bool sinsp_chisel::run(sinsp_evt* evt)
{
#ifdef HAS_LUA_CHISELS
	string line;

	ASSERT(m_ls);

	//
	// If this is the first event, put the event pointer on the stack.
	// We assume that the event pointer will never change.
	//
	if(m_lua_is_first_evt)
	{
		first_event_inits(evt);
	}

	//
	// If there is a timeout callback, see if it's time to call it
	//
	do_timeout(evt);

	//
	// If there is a filter, run it
	//
	if(m_lua_cinfo->m_filter != NULL)
	{
		if(!m_lua_cinfo->m_filter->run(evt))
		{
			return false;
		}
	}

	//
	// If the script has the on_event callback, call it
	//
	if(m_lua_has_handle_evt)
	{
		lua_getglobal(m_ls, "on_event");
			
		if(lua_pcall(m_ls, 0, 1, 0) != 0) 
		{
			throw sinsp_exception(m_filename + " chisel error: " + lua_tostring(m_ls, -1));
		}
	
		int oeres = lua_toboolean(m_ls, -1);
		lua_pop(m_ls, 1);

		if(oeres == false)
		{
			return false;
		}
	}

	//
	// If the script has a formatter, run it
	//
	if(m_lua_cinfo->m_formatter != NULL)
	{
		if(m_lua_cinfo->m_formatter->tostring(evt, &line))
		{
			cout << line << endl;
		}
	}

	return true;
#endif
}

void sinsp_chisel::do_timeout(sinsp_evt* evt)
{
	if(m_lua_is_first_evt)
	{
		first_event_inits(evt);
	}

	if(m_lua_cinfo->m_callback_interval != 0)
	{
		uint64_t ts = evt->get_ts();
		uint64_t sample_time = ts - ts % m_lua_cinfo->m_callback_interval;

		if(sample_time != m_lua_last_interval_sample_time)
		{
			int64_t delta = 0;

			if(m_lua_last_interval_ts != 0)
			{
				delta = ts - m_lua_last_interval_ts;
				ASSERT(delta > 0);
			}

			lua_getglobal(m_ls, "on_interval");
			
			lua_pushnumber(m_ls, (double)(ts / 1000000000)); 
			lua_pushnumber(m_ls, (double)(ts % 1000000000)); 
			lua_pushnumber(m_ls, (double)delta); 

			if(lua_pcall(m_ls, 3, 1, 0) != 0) 
			{
				throw sinsp_exception(m_filename + " chisel error: calling on_interval() failed:" + lua_tostring(m_ls, -1));
			}
	
			int oeres = lua_toboolean(m_ls, -1);
			lua_pop(m_ls, 1);

			if(oeres == false)
			{
				throw sinsp_exception("execution terminated by the " + m_filename + " chisel");
			}
	
			m_lua_last_interval_sample_time = sample_time;
			m_lua_last_interval_ts = ts;
		}
	}
}

void sinsp_chisel::on_capture_start()
{
#ifdef HAS_LUA_CHISELS
	lua_getglobal(m_ls, "on_capture_start");
			
	if(lua_isfunction(m_ls, -1))
	{
		if(lua_pcall(m_ls, 0, 1, 0) != 0) 
		{
			throw sinsp_exception(m_filename + " chisel error: " + lua_tostring(m_ls, -1));
		}

		if(!lua_isboolean(m_ls, -1)) 
		{
			throw sinsp_exception(m_filename + " chisel error: wrong on_capture_start() return value. Boolean expected.");
		}

		if(!lua_toboolean(m_ls, -1))
		{
			throw sinsp_exception("init() for chisel " + m_filename + " failed.");
		}

		lua_pop(m_ls, 1);
	}
#endif // HAS_LUA_CHISELS
}

void sinsp_chisel::on_capture_end()
{
#ifdef HAS_LUA_CHISELS
	lua_getglobal(m_ls, "on_capture_end");

	if(lua_isfunction(m_ls, -1))
	{
		uint64_t ts = m_inspector->m_firstevent_ts;
		uint64_t te = m_inspector->m_lastevent_ts;
		int64_t delta = te - ts;

		lua_pushnumber(m_ls, (double)(te / 1000000000)); 
		lua_pushnumber(m_ls, (double)(te % 1000000000)); 
		lua_pushnumber(m_ls, (double)delta);

		if(lua_pcall(m_ls, 3, 0, 0) != 0) 
		{
			throw sinsp_exception(m_filename + " chisel error: " + lua_tostring(m_ls, -1));
		}

		lua_pop(m_ls, 1);
	}
#endif // HAS_LUA_CHISELS
}

#endif // HAS_CHISELS
