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

#ifdef HAS_CHISELS

class lua_cbacks
{
public:
	static uint32_t rawval_to_lua_stack(lua_State *ls, uint8_t* rawval, const filtercheck_field_info* finfo, uint32_t len);

	static int get_num(lua_State *ls); 
	static int get_ts(lua_State *ls);
	static int get_type(lua_State *ls);
	static int get_cpuid(lua_State *ls);
	static int request_field(lua_State *ls);
	static int field(lua_State *ls);
	static int set_global_filter(lua_State *ls);
	static int set_filter(lua_State *ls);
	static int set_snaplen(lua_State *ls);
	static int set_output_format(lua_State *ls);
	static int set_fatfile_dump_mode(lua_State *ls);
	static int make_ts(lua_State *ls);
	static int run_sysdig(lua_State *ls);
	static int end_capture(lua_State *ls);
	static int is_live(lua_State *ls);
	static int is_tty(lua_State *ls);
	static int get_terminal_info(lua_State *ls);
	static int get_filter(lua_State *ls);
	static int get_machine_info(lua_State *ls);
	static int get_thread_table(lua_State *ls);
	static int get_container_table(lua_State *ls);
	static int is_print_container_data(lua_State *ls);
	static int get_output_format(lua_State *ls);
	static int get_evtsource_name(lua_State *ls);
	static int set_event_formatter(lua_State *ls);
	static int set_interval_ns(lua_State *ls);
	static int set_interval_s(lua_State *ls);
	static int exec(lua_State *ls);
	static int log(lua_State *ls);
	static int udp_setpeername(lua_State *ls);
	static int udp_send(lua_State *ls);
#ifdef HAS_ANALYZER
	static int push_metric(lua_State *ls);
#endif
};

#endif // HAS_CHISELS

