// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

The following file was originally developed in the sysdig cli
project and then contributed to the falcosecurity/libs project
(https://github.com/draios/sysdig/commit/abf90f39f8e5ea6eb4276cc3f980dbd878816ecd
with the #1737 PR). At the end, given its removal from the
falcosecurity/libs project, has been reintroduced to the
draios/sysdig project.

*/

#pragma once

#include <libsinsp/sinsp.h>
#include <chisel/chisel_viewinfo.h>

class sinsp_filter_check;

/*!
	\brief Add a new directory containing chisels.

	\parame front_add if true, the chisel directory is added at the front of
	the search list and therefore gets priority.

	\note This function is not reentrant.
*/
void chisel_add_dir(std::string dirname, bool front_add);

typedef struct lua_State lua_State;

/** @defgroup filter Filtering events
 * Filtering infrastructure.
 *  @{
 */

/*!
  \brief This is the class that compiles and runs filters.
*/
struct chiseldir_info
{
	bool m_need_to_resolve;
	std::string m_dir;
};

class chiselarg_desc
{
public:
	chiselarg_desc(std::string name, std::string type, std::string description, bool optional)
	{
		m_name = name;
		m_type = type;
		m_description = description;
		m_optional = optional;
	}

	std::string m_name;
	std::string m_type;
	std::string m_description;
	bool m_optional;
};

class chisel_desc
{
public:
	void reset()
	{
		m_name = "";
		m_description = "";
		m_category = "";
		m_shortdesc = "";
		m_args.clear();
	}

	std::string m_name;
	std::string m_description;
	std::string m_category;
	std::string m_shortdesc;
	std::vector<chiselarg_desc> m_args;
	chisel_view_info m_viewinfo;
};

class chisel_metric
{
public:
	void reset()
	{
		m_name = "";
		m_value = 0;
		m_tags.clear();
	}

	std::string m_name;
	double m_value = 0;
	std::map<std::string, std::string> m_tags;
};

class chiselinfo
{
public:
	chiselinfo(sinsp* inspector);
	void init(std::string filterstr, std::string formatterstr);
	void set_filter(std::string filterstr);
	void set_formatter(std::string formatterstr);
	void set_callback_interval(uint64_t interval);
	void set_callback_precise_interval(uint64_t interval);
	~chiselinfo();
	sinsp_filter* m_filter;
	sinsp_evt_formatter* m_formatter;
	sinsp_dumper* m_dumper;
	uint64_t m_callback_interval;
	uint64_t m_callback_precise_interval;
	bool m_has_nextrun_args;
	std::string m_nextrun_args;
	bool m_end_capture;

private:
	sinsp* m_inspector;
};

class SINSP_PUBLIC sinsp_chisel
{
public:
	sinsp_chisel(sinsp* inspector, std::string filename, bool is_file = true);
	~sinsp_chisel();

	static void add_lua_package_path(lua_State* ls, const std::string& path);
	static void get_chisel_list(std::vector<chisel_desc>* chisel_descs);

	void load(std::string cmdstr, bool is_file = true);
	std::string get_name()
	{
		return m_filename;
	}
	uint32_t get_n_args();
	uint32_t get_n_optional_args();
	uint32_t get_n_required_args();
	void set_args(std::string args);
	void set_args(std::vector<std::pair<std::string, std::string>> args);
	bool run(sinsp_evt* evt);
	void do_timeout(sinsp_evt* evt);
	void do_end_of_sample();
	void on_init();
	void on_capture_start();
	void on_capture_end();
	bool get_nextrun_args(std::string* args);
	chisel_desc* get_lua_script_info()
	{
		return &m_lua_script_info;
	}

private:
	bool openfile(std::string filename, std::ifstream* is);
	void free_lua_chisel();
	static chisel_field_aggregation string_to_aggregation(std::string ag);
	static void parse_view_column(lua_State *ls, chisel_desc* cd, void* columns);
	static void parse_view_columns(lua_State *ls, chisel_desc* cd, void* columns);
	static void parse_view_action(lua_State *ls, chisel_desc* cd, void* actions);
	static void parse_view_actions(lua_State *ls, chisel_desc* cd, void* actions);
	static bool parse_view_info(lua_State *ls, chisel_desc* cd);
	static bool init_lua_chisel(chisel_desc &cd, std::string const &path);
	void first_event_inits(sinsp_evt* evt);

	sinsp* m_inspector;
	std::string m_description;
	std::vector<std::string> m_argvals;
	std::string m_filename;
	lua_State* m_ls;
	chisel_desc m_lua_script_info;
	bool m_lua_has_handle_evt;
	bool m_lua_is_first_evt;
	uint64_t m_lua_last_interval_sample_time;
	uint64_t m_lua_last_interval_ts;
	std::vector<sinsp_filter_check*> m_allocated_fltchecks;
	char m_lua_fld_storage[PPM_MAX_ARG_SIZE];
	chiselinfo* m_lua_cinfo;
	std::string m_new_chisel_to_exec;
	int m_udp_socket;
	struct sockaddr_in m_serveraddr;

	friend class lua_cbacks;
};

/*@}*/
