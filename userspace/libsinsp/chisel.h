/*

 














*/

#pragma once

#ifdef HAS_CHISELS

class sinsp_filter_check;
class sinsp_evt_formatter;
namespace Json {
	class Value;
}

typedef struct lua_State lua_State;

/** @defgroup filter Filtering events
 * Filtering infrastructure.
 *  @{
 */

/*!
  \brief This is the class that compiles and runs sysdig-type filters.
*/
typedef struct chiseldir_info
{
	bool m_need_to_resolve;
	char m_dir[1024];
}chiseldir_info;

class chiselarg_desc
{
public:
	chiselarg_desc(string name, string type, string description)
	{
		m_name = name;
		m_type = type;
		m_description = description;
	}

	string m_name;
	string m_type;
	string m_description;
};

class chisel_desc
{
public:
	void reset()
	{
		m_name = "";
		m_description = "";
		m_args.clear();
	}

	string m_name;
	string m_description;
	vector<chiselarg_desc> m_args;
};


class chiselinfo
{
public:
	chiselinfo(sinsp* inspector);
	void init(string filterstr, string formatterstr); 
	void set_filter(string filterstr);
	void set_formatter(string formatterstr);
	void set_callback_interval(uint64_t interval);
	~chiselinfo();
	sinsp_filter* m_filter;
	sinsp_evt_formatter* m_formatter;
	sinsp_dumper* m_dumper;
	uint64_t m_callback_interval;

private:
	sinsp* m_inspector;
};

class SINSP_PUBLIC sinsp_chisel
{
public:
	sinsp_chisel(sinsp* inspector, string filename);
	~sinsp_chisel();
	static void add_lua_package_path(lua_State* ls, const char* path);
	static void get_chisel_list(vector<chisel_desc>* chisel_descs);
	void load(string cmdstr);
	uint32_t get_n_args();
	void set_args(vector<string>* argvals);
	bool run(sinsp_evt* evt);
	void on_init();
	void on_capture_start();
	void on_capture_end();

private:
	bool openfile(string filename, OUT ifstream* is);
	void free_lua_chisel();

	sinsp* m_inspector;
	string m_description;
	Json::Value* m_root;
	vector<chiselinfo*> m_subchisels;
	vector<string> m_argvals;
	string m_filename;
	lua_State* m_ls;
	chisel_desc m_lua_script_info;
	bool m_lua_has_handle_evt;
	bool m_lua_is_first_evt;
	uint64_t m_lua_last_interval_sample_time;
	vector<sinsp_filter_check*> m_allocated_fltchecks;
	char m_lua_fld_storage[1024];
	chiselinfo* m_lua_cinfo;
	string m_new_chisel_to_exec;

	friend class lua_cbacks;
};

/*@}*/

#endif // HAS_CHISELS

