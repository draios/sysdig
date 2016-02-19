#include <iostream>
#include <fstream>
#include "sinsp.h"
#include "sinsp_int.h"

#include "lua_parser.h"
#include "lua_parser_api.h"



extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

const static struct luaL_reg ll_filter [] =
{
	{"make_filter_check", &lua_parser_cbacks::make_filter_check},
	{NULL,NULL}
};

lua_parser::lua_parser(sinsp* inspector, string filename)
{
	m_inspector = inspector;

	m_ls = NULL;
	m_lua_has_load_rules = false;

	m_filter = new sinsp_filter(m_inspector);

	load(filename);
}

lua_parser::~lua_parser()
{
	if(m_ls)
	{
		lua_close(m_ls);
		m_ls = NULL;
	}
	delete m_filter;

}

void lua_parser::load(string filename)
{
	m_filename = filename;
	trim(filename);

	// Initialize Lua interpreter
	m_ls = lua_open();
	luaL_openlibs(m_ls);

	// Register our c++ defined functions
	luaL_openlib(m_ls, "filter", ll_filter, 0);

	lua_pushlightuserdata(m_ls, this);
	lua_setglobal(m_ls, "siparser");

	ifstream is;
	is.open(filename);
	if(!is.is_open())
	{
		throw sinsp_exception("can't open file " + filename);
	}

	string scriptstr((istreambuf_iterator<char>(is)),
			 istreambuf_iterator<char>());

	//
	// Load the script
	//
	if(luaL_loadstring(m_ls, scriptstr.c_str()) || lua_pcall(m_ls, 0, 0, 0))
	{
		throw sinsp_exception("Failed to load script " +
			m_filename + ": " + lua_tostring(m_ls, -1));
	}
	//
	// Check if the script has a "load_rules" function
	//
	lua_getglobal(m_ls, "load_rules");
	if(lua_isfunction(m_ls, -1))
	{
		m_lua_has_load_rules = true;
		lua_pop(m_ls, 1);
	}

}

