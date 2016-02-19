#pragma once

#include <string.h>

#include "sinsp.h"
#include "filterchecks.h"

typedef struct lua_State lua_State;

class lua_parser
{
public:
	lua_parser(sinsp* inspector, string filename);
	~lua_parser();
	void load(string cmdstr);
	sinsp_filter* m_filter;

 private:
	sinsp* m_inspector;
	bool m_lua_has_load_rules;
	lua_State* m_ls;
	string m_filename;
	boolop m_last_boolop;

	friend class lua_parser_cbacks;
};

