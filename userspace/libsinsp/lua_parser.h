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
	lua_State* m_ls;

	bool m_lua_has_load_rules;
	string m_filename;

	boolop m_last_boolop;
	bool m_have_rel_expr;
	int32_t m_nest_level;

	friend class lua_parser_cbacks;
};

