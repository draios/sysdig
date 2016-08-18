#pragma once

#include "sinsp.h"

typedef struct lua_State lua_State;

class lua_parser
{
public:
	lua_parser(sinsp* inspector, lua_State *ls);
	~lua_parser();
	sinsp_filter* get_filter(bool reset_filter = false);

 private:

	void reset();
	sinsp* m_inspector;

	sinsp_filter* m_filter;

	boolop m_last_boolop;
	bool m_have_rel_expr;
	int32_t m_nest_level;

	lua_State* m_ls;

	friend class lua_parser_cbacks;
};

