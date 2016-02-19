#include "filterchecks.h"
#include "lua_parser_api.h"
#include "lua_parser.h"

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

extern sinsp_filter_check_list g_filterlist;

cmpop string_to_cmpop(const char* str)
{
	if(strcmp(str, "=") == 0)
	{
		return CO_EQ;
	}
	else if(strcmp(str, "!=") == 0)
	{
		return CO_NE;
	}
	else if(strcmp(str, "<=") == 0)
	{
		return CO_LE;
	}
	else if(strcmp(str, "<") == 0)
	{
		return CO_LT;
	}
	else if(strcmp(str, ">=") == 0)
	{
		return CO_GE;
	}
	else if(strcmp(str, ">") == 0)
	{
		return CO_GT;
	}
	else if(strcmp(str, "contains") == 0)
	{
		return CO_CONTAINS;
	}
	else if(strcmp(str, "icontains") == 0)
	{
		return CO_ICONTAINS;
	}
	else if(strcmp(str, "in") == 0)
	{
		return CO_IN;
	}
	else if(strcmp(str, "exists") == 0)
	{
		return CO_EXISTS;
	}
	else
	{
		throw sinsp_exception("filter error: invalid comparison operator: " + string(str));
	}
}


int lua_parser_cbacks::make_filter_check(lua_State *ls)
{
	lua_getglobal(ls, "siparser");

	lua_parser* parser = (lua_parser*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	sinsp* inspector = parser->m_inspector;
	sinsp_filter* filter = parser->m_filter;

	const char* fld = luaL_checkstring(ls, 1);
	sinsp_filter_check* chk = g_filterlist.new_filter_check_from_fldname(fld,
									     inspector,
									     true);

	if(chk == NULL)
	{
		string err = "make_filter_check called with nonexistent field " + string(fld);
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("parser API error");
	}

	try
	{
		chk->parse_field_name(fld, true);

		const char* cmpop = luaL_checkstring(ls, 2);
		chk->m_cmpop = string_to_cmpop(cmpop);

		// "exists" is the only unary comparison op
		if(strcmp(cmpop, "exists"))
		{
			const char* value = luaL_checkstring(ls, 3);
			chk->parse_filter_value(value, strlen(value));
		}
	}
	catch(sinsp_exception& e)
	{
		fprintf(stderr, "filter parsing error: %s\n\n", e.what());
		throw e;
	}

	filter->push_expression(BO_NONE);
	filter->add_check(chk);
	filter->pop_expression();

	return 0;
}

