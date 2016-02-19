#include "filterchecks.h"
#include "lua_parser_api.h"
#include "lua_parser.h"

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

extern sinsp_filter_check_list g_filterlist;

// It would be nice to expose this up to Lua so that comparison operator
// parsing/encoding can be done there.
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

boolop string_to_boolop(const char* str)
{
	if(strcmp(str, "or") == 0)
	{
		return BO_OR;
	}
	else if(strcmp(str, "and") == 0)
	{
		return BO_AND;
	}
	else if(strcmp(str, "not") == 0)
	{
		return BO_NOT;
	}
	else
	{
		throw sinsp_exception("filter error: invalid boolean operator: " + string(str));
	}
}

int lua_parser_cbacks::bool_op(lua_State *ls)
{
	lua_getglobal(ls, "siparser");

	lua_parser* parser = (lua_parser*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	const char* opstr = luaL_checkstring(ls, 1);
	boolop op = string_to_boolop(opstr);

	parser->m_last_boolop = op;
	return 0;

}

int lua_parser_cbacks::rel_expr(lua_State *ls)
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
		string err = "filter_check called with nonexistent field " + string(fld);
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("parser API error");
	}

	try
	{
		chk->m_boolop = parser->m_last_boolop;

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

	//	filter->push_expression(BO_NONE);
	filter->add_check(chk);
	//	filter->pop_expression();

	return 0;
}

