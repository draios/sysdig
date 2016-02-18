#include "filterchecks.h"
#include "lua_parser_api.h"
#include "lua_parser.h"

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

extern sinsp_filter_check_list g_filterlist;

int lua_parser_cbacks::make_filter_check(lua_State *ls)
{
	lua_getglobal(ls, "siparser");

	lua_parser* parser = (lua_parser*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	sinsp* inspector = parser->m_inspector;

	const char* fld = lua_tostring(ls, 1);
	const char* value = lua_tostring(ls, 2);

	if(fld == NULL)
	{
		string err = " make_filter_check called with nil field";
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("parser API error");
	}

	if(value == NULL)
	{
		string err = " make_filter_check called with nil value";
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("parser API error");
	}

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
		chk->parse_filter_value(value, strlen(value));
	}
	catch(sinsp_exception& e)
	{
		fprintf(stderr, "%s\n\n", e.what());
		throw e;
	}
	catch(...)
	{
		throw sinsp_exception("error parsing the filter operands");
	}



	//	parser->m_allocated_fltchecks.push_back(chk);

	return 0;
}

