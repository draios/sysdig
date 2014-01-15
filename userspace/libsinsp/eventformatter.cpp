#include "sinsp.h"
#include "sinsp_int.h"
#include "filter.h"
#include "filterchecks.h"
#include "eventformatter.h"

///////////////////////////////////////////////////////////////////////////////
// rawstring_check implementation
///////////////////////////////////////////////////////////////////////////////
#ifdef HAS_FILTERING
extern sinsp_filter_check_list g_filterlist;

sinsp_evt_formatter::sinsp_evt_formatter(sinsp* inspector, const string& fmt)
{
	m_inspector = inspector;
	set_format(fmt);
}

void sinsp_evt_formatter::set_format(const string& fmt)
{
	uint32_t j;
	uint32_t last_nontoken_str_start = 0;
	string lfmt(fmt);

	if(lfmt == "")
	{
		throw sinsp_exception("empty formatting token");
	}

	//
	// If the string starts with a *, it means that we are ok with printing
	// the string even when not all the values it specifies are set.
	//
	if(lfmt[0] == '*')
	{
		m_require_all_values = false;
		lfmt.erase(0, 1);
	}
	else
	{
		m_require_all_values = true;
	}

	//
	// Parse the string and extract the tokens
	//
	const char* cfmt = lfmt.c_str();

	m_tokens.clear();

	for(j = 0; j < lfmt.length(); j++)
	{
		if(cfmt[j] == '%')
		{
			if(last_nontoken_str_start != j)
			{
				m_tokens.push_back(new rawstring_check(lfmt.substr(last_nontoken_str_start, j - last_nontoken_str_start)));
			}

			sinsp_filter_check* chk = g_filterlist.new_filter_check_from_fldname(string(cfmt + j + 1), m_inspector);
			if(chk == NULL)
			{
				throw sinsp_exception("invalid formatting token " + string(cfmt + j + 1));
			}

			j += chk->parse_field_name(cfmt + j + 1);
			ASSERT(j <= lfmt.length());

			m_tokens.push_back(chk);

			last_nontoken_str_start = j + 1;
		}
	}

	if(last_nontoken_str_start != j)
	{
		m_tokens.push_back(new rawstring_check(lfmt.substr(last_nontoken_str_start, j - last_nontoken_str_start)));
	}
}

bool sinsp_evt_formatter::tostring(sinsp_evt* evt, OUT string* res)
{
	vector<sinsp_filter_check*>::iterator it;
	res->clear();

	for(it = m_tokens.begin(); it != m_tokens.end(); ++it)
	{
		char* str = (*it)->tostring(evt);

		if(str != NULL)
		{
			(*res) += str;
		}
		else
		{
			if(m_require_all_values)
			{
				return false;
			}
			else
			{
				(*res) += "<NA>";
			}
		}
	}

	return true;
}

#else  // HAS_FILTERING

sinsp_evt_formatter::sinsp_evt_formatter(sinsp* inspector, const string& fmt)
{
}

void sinsp_evt_formatter::set_format(const string& fmt)
{
	throw sinsp_exception("sinsp_evt_formatter unvavailable because it was not compiled in the library");
}

bool sinsp_evt_formatter::tostring(sinsp_evt* evt, OUT string* res)
{
	throw sinsp_exception("sinsp_evt_formatter unvavailable because it was not compiled in the library");
	return false;
}
#endif // HAS_FILTERING
