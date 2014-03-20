/*
Copyright (C) 2013-2014 Draios inc.
 
This file is part of sysdig.

sysdig is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

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

sinsp_evt_formatter::~sinsp_evt_formatter()
{
	uint32_t j;

	for(j = 0; j < m_chks_to_free.size(); j++)
	{
		delete m_chks_to_free[j];
	}
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
				rawstring_check* newtkn = new rawstring_check(lfmt.substr(last_nontoken_str_start, j - last_nontoken_str_start));
				m_tokens.push_back(newtkn);
				m_chks_to_free.push_back(newtkn);
			}

			sinsp_filter_check* chk = g_filterlist.new_filter_check_from_fldname(string(cfmt + j + 1), 
				m_inspector, 
				false);

			if(chk == NULL)
			{
				throw sinsp_exception("invalid formatting token " + string(cfmt + j + 1));
			}

			m_chks_to_free.push_back(chk);

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
