/*
Copyright (C) 2013-2014 Draios inc.

This file is part of sysdig.

sysdig is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "sinsp.h"
#include "sinsp_int.h"
#include "sinsp_errno.h"
#include "sinsp_signal.h"
#include "filter.h"
#include "filterchecks.h"
#include "chisel.h"
#include "protodecoder.h"

///////////////////////////////////////////////////////////////////////////////
// sinsp_view_info implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_view_info::sinsp_view_info()
{
	m_valid = false;
}

sinsp_view_info::sinsp_view_info(viewtype type, 
	string id,
	string name,
	vector<string> tags,
	vector<sinsp_view_column_info> columns,
	string applies_to,
	string filter,
	string drilldown_target,
	bool use_defaults)
{
	m_id = id;
	m_name = name;
	m_does_merge = false;
	m_type = type;
	m_tags = tags;	
	m_columns = columns;
	m_drilldown_target = drilldown_target;

	m_use_defaults = use_defaults;
		
	if(applies_to != "")
	{
		char *p = strtok((char*)applies_to.c_str(), ",");
		while (p) 
		{
			string ts(p);
			trim(ts);

			if(ts == "all")
			{
				m_applies_to.push_back("");
			}
			else
			{
				m_applies_to.push_back(ts);
			}

			p = strtok(NULL, ",");
		}
	}
	else
	{
		m_applies_to.push_back("");
	}

	//
	// Determine the sorting column
	//
	uint32_t n_sorting_cols = 0;

	for(uint32_t j = 0; j < columns.size(); j++)
	{
		if((columns[j].m_flags & TEF_IS_SORT_COLUMN) != 0)
		{
			m_sortingcol = j;
			n_sorting_cols++;
		}

		if((columns[j].m_flags & TEF_IS_MERGE_KEY) != 0)
		{
			m_does_merge = true;
		}
	}

	if(n_sorting_cols == 0)
	{
		m_sortingcol = 0;
	}
	else if(n_sorting_cols > 1)
	{
		throw sinsp_exception("view format error: more than one sprting column");
	}

	m_filter = filter;
	m_valid = true;
}

void sinsp_view_info::get_col_names_and_sizes(OUT vector<string>* colnames, OUT vector<int32_t>* colsizes)
{
	if(m_type == viewtype::T_LIST)
	{
		colsizes->push_back(-1);
		colnames->push_back("");
	}

	for(auto fit : m_columns)
	{
		if(m_does_merge)
		{
			if((fit.m_flags & TEF_IS_KEY) != 0)
			{
				continue;
			}

			if((fit.m_flags & TEF_IS_MERGE_KEY) != 0)
			{
				colsizes->insert(colsizes->begin(), fit.m_colsize);
				colnames->insert(colnames->begin(), fit.m_name);
				continue;
			}
		}

		colsizes->push_back(fit.m_colsize);
		colnames->push_back(fit.m_name);
	}
}
