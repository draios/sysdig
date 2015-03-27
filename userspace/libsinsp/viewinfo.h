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

#pragma once	

//
// Aggregation type for table fields
//
typedef enum sinsp_field_aggregation
{
	A_NONE,
	A_SUM,
	A_AVG,
	A_TIME_AVG,
	A_MIN,
	A_MAX,		
}sinsp_field_aggregation;

///////////////////////////////////////////////////////////////////////////////
// View information
///////////////////////////////////////////////////////////////////////////////
enum sinsp_view_column_info_flags
{
	TEF_NONE = 0,
	TEF_IS_KEY = 1,
	TEF_IS_SORT_COLUMN = (1 << 1),
	TEF_IS_GROUPBY_KEY = (1 << 2),
};

class sinsp_view_column_info
{
public:
	sinsp_view_column_info(string field,
	string name,
	uint32_t colsize,
	sinsp_view_column_info_flags flags,
	sinsp_field_aggregation aggregation,
	sinsp_field_aggregation groupby_aggregation)
	{
		m_field = field;
		m_name = name;
		m_colsize = colsize;
		m_aggregation = aggregation;
		m_groupby_aggregation = groupby_aggregation;
		m_flags = flags;
	}

	string m_field;
	string m_name;
	uint32_t m_colsize;
	sinsp_field_aggregation m_aggregation;
	sinsp_field_aggregation m_groupby_aggregation;
	sinsp_view_column_info_flags m_flags;
};

class sinsp_view_info
{
public:
	enum viewtype
	{
		T_NONE = 0,
		T_TABLE,
		T_LIST,
		T_TEXT,
	};

	sinsp_view_info();
	sinsp_view_info(viewtype type,
		string id,
		string name,
		vector<string> tags,
		vector<sinsp_view_column_info> columns,
		string applies_to,
		string filter,
		string drilldown_target,
		bool use_defaults);

	void get_col_names_and_sizes(OUT vector<string>* colnames, OUT vector<int32_t>* colsizes);

	string m_id;
	string m_name;
	vector<string> m_tags;
	uint32_t m_sortingcol;
	string m_filter;
	vector<string> m_applies_to;
	vector<sinsp_view_column_info> m_columns;
	bool m_use_defaults;
	bool m_does_groupby;
	viewtype m_type;
	bool m_valid;
	string m_drilldown_target;
};
