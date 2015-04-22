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

//
// sinsp_view_column_info flags
//
#define TEF_NONE 0
#define TEF_IS_KEY 1
#define TEF_IS_SORT_COLUMN (1 << 1)
#define TEF_IS_GROUPBY_KEY (1 << 2)

///////////////////////////////////////////////////////////////////////////////
// Column information
///////////////////////////////////////////////////////////////////////////////
class sinsp_view_column_info
{
public:
	sinsp_view_column_info(string field,
		string name,
		string description,
		uint32_t colsize,
		uint32_t flags,
		sinsp_field_aggregation aggregation,
		sinsp_field_aggregation groupby_aggregation,
		vector<string> tags)
	{
		m_field = field;
		m_name = name;
		m_description = description;
		m_colsize = colsize;
		m_aggregation = aggregation;
		m_groupby_aggregation = groupby_aggregation;
		m_flags = flags;
		m_tags = tags;
	}

	string m_field;
	string m_name;
	string m_description;
	uint32_t m_colsize;
	sinsp_field_aggregation m_aggregation;
	sinsp_field_aggregation m_groupby_aggregation;
	uint32_t m_flags;
	vector<string> m_tags;
};

///////////////////////////////////////////////////////////////////////////////
// View information
///////////////////////////////////////////////////////////////////////////////
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
		string description,
		vector<string> tags,
		vector<string> tips,
		vector<sinsp_view_column_info> columns,
		string applies_to,
		string filter,
		string drilldown_target,
		bool use_defaults,
		bool is_root);

	void get_col_names_and_sizes(OUT vector<string>* colnames, OUT vector<int32_t>* colsizes);
	viewtype get_type()
	{
		return m_type;
	}

	bool does_groupby()
	{
		return m_does_groupby;
	}

	void apply_tag(string tag);

	string m_id;
	string m_name;
	string m_description;
	vector<string> m_tags;
	vector<string> m_tips;
	uint32_t m_sortingcol;
	string m_filter;
	vector<string> m_applies_to;
	vector<sinsp_view_column_info> m_columns;
	bool m_use_defaults;
	bool m_does_groupby;
	viewtype m_type;
	bool m_valid;
	string m_drilldown_target;
	bool m_is_root;

private:
	void move_key_to_front(uint32_t keyflag);
};

///////////////////////////////////////////////////////////////////////////////
// View manager
///////////////////////////////////////////////////////////////////////////////
class sinsp_view_manager
{
public:
	void add(sinsp_view_info* vinfo);
	vector<sinsp_view_info>* get_views();
	uint32_t get_selected_view();
	void set_selected_view(string viewid);
	size_t size()
	{
		return m_views.size();
	}
	sinsp_view_info* at(uint32_t viewnum)
	{
		return &m_views[viewnum];
	}

private:
	void sort_views();

	vector<sinsp_view_info> m_views;

	string m_selected_view_id;
};
