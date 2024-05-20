// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

The following file was originally developed in the sysdig cli
project and then contributed to the falcosecurity/libs project
(https://github.com/draios/sysdig/commit/abf90f39f8e5ea6eb4276cc3f980dbd878816ecd
with the #1737 PR). At the end, given its removal from the
falcosecurity/libs project, has been reintroduced to the
draios/sysdig project.

*/

#pragma once

#define VIEW_ID_SPY -1
#define VIEW_ID_DIG -2
#define VIEW_ID_INFO -3

//
// Aggregation type for table fields
//
enum chisel_field_aggregation
{
	A_NONE,
	A_SUM,
	A_AVG,
	A_TIME_AVG,
	A_MIN,
	A_MAX,
};

//
// chisel_view_column_info flags
//
#define TEF_NONE 0
#define TEF_IS_KEY 1
#define TEF_IS_SORT_COLUMN (1 << 1)
#define TEF_IS_GROUPBY_KEY (1 << 2)
#define TEF_FILTER_IN_CHILD_ONLY (1 << 3)

///////////////////////////////////////////////////////////////////////////////
// Column information
///////////////////////////////////////////////////////////////////////////////
class chisel_view_column_info
{
public:
	chisel_view_column_info()
	{
	}

	chisel_view_column_info(std::string field,
		std::string name,
		std::string description,
		uint32_t colsize,
		uint32_t flags,
		chisel_field_aggregation aggregation,
		chisel_field_aggregation groupby_aggregation,
		std::vector<std::string> tags,
		std::string filterfield)
	{
		m_field = field;
		m_name = name;
		m_description = description;
		m_colsize = colsize;
		m_aggregation = aggregation;
		m_groupby_aggregation = groupby_aggregation;
		m_flags = flags;
		m_tags = tags;
		m_filterfield = filterfield;
	}

	std::string get_field(uint32_t depth);
	std::string get_filter_field(uint32_t depth);

	std::string m_field;
	std::string m_name;
	std::string m_description;
	uint32_t m_colsize;
	chisel_field_aggregation m_aggregation;
	chisel_field_aggregation m_groupby_aggregation;
	uint32_t m_flags;
	std::vector<std::string> m_tags;
	std::string m_filterfield;
};

///////////////////////////////////////////////////////////////////////////////
// action information
///////////////////////////////////////////////////////////////////////////////
class chisel_view_action_info
{
public:
	chisel_view_action_info(char hotkey,
		std::string command,
		std::string description,
		bool ask_confirmation,
		bool waitfinish)
	{
		m_hotkey = hotkey;
		m_command = command;
		m_description = description;
		m_ask_confirmation = ask_confirmation;
		m_waitfinish = waitfinish;
	}

	char m_hotkey;
	std::string m_command;
	std::string m_description;
	bool m_ask_confirmation;
	bool m_waitfinish;
};

///////////////////////////////////////////////////////////////////////////////
// View information
///////////////////////////////////////////////////////////////////////////////
class chisel_view_info
{
public:
	enum viewtype
	{
		T_NONE = 0,
		T_TABLE,
		T_LIST,
		T_TEXT,
		T_SPECTRO,
	};

	chisel_view_info();
	chisel_view_info(viewtype type,
		std::string id,
		std::string name,
		std::string description,
		std::vector<std::string> tags,
		std::vector<std::string> tips,
		std::vector<chisel_view_column_info> columns,
		std::vector<std::string> applies_to,
		std::string filter,
		std::string drilldown_target,
		bool use_defaults,
		bool is_root,
		std::vector<chisel_view_action_info> actions,
		bool drilldown_increase_depth,
		std::string spectro_type,
		bool propagate_filter);

	void get_col_names_and_sizes(std::vector<std::string>* colnames, std::vector<int32_t>* colsizes);
	chisel_view_column_info* get_key();
	std::string get_filter(uint32_t depth) const;
	viewtype get_type()
	{
		return m_type;
	}

	bool does_groupby()
	{
		return m_does_groupby;
	}

	void apply_tag(std::string tag);

	void run_action(chisel_view_action_info* action);
	std::string m_id;
	std::string m_name;
	std::string m_description;
	std::vector<std::string> m_tags;
	std::vector<std::string> m_tips;
	int32_t m_sortingcol;
	std::vector<std::string> m_applies_to;
	std::vector<chisel_view_column_info> m_columns;
	bool m_use_defaults;
	bool m_does_groupby;
	viewtype m_type;
	bool m_valid;
	std::string m_drilldown_target;
	bool m_is_root;
	std::vector<chisel_view_action_info> m_actions;
	std::vector<char> m_col_sort_hotkeys;
	uint32_t max_col_sort_hotkeys;
	bool m_drilldown_increase_depth;
	bool m_propagate_filter;
	std::string m_spectro_type;
	std::string m_filter;

private:
	void set_sorting_col();
	void move_key_to_front(uint32_t keyflag);
	void set_col_sorting_hotkeys();

	uint32_t m_n_sorting_cols;
};


///////////////////////////////////////////////////////////////////////////////
// View manager
///////////////////////////////////////////////////////////////////////////////
class chisel_view_manager
{
public:
	void add(chisel_view_info* vinfo);
	std::vector<chisel_view_info>* get_views();
	uint32_t get_selected_view();
	void set_selected_view(std::string viewid);
	size_t size() const
	{
		return m_views.size();
	}
	chisel_view_info* at(uint32_t viewnum)
	{
		return &m_views[viewnum];
	}
	const chisel_view_info* at(uint32_t viewnum) const
	{
		return &m_views[viewnum];
	}

private:
	void sort_views();

	std::vector<chisel_view_info> m_views;

	std::string m_selected_view_id;
};
