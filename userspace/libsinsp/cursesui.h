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

#ifndef _WIN32
#include <unistd.h>
#endif

#define UI_USER_INPUT_CHECK_PERIOD_NS 10000000
#define SIDEMENU_WIDTH 20

string combine_filters(string flt1, string flt2);

class sinsp_table_info
{
public:
	sinsp_table_info(string name, 
		string config,
		string applyto,
		uint32_t sortingcol, 
		string merge_config, 
		string colnames, 
		string colsizes, 
		string filter);

	string m_name;
	string m_config;
	string m_merge_config;
	vector<int32_t> m_colsizes;
	vector<string> m_colnames;
	uint32_t m_sortingcol;
	string m_filter;
	vector<string> m_applyto;
};

class sinsp_ui_selection_info
{
public:
	sinsp_ui_selection_info(string field, 
		string val, 
		uint32_t prev_selected_view, 
		uint32_t prev_selected_sidemenu_entry, 
		sinsp_table_field* rowkey)
	{
		m_field = field;
		m_val = val;
		m_prev_selected_view = prev_selected_view;
		m_prev_selected_sidemenu_entry = prev_selected_sidemenu_entry;

		m_rowkey = *rowkey;
	}

	string m_field;
	string m_val;
	uint32_t m_prev_selected_view;
	uint32_t m_prev_selected_sidemenu_entry;
	sinsp_table_field m_rowkey;
};

class sinsp_ui_selection_hierarchy
{
public:
	void push_back(string field, 
		string val, 
		uint32_t prev_selected_view, 
		uint32_t prev_selected_sidemenu_entry, 
		sinsp_table_field* rowkey)
	{
		m_hierarchy.push_back(sinsp_ui_selection_info(field, 
			val, 
			prev_selected_view, 
			prev_selected_sidemenu_entry, 
			rowkey));
	}

	string tofilter()
	{
		string res;
		uint32_t j;

		for(j = 0; j < m_hierarchy.size(); j++)
		{
			res += m_hierarchy[j].m_field;
			res += "=";
			res += m_hierarchy[j].m_val;

			if(j < m_hierarchy.size() - 1)
			{
				res += " and ";
			}
		}

		return res;
	}

	vector<sinsp_ui_selection_info> m_hierarchy;
};

class sinsp_cursesui
{
public:
	enum ColorElements_ {
		RESET_COLOR,
		DEFAULT_COLOR,
		FUNCTION_BAR,
		FUNCTION_KEY,
		FAILED_SEARCH,
		PANEL_HEADER_FOCUS,
		PANEL_HEADER_UNFOCUS,
		PANEL_HIGHLIGHT_FOCUS,
		PANEL_HIGHLIGHT_UNFOCUS,
		LARGE_NUMBER,
		METER_TEXT,
		METER_VALUE,
		LED_COLOR,
		UPTIME,
		BATTERY,
		TASKS_RUNNING,
		SWAP,
		PROCESS,
		PROCESS_SHADOW,
		PROCESS_TAG,
		PROCESS_MEGABYTES,
		PROCESS_TREE,
		PROCESS_R_STATE,
		PROCESS_D_STATE,
		PROCESS_BASENAME,
		PROCESS_HIGH_PRIORITY,
		PROCESS_LOW_PRIORITY,
		PROCESS_THREAD,
		PROCESS_THREAD_BASENAME,
		BAR_BORDER,
		BAR_SHADOW,
		GRAPH_1,
		GRAPH_2,
		GRAPH_3,
		GRAPH_4,
		GRAPH_5,
		GRAPH_6,
		GRAPH_7,
		GRAPH_8,
		GRAPH_9,
		MEMORY_USED,
		MEMORY_BUFFERS,
		MEMORY_BUFFERS_TEXT,
		MEMORY_CACHE,
		LOAD,
		LOAD_AVERAGE_FIFTEEN,
		LOAD_AVERAGE_FIVE,
		LOAD_AVERAGE_ONE,
		CHECK_BOX,
		CHECK_MARK,
		CHECK_TEXT,
		CLOCK,
		HELP_BOLD,
		HOSTNAME,
		CPU_NICE,
		CPU_NICE_TEXT,
		CPU_NORMAL,
		CPU_KERNEL,
		CPU_IOWAIT,
		CPU_IRQ,
		CPU_SOFTIRQ,
		CPU_STEAL,
		CPU_GUEST,
		LAST_COLORELEMENT
	};

	sinsp_cursesui(sinsp* inspector, string event_source_name, string capture_filter);
	~sinsp_cursesui();
	void configure(vector<sinsp_table_info>* views);
	void start(bool is_drilldown, string filter);
	sinsp_table_info* get_selected_view();
	// returns false if there is no suitable drill down view for this field
	bool drilldown(string field, string val);
	// returns false if we are already at the top of the hierarchy
	bool drillup();
	void pause();

	//
	// Return true if the application is supposed to exit
	//
	inline bool process_event(sinsp_evt* evt)
	{
		bool end_of_sample;
		uint64_t ts = evt->get_ts();

		//
		// Process the user input
		//
#ifndef NOCURSESUI
		if(ts - m_last_input_check_ts > UI_USER_INPUT_CHECK_PERIOD_NS)
		{
			uint32_t ninputs = 0;

			while(true)
			{
				int input = getch();

				if(input == -1)
				{
					break;
				}
				else
				{
					ninputs++;
				}

				sysdig_table_action ta = handle_input(input);

				if(ta == STA_QUIT)
				{
					return true;
				}
				else if(ta == STA_SWITCH_VIEW)
				{
					string field;
					if(m_sel_hierarchy.m_hierarchy.size() > 0)
					{
						sinsp_ui_selection_info* psinfo = &m_sel_hierarchy.m_hierarchy[m_sel_hierarchy.m_hierarchy.size() - 1];
						field = psinfo->m_field;
					}

					string filter = combine_filters(m_sel_hierarchy.tofilter(), 
						m_views[m_selected_view].m_filter);

					clear();

					try
					{
						start(true, filter);
					}
					catch(...)
					{
						m_inspector->close();

	#ifdef HAS_FILTERING
						if(m_capture_filter != "")
						{
							m_inspector->set_filter(m_capture_filter);
						}
	#endif

						start(true, filter);
						m_inspector->open(m_event_source_name);
					}

					populate_sidemenu(field, &m_sidemenu_viewlist);

					delete m_sidemenu;
					m_sidemenu = NULL;

					m_viz->render(true);
					render();
				}
				else if(ta == STA_DRILLDOWN)
				{
					auto res = m_datatable->get_row_key_name_and_val(m_viz->m_selct);
					drilldown(res.first->m_name, res.second.c_str());
				}
				else if(ta == STA_DRILLUP)
				{
					drillup();
				}
			}

			if(ninputs == 0)
			{
				m_last_input_check_ts = ts;
			}
		}
#endif

		//
		// Check if it's time to flush
		//
		end_of_sample = (evt == NULL || ts > m_datatable->m_next_flush_time_ns);

		if(end_of_sample)
		{
			m_datatable->flush(evt);

			//
			// It's time to refresh the data for this chart.
			// First of all, render the chart
			//
			vector<sinsp_sample_row>* sample = 
				m_datatable->get_sample();

#ifndef NOCURSESUI
			m_viz->update_data(sample);
			m_viz->render(true);

			//
			// Now refresh the UI.
			//
			render();

			if(!m_inspector->is_live())
			{
				while(getch() != 'a')
				{
					usleep(100000);
				}
			}
#endif				
		}

		m_datatable->process_event(evt);

		return false;
	}

	int m_colors[LAST_COLORELEMENT];
	vector<sinsp_table_info> m_views;
	uint32_t m_selected_view;
	uint32_t m_selected_sidemenu_entry;
	sinsp_ui_selection_hierarchy m_sel_hierarchy;
	vector<sidemenu_list_entry> m_sidemenu_viewlist;
	curses_table* m_viz;
	uint32_t m_screenw;
	uint32_t m_screenh;

private:
#ifndef NOCURSESUI
	void render();
	void render_header();
	void render_default_main_menu();
	void render_search_main_menu();
	void render_main_menu();
	sysdig_table_action handle_textbox_input(int ch);
	sysdig_table_action handle_input(int ch);

#endif
	void populate_sidemenu(string field, vector<sidemenu_list_entry>* viewlist);

	sinsp* m_inspector;
	vector<string> m_menuitems;
	sinsp_table* m_datatable;
	string m_event_source_name;
	string m_capture_filter;
	bool m_paused;
	uint64_t m_last_input_check_ts;
	bool m_searching;
	curses_table_sidemenu* m_sidemenu;
	uint32_t m_cursor_pos;
	string m_flt_string;
};
