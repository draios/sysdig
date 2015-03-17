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
#define VIEW_ID_SPY -1
#define VIEW_ID_DIG -2

string combine_filters(string flt1, string flt2);
class ctext;

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

extern sinsp_logger g_logger;

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
		SPY_READ,
		SPY_WRITE,
		LAST_COLORELEMENT
	};

	sinsp_cursesui(sinsp* inspector, string event_source_name, 
		string cmdline_capture_filter);
	~sinsp_cursesui();
	void configure(vector<sinsp_table_info>* views);
	void start(bool is_drilldown, bool is_spy_switch);
	sinsp_table_info* get_selected_view();
	void pause();
	bool is_searching()
	{
		return m_output_filtering;
	}
	bool is_eof()
	{
		return m_eof != 0;
	}
	void render();

	//
	// Return true if the application is supposed to exit
	//
	inline bool process_event(sinsp_evt* evt, int32_t next_res)
	{
		bool end_of_sample;
		uint64_t ts = evt->get_ts();

		//
		// Process the user input
		//
#ifndef NOCURSESUI
		if((ts - m_last_input_check_ts > m_input_check_period_ns) || m_eof)
		{
			uint32_t ninputs = 0;

			uint64_t evtnum = evt->get_num();

			//
			// If this is a file, print the progress once in a while
			//
			if(!m_inspector->is_live())
			{
				if(evtnum - m_last_progress_evt > 30000)
				{
					print_progress(m_inspector->get_read_progress());
					m_last_progress_evt = evtnum;
				}
			}

			//
			// If we have more than one event in the queue, consume all of them
			//
			while(true)
			{
				int input = getch();

				if(input == -1)
				{
					//
					// All events consumed
					//
					break;
				}
				else
				{
					ninputs++;
				}

				//
				// Handle the event
				//
				sysdig_table_action ta = handle_input(input);

				//
				// Some events require that we perform additional actions
				//
				switch(ta)
				{
				case STA_QUIT:
					return true;
				case STA_SWITCH_VIEW:
					switch_view(false);
					break;
				case STA_SWITCH_SPY:
					switch_view(true);
					return false;
				case STA_DRILLDOWN:
					{
						auto res = m_datatable->get_row_key_name_and_val(m_viz->m_selct);
						drilldown(res.first->m_name, res.second.c_str());
					}
					break;
				case STA_DRILLUP:
					drillup();
					break;
				case STA_SPY:
					{
						auto res = m_datatable->get_row_key_name_and_val(m_viz->m_selct);
						spy_selection(res.first->m_name, res.second.c_str(), false);
					}
					return false;
				case STA_DIG:
					{
						auto res = m_datatable->get_row_key_name_and_val(m_viz->m_selct);
						spy_selection(res.first->m_name, res.second.c_str(), true);
					}
					return false;
				case STA_NONE:
					break;
				default:
					ASSERT(false);
					break;
				}
			}

			if(ninputs == 0)
			{
				m_last_input_check_ts = ts;
			}
		}
#endif

		//
		// We reading from a file and we reached its end. 
		// We keep looping because we want to handle user events, but we stop the
		// processing here. We also make sure to sleep a bit to keep the CPU under
		// control. 
		//
		if(m_eof > 1)
		{
#ifndef NOCURSESUI
			usleep(10000);
#endif
			return false;
		}

		//
		// Perform event processing
		//
#ifndef NOCURSESUI
		if(m_spy_box)
		{
			m_spy_box->process_event(evt, next_res);
		}
		else
#endif
		{
			//
			// Check if it's time to flush
			//
			if(m_inspector->is_live() || m_offline_replay)
			{
				end_of_sample = (evt == NULL || ts > m_datatable->m_next_flush_time_ns);
			}
			else
			{
				//
				// For files, we flush only once, at the end of the capture.
				//
				if(next_res == SCAP_EOF)
				{
					end_of_sample = true;
				}
				else
				{
					end_of_sample = false;				
				}
			}

			if(end_of_sample)
			{
				handle_end_of_sample(evt, next_res);

				//
				// Check if this the end of the capture file, and if yes take note of that 
				//
				if(next_res == SCAP_EOF)
				{
					ASSERT(!m_inspector->is_live());
					m_eof++;
					return false;
				}
			}

			m_datatable->process_event(evt);
		}

		return false;
	}

	int m_colors[LAST_COLORELEMENT];
	vector<sinsp_table_info> m_views;
	int32_t m_selected_view;
	uint32_t m_selected_sidemenu_entry;
	sinsp_ui_selection_hierarchy m_sel_hierarchy;
	curses_table* m_viz;
	uint32_t m_screenw;
	uint32_t m_screenh;
	uint32_t m_eof;
	uint64_t m_input_check_period_ns;
	bool m_search_nomatch;
#ifndef NOCURSESUI
	curses_table_sidemenu* m_sidemenu;
#endif

private:
	void handle_end_of_sample(sinsp_evt* evt, int32_t next_res);
	void restart_capture(bool is_spy_switch);
	void switch_view(bool is_spy_switch);
	void spy_selection(string field, string val, bool is_dig);
	// returns false if there is no suitable drill down view for this field
	bool drilldown(string field, string val);
	// returns false if we are already at the top of the hierarchy
	bool drillup();
	void create_complete_filter();

#ifndef NOCURSESUI
	void render_header();
	void render_default_main_menu();
	void render_filtersearch_main_menu();
	void render_spy_main_menu();
	void render_main_menu();
	sysdig_table_action handle_textbox_input(int ch);
	sysdig_table_action handle_input(int ch);
	void populate_sidemenu(string field, vector<sidemenu_list_entry>* viewlist);
	void print_progress(double progress);

	curses_textbox* m_spy_box;
#endif

	sinsp* m_inspector;
	vector<string> m_menuitems;
	sinsp_table* m_datatable;
	string m_event_source_name;
	string m_cmdline_capture_filter;
	string m_complete_filter;
	string m_manual_filter;
	string m_manual_search_text;
	bool m_paused;
	uint64_t m_last_input_check_ts;
	bool m_output_filtering;
	bool m_output_searching;
	uint32_t m_cursor_pos;
	bool m_is_filter_sysdig;
	bool m_offline_replay;
	uint64_t m_last_progress_evt;
	vector<sidemenu_list_entry> m_sidemenu_viewlist;
};
