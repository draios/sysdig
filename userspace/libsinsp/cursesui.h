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

#ifdef CSYSDIG

#ifndef _WIN32
#include <unistd.h>
#endif

#define UI_USER_INPUT_CHECK_PERIOD_NS 10000000
#define VIEW_SIDEMENU_WIDTH 20
#define ACTION_SIDEMENU_WIDTH 30
#define VIEW_ID_SPY -1
#define VIEW_ID_DIG -2
#define VIEW_ID_INFO -3

string combine_filters(string flt1, string flt2);
class ctext;
class sinsp_chart;
class curses_spectro;
extern sinsp_logger g_logger;

class sinsp_menuitem_info
{
public:
	enum type 
	{
		TABLE = 1,
		LIST = 2,
		ALL = TABLE | LIST,
	};

	sinsp_menuitem_info(string key, 
		string desc, 
		sinsp_menuitem_info::type type,
		int keyboard_equivalent)
	{
		m_key = key;
		m_desc = desc;
		m_type = type;
		m_keyboard_equivalent = keyboard_equivalent;
	}

	string m_key;
	string m_desc;
	sinsp_menuitem_info::type m_type;
	int m_keyboard_equivalent;
};

class sinsp_ui_selection_info
{
public:
	sinsp_ui_selection_info(string field, 
		string val,
		sinsp_view_column_info* column_info,
		string view_filter,
		uint32_t prev_selected_view, 
		uint32_t prev_selected_sidemenu_entry, 
		sinsp_table_field* rowkey,
		uint32_t prev_sorting_col,
		string prev_manual_filter,
		bool prev_is_filter_sysdig,
		bool prev_is_sorting_ascending,
		bool is_drilldown)
	{
		m_field = field;
		m_column_info = column_info;
		m_val = val;
		m_view_filter = view_filter;
		m_prev_selected_view = prev_selected_view;
		m_prev_selected_sidemenu_entry = prev_selected_sidemenu_entry;
		m_prev_sorting_col = prev_sorting_col;
		m_prev_manual_filter = prev_manual_filter;
		m_prev_is_filter_sysdig = prev_is_filter_sysdig;
		m_prev_is_sorting_ascending = prev_is_sorting_ascending;
		m_is_drilldown = is_drilldown;

		if(rowkey != NULL)
		{
			m_rowkey = *rowkey;
		}
		else
		{
			m_rowkey.m_len = 0;	
			m_rowkey.m_val = NULL;	
		}
	}

	string m_field;
	string m_val;
	sinsp_view_column_info* m_column_info;
	string m_view_filter;
	uint32_t m_prev_selected_view;
	uint32_t m_prev_selected_sidemenu_entry;
	uint32_t m_prev_sorting_col;
	string m_prev_manual_filter;
	bool m_prev_is_filter_sysdig;
	sinsp_table_field m_rowkey;
	bool m_prev_is_sorting_ascending;
	bool m_is_drilldown;
};

class sinsp_ui_selection_hierarchy
{
public:
	void push_back(string field, 
		string val,
		sinsp_view_column_info* column_info,
		string view_filter,
		uint32_t prev_selected_view, 
		uint32_t prev_selected_sidemenu_entry, 
		sinsp_table_field* rowkey,
		uint32_t prev_sorting_col,
		string prev_manual_filter,
		bool prev_is_filter_sysdig,
		bool prev_is_sorting_ascending,
		bool is_drilldown)
	{
		m_hierarchy.push_back(sinsp_ui_selection_info(field, 
			val,
			column_info,
			view_filter,
			prev_selected_view, 
			prev_selected_sidemenu_entry,
			rowkey,
			prev_sorting_col,
			prev_manual_filter,
			prev_is_filter_sysdig,
			prev_is_sorting_ascending,
			is_drilldown));
	}

	~sinsp_ui_selection_hierarchy()
	{
		for(auto e : m_hierarchy)
		{
			if(e.m_rowkey.m_val != NULL)
			{
				delete [] e.m_rowkey.m_val;
			}
		}
	}

	string tofilter()
	{
		string res;
		uint32_t j;
		uint32_t hs = (uint32_t)m_hierarchy.size();

		for(j = 0; j < hs; j++)
		{
			bool has_filter = false;
			uint32_t lastsize = res.size();

			if(m_hierarchy[j].m_view_filter != "")
			{
				has_filter = true;
			}

			if(hs > 1)
			{
				res += "(";
			}

			if(has_filter)
			{
				res += "(";
				res += m_hierarchy[j].m_view_filter;
				res += ")";
			}

			if(m_hierarchy[j].m_field != "")
			{
				bool skip = false;

				if(m_hierarchy[j].m_column_info != NULL &&
				(m_hierarchy[j].m_column_info->m_flags & TEF_FILTER_IN_CHILD_ONLY))
				{
					if(j < hs - 1)
					{
						skip = true;
					}
				}	

				if(!skip)
				{
					if(has_filter)
					{
						res += " and ";
					}
					res += m_hierarchy[j].m_field;
					res += "=";
					res += m_hierarchy[j].m_val;
				}
			}

			if(res.size() != lastsize)
			{
				if(hs > 1)
				{
					res += ")";
				}

				res += " and ";

				if(res.size() >= 7 && res.substr(res.size() - 7) == "() and ")
				{
					res = res.substr(0, res.size() - 7);
				}

			}
		}

		if(res.size() >= 5)
		{
			string trailer = res.substr(res.size() - 5).c_str();
			if(trailer == " and ")
			{
				res = res.substr(0, res.size() - 5);
			}
		}

		return res;
	}

	uint32_t size()
	{
		return (uint32_t)m_hierarchy.size();
	}

	sinsp_ui_selection_info* at(uint32_t j)
	{
		return &m_hierarchy[j];
	}

	bool pop_back()
	{
		if(m_hierarchy.size() == 0)
		{
			return false;
		}
		else
		{
			m_hierarchy.pop_back();
			return true;
		}
	}


private:
	vector<sinsp_ui_selection_info> m_hierarchy;
};

class sinsp_mouse_to_key_list_entry
{
public:
	sinsp_mouse_to_key_list_entry(uint32_t startx,
		uint32_t starty,
		uint32_t endx,
		uint32_t endy,
		int keyboard_equivalent)
	{
		m_startx = startx;
		m_endx = endx;
		m_starty = starty;
		m_endy = endy;
		m_keyboard_equivalent = keyboard_equivalent;
	}

	uint32_t m_startx;
	uint32_t m_endx;
	uint32_t m_starty;
	uint32_t m_endy;
	int m_keyboard_equivalent;
};

class sinsp_mouse_to_key_list
{
public:
	void add(sinsp_mouse_to_key_list_entry entry)
	{
		m_list.push_back(entry);		
	}

	int get_key_from_coordinates(uint32_t x, uint32_t y)
	{		
		for(auto e : m_list)
		{
			if(x >= e.m_startx &&
				x <= e.m_endx &&
				y >= e.m_starty &&
				y <= e.m_endy)
			{
				return e.m_keyboard_equivalent;
			}
		}

		return -1;
	}

	void clear()
	{
		m_list.clear();
	}

	vector<sinsp_mouse_to_key_list_entry> m_list;
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
		PANEL_HEADER_LIST_FOCUS,
		PANEL_HEADER_LIST_HIGHLIGHT,
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
		GRAPH_BLACK,
		GRAPH_WHITE,
		GRAPH_WHITE_D,
		GRAPH_GREEN_L,
		GRAPH_GREEN,
		GRAPH_GREEN_D,
		GRAPH_YELLOW_L,
		GRAPH_YELLOW,
		GRAPH_YELLOW_D,
		GRAPH_RED_L,
		GRAPH_RED,
		GRAPH_RED_D,
		GRAPH_MAGENTA_L,
		GRAPH_MAGENTA,
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
		string cmdline_capture_filter, uint64_t refresh_interval_ns, 
		bool print_containers, bool raw_output, bool is_mousedrag_available);
	~sinsp_cursesui();
	void configure(sinsp_view_manager* views);
	void start(bool is_drilldown, bool is_spy_switch);
	sinsp_view_info* get_selected_view();
	sinsp_view_info* get_prev_selected_view();
	void pause();
	bool is_searching()
	{
		return m_output_filtering;
	}
	bool is_eof()
	{
		return m_eof != 0;
	}
	void set_truncated_input(bool truncated)
	{
		m_truncated_input = truncated;
	}
#ifndef NOCURSESUI
	void render();
#endif
	void turn_search_on(search_caller_interface* ifc, string header_text);
	uint64_t get_time_delta();
	void run_action(sinsp_view_action_info* action);
	void spy_selection(string field, string val, sinsp_view_column_info* column_info, bool is_dig);
	sysdig_table_action handle_input(int ch);

	//
	// Return true if the application is supposed to exit
	//
	inline bool process_event(sinsp_evt* evt, int32_t next_res)
	{
		uint64_t ts = evt->get_ts();
		if(!m_inspector->is_live())
		{
			if(m_1st_evt_ts == 0)
			{
				m_1st_evt_ts = ts;	
			}

			m_last_evt_ts = ts;	
		}

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
			if(!m_inspector->is_live() && !m_offline_replay)
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
				bool sppaused = is_spectro_paused(input);

				if(input == -1)
				{
					//
					// All events consumed
					//
					if(m_spectro)
					{
						if(sppaused)
						{
							usleep(100000);
							continue;
						}
						else
						{
							break;
						}
					}
					else
					{
						break;
					}
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
					return false;
				case STA_SWITCH_SPY:
					switch_view(true);
					return false;
				case STA_DRILLDOWN:
					{
						if(m_viz != NULL)
						{
							sinsp_view_column_info* kinfo = get_selected_view()->get_key();

							//
							// Note: kinfo is null for list views, that currently don't support
							//       drill down
							//
							if(kinfo != NULL)
							{
								auto res = m_datatable->get_row_key_name_and_val(m_viz->m_selct);
								if(res.first != NULL)
								{
									drilldown(kinfo->get_filter_field(m_view_depth),
										res.second.c_str(), 
										kinfo,
										res.first);
								}
							}
						}
						else
						{
							ASSERT(m_spectro != NULL);
							drilldown("", "", NULL, NULL);							
						}
					}
					return false;
				case STA_DRILLUP:
					drillup();
					return false;
				case STA_SPECTRO:
				case STA_SPECTRO_FILE:
					{
						sinsp_view_column_info* kinfo = get_selected_view()->get_key();

						//
						// Note: kinfo is null for list views, that currently don't support
						//       drill down
						//
						if(kinfo != NULL)
						{
							auto res = m_datatable->get_row_key_name_and_val(m_viz->m_selct);
							if(res.first != NULL)
							{
								spectro_selection(get_selected_view()->get_key()->get_filter_field(m_view_depth), 
									res.second.c_str(),
									get_selected_view()->get_key(),
									res.first, ta);
							}
						}
					}
					return false;
				case STA_SPY:
					{
						auto res = m_datatable->get_row_key_name_and_val(m_viz->m_selct);
						if(res.first != NULL)
						{
							spy_selection(get_selected_view()->get_key()->get_filter_field(m_view_depth), 
								res.second.c_str(),
								get_selected_view()->get_key(),
								false);
						}
					}
					return false;
				case STA_DIG:
					{
						if(m_viz)
						{
							auto res = m_datatable->get_row_key_name_and_val(m_viz->m_selct);
							if(res.first != NULL)
							{
								spy_selection(get_selected_view()->get_key()->get_filter_field(m_view_depth), 
									res.second.c_str(),
									get_selected_view()->get_key(),
									true);
							}
						}
						else
						{
							ASSERT(m_spectro);
							spy_selection("", "", NULL, true);
						}
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
		// We were reading from a file and we reached its end. 
		// Unless we are in raw mode, we keep looping because we want to handle user events, 
		// but we stop the processing here. We also make sure to sleep a bit to keep the 
		// CPU under control. 
		//
		if(m_eof > 1)
		{
#ifndef NOCURSESUI
			usleep(10000);
#endif
			if(m_raw_output)
			{
				return true;
			}
			else
			{
				return false;
			}
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
			bool end_of_sample;

			//
			// Check if it's time to flush
			//
			if(m_inspector->is_live() || m_offline_replay)
			{
				if(next_res == SCAP_EOF)
				{
					end_of_sample = true;
				}
				else
				{
					end_of_sample = (evt == NULL || ts > m_datatable->m_next_flush_time_ns);
				}
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

	sinsp_table* m_datatable;
	int m_colors[LAST_COLORELEMENT];
	sinsp_view_manager m_views;
	int32_t m_selected_view;
	int32_t m_prev_selected_view;
	uint32_t m_selected_view_sidemenu_entry;
	uint32_t m_selected_action_sidemenu_entry;
	uint32_t m_selected_view_sort_sidemenu_entry;
	sinsp_ui_selection_hierarchy m_sel_hierarchy;
	uint32_t m_screenw;
	uint32_t m_screenh;
	uint32_t m_eof;
	uint64_t m_input_check_period_ns;
	bool m_search_nomatch;
	bool m_print_containers;
	int32_t m_sidemenu_sorting_col;
#ifndef NOCURSESUI
	curses_table* m_viz;
	curses_spectro* m_spectro;
	curses_table_sidemenu* m_view_sidemenu;
	curses_table_sidemenu* m_action_sidemenu;
	curses_viewinfo_page* m_viewinfo_page;
	curses_table_sidemenu* m_view_sort_sidemenu;
	curses_mainhelp_page* m_mainhelp_page;
	curses_textbox* m_spy_box;
	sinsp_evt::param_fmt m_spybox_text_format;
#endif
	bool m_offline_replay;
	uint64_t m_refresh_interval_ns;
	sinsp* m_inspector;
	uint32_t m_view_depth;
	bool m_is_mousedrag_available;

private:
	void handle_end_of_sample(sinsp_evt* evt, int32_t next_res);
	void restart_capture(bool is_spy_switch);
	void switch_view(bool is_spy_switch);
	bool spectro_selection(string field, string val, sinsp_view_column_info* column_info, filtercheck_field_info* info, sysdig_table_action ta);
	bool do_drilldown(string field, string val, sinsp_view_column_info* column_info, uint32_t new_view_num, filtercheck_field_info* info);
	// returns false if there is no suitable drill down view for this field
	bool drilldown(string field, string val, sinsp_view_column_info* column_info, filtercheck_field_info* info);
	// returns false if we are already at the top of the hierarchy
	bool drillup();
	void create_complete_filter();

#ifndef NOCURSESUI
	void render_header();
	void draw_bottom_menu(vector<sinsp_menuitem_info>* items, bool istable);
	void render_default_main_menu();
	void render_filtersearch_main_menu();
	void render_spy_main_menu();
	void render_position_info();
	void render_main_menu();
	sysdig_table_action handle_textbox_input(int ch);
	void populate_view_sidemenu(string field, vector<sidemenu_list_entry>* viewlist);
	void populate_action_sidemenu();
	void populate_view_cols_sidemenu();
	void print_progress(double progress);
	void show_selected_view_info();
	bool is_spectro_paused(int input);
#endif

	vector<sinsp_menuitem_info> m_menuitems;
	vector<sinsp_menuitem_info> m_menuitems_spybox;
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
	uint64_t m_last_progress_evt;
	vector<sidemenu_list_entry> m_sidemenu_viewlist;
	sinsp_chart* m_chart;
	search_caller_interface* m_search_caller_interface;
	int32_t m_search_start_x, m_search_start_y;
	uint64_t m_n_evts_in_file;
	uint64_t m_1st_evt_ts;
	uint64_t m_last_evt_ts;
	uint64_t m_evt_ts_delta;
	sinsp_filter_check_reference* m_timedelta_formatter;
	sinsp_mouse_to_key_list m_mouse_to_key_list;
	uint32_t m_filterstring_start_x;
	uint32_t m_filterstring_end_x;
	string m_search_header_text;
	bool m_raw_output;
	bool m_truncated_input;
};

#endif // CSYSDIG
