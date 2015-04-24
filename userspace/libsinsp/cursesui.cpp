/*
Copyright (C) 2013-2015 Draios inc.

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
#include "../../driver/ppm_ringbuffer.h"
#include "filter.h"
#include "filterchecks.h"

#ifndef _WIN32
#include <curses.h>
#endif
#include "table.h"
#include "cursescomponents.h"
#include "cursestable.h"
#include "ctext.h"
#include "cursesui.h"

#ifndef NOCURSESUI
#define ColorPair(i,j) COLOR_PAIR((7-i)*8+j)
#endif

///////////////////////////////////////////////////////////////////////////////
// sinsp_cursesui implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_cursesui::sinsp_cursesui(sinsp* inspector, 
							   string event_source_name, 
							   string cmdline_capture_filter, 
							   uint64_t refresh_interval_ns)
{
	m_inspector = inspector;
	m_event_source_name = event_source_name;
	m_selected_view = 0;
	m_selected_sidemenu_entry = 0;
	m_datatable = NULL;
	m_viz = NULL;
	m_cmdline_capture_filter = cmdline_capture_filter;
	m_paused = false;
	m_last_input_check_ts = 0;
	m_output_filtering = false;
	m_output_searching = false;
	m_is_filter_sysdig = false;
	m_eof = 0;
	m_offline_replay = false;
	m_last_progress_evt = 0;
	m_input_check_period_ns = UI_USER_INPUT_CHECK_PERIOD_NS;
	m_search_nomatch = false;
	m_chart = NULL;
	m_n_evts_in_file = 0;
	m_1st_evt_ts = 0;
	m_last_evt_ts = 0;
	m_evt_ts_delta = 0;
	m_timedelta_formatter = new sinsp_filter_check_reference();
	m_refresh_interval_ns = refresh_interval_ns;

#ifndef NOCURSESUI
	m_sidemenu = NULL;
	m_spy_box = NULL;
	m_search_caller_interface = NULL;
	m_viewinfo_page = NULL;
	m_mainhelp_page = NULL;

	//
	// Colors initialization
	//
	m_colors[RESET_COLOR] = ColorPair( COLOR_WHITE,COLOR_BLACK);
	m_colors[DEFAULT_COLOR] = ColorPair( COLOR_WHITE,COLOR_BLACK);
	m_colors[FUNCTION_BAR] = ColorPair(COLOR_BLACK,COLOR_YELLOW);
	m_colors[FUNCTION_KEY] = ColorPair( COLOR_WHITE,COLOR_BLACK);
	m_colors[PANEL_HEADER_FOCUS] = ColorPair(COLOR_BLACK,COLOR_GREEN);
	m_colors[PANEL_HEADER_UNFOCUS] = ColorPair(COLOR_BLACK,COLOR_GREEN);
	m_colors[PANEL_HIGHLIGHT_FOCUS] = ColorPair(COLOR_BLACK,COLOR_CYAN);
	m_colors[PANEL_HIGHLIGHT_UNFOCUS] = ColorPair(COLOR_BLACK, COLOR_WHITE);
	m_colors[PANEL_HEADER_LIST_FOCUS] = ColorPair(COLOR_BLACK,COLOR_YELLOW);
	m_colors[PANEL_HEADER_LIST_HIGHLIGHT] = ColorPair(COLOR_BLACK,COLOR_GREEN);
	m_colors[FAILED_SEARCH] = ColorPair(COLOR_RED,COLOR_CYAN);
	m_colors[UPTIME] = A_BOLD | ColorPair(COLOR_CYAN,COLOR_BLACK);
	m_colors[BATTERY] = A_BOLD | ColorPair(COLOR_CYAN,COLOR_BLACK);
	m_colors[LARGE_NUMBER] = A_BOLD | ColorPair(COLOR_RED,COLOR_BLACK);
	m_colors[METER_TEXT] = ColorPair(COLOR_CYAN,COLOR_BLACK);
	m_colors[METER_VALUE] = A_BOLD | ColorPair(COLOR_CYAN,COLOR_BLACK);
	m_colors[LED_COLOR] = ColorPair(COLOR_GREEN,COLOR_BLACK);
	m_colors[TASKS_RUNNING] = A_BOLD | ColorPair(COLOR_GREEN,COLOR_BLACK);
	m_colors[PROCESS] = A_NORMAL;
	m_colors[PROCESS_SHADOW] = A_BOLD | ColorPair(COLOR_BLACK,COLOR_BLACK);
	m_colors[PROCESS_TAG] = A_BOLD | ColorPair(COLOR_YELLOW,COLOR_BLACK);
	m_colors[PROCESS_MEGABYTES] = ColorPair(COLOR_CYAN,COLOR_BLACK);
	m_colors[PROCESS_BASENAME] = A_BOLD | ColorPair(COLOR_CYAN,COLOR_BLACK);
	m_colors[PROCESS_TREE] = ColorPair(COLOR_CYAN,COLOR_BLACK);
	m_colors[PROCESS_R_STATE] = ColorPair(COLOR_GREEN,COLOR_BLACK);
	m_colors[PROCESS_D_STATE] = A_BOLD | ColorPair(COLOR_RED,COLOR_BLACK);
	m_colors[PROCESS_HIGH_PRIORITY] = ColorPair(COLOR_RED,COLOR_BLACK);
	m_colors[PROCESS_LOW_PRIORITY] = ColorPair(COLOR_RED,COLOR_BLACK);
	m_colors[PROCESS_THREAD] = ColorPair(COLOR_GREEN,COLOR_BLACK);
	m_colors[PROCESS_THREAD_BASENAME] = A_BOLD | ColorPair(COLOR_GREEN,COLOR_BLACK);
	m_colors[BAR_BORDER] = A_BOLD;
	m_colors[BAR_SHADOW] = A_BOLD | ColorPair(COLOR_BLACK,COLOR_BLACK);
	m_colors[SWAP] = ColorPair(COLOR_RED,COLOR_BLACK);
	m_colors[GRAPH_1] = A_BOLD | ColorPair(COLOR_RED,COLOR_BLACK);
	m_colors[GRAPH_2] = ColorPair(COLOR_RED,COLOR_BLACK);
	m_colors[GRAPH_3] = A_BOLD | ColorPair(COLOR_YELLOW,COLOR_BLACK);
	m_colors[GRAPH_4] = A_BOLD | ColorPair(COLOR_GREEN,COLOR_BLACK);
	m_colors[GRAPH_5] = ColorPair(COLOR_GREEN,COLOR_BLACK);
	m_colors[GRAPH_6] = ColorPair(COLOR_CYAN,COLOR_BLACK);
	m_colors[GRAPH_7] = A_BOLD | ColorPair(COLOR_BLUE,COLOR_BLACK);
	m_colors[GRAPH_8] = ColorPair(COLOR_BLUE,COLOR_BLACK);
	m_colors[GRAPH_9] = A_BOLD | ColorPair(COLOR_BLACK,COLOR_BLACK);
	m_colors[MEMORY_USED] = ColorPair(COLOR_GREEN,COLOR_BLACK);
	m_colors[MEMORY_BUFFERS] = ColorPair(COLOR_BLUE,COLOR_BLACK);
	m_colors[MEMORY_BUFFERS_TEXT] = A_BOLD | ColorPair(COLOR_BLUE,COLOR_BLACK);
	m_colors[MEMORY_CACHE] = ColorPair(COLOR_YELLOW,COLOR_BLACK);
	m_colors[LOAD_AVERAGE_FIFTEEN] = A_BOLD | ColorPair(COLOR_BLACK,COLOR_BLACK);
	m_colors[LOAD_AVERAGE_FIVE] = A_NORMAL;
	m_colors[LOAD_AVERAGE_ONE] = A_BOLD;
	m_colors[LOAD] = A_BOLD;
	m_colors[HELP_BOLD] = A_BOLD | ColorPair(COLOR_CYAN,COLOR_BLACK);
	m_colors[CLOCK] = A_BOLD;
	m_colors[CHECK_BOX] = ColorPair(COLOR_CYAN,COLOR_BLACK);
	m_colors[CHECK_MARK] = A_BOLD;
	m_colors[CHECK_TEXT] = A_NORMAL;
	m_colors[HOSTNAME] = A_BOLD;
	m_colors[CPU_NICE] = ColorPair(COLOR_BLUE,COLOR_BLACK);
	m_colors[CPU_NICE_TEXT] = A_BOLD | ColorPair(COLOR_BLUE,COLOR_BLACK);
	m_colors[CPU_NORMAL] = ColorPair(COLOR_GREEN,COLOR_BLACK);
	m_colors[CPU_KERNEL] = ColorPair(COLOR_RED,COLOR_BLACK);
	m_colors[CPU_IOWAIT] = A_BOLD | ColorPair(COLOR_BLACK, COLOR_BLACK);
	m_colors[CPU_IRQ] = ColorPair(COLOR_YELLOW,COLOR_BLACK);
	m_colors[CPU_SOFTIRQ] = ColorPair(COLOR_MAGENTA,COLOR_BLACK);
	m_colors[SPY_READ] = ColorPair(COLOR_RED,COLOR_BLACK);
	m_colors[SPY_WRITE] = ColorPair(COLOR_BLUE,COLOR_BLACK);

	//
	// Populate the main menu entries
	//
	m_menuitems.push_back(sinsp_menuitem_info("F1", "Help", sinsp_menuitem_info::ALL, KEY_F(1)));
	m_menuitems.push_back(sinsp_menuitem_info("F2", "Views", sinsp_menuitem_info::ALL, KEY_F(2)));
	m_menuitems.push_back(sinsp_menuitem_info("F4", "Filter", sinsp_menuitem_info::ALL, KEY_F(4)));
	m_menuitems.push_back(sinsp_menuitem_info("F5", "Echo", sinsp_menuitem_info::TABLE, KEY_F(5)));
	m_menuitems.push_back(sinsp_menuitem_info("F6", "Dig", sinsp_menuitem_info::TABLE, KEY_F(6)));
	m_menuitems.push_back(sinsp_menuitem_info("F7", "Legend", sinsp_menuitem_info::ALL, KEY_F(7)));
	m_menuitems.push_back(sinsp_menuitem_info("CTRL+F", "Search", sinsp_menuitem_info::ALL, 6));
	m_menuitems.push_back(sinsp_menuitem_info("p", "Pause", sinsp_menuitem_info::ALL, 'p'));
	m_menuitems.push_back(sinsp_menuitem_info("c", "Clear", sinsp_menuitem_info::LIST, 'c'));

	m_menuitems_spybox.push_back(sinsp_menuitem_info("F1", "Help", sinsp_menuitem_info::ALL, KEY_F(1)));
	m_menuitems_spybox.push_back(sinsp_menuitem_info("F2", "View As", sinsp_menuitem_info::ALL, KEY_F(2)));
	m_menuitems_spybox.push_back(sinsp_menuitem_info("CTRL+F", "Search", sinsp_menuitem_info::ALL, 6));
	m_menuitems_spybox.push_back(sinsp_menuitem_info("p", "Pause", sinsp_menuitem_info::ALL, 'p'));
	m_menuitems_spybox.push_back(sinsp_menuitem_info("Bak", "Back", sinsp_menuitem_info::ALL, KEY_BACKSPACE));
	m_menuitems_spybox.push_back(sinsp_menuitem_info("c", "Clear", sinsp_menuitem_info::ALL, 'c'));

	//
	// Get screen dimensions
	//
	getmaxyx(stdscr, m_screenh, m_screenw);
#endif
}

sinsp_cursesui::~sinsp_cursesui()
{
	if(m_datatable != NULL)
	{
		delete m_datatable;
	}

#ifndef NOCURSESUI
	if(m_viz != NULL)
	{
		delete m_viz;
	}

	if(m_sidemenu != NULL)
	{
		delete m_sidemenu;
	}

	if(m_viewinfo_page != NULL)
	{
		delete m_viewinfo_page;
	}

	if(m_mainhelp_page != NULL)
	{
		delete m_mainhelp_page;
	}
#endif

	delete m_timedelta_formatter;
}

void sinsp_cursesui::configure(sinsp_view_manager* views)
{
	if(views == NULL)
	{
		ASSERT(false);
		throw sinsp_exception("trying to configure the command line UI with no views");
	}

	//
	// Copy the input views
	//
	m_views = *views;

	//
	// Determine which view is the starting one
	//
	m_selected_view = m_views.get_selected_view();
	m_selected_sidemenu_entry = m_selected_view;
}

void sinsp_cursesui::start(bool is_drilldown, bool is_spy_switch)
{
	//
	// Input validation
	//
	if(m_selected_view >= 0)
	{
		if(m_selected_view >= (int32_t)m_views.size())
		{
			ASSERT(false);
			throw sinsp_exception("invalid view");		
		}
	}

	//
	// Delete the previous table and visualizations
	//
	if(m_datatable != NULL)
	{
		delete m_datatable;
		m_datatable = NULL;
	}

#ifndef NOCURSESUI
	if(m_viz != NULL)
	{
		delete m_viz;
		m_viz = NULL;
		m_chart = NULL;
	}

	if(m_spy_box && !is_spy_switch)
	{
		delete m_spy_box;
		m_spy_box = NULL;
		m_chart = NULL;
	}
#endif

	//
	// Update the filter based on what's selected
	//
	create_complete_filter();

	//
	// If we need a new datatable, allocate it and set it up
	//
	sinsp_view_info* wi = NULL;
	sinsp_table::tabletype ty = sinsp_table::TT_NONE;

	if(m_selected_view >= 0)
	{
		wi = m_views.at(m_selected_view);

		if(wi->m_type == sinsp_view_info::T_TABLE)
		{
			ty = sinsp_table::TT_TABLE;
		}
		else if(wi->m_type == sinsp_view_info::T_LIST)
		{
			ty = sinsp_table::TT_LIST;
		}
		else
		{
			ASSERT(false);
		}

		m_datatable = new sinsp_table(m_inspector, ty, m_refresh_interval_ns);

		try
		{
			m_datatable->configure(&wi->m_columns, 
				m_complete_filter,
				wi->m_use_defaults);
		}
		catch(...)
		{
			delete m_datatable;
			m_datatable = NULL;
			throw;
		}

		m_datatable->set_sorting_col(wi->m_sortingcol);
	}
#ifndef NOCURSESUI
	else
	{
		//
		// Create the visualization component
		//
		m_spy_box = new curses_textbox(m_inspector, this, m_selected_view);
		m_spy_box->reset();
		m_chart = m_spy_box;
		m_spy_box->set_filter(m_complete_filter);
	}

	//
	// If we need a table visualization, allocate it and set it up
	//
	if(m_selected_view >= 0)
	{
		ASSERT(ty != sinsp_table::TT_NONE);
		m_viz = new curses_table(this, m_inspector, ty);
		m_chart = m_viz;

		vector<int32_t> colsizes;
		vector<string> colnames;

		ASSERT(wi != NULL);

		wi->get_col_names_and_sizes(&colnames, &colsizes);

		m_viz->configure(m_datatable, &colsizes, &colnames);
		if(!is_drilldown)
		{
			populate_sidemenu("", &m_sidemenu_viewlist);
		}
	}
#endif
}

#ifndef NOCURSESUI
void sinsp_cursesui::render_header()
{
	uint32_t j = 0;
	uint32_t k;

	//
	// Show the 'viewing' line
	//
	attrset(m_colors[HELP_BOLD]);
	move(0, 0);
	for(j = 0; j < m_screenw; j++)
	{
		addch(' ');
	}

	mvaddstr(0, 0, "Viewing:");
 
	attrset(m_colors[sinsp_cursesui::PROCESS]);

	string vs;

	if(m_selected_view >= 0)
	{
		sinsp_view_info* sv = get_selected_view();
		const char* vcs = sv->m_name.c_str();
		vs = vcs;
	}
	else
	{
		if(m_selected_view == VIEW_ID_SPY)
		{
			vs = "I/O activity";
		}
		else if(m_selected_view == VIEW_ID_DIG)
		{
			vs = "sysdig output";
		}
		else
		{
			ASSERT(false);
		}
	}

	if(m_sel_hierarchy.m_hierarchy.size() != 0)
	{
		vs += " for ";

		for(j = 0; j < m_sel_hierarchy.m_hierarchy.size(); j++)
		{
			vs += m_sel_hierarchy.m_hierarchy[j].m_field;
			vs += "=";
			vs += m_sel_hierarchy.m_hierarchy[j].m_val;

			if(j < m_sel_hierarchy.m_hierarchy.size() - 1)
			{
				vs += " and ";
			}
		}
	}

	mvaddstr(0, sizeof("Viewing: ") - 1, vs.c_str());

	if(m_paused)
	{
		string wstr = "PAUSED";
		attrset(m_colors[sinsp_cursesui::LARGE_NUMBER]);
		mvprintw(0,
			m_screenw / 2 - wstr.size() / 2, 
			wstr.c_str());	
	}

	//
	// Show the 'filter' line
	//
	attrset(m_colors[HELP_BOLD]);

	move(1, 0);
	for(uint32_t j = 0; j < m_screenw; j++)
	{
		addch(' ');
	}

	attrset(m_colors[HELP_BOLD]);

	mvaddstr(1, 0, "Source:");
	k = sizeof("Source: ") - 1;

	attrset(m_colors[sinsp_cursesui::PROCESS]);
	
	string srcstr;
	
	if(m_inspector->is_live())
	{
		srcstr = "Live System";
	}
	else
	{
		if(m_n_evts_in_file == 0)
		{
			m_n_evts_in_file = m_inspector->get_num_events();
			m_evt_ts_delta = m_last_evt_ts - m_1st_evt_ts;
		}

		srcstr = m_inspector->get_input_filename();
		srcstr += " (" + to_string(m_n_evts_in_file) + " evts, ";

		m_timedelta_formatter->set_val(PT_RELTIME, 
			(uint8_t*)&m_evt_ts_delta,
			8,
			0,
			ppm_print_format::PF_DEC);

			srcstr += string(m_timedelta_formatter->tostring_nice(NULL, 0)) + ")";
	}

	mvaddnstr(1, k, srcstr.c_str(), m_screenw - k - 1);

	k += srcstr.size() + 1;
	m_filterstring_start_x = k;

	attrset(m_colors[HELP_BOLD]);

	mvaddstr(1, k, "Filter:");
	k += sizeof("Filter: ") - 1;

	attrset(m_colors[sinsp_cursesui::PROCESS]);

	string sflt;
	if(m_complete_filter != "")
	{
		sflt = m_complete_filter.c_str();
	}
	else
	{
		sflt = "none";
	}

	mvaddnstr(1, k, sflt.c_str(), m_screenw - k - 1);
	
	k += sflt.size();
	m_filterstring_end_x = k;
}

void sinsp_cursesui::turn_search_on(search_caller_interface* ifc)
{
	ASSERT(m_spy_box != NULL);
	m_spy_box->get_offset(&m_search_start_x, &m_search_start_y);

	m_search_caller_interface = ifc;
	m_output_searching = false;
	m_output_filtering = false;
	m_cursor_pos = 0;
	curs_set(1);
	render();
}

void sinsp_cursesui::draw_bottom_menu(vector<sinsp_menuitem_info>* items, bool istable)
{
	uint32_t j = 0;
	uint32_t k = 0;

	//
	// Clear the line
	//
	move(m_screenh - 1, 0);
	for(uint32_t j = 0; j < m_screenw; j++)
	{
		addch(' ');
	}

	m_mouse_to_key_list.clear();

	for(j = 0; j < items->size(); j++)
	{
		if(istable && ((items->at(j).m_type & sinsp_menuitem_info::TABLE) == 0))
		{
			continue;
		}

		if((!istable) && ((items->at(j).m_type & sinsp_menuitem_info::LIST) == 0))
		{
			continue;
		}

		uint32_t startx = k;

		attrset(m_colors[PROCESS]);
		string fks = items->at(j).m_key;
		mvaddnstr(m_screenh - 1, k, fks.c_str(), MAX(fks.size(), 2));
		k += MAX(fks.size(), 2);

		attrset(m_colors[PANEL_HIGHLIGHT_FOCUS]);
		fks = items->at(j).m_desc;
		
		if(fks.size() < 6)
		{
			fks.resize(6, ' ');
		}
		
		mvaddnstr(m_screenh - 1, k, fks.c_str(), fks.size());
		k += fks.size();
		
		m_mouse_to_key_list.add(sinsp_mouse_to_key_list_entry(startx,
			m_screenh - 1,
			k - 1,
			m_screenh - 1,
			items->at(j).m_keyboard_equivalent));
	}
}

void sinsp_cursesui::render_default_main_menu()
{
	bool istable;

	if(m_datatable != NULL && m_datatable->m_type == sinsp_table::TT_TABLE)
	{
		istable = true;
	}
	else
	{
		istable = false;
	}

	draw_bottom_menu(&m_menuitems, istable);
}

void sinsp_cursesui::render_spy_main_menu()
{
	draw_bottom_menu(&m_menuitems_spybox, false);
}

void sinsp_cursesui::render_filtersearch_main_menu()
{
	uint32_t k = 0;
	string* str;

	//
	// Pick the right string based on what we're doing
	//
	if(m_output_filtering)
	{
		str = &m_complete_filter;

		if(*str == "" && m_is_filter_sysdig && m_complete_filter != "")
		{
			*str = m_complete_filter;
		}
	}
	else if(m_output_searching)
	{
		str = &m_manual_search_text;
	}
	else
	{
		if(m_search_caller_interface)
		{
			str = m_search_caller_interface->get_last_search_string();
		}
		else
		{
			ASSERT(false);
		}
	}

	//
	// Only clear the line if this is the first refresh, to prevent deleting the
	// text that the user is typing
	//
	if(m_cursor_pos == 0)
	{
		move(m_screenh - 1, 0);
		for(uint32_t j = 0; j < m_screenw; j++)
		{
			addch(' ');
		}
	}

	attrset(m_colors[PROCESS]);
	string fks = "F1";
	mvaddnstr(m_screenh - 1, k, fks.c_str(), 10);
	k += fks.size();
	attrset(m_colors[PANEL_HIGHLIGHT_FOCUS]);
	fks = "Help";
	fks.resize(6, ' ');
	mvaddnstr(m_screenh - 1, k, fks.c_str(), 6);
	k += 6;

	if(m_output_filtering)
	{
		attrset(m_colors[PROCESS]);
		fks = "F2";
		mvaddnstr(m_screenh - 1, k, fks.c_str(), 10);
		k += fks.size();
		attrset(m_colors[PANEL_HIGHLIGHT_FOCUS]);
		if(m_is_filter_sysdig)
		{
			fks = "Text";
		}
		else
		{
			fks = "sysdig";
		}
		fks.resize(6, ' ');
		mvaddnstr(m_screenh - 1, k, fks.c_str(), 6);
		k += 6;
	}

	attrset(m_colors[PROCESS]);
	fks = "Enter";
	mvaddnstr(m_screenh - 1, k, fks.c_str(), 10);
	k += fks.size();

	attrset(m_colors[PANEL_HIGHLIGHT_FOCUS]);
	fks = "Done";
	fks.resize(6, ' ');
	mvaddnstr(m_screenh - 1, k, fks.c_str(), 6);
	k += 6;

	attrset(m_colors[PROCESS]);
	fks = "Esc";
	mvaddnstr(m_screenh - 1, k, fks.c_str(), 10);
	k += fks.size();

	attrset(m_colors[PANEL_HIGHLIGHT_FOCUS]);
	fks = "Clear";
	fks.resize(6, ' ');
	mvaddnstr(m_screenh - 1, k, fks.c_str(), 6);
	k += 6;

	k++;
	attrset(m_colors[PANEL_HIGHLIGHT_FOCUS]);
	if(m_is_filter_sysdig)
	{
		fks = "Expression: ";
	}
	else
	{
		fks = "Text: ";
	}
	mvaddnstr(m_screenh - 1, k, fks.c_str(), 20);
	k += fks.size();

	uint32_t cursor_pos = k;

	if(m_cursor_pos == 0)
	{
		for(; k < m_screenw; k++)
		{
			addch(' ');
		}

		m_cursor_pos = cursor_pos;

		mvprintw(m_screenh - 1, m_cursor_pos, str->c_str());

		m_cursor_pos += str->size();
	}

	move(m_screenh - 1, m_cursor_pos);
}

void sinsp_cursesui::render_position_info()
{
	if(m_chart == NULL)
	{
		return;
	}

	int32_t pos;
	int32_t totlines;
	float percent;
	bool truncated;
	if(m_chart->get_position(&pos, &totlines, &percent, &truncated))
	{
		char prstr[128];
		string trs;
		uint32_t csize = 18;

		attrset(m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);

		move(m_screenh - 1, m_screenw - csize);
		for(uint32_t k = 0; k < csize; k++)
		{
			addch(' ');
		}

		if(truncated)
		{
			trs = "(truncated)";
		}

		if(percent != 0)
		{
			sprintf(prstr, "%d/%d(%.1f%%)%s", (int)pos, (int)totlines, percent * 100, trs.c_str());
		}
		else
		{
			sprintf(prstr, "%d/%d(0.0%%)%s", (int)pos, (int)totlines, trs.c_str());
		}

		mvaddstr(m_screenh - 1, 
			m_screenw - strlen(prstr),
			prstr);
	}
}

void sinsp_cursesui::render_main_menu()
{
	if(m_output_filtering || m_output_searching || m_search_caller_interface != NULL)
	{
		render_filtersearch_main_menu();
	}
	else if(m_spy_box != NULL)
	{
		render_spy_main_menu();
	}
	else
	{
		render_default_main_menu();
	}
}

void sinsp_cursesui::render()
{
	//
	// Draw the header at the top of the page
	//
	render_header();

	//
	// Print the position in the chart
	//
	if(m_output_filtering || m_output_searching || m_search_caller_interface != NULL)
	{
		render_position_info();
	}

	//
	// Draw the menu at the bottom of the screen
	//
	render_main_menu();

	//
	// If required, draw the side menu
	//
	if(m_sidemenu)
	{
		m_sidemenu->render();
	}

	//
	// Print the position in the chart
	//
	if(!(m_output_filtering || m_output_searching || m_search_caller_interface != NULL))
	{
		render_position_info();
	}
}
#endif

sinsp_view_info* sinsp_cursesui::get_selected_view()
{
	if(m_selected_view < 0)
	{
		return NULL;
	}

	ASSERT(m_selected_view < (int32_t)m_views.size());
	return m_views.at(m_selected_view);
}

#ifndef NOCURSESUI
void sinsp_cursesui::populate_sidemenu(string field, vector<sidemenu_list_entry>* viewlist)
{
	uint32_t k = 0;

	viewlist->clear();

	for(uint32_t j = 0; j < m_views.size(); ++j)
	{
		auto it = m_views.at(j);

		for(auto atit = it->m_applies_to.begin(); atit != it->m_applies_to.end(); ++atit)
		{
			if(*atit == field)
			{
				viewlist->push_back(sidemenu_list_entry(it->m_name, j));

				if(it->m_name == m_views.at(m_selected_view)->m_name)
				{
					m_selected_sidemenu_entry = k;

					if(m_sidemenu != NULL)
					{
						m_sidemenu->m_selct = k;
					}
				}

				k++;
			}
		}
	}

	if(m_sidemenu != NULL)
	{
		m_sidemenu->set_entries(viewlist);
	}
}
#endif // NOCURSESUI

string combine_filters(string flt1, string flt2)
{
	if(flt1 == "")
	{
		return flt2;
	}
	else
	{
		if(flt2 == "")
		{
			return flt1;
		}
	}

	string res = "(" + flt1 + ") and (" + flt2 + ")";
	return res;
}

void sinsp_cursesui::handle_end_of_sample(sinsp_evt* evt, int32_t next_res)
{
	m_datatable->flush(evt);

	//
	// It's time to refresh the data for this chart.
	// First of all, create the data for the chart
	//
	vector<sinsp_sample_row>* sample = 
		m_datatable->get_sample();

#ifndef NOCURSESUI
	//
	// If the help page has been shown, don't update the screen
	//
	if(m_viewinfo_page != NULL || m_mainhelp_page != NULL)
	{
		return;
	}

	//
	// Now refresh the UI.
	//
	if(m_viz)
	{
		m_viz->update_data(sample);

		if(m_datatable->m_type == sinsp_table::TT_LIST && m_inspector->is_live())
		{
			m_viz->follow_end();
		}

		m_viz->render(true);
	}

	render();

#endif
	//
	// If this is a trace file, check if we reached the end of the file.
	// Or, if we are in replay mode, wait for a key press before processing
	// the next sample.
	//
	if(!m_inspector->is_live())
	{
#ifndef NOCURSESUI
		if(m_offline_replay)
		{
			while(getch() != ' ')
			{
				usleep(10000);
			}
		}
#endif
	}
}

void sinsp_cursesui::restart_capture(bool is_spy_switch)
{
	m_inspector->close();
	start(true, is_spy_switch);
	m_inspector->open(m_event_source_name);
}

void sinsp_cursesui::create_complete_filter()
{
	if(m_is_filter_sysdig && m_manual_filter != "")
	{
		m_complete_filter = m_manual_filter;
	}
	else
	{
		m_complete_filter = m_cmdline_capture_filter;

		m_complete_filter = combine_filters(m_complete_filter, m_sel_hierarchy.tofilter());

		//
		// Note: m_selected_view is smaller than 0 when there's no view, because we're doing
		//       non-view stuff like spying.
		//
		if(m_selected_view >= 0)
		{
			m_complete_filter = combine_filters(m_complete_filter, 
				m_views.at(m_selected_view)->m_filter);
		}
	}
}

void sinsp_cursesui::switch_view(bool is_spy_switch)
{
	string field;

	if(m_sel_hierarchy.m_hierarchy.size() > 0)
	{
		sinsp_ui_selection_info* psinfo = &m_sel_hierarchy.m_hierarchy[m_sel_hierarchy.m_hierarchy.size() - 1];
		field = psinfo->m_field;
	}

#ifndef NOCURSESUI
	//
	// Clear the screen to make sure all the crap is removed
	//
	clear();

	//
	// If we're currently visualizing the spy box, reset it and return immediately
	//
	if(is_spy_switch)
	{
		if(m_spy_box)
		{
			m_spy_box->reset();
		}
	}
#endif

	//
	// If this is a file, we need to restart the capture.
	// If it's a live capture, we restart only if start() fails, which usually
	// happens in case one of the filter fields requested thread state.
	//
	if(!m_inspector->is_live())
	{
		m_eof = 0;
		m_last_progress_evt = 0;
		restart_capture(is_spy_switch);
	}
	else
	{
		try
		{
			start(true, is_spy_switch);
		}
		catch(...)
		{
			restart_capture(is_spy_switch);
		}
	}

#ifndef NOCURSESUI
	delete m_sidemenu;
	m_sidemenu = NULL;

	if(m_viz != NULL)
	{
		m_viz->render(true);
	}

	render();
#endif
}

void sinsp_cursesui::spy_selection(string field, string val, bool is_dig)
{
	//
	// Perform the drill down
	//
#ifndef NOCURSESUI
	sinsp_table_field* rowkey = m_datatable->get_row_key(m_viz->m_selct);
#else
	sinsp_table_field* rowkey = NULL;
#endif
	sinsp_table_field rowkeybak;
	if(rowkey != NULL)
	{
		rowkeybak.m_val = new uint8_t[rowkey->m_len];
		memcpy(rowkeybak.m_val, rowkey->m_val, rowkey->m_len);
		rowkeybak.m_len = rowkey->m_len;
	}

	uint32_t srtcol;
	srtcol = m_datatable->get_sorting_col();

	m_sel_hierarchy.push_back(field, val, 
		m_selected_view, m_selected_sidemenu_entry, 
		&rowkeybak, srtcol);

	if(is_dig)
	{
		m_selected_view = VIEW_ID_DIG;
	}
	else
	{
		m_selected_view = VIEW_ID_SPY;
	}

	if(!m_inspector->is_live())
	{
		m_eof = 0;
		m_last_progress_evt = 0;
		restart_capture(false);
	}
	else
	{
		try
		{
			start(true, false);
		}
		catch(...)
		{
			restart_capture(false);
		}
	}

#ifndef NOCURSESUI
	render();
#endif
}

// returns false if there is no suitable drill down view for this field
bool sinsp_cursesui::do_drilldown(string field, string val, uint32_t new_view_num)
{
#ifndef NOCURSESUI
	sinsp_table_field* rowkey = m_datatable->get_row_key(m_viz->m_selct);
#else
	sinsp_table_field* rowkey = NULL;
#endif
	sinsp_table_field rowkeybak;
	if(rowkey != NULL)
	{
		rowkeybak.m_val = new uint8_t[rowkey->m_len];
		memcpy(rowkeybak.m_val, rowkey->m_val, rowkey->m_len);
		rowkeybak.m_len = rowkey->m_len;
	}

	uint32_t srtcol;
	srtcol = m_datatable->get_sorting_col();

	m_sel_hierarchy.push_back(field, val, 
		m_selected_view, m_selected_sidemenu_entry, 
		&rowkeybak, srtcol);
	m_selected_view = new_view_num;

	if(!m_inspector->is_live())
	{
		m_eof = 0;
		m_last_progress_evt = 0;
		restart_capture(false);
	}
	else
	{
		try
		{
			start(true, false);
		}
		catch(...)
		{
			restart_capture(false);
		}
	}

#ifndef NOCURSESUI
	clear();
	populate_sidemenu(field, &m_sidemenu_viewlist);
//	m_selected_sidemenu_entry = 0;
	m_viz->render(true);
	render();
#endif

	m_manual_filter = "";

	return true;
}

// returns false if there is no suitable drill down view for this field
bool sinsp_cursesui::drilldown(string field, string val)
{
	uint32_t j = 0;

	for(j = 0; j < m_views.size(); ++j)
	{
		if(m_views.at(j)->m_id == m_views.at(m_selected_view)->m_drilldown_target)
		{
			return do_drilldown(field, val, j);			
		}
	}

	for(j = 0; j < m_views.size(); ++j)
	{
		auto it = m_views.at(j);

		for(auto atit = it->m_applies_to.begin(); atit != it->m_applies_to.end(); ++atit)
		{
			if(*atit == field)
			{
				return do_drilldown(field, val, j);
			}
		}
	}

	return false;
}

bool sinsp_cursesui::drillup()
{
	if(m_sel_hierarchy.m_hierarchy.size() > 0)
	{
		string field;
		sinsp_ui_selection_info* sinfo = &m_sel_hierarchy.m_hierarchy[m_sel_hierarchy.m_hierarchy.size() - 1];

		m_manual_filter = "";

		if(m_sel_hierarchy.m_hierarchy.size() > 1)
		{
			sinsp_ui_selection_info* psinfo = &m_sel_hierarchy.m_hierarchy[m_sel_hierarchy.m_hierarchy.size() - 2];
			field = psinfo->m_field;
		}

		sinsp_table_field rowkey = sinfo->m_rowkey;

		m_selected_view = sinfo->m_prev_selected_view;
		m_selected_sidemenu_entry = sinfo->m_prev_selected_sidemenu_entry;
		ASSERT(m_selected_view < (int32_t)m_views.size());
		m_sel_hierarchy.m_hierarchy.pop_back();
		//m_views[m_selected_view].m_filter = m_sel_hierarchy.tofilter();

		if(!m_inspector->is_live())
		{
			m_eof = 0;
			m_last_progress_evt = 0;
			restart_capture(false);
		}
		else
		{
			try
			{
				start(true, false);
			}
			catch(...)
			{
				restart_capture(false);
			}
		}
#ifndef NOCURSESUI
		if(rowkey.m_val != NULL)
		{
			m_viz->m_last_key.copy(&rowkey);
			m_viz->m_last_key.m_isvalid = true;
			m_viz->m_selection_changed = true;
		}
		else
		{
			m_viz->m_last_key.m_isvalid = false;
		}

		m_viz->m_drilled_up = true;
		populate_sidemenu(field, &m_sidemenu_viewlist);

		//
		// If sorting is different from the default one, restore it
		//
		if(sinfo->m_prev_sorting_col != m_views.at(m_selected_view)->m_sortingcol)
		{
			m_datatable->set_sorting_col(sinfo->m_prev_sorting_col);
		}

		clear();
		m_viz->render(true);

		render();
#endif

		delete[] rowkey.m_val;
		return true;
	}

	return false;
}

void sinsp_cursesui::pause()
{
	m_paused = !m_paused;
	m_datatable->set_paused(m_paused);
#ifndef NOCURSESUI
	render_header();
#endif
}

#ifndef NOCURSESUI
void sinsp_cursesui::print_progress(double progress)
{
	attrset(m_colors[sinsp_cursesui::PROCESS]);

	string wstr = "Processing File";
	mvprintw(m_screenh / 2,
		m_screenw / 2 - wstr.size() / 2, 
		wstr.c_str());	

	//
	// Using sprintf because to_string doesn't support setting the precision 
	//
	char numbuf[64];
	sprintf(numbuf, "%.2lf", progress);
	wstr = "Progress: " + string(numbuf);
	mvprintw(m_screenh / 2 + 1,
		m_screenw / 2 - wstr.size() / 2, 
		wstr.c_str());

	refresh();
}

sysdig_table_action sinsp_cursesui::handle_textbox_input(int ch)
{
	bool closing = false;
	string* str = NULL;
	bool handled = true;

	//
	// Pick the right string based on what we're doing
	//
	if(m_output_filtering)
	{
		str = &m_manual_filter;
	}
	else if(m_output_searching)
	{
		str = &m_manual_search_text;
	}
	else
	{
		if(m_search_caller_interface)
		{
			str = m_search_caller_interface->get_last_search_string();
		}
		else
		{
			ASSERT(false);
		}
	}

	switch(ch)
	{
		case KEY_F(2):
			m_is_filter_sysdig = !m_is_filter_sysdig;
			*str = "";
			m_cursor_pos = 0;
			render();
			return STA_NONE;
		case KEY_DOWN:
		case KEY_UP:
		case KEY_PPAGE:
		case KEY_NPAGE:
			if(m_spy_box != NULL)
			{
				m_spy_box->handle_input(ch);
			}
			else
			{
				m_viz->handle_input(ch);
			}
			return STA_NONE;
		case 27: // ESC
			*str = "";

			if(m_spy_box != NULL)
			{
				m_spy_box->scroll_to(m_search_start_x, m_search_start_y);
				m_spy_box->up();
			}
			// FALL THROUGH
		case '\n':
		case '\r':
		case KEY_ENTER:
		case 6:	// CTRL+F
		case KEY_F(4):
			closing = true;
			curs_set(0);

			if(m_is_filter_sysdig)
			{
				if(*str != "")
				{
					sinsp_filter* f;

					try
					{
						f = new sinsp_filter(m_inspector, *str);
					}
					catch(sinsp_exception e)
					{
						//
						// Backup the cursor position
						//
						int cx, cy;
						getyx(stdscr, cy, cx);

						//
						// Print the error string
						//
						string wstr = "Invalid sysdig filter";

						attrset(m_colors[sinsp_cursesui::FAILED_SEARCH]);
						mvprintw(m_screenh / 2,
							m_screenw / 2 - wstr.size() / 2, 
							wstr.c_str());	

						//
						// Restore the cursor
						//
						attrset(m_colors[PANEL_HIGHLIGHT_FOCUS]);
						move(cy, cx);
						curs_set(1);
//						*str = "";
						closing = false;
						break;
					}

					delete f;
				}
			}

			break;
		case KEY_BACKSPACE:
			if(str->size() > 0)
			{
				m_cursor_pos--;
				move(m_screenh - 1, m_cursor_pos);
				addch(' ');
				move(m_screenh - 1, m_cursor_pos);
				str->pop_back();

				if(str->size() < 2)
				{
					if(m_spy_box != NULL)
					{
						m_spy_box->scroll_to(m_search_start_x, m_search_start_y); 
					}
				}

				break;
			}
			else
			{
				return STA_NONE;
			}
		case KEY_F(3):
			if(m_search_caller_interface)
			{
				if(m_search_caller_interface->on_search_next())
				{
					render();
				}
				else
				{
					string wstr = "  NOT FOUND ";
					attrset(m_colors[sinsp_cursesui::FAILED_SEARCH]);

					mvprintw(m_screenh / 2,
						m_screenw / 2 - wstr.size() / 2, 
						wstr.c_str());

					render();
				}
			}

			break;
		default:
			handled = false;
			break;
	}

	if(ch >= ' ' && ch <= '~')
	{
		addch(ch);
		*str += ch;
		m_cursor_pos++;
	}
	else
	{
		if(!handled)
		{
			return STA_NONE;
		}
	}

	if(m_output_filtering)
	{
		if(!m_is_filter_sysdig)
		{
			//
			// Update the filter in the datatable
			//
			m_datatable->set_freetext_filter(*str);

			//
			// Refresh the data and the visualization
			//
			m_viz->update_data(m_datatable->get_sample());
			m_viz->render(true);
		}
	}
	else if(m_output_searching)
	{
		sinsp_table_field* skey = m_datatable->search_in_sample(*str);

		if(skey != NULL)
		{
			int32_t selct = m_datatable->get_row_from_key(skey);
			m_viz->goto_row(selct);
			m_search_nomatch = false;
		}
		else
		{
			m_search_nomatch = true;
			m_viz->render(true);
		}
	}
	else
	{
		if(m_search_caller_interface)
		{
			if(m_search_caller_interface->on_search_key_pressed(*str))
			{
				render();
			}
			else
			{
				string wstr = "  NOT FOUND ";
				attrset(m_colors[sinsp_cursesui::FAILED_SEARCH]);

				mvprintw(m_screenh / 2,
					m_screenw / 2 - wstr.size() / 2, 
					wstr.c_str());

				render();
			}

			render();
		}
		else
		{
			ASSERT(false);
		}
	}

	if(closing)
	{
		m_search_nomatch = false;
		m_output_filtering = false;
		m_output_searching = false;
		m_search_caller_interface = NULL;
		render();

		if(m_is_filter_sysdig)
		{
			return STA_SWITCH_VIEW;
		}
	}

	return STA_NONE;
}

sysdig_table_action sinsp_cursesui::handle_input(int ch)
{
	//
	// Avoid parsing keys during file load
	//
	if((!m_inspector->is_live()) && !is_eof())
	{
		if(ch != KEY_BACKSPACE && 
			ch != 'q' &&
			ch != KEY_F(10))
		{
			return STA_NONE;
		}
	}

	if(m_mainhelp_page != NULL)
	{
		sysdig_table_action actn = m_mainhelp_page->handle_input(ch);

		if(actn == STA_DESTROY_CHILD)
		{
			delete m_mainhelp_page;
			m_mainhelp_page = NULL;

			if(m_spy_box)
			{
				m_spy_box->render();
			}

			if(m_viz != NULL)
			{
				m_viz->render(true);
			}

			if(m_viewinfo_page)
			{
				m_viewinfo_page->render();
			}

			render();
			return STA_NONE;
		}

		return actn;
	}

	if(m_sidemenu)
	{
		sysdig_table_action ta = m_sidemenu->handle_input(ch);
		if(ta == STA_SWITCH_VIEW)
		{
			if(m_viewinfo_page)
			{
				delete m_viewinfo_page;
				m_viewinfo_page = NULL;
			}

			return ta;
		}
		else if(ta != STA_PARENT_HANDLE)
		{
			return STA_NONE;
		}
	}

	if(m_output_filtering || m_output_searching || m_search_caller_interface != NULL)
	{
		ASSERT(m_sidemenu == NULL);
		return handle_textbox_input(ch);
	}

	if(m_spy_box != NULL)
	{
		ASSERT(m_sidemenu == NULL);
		ASSERT(m_output_filtering == false);
		ASSERT(m_output_searching == false);
		sysdig_table_action actn = m_spy_box->handle_input(ch);
		if(actn != STA_PARENT_HANDLE)
		{
			return actn;
		}
	}

	//
	// Note: the info page doesn't handle input when the sidemenu is on, because in that
	//       case it's just going to passively show the info for the selected view
	//
	if(m_viewinfo_page && m_sidemenu == NULL)
	{
		sysdig_table_action actn = m_viewinfo_page->handle_input(ch);

		if(actn == STA_DESTROY_CHILD)
		{
			delete m_viewinfo_page;
			m_viewinfo_page = NULL;
			if(m_viz != NULL)
			{
				m_viz->render(true);
			}

			render();
			return STA_NONE;
		}

		return actn;
	}

	//
	// Pass the event to the table viz
	//
	if(m_viz)
	{
		sysdig_table_action actn = m_viz->handle_input(ch);
		if(actn != STA_PARENT_HANDLE)
		{
			return actn;
		}
	}

	switch(ch)
	{
		case '?':
		case 'h':
		case KEY_F(1):
			m_mainhelp_page = new curses_mainhelp_page(this);
			break;
		case KEY_F(10):
		case 'q':
			return STA_QUIT;
		case 'p':
			pause();
			break;
		case KEY_F(2):
			if(m_sidemenu == NULL)
			{
				m_viz->set_x_start(SIDEMENU_WIDTH);
				m_sidemenu = new curses_table_sidemenu(this);
				m_sidemenu->set_entries(&m_sidemenu_viewlist);
				m_sidemenu->m_selct = m_selected_sidemenu_entry;
				m_sidemenu->set_title("Select View");

				render();

				m_viewinfo_page = new curses_viewinfo_page(this, 
					m_selected_view,
					TABLE_Y_START,
					SIDEMENU_WIDTH,
					m_screenh - TABLE_Y_START - 1,
					m_screenw - SIDEMENU_WIDTH);
			}
			else
			{
				if(m_viewinfo_page)
				{
					delete m_viewinfo_page;
					m_viewinfo_page = NULL;
				}

				m_viz->set_x_start(0);
				delete m_sidemenu;
				m_sidemenu = NULL;
				m_viz->recreate_win();
				render();
			}

			break;
		case '/':
		case 6:	// CTRL+F
			m_search_caller_interface = NULL;
			m_output_searching = true;
			//m_manual_search_text = "";
			m_cursor_pos = 0;
			curs_set(1);
			render();
			break;
		//case KEY_F(3):
		//	break;
		case '\\':
		case KEY_F(4):
			m_search_caller_interface = NULL;
			m_output_filtering = true;
			m_cursor_pos = 0;
			curs_set(1);
			render();
			break;
		case KEY_F(5):
		case 'e':
			if(m_datatable == NULL)
			{
				//
				// No F5 for non table displays
				//
				return STA_NONE;
			}
			else if(m_datatable->m_type == sinsp_table::TT_LIST)
			{
				//
				// No F5 for list tables
				//
				return STA_NONE;
			}

			if(m_datatable->m_sample_data != NULL && m_datatable->m_sample_data->size() != 0)
			{
				m_selected_sidemenu_entry = 0;
				return STA_SPY;
			}
			break;
		case KEY_F(6):
		case 'd':
			if(m_datatable == NULL)
			{
				//
				// No F5 for non table displays
				//
				return STA_NONE;
			}
			else if(m_datatable->m_type == sinsp_table::TT_LIST)
			{
				//
				// No F5 for list tables
				//
				return STA_NONE;
			}

			if(m_datatable->m_sample_data != NULL && m_datatable->m_sample_data->size() != 0)
			{
				m_selected_sidemenu_entry = 0;
				return STA_DIG;
			}

			break;
		case KEY_F(7):
			m_viewinfo_page = new curses_viewinfo_page(this,
				m_selected_view,
				0,
				0,
				m_screenh,
				m_screenw);
			break;
		case KEY_RESIZE:
			getmaxyx(stdscr, m_screenh, m_screenw);
			
			render();

			if(m_spy_box)
			{
				m_spy_box->render();
				m_spy_box->render();
			}

			if(m_viz != NULL)
			{
				m_viz->render(true);
				m_viz->render(true);
			}

			if(m_viewinfo_page)
			{
				m_viewinfo_page->render();
				m_viewinfo_page->render();
			}

			render();

			break;
		case KEY_MOUSE:
			{
				MEVENT* event;

				if(m_sidemenu != NULL)
				{
					event = &m_sidemenu->m_last_mevent;
				}
				else if(m_spy_box != NULL)
				{
					event = &m_spy_box->m_last_mevent;
				}
				else if(m_viz != NULL)
				{
					event = &m_viz->m_last_mevent;
				}

				if(event->bstate & BUTTON1_CLICKED ||
					event->bstate & BUTTON1_DOUBLE_CLICKED)
				{
					if((uint32_t)event->y == m_screenh - 1)
					{
						int keyc = m_mouse_to_key_list.get_key_from_coordinates(event->x, event->y);
						if(keyc != -1)
						{
							return handle_input(keyc);
						}
					}
					else if((uint32_t)event->y == 1 &&
						(uint32_t)event->x >= m_filterstring_start_x &&
						(uint32_t)event->x <= m_filterstring_end_x)
					{
						m_search_caller_interface = NULL;
						m_is_filter_sysdig = true;
						m_output_filtering = true;
						m_manual_filter = m_complete_filter;
						m_cursor_pos = 0;
						curs_set(1);
						render();
					}
				}
			}

			break;
		default:
			break;
	}

	return STA_NONE;
}

#endif // NOCURSESUI
