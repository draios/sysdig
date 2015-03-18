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
// sinsp_view_info implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_view_info::sinsp_view_info(string name,
	vector<sinsp_table_entry>* entries,
	string applyto,
	string merge_config,
	string filter,
	bool use_defaults)
{
	m_name = name;
	
	if(entries == NULL)
	{
		ASSERT(false);
		throw sinsp_exception("invalid view definition, entries=NULL");
	}
	m_entries = *entries;

	m_use_defaults = use_defaults;
		
	if(applyto != "")
	{
		char *p = strtok((char*)applyto.c_str(), ",");
		while (p) 
		{
			string ts(p);
			trim(ts);

			if(ts == "all")
			{
				m_applyto.push_back("");
			}
			else
			{
				m_applyto.push_back(ts);
			}

			p = strtok(NULL, ",");
		}
	}
	else
	{
		m_applyto.push_back("");
	}

	//
	// Determine the sorting column
	//
	uint32_t n_sorting_cols = 0;

	for(uint32_t j = 0; j < entries->size(); j++)
	{
		if((entries->at(j).m_flags & TEF_SORTBY) != 0)
		{
			m_sortingcol = j;
			n_sorting_cols++;
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
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_cursesui implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_cursesui::sinsp_cursesui(sinsp* inspector, 
							   string event_source_name, 
							   string cmdline_capture_filter)
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
#ifndef NOCURSESUI
	m_sidemenu = NULL;
	m_spy_box = NULL;

	//
	// Colors initialization
	//
	m_colors[RESET_COLOR] = ColorPair( COLOR_WHITE,COLOR_BLACK);
	m_colors[DEFAULT_COLOR] = ColorPair( COLOR_WHITE,COLOR_BLACK);
	m_colors[FUNCTION_BAR] = ColorPair(COLOR_BLACK,COLOR_CYAN);
	m_colors[FUNCTION_KEY] = ColorPair( COLOR_WHITE,COLOR_BLACK);
	m_colors[PANEL_HEADER_FOCUS] = ColorPair(COLOR_BLACK,COLOR_GREEN);
	m_colors[PANEL_HEADER_UNFOCUS] = ColorPair(COLOR_BLACK,COLOR_GREEN);
	m_colors[PANEL_HIGHLIGHT_FOCUS] = ColorPair(COLOR_BLACK,COLOR_CYAN);
	m_colors[PANEL_HIGHLIGHT_UNFOCUS] = ColorPair(COLOR_BLACK, COLOR_WHITE);
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
	m_menuitems.push_back("Help");
	m_menuitems.push_back("Views");
	m_menuitems.push_back("Search");
	m_menuitems.push_back("Filter");
	m_menuitems.push_back("Spy IO");
	m_menuitems.push_back("Dig");
	m_menuitems.push_back("Legend");

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
#endif
}

void sinsp_cursesui::configure(vector<sinsp_view_info>* views)
{
	if(views == NULL)
	{
		ASSERT(false);
		throw sinsp_exception("trying to configure the command line UI with no views");
	}

	m_views = *views;
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
	}

	if(m_spy_box && !is_spy_switch)
	{
		delete m_spy_box;
		m_spy_box = NULL;
	}
#endif

	//
	// Update the filter based on what's selected
	//
	create_complete_filter();

	//
	// If we need a new datatable, allocate it and set it up
	//
	if(m_selected_view >= 0)
	{
		m_datatable = new sinsp_table(m_inspector);

		try
		{
			m_datatable->configure(&m_views[m_selected_view].m_entries, 
				m_complete_filter,
				m_views[m_selected_view].m_use_defaults);
		}
		catch(...)
		{
			delete m_datatable;
			m_datatable = NULL;
			throw;
		}

		m_datatable->set_sorting_col(m_views[m_selected_view].m_sortingcol);
	}
#ifndef NOCURSESUI
	else
	{
		//
		// Create the visualization component
		//
		m_spy_box = new curses_textbox(m_inspector, this, m_selected_view);
		m_spy_box->set_filter(m_complete_filter);
	}

	//
	// If we need a table visualization, allocate it and set it up
	//
	if(m_selected_view >= 0)
	{
		m_viz = new curses_table(this, m_inspector);

		vector<int32_t> colsizes;
		vector<string> colnames;

		for(auto fit : m_views[m_selected_view].m_entries)
		{
			colsizes.push_back(fit.m_colsize);
			colnames.push_back(fit.m_name);
		}

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

	attrset(m_colors[PROCESS]);
	move(0, 0);
	for(j = 0; j < m_screenw; j++)
	{
		addch(' ');
	}

	mvaddstr(0, 0, "Viewing:");

	attrset(m_colors[PROCESS]);

	string vs;

	if(m_selected_view >= 0)
	{
		sinsp_view_info* sv = get_selected_view();
		const char* vcs = sv->m_name.c_str();
		vs = vcs;
		vs += " for ";
	}
	else
	{
		if(m_selected_view == VIEW_ID_SPY)
		{
			vs = "I/O activity for ";
		}
		else if(m_selected_view == VIEW_ID_DIG)
		{
			vs = "sysdig output for ";
		}
		else
		{
			ASSERT(false);
		}
	}

	if(m_sel_hierarchy.m_hierarchy.size() != 0)
	{
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

	attrset(m_colors[PROCESS]);
	mvaddstr(1, 0, "Filter:");
	uint32_t k = sizeof("Filter: ") - 1;

	if(m_complete_filter != "")
	{
		mvaddstr(1, k, m_complete_filter.c_str());
	}
	else
	{
		mvaddstr(1, k, "none");		
	}
}

void sinsp_cursesui::render_default_main_menu()
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

	for(j = 0; j < m_menuitems.size(); j++)
	{
		attrset(m_colors[PROCESS]);
		string fks = string("F") + to_string(j + 1);
		mvaddnstr(m_screenh - 1, k, fks.c_str(), 2);
		k += 2;

		attrset(m_colors[PANEL_HIGHLIGHT_FOCUS]);
		fks = m_menuitems[j];
		fks.resize(6, ' ');
		mvaddnstr(m_screenh - 1, k, fks.c_str(), 6);
		k += 6;
	}
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
		str = &m_manual_filter;
	}
	else if(m_output_searching)
	{
		str = &m_manual_search_text;
	}
	else
	{
		ASSERT(false);
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

void sinsp_cursesui::render_spy_main_menu()
{
	uint32_t k = 0;

	//
	// Clear the line
	//
	move(m_screenh - 1, 0);
	for(uint32_t j = 0; j < m_screenw; j++)
	{
		addch(' ');
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

	attrset(m_colors[PROCESS]);
	fks = "F2";
	mvaddnstr(m_screenh - 1, k, fks.c_str(), 10);
	k += fks.size();
	attrset(m_colors[PANEL_HIGHLIGHT_FOCUS]);
	fks = "View As";
	fks.resize(7, ' ');
	mvaddnstr(m_screenh - 1, k, fks.c_str(), 7);
	k += 7;

	attrset(m_colors[PROCESS]);
	fks = "P ";
	mvaddnstr(m_screenh - 1, k, fks.c_str(), 10);
	k += fks.size();
	attrset(m_colors[PANEL_HIGHLIGHT_FOCUS]);
	if(true)
	{
		fks = "Pause";
	}
	else
	{
		fks = "Resume";
	}
	fks.resize(6, ' ');
	mvaddnstr(m_screenh - 1, k, fks.c_str(), 6);
	k += 6;

	attrset(m_colors[PROCESS]);
	fks = "Bak";
	mvaddnstr(m_screenh - 1, k, fks.c_str(), 10);
	k += fks.size();
	attrset(m_colors[PANEL_HIGHLIGHT_FOCUS]);
	fks = "Exit";
	fks.resize(6, ' ');
	mvaddnstr(m_screenh - 1, k, fks.c_str(), 6);
	k += 6;

	attrset(m_colors[PROCESS]);
	fks = "Del";
	mvaddnstr(m_screenh - 1, k, fks.c_str(), 10);
	k += fks.size();

	attrset(m_colors[PANEL_HIGHLIGHT_FOCUS]);
	fks = "Clear";
	fks.resize(6, ' ');
	mvaddnstr(m_screenh - 1, k, fks.c_str(), 6);
	k += 6;
}

void sinsp_cursesui::render_main_menu()
{
	if(m_output_filtering || m_output_searching)
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
}
#endif

sinsp_view_info* sinsp_cursesui::get_selected_view()
{
	if(m_selected_view < 0)
	{
		return NULL;
	}

	ASSERT(m_selected_view < (int32_t)m_views.size());
	return &m_views[m_selected_view];
}

#ifndef NOCURSESUI
void sinsp_cursesui::populate_sidemenu(string field, vector<sidemenu_list_entry>* viewlist)
{
	uint32_t j = 0;

	viewlist->clear();

	for(auto it = m_views.begin(); it != m_views.end(); ++it)
	{
		for(auto atit = it->m_applyto.begin(); atit != it->m_applyto.end(); ++atit)
		{
			if(*atit == field)
			{
				viewlist->push_back(sidemenu_list_entry(it->m_name, j));
			}
		}

		j++;
	}

	if(m_sidemenu)
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
	// First of all, render the chart
	//
	vector<sinsp_sample_row>* sample = 
		m_datatable->get_sample();

#ifndef NOCURSESUI
	//
	// Now refresh the UI.
	//
	if(m_viz)
	{
		m_viz->update_data(sample);
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
	m_complete_filter = m_cmdline_capture_filter;

	if(m_is_filter_sysdig)
	{
		m_complete_filter = combine_filters(m_complete_filter, m_manual_filter);
	}

	m_complete_filter = combine_filters(m_complete_filter, m_sel_hierarchy.tofilter());

	//
	// Note: m_selected_view is smaller than 0 when there's no view, because we're doing
	//       non-view stuff like spying.
	//
	if(m_selected_view >= 0)
	{
		m_complete_filter = combine_filters(m_complete_filter, m_views[m_selected_view].m_filter);
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
		restart_capture(true);
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
	// XXX should this be removed?
	populate_sidemenu(field, &m_sidemenu_viewlist);

	delete m_sidemenu;
	m_sidemenu = NULL;

	m_viz->render(true);
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

	m_sel_hierarchy.push_back(field, val, 
		m_selected_view, m_selected_sidemenu_entry, 
		&rowkeybak, m_datatable->get_sorting_col());

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
bool sinsp_cursesui::drilldown(string field, string val)
{
	uint32_t j = 0;

	for(auto it = m_views.begin(); it != m_views.end(); ++it)
	{
		for(auto atit = it->m_applyto.begin(); atit != it->m_applyto.end(); ++atit)
		{
			if(*atit == field)
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

				m_sel_hierarchy.push_back(field, val, 
					m_selected_view, m_selected_sidemenu_entry, 
					&rowkeybak, m_datatable->get_sorting_col());
				m_selected_view = j;

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
				m_selected_sidemenu_entry = 0;
				m_viz->render(true);
				render();
#endif

				return true;
			}
		}

		j++;
	}

	return false;
}

bool sinsp_cursesui::drillup()
{
	if(m_sel_hierarchy.m_hierarchy.size() > 0)
	{
		string field;
		sinsp_ui_selection_info* sinfo = &m_sel_hierarchy.m_hierarchy[m_sel_hierarchy.m_hierarchy.size() - 1];

		if(m_sel_hierarchy.m_hierarchy.size() > 1)
		{
			sinsp_ui_selection_info* psinfo = &m_sel_hierarchy.m_hierarchy[m_sel_hierarchy.m_hierarchy.size() - 2];
			field = psinfo->m_field;
		}
		
//		field = sinfo->m_field;

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
		if(sinfo->m_prev_sorting_col != m_views[m_selected_view].m_sortingcol)
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
	string* str;

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
		ASSERT(false);
	}

	switch(ch)
	{
		case KEY_F(2):
			m_is_filter_sysdig = !m_is_filter_sysdig;
			*str = "";
			m_cursor_pos = 0;
			render();
			return STA_NONE;
		case 27: // ESC
			*str = "";
			// FALL THROUGH
		case '\n':
		case '\r':
		case KEY_ENTER:
		case KEY_F(4):
			closing = true;
			curs_set(0);
			render();

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
						string wstr = "Invalid sysdig filter";

						attrset(m_colors[sinsp_cursesui::FAILED_SEARCH]);
						mvprintw(m_screenh / 2,
							m_screenw / 2 - wstr.size() / 2, 
							wstr.c_str());	

						*str = "";
						break;
					}

					delete f;
				}

				return STA_SWITCH_VIEW;
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
				break;
			}
			else
			{
				return STA_NONE;
			}
	}

	if(ch >= ' ' && ch <= '~')
	{
		addch(ch);
		*str += ch;
		m_cursor_pos++;
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
		ASSERT(false);
	}

	if(closing)
	{
		m_search_nomatch = false;
		m_output_filtering = false;
		m_output_searching = false;
		render();
	}

	return STA_NONE;
}

sysdig_table_action sinsp_cursesui::handle_input(int ch)
{
	if(m_sidemenu)
	{
		sysdig_table_action ta = m_sidemenu->handle_input(ch);
		if(ta == STA_SWITCH_VIEW)
		{
			return ta;
		}
		else if(ta != STA_PARENT_HANDLE)
		{
			return STA_NONE;
		}
	}

	if(m_output_filtering || m_output_searching)
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
	// Pass the event to the table viz
	//
	sysdig_table_action actn = m_viz->handle_input(ch);
	if(actn != STA_PARENT_HANDLE)
	{
		return actn;
	}

	switch(ch)
	{
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
				m_sidemenu->set_title("Select View");
			}
			else
			{
				m_viz->set_x_start(0);
				delete m_sidemenu;
				m_sidemenu = NULL;
			}

			m_viz->recreate_win();
			render();
			break;
		case KEY_F(3):
			m_output_searching = true;
			m_manual_search_text = "";
			m_cursor_pos = 0;
			curs_set(1);
			render();
			break;
		case KEY_F(4):
			m_output_filtering = true;
			m_cursor_pos = 0;
			curs_set(1);
			render();
			break;
		case KEY_F(5):
			return STA_SPY;
			break;
		case KEY_F(6):
			return STA_DIG;
			break;
		default:
		break;
	}

	return STA_NONE;
}

#endif // NOCURSESUI
