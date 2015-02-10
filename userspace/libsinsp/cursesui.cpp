#include "sinsp.h"
#include "sinsp_int.h"
#include "../../driver/ppm_ringbuffer.h"
#include "filter.h"
#include "filterchecks.h"

#ifndef _WIN32
#include <curses.h>
#endif
#include "table.h"
#include "cursestable.h"
#include "cursesui.h"

#ifndef NOCURSESUI
#define ColorPair(i,j) COLOR_PAIR((7-i)*8+j)
#endif

///////////////////////////////////////////////////////////////////////////////
// sinsp_table_info implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_table_info::sinsp_table_info(string name, 
	string config,
	string applyto,
	uint32_t sortingcol, 
	string merge_config, 
	string colnames, 
	string colsizes, 
	string filter)
{
	m_name = name;
	m_config = config;
	m_merge_config = merge_config;
		
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

	if(colnames != "")
	{
		char *p = strtok((char*)colnames.c_str(), ",");
		while (p) 
		{
			string ts(p);
			trim(ts);
			m_colnames.push_back(ts);
			p = strtok(NULL, ",");
		}
	}

	if(colsizes != "")
	{
		char *p = strtok((char*)colsizes.c_str(), " ,");
		while (p) 
		{
			try
			{
				m_colsizes.push_back(stoi(p));
			}
			catch(...)
			{
				throw sinsp_exception("table column size string contains invalid numbers");
			}

			p = strtok(NULL, " ,");
		}
	}

	m_sortingcol = sortingcol;
	m_filter = filter;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_cursesui implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_cursesui::sinsp_cursesui(sinsp* inspector)
{
	m_inspector = inspector;
	m_selected_view = 0;
	m_selected_sidemenu_entry = 0;
	m_datatable = NULL;
	m_viz = NULL;

	//
	// Colors initialization
	//
#ifndef NOCURSESUI
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
	m_colors[CPU_STEAL] = ColorPair(COLOR_CYAN,COLOR_BLACK);
	m_colors[CPU_GUEST] = ColorPair(COLOR_CYAN,COLOR_BLACK);

	//
	// Populate the main menu entries
	//
	m_menuitems.push_back("Help");
	m_menuitems.push_back("View");
	m_menuitems.push_back("Legend");
	m_menuitems.push_back("Setup");
	m_menuitems.push_back("Search");

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
#endif
}

void sinsp_cursesui::configure(vector<sinsp_table_info>* views)
{
	if(views == NULL)
	{
		ASSERT(false);
		throw sinsp_exception("trying to configure the command line UI with no views");
	}

	m_views = *views;
}

void sinsp_cursesui::start(bool is_drilldown)
{
	if(m_selected_view >= m_views.size())
	{
		ASSERT(false);
		throw sinsp_exception("invalid view");		
	}

	if(m_datatable != NULL)
	{
		delete m_datatable;
	}

#ifndef NOCURSESUI
	if(m_viz != NULL)
	{
		delete m_viz;
	}
#endif

	m_datatable = new sinsp_table(m_inspector);

	m_datatable->configure(m_views[m_selected_view].m_config, 
		m_views[m_selected_view].m_merge_config,
		m_views[m_selected_view].m_filter);

	m_datatable->set_sorting_col(m_views[m_selected_view].m_sortingcol);

#ifndef NOCURSESUI
	m_viz = new curses_table();
	m_viz->configure(this, m_datatable, &m_views[m_selected_view].m_colsizes, &m_views[m_selected_view].m_colnames);
	if(!is_drilldown)
	{
		populate_sidemenu("", &m_viz->m_sidemenu_viewlist);
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

	attrset(m_colors[PANEL_HEADER_FOCUS]);
	mvaddstr(0, 0, "Viewing");

	attrset(m_colors[PROCESS]);
	const char* vcs = get_selected_view()->m_name.c_str();

	string vs(vcs);
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

	mvaddstr(0, sizeof("Viewing ") - 1, vs.c_str());
}

void sinsp_cursesui::render_main_menu()
{
	uint32_t j = 0;
	uint32_t k = 0;

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
}
#endif

sinsp_table_info* sinsp_cursesui::get_selected_view()
{
	ASSERT(m_selected_view < m_views.size());
	return &m_views[m_selected_view];
}

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

				m_sel_hierarchy.push_back(field, val, m_selected_view, m_selected_sidemenu_entry, &rowkeybak);
				m_selected_view = j;

				it->m_filter = m_sel_hierarchy.tofilter();

				start(true);
#ifndef NOCURSESUI
				clear();
				populate_sidemenu(field, &m_viz->m_sidemenu_viewlist);
				m_selected_sidemenu_entry = 0;
				m_viz->render(true);
				render();
//mvprintw(1, 0, "!!!!%d-%s", pippo, field.c_str());
//refresh();
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
		ASSERT(m_selected_view < m_views.size());
		m_sel_hierarchy.m_hierarchy.pop_back();
		m_views[m_selected_view].m_filter = m_sel_hierarchy.tofilter();

		start(true);
#ifndef NOCURSESUI
		m_viz->m_last_key.copy(&rowkey);
		m_viz->m_last_key.m_isvalid = true;
		m_viz->m_drilled_up = true;
		populate_sidemenu(field, &m_viz->m_sidemenu_viewlist);
		clear();
//mvprintw(1, 0, "@@@@%d-%d-%s", m_selected_view, m_selected_sidemenu_entry, field.c_str());
//refresh();
		m_viz->render(true);
		render();
#endif

		delete[] rowkey.m_val;
		return true;
	}

	return false;
}
