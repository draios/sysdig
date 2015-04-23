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

#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#ifndef _WIN32
#include <unistd.h>
#include <algorithm>
#endif
#include <string>
#include <unordered_map>
#include <map>
#include <queue>
#include <vector>
#include <set>
using namespace std;

#include "sinsp.h"
#include "sinsp_int.h"
#include "../../driver/ppm_ringbuffer.h"
#include "filter.h"
#include "filterchecks.h"

#ifdef SYSTOP

#include <curses.h>
#include "table.h"
#include "ctext.h"
#include "cursescomponents.h"
#include "cursestable.h"
#include "cursesui.h"

///////////////////////////////////////////////////////////////////////////////
// curses_scrollable_list implementation
///////////////////////////////////////////////////////////////////////////////
curses_scrollable_list::curses_scrollable_list()
{
	m_selct = 0;
	m_firstrow = 0;
	m_lastrow_selected = true;
}

void curses_scrollable_list::sanitize_selection(int32_t datasize)
{
	if(m_firstrow > (datasize - (int32_t)m_h + 1))
	{
		m_firstrow = datasize - (int32_t)m_h + 1;
	}
	
	if(m_firstrow < 0)
	{
		m_firstrow = 0;
	}	

	if(m_selct > datasize - 1)
	{
		m_selct = datasize - 1;
	}
	
	if(m_selct < 0)
	{
		m_selct = 0;
	}	

	if(m_firstrow > m_selct)
	{
		m_firstrow = m_selct;
	}
}

void curses_scrollable_list::selection_up(int32_t datasize)
{
	if(m_selct > 0)
	{
		if(m_selct <= (int32_t)m_firstrow)
		{
			m_firstrow--;
		}

		m_selct--;
		sanitize_selection(datasize);
	}

	m_lastrow_selected = false;
}

void curses_scrollable_list::selection_down(int32_t datasize)
{
	if(m_selct < datasize - 1)
	{
		if(m_selct - m_firstrow > (int32_t)m_h - 3)
		{
			m_firstrow++;
		}

		m_selct++;
		sanitize_selection(datasize);
	}

	if(m_selct == datasize - 1)
	{
		m_lastrow_selected = true;		
	}
}

void curses_scrollable_list::selection_pageup(int32_t datasize)
{
	m_firstrow -= (m_h - 1);
	m_selct -= (m_h - 1);

	sanitize_selection(datasize);

	m_lastrow_selected = false;
}

void curses_scrollable_list::selection_pagedown(int32_t datasize)
{
	m_firstrow += (m_h - 1);
	m_selct += (m_h - 1);

	sanitize_selection(datasize);

	if(m_selct == datasize - 1)
	{
		m_lastrow_selected = true;		
	}
}

void curses_scrollable_list::selection_home(int32_t datasize)
{
	m_firstrow = 0;
	m_selct = 0;

	sanitize_selection(datasize);

	m_lastrow_selected = false;
}

void curses_scrollable_list::selection_end(int32_t datasize)
{
	m_firstrow = datasize - 1;
	m_selct = datasize - 1;

	sanitize_selection(datasize);

	m_lastrow_selected = true;
}

void curses_scrollable_list::selection_goto(int32_t datasize, int32_t row)
{
	if(row == -1 ||
		row >= datasize)
	{
		ASSERT(false);
		return;
	}

	m_firstrow = row - (m_h /2);
	m_selct = row;

	sanitize_selection(datasize);
}

///////////////////////////////////////////////////////////////////////////////
// curses_table_sidemenu implementation
///////////////////////////////////////////////////////////////////////////////
curses_table_sidemenu::curses_table_sidemenu(sinsp_cursesui* parent)
{
	ASSERT(parent != NULL);
	m_parent = parent;
	m_h = m_parent->m_screenh - TABLE_Y_START - 1;
	m_w = SIDEMENU_WIDTH;
	m_y_start = TABLE_Y_START;
	m_win = newwin(m_h, m_w, m_y_start, 0);
	m_selct = m_parent->m_selected_sidemenu_entry;
	m_selct_ori = m_selct;
	m_entries = NULL;
}

curses_table_sidemenu::~curses_table_sidemenu()
{
	delwin(m_win);
}

void curses_table_sidemenu::render()
{
	int32_t j, k;

	ASSERT(m_entries != NULL);

	//
	// Render window header
	//
	wattrset(m_win, m_parent->m_colors[sinsp_cursesui::PANEL_HEADER_FOCUS]);

	wmove(m_win, 0, 0);
	for(j = 0; j < (int32_t)m_w - 1; j++)
	{
		waddch(m_win, ' ');
	}

	// white space at the right
	wattrset(m_win, m_parent->m_colors[sinsp_cursesui::PROCESS]);
	waddch(m_win, ' ');

	ASSERT(m_title != "");
	wattrset(m_win, m_parent->m_colors[sinsp_cursesui::PANEL_HEADER_FOCUS]);
	mvwaddnstr(m_win, 0, 0, m_title.c_str(), m_w);

	//
	// Render the rows
	//
	for(j = m_firstrow; j < MIN(m_firstrow + (int32_t)m_h - 1, (int32_t)m_entries->size()); j++)
	{
		if(j == m_selct)
		{
			wattrset(m_win, m_parent->m_colors[sinsp_cursesui::PANEL_HIGHLIGHT_FOCUS]);
		}
		else
		{
			wattrset(m_win, m_parent->m_colors[sinsp_cursesui::PROCESS]);
		}

		// clear the line
		wmove(m_win, j - m_firstrow + 1, 0);
		for(k = 0; k < (int32_t)m_w - 1; k++)
		{
			waddch(m_win, ' ');
		}

		// add the new line
		mvwaddnstr(m_win, j - m_firstrow + 1, 0, m_entries->at(j).m_name.c_str(), m_w);

		// white space at the right
		wattrset(m_win, m_parent->m_colors[sinsp_cursesui::PROCESS]);
		wmove(m_win, j - m_firstrow + 1, m_w - 1);
		waddch(m_win, ' ');
	}

	wrefresh(m_win);
}

//
// Update the view info page in the parent
//
void curses_table_sidemenu::update_view_info()
{
	if(m_parent->m_viewinfo_page)
	{
		delete m_parent->m_viewinfo_page;

		ASSERT(m_selct < (int32_t)m_entries->size());

		m_parent->m_viewinfo_page = new curses_viewinfo_page(m_parent,
			m_entries->at(m_selct).m_id,
			TABLE_Y_START,
			SIDEMENU_WIDTH,
			m_parent->m_screenh - TABLE_Y_START - 1,
			m_parent->m_screenw - SIDEMENU_WIDTH);
	}
}

//
// Return true if the parent should handle the event
//
sysdig_table_action curses_table_sidemenu::handle_input(int ch)
{
	int32_t prev_select;

	switch(ch)
	{
		case KEY_F(1):
		case KEY_HOME:
		case KEY_END:
			return STA_NONE;
		case '\n':
		case '\r':
		case KEY_ENTER:
			ASSERT(m_selct < (int32_t)m_entries->size());
			if(m_parent->m_spy_box == NULL)
			{
				m_parent->m_selected_view = m_entries->at(m_selct).m_id;
			}
			m_parent->m_selected_sidemenu_entry = m_selct;
			return STA_SWITCH_VIEW;
		case KEY_BACKSPACE:
		case 27: // ESC
			ASSERT(m_selct < (int32_t)m_entries->size());
			if(m_parent->m_spy_box == NULL)
			{
				m_parent->m_selected_view = m_entries->at(m_selct).m_id;
			}
			m_parent->m_selected_sidemenu_entry = m_selct_ori;
			return STA_SWITCH_VIEW;
		case KEY_UP:
			if(m_entries->size() == 0)
			{
				return STA_NONE;
			}

			prev_select = m_selct;

			selection_up((int32_t)m_entries->size());

			if(m_selct != prev_select)
			{
				update_view_info();
			}

			render();
			return STA_NONE;
		case KEY_DOWN:
			if(m_entries->size() == 0)
			{
				return STA_NONE;
			}

			prev_select = m_selct;

			selection_down((int32_t)m_entries->size());

			if(m_selct != prev_select)
			{
				update_view_info();
			}

			render();
			return STA_NONE;
		case KEY_PPAGE:
			if(m_entries->size() == 0)
			{
				return STA_NONE;
			}

			prev_select = m_selct;

			selection_pageup((int32_t)m_entries->size());

			if(m_selct != prev_select)
			{
				update_view_info();
			}

			render();
			return STA_NONE;
		case KEY_NPAGE:
			if(m_entries->size() == 0)
			{
				return STA_NONE;
			}

			prev_select = m_selct;

			selection_pagedown((int32_t)m_entries->size());

			if(m_selct != prev_select)
			{
				update_view_info();
			}

			render();
			return STA_NONE;
		case KEY_MOUSE:
			{
				MEVENT event;

				if(m_entries->size() == 0)
				{
					return STA_NONE;
				}

				if(getmouse(&event) == OK)
				{
					if(event.bstate & BUTTON1_CLICKED)
					{
						if((uint32_t)event.y > TABLE_Y_START &&
							(uint32_t)event.y < TABLE_Y_START + m_h - 1)
						{
							//
							// This is a click one of the menu entries. Update the selection.
							//
							m_selct = m_firstrow + (event.y - TABLE_Y_START - 1);
							sanitize_selection((int32_t)m_entries->size());
							update_view_info();
							render();
						}
					}
					else if(event.bstate & BUTTON1_DOUBLE_CLICKED)
					{
						if((uint32_t)event.y > TABLE_Y_START &&
							(uint32_t)event.y < TABLE_Y_START + m_h - 1)
						{
							//
							// This is a double click one of the menu entries. 
							// Update the selection.
							//
							m_selct = m_firstrow + (event.y - TABLE_Y_START - 1);
							sanitize_selection((int32_t)m_entries->size());
							render();

							//
							// This delay is here just as a lazy way to give the user the
							// feeling that the row has been clicked 
							//
							usleep(200000);

							//
							// Notify the parent that a selection has happened
							//
							ASSERT(m_selct < (int32_t)m_entries->size());
							if(m_parent->m_spy_box == NULL)
							{
								m_parent->m_selected_view = m_entries->at(m_selct).m_id;
							}
							m_parent->m_selected_sidemenu_entry = m_selct;
							return STA_SWITCH_VIEW;
						}
					}
				}
			}

			return STA_NONE;
		default:
			break;
	}

	return STA_PARENT_HANDLE;
}

///////////////////////////////////////////////////////////////////////////////
// curses_textbox implementation
///////////////////////////////////////////////////////////////////////////////
curses_textbox::curses_textbox(sinsp* inspector, sinsp_cursesui* parent, int32_t viz_type)
{
	ASSERT(inspector != NULL);
	ASSERT(parent != NULL);

	m_parent = parent;
	m_win = NULL;
	m_ctext = NULL;
	m_filter = NULL;
	m_inspector = inspector;
	n_prints = 0;
	m_paused = false;
	m_sidemenu = NULL;
	m_viz_type = viz_type;
	m_searcher = NULL;
	m_has_searched = false;

	ctext_config config;

	m_win = newwin(m_parent->m_screenh - 4, m_parent->m_screenw, TABLE_Y_START + 1, 0);
	m_ctext = new ctext(m_win);

	m_ctext->get_config(&config);

	config.m_buffer_size = 500000;
	config.m_scroll_on_append = true;
	config.m_bounding_box = true;

	//
	// visualization-type inits
	//
	if(m_viz_type == VIEW_ID_DIG)
	{
		m_formatter = new sinsp_evt_formatter(m_inspector, DEFAULT_OUTPUT_STR);
		config.m_do_wrap = false;
	}
	else
	{
		m_formatter = NULL;
		config.m_do_wrap = true;
	}

	//
	// set the config back
	//
	m_ctext->set_config(&config);

	//
	// Allocate the searcher
	//
	m_searcher = new ctext_search();

	//
	// If we're offline, disable screen refresh until we've parsed the file
	//
	if(!m_inspector->is_live())
	{
		m_ctext->ob_start();
	}

	//
	// Initialize the inspector to capture longer buffers and format them in a 
	// readable way
	//
	m_inspector->set_buffer_format(sinsp_evt::PF_NORMAL);
	m_inspector->set_snaplen(2000);

	//
	// Tell the parent to check for input more often
	//
	m_parent->m_input_check_period_ns = 100000;

	//
	// Initial screen refresh
	//
	render();
}

curses_textbox::~curses_textbox()
{
	if(m_sidemenu)
	{
		delete m_sidemenu;
	}

	delwin(m_win);
	
	delete m_ctext;

	if(m_searcher)
	{
		delete m_searcher;
	}

	if(m_filter != NULL)
	{
		delete m_filter;
	}

	if(m_formatter)
	{
		delete m_formatter;
	}

	//
	// Restore default snaplen and output formatting
	//
	m_inspector->set_snaplen(80);
	m_inspector->set_buffer_format(sinsp_evt::PF_EOLS);

	//
	// Tell the parent to check for input at the usual frequency
	//
	m_parent->m_input_check_period_ns = UI_USER_INPUT_CHECK_PERIOD_NS;
}

void curses_textbox::set_filter(string filter)
{
	m_filter = new sinsp_filter(m_inspector, filter);
}

void curses_textbox::print_no_data()
{
	attrset(m_parent->m_colors[sinsp_cursesui::PROCESS]);

	string wstr = "No Data For This Selection";
	mvprintw(m_parent->m_screenh / 2,
		m_parent->m_screenw / 2 - wstr.size() / 2, 
		wstr.c_str());	

	refresh();
}

void curses_textbox::process_event_spy(sinsp_evt* evt, int32_t next_res)
{
	//
	// Drop any non I/O event
	//
	ppm_event_flags eflags = evt->get_flags();

	if(!(eflags & EF_READS_FROM_FD || eflags & EF_WRITES_TO_FD))
	{
		return;
	}

	//
	// Get and validate the lenght
	//
	sinsp_evt_param* parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	int64_t len = *(int64_t*)parinfo->m_val;
	if(len <= 0)
	{
		return;
	}

	//
	// Get thread and fd
	//
	sinsp_threadinfo* m_tinfo =	evt->get_thread_info();
	if(m_tinfo == NULL)
	{
		return;
	}

	sinsp_fdinfo_t* m_fdinfo = evt->get_fd_info();
	if(m_fdinfo == NULL)
	{
		return;
	}
	string fdname = m_fdinfo->m_name;
	if(fdname == "")
	{
		fdname = "unnamed FD";
	}

	//
	// Get the buffer
	//
	const char* resolved_argstr;
	const char* argstr;
	argstr = evt->get_param_value_str("data", &resolved_argstr, m_inspector->get_buffer_format());
	//uint32_t len = evt->m_rawbuf_str_len;

	if(argstr != NULL)
	{
		//
		// Create the info string
		//
//		string info_str = "------ " + to_string(evt->get_num());
		string info_str = "------ ";
		string dirstr;
		string cnstr;
		if(eflags & EF_READS_FROM_FD)
		{
			dirstr = "Read ";
			cnstr = "from ";
			wattrset(m_win, m_parent->m_colors[sinsp_cursesui::SPY_READ]);
		}
		else if(eflags & EF_WRITES_TO_FD)
		{
			wattrset(m_win, m_parent->m_colors[sinsp_cursesui::SPY_WRITE]);
			dirstr = "Write ";
			cnstr = "to ";
		}

		info_str += dirstr + to_string(len) + 
			"B " + 
			cnstr + 
			fdname + 
			" (" + m_tinfo->m_comm.c_str() + ")";

		//
		// Sanitize the info string
		//
		info_str.erase(remove_if(info_str.begin(), info_str.end(), g_invalidchar()), info_str.end());

		//
		// Print the whole thing
		//
		m_ctext->printf("%s", info_str.c_str());
		m_ctext->printf("\n");
		m_ctext->printf("\n");
		m_ctext->printf("%s", argstr);
	}

	m_ctext->printf("\n");
	m_ctext->printf("\n");

	n_prints++;

	if(n_prints == 1)
	{
		render();
	}
}

void curses_textbox::process_event_dig(sinsp_evt* evt, int32_t next_res)
{
	string line;

	m_formatter->tostring(evt, &line);

	m_ctext->printf("%s\n", line.c_str());

	n_prints++;

	if(n_prints == 1)
	{
		render();
	}
}

void curses_textbox::process_event(sinsp_evt* evt, int32_t next_res)
{
	//
	// Check if this the end of the capture file, and if yes take note of that 
	//
	if(next_res == SCAP_EOF)
	{
		ASSERT(!m_inspector->is_live());
		m_parent->m_eof = 2;
		m_ctext->jump_to_first_line();
		m_ctext->ob_end();
		render();

		if(n_prints == 0)
		{
			print_no_data();
		}

		return;
	}

	//
	// If the user pressed 'p', skip the event
	//
	if(m_paused)
	{
		return;
	}

	//
	// Filter the event
	//
	if(m_filter)
	{
		if(!m_filter->run(evt))
		{
			return;
		}
	}

	if(m_viz_type == VIEW_ID_SPY)
	{
		process_event_spy(evt, next_res);
	}
	else
	{
		process_event_dig(evt, next_res);		
	}
}

void curses_textbox::populate_sidemenu()
{
	ASSERT(m_sidemenu != NULL);
	m_entries.clear();
	m_entries.push_back(sidemenu_list_entry("dotted ascii", -1));
	m_entries.push_back(sidemenu_list_entry("printable ascii", -1));
	m_entries.push_back(sidemenu_list_entry("hex", -1));
	if(m_viz_type == VIEW_ID_DIG)
	{
		m_entries.push_back(sidemenu_list_entry("json", 0));
	}

	m_sidemenu->set_entries(&m_entries);
	m_sidemenu->set_title("View As");
}

void curses_textbox::render_header()
{
	move(2, 0);
	attrset(m_parent->m_colors[sinsp_cursesui::FUNCTION_BAR]);

	for(uint32_t j = 0; j < m_parent->m_screenw; j++)
	{
		addch(' ');
	}

	refresh();
}

void curses_textbox::render()
{
	m_ctext->redraw();
	render_header();
	m_parent->render();

	if(m_paused)
	{
		string wstr = "   PAUSED   ";
		attrset(m_parent->m_colors[sinsp_cursesui::LARGE_NUMBER]);
		mvprintw(0,
			m_parent->m_screenw / 2 - wstr.size() / 2, 
			wstr.c_str());	
	}

	//
	// If required, draw the side menu
	//
	if(m_sidemenu)
	{
		m_sidemenu->render();
	}
}

//
// Return true if the parent should handle the event
//
sysdig_table_action curses_textbox::handle_input(int ch)
{
	if(m_sidemenu)
	{
		sysdig_table_action ta = m_sidemenu->handle_input(ch);
		if(ta == STA_SWITCH_VIEW)
		{
			return STA_SWITCH_SPY;
		}
		else if(ta != STA_PARENT_HANDLE)
		{
			return STA_NONE;
		}
	}

	switch(ch)
	{
		case KEY_F(1):
		case 'q':
			return STA_PARENT_HANDLE;
		case KEY_BACKSPACE:
			return STA_DRILLUP;
		case KEY_UP:
			m_ctext->up();
			render();
			return STA_NONE;
		case '\n':
		case '\r':
		case KEY_ENTER:
		case KEY_DOWN:
			m_ctext->down();
			render();
			return STA_NONE;
		case KEY_LEFT:
			m_ctext->left();
			render();
			return STA_NONE;
		case KEY_RIGHT:
			m_ctext->right();
			render();
			return STA_NONE;
		case KEY_PPAGE:
			m_ctext->page_up();
			render();
			return STA_NONE;
		case ' ':
		case KEY_NPAGE:
			m_ctext->page_down();
			render();
			return STA_NONE;
		case KEY_HOME:
			m_ctext->jump_to_first_line();
			m_ctext->scroll_to(0, 0);
			render();
			return STA_NONE;
		case KEY_END:
			m_ctext->jump_to_last_line();
			render();
			return STA_NONE;
		case 'c':
		case KEY_DC:
			m_ctext->clear();
			render();
			return STA_NONE;
		case 'p':
			if(m_inspector->is_live())
			{
				m_paused = !m_paused;
			}
			m_ctext->jump_to_last_line();
			m_parent->render();
			render();
			return STA_NONE;	
		case KEY_F(2):
			if(m_parent->m_screenw < 20)
			{
				return STA_NONE;				
			}

			if(m_sidemenu == NULL)
			{
				m_sidemenu = new curses_table_sidemenu(this->m_parent);
				populate_sidemenu();
				clear();
				wresize(m_win, m_parent->m_screenh - 4, m_parent->m_screenw - 20);
				mvwin(m_win, TABLE_Y_START + 1, 20);
				wrefresh(m_win);
				m_parent->render();
				render();
				m_ctext->redraw();
			}
			else
			{
				delete m_sidemenu;
				m_sidemenu = NULL;				

				wresize(m_win, m_parent->m_screenh - 4, m_parent->m_screenw);
				mvwin(m_win, TABLE_Y_START + 1, 0);
				wrefresh(m_win);
				m_parent->render();
				render();
				m_ctext->redraw();
			}

			return STA_NONE;
		case '/':
		case KEY_F(3):
			on_search_next();
			break;
		case 6:	// CTRL+F
			m_parent->turn_search_on(this);
			break;
		default:
			break;
	}

	return STA_NONE;
}

void curses_textbox::reset()
{
	if(m_sidemenu != NULL)
	{
		delete m_sidemenu;
		m_sidemenu = NULL;				

		wresize(m_win, m_parent->m_screenh - 4, m_parent->m_screenw);
		mvwin(m_win, TABLE_Y_START + 1, 0);
		wrefresh(m_win);
	}

	switch(m_parent->m_selected_sidemenu_entry)
	{
		case 0:
			m_inspector->set_buffer_format(sinsp_evt::PF_NORMAL);
			break;
		case 1:
			m_inspector->set_buffer_format(sinsp_evt::PF_EOLS);
			break;
		case 2:
			m_inspector->set_buffer_format(sinsp_evt::PF_HEXASCII);
			break;
		case 3:
			m_inspector->set_buffer_format(sinsp_evt::PF_JSON);
			break;
		default:
			ASSERT(false);
			break;
	}

	//
	// If we're offline, disable screen refresh until we've parsed the file
	//
	if(!m_inspector->is_live())
	{
		m_ctext->ob_start();
	}

	//
	// Disable pause
	//
	m_paused = false;
	
	//
	// Clear the screen
	//
	m_ctext->clear();

	//
	// Redraw everything
	//
	m_parent->render();
	render();
	m_ctext->redraw();
	n_prints = 0;
}

bool curses_textbox::get_position(OUT int32_t* pos, 
	OUT int32_t* totlines, 
	OUT float* percent, 
	OUT bool* truncated)
{
	int32_t ox;

	m_ctext->get_offset(&ox, pos);
	m_ctext->get_buf_size(totlines);
	m_ctext->get_offset_percent(percent);
	*truncated = (m_ctext->available_rows() <= 0);

	return true;
}

string* curses_textbox::get_last_search_string()
{
	return &m_last_search_string;
}

int8_t curses_textbox::get_offset(int32_t* x, int32_t* y)
{
	return m_ctext->get_offset(x, y);
}

int8_t curses_textbox::scroll_to(int32_t x, int32_t y)
{
	return m_ctext->scroll_to(x, y);
}

void curses_textbox::up()
{
	m_ctext->up();
}

bool curses_textbox::on_search_key_pressed(string search_str)
{
	m_last_search_string = search_str;

	m_ctext->new_search(m_searcher, 
		search_str,
		true);

	if(m_ctext->str_search(m_searcher) != 0)
	{
		return false;
	}
	else
	{
		m_has_searched = true;
		return true;
	}
}

bool curses_textbox::on_search_next()
{
	if(!m_has_searched)
	{
		return false;
	}

	if(m_ctext->str_search(m_searcher) != 0)
	{
		return false;
	}
	else
	{
		return true;
	}
}

///////////////////////////////////////////////////////////////////////////////
// curses_viewinfo_page implementation
///////////////////////////////////////////////////////////////////////////////
curses_viewinfo_page::curses_viewinfo_page(sinsp_cursesui* parent,
	uint32_t viewnum,
	uint32_t starty, 
	uint32_t startx, 
	uint32_t h, 
	uint32_t w)
{
	m_parent = parent;
	ctext_config config;

	sinsp_view_info* vinfo = parent->m_views.at(viewnum);

	m_win = newwin(h, w, starty, startx);

	m_ctext = new ctext(m_win);
//	m_ctext = new ctext(stdscr);

	m_ctext->get_config(&config);

	config.m_buffer_size = 50000;
	config.m_scroll_on_append = false;
	config.m_bounding_box = true;
	config.m_do_wrap = true;

	m_ctext->set_config(&config);

	//
	// Print title and info
	//
	wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
	m_ctext->printf("%s\n", vinfo->m_name.c_str());

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf("%s\n\n", vinfo->m_description.c_str());

	//
	// Print the tips if present
	//
	if(vinfo->m_tips.size() != 0)
	{
		wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
		m_ctext->printf("Tips\n");

		for(uint32_t j = 0; j < vinfo->m_tips.size(); j++)
		{
			wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
			m_ctext->printf("%s\n\n", vinfo->m_tips[j].c_str());
		}
	}

	//
	// Print columns info
	//
//	vector<filtercheck_field_info>* legend = parent->m_datatable->get_legend();

	wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
	m_ctext->printf("Columns\n");

	uint32_t j;

	if(vinfo->get_type() == sinsp_view_info::T_TABLE)
	{
		j = vinfo->does_groupby()? 2 : 1;
	}
	else
	{
		j = 0;		
	}

	for(; j < vinfo->m_columns.size(); j++)
	{
		auto c = &(vinfo->m_columns[j]);

		string desc;
		desc = c->m_description;

		wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
		m_ctext->printf("%s", c->m_name.c_str());
		wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
		m_ctext->printf(": %s", desc.c_str());
		m_ctext->printf("\n");
	}

	m_ctext->printf("\n");

	//
	// Print the view ID
	//
	wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
	m_ctext->printf("ID\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf("%s\n\n", vinfo->m_id.c_str());

	//
	// If there's a filter, print it 
	//
	if(vinfo->m_filter != "")
	{
		wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
		m_ctext->printf("Filter\n");

		wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
		m_ctext->printf("%s\n\n", vinfo->m_filter.c_str());
	}

	//
	// Done. Refresh the screen
	//
	m_ctext->redraw();
}

curses_viewinfo_page::~curses_viewinfo_page()
{
	delete m_ctext;
	delwin(m_win);
}

void curses_viewinfo_page::render()
{
	m_ctext->redraw();
}

sysdig_table_action curses_viewinfo_page::handle_input(int ch)
{
	int32_t totlines;

	m_ctext->get_buf_size(&totlines);

	if(totlines < (int32_t)m_parent->m_screenh)
	{
		return STA_DESTROY_CHILD;			
	}

	switch(ch)
	{
		case KEY_UP:
			m_ctext->up();
			render();
			return STA_NONE;
		case '\n':
		case '\r':
		case KEY_ENTER:
		case KEY_DOWN:
			m_ctext->down();
			render();
			return STA_NONE;
		case KEY_LEFT:
			m_ctext->left();
			render();
			return STA_NONE;
		case KEY_RIGHT:
			m_ctext->right();
			render();
			return STA_NONE;
		case KEY_PPAGE:
			m_ctext->page_up();
			render();
			return STA_NONE;
		case ' ':
		case KEY_NPAGE:
			m_ctext->page_down();
			render();
			return STA_NONE;
		case KEY_HOME:
			m_ctext->jump_to_first_line();
			m_ctext->scroll_to(0, 0);
			render();
			return STA_NONE;
		case KEY_END:
			m_ctext->jump_to_last_line();
			render();
			return STA_NONE;
		default:
		break;
	}

	return STA_DESTROY_CHILD;	
}

///////////////////////////////////////////////////////////////////////////////
// curses_mainhelp_page implementation
///////////////////////////////////////////////////////////////////////////////
extern string g_version_string;

curses_mainhelp_page::curses_mainhelp_page(sinsp_cursesui* parent)
{
	m_parent = parent;
	ctext_config config;

	m_win = newwin(parent->m_screenh, parent->m_screenw, 0, 0);

	m_ctext = new ctext(m_win);

	m_ctext->get_config(&config);

	config.m_buffer_size = 50000;
	config.m_scroll_on_append = false;
	config.m_bounding_box = true;
	config.m_do_wrap = true;

	m_ctext->set_config(&config);

	//
	// Print title and info
	//
	wattrset(m_win, parent->m_colors[sinsp_cursesui::TASKS_RUNNING]);
	m_ctext->printf("XXX %s. See man page for full documentation\n\n",
		g_version_string.c_str());

	wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
	m_ctext->printf("How to use XXX\n",
		g_version_string.c_str());

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(
"1. you can either see real time data, or analyze a trace file by using the -r command line flag.\n"
"2. you switch view by using the F2 key.\n"
"3. you drill down into a selection by clicking enter. You drill up by clicking backspace.\n"
"4. you can observe I/O activity (F5) or see sysdig output (F6) for anything you select.\n"
);

	//
	// Explore window keys
	//
	wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
	m_ctext->printf("\nExplore Window\n",
		g_version_string.c_str());

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf(" Arrows");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": scroll in the list       ");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("CTRL+F /");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": incremental search\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("     F2");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": switch view                  ");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("F4 \\");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": incremental filtering\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("  Enter");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": drill down                  ");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("F10 q");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": quit\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("Bkspace");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": drill up                    ");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("DEL c");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": clear the view content\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("   F5 e");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": echo FDs for selection         ");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("F7");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": see info page for the selected view\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("   F6 d");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": sysdig output for selection     ");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("P");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": Pause visualization\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf(" ? F1 h");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": show this help screen\n");

	//
	// Text windows keys
	//
	wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
	m_ctext->printf("\nEcho and sysdig Windows\n",
		g_version_string.c_str());

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf(" Arrows");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": scroll up and down       ");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("CTRL+F /");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": search\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("Bkspace");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": drill up                  ");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("     F3");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": find next\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("     F2");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": choose buffer print format      ");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("P");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": Pause visualization\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("  DEL c");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": clear the screen\n");

	//
	// Done. Refresh the screen
	//
	m_ctext->redraw();
}

curses_mainhelp_page::~curses_mainhelp_page()
{
	delete m_ctext;
	delwin(m_win);
}

void curses_mainhelp_page::render()
{
	m_ctext->redraw();
}

sysdig_table_action curses_mainhelp_page::handle_input(int ch)
{
	int32_t totlines;

	m_ctext->get_buf_size(&totlines);

	if(totlines < (int32_t)m_parent->m_screenh)
	{
		return STA_DESTROY_CHILD;			
	}

	switch(ch)
	{
		case KEY_F(1):
			return STA_NONE;
		case 'q':
		case KEY_F(10):
			return STA_PARENT_HANDLE;
		case KEY_UP:
			m_ctext->up();
			render();
			return STA_NONE;
		case '\n':
		case '\r':
		case KEY_ENTER:
		case KEY_DOWN:
			m_ctext->down();
			render();
			return STA_NONE;
		case KEY_PPAGE:
			m_ctext->page_up();
			render();
			return STA_NONE;
		case ' ':
		case KEY_NPAGE:
			m_ctext->page_down();
			render();
			return STA_NONE;
		case KEY_HOME:
			m_ctext->jump_to_first_line();
			m_ctext->scroll_to(0, 0);
			render();
			return STA_NONE;
		case KEY_END:
			m_ctext->jump_to_last_line();
			render();
			return STA_NONE;
		default:
		break;
	}

	return STA_DESTROY_CHILD;	
}

#endif // SYSTOP
