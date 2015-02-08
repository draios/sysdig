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
#include "cursestable.h"
#include "cursesui.h"

///////////////////////////////////////////////////////////////////////////////
// curses_table_sidemenu implementation
///////////////////////////////////////////////////////////////////////////////
curses_scrollable_list::curses_scrollable_list()
{
	m_selct = 0;
	m_firstrow = 0;
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
}

void curses_scrollable_list::selection_pageup(int32_t datasize)
{
	m_firstrow -= (m_h - 1);
	m_selct -= (m_h - 1);

	sanitize_selection(datasize);
}

void curses_scrollable_list::selection_pagedown(int32_t datasize)
{
	m_firstrow += (m_h - 1);
	m_selct += (m_h - 1);

	sanitize_selection(datasize);
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
curses_table_sidemenu::curses_table_sidemenu(curses_table* parent)
{
	ASSERT(parent != NULL);
	m_parent = parent;
	m_h = parent->m_h - 1;
	m_w = SIDEMENU_WIDTH;
	m_y_start = TABLE_Y_START;
	m_win = newwin(m_h, m_w, m_y_start, 0);
	m_selct = m_parent->m_parent->m_selected_view;
}

curses_table_sidemenu::~curses_table_sidemenu()
{
	delwin(m_win);
}

void curses_table_sidemenu::render()
{
	int32_t j, k;

	//
	// Render window header
	//
	wattrset(m_win, m_parent->m_parent->m_colors[sinsp_cursesui::PANEL_HEADER_FOCUS]);

	wmove(m_win, 0, 0);
	for(j = 0; j < (int32_t)m_w - 1; j++)
	{
		waddch(m_win, ' ');
	}

	// white space at the right
	wattrset(m_win, m_parent->m_parent->m_colors[sinsp_cursesui::PROCESS]);
	waddch(m_win, ' ');

	wattrset(m_win, m_parent->m_parent->m_colors[sinsp_cursesui::PANEL_HEADER_FOCUS]);
	mvwaddnstr(m_win, 0, 0, "Select View", m_w);

	//
	// Render the rows
	//
	for(j = m_firstrow; j < MIN(m_firstrow + (int32_t)m_h - 1, (int32_t)m_parent->m_parent->m_views.size()); j++)
	{
		if(j == m_selct)
		{
			wattrset(m_win, m_parent->m_parent->m_colors[sinsp_cursesui::PANEL_HIGHLIGHT_FOCUS]);
		}
		else
		{
			wattrset(m_win, m_parent->m_parent->m_colors[sinsp_cursesui::PROCESS]);
		}

		// clear the line
		wmove(m_win, j - m_firstrow + 1, 0);
		for(k = 0; k < (int32_t)m_w - 1; k++)
		{
			waddch(m_win, ' ');
		}

		// add the new line
		mvwaddnstr(m_win, j - m_firstrow + 1, 0, m_parent->m_parent->m_views[j].m_name.c_str(), m_w);

		// white space at the right
		wattrset(m_win, m_parent->m_parent->m_colors[sinsp_cursesui::PROCESS]);
		wmove(m_win, j - m_firstrow + 1, m_w - 1);
		waddch(m_win, ' ');
	}

	wrefresh(m_win);
}

//
// Return true if the parent should handle the event
//
sysdig_table_action curses_table_sidemenu::handle_input(int ch)
{
	switch(ch)
	{
		case '\n':
		case '\r':
		case KEY_ENTER:
			m_parent->m_parent->m_selected_view = m_selct;
			return STA_SWITCH_VIEW;
		case KEY_UP:
			selection_up((int32_t)m_parent->m_parent->m_views.size());
			render();
			return STA_NONE;
		case KEY_DOWN:
			selection_down((int32_t)m_parent->m_parent->m_views.size());
			render();
			return STA_NONE;
		case KEY_PPAGE:
			selection_pageup((int32_t)m_parent->m_parent->m_views.size());
			render();
			return STA_NONE;
		case KEY_NPAGE:
			selection_pagedown((int32_t)m_parent->m_parent->m_views.size());
			render();
			return STA_NONE;
		case KEY_MOUSE:
			{
/*
				uint32_t j;
				MEVENT event;

				if(getmouse(&event) == OK)
				{
//					if(event.bstate & BUTTON1_PRESSED)
					{
						ASSERT((m_data->size() == 0) || (m_column_startx.size() == m_data->at(0).m_values.size()));

						if((uint32_t)event.y == m_table_y_start)
						{
							//
							// This is a click on a column header. Change the sorting accordingly.
							//
							for(j = 0; j < m_column_startx.size() - 1; j++)
							{
								if((uint32_t)event.x >= m_column_startx[j] && (uint32_t)event.x < m_column_startx[j + 1])
								{
									m_table->set_sorting_col(j + 1);
									break;
								}
							}

							if(j == m_column_startx.size() - 1)
							{
								m_table->set_sorting_col(j + 1);
							}

							render(true);
						}
						else if((uint32_t)event.y > m_table_y_s						(uint32_t)event.y < m_table_y_start + m_h - 1)
						{
							//
							// This is a click on a row. Update the selection.
							//
							m_selct = event.y - m_table_y_start - 1;
							sanitize_selection();
							update_rowkey(m_selct);
							render(true);
						}
					}
				}
*/			
			}
			break;
			
	}

	return STA_PARENT_HANDLE;
}

///////////////////////////////////////////////////////////////////////////////
// curses_table implementation
///////////////////////////////////////////////////////////////////////////////
curses_table::curses_table()
{
	m_data = NULL;
	m_table = NULL;
	m_table_x_start = 0;
	m_table_y_start = TABLE_Y_START;
	m_sidemenu = NULL;

	m_converter = new sinsp_filter_check_reference();

	for (int i = 0; i < 8; i++)
	{
		for (int j = 0; j < 8; j++)
		{
			init_pair((7-i)*8+j, i, (j==0?-1:j));
		}
	}

	//
	// Column sizes initialization
	//
	m_colsizes[PT_NONE] = 0;
	m_colsizes[PT_INT8] = 8;
	m_colsizes[PT_INT16] = 8;
	m_colsizes[PT_INT32] = 8;
	m_colsizes[PT_INT64] = 8;
	m_colsizes[PT_UINT8] = 8;
	m_colsizes[PT_UINT16] = 8;
	m_colsizes[PT_UINT32] = 8;
	m_colsizes[PT_UINT64] = 8;
	m_colsizes[PT_CHARBUF] = 32;
	m_colsizes[PT_BYTEBUF] = 32;
	m_colsizes[PT_ERRNO] = 8;
	m_colsizes[PT_SOCKADDR] = 16;
	m_colsizes[PT_SOCKTUPLE] = 16;
	m_colsizes[PT_FD] = 32;
	m_colsizes[PT_PID] = 16;
	m_colsizes[PT_FDLIST] = 16;
	m_colsizes[PT_FSPATH] = 32;
	m_colsizes[PT_SYSCALLID] = 8;
	m_colsizes[PT_SIGTYPE] = 8;
	m_colsizes[PT_RELTIME] = 16;
	m_colsizes[PT_ABSTIME] = 16;
	m_colsizes[PT_PORT] = 8;
	m_colsizes[PT_L4PROTO] = 8;
	m_colsizes[PT_SOCKFAMILY] = 8;
	m_colsizes[PT_BOOL] = 8;
	m_colsizes[PT_IPV4ADDR] = 8;
	m_colsizes[PT_DYN] = 8;
	m_colsizes[PT_FLAGS8] = 32;
	m_colsizes[PT_FLAGS16] = 32;
	m_colsizes[PT_FLAGS32] = 32;
	m_colsizes[PT_UID] = 12;
	m_colsizes[PT_GID] = 12;
	m_colsizes[PT_MAX] = 0;

	//
	// Define the table size
	//
	getmaxyx(stdscr, m_screenh, m_screenw);
	m_w = TABLE_WIDTH;
	m_h = m_screenh - 3;
	m_scrolloff_x = 0;
	m_scrolloff_y = 10;

	//
	// Create the table window
	//
	refresh();
	m_tblwin = newwin(m_h, 500, m_table_y_start, 0);
}

curses_table::~curses_table()
{
	delwin(m_tblwin);

	if(m_sidemenu != NULL)
	{
		delete m_sidemenu;
	}

	delete m_converter;
}

void curses_table::configure(sinsp_cursesui* parent, sinsp_table* table, vector<int32_t>* colsizes)
{
	uint32_t j;

	m_parent = parent;
	m_table = table;

	vector<filtercheck_field_info>* legend = m_table->get_legend();

	if(colsizes)
	{
		if(colsizes->size() != 0 && colsizes->size() != legend->size())
		{
			throw sinsp_exception("invalid table legend: column sizes doesn't match (" + 
				to_string(colsizes->size()) + " column sizes, " + 
				to_string(legend->size()) + " entries in legend)");
		}
	}

	for(j = 1; j < legend->size(); j++)
	{
		curses_table_column_info ci;
		ci.m_info = legend->at(j);

		if(colsizes->size() == 0 || colsizes->at(j) == -1)
		{
			ci.m_size = m_colsizes[legend->at(j).m_type];
		}
		else
		{
			ci.m_size = colsizes->at(j);		
		}
/*
		int32_t namelen = strlen(ci.m_info.m_name);
		
		if(ci.m_size < namelen + 1)
		{
			ci.m_size = namelen + 1;
		}
*/
		m_legend.push_back(ci);
	}
}

void curses_table::update_rowkey(int32_t row)
{
	sinsp_table_field* rowkey = m_table->get_row_key(row);

	if(rowkey != NULL)
	{
		m_last_key.copy(rowkey);
		m_last_key.m_isvalid = true;
	}
	else
	{
		m_last_key.m_isvalid = false;
	}
}

void curses_table::update_data(vector<sinsp_sample_row>* data)
{
	m_data = data;

	if(!m_last_key.m_isvalid)
	{
		update_rowkey(m_selct);
	}
	else
	{
		m_selct = m_table->get_row_from_key(&m_last_key);
		if(m_selct == -1)
		{
			m_selct = 0;
			m_firstrow = 0;
			m_last_key.m_isvalid = false;
		}
		else
		{
			selection_goto((int32_t)m_data->size(), m_selct);			
			render(true);
		}

		sanitize_selection((int32_t)m_data->size());
	}
}

void curses_table::render(bool data_changed)
{
	uint32_t j, k;
	int32_t l, m;

	if(m_data == NULL)
	{
		return;
	}

	if(m_data->size() != 0)
	{
		if(m_legend.size() != m_data->at(0).m_values.size())
		{
			ASSERT(false);
			throw sinsp_exception("corrupted curses table data");
		}
	}

	if(data_changed)
	{
		vector<filtercheck_field_info>* legend = m_table->get_legend();
		m_column_startx.clear();

		if(m_selct < 0)
		{
			m_selct = 0;
		}
		else if(m_selct > (int32_t)m_data->size() - 1)
		{
			m_selct = (int32_t)m_data->size() - 1;
		}

		wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::PANEL_HEADER_FOCUS]);

		//
		// Render the column headers
		//
		wmove(m_tblwin, 0, 0);
		for(j = 0; j < m_w; j++)
		{
			waddch(m_tblwin, ' ');
		}

		for(j = 0, k = 0; j < m_legend.size(); j++)
		{
			if(j == m_table->get_sorting_col())
			{
				wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::PANEL_HIGHLIGHT_FOCUS]);
			}
			else
			{
				wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::PANEL_HEADER_FOCUS]);
			}

			m_column_startx.push_back(k);
			mvwaddnstr(m_tblwin, 0, k, m_legend[j].m_info.m_name, m_legend[j].m_size - 1);

			for(l = strlen(m_legend[j].m_info.m_name); l < m_legend[j].m_size; l++)
			{
				waddch(m_tblwin, ' ');
			}

			k += m_legend[j].m_size;
		}

		//
		// Render the rows
		//
		vector<sinsp_table_field>* row;

		for(l = 0; l < (int32_t)MIN(m_data->size(), m_h - 1); l++)
		{
			if(l + m_firstrow >= (int32_t)m_data->size())
			{
				break;
			}

			row = &(m_data->at(l + m_firstrow).m_values);

			if(l == m_selct - (int32_t)m_firstrow)
			{
				wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::PANEL_HIGHLIGHT_FOCUS]);
			}
			else
			{
				wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::PROCESS]);
			}

			//
			// Render the rows
			//
			wmove(m_tblwin, l + 1, 0);
			for(j = 0; j < m_w; j++)
			{
				waddch(m_tblwin, ' ');
			}

			for(j = 0, k = 0; j < m_legend.size(); j++)
			{
				m_converter->set_val(m_legend[j].m_info.m_type, 
					row->at(j).m_val, 
					row->at(j).m_len,
					legend->at(j).m_print_format);

				mvwaddnstr(m_tblwin, l + 1, k, m_converter->tostring_nice(NULL), m_legend[j].m_size);
				k += m_legend[j].m_size;
			}
		}

		wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::PROCESS]);

		if(l < (int32_t)m_h - 1)
		{
			for(m = l; m < (int32_t)m_h - 1; m++)
			{
				wmove(m_tblwin, m + 1, 0);

				for(j = 0; j < m_w; j++)
				{
					waddch(m_tblwin, ' ');
				}
			}
		}
	}

	wrefresh(m_tblwin);

	copywin(m_tblwin,
		stdscr,
		0,
		m_scrolloff_x,
		m_scrolloff_y,
		0,
		m_scrolloff_y + (m_h - 1),
		m_screenw - 1,
		FALSE);

	wrefresh(m_tblwin);

//mvprintw(0, 0, "!!!!%d", (int)res);
//refresh();

	//
	// Draw the side menu
	//
	if(m_sidemenu)
	{
		m_sidemenu->render();
	}

	refresh();
}

void curses_table::scrollwin(uint32_t x, uint32_t y)
{
	wrefresh(m_tblwin);

	m_scrolloff_x = x;
	m_scrolloff_y = y;

	render(false);
}

//
// Return false if the user wants us to exit
//
sysdig_table_action curses_table::handle_input(int ch)
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

	switch(ch)
	{
		case 'q':
			return STA_QUIT;
/*
		case 'a':
			numbers[0]++;
			render(true);
			break;
		case KEY_LEFT:
			if(scrollpos > 0)
			{
				scrollpos--;
				scrollwin(scrollpos, 10);
			}
			break;
		case KEY_RIGHT:
			if(scrollpos < TABLE_WIDTH - (int32_t)m_screenw)
			{
				scrollpos++;
				scrollwin(scrollpos, 10);
			}
			break;
*/			
		case KEY_UP:
			selection_up((int32_t)m_data->size());
			update_rowkey(m_selct);
			render(true);
			break;
		case KEY_DOWN:
			selection_down((int32_t)m_data->size());
			update_rowkey(m_selct);
			render(true);
			break;
		case KEY_PPAGE:
			selection_pageup((int32_t)m_data->size());
			update_rowkey(m_selct);
			render(true);
			break;
		case KEY_NPAGE:
			selection_pagedown((int32_t)m_data->size());
			update_rowkey(m_selct);
			render(true);
			break;
		case '\n':
		case '\r':
		case KEY_ENTER:
			{
				return STA_DRILLDOWN;
			}
			break;
		case KEY_BACKSPACE:
			{
				return STA_DRILLUP;
			}
			break;
		case KEY_F(1):
			mvprintw(0, 0, "F1");
			refresh();
			break;
		case KEY_F(2):
			if(m_sidemenu == NULL)
			{
				m_table_x_start = SIDEMENU_WIDTH;
				m_sidemenu = new curses_table_sidemenu(this);
			}
			else
			{
				m_table_x_start = 0;
				delete m_sidemenu;
				m_sidemenu = NULL;
			}

			delwin(m_tblwin);
			m_tblwin = newwin(m_h, 500, m_table_y_start, m_table_x_start);
			render(true);
			break;
		case KEY_MOUSE:
			{
				uint32_t j;
				MEVENT event;

				if(getmouse(&event) == OK)
				{
//					if(event.bstate & BUTTON1_PRESSED)
					{
						ASSERT((m_data->size() == 0) || (m_column_startx.size() == m_data->at(0).m_values.size()));

						if((uint32_t)event.y == m_table_y_start)
						{
							//
							// This is a click on a column header. Change the sorting accordingly.
							//
							for(j = 0; j < m_column_startx.size() - 1; j++)
							{
								if((uint32_t)event.x >= m_column_startx[j] && (uint32_t)event.x < m_column_startx[j + 1])
								{
									m_table->set_sorting_col(j + 1);
									break;
								}
							}

							if(j == m_column_startx.size() - 1)
							{
								m_table->set_sorting_col(j + 1);
							}

							render(true);
						}
						else if((uint32_t)event.y > m_table_y_start &&
							(uint32_t)event.y < m_table_y_start + m_h - 1)
						{
							//
							// This is a click on a row. Update the selection.
							//
							m_selct = event.y - m_table_y_start - 1;
							sanitize_selection((int32_t)m_data->size());
							update_rowkey(m_selct);
							render(true);
						}
					}
				}
			}
			break;
	}

	return STA_NONE;
}

#endif // SYSTOP
