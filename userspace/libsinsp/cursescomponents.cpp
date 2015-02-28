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
#include "cursescomponents.h"
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
curses_table_sidemenu::curses_table_sidemenu(sinsp_cursesui* parent)
{
	ASSERT(parent != NULL);
	m_parent = parent;
	m_h = parent->m_viz->m_h - 1;
	m_w = SIDEMENU_WIDTH;
	m_y_start = TABLE_Y_START;
	m_win = newwin(m_h, m_w, m_y_start, 0);
	m_selct = m_parent->m_selected_sidemenu_entry;
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
	wattrset(m_win, m_parent->m_colors[sinsp_cursesui::PANEL_HEADER_FOCUS]);

	wmove(m_win, 0, 0);
	for(j = 0; j < (int32_t)m_w - 1; j++)
	{
		waddch(m_win, ' ');
	}

	// white space at the right
	wattrset(m_win, m_parent->m_colors[sinsp_cursesui::PROCESS]);
	waddch(m_win, ' ');

	wattrset(m_win, m_parent->m_colors[sinsp_cursesui::PANEL_HEADER_FOCUS]);
	mvwaddnstr(m_win, 0, 0, "Select View", m_w);

	//
	// Render the rows
	//
	for(j = m_firstrow; j < MIN(m_firstrow + (int32_t)m_h - 1, (int32_t)m_parent->m_sidemenu_viewlist.size()); j++)
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
		mvwaddnstr(m_win, j - m_firstrow + 1, 0, m_parent->m_sidemenu_viewlist[j].m_viewname.c_str(), m_w);

		// white space at the right
		wattrset(m_win, m_parent->m_colors[sinsp_cursesui::PROCESS]);
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
			ASSERT(m_selct < (int32_t)m_parent->m_sidemenu_viewlist.size());
			m_parent->m_selected_view = m_parent->m_sidemenu_viewlist[m_selct].m_viewid;
			m_parent->m_selected_sidemenu_entry = m_selct;
			return STA_SWITCH_VIEW;
		case KEY_UP:
			selection_up((int32_t)m_parent->m_sidemenu_viewlist.size());
			render();
			return STA_NONE;
		case KEY_DOWN:
			selection_down((int32_t)m_parent->m_sidemenu_viewlist.size());
			render();
			return STA_NONE;
		case KEY_PPAGE:
			selection_pageup((int32_t)m_parent->m_sidemenu_viewlist.size());
			render();
			return STA_NONE;
		case KEY_NPAGE:
			selection_pagedown((int32_t)m_parent->m_sidemenu_viewlist.size());
			render();
			return STA_NONE;
		case KEY_MOUSE:
			{
				MEVENT event;

				if(getmouse(&event) == OK)
				{
					if(event.bstate & BUTTON1_CLICKED)
					{
						if((uint32_t)event.y > m_parent->m_viz->m_table_y_start &&
							(uint32_t)event.y < m_parent->m_viz->m_table_y_start + m_h - 1)
						{
							//
							// This is a click one of the menu entries. Update the selection.
							//
							m_selct = m_firstrow + (event.y - m_parent->m_viz->m_table_y_start - 1);
							sanitize_selection((int32_t)m_parent->m_sidemenu_viewlist.size());
							render();
						}
					}
					else if(event.bstate & BUTTON1_DOUBLE_CLICKED)
					{
						if((uint32_t)event.y > m_parent->m_viz->m_table_y_start &&
							(uint32_t)event.y < m_parent->m_viz->m_table_y_start + m_h - 1)
						{
							//
							// This is a double click one of the menu entries. 
							// Update the selection.
							//
							m_selct = m_firstrow + (event.y - m_parent->m_viz->m_table_y_start - 1);
							sanitize_selection((int32_t)m_parent->m_sidemenu_viewlist.size());
							render();

							//
							// This delay is here just as a lazy way to give the user the
							// feeling that the row has been clicked 
							//
							usleep(200000);

							//
							// Notify the parent that a selection has happened
							//
							ASSERT(m_selct < (int32_t)m_parent->m_sidemenu_viewlist.size());
							m_parent->m_selected_view = m_parent->m_sidemenu_viewlist[m_selct].m_viewid;
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

#endif // SYSTOP
