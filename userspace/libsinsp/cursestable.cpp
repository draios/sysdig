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
// curses_table implementation
///////////////////////////////////////////////////////////////////////////////
curses_table::curses_table(sinsp_cursesui* parent, sinsp* inspector)
{
	m_tblwin = NULL;
	m_data = NULL;
	m_table = NULL;
	m_table_x_start = 0;
	m_table_y_start = TABLE_Y_START;
	m_drilled_up = false;
	m_selection_changed = false;
	m_parent = parent;
	m_inspector = inspector;

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
	m_colsizes[PT_DOUBLE] = 8;

	//
	// Define the table size
	//
	m_w = TABLE_WIDTH;
	m_h = m_parent->m_screenh - 3;
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
	if(m_tblwin)
	{
		delwin(m_tblwin);
	}

	delete m_converter;
}

void curses_table::configure(sinsp_table* table, 
	vector<int32_t>* colsizes, vector<string>* colnames)
{
	uint32_t j;

	m_table = table;

	vector<filtercheck_field_info>* legend = m_table->get_legend();

	if(colsizes)
	{
		if(colsizes->size() != 0 && colsizes->size() != legend->size())
		{
			throw sinsp_exception("invalid table legend for view " + m_parent->m_views[m_parent->m_selected_view].m_name + 
				" : column sizes doesn't match (" + 
				to_string(colsizes->size()) + " column sizes, " + 
				to_string(legend->size()) + " entries in legend)");
		}
	}

	if(colnames)
	{
		if(colnames->size() != 0 && colnames->size() != legend->size())
		{
			throw sinsp_exception("invalid table legend for view " + m_parent->m_views[m_parent->m_selected_view].m_name + 
				" : column names doesn't match (" + 
				to_string(colnames->size()) + " column names, " + 
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

		if(colnames->size() == 0)
		{
			ci.m_name = ci.m_info.m_name;
		}
		else
		{
			ci.m_name = colnames->at(j);	
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

	if(m_selection_changed && (m_last_key.m_isvalid || m_drilled_up))
	{
		int32_t selct = m_table->get_row_from_key(&m_last_key);
		if(selct == -1)
		{
			m_selct--;
			m_last_key.m_isvalid = false;
		}
		else
		{
			m_selct = selct;
			selection_goto((int32_t)m_data->size(), m_selct);			
			render(true);
		}

		sanitize_selection((int32_t)m_data->size());
	}
	else
	{
		update_rowkey(m_selct);
	}
}

void curses_table::print_wait()
{
	string wstr;

	if(m_inspector->is_live())
	{
		wstr = "Gathering Data";
	}
	else
	{
		if(m_parent->is_eof())
		{
			wstr = "No Data For This View";
		}
	}

	wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::PROCESS]);

	mvwprintw(m_tblwin, 
		m_parent->m_screenh / 2,
		m_parent->m_screenw / 2 - wstr.size() / 2, 
		wstr.c_str());	
}

void curses_table::print_nomatch()
{
	string wstr = "No match";

	wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::FAILED_SEARCH]);

	mvwprintw(m_tblwin, 
		m_parent->m_screenh / 2,
		m_parent->m_screenw / 2 - wstr.size() / 2, 
		wstr.c_str());	
}

void curses_table::render(bool data_changed)
{
	uint32_t j, k;
	int32_t l, m;

	wclear(m_tblwin);

	//
	// Clear the screen
	//
	for(j = 1; j < m_h; j++)
	{
		wmove(m_tblwin, j, 0);
		for(k = 0; k < m_w; k++)
		{
			waddch(m_tblwin, ' ');
		}
	}

	if(m_data == NULL)
	{
		print_wait();
		goto render_end;
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

			string coltext = m_legend[j].m_name;
			if((int32_t)coltext.size() > m_legend[j].m_size - 2)
			{
				coltext = coltext.substr(0, m_legend[j].m_size - 2);
			}

			curses_table::alignment al = get_field_alignment(m_table->m_types->at(j + 1));
			if(al == curses_table::ALIGN_RIGHT)
			{
				coltext.insert(0, m_legend[j].m_size - coltext.size() - 2, ' ');
			}

			mvwaddnstr(m_tblwin, 0, k, coltext.c_str(), m_legend[j].m_size - 1);

			for(l = strlen(m_legend[j].m_name.c_str()); l < m_legend[j].m_size; l++)
			{
				waddch(m_tblwin, ' ');
			}

			k += m_legend[j].m_size;
		}

		//
		// If there is no data, print the "waiting for data" message
		//
		if(m_data->size() == 0)
		{
			if(!m_parent->is_searching())
			{
				print_wait();
				goto render_end;
			}
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

			//
			// Pick the proper color based on the selection
			//
			if(l == m_selct - (int32_t)m_firstrow)
			{
				wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::PANEL_HIGHLIGHT_FOCUS]);
			}
			else
			{
				wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::PROCESS]);
			}

			//
			// Render the row
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
					row->at(j).m_cnt,
					m_legend[j].m_info.m_print_format);

				uint32_t size = m_legend[j].m_size - 1;
				mvwaddnstr(m_tblwin, l + 1, k, m_converter->tostring_nice(NULL, size - 1), size);
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

render_end:
	if(m_data && m_data->size() == 0)
	{
		if(m_parent->is_searching())
		{
			print_nomatch();
		}
	}

	wrefresh(m_tblwin);

	copywin(m_tblwin,
		stdscr,
		0,
		0,
		2,
		0,
		m_h,
		m_parent->m_screenw - 1,
		FALSE);

	wrefresh(m_tblwin);
//mvprintw(0, 0, "!!!!%d", (int)res);
//refresh();

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
	switch(ch)
	{
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
			m_selection_changed = true;
			selection_up((int32_t)m_data->size());
			update_rowkey(m_selct);
			render(true);
			break;
		case KEY_DOWN:
			m_selection_changed = true;
			selection_down((int32_t)m_data->size());
			update_rowkey(m_selct);
			render(true);
			break;
		case KEY_PPAGE:
			m_selection_changed = true;
			selection_pageup((int32_t)m_data->size());
			update_rowkey(m_selct);
			render(true);
			break;
		case KEY_NPAGE:
			m_selection_changed = true;
			selection_pagedown((int32_t)m_data->size());
			update_rowkey(m_selct);
			render(true);
			break;
		case '\n':
		case '\r':
		case KEY_ENTER:
			return STA_DRILLDOWN;
		case KEY_BACKSPACE:
			return STA_DRILLUP;
		case KEY_F(1):
			mvprintw(0, 0, "F1");
			refresh();
			break;
		case KEY_MOUSE:
			{
				uint32_t j;
				MEVENT event;

				if(getmouse(&event) == OK)
				{
					if(event.bstate & BUTTON1_CLICKED)
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

							m_table->sort_sample();
							update_data(m_data);
							render(true);
						}
						else if((uint32_t)event.y > m_table_y_start &&
							(uint32_t)event.y < m_table_y_start + m_h - 1)
						{
							//
							// This is a click on a row. Update the selection.
							//
							m_selection_changed = true;
							m_selct = m_firstrow + (event.y - m_table_y_start - 1);
							sanitize_selection((int32_t)m_data->size());
							update_rowkey(m_selct);
							render(true);
						}
					}
					else if(event.bstate & BUTTON1_DOUBLE_CLICKED)
					{
						if((uint32_t)event.y > m_table_y_start &&
							(uint32_t)event.y < m_table_y_start + m_h - 1)
						{
							//
							// Update the selection
							//
							m_selection_changed = true;
							m_selct = m_firstrow + (event.y - m_table_y_start - 1);
							sanitize_selection((int32_t)m_data->size());
							update_rowkey(m_selct);
							render(true);

							//
							// This delay is here just as a lazy way to give the user the
							// feeling that the row has been clicked 
							//
							usleep(200000);

							//
							// Let the ui manager know that a drill down needs to happen
							//
							return STA_DRILLDOWN;
						}
					}
				}
			}
			break;
		default:
			break;
	}

	return STA_PARENT_HANDLE;
}

curses_table::alignment curses_table::get_field_alignment(ppm_param_type type)
{
	switch(type)
	{
	case PT_INT8:
	case PT_INT16:
	case PT_INT32:
	case PT_INT64:
	case PT_UINT8:
	case PT_UINT16:
	case PT_UINT32:
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
	case PT_DOUBLE:
		return ALIGN_RIGHT;
	default:
		return ALIGN_LEFT;
	}
}

void curses_table::recreate_win()
{
	delwin(m_tblwin);
	m_tblwin = newwin(m_h, 500, m_table_y_start, m_table_x_start);
	render(true);
}

#endif // SYSTOP
