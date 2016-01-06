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

#ifdef CSYSDIG
#ifndef NOCURSESUI

#include <curses.h>
#include "table.h"
#include "ctext.h"
#include "cursescomponents.h"
#include "cursestable.h"
#include "cursesspectro.h"
#include "cursesui.h"

//
// The color palette that we will use for the chart
//
uint32_t g_colpalette[] = 
{
	22, 28, 64, 34, 2, 76, 46, 118, 154, 191, 227, 226, 11, 220, 209, 208, 202, 197, 9, 1
};
uint32_t g_colpalette_size = sizeof(g_colpalette) / sizeof(g_colpalette[0]);

///////////////////////////////////////////////////////////////////////////////
// ANSI terminal helpers
///////////////////////////////////////////////////////////////////////////////
inline void ansi_movedown(int n)
{
	printf("\033[%dE", n);
}

inline void ansi_moveup(int n)
{
	printf("\033[%dF", n);
}

inline void ansi_hidecursor()
{
	printf("\033[?25l");
}

inline void ansi_showcursor()
{
	printf("\033[?25h");
}

inline void ansi_moveto(uint32_t y, uint32_t x)
{
	printf("\033[%d;%dH", y, x);
}

inline void ansi_clearline()
{
	printf("\033[2K");
}

inline void ansi_setcolor(int col)
{
	printf("\033[48;5;%dm", col);
}

inline void ansi_reset_color()
{
	printf("\033[0m");
}

inline void ansi_clearscreen()
{
	printf("\033[2J");
}

///////////////////////////////////////////////////////////////////////////////
// curses_spectro implementation
///////////////////////////////////////////////////////////////////////////////
curses_spectro::curses_spectro(sinsp_cursesui* parent, sinsp* inspector)
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
	m_n_flushes = 0;
	m_mouse_masked = false;

	//
	// Define the table size
	//
	m_w = m_parent->m_screenw;
	m_h = m_parent->m_screenh;

	//
	// Create the table window
	//
	refresh();
	m_tblwin = newwin(2, m_w, m_parent->m_screenh - 3, 0);

	//
	// Put the inspector in offline replay mode
	//
	if(!m_inspector->is_live())
	{
		parent->m_offline_replay = true;
	}
}

curses_spectro::~curses_spectro()
{
/*	
	if(m_inspector->is_live())
	{
		ansi_movedown(1);
		draw_menu();
		ansi_moveup(1);
		printf("\n\n");
		ansi_moveup(1);		
	}
	else
	{
		ansi_movedown(1);
		draw_menu();
		printf("\n");		
	}
*/
	ansi_moveto(m_h, 0);
	printf("\n");


	//
	// Disable offline replay mode
	//
	if(!m_inspector->is_live())
	{
		m_parent->m_offline_replay = false;
	}

	if(m_tblwin)
	{
		delwin(m_tblwin);
	}

	delete m_converter;
}

void curses_spectro::configure(sinsp_table* table)
{
	uint32_t j;

	m_table = table;

	vector<filtercheck_field_info>* legend = m_table->get_legend();

	for(j = 1; j < legend->size(); j++)
	{
		curses_table_column_info ci;
		ci.m_info = legend->at(j);
		m_legend.push_back(ci);
	}
}

void curses_spectro::print_error(string wstr)
{
	wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::FAILED_SEARCH]);

	mvwprintw(m_tblwin, 
		m_parent->m_screenh / 2,
		m_parent->m_screenw / 2 - wstr.size() / 2, 
		wstr.c_str());	
}

void curses_spectro::update_data(vector<sinsp_sample_row>* data, bool force_selection_change)
{
	m_data = data;
}

uint32_t curses_spectro::mkcol(uint64_t val)
{
	uint32_t refresh_per_sec = 2;
	uint32_t col = log10((int)val * refresh_per_sec + 1) / log10(1.6);

	if(col < 1)
	{
		col = 1;
	}

	if(col > g_colpalette_size - 1)
	{
		col = g_colpalette_size - 1;
	}

	return g_colpalette[col - 1];
}

void curses_spectro::draw_axis()
{
	uint64_t x = 0;

	while(true)
	{
		if(x >= m_w)
		{
			break;
		}

		uint32_t curtime = (uint32_t)((double)x * 11 / m_w);
		uint32_t prevtime = (uint32_t)(((double)x - 1) * 11 / m_w);

		if(x == 0 || curtime != prevtime)
		{
			uint64_t aval = (uint64_t)pow(10, curtime);

			m_converter->set_val(PT_RELTIME, 
				(uint8_t*)&aval,
				8,
				0,
				ppm_print_format::PF_DEC);

			string tstr = m_converter->tostring_nice(NULL, 0, 1000000000);
			printf("|%s", tstr.c_str());
			x += tstr.size() + 1;
		}
		else
		{
			printf(" ");
			x++;
		}
	}
}

 	void curses_spectro::draw_menu()
{
//	ansi_clearline();

	printf("F1");
	ansi_setcolor(24);
	printf("Help  ");
	ansi_reset_color();

	printf("F2");
	ansi_setcolor(24);
	printf("Views ");
	ansi_reset_color();

	printf("p ");
	ansi_setcolor(24);
	printf("Pause ");
	ansi_reset_color();

	printf("BKSPACE");
	ansi_setcolor(24);
	printf("Back");
	ansi_reset_color();
}

void curses_spectro::render(bool data_changed)
{
	//
	// Clear the screen
	//
	if(m_data == NULL)
	{
		return;
	}

	m_n_flushes++;

	if(m_data->size() != 0)
	{
		if(m_legend.size() != m_data->at(0).m_values.size())
		{
			ASSERT(false);
			throw sinsp_exception("corrupted curses table data");
		}
	}
	else
	{
		if(m_n_flushes < 2)
		{
			printf("\n");
		}
		else
		{
			return;
		}
	}

	if(data_changed)
	{
		unordered_map<uint64_t, uint32_t> freqs;

		//
		// Create a map with the frequencies for every latency interval
		//
		for(auto d : *m_data)
		{
			sinsp_table_field* key = &(d.m_values[0]); 
			sinsp_table_field* data = &(d.m_values[1]); 
			if(key->m_len != 8)
			{
				throw sinsp_exception("the key of a spectrogram view must be a number");
			}

			uint64_t val = *(uint64_t*)key->m_val;
			freqs[val] = *(uint32_t*)data->m_val;
		}

		ansi_moveto(m_h - 2, 0);

		//
		// Render the line
		//
		m_t_row.clear(m_table->m_next_flush_time_ns);

		for(uint32_t j = 0; j < m_w - 1; j++)
		{
			auto it = freqs.find(j);

			if(it != freqs.end())
			{
				m_t_row.push_back(it->second);
				uint32_t col = mkcol(it->second);
				ansi_setcolor(col);
				printf(" ");
			}
			else
			{
				m_t_row.push_back(0);
				ansi_setcolor(0);
				printf(" ");
			}
		}

		m_history.push_back(m_t_row);

		ansi_reset_color();
		ansi_moveto(m_h - 1, 0);
		draw_axis();
		ansi_moveto(m_h, 0);
		draw_menu();
		printf("\n");
	}
}

//
// Return false if the user wants us to exit
//
sysdig_table_action curses_spectro::handle_input(int ch)
{
	if(m_data == NULL)
	{
		return STA_PARENT_HANDLE;
	}

	switch(ch)
	{
		case KEY_F(2):
			clear();
			return STA_PARENT_HANDLE;
		case KEY_ENTER:
			return STA_DRILLDOWN;
		case KEY_BACKSPACE:
		case 127:
			return STA_DRILLUP;
		case KEY_DOWN:
			return STA_NONE;
		case KEY_UP:
			return STA_NONE;
		case KEY_MOUSE:
			{
				if(!m_mouse_masked)
				{
					mousemask(ALL_MOUSE_EVENTS | REPORT_MOUSE_POSITION, NULL);
					m_mouse_masked = true;
				}

				if(getmouse(&m_last_mevent) == OK)
				{
					if(m_last_mevent.bstate & BUTTON1_CLICKED)
					{
						//
						// Bottom menu clicks are handled by the parent
						//
						if((uint32_t)m_last_mevent.y == m_parent->m_screenh - 1)
						{
							return STA_PARENT_HANDLE;
						}

						g_logger.format("mouse clicked");
					}
					else
					{
						if((m_h - m_last_mevent.y > 3) && 
							(m_h - m_last_mevent.y - 4) < m_history.size() - 1)
						{
							curses_spectro_history_row& row = m_history[m_history.size() - 1 - (m_h - m_last_mevent.y - 4)];

							ASSERT(m_last_mevent.x >= 0);
							ASSERT(row.m_data.size() == m_w);
							ASSERT(m_last_mevent.x < m_w);

							uint32_t val = row.m_data[m_last_mevent.x];

							g_logger.format("mouse: %d:%d %d %d", m_last_mevent.x, 
								m_last_mevent.y,
								m_h - m_last_mevent.y - 4,
								(int)val);

						}
					}
				}
			}
			break;
		case 'c':
		case KEY_DC: // Del
			break;
		case KEY_F(7):
			return STA_NONE;
		default:
			break;
	}

	return STA_PARENT_HANDLE;
}

void curses_spectro::recreate_win(int h)
{
	delwin(m_tblwin);
	
	m_tblwin = newwin(m_h - 3, m_w, m_table_y_start, m_table_x_start);
	render(true);
}

#endif // NOCURSESUI
#endif // CSYSDIG
