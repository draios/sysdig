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

inline void ansi_reset_color()
{
	printf("\033[0m");
}

inline void ansi_hidecursor()
{
	printf("\033[?25l");
}

inline void ansi_showcursor()
{
	printf("\033[?25h");
}

inline void ansi_moveto(uint32_t x, uint32_t y)
{
	printf("\033[%d;%dH", x, y);
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

	//
	// Define the table size
	//
	m_w = m_parent->m_screenw;
	m_h = m_parent->m_screenh - 3;

	//
	// Create the table window
	//
	refresh();
	m_tblwin = newwin(2, m_w, m_parent->m_screenh - 3, 0);

	//
	// Create the color palette
	//
	/*
	m_colpalette.push_back(colpalette_entry(m_parent->m_colors[sinsp_cursesui::GRAPH_WHITE], ' '));
	m_colpalette.push_back(colpalette_entry(m_parent->m_colors[sinsp_cursesui::GRAPH_WHITE_D], '*'));
	m_colpalette.push_back(colpalette_entry(m_parent->m_colors[sinsp_cursesui::GRAPH_GREEN_L], '*'));
	m_colpalette.push_back(colpalette_entry(m_parent->m_colors[sinsp_cursesui::GRAPH_GREEN], ' '));
	m_colpalette.push_back(colpalette_entry(m_parent->m_colors[sinsp_cursesui::GRAPH_GREEN_D], '*'));
	m_colpalette.push_back(colpalette_entry(m_parent->m_colors[sinsp_cursesui::GRAPH_YELLOW_L], '*'));
	m_colpalette.push_back(colpalette_entry(m_parent->m_colors[sinsp_cursesui::GRAPH_YELLOW], ' '));
	m_colpalette.push_back(colpalette_entry(m_parent->m_colors[sinsp_cursesui::GRAPH_YELLOW_D], '*'));
	m_colpalette.push_back(colpalette_entry(m_parent->m_colors[sinsp_cursesui::GRAPH_RED_L], '*'));
	m_colpalette.push_back(colpalette_entry(m_parent->m_colors[sinsp_cursesui::GRAPH_RED], ' '));
	m_colpalette.push_back(colpalette_entry(m_parent->m_colors[sinsp_cursesui::GRAPH_RED_D], '*'));
	m_colpalette.push_back(colpalette_entry(m_parent->m_colors[sinsp_cursesui::GRAPH_MAGENTA_L], '*'));
	m_colpalette.push_back(colpalette_entry(m_parent->m_colors[sinsp_cursesui::GRAPH_MAGENTA], ' '));
	*/

	//
	// Exit curses mode
	//
	endwin();
	(void) nonl(); // tell curses not to do NL->CR/NL on output
	intrflush(stdscr, false);
	mousemask(ALL_MOUSE_EVENTS, NULL);
	ansi_hidecursor();
	ansi_moveto(m_h, 0);
}

curses_spectro::~curses_spectro()
{
	ansi_showcursor();

	//
	// Reenter curses mode
	//
	reset_prog_mode();

	if(m_tblwin)
	{
		delwin(m_tblwin);
	}
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

void curses_spectro::print_wait()
{
	string wstr;

	if(m_inspector->is_live())
	{
		wstr = "Collecting Data";
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
	uint32_t refresh_per_sec = 1;
	uint32_t col = log10((int)val * refresh_per_sec + 1) / log10(1.6);

	if(col < 1)
	{
		col = 1;
	}

	if(col > g_colpalette_size - 1)
	{
		col = g_colpalette_size - 1;
	}

	return g_colpalette[col];
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
		unordered_map<uint64_t, uint64_t> freqs;

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
			freqs[val] = *(uint64_t*)data->m_val;
		}

		//
		// Render the line
		//
		ansi_moveup(1);

		for(uint32_t j = 0; j < m_w - 1; j++)
		{
			auto it = freqs.find(j);

			if(it != freqs.end())
			{
				uint32_t col = mkcol(it->second);
				printf("\033[48;5;%dm", col);
				printf(" ");
			}
			else
			{
				printf("\033[48;5;%dm", 0);
				printf(" ");
			}
		}

		printf("\n");
		ansi_movedown(1);
		ansi_reset_color();
		for(uint32_t j = 0; j < m_w - 1; j++)
		{
			printf("*");
		}
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

	g_logger.format("%d", (int)ch);

	switch(ch)
	{
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
				}
			}
			break;
		case 'c':
		case KEY_DC: // Del
			break;
		default:
			break;
	}

	//
	// Check if this view has any action configured, and if yes find if this key
	// is one of the view hotkeys
	//
	sinsp_view_info* vinfo = m_parent->get_selected_view();

	for(auto hk : vinfo->m_actions)
	{
		if(hk.m_hotkey == ch)
		{
			m_parent->run_action(&hk);
			return STA_NONE;
		}
	}

	return STA_PARENT_HANDLE;
}

void curses_spectro::recreate_win(int h)
{
	delwin(m_tblwin);
	
	if(h != 0)
	{
		m_h = h;
	}
	
	m_tblwin = newwin(m_h, m_w, m_table_y_start, m_table_x_start);
	render(true);
}

#endif // NOCURSESUI
#endif // CSYSDIG
