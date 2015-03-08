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

class sidemenu_list_entry
{
public:
	sidemenu_list_entry(string viewname, uint32_t viewid)
	{
		m_viewname = viewname;
		m_viewid = viewid;
	}

	string m_viewname;
	uint32_t m_viewid;
};

#ifdef SYSTOP
#define TABLE_WIDTH 400
#define TABLE_Y_START 2

#include <curses.h>

class sinsp_filter_check_reference;
class curses_table;
class sinsp_cursesui;
class ctext;

class curses_table_column_info
{
public:	
	curses_table_column_info()
	{
	}

	//
	// Use -1 as size for atuosize
	//
	curses_table_column_info(IN filtercheck_field_info* info, int32_t size)
	{
		m_info = *info;
		m_size = size;
	}

//private:
	filtercheck_field_info m_info;
	int32_t m_size;
	string m_name;

	friend class curses_table;
};

class curses_scrollable_list
{
public:
	curses_scrollable_list();
	void sanitize_selection(int32_t datasize);
	void selection_up(int32_t datasize);
	void selection_down(int32_t datasize);
	void selection_pageup(int32_t datasize);
	void selection_pagedown(int32_t datasize);
	void selection_goto(int32_t datasize, int32_t row);

	int32_t m_selct;
	int32_t m_firstrow;
	uint32_t m_w;
	uint32_t m_h;
};

class curses_table_sidemenu : public curses_scrollable_list
{
public:
	curses_table_sidemenu(sinsp_cursesui* parent);
	~curses_table_sidemenu();
	void render();
	sysdig_table_action handle_input(int ch);

	WINDOW* m_win;
	int32_t m_y_start;
	sinsp_cursesui* m_parent;
};

class curses_textbox
{
public:
	curses_textbox(sinsp* inspector, sinsp_cursesui* parent);
	~curses_textbox();
	//void render();
	void set_filter(string filter);
	void process_event(sinsp_evt* evt, int32_t next_res);
	sysdig_table_action handle_input(int ch);

	WINDOW *m_win;
	ctext* m_ctext;
	sinsp_filter_check_reference* m_printer;
	sinsp_cursesui* m_parent;
	sinsp* m_inspector;
	sinsp_filter* m_filter;
};

#endif