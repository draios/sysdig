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

#ifdef SYSTOP
#define TABLE_WIDTH 400
#define TABLE_Y_START 2
#define SIDEMENU_WIDTH 20

#include <curses.h>

class sinsp_filter_check_reference;
class curses_table;
class sinsp_cursesui;

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

class curses_table_sidemenu : public curses_scrollable_list
{
public:
	curses_table_sidemenu(curses_table* parent);
	~curses_table_sidemenu();
	void render();
	sysdig_table_action handle_input(int ch);

	WINDOW* m_win;
	int32_t m_y_start;
	curses_table* m_parent;
};

class curses_table : public curses_scrollable_list
{
public:
	curses_table();
	~curses_table();

	void configure(sinsp_cursesui* parent, sinsp_table* table, 
		vector<int32_t>* colsizes, vector<string>* colnames);
	void update_data(vector<sinsp_sample_row>* data);
	void render(bool data_changed);
	void scrollwin(uint32_t x, uint32_t y);
	sysdig_table_action handle_input(int ch);
	sinsp_table_field_storage m_last_key;

	bool m_drilled_up;
	curses_table_sidemenu* m_sidemenu;
	vector<sidemenu_list_entry> m_sidemenu_viewlist;
	
private:
	void update_rowkey(int32_t row);

	WINDOW* m_tblwin;
	sinsp_cursesui* m_parent;
	sinsp_table* m_table;
	int32_t m_table_x_start;
	uint32_t m_table_y_start;
	uint32_t m_screenw;
	uint32_t m_screenh;
	uint32_t m_scrolloff_x;
	uint32_t m_scrolloff_y;
	uint32_t m_colsizes[PT_MAX];
	vector<curses_table_column_info> m_legend;
	vector<sinsp_sample_row>* m_data;
	sinsp_filter_check_reference* m_converter;
	vector<uint32_t> m_column_startx;

	friend class curses_table_sidemenu;
};

#endif