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
	sidemenu_list_entry(string name, uint32_t id)
	{
		m_name = name;
		m_id = id;
	}

	string m_name;
	uint32_t m_id;
};

#ifdef SYSTOP
#define TABLE_WIDTH 400
#define TABLE_Y_START 2

#include <curses.h>

class sinsp_filter_check_reference;
class curses_table;
class sinsp_cursesui;
class ctext;
class sinsp_evt_formatter;

class sinsp_chart
{
public:
	virtual ~sinsp_chart()
	{

	}

	//
	// Retuens false if this chart doesn't support returning the current position
	//
	virtual bool get_position(OUT int32_t* pos, 
		OUT int32_t* totlines, 
		OUT float* percent,
		OUT bool* truncated) = 0;
};

class curses_table_column_info
{
public:	
	curses_table_column_info()
	{
	}

	//
	// Use -1 as size for autosize
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
	int32_t m_selct_ori;
	int32_t m_firstrow;
	uint32_t m_w;
	uint32_t m_h;
};

class curses_table_sidemenu : public curses_scrollable_list
{
public:
	curses_table_sidemenu(sinsp_cursesui* parent);
	~curses_table_sidemenu();
	void set_entries(vector<sidemenu_list_entry>* entries)
	{
		m_entries = entries;
	}
	void set_title(string title)
	{
		m_title = title;
	}
	void render();
	sysdig_table_action handle_input(int ch);

	WINDOW* m_win;
	int32_t m_y_start;
	sinsp_cursesui* m_parentui;
	vector<sidemenu_list_entry>* m_entries;
	string m_title;
};

class curses_textbox : public sinsp_chart
{
public:
	curses_textbox(sinsp* inspector, sinsp_cursesui* parent, int32_t viz_type);
	~curses_textbox();
	void render();
	void set_filter(string filter);
	void print_no_data();
	void process_event(sinsp_evt* evt, int32_t next_res);
	void render_header();
	sysdig_table_action handle_input(int ch);
	void populate_sidemenu();
	void reset();
	bool get_position(OUT int32_t* pos, OUT int32_t* totlines, OUT float* percent, OUT bool* truncated);

private:
	inline void process_event_spy(sinsp_evt* evt, int32_t next_res);
	inline void process_event_dig(sinsp_evt* evt, int32_t next_res);

	WINDOW *m_win;
	ctext* m_ctext;
	sinsp_cursesui* m_parent;
	sinsp* m_inspector;
	sinsp_filter* m_filter;
	uint32_t n_prints;
	bool m_paused;
	curses_table_sidemenu* m_sidemenu;
	vector<sidemenu_list_entry> m_entries;
	int32_t m_viz_type;
	sinsp_evt_formatter* m_formatter;
};

#endif