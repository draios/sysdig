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
#define TABLE_HEIGHT 20
#define TABLE_Y_START 1
#define SIDEMENU_WIDTH 20

#define ColorPair(i,j) COLOR_PAIR((7-i)*8+j)

class sinsp_filter_check_reference;
class curses_table;

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
	enum ColorElements_ {
		RESET_COLOR,
		DEFAULT_COLOR,
		FUNCTION_BAR,
		FUNCTION_KEY,
		FAILED_SEARCH,
		PANEL_HEADER_FOCUS,
		PANEL_HEADER_UNFOCUS,
		PANEL_HIGHLIGHT_FOCUS,
		PANEL_HIGHLIGHT_UNFOCUS,
		LARGE_NUMBER,
		METER_TEXT,
		METER_VALUE,
		LED_COLOR,
		UPTIME,
		BATTERY,
		TASKS_RUNNING,
		SWAP,
		PROCESS,
		PROCESS_SHADOW,
		PROCESS_TAG,
		PROCESS_MEGABYTES,
		PROCESS_TREE,
		PROCESS_R_STATE,
		PROCESS_D_STATE,
		PROCESS_BASENAME,
		PROCESS_HIGH_PRIORITY,
		PROCESS_LOW_PRIORITY,
		PROCESS_THREAD,
		PROCESS_THREAD_BASENAME,
		BAR_BORDER,
		BAR_SHADOW,
		GRAPH_1,
		GRAPH_2,
		GRAPH_3,
		GRAPH_4,
		GRAPH_5,
		GRAPH_6,
		GRAPH_7,
		GRAPH_8,
		GRAPH_9,
		MEMORY_USED,
		MEMORY_BUFFERS,
		MEMORY_BUFFERS_TEXT,
		MEMORY_CACHE,
		LOAD,
		LOAD_AVERAGE_FIFTEEN,
		LOAD_AVERAGE_FIVE,
		LOAD_AVERAGE_ONE,
		CHECK_BOX,
		CHECK_MARK,
		CHECK_TEXT,
		CLOCK,
		HELP_BOLD,
		HOSTNAME,
		CPU_NICE,
		CPU_NICE_TEXT,
		CPU_NORMAL,
		CPU_KERNEL,
		CPU_IOWAIT,
		CPU_IRQ,
		CPU_SOFTIRQ,
		CPU_STEAL,
		CPU_GUEST,
		LAST_COLORELEMENT
	};

	curses_table();
	~curses_table();

	void configure(sinsp_table* m_table, 
		vector<int32_t>* colsizes,
		vector<sinsp_table_info>* views);
	void update_data(vector<sinsp_sample_row>* data);
	void render(bool data_changed);
	void scrollwin(uint32_t x, uint32_t y);
	sysdig_table_action handle_input(int ch);

private:
	void update_rowkey(int32_t row);
	void render_main_menu();

	int m_colors[LAST_COLORELEMENT];
	WINDOW* m_tblwin;
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
	sinsp_table_field_storage m_last_key;
	vector<string> m_menuitems;
	curses_table_sidemenu* m_sidemenu;
	vector<sinsp_table_info> m_views;
	uint32_t m_selected_view;

	friend class curses_table_sidemenu;
};

#endif