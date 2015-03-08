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

class curses_table : public curses_scrollable_list
{
public:
	enum alignment
	{
		ALIGN_LEFT,
		ALIGN_RIGHT,
	};

	curses_table(sinsp_cursesui* parent, sinsp* inspector);
	~curses_table();

	void configure(sinsp_table* table, 
		vector<int32_t>* colsizes, vector<string>* colnames);
	void update_data(vector<sinsp_sample_row>* data);
	void render(bool data_changed);
	void scrollwin(uint32_t x, uint32_t y);
	sysdig_table_action handle_input(int ch);
	void set_x_start(uint32_t x)
	{
		m_table_x_start = x;
	}
	void recreate_win();

	sinsp_table_field_storage m_last_key;
	bool m_drilled_up;
	bool m_selection_changed;
	
private:
	void update_rowkey(int32_t row);
	alignment get_field_alignment(ppm_param_type type);
	void print_nomatch();
	void print_wait();

	sinsp* m_inspector;
	WINDOW* m_tblwin;
	sinsp_cursesui* m_parent;
	sinsp_table* m_table;
	int32_t m_table_x_start;
	uint32_t m_table_y_start;
	uint32_t m_scrolloff_x;
	uint32_t m_scrolloff_y;
	uint32_t m_colsizes[PT_MAX];
	vector<curses_table_column_info> m_legend;
	vector<sinsp_sample_row>* m_data;
	sinsp_filter_check_reference* m_converter;
	vector<uint32_t> m_column_startx;
	char alignbuf[64];

	friend class curses_table_sidemenu;
};

#endif