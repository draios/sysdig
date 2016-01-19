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

#ifdef CSYSDIG
#ifndef NOCURSESUI

class colpalette_entry
{
public:
	colpalette_entry(int color, char ch)
	{
		m_color = color;
		m_char = ch;
	}

	int m_color;
	char m_char;
};

class curses_spectro_history_row
{
public:
	uint64_t m_ts;
	vector<uint32_t> m_data;

	void clear(uint64_t ts)
	{
		m_ts = ts;
		m_data.clear();
	}

	void push_back(uint32_t val)
	{
		m_data.push_back(val);
	}
};

class curses_spectro : 
	public sinsp_chart
{
public:
	enum alignment
	{
		ALIGN_LEFT,
		ALIGN_RIGHT,
	};

	curses_spectro(sinsp_cursesui* parent, sinsp* inspector);
	~curses_spectro();

	void configure(sinsp_table* table);
	void update_data(vector<sinsp_sample_row>* data, bool force_selection_change = false);
	void render(bool data_changed);
	sysdig_table_action handle_input(int ch);
	void set_x_start(uint32_t x)
	{
		m_table_x_start = x;
	}
	void recreate_win(int h);
	uint32_t get_data_size()
	{
		if(m_table != NULL)
		{
			return m_data->size();
		}
		else
		{
			return 0;
		}
	}
	bool get_position(OUT int32_t* pos,	OUT int32_t* totlines, OUT float* percent, OUT bool* truncated)
	{
		return false;
	}

	sinsp_table_field_storage m_last_key;
	bool m_drilled_up;
	bool m_selection_changed;
	MEVENT m_last_mevent;
	
private:
	void print_error(string wstr);
	uint32_t mkcol(uint64_t n);
	void draw_axis();
	void draw_menu();

	sinsp* m_inspector;
	WINDOW* m_tblwin;
	sinsp_cursesui* m_parent;
	sinsp_table* m_table;
	int32_t m_table_x_start;
	uint32_t m_table_y_start;
	vector<curses_table_column_info> m_legend;
	vector<sinsp_sample_row>* m_data;
	uint32_t m_w;
	uint32_t m_h;
	vector<uint32_t> m_colpalette;
	sinsp_filter_check_reference* m_converter;
	uint64_t m_n_flushes;
	vector<curses_spectro_history_row> m_history;
	curses_spectro_history_row m_t_row;
	bool m_mouse_masked;

	friend class curses_spectro_sidemenu;
};

#endif // NOCURSESUI
#endif // CSYSDIG