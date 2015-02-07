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

#ifndef _WIN32
#include <unistd.h>
#endif

class sinsp_table_info
{
public:
	sinsp_table_info()
	{
		m_colsizes = NULL;
	}

	sinsp_table_info(string name, string config, uint32_t sortingcol = 1, string merge_config = "", vector<int32_t>* colsizes = NULL)
	{
		m_name = name;
		m_config = config;
		m_merge_config = merge_config;
		m_colsizes = colsizes;
		m_sortingcol = sortingcol;
	}

	string m_name;
	string m_config;
	string m_merge_config;
	vector<int32_t>* m_colsizes;
	uint32_t m_sortingcol;
};

class sinsp_cursesui
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

	sinsp_cursesui(sinsp* inspector);
	~sinsp_cursesui();
	void configure(vector<sinsp_table_info>* views);
	void start();
	sinsp_table_info* get_selected_view();

	//
	// Return true if the application is supposed to exit
	//
	inline bool process_event(sinsp_evt* evt)
	{
		bool end_of_sample;

#ifndef NOCURSESUI
		int input = getch();
#endif

#ifndef NOCURSESUI
		sysdig_table_action ta = m_viz->handle_input(input);
		if(ta == STA_QUIT)
		{
			return true;
		}
		else if(ta == STA_SWITCH_VIEW)
		{
			clear();
			start();
			m_viz->render(true);
			render();
		}
#endif

		//
		// Check if it's time to flush
		//
		end_of_sample = (evt == NULL || evt->get_ts() > m_datatable->m_next_flush_time_ns);

		if(end_of_sample)
		{
			m_datatable->flush(evt);

			//
			// It's time to refresh the data for this chart.
			// First of all, render the chart
			//
			vector<sinsp_sample_row>* sample = 
				m_datatable->get_sample();

#ifndef NOCURSESUI
			m_viz->update_data(sample);
			m_viz->render(true);

			//
			// Now refresh the UI.
			//
			render();

			if(!m_inspector->is_live())
			{
				while(getch() != 'a')
				{
mvprintw(4, 10, "aaa");
refresh();						
					usleep(100000);
				}
			}
#endif				
		}

		m_datatable->process_event(evt);

		return false;
	}

	int m_colors[LAST_COLORELEMENT];
	vector<sinsp_table_info> m_views;
	uint32_t m_selected_view;

private:
#ifndef NOCURSESUI
	void render();
	void render_header();
	void render_main_menu();
#endif
	sinsp* m_inspector;
	vector<string> m_menuitems;
	uint32_t m_screenw;
	uint32_t m_screenh;
	sinsp_table* m_datatable;
	curses_table* m_viz;
};
