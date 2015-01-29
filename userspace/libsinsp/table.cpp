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

#include <curses.h>


#include "sinsp.h"
#include "sinsp_int.h"
#include "../../driver/ppm_ringbuffer.h"
#include "filter.h"
#include "filterchecks.h"
#include "table.h"

extern sinsp_filter_check_list g_filterlist;

sinsp_table::sinsp_table(sinsp* inspector)
{
	m_inspector = inspector;
	m_is_key_present = false;
	m_field_pointers = NULL;
	m_n_fields = 0;
	m_refresh_interval = SINSP_TABLE_DEFAULT_REFRESH_INTERVAL_NS;
	m_next_flush_time_ns = 0;
	m_printer = new sinsp_filter_check_reference();
	m_buffer = &m_buffer1;
}

sinsp_table::~sinsp_table()
{
	uint32_t j;

	for(j = 0; j < m_chks_to_free.size(); j++)
	{
		delete m_chks_to_free[j];
	}

	if(m_field_pointers != NULL)
	{
		delete[] m_field_pointers;
	}

	delete m_printer;
}

void sinsp_table::configure(const string& fmt)
{
	uint32_t j;
	string lfmt(fmt);

	if(lfmt == "")
	{
		throw sinsp_exception("empty table initializer");
	}

	//
	// Parse the string and extract the tokens
	//
	const char* cfmt = lfmt.c_str();

	m_extractors.clear();
	uint32_t lfmtlen = (uint32_t)lfmt.length();

	for(j = 0; j < lfmtlen;)
	{
		uint32_t preamble_len = 0;
		bool is_this_the_key = false;

		if(cfmt[j] == '*')
		{
			if(m_is_key_present)
			{
				throw sinsp_exception("invalid table configuration");
			}

			m_is_key_present = true;
			is_this_the_key = true;
			preamble_len = 1;
		}

		if(j == lfmtlen - 1)
		{
			throw sinsp_exception("invalid table configuration");
		}

		sinsp_filter_check* chk = g_filterlist.new_filter_check_from_fldname(string(cfmt + j + preamble_len), 
			m_inspector, 
			false);

		if(chk == NULL)
		{
			throw sinsp_exception("invalid table token " + string(cfmt + j + preamble_len));
		}

		m_chks_to_free.push_back(chk);

		j += chk->parse_field_name(cfmt + j + preamble_len) + preamble_len;
		ASSERT(j <= lfmt.length());

		while(cfmt[j] == ' ' || cfmt[j] == '\t' || cfmt[j] == ',')
		{
			j++;
		}

		if(is_this_the_key)
		{
			m_extractors.insert(m_extractors.begin(), chk);
		}
		else
		{
			m_extractors.push_back(chk);
		}
	}

	m_field_pointers = new sinsp_table_field[m_extractors.size()];
	m_n_fields = (uint32_t)m_extractors.size();

	//
	// Make sure this is a valid table
	//
	if(!m_is_key_present)
	{
		throw sinsp_exception("table is missing a key");
	}

	if(m_n_fields < 2)
	{
		throw sinsp_exception("table has no values");
	}

	for(auto it = m_extractors.begin(); it != m_extractors.end(); ++it)
	{
		m_types.push_back((*it)->get_field_info()->m_type);
		m_legend.push_back(*(*it)->get_field_info());
	}

	m_vals_array_size = (m_n_fields - 1) * sizeof(sinsp_table_field);
}

int puppo = 0;
bool sinsp_table::process_event(sinsp_evt* evt)
{
	bool res = false;
	uint32_t j;

	if(evt == NULL || evt->get_ts() > m_next_flush_time_ns)
	{
		flush(evt);
		res = true;
	}

	for(j = 0; j < m_n_fields; j++)
	{
		uint32_t len;
		uint8_t* val = m_extractors[j]->extract(evt, &len);

		//
		// XXX For the moment, we drop samples that contain empty values.
		// At a certain point we will want to introduce the concept of zero
		// by default.
		//
		if(val == NULL)
		{
			return res;
		}

		sinsp_table_field* pfld = &(m_field_pointers[j]);

		pfld->m_val = val;
		pfld->m_len = get_field_len(j);
	}

	sinsp_table_field key(m_field_pointers[0].m_val, m_field_pointers[0].m_len);
	auto it = m_table.find(key);

	sinsp_table_field* vals;

	if(it == m_table.end())
	{
		//
		// New entry
		//
		key.m_val = m_buffer->copy(key.m_val, key.m_len);
		vals = (sinsp_table_field*)m_buffer->reserve(m_vals_array_size);

		for(j = 1; j < m_n_fields; j++)
		{
			uint32_t vlen = get_field_len(j);
			vals[j - 1].m_val = m_buffer->copy(m_field_pointers[j].m_val, vlen);
			vals[j - 1].m_len = vlen;
		}

		m_table[key] = vals;
	}
	else
	{
		//
		// Existing entry
		//
		vals = it->second;

		for(j = 1; j < m_n_fields; j++)
		{
			add_fields(m_types[j], &(vals[j - 1]), &m_field_pointers[j]);
		}
	}

	return res;
}

void sinsp_table::flush(sinsp_evt* evt)
{
	if(m_next_flush_time_ns != 0)
	{
		for(auto it = m_table.begin(); it != m_table.end(); ++it)
		{
			m_printer->set_val(m_types[0], it->first.m_val, it->first.m_len);
//			printf("%s", m_printer->tostring(NULL));

			for(uint32_t j = 1; j < m_n_fields; j++)
			{
				m_printer->set_val(m_types[j], it->second[j - 1].m_val, it->second[j - 1].m_len);
//				printf(" %s", m_printer->tostring(NULL));
			}

//			printf("\n");
		}

//		printf("----------------------\n");

		create_sample();
mvprintw(4, 10, "!!%d", (int)m_sample_data.size());
refresh();

		switch_buffers();
		m_buffer->clear();
		m_table.clear();
	}

	uint64_t ts = evt->get_ts();
	m_next_flush_time_ns = ts - (ts % m_refresh_interval) + m_refresh_interval;

	return;
}

vector<vector<sinsp_table_field>>* sinsp_table::get_sample(uint32_t sorting_col)
{
	return &m_sample_data;
}

void sinsp_table::create_sample()
{
	uint32_t j;
	m_sample_data.clear();
	vector<sinsp_table_field> row;

	for(auto it = m_table.begin(); it != m_table.end(); ++it)
	{
		row.clear();

		sinsp_table_field* fields = it->second;
		for(j = 0; j < m_n_fields - 1; j++)
		{
			row.push_back(fields[j]);
		}

		m_sample_data.push_back(row);
	}
}

void sinsp_table::add_fields(ppm_param_type type, sinsp_table_field *dst, sinsp_table_field *src)
{
	uint8_t* operand1 = dst->m_val;
	uint8_t* operand2 = src->m_val;

	switch(type)
	{
	case PT_INT8:
		*(int8_t*)operand1 += *(int8_t*)operand2;
		return;
	case PT_INT16:
		*(int16_t*)operand1 += *(int16_t*)operand2;
		return;
	case PT_INT32:
		*(int32_t*)operand1 += *(int32_t*)operand2;
		return;
	case PT_INT64:
		*(int64_t*)operand1 += *(int64_t*)operand2;
		return;
	case PT_UINT8:
		*(uint8_t*)operand1 += *(uint8_t*)operand2;
		return;
	case PT_UINT16:
		*(uint16_t*)operand1 += *(uint16_t*)operand2;
		return;
	case PT_UINT32:
		*(uint32_t*)operand1 += *(uint32_t*)operand2;
		return;
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
		*(uint64_t*)operand1 += *(uint64_t*)operand2;
		return;
	default:
		return;
	}
}

uint32_t sinsp_table::get_field_len(uint32_t id)
{
	ppm_param_type type = m_types[id];
	sinsp_table_field *fld = &(m_field_pointers[id]);

	switch(type)
	{
	case PT_INT8:
		return 1;
	case PT_INT16:
		return 2;
	case PT_INT32:
		return 4;
	case PT_INT64:
	case PT_FD:
	case PT_PID:
	case PT_ERRNO:
		return 8;
	case PT_FLAGS8:
	case PT_UINT8:
	case PT_SIGTYPE:
		return 1;
	case PT_FLAGS16:
	case PT_UINT16:
	case PT_PORT:
	case PT_SYSCALLID:
		return 2;
	case PT_UINT32:
	case PT_FLAGS32:
	case PT_BOOL:
	case PT_IPV4ADDR:
		return 4;
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
		return 8;
	case PT_CHARBUF:
		return (uint32_t)(strlen((char*)fld->m_val) + 1);
	case PT_BYTEBUF:
		return fld->m_len;
	case PT_SOCKADDR:
	case PT_SOCKTUPLE:
	case PT_FDLIST:
	case PT_FSPATH:
	default:
		ASSERT(false);
		return false;
	}
}

void sinsp_table::switch_buffers()
{
	if(m_buffer == &m_buffer1)
	{
		m_buffer = &m_buffer2;
	}
	else
	{
		m_buffer = &m_buffer1;
	}
}
