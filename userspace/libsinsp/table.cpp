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

#include <algorithm>
#ifndef _WIN32
#include <curses.h>
#endif

#include "sinsp.h"
#include "sinsp_int.h"
#include "../../driver/ppm_ringbuffer.h"
#include "filter.h"
#include "filterchecks.h"
#include "table.h"

extern sinsp_filter_check_list g_filterlist;
extern sinsp_evttables g_infotables;

//
//
// Table sorter functor
typedef struct table_row_cmp
{
	bool operator()(const sinsp_sample_row& src, const sinsp_sample_row& dst)
	{
		ppm_cmp_operator op;

		if(m_ascending)
		{
			op = CO_LT;
		}
		else
		{
			op = CO_GT;
		}

		return flt_compare(op, m_type, 
			src.m_values[m_colid].m_val, 
			dst.m_values[m_colid].m_val, 
			src.m_values[m_colid].m_len, 
			dst.m_values[m_colid].m_len);
	}

	uint32_t m_colid;
	ppm_param_type m_type;
	bool m_ascending;
}table_row_cmp;

sinsp_table::sinsp_table(sinsp* inspector)
{
	m_inspector = inspector;
	m_is_key_present = false;
	m_is_merge_key_present = false;
	m_fld_pointers = NULL;
	m_premerge_fld_pointers = NULL;
	m_postmerge_fld_pointers = NULL;
	m_n_fields = 0;
	m_n_premerge_fields = 0;
	m_n_postmerge_fields = 0;
	m_refresh_interval = 2LL * SINSP_TABLE_DEFAULT_REFRESH_INTERVAL_NS;
	m_next_flush_time_ns = 0;
	m_printer = new sinsp_filter_check_reference();
	m_buffer = &m_buffer1;
	m_is_sorting_ascending = false;
	m_sorting_col = -1;
	m_do_merging = true;
	m_types = &m_premerge_types;
	m_table = &m_premerge_table;
	m_filter = NULL;
	m_use_defaults = false;
	m_zero_u64 = 0;
	m_zero_double = 0;
	m_paused = false;
}

sinsp_table::~sinsp_table()
{
	uint32_t j;

	for(j = 0; j < m_chks_to_free.size(); j++)
	{
		delete m_chks_to_free[j];
	}

	if(m_premerge_fld_pointers != NULL)
	{
		delete[] m_premerge_fld_pointers;
	}

	if(m_postmerge_fld_pointers != NULL)
	{
		delete[] m_postmerge_fld_pointers;
	}

	delete m_printer;
}

void sinsp_table::configure(const string& fmt, const string& merge_fmt, const string& filter)
{
	uint32_t j;
	string lfmt(fmt);

	if(lfmt == "")
	{
		throw sinsp_exception("empty table initializer");
	}

	//////////////////////////////////////////////////////////////////////////////////////
	// If a filter has been spefied, compile it
	//////////////////////////////////////////////////////////////////////////////////////
	if(filter != "")
	{
		m_filter = new sinsp_filter(m_inspector, filter);
	}

	//////////////////////////////////////////////////////////////////////////////////////
	// Parse the format string and extract the tokens
	//////////////////////////////////////////////////////////////////////////////////////
	const char* cfmt = lfmt.c_str();

	m_extractors.clear();
	uint32_t lfmtlen = (uint32_t)lfmt.length();

	for(j = 0; j < lfmtlen;)
	{
		uint32_t preamble_len = 0;
		bool is_this_the_key = false;
		sinsp_filter_check::aggregation ag = sinsp_filter_check::A_NONE;
		bool continue_loop = false;

		switch(cfmt[j])
		{
			case '*':
				if(j == 0)
				{
					j++;
					m_use_defaults = true;
					continue_loop = true;
				}
				break;
			case 'K':
				if(m_is_key_present)
				{
					throw sinsp_exception("invalid table configuration");
				}

				m_is_key_present = true;
				is_this_the_key = true;
				preamble_len = 1;
				break;
			case 'S':
				ag = sinsp_filter_check::A_SUM;
				preamble_len = 1;
				break;
			case 'T':
				ag = sinsp_filter_check::A_TIME_AVG;
				preamble_len = 1;
				break;
			case 'A':
				ag = sinsp_filter_check::A_AVG;
				preamble_len = 1;
				break;
			case 'm':
				ag = sinsp_filter_check::A_MIN;
				preamble_len = 1;
				break;
			case 'M':
				ag = sinsp_filter_check::A_MAX;
				preamble_len = 1;
				break;
			default:
				break;
		}

		if(continue_loop)
		{
			continue;
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

		chk->m_aggregation = ag;
		m_chks_to_free.push_back(chk);

		j += chk->parse_field_name(cfmt + j + preamble_len, true) + preamble_len;
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

	m_premerge_fld_pointers = new sinsp_table_field[m_extractors.size()];
	m_fld_pointers = m_premerge_fld_pointers;
	m_n_premerge_fields = (uint32_t)m_extractors.size();
	m_n_fields = m_n_premerge_fields;

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
		m_premerge_types.push_back((*it)->get_field_info()->m_type);
		m_premerge_legend.push_back(*(*it)->get_field_info());
	}

	m_premerge_vals_array_sz = (m_n_fields - 1) * sizeof(sinsp_table_field);
	m_vals_array_sz = m_premerge_vals_array_sz;

	//////////////////////////////////////////////////////////////////////////////////////
	// If a merge has been specified, configure it 
	//////////////////////////////////////////////////////////////////////////////////////
	if(merge_fmt == "")
	{
		//
		// No merge string. We can stop here
		//
		m_do_merging = false;
		return;
	}

	char* cmfmt = (char*)merge_fmt.c_str();
	uint32_t mfmtlen = (uint32_t)merge_fmt.length();

	for(j = 0; j < mfmtlen;)
	{
		uint32_t preamble_len = 0;
		bool is_this_the_key = false;
		sinsp_filter_check::aggregation ag = sinsp_filter_check::A_NONE;

		switch(cmfmt[j])
		{
			case 'K':
				if(m_is_merge_key_present)
				{
					throw sinsp_exception("invalid table configuration");
				}

				m_is_merge_key_present = true;
				is_this_the_key = true;
				preamble_len = 1;
				break;
			case 'S':
				ag = sinsp_filter_check::A_SUM;
				preamble_len = 1;
				break;
			case 'T':
				ag = sinsp_filter_check::A_TIME_AVG;
				preamble_len = 1;
				break;
			case 'm':
				ag = sinsp_filter_check::A_MIN;
				preamble_len = 1;
				break;
			case 'M':
				ag = sinsp_filter_check::A_MAX;
				preamble_len = 1;
				break;
			default:
				break;
		}

		if(j == mfmtlen - 1)
		{
			throw sinsp_exception("invalid table merge configuration");
		}

		char* scnum = cmfmt + j + preamble_len;
		uint32_t cnum; 
		uint32_t ns = sscanf(scnum, "%" PRIu32, &cnum);

		if(ns != 1 || cnum >= m_n_fields)
		{
			throw sinsp_exception("invalid table merge identifier");
		}

		m_merge_columns.push_back(cnum);

		sinsp_filter_check* chk = m_extractors[cnum];

		chk->m_merge_aggregation = ag;

		if(is_this_the_key)
		{
			m_mergers.insert(m_mergers.begin(), chk);
		}
		else
		{
			m_mergers.push_back(chk);
		}

		//
		// Go to the end of the string
		//
		j += preamble_len + 1;
		while(j < mfmtlen && (cmfmt[j] != ' ' && cmfmt[j] != '\t' && cmfmt[j] != ','))
		{
			j++;
		}

		//
		// Skip spaces
		//
		while(j < mfmtlen && (cmfmt[j] == ' ' || cmfmt[j] == '\t' || cmfmt[j] == ','))
		{
			j++;
		}
	}

	m_postmerge_fld_pointers = new sinsp_table_field[m_mergers.size()];
	m_n_postmerge_fields = (uint32_t)m_mergers.size();

	if(!m_is_merge_key_present)
	{
		throw sinsp_exception("table is missing the merge key");
	}

	if(m_merge_columns.size() < 2)
	{
		throw sinsp_exception("merged table has no values");
	}

	for(auto it = m_mergers.begin(); it != m_mergers.end(); ++it)
	{
		m_postmerge_types.push_back((*it)->get_field_info()->m_type);
		m_postmerge_legend.push_back(*(*it)->get_field_info());
	}

	m_postmerge_vals_array_sz = (m_n_postmerge_fields - 1) * sizeof(sinsp_table_field);
}

void sinsp_table::add_row(bool merging)
{
	uint32_t j;

	sinsp_table_field key(m_fld_pointers[0].m_val, 
		m_fld_pointers[0].m_len,
		m_fld_pointers[0].m_cnt);

	auto it = m_table->find(key);

	if(it == m_table->end())
	{
		//
		// New entry
		//
		key.m_val = m_buffer->copy(key.m_val, key.m_len);
		key.m_cnt = 1;
		m_vals = (sinsp_table_field*)m_buffer->reserve(m_vals_array_sz);

		for(j = 1; j < m_n_fields; j++)
		{
			uint32_t vlen = get_field_len(j);
			m_vals[j - 1].m_val = m_buffer->copy(m_fld_pointers[j].m_val, vlen);
			m_vals[j - 1].m_len = vlen;
			m_vals[j - 1].m_cnt = 1;
		}

		(*m_table)[key] = m_vals;
	}
	else
	{
		//
		// Existing entry
		//
		m_vals = it->second;

		for(j = 1; j < m_n_fields; j++)
		{
			if(merging)
			{
				add_fields(j, &m_fld_pointers[j], m_mergers[j]->m_merge_aggregation);
			}
			else
			{
				add_fields(j, &m_fld_pointers[j], m_extractors[j]->m_aggregation);
			}
		}
	}
}

void sinsp_table::process_event(sinsp_evt* evt)
{
	uint32_t j;

	//
	// Apply the filter
	//
	if(m_filter)
	{
		if(!m_filter->run(evt))
		{
			return;
		}
	}

	//
	// Extract the values and create the row to add
	//
	for(j = 0; j < m_n_premerge_fields; j++)
	{
		uint32_t len;
		uint8_t* val = m_extractors[j]->extract(evt, &len);

		sinsp_table_field* pfld = &(m_premerge_fld_pointers[j]);

		//
		// XXX For the moment, we only support defaults for numeric fields.
		// At a certain point we will want to introduce the concept of zero
		// for other fields too.
		//
		if(val == NULL)
		{
			if(m_use_defaults)
			{
				pfld->m_val = get_default_val(&m_premerge_legend[j]);
				if(pfld->m_val == NULL)
				{
					return;
				}

				pfld->m_cnt = 1;
			}
			else
			{
				return;
			}
		}
		else
		{
			pfld->m_val = val;
			pfld->m_cnt = 1;
		}

		pfld->m_len = get_field_len(j);
	}

	//
	// Add the row
	//
	add_row(false);

	return;
}

void sinsp_table::process_proctable(sinsp_evt* evt)
{
	sinsp_evt tevt;
	scap_evt tscapevt;

	threadinfo_map_t* threadtable  = m_inspector->m_thread_manager->get_threads();
	ASSERT(threadtable != NULL);

	uint64_t ts = evt->get_ts();
	uint64_t ts_s = ts - (ts % ONE_SECOND_IN_NS);
	tscapevt.ts = ts_s - 1;

	//
	// Note: as the event type for this fake event, we pick one of the unused
	//       numbers, so we guarantee that filter checks will not wrongly pick it up
	//
	tscapevt.type = PPME_SYSDIGEVENT_X;
	tscapevt.len = 0;

	tevt.m_inspector = m_inspector;
	tevt.m_info = &(g_infotables.m_event_info[PPME_SYSDIGEVENT_X]);
	tevt.m_pevt = NULL;
	tevt.m_cpuid = 0;
	tevt.m_evtnum = 0;
	tevt.m_pevt = &tscapevt;
	tevt.m_fdinfo = NULL;

	for(auto it = threadtable->begin(); it != threadtable->end(); ++it)
	{
		tevt.m_tinfo = &it->second;

		if(m_filter)
		{
			if(!m_filter->run(evt))
			{
				continue;
			}
		}

		process_event(&tevt);
	}
}

void sinsp_table::flush(sinsp_evt* evt)
{
	if(!m_paused)
	{
		if(m_next_flush_time_ns != 0)
		{
			//
			// Time to emit the sample! 
			// Add the proctable as a sample at the end of the second
			//
			process_proctable(evt);

			//
			// If there is a merging step, switch the types to point to the merging ones.
			//
			if(m_do_merging)
			{
				m_types = &m_postmerge_types;
				m_table = &m_merge_table;
				m_n_fields = m_n_postmerge_fields;
				m_vals_array_sz = m_postmerge_vals_array_sz;
				m_fld_pointers = m_postmerge_fld_pointers;
			}

			//
			// Emit the sample
			//
			create_sample();

			//
			// Switch the data storage so that the current one is still usable by the 
			// consumers of the table.
			//
			switch_buffers();

			//
			// Reinitialize the tables
			//
			m_buffer->clear();
			m_premerge_table.clear();
			m_merge_table.clear();
		}
	}

	uint64_t ts = evt->get_ts();
	m_next_flush_time_ns = ts - (ts % m_refresh_interval) + m_refresh_interval;

	return;
}

void sinsp_table::stdout_print(vector<sinsp_sample_row>* sample_data)
{
	vector<filtercheck_field_info>* legend = get_legend();

	for(auto it = sample_data->begin(); it != sample_data->end(); ++it)
	{
		for(uint32_t j = 0; j < m_n_fields - 1; j++)
		{
			m_printer->set_val(m_types->at(j + 1), 
				it->m_values[j].m_val, 
				it->m_values[j].m_len,
				it->m_values[j].m_cnt,
				legend->at(j + 1).m_print_format);
				printf("%s ", m_printer->tostring_nice(NULL, 10));
				//printf("%s ", m_printer->tostring(NULL));
		}

		printf("\n");
	}

	printf("----------------------\n");
}

void sinsp_table::filter_sample()
{
	vector<filtercheck_field_info>* legend = get_legend();

	m_filtered_sample_data.clear();

	for(auto it : m_full_sample_data)
	{
		for(uint32_t j = 0; j < it.m_values.size(); j++)
		{
			ppm_param_type type = m_types->at(j + 1);

			if(type == PT_CHARBUF || type == PT_BYTEBUF || type == PT_SYSCALLID ||
				type == PT_PORT || type == PT_L4PROTO || type == PT_SOCKFAMILY || type == PT_IPV4ADDR ||
				type == PT_UID || type == PT_GID)
			{
				m_printer->set_val(type, 
					it.m_values[j].m_val, 
					it.m_values[j].m_len,
					it.m_values[j].m_cnt,
					legend->at(j + 1).m_print_format);
					
				string strval = m_printer->tostring_nice(NULL, 0);

				if(strval.find(m_freetext_filter) != string::npos)
				{
					m_filtered_sample_data.push_back(it);
					break;
				}
			}
		}
	}
}

//
// Returns the key of the first match, or NULL if no match
//
sinsp_table_field* sinsp_table::search_in_sample(string text)
{
	vector<filtercheck_field_info>* legend = get_legend();

	for(auto it = m_full_sample_data.begin(); it != m_full_sample_data.end(); ++it)
	{
		for(uint32_t j = 0; j < it->m_values.size(); j++)
		{
			ppm_param_type type = m_types->at(j + 1);

			if(type == PT_CHARBUF || type == PT_BYTEBUF || type == PT_SYSCALLID ||
				type == PT_PORT || type == PT_L4PROTO || type == PT_SOCKFAMILY || type == PT_IPV4ADDR ||
				type == PT_UID || type == PT_GID)
			{
				m_printer->set_val(type,
					it->m_values[j].m_val,
					it->m_values[j].m_len,
					it->m_values[j].m_cnt,
					legend->at(j + 1).m_print_format);

				string strval = m_printer->tostring_nice(NULL, 0);

				if(strval.find(text) != string::npos)
				{
					return &(it->m_key);
				}
			}
		}
	}

	return NULL;
}

void sinsp_table::sort_sample()
{
	if(m_sample_data->size() != 0)
	{
		if(m_sorting_col >= (int32_t)m_sample_data->at(0).m_values.size())
		{
			throw sinsp_exception("invalid table sorting column");
		}

		table_row_cmp cc;
		cc.m_colid = m_sorting_col;

		cc.m_ascending = m_is_sorting_ascending;
		cc.m_type = m_types->at(m_sorting_col + 1);

//mvprintw(4, 10, "s%d:%d", (int)m_sorting_col, (int)m_is_sorting_ascending);
//refresh();

		sort(m_sample_data->begin(),
			m_sample_data->end(),
			cc);
	}
}

vector<sinsp_sample_row>* sinsp_table::get_sample()
{
	//
	// No sample generation happens when the table is paused
	//
	if(!m_paused)
	{
		//
		// If we have a freetext filter, we start by filtering the sample
		//
		if(m_freetext_filter != "")
		{
			filter_sample();
			m_sample_data = &m_filtered_sample_data;
		}
		else
		{
			m_sample_data = &m_full_sample_data;
		}

		//
		// Sort the sample
		//
		sort_sample();
	}

#ifdef _WIN32
	stdout_print(m_sample_data);
#endif

	//
	// Restore the lists used for event processing
	//
	m_types = &m_premerge_types;
	m_table = &m_premerge_table;
	m_n_fields = m_n_premerge_fields;
	m_vals_array_sz = m_premerge_vals_array_sz;
	m_fld_pointers = m_premerge_fld_pointers;

	return m_sample_data;
}

void sinsp_table::set_sorting_col(uint32_t col)
{
	uint32_t n_fields;
	vector<ppm_param_type>* types;

	if(m_do_merging)
	{
		n_fields = m_n_postmerge_fields;
		types = &m_postmerge_types;
	}
	else
	{
		n_fields = m_n_premerge_fields;
		types = &m_premerge_types;
	}

	if(col == 0)
	{
		throw sinsp_exception("cannot sort by key");
	}

	if(col >= n_fields)
	{
		throw sinsp_exception("invalid table sorting column");
	}

	if(col == (uint32_t)(m_sorting_col + 1))
	{
		m_is_sorting_ascending = !m_is_sorting_ascending;
	}
	else
	{
		switch(types->at(col))
		{
			case PT_INT8:
			case PT_INT16:
			case PT_INT32:
			case PT_INT64:
			case PT_UINT8:
			case PT_UINT16:
			case PT_UINT32:
			case PT_UINT64:
			case PT_RELTIME:
			case PT_ABSTIME:
			case PT_DOUBLE:
				m_is_sorting_ascending = false;
				break;
			default:
				m_is_sorting_ascending = true;
				break;
		}
	}

	m_sorting_col = col - 1;
}

void sinsp_table::create_sample()
{
	uint32_t j;
	m_full_sample_data.clear();
	sinsp_sample_row row;

	//
	// If merging is on, perform the merge and switch to the merged table 
	//
	if(m_do_merging)
	{
		m_table = &m_merge_table;
		m_merge_table.clear();

		for(auto it = m_premerge_table.begin(); it != m_premerge_table.end(); ++it)
		{
			for(j = 0; j < m_n_postmerge_fields; j++)
			{
				sinsp_table_field* pfld = &(m_postmerge_fld_pointers[j]);

				uint32_t col = m_merge_columns[j];
				if(col == 0)
				{
					pfld->m_val = it->first.m_val;
					pfld->m_len = it->first.m_len;
					pfld->m_cnt = it->first.m_cnt;
				}
				else
				{
					pfld->m_val = it->second[col - 1].m_val;
					pfld->m_len = it->second[col - 1].m_len;
					pfld->m_cnt = it->second[col - 1].m_cnt;
				}
			}

			add_row(true);
		}
	}
	else
	{
		m_table = &m_premerge_table;
	}

	//
	// Emit the table
	//
	for(auto it = m_table->begin(); it != m_table->end(); ++it)
	{
		row.m_key = it->first;

		row.m_values.clear();

		sinsp_table_field* fields = it->second;
		for(j = 0; j < m_n_fields - 1; j++)
		{
			row.m_values.push_back(fields[j]);
		}

		m_full_sample_data.push_back(row);
	}

}

void sinsp_table::add_fields_sum(ppm_param_type type, sinsp_table_field *dst, sinsp_table_field *src)
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
	case PT_DOUBLE:
		*(double*)operand1 += *(double*)operand2;
		return;
	default:
		return;
	}
}

void sinsp_table::add_fields_max(ppm_param_type type, sinsp_table_field *dst, sinsp_table_field *src)
{
	uint8_t* operand1 = dst->m_val;
	uint8_t* operand2 = src->m_val;

	switch(type)
	{
	case PT_INT8:
		if(*(int8_t*)operand1 < *(int8_t*)operand2)
		{
			*(int8_t*)operand1 = *(int8_t*)operand2;
		}
		return;
	case PT_INT16:
		if(*(int16_t*)operand1 < *(int16_t*)operand2)
		{
			*(int16_t*)operand1 = *(int16_t*)operand2;
		}
		return;
	case PT_INT32:
		if(*(int32_t*)operand1 < *(int32_t*)operand2)
		{
			*(int32_t*)operand1 = *(int32_t*)operand2;
		}
		return;
	case PT_INT64:
		if(*(int64_t*)operand1 < *(int64_t*)operand2)
		{
			*(int64_t*)operand1 = *(int64_t*)operand2;
		}
		return;
	case PT_UINT8:
		if(*(uint8_t*)operand1 < *(uint8_t*)operand2)
		{
			*(uint8_t*)operand1 = *(uint8_t*)operand2;
		}
		return;
	case PT_UINT16:
		if(*(uint16_t*)operand1 < *(uint16_t*)operand2)
		{
			*(uint16_t*)operand1 = *(uint16_t*)operand2;
		}
		return;
	case PT_UINT32:
		if(*(uint32_t*)operand1 < *(uint32_t*)operand2)
		{
			*(uint32_t*)operand1 = *(uint32_t*)operand2;
		}
		return;
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
		if(*(uint64_t*)operand1 < *(uint64_t*)operand2)
		{
			*(uint64_t*)operand1 = *(uint64_t*)operand2;
		}
		return;
	case PT_DOUBLE:
		if(*(double*)operand1 < *(double*)operand2)
		{
			*(double*)operand1 = *(double*)operand2;
		}
		return;
	case PT_CHARBUF:
	case PT_BYTEBUF:
		if(dst->m_len >= src->m_len)
		{
			memcpy(dst->m_val, src->m_val, src->m_len);
		}
		else
		{
			dst->m_val = m_buffer->copy(src->m_val, src->m_len);
		}

		dst->m_len = src->m_len;
	default:
		return;
	}
}

void sinsp_table::add_fields(uint32_t dst_id, sinsp_table_field* src, uint32_t aggr)
{
	ppm_param_type type = (*m_types)[dst_id];
	sinsp_table_field* dst = &(m_vals[dst_id - 1]);

	switch(aggr)
	{
	case sinsp_filter_check::A_NONE:
		return;
	case sinsp_filter_check::A_SUM:
		add_fields_sum(type, dst, src);		
		return;
	case sinsp_filter_check::A_AVG:
		dst->m_cnt++;
		add_fields_sum(type, dst, src);		
		return;
	case sinsp_filter_check::A_MAX:
		add_fields_max(type, dst, src);		
		return;
	default:
		ASSERT(false);
		return;
	}
}

uint32_t sinsp_table::get_field_len(uint32_t id)
{
	ppm_param_type type;
	sinsp_table_field *fld;

	type = (*m_types)[id];
	fld = &(m_fld_pointers[id]);

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
	case PT_DOUBLE:
		return sizeof(double);
	case PT_SOCKADDR:
	case PT_SOCKTUPLE:
	case PT_FDLIST:
	case PT_FSPATH:
	default:
		ASSERT(false);
		return false;
	}
}

uint8_t* sinsp_table::get_default_val(filtercheck_field_info* fld)
{
	switch(fld->m_type)
	{
	case PT_INT8:
	case PT_INT16:
	case PT_INT32:
	case PT_INT64:
	case PT_UINT8:
	case PT_UINT16:
	case PT_UINT32:
	case PT_UINT64:
		if(fld->m_print_format == PF_DEC)
		{
			return (uint8_t*)&m_zero_u64;
		}
		else
		{
			return NULL;
		}
	case PT_DOUBLE:
			return (uint8_t*)&m_zero_double;
	default:
		return NULL;
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

pair<filtercheck_field_info*, string> sinsp_table::get_row_key_name_and_val(uint32_t rownum)
{
	pair<filtercheck_field_info*, string> res;
	vector<sinsp_filter_check*>* extractors;
	vector<ppm_param_type>* types;

	if(m_do_merging)
	{
		extractors = &m_mergers;
		types = &m_postmerge_types;
	}
	else
	{
		extractors = &m_extractors;
		types = &m_premerge_types;
	}

	if(rownum >= m_sample_data->size())
	{
		ASSERT(false);
		res.first = NULL;
		res.second = "";
	}
	else
	{
		vector<filtercheck_field_info>* legend = get_legend();
		res.first = (filtercheck_field_info*)((*extractors)[0])->get_field_info();
		ASSERT(res.first != NULL);

		m_printer->set_val(types->at(0),
			m_sample_data->at(rownum).m_key.m_val, 
			m_sample_data->at(rownum).m_key.m_len,
			m_sample_data->at(rownum).m_key.m_cnt,
			legend->at(0).m_print_format);

		res.second = m_printer->tostring(NULL);
	}

	return res;
}

sinsp_table_field* sinsp_table::get_row_key(uint32_t rownum)
{
	if(rownum >= m_sample_data->size())
	{
		return NULL;
	}

	return &m_sample_data->at(rownum).m_key;
}

int32_t sinsp_table::get_row_from_key(sinsp_table_field* key)
{
	uint32_t j;

	for(j = 0; j < m_sample_data->size(); j++)
	{
		sinsp_table_field* rowkey = &(m_sample_data->at(j).m_key);

		if(rowkey->m_len == key->m_len)
		{
			if(memcmp(rowkey->m_val, key->m_val, key->m_len) == 0)
			{
				return j;
			}
		}
	}

	return -1;
}

void sinsp_table::set_paused(bool paused)
{
	m_paused = paused;
}
