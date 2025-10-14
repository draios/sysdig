// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

The following file was originally developed in the sysdig cli
project and then contributed to the falcosecurity/libs project
(https://github.com/draios/sysdig/commit/abf90f39f8e5ea6eb4276cc3f980dbd878816ecd
with the #1737 PR). At the end, given its removal from the
falcosecurity/libs project, has been reintroduced to the
draios/sysdig project.

*/

#include <libsinsp/sinsp.h>
#include <libsinsp/filterchecks.h>
#include <chisel/chisel_viewinfo.h>

#define CHISEL_TABLE_DEFAULT_REFRESH_INTERVAL_NS 1000000000
#define CHISEL_TABLE_BUFFER_ENTRY_SIZE 16384

enum chisel_table_action
{
	STA_NONE,
	STA_PARENT_HANDLE,
	STA_QUIT,
	STA_SWITCH_VIEW,
	STA_SWITCH_SPY,
	STA_DRILLDOWN,
	STA_DRILLDOWN_TEMPLATE,
	STA_DRILLUP,
	STA_SPY,
	STA_DIG,
	STA_SPECTRO,
	STA_SPECTRO_FILE,
	STA_DESTROY_CHILD,
};

class chisel_table_field
{
public:
	chisel_table_field()
	{
		m_val = NULL;
	}

	chisel_table_field(uint8_t* val, uint32_t len, uint32_t cnt)
	{
		m_len = len;
		m_val = val;
		m_cnt = cnt;
	}

	bool operator==(const chisel_table_field &other) const
	{
		if(m_len!= other.m_len)
		{
			return false;
		}

		if(memcmp(m_val, other.m_val, m_len) == 0)
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	uint32_t m_len;
	uint32_t m_cnt;		// For averages, this stores the entry count
	uint8_t* m_val;

	friend class curses_table;
};

#define STF_STORAGE_BUFSIZE 512

class chisel_table_field_storage : public chisel_table_field
{
public:
	chisel_table_field_storage()
	{
		m_storage_len = STF_STORAGE_BUFSIZE;
		m_val = new uint8_t[m_storage_len];
		m_isvalid = false;
	}

	~chisel_table_field_storage()
	{
		if(m_val != NULL)
		{
			delete[] m_val;
		}
	}

	void copy(chisel_table_field* other)
	{
		if(other->m_len > m_storage_len)
		{
			resize(other->m_len);
		}

		m_len = other->m_len;

		memcpy(m_val, other->m_val, m_len);
	}

	bool m_isvalid;

private:
	void resize(uint32_t newlen)
	{
		delete[] m_val;
		m_val = NULL;
		m_storage_len = newlen;
		m_val = new uint8_t[m_storage_len];
	}

	uint32_t m_storage_len;
};

struct chisel_table_field_hasher
{
  size_t operator()(const chisel_table_field& k) const
  {
	  size_t h = 0;
	  uint8_t* s = k.m_val;
	  uint32_t len = k.m_len;

	  while(--len)
	  {
		  h = h * 101 + (unsigned) *s++;
	  }

	  return h;
  }
};

class chisel_table_buffer
{
public:
	chisel_table_buffer()
	{
		push_buffer();
	}

	~chisel_table_buffer()
	{
		for(auto it = m_bufs.begin(); it != m_bufs.end(); ++it)
		{
			delete[] *it;
		}
	}

	void push_buffer()
	{
		m_curbuf = new uint8_t[CHISEL_TABLE_BUFFER_ENTRY_SIZE];
		m_bufs.push_back(m_curbuf);
		m_pos = 0;
	}

	uint8_t* copy(uint8_t* src, uint32_t len)
	{
		if(m_pos + len >= CHISEL_TABLE_BUFFER_ENTRY_SIZE)
		{
			push_buffer();
		}

		uint8_t* dest = m_curbuf + m_pos;
		memcpy(dest, src, len);
		m_pos += len;
		return dest;
	}

	uint8_t* reserve(uint32_t len)
	{
		if(len >= CHISEL_TABLE_BUFFER_ENTRY_SIZE)
		{
			ASSERT(false);
			throw sinsp_exception("field value too long");
		}

		if(m_pos + len >= CHISEL_TABLE_BUFFER_ENTRY_SIZE)
		{
			push_buffer();
		}

		uint8_t* dest = m_curbuf + m_pos;
		m_pos += len;
		return dest;
	}

	void clear()
	{
		for(auto it = m_bufs.begin(); it != m_bufs.end(); ++it)
		{
			delete[] *it;
		}

		m_bufs.clear();
		push_buffer();
		m_pos = 0;
	}

	std::vector<uint8_t*> m_bufs;
	uint8_t* m_curbuf;
	uint32_t m_pos;
};

class chisel_sample_row
{
public:
	chisel_table_field m_key;
	std::vector<chisel_table_field> m_values;
};

class chisel_table
{
public:
	enum tabletype
	{
		TT_NONE = 0,
		TT_TABLE,
		TT_LIST,
	};

	enum output_type
	{
		OT_CURSES,
		OT_RAW,
		OT_JSON,
	};

	struct check_wrapper
	{
		check_wrapper(
				sinsp_filter_check* check,
				chisel_field_aggregation aggregation=A_NONE,
				chisel_field_aggregation merge_aggregation=A_NONE):
			m_check(check),
			m_aggregation(aggregation),
			m_merge_aggregation(merge_aggregation)
		{
		}

		~check_wrapper()
		{
			delete m_check;
		}

		sinsp_filter_check* m_check;
		chisel_field_aggregation m_aggregation;
		chisel_field_aggregation m_merge_aggregation;
	};

	chisel_table(sinsp* inspector, std::shared_ptr<sinsp_filter_check_list> filter_list, tabletype type,
		uint64_t refresh_interval_ns, chisel_table::output_type output_type,
		uint32_t json_first_row, uint32_t json_last_row);
	~chisel_table();
	void configure(std::vector<chisel_view_column_info>* entries, const std::string& filter, bool use_defaults, uint32_t view_depth);
	void process_event(sinsp_evt* evt);
	void flush(sinsp_evt* evt, uint64_t last_evt_ts = 0);
	void filter_sample();
	//
	// Returns the key of the first match, or NULL if no match
	//
	chisel_table_field* search_in_sample(std::string text);
	void sort_sample();
	std::vector<chisel_sample_row>* get_sample(uint64_t time_delta);
	std::vector<filtercheck_field_info>* get_legend()
	{
		if(m_do_merging)
		{
			return &m_postmerge_legend;
		}
		else
		{
			return &m_premerge_legend;
		}
	}
	void set_sorting_col(uint32_t col);
	uint32_t get_sorting_col() const;
	std::pair<filtercheck_field_info*, std::string> get_row_key_name_and_val(uint32_t rownum, bool force);
	chisel_table_field* get_row_key(uint32_t rownum);
	int32_t get_row_from_key(chisel_table_field* key) const;
	void set_paused(bool paused);
	void set_freetext_filter(std::string filter)
	{
		m_freetext_filter = filter;
	}
	tabletype get_type() const
	{
		return m_type;
	}
	void set_refresh_interval(uint64_t newinterval_ns)
	{
		m_refresh_interval_ns = newinterval_ns;
	}
	void clear();
	bool is_merging() const
	{
		return m_do_merging;
	}
	bool is_sorting_ascending() const
	{
		return m_is_sorting_ascending;
	}
	void set_is_sorting_ascending(bool is_sorting_ascending)
	{
		m_is_sorting_ascending = is_sorting_ascending;
	}

	uint64_t m_next_flush_time_ns;
	uint64_t m_prev_flush_time_ns;
	uint64_t m_refresh_interval_ns;
	std::vector<ppm_param_type>* m_types;
	uint64_t m_json_output_lines_count;

private:
	inline void add_row(bool merging);
	inline void add_fields_sum(ppm_param_type type, chisel_table_field* dst, chisel_table_field* src);
	inline void add_fields_sum_of_avg(ppm_param_type type, chisel_table_field* dst, chisel_table_field* src);
	inline void add_fields_max(ppm_param_type type, chisel_table_field* dst, chisel_table_field* src);
	inline void add_fields_min(ppm_param_type type, chisel_table_field* dst, chisel_table_field* src);
	inline void add_fields(uint32_t dst_id, chisel_table_field* src, uint32_t aggr);
	void process_proctable(sinsp_evt* evt, uint64_t last_evt_ts = 0);
	inline uint32_t get_field_len(uint32_t id, uint32_t extracted_len = 0) const;
	inline uint8_t* get_default_val(filtercheck_field_info* fld);
	void create_sample();
	void switch_buffers();
	void print_raw(std::vector<chisel_sample_row>* sample_data, uint64_t time_delta);
	void print_json(std::vector<chisel_sample_row>* sample_data, uint64_t time_delta);

	sinsp* m_inspector;
	std::shared_ptr<sinsp_filter_check_list> m_filter_check_list;
	std::unordered_map<chisel_table_field, chisel_table_field*, chisel_table_field_hasher>* m_table;
	std::unordered_map<chisel_table_field, chisel_table_field*, chisel_table_field_hasher> m_premerge_table;
	std::unordered_map<chisel_table_field, chisel_table_field*, chisel_table_field_hasher> m_merge_table;
	std::vector<filtercheck_field_info> m_premerge_legend;
	std::vector<check_wrapper*> m_premerge_extractors;
	std::vector<check_wrapper*> m_postmerge_extractors;
	std::vector<check_wrapper*>* m_extractors;
	std::vector<check_wrapper*> m_chks_to_free;
	std::vector<ppm_param_type> m_premerge_types;
	std::vector<ppm_param_type> m_postmerge_types;
	bool m_is_key_present;
	bool m_is_groupby_key_present;
	std::vector<uint32_t> m_groupby_columns;
	std::vector<filtercheck_field_info> m_postmerge_legend;
	chisel_table_field* m_fld_pointers;
	chisel_table_field* m_premerge_fld_pointers;
	chisel_table_field* m_postmerge_fld_pointers;
	uint32_t m_n_fields;
	uint32_t m_n_premerge_fields;
	uint32_t m_n_postmerge_fields;
	chisel_table_buffer* m_buffer;
	chisel_table_buffer m_buffer1;
	chisel_table_buffer m_buffer2;
	uint32_t m_vals_array_sz;
	uint32_t m_premerge_vals_array_sz;
	uint32_t m_postmerge_vals_array_sz;
	sinsp_filter_check_reference* m_printer;
	std::vector<chisel_sample_row> m_full_sample_data;
	std::vector<chisel_sample_row> m_filtered_sample_data;
	std::vector<chisel_sample_row>* m_sample_data;
	chisel_table_field* m_vals;
	int32_t m_sorting_col;
	bool m_just_sorted;
	bool m_is_sorting_ascending;
	bool m_do_merging;
	sinsp_filter* m_filter;
	bool m_use_defaults;
	uint64_t m_zero_u64;
	uint64_t m_zero_double;
	bool m_paused;
	std::string m_freetext_filter;
	tabletype m_type;
	output_type m_output_type;
	uint32_t m_view_depth;
	uint32_t m_json_first_row;
	uint32_t m_json_last_row;

	friend class curses_table;
	friend class sinsp_cursesui;
};
