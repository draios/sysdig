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

#define SINSP_TABLE_DEFAULT_REFRESH_INTERVAL_NS 1000000000
#define SINSP_TABLE_BUFFER_ENTRY_SIZE 16384

class sinsp_filter_check_reference;

class sinsp_table_field
{
public:
	sinsp_table_field()
	{
		m_val = NULL;
	}

	sinsp_table_field(uint8_t* val, uint32_t len)
	{
		m_len = len;
		m_val = val;
	}

	bool operator==(const sinsp_table_field &other) const
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
	uint8_t* m_val;

	friend class curses_table;	
};

struct sinsp_table_field_hasher
{
  size_t operator()(const sinsp_table_field& k) const
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

class sinsp_table_buffer
{
public:
	sinsp_table_buffer()
	{
		push_buffer();
	}

	void push_buffer()
	{
		m_curbuf = new uint8_t[SINSP_TABLE_BUFFER_ENTRY_SIZE];
		m_bufs.push_back(m_curbuf);
		m_pos = 0;
	}

	uint8_t* copy(uint8_t* src, uint32_t len)
	{
		if(m_pos + len >= SINSP_TABLE_BUFFER_ENTRY_SIZE)
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
		if(len >= SINSP_TABLE_BUFFER_ENTRY_SIZE)
		{
			ASSERT(false);
			throw sinsp_exception("field value too long");
		}

		if(m_pos + len >= SINSP_TABLE_BUFFER_ENTRY_SIZE)
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

	vector<uint8_t*> m_bufs;
	uint8_t* m_curbuf;
	uint32_t m_pos;
};

class sinsp_table
{
public:	
	sinsp_table(sinsp* inspector);
	~sinsp_table();
	void configure(const string& fmt);
	bool process_event(sinsp_evt* evt);
	void flush(sinsp_evt* evt);
	vector<vector<sinsp_table_field>>* get_sample(uint32_t sorting_col);
	vector<filtercheck_field_info>* get_legend()
	{
		return &m_legend;
	}

private:
	inline void add_fields_sum(ppm_param_type type, sinsp_table_field* dst, sinsp_table_field* src);
	inline void add_fields(uint32_t dst_id, sinsp_table_field* src);
	inline uint32_t get_field_len(uint32_t id);
	void create_sample();
	void switch_buffers();

	sinsp* m_inspector;
	unordered_map<sinsp_table_field, sinsp_table_field*, sinsp_table_field_hasher> m_table;
	vector<filtercheck_field_info> m_legend;
	vector<sinsp_filter_check*> m_extractors;
	vector<sinsp_filter_check*> m_chks_to_free;
	vector<ppm_param_type> m_types;
	bool m_is_key_present;
	sinsp_table_field* m_field_pointers;
	uint32_t m_n_fields;
	sinsp_table_buffer* m_buffer;
	sinsp_table_buffer m_buffer1;
	sinsp_table_buffer m_buffer2;
	uint32_t m_vals_array_size;
	uint64_t m_refresh_interval;
	uint64_t m_next_flush_time_ns;
	sinsp_filter_check_reference* m_printer;
	vector<vector<sinsp_table_field>> m_sample_data;
	sinsp_table_field* m_vals;
};
