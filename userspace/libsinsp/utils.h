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

#pragma once

class sinsp_evttables;
typedef union _sinsp_sockinfo sinsp_sockinfo;
typedef union _ipv4tuple ipv4tuple;
typedef union _ipv6tuple ipv6tuple;
typedef struct ipv4serverinfo ipv4serverinfo;
typedef struct ipv6serverinfo ipv6serverinfo;
class filter_check_info;

///////////////////////////////////////////////////////////////////////////////
// Initializer class.
// An instance of this class is created when the library is loaded.
// ONE-SHOT INIT-TIME OPERATIONS SHOULD BE DONE IN THE CONSTRUCTOR OF THIS
// CLASS TO KEEP THEM UNDER A SINGLE PLACE.
///////////////////////////////////////////////////////////////////////////////
class sinsp_initializer
{
public:
	sinsp_initializer();
	~sinsp_initializer();
};

///////////////////////////////////////////////////////////////////////////////
// A collection of useful functions
///////////////////////////////////////////////////////////////////////////////
class sinsp_utils
{
public:
	//
	// Convert an errno number into the corresponding compact code
	//
	static const char* errno_to_str(int32_t code);

	//
	// Convert a signal number into the corresponding signal name
	//
	static const char* signal_to_str(uint8_t code);

	//
	//
	//
	static bool sockinfo_to_str(sinsp_sockinfo* sinfo, scap_fd_type stype, char* targetbuf, uint32_t targetbuf_size, bool resolve = false);

	//
	// Concatenate two paths and puts the result in "target".
	// If path2 is relative, the concatenation happens and the result is true.
	// If path2 is absolute, the concatenation does not happen, target contains path2 and the result is false.
	// Assumes that path1 is well formed. 
	//
	static bool concatenate_paths(char* target, uint32_t targetlen, const char* path1, uint32_t len1, const char* path2, uint32_t len2); 

	//
	// Determines if an IPv6 address is IPv4-mapped
	//
	static bool is_ipv4_mapped_ipv6(uint8_t* paddr);

	//
	// Given a string, scan the event list and find the longest argument that the input string contains
	//
	static const struct ppm_param_info* find_longest_matching_evt_param(string name);

	//
	// Get the list of filtercheck fields
	//
	static void get_filtercheck_fields_info(vector<const filter_check_info*>* list);

	static uint64_t get_current_time_ns();

#ifndef _WIN32
	//
	// Print the call stack
	//
	static void bt(void);
#endif // _WIN32
};

///////////////////////////////////////////////////////////////////////////////
// little STL thing to sanitize strings
///////////////////////////////////////////////////////////////////////////////
struct g_invalidchar
{
    bool operator()(char c) const 
	{
		if(c < -1)
		{
			return true;
		}

		return !isprint((unsigned)c);
    }
};

///////////////////////////////////////////////////////////////////////////////
// Time functions for Windows
///////////////////////////////////////////////////////////////////////////////
#ifdef _WIN32
struct timezone2 
{
	int32_t  tz_minuteswest;
	bool  tz_dsttime;
};

SINSP_PUBLIC int gettimeofday(struct timeval *tv, struct timezone2 *tz);
#endif // _WIN32

///////////////////////////////////////////////////////////////////////////////
// gethostname wrapper
///////////////////////////////////////////////////////////////////////////////
string sinsp_gethostname();

///////////////////////////////////////////////////////////////////////////////
// tuples to string
///////////////////////////////////////////////////////////////////////////////

// each of these functions uses values in network byte order

string ipv4tuple_to_string(ipv4tuple* tuple, bool resolve);
string ipv6tuple_to_string(_ipv6tuple* tuple, bool resolve);
string ipv4serveraddr_to_string(ipv4serverinfo* addr, bool resolve);
string ipv6serveraddr_to_string(ipv6serverinfo* addr, bool resolve);

// `l4proto` should be of type scap_l4_proto, but since it's an enum sometimes
// is used as int and we would have to cast
// `port` must be saved with network byte order
// `l4proto` could be neither TCP nor UDP, in this case any protocol will be
//           matched
string port_to_string(uint16_t port, uint8_t l4proto, bool resolve);

///////////////////////////////////////////////////////////////////////////////
// String helpers
///////////////////////////////////////////////////////////////////////////////
vector<string> sinsp_split(const string &s, char delim);
template<typename It>
string sinsp_join(It begin, It end, char delim);
string& ltrim(string &s);
string& rtrim(string &s);
string& trim(string &s);
void replace_in_place(string &s, const string &search, const string &replace);
void replace_in_place(string& str, string& substr_to_replace, string& new_substr);

///////////////////////////////////////////////////////////////////////////////
// number parser
///////////////////////////////////////////////////////////////////////////////
class sinsp_numparser
{
public:
	static uint8_t parseu8(const string& str);
	static int8_t parsed8(const string& str);
	static uint16_t parseu16(const string& str);
	static int16_t parsed16(const string& str);
	static uint32_t parseu32(const string& str);
	static int32_t parsed32(const string& str);
	static uint64_t parseu64(const string& str);
	static int64_t parsed64(const string& str);

	static bool tryparseu32(const string& str, uint32_t* res);
	static bool tryparsed32(const string& str, int32_t* res);
	static bool tryparseu64(const string& str, uint64_t* res);
	static bool tryparsed64(const string& str, int64_t* res);

	static bool tryparseu32_fast(const char* str, uint32_t strlen, uint32_t* res);
	static bool tryparsed32_fast(const char* str, uint32_t strlen, int32_t* res);
};

///////////////////////////////////////////////////////////////////////////////
// JSON helpers
///////////////////////////////////////////////////////////////////////////////
namespace Json
{
	class Value;
}

std::string get_json_string(const Json::Value& root, const std::string& name);

///////////////////////////////////////////////////////////////////////////////
// A simple class to manage pre-allocated objects in a LIFO
// fashion and make sure all of them are deleted upon destruction.
///////////////////////////////////////////////////////////////////////////////
template<typename OBJ>
class simple_lifo_queue
{
public:
	simple_lifo_queue(uint32_t size)
	{
		uint32_t j;
		for(j = 0; j < size; j++)
		{
			OBJ* newentry = new OBJ;
			m_full_list.push_back(newentry);
			m_avail_list.push_back(newentry);
		}
	}
	~simple_lifo_queue()
	{
		while(!m_avail_list.empty())
		{
			OBJ* head = m_avail_list.front();
			delete head;
			m_avail_list.pop_front();
		}
	}
	void push(OBJ* newentry)

	{
		m_avail_list.push_front(newentry);
	}

	OBJ* pop()
	{
		if(m_avail_list.empty())
		{
			return NULL;
		}
		OBJ* head = m_avail_list.front();
		m_avail_list.pop_front();
		return head;
	}

	bool empty()
	{
		return m_avail_list.empty();
	}

private:
	list<OBJ*> m_avail_list;
	list<OBJ*> m_full_list;
};
