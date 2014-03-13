/*
Copyright (C) 2013-2014 Draios inc.
 
This file is part of sysdig.

sysdig is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once	

class sinsp_evttables;

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
	static bool sockinfo_to_str(sinsp_sockinfo* sinfo, scap_fd_type stype, char* targetbuf, uint32_t targetbuf_size);

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
string ipv4tuple_to_string(ipv4tuple* tuple);
string ipv6tuple_to_string(_ipv6tuple* tuple);
string ipv4serveraddr_to_string(ipv4serverinfo* addr);
string ipv6serveraddr_to_string(ipv6serverinfo* addr);

///////////////////////////////////////////////////////////////////////////////
// String split
///////////////////////////////////////////////////////////////////////////////
vector<string> sinsp_split(const string &s, char delim);

///////////////////////////////////////////////////////////////////////////////
// number parser
///////////////////////////////////////////////////////////////////////////////
class sinsp_numparser
{
public:
	static uint32_t parseu8(const string& str);
	static int32_t parsed8(const string& str);
	static uint32_t parseu16(const string& str);
	static int32_t parsed16(const string& str);
	static uint32_t parseu32(const string& str);
	static int32_t parsed32(const string& str);
	static uint64_t parseu64(const string& str);
	static int64_t parsed64(const string& str);

	static bool tryparseu32(const string& str, uint32_t* res);
	static bool tryparsed32(const string& str, int32_t* res);
	static bool tryparseu64(const string& str, uint64_t* res);
	static bool tryparsed64(const string& str, int64_t* res);
};
