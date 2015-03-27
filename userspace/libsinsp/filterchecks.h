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
#include <json/json.h>

#ifdef HAS_FILTERING

#define VALIDATE_STR_VAL if(val.length() >= sizeof(m_val_storage)) \
{ \
	throw sinsp_exception("filter error: value too long: " + val); \
}

bool flt_compare(ppm_cmp_operator op, ppm_param_type type, void* operand1, void* operand2, uint32_t op1_len = 0, uint32_t op2_len = 0);
bool flt_compare_avg(ppm_cmp_operator op, ppm_param_type type, void* operand1, void* operand2, uint32_t op1_len, uint32_t op2_len, uint32_t cnt1, uint32_t cnt2);

char* flt_to_string(uint8_t* rawval, filtercheck_field_info* finfo);

class operand_info
{
public:
	uint32_t m_id;
	ppm_param_type m_type;
	string m_name;
	string m_description;
};

///////////////////////////////////////////////////////////////////////////////
// The filter check interface
// NOTE: in order to add a new type of filter check, you need to add a class for
//       it and then add it to new_filter_check_from_name.
///////////////////////////////////////////////////////////////////////////////
class sinsp_filter_check
{
public:
	sinsp_filter_check();
	
	virtual ~sinsp_filter_check()
	{
	}

	//
	// Allocate a new check of the same type.
	// Every filtercheck plugin must implement this.
	//
	virtual sinsp_filter_check* allocate_new() = 0;

	//
	// Get the list of fields that this check exports
	//
	virtual filter_check_info* get_fields()
	{
		return &m_info;
	}

	//
	// Parse the name of the field.
	// Returns the lenght of the parsed field if successful, an exception in 
	// case of error.
	//
	virtual int32_t parse_field_name(const char* str, bool alloc_state);
	
	//
	// If this check is used by a filter, extract the constant to compare it to
	// Doesn't return the field lenght because the filtering engine can calculate it.
	//
	virtual void parse_filter_value(const char* str, uint32_t len);

	//
	// Return the info about the field that this instance contains 
	//
	virtual const filtercheck_field_info* get_field_info();

	//
	// Extract the field from the event
	//
	virtual uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len) = 0;

	//
	// Extract the field as json from the event (by default, fall
	// back to the regular extract functionality)
	//
	virtual Json::Value extract_as_js(sinsp_evt *evt, OUT uint32_t* len)
	{
		return Json::Value::null;
	}

	//
	// Compare the field with the constant value obtained from parse_filter_value()
	//
	virtual bool compare(sinsp_evt *evt);

	//
	// Extract the value from the event and convert it into a string
	//
	virtual char* tostring(sinsp_evt* evt);

	//
	// Extract the value from the event and convert it into a Json value
	// or object
	//
	virtual Json::Value tojson(sinsp_evt* evt);

	sinsp* m_inspector;
	boolop m_boolop;
	ppm_cmp_operator m_cmpop;
	sinsp_field_aggregation m_aggregation;
	sinsp_field_aggregation m_merge_aggregation;

protected:
	char* rawval_to_string(uint8_t* rawval, const filtercheck_field_info* finfo, uint32_t len);
	Json::Value rawval_to_json(uint8_t* rawval, const filtercheck_field_info* finfo, uint32_t len);
	void string_to_rawval(const char* str, uint32_t len, ppm_param_type ptype);

	char m_getpropertystr_storage[1024];
	vector<uint8_t> m_val_storage;
	const filtercheck_field_info* m_field;
	filter_check_info m_info;
	uint32_t m_field_id;
	uint32_t m_th_state_id;
	uint32_t m_val_storage_len;

private:
	void set_inspector(sinsp* inspector);

friend class sinsp_filter_check_list;
};

//
// Global class that stores the list of filtercheck plugins and offers
// functions to work with it.
//
class sinsp_filter_check_list
{
public:
	sinsp_filter_check_list();
	~sinsp_filter_check_list();
	void add_filter_check(sinsp_filter_check* filter_check);
	void get_all_fields(vector<const filter_check_info*>* list);
	sinsp_filter_check* new_filter_check_from_another(sinsp_filter_check *chk);
	sinsp_filter_check* new_filter_check_from_fldname(const string& name, sinsp* inspector, bool do_exact_check);

private:
	vector<sinsp_filter_check*> m_check_list;
};

///////////////////////////////////////////////////////////////////////////////
// Filter expression class
// A filter expression contains multiple filters connected by boolean expressions,
// e.g. "check or check", "check and check and check", "not check"
///////////////////////////////////////////////////////////////////////////////
class sinsp_filter_expression : public sinsp_filter_check
{
public:
	sinsp_filter_expression();
	~sinsp_filter_expression();
	sinsp_filter_check* allocate_new();
	void add_check(sinsp_filter_check* chk);
	// does nothing for sinsp_filter_expression
	void parse(string expr);
	bool compare(sinsp_evt *evt);

	//
	// The following methods are part of the filter check interface but are irrelevant
	// for this class, because they are used only for the leaves of the filtering tree.
	//
	int32_t parse_field_name(const char* str, bool alloc_state)
	{
		ASSERT(false);
		return 0;
	}

	void parse_filter_value(const char* str, uint32_t len)
	{
		ASSERT(false);
	}

	const filtercheck_field_info* get_field_info()
	{
		ASSERT(false);
		return NULL;
	}

	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len)
	{
		ASSERT(false);
		return NULL;
	}

	sinsp_filter_expression* m_parent;
	vector<sinsp_filter_check*> m_checks;
};

///////////////////////////////////////////////////////////////////////////////
// Filter check classes
///////////////////////////////////////////////////////////////////////////////

//
// fd checks
//
class sinsp_filter_check_fd : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_FDNUM = 0,
		TYPE_FDTYPE = 1,
		TYPE_FDTYPECHAR = 2,
		TYPE_FDNAME = 3,
		TYPE_DIRECTORY = 4,
		TYPE_FILENAME = 5,
		TYPE_IP = 6,
		TYPE_CLIENTIP = 7,
		TYPE_SERVERIP = 8,
		TYPE_PORT = 9,
		TYPE_CLIENTPORT = 10,
		TYPE_SERVERPORT = 11,
		TYPE_L4PROTO = 12,
		TYPE_SOCKFAMILY = 13,
		TYPE_IS_SERVER = 14,
		TYPE_UID = 15,
		TYPE_CONTAINERNAME = 16,
	};

	enum fd_type
	{
		FDT_NONE,
		FDT_FILE,
		FDT_SOCK,
		FDT_IPV4_SOCK,
		FDT_IPV6_SOCK,
		FDT_UNIX_SOCK,
		FDT_PIPE,
		FDT_EVENT,
		FDT_SIGNALFD,
		FDT_EVENTPOLL,
		FDT_INOTIFY,
		FDT_TIMERFD
	};

	sinsp_filter_check_fd();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str, bool alloc_state);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len);
	bool compare_ip(sinsp_evt *evt);
	bool compare_port(sinsp_evt *evt);
	bool compare(sinsp_evt *evt);

	sinsp_threadinfo* m_tinfo;
	sinsp_fdinfo_t* m_fdinfo;
	fd_type m_fd_type;
	string m_tstr;
	uint8_t m_tcstr[2];
	uint32_t m_tbool;

private:
	uint8_t* extract_from_null_fd(sinsp_evt *evt, OUT uint32_t* len);
	bool extract_fdname_from_creator(sinsp_evt *evt, OUT uint32_t* len);
	bool extract_fd(sinsp_evt *evt);
};

//
// thread sinsp_filter_check_syslog
//
class sinsp_filter_check_thread : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_PID = 0,
		TYPE_EXE = 1,
		TYPE_NAME = 2,
		TYPE_ARGS = 3,
		TYPE_ENV = 4,
		TYPE_CMDLINE = 5,
		TYPE_EXELINE = 6,
		TYPE_CWD = 7,
		TYPE_NTHREADS = 8,
		TYPE_NCHILDS = 9,
		TYPE_PPID = 10,
		TYPE_PNAME = 11,
		TYPE_APID = 12,
		TYPE_ANAME = 13,
		TYPE_LOGINSHELLID = 14,
		TYPE_DURATION = 15,
		TYPE_FDOPENCOUNT = 16,
		TYPE_FDLIMIT = 17,
		TYPE_FDUSAGE = 18,
		TYPE_VMSIZE = 19,
		TYPE_VMRSS = 20,
		TYPE_VMSWAP = 21,
		TYPE_PFMAJOR = 22,
		TYPE_PFMINOR = 23,
		TYPE_TID = 24,
		TYPE_ISMAINTHREAD = 25,
		TYPE_EXECTIME = 26,
		TYPE_TOTEXECTIME = 27,
		TYPE_CGROUPS = 28,
		TYPE_CGROUP = 29,
		TYPE_VTID = 30,
		TYPE_VPID = 31,
		TYPE_PROC_CPU = 32,
		TYPE_THREAD_CPU = 33,
		TYPE_IOBYTES = 34,
		TYPE_TOTIOBYTES = 35,
		TYPE_LATENCY = 36,
		TYPE_TOTLATENCY = 37,
	};

	sinsp_filter_check_thread();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str, bool alloc_state);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len);
	bool compare(sinsp_evt *evt);

private:
	uint64_t extract_exectime(sinsp_evt *evt);
	int32_t extract_arg(string fldname, string val, OUT const struct ppm_param_info** parinfo);
	inline bool compare_full_apid(sinsp_evt *evt);
	bool compare_full_aname(sinsp_evt *evt);

	int32_t m_argid;
	string m_argname;
	uint32_t m_tbool;
	string m_tstr;
	uint64_t m_u64val;
	int64_t m_s64val;
	double m_dval;
	vector<uint64_t> m_last_proc_switch_times;
	uint32_t m_th_state_id;
	uint64_t m_cursec_ts;
};

//
// event checks
//
class sinsp_filter_check_event : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_NUMBER = 0,
		TYPE_TIME = 1,
		TYPE_TIME_S = 2,
		TYPE_DATETIME = 3,
		TYPE_RAWTS = 4,
		TYPE_RAWTS_S = 5,
		TYPE_RAWTS_NS = 6,
		TYPE_RELTS = 7,
		TYPE_RELTS_S = 8,
		TYPE_RELTS_NS = 9,
		TYPE_LATENCY = 10,
		TYPE_LATENCY_S = 11,
		TYPE_LATENCY_NS = 12,
		TYPE_DELTA = 13,
		TYPE_DELTA_S = 14,
		TYPE_DELTA_NS = 15,
		TYPE_DIR = 16,
		TYPE_TYPE = 17,
		TYPE_SYSCALL_TYPE = 18,
		TYPE_CPU = 19,
		TYPE_ARGS = 20,
		TYPE_ARGSTR = 21,
		TYPE_ARGRAW = 22,
		TYPE_INFO = 23,
		TYPE_BUFFER = 24,
		TYPE_BUFLEN = 25,
		TYPE_RESSTR = 26,
		TYPE_RESRAW = 27,
		TYPE_FAILED = 28,
		TYPE_ISIO = 29,
		TYPE_ISIO_READ = 30,
		TYPE_ISIO_WRITE = 31,
		TYPE_IODIR = 32,
		TYPE_ISWAIT = 33,
		TYPE_ISSYSLOG = 34,
		TYPE_COUNT = 35,
		TYPE_AROUND = 36,
		TYPE_ABSPATH = 37,
		TYPE_BUFLEN_FILE = 38,
		TYPE_BUFLEN_FILE_IN = 39,
		TYPE_BUFLEN_FILE_OUT = 40,
		TYPE_BUFLEN_NET = 41,
		TYPE_BUFLEN_NET_IN = 42,
		TYPE_BUFLEN_NET_OUT = 43,
	};

	sinsp_filter_check_event();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str, bool alloc_state);
	void parse_filter_value(const char* str, uint32_t len);
	const filtercheck_field_info* get_field_info();
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len);
	Json::Value extract_as_js(sinsp_evt *evt, OUT uint32_t* len);
	bool compare(sinsp_evt *evt);

	uint64_t m_first_ts;
	uint64_t m_u64val;
	uint64_t m_tsdelta;
	uint32_t m_u32val;
	string m_strstorage;
	string m_argname;
	int32_t m_argid;
	const ppm_param_info* m_arginfo;
	//
	// Note: this copy of the field is used by some fields, like TYPE_ARGS and 
	// TYPE_RESARG, that need to do on the fly type customization
	//
	filtercheck_field_info m_customfield;

private:
	int32_t extract_arg(string fldname, string val, OUT const struct ppm_param_info** parinfo);
	int32_t gmt2local(time_t t);
	void ts_to_string(uint64_t ts, OUT string* res, bool full, bool ns);
	uint8_t *extract_abspath(sinsp_evt *evt, OUT uint32_t *len);
	inline uint8_t* extract_buflen(sinsp_evt *evt);

	bool m_is_compare;
	double m_pippo;
};

//
// user checks
//
class sinsp_filter_check_user : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_UID = 0,
		TYPE_NAME = 1,
		TYPE_HOMEDIR = 2,
		TYPE_SHELL = 3,
	};

	sinsp_filter_check_user();
	sinsp_filter_check* allocate_new();
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len);

	uint32_t m_uid;
	string m_strval;
};

//
// group checks
//
class sinsp_filter_check_group : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_GID,
		TYPE_NAME,
	};

	sinsp_filter_check_group();
	sinsp_filter_check* allocate_new();
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len);

	uint32_t m_gid;
	string m_name;
};

//
// Fake filter check used by the event formatter to render format text
//
class rawstring_check : public sinsp_filter_check
{
public:
	rawstring_check(string text);
	sinsp_filter_check* allocate_new();
	void set_text(string text);
	int32_t parse_field_name(const char* str, bool alloc_state);
	void parse_filter_value(const char* str, uint32_t len);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len);

	// XXX this is overkill and wasted for most of the fields.
	// It could be optimized by dynamically allocating the right amount
	// of memory, but we don't care for the moment since we expect filters 
	// to be pretty small.
	string m_text;
	uint32_t m_text_len;
};

//
// syslog checks
//
class sinsp_decoder_syslog;

class sinsp_filter_check_syslog : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_FACILITY_STR = 0,
		TYPE_FACILITY,
		TYPE_SEVERITY_STR,
		TYPE_SEVERITY,
		TYPE_MESSAGE,
	};

	sinsp_filter_check_syslog();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str, bool alloc_state);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len);

	sinsp_decoder_syslog* m_decoder;
	uint32_t m_gid;
	string m_name;
};

class sinsp_filter_check_container : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_CONTAINER_ID = 0,
		TYPE_CONTAINER_NAME,
		TYPE_CONTAINER_IMAGE,
	};

	sinsp_filter_check_container();
	sinsp_filter_check* allocate_new();
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len);

private:
	string m_tstr;
};

//
// For internal use
//
class sinsp_filter_check_reference : public sinsp_filter_check
{
public:
	enum alignment
	{
		ALIGN_LEFT,
		ALIGN_RIGHT,
	};

	sinsp_filter_check_reference();
	sinsp_filter_check* allocate_new();
	inline void set_val(ppm_param_type type, uint8_t* val, 
		int32_t len, uint32_t cnt,
		ppm_print_format print_format)
	{
		m_finfo.m_type = type;
		m_val = val;
		m_len = len;
		m_cnt = cnt;
		m_print_format = print_format;
	}
	int32_t parse_field_name(const char* str, bool alloc_state);
	void parse_filter_value(const char* str, uint32_t len);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len);
	char* tostring_nice(sinsp_evt* evt, uint32_t str_len);

private:
	inline char* format_bytes(int64_t val, uint32_t str_len);
	inline char* format_time(uint64_t val, uint32_t str_len);

	filtercheck_field_info m_finfo;
	uint8_t* m_val;
	uint32_t m_len;
	uint32_t m_cnt;		// For averages, this stores the entry count
	ppm_print_format m_print_format;
};

//
// For internal use
//
class sinsp_filter_check_utils : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_CNT,
	};

	sinsp_filter_check_utils();
	sinsp_filter_check* allocate_new();
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len);

private:
	uint64_t m_cnt;
};

#endif // HAS_FILTERING
