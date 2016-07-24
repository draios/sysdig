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
#include <unordered_set>
#include <json/json.h>
#include "k8s.h"
#include "mesos.h"

#ifdef HAS_FILTERING

class sinsp_filter_check_reference;

bool flt_compare(cmpop op, ppm_param_type type, void* operand1, void* operand2, uint32_t op1_len = 0, uint32_t op2_len = 0);
bool flt_compare_avg(cmpop op, ppm_param_type type, void* operand1, void* operand2, uint32_t op1_len, uint32_t op2_len, uint32_t cnt1, uint32_t cnt2);
bool flt_compare_ipv4net(cmpop op, uint64_t operand1, ipv4net* operand2);

char* flt_to_string(uint8_t* rawval, filtercheck_field_info* finfo);
int32_t gmt2local(time_t t);
void ts_to_string(uint64_t ts, OUT string* res, bool full, bool ns);

class operand_info
{
public:
	uint32_t m_id;
	ppm_param_type m_type;
	string m_name;
	string m_description;
};

// Used for CO_IN filterchecks using PT_CHARBUFs to allow for quick
// multi-value comparisons. Should also work for any filtercheck with
// a buffer and length. When compiling with gnu compilers, use the
// built in but not standard _hash_impl::hash function, which uses
// murmurhash2 and is quite fast. Otherwise, uses
// http://www.cse.yorku.ca/~oz/hash.html.

// Used by m_val_storages_members
typedef pair<uint8_t *, uint32_t> filter_value_member_t;

struct g_hash_membuf
{
	size_t operator()(filter_value_member_t val) const
	{
#ifdef __GNUC__
		return std::_Hash_impl::hash(val.first, val.second);
#else
		size_t hash = 5381;
		for(uint8_t *p = val.first; p-val.first < val.second; p++)
		{
			int c = *p;

			hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
		}
		return hash;
#endif
	}
};

struct g_equal_to_membuf
{
	bool operator()(filter_value_member_t a, filter_value_member_t b) const
	{
		return (a.second == b.second &&
			memcmp(a.first, b.first, a.second) == 0);
	}
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
	// Returns the length of the parsed field if successful, an exception in
	// case of error.
	//
	virtual int32_t parse_field_name(const char* str, bool alloc_state);

	//
	// If this check is used by a filter, extract the constant to compare it to
	// Doesn't return the field length because the filtering engine can calculate it.
	//
	void add_filter_value(const char* str, uint32_t len, uint16_t i = 0 );
	virtual void parse_filter_value(const char* str, uint32_t len, uint8_t *storage, uint32_t storage_len);

	//
	// Called after parsing for optional validation of the filter value
	//
	void validate_filter_value(const char* str, uint32_t len) {}

	//
	// Return the info about the field that this instance contains
	//
	virtual const filtercheck_field_info* get_field_info();

	//
        // Extract the field from the event. In sanitize_strings is true, any
        // string values are sanitized to remove nonprintable characters.
	//
	virtual uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true) = 0;

	//
	// Extract the field as json from the event (by default, fall
	// back to the regular extract functionality)
	//
	virtual Json::Value extract_as_js(sinsp_evt *evt, OUT uint32_t* len)
	{
		return Json::Value::nullRef;
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

	//
	// Configure numeric id to be set on events that match this filter
	//
	void set_check_id(int32_t id);
	virtual int32_t get_check_id();

	sinsp* m_inspector;
	bool m_needs_state_tracking = false;
	boolop m_boolop;
	cmpop m_cmpop;
	sinsp_field_aggregation m_aggregation;
	sinsp_field_aggregation m_merge_aggregation;

protected:
	bool flt_compare(cmpop op, ppm_param_type type, void* operand1, uint32_t op1_len = 0, uint32_t op2_len = 0);

	char* rawval_to_string(uint8_t* rawval, const filtercheck_field_info* finfo, uint32_t len);
	Json::Value rawval_to_json(uint8_t* rawval, const filtercheck_field_info* finfo, uint32_t len);
	void string_to_rawval(const char* str, uint32_t len, ppm_param_type ptype);

	char m_getpropertystr_storage[1024];
	vector<vector<uint8_t>> m_val_storages;
	inline uint8_t* filter_value_p(uint16_t i = 0) { return &m_val_storages[i][0]; }
	inline vector<uint8_t> filter_value(uint16_t i = 0) { return m_val_storages[i]; }

	unordered_set<filter_value_member_t,
		g_hash_membuf,
		g_equal_to_membuf> m_val_storages_members;

	uint32_t m_val_storages_min_size;
	uint32_t m_val_storages_max_size;

	const filtercheck_field_info* m_field;
	filter_check_info m_info;
	uint32_t m_field_id;
	uint32_t m_th_state_id;
	uint32_t m_val_storage_len;

private:
	void set_inspector(sinsp* inspector);
	int32_t m_check_id = 0;

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

	const filtercheck_field_info* get_field_info()
	{
		ASSERT(false);
		return NULL;
	}

	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true)
	{
		ASSERT(false);
		return NULL;
	}

	int32_t get_check_id();

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
		TYPE_LIP = 9,
		TYPE_RIP = 10,
		TYPE_PORT = 11,
		TYPE_CLIENTPORT = 12,
		TYPE_SERVERPORT = 13,
		TYPE_LPORT = 14,
		TYPE_RPORT = 15,
		TYPE_L4PROTO = 16,
		TYPE_SOCKFAMILY = 17,
		TYPE_IS_SERVER = 18,
		TYPE_UID = 19,
		TYPE_CONTAINERNAME = 20,
		TYPE_CONTAINERDIRECTORY = 21,
		TYPE_PROTO = 22,
		TYPE_CLIENTPROTO = 23,
		TYPE_SERVERPROTO = 24,
		TYPE_LPROTO = 25,
		TYPE_RPROTO = 26,
		TYPE_NET = 27,
		TYPE_CNET = 28,
		TYPE_SNET = 29,
		TYPE_LNET = 30,
		TYPE_RNET = 31
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
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);
	bool compare_ip(sinsp_evt *evt);
	bool compare_net(sinsp_evt *evt);
	bool compare_port(sinsp_evt *evt);
	bool compare(sinsp_evt *evt);

	sinsp_threadinfo* m_tinfo;
	sinsp_fdinfo_t* m_fdinfo;
	fd_type m_fd_type;
	string m_tstr;
	uint8_t m_tcstr[2];
	uint32_t m_tbool;

private:
	uint8_t* extract_from_null_fd(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings);
	bool extract_fdname_from_creator(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings);
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
		TYPE_THREAD_CPU = 32,
		TYPE_THREAD_CPU_USER = 33,
		TYPE_THREAD_CPU_SYSTEM = 34,
		TYPE_THREAD_VMSIZE = 35,
		TYPE_THREAD_VMRSS = 36,
		TYPE_THREAD_VMSIZE_B = 37,
		TYPE_THREAD_VMRSS_B = 38,
		TYPE_SID = 39,
		TYPE_SNAME = 40,
	};

	sinsp_filter_check_thread();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str, bool alloc_state);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);
	bool compare(sinsp_evt *evt);

private:
	uint64_t extract_exectime(sinsp_evt *evt);
	int32_t extract_arg(string fldname, string val, OUT const struct ppm_param_info** parinfo);
	uint8_t* extract_thread_cpu(sinsp_evt *evt, sinsp_threadinfo* tinfo, bool extract_user, bool extract_system);
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
		TYPE_LATENCY_QUANTIZED = 13,
		TYPE_LATENCY_HUMAN = 14,
		TYPE_DELTA = 15,
		TYPE_DELTA_S = 16,
		TYPE_DELTA_NS = 17,
		TYPE_RUNTIME_TIME_OUTPUT_FORMAT = 18,
		TYPE_DIR = 19,
		TYPE_TYPE = 20,
		TYPE_TYPE_IS = 21,
		TYPE_SYSCALL_TYPE = 22,
		TYPE_CATEGORY = 23,
		TYPE_CPU = 24,
		TYPE_ARGS = 25,
		TYPE_ARGSTR = 26,
		TYPE_ARGRAW = 27,
		TYPE_INFO = 28,
		TYPE_BUFFER = 29,
		TYPE_BUFLEN = 30,
		TYPE_RESSTR = 31,
		TYPE_RESRAW = 32,
		TYPE_FAILED = 33,
		TYPE_ISIO = 34,
		TYPE_ISIO_READ = 35,
		TYPE_ISIO_WRITE = 36,
		TYPE_IODIR = 37,
		TYPE_ISWAIT = 38,
		TYPE_WAIT_LATENCY = 39,
		TYPE_ISSYSLOG = 40,
		TYPE_COUNT = 41,
		TYPE_COUNT_ERROR = 42,
		TYPE_COUNT_ERROR_FILE = 43,
		TYPE_COUNT_ERROR_NET = 44,
		TYPE_COUNT_ERROR_MEMORY = 45,
		TYPE_COUNT_ERROR_OTHER = 46,
		TYPE_COUNT_EXIT = 47,
		TYPE_COUNT_PROCINFO = 48,
		TYPE_COUNT_THREADINFO = 49,
		TYPE_AROUND = 50,
		TYPE_ABSPATH = 51,
		TYPE_BUFLEN_IN = 52,
		TYPE_BUFLEN_OUT = 53,
		TYPE_BUFLEN_FILE = 54,
		TYPE_BUFLEN_FILE_IN = 55,
		TYPE_BUFLEN_FILE_OUT = 56,
		TYPE_BUFLEN_NET = 57,
		TYPE_BUFLEN_NET_IN = 58,
		TYPE_BUFLEN_NET_OUT = 59,
		TYPE_ISOPEN_READ = 60,
		TYPE_ISOPEN_WRITE = 61
	};

	sinsp_filter_check_event();
	~sinsp_filter_check_event();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str, bool alloc_state);
	void parse_filter_value(const char* str, uint32_t len, uint8_t *storage, uint32_t storage_len);
	void validate_filter_value(const char* str, uint32_t len);
	const filtercheck_field_info* get_field_info();
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);
	Json::Value extract_as_js(sinsp_evt *evt, OUT uint32_t* len);
	bool compare(sinsp_evt *evt);

	uint64_t m_u64val;
	uint64_t m_tsdelta;
	uint32_t m_u32val;
	string m_strstorage;
	string m_argname;
	int32_t m_argid;
	uint32_t m_evtid;
	uint32_t m_evtid1;
	const ppm_param_info* m_arginfo;

	//
	// Note: this copy of the field is used by some fields, like TYPE_ARGS and
	// TYPE_RESARG, that need to do on the fly type customization
	//
	filtercheck_field_info m_customfield;

private:
	int32_t extract_arg(string fldname, string val, OUT const struct ppm_param_info** parinfo);
	int32_t extract_type(string fldname, string val, OUT const struct ppm_param_info** parinfo);
	uint8_t* extract_error_count(sinsp_evt *evt, OUT uint32_t* len);
	uint8_t *extract_abspath(sinsp_evt *evt, OUT uint32_t *len);
	inline uint8_t* extract_buflen(sinsp_evt *evt);

	bool m_is_compare;
	char* m_storage;
	uint32_t m_storage_size;
	const char* m_cargname;
	sinsp_filter_check_reference* m_converter;
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
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

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
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

	uint32_t m_gid;
	string m_name;
};

//
// Tracers
//
#define TEXT_ARG_ID -1000000

class sinsp_filter_check_tracer : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_ID = 0,
		TYPE_TIME,
		TYPE_NTAGS,
		TYPE_NARGS,
		TYPE_TAGS,
		TYPE_TAG,
		TYPE_ARGS,
		TYPE_ARG,
		TYPE_ENTERARGS,
		TYPE_ENTERARG,
		TYPE_DURATION,
		TYPE_DURATION_QUANTIZED,
		TYPE_DURATION_HUMAN,
		TYPE_TAGDURATION,
		TYPE_COUNT,
		TYPE_TAGCOUNT,
		TYPE_TAGCHILDSCOUNT,
		TYPE_IDTAG,
		TYPE_RAWTIME,
		TYPE_RAWPARENTTIME,
	};

	sinsp_filter_check_tracer();
	~sinsp_filter_check_tracer();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str, bool alloc_state);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

private:
	int32_t extract_arg(string fldname, string val, OUT const struct ppm_param_info** parinfo);
	inline int64_t* extract_duration(uint16_t etype, sinsp_tracerparser* eparser);
	uint8_t* extract_args(sinsp_partial_tracer* pae);
	uint8_t* extract_arg(sinsp_partial_tracer* pae);

	int32_t m_argid;
	string m_argname;
	const char* m_cargname;
	char* m_storage;
	uint32_t m_storage_size;
	int64_t m_s64val;
	int32_t m_u32val;
	sinsp_filter_check_reference* m_converter;
	string m_strstorage;
};

//
// Events in tracers checks
//
class sinsp_filter_check_evtin : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_ID = 0,
		TYPE_NTAGS,
		TYPE_NARGS,
		TYPE_TAGS,
		TYPE_TAG,
		TYPE_ARGS,
		TYPE_ARG,
		TYPE_P_ID,
		TYPE_P_NTAGS,
		TYPE_P_NARGS,
		TYPE_P_TAGS,
		TYPE_P_TAG,
		TYPE_P_ARGS,
		TYPE_P_ARG,
		TYPE_S_ID,
		TYPE_S_NTAGS,
		TYPE_S_NARGS,
		TYPE_S_TAGS,
		TYPE_S_TAG,
		TYPE_S_ARGS,
		TYPE_S_ARG,
		TYPE_M_ID,
		TYPE_M_NTAGS,
		TYPE_M_NARGS,
		TYPE_M_TAGS,
		TYPE_M_TAG,
		TYPE_M_ARGS,
		TYPE_M_ARG,
	};

	sinsp_filter_check_evtin();
	~sinsp_filter_check_evtin();
	int32_t parse_field_name(const char* str, bool alloc_state);
	sinsp_filter_check* allocate_new();
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);
	bool compare(sinsp_evt *evt);

	uint64_t m_u64val;
	uint64_t m_tsdelta;
	uint32_t m_u32val;
	string m_strstorage;
	string m_argname;
	int32_t m_argid;
	uint32_t m_evtid;
	uint32_t m_evtid1;
	const ppm_param_info* m_arginfo;

	//
	// Note: this copy of the field is used by some fields, like TYPE_ARGS and
	// TYPE_RESARG, that need to do on the fly type customization
	//
	filtercheck_field_info m_customfield;

private:
	int32_t extract_arg(string fldname, string val);
	inline bool compare_tracer(sinsp_evt *evt, sinsp_partial_tracer* pae);

	bool m_is_compare;
	char* m_storage;
	uint32_t m_storage_size;
	const char* m_cargname;
	sinsp_filter_check_reference* m_converter;
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
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

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
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

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
		TYPE_CONTAINER_TYPE
	};

	sinsp_filter_check_container();
	sinsp_filter_check* allocate_new();
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

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
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);
	char* tostring_nice(sinsp_evt* evt, uint32_t str_len, uint64_t time_delta);

private:
	inline char* format_bytes(double val, uint32_t str_len, bool is_int);
	inline char* format_time(uint64_t val, uint32_t str_len);
	char* print_double(uint8_t* rawval, uint32_t str_len);
	char* print_int(uint8_t* rawval, uint32_t str_len);

	filtercheck_field_info m_finfo;
	uint8_t* m_val;
	uint32_t m_len;
	double m_cnt;		// For averages, this stores the entry count
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
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

private:
	uint64_t m_cnt;
};

//
// fdlist checks
//
class sinsp_filter_check_fdlist : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_FDNUMS = 0,
		TYPE_FDNAMES = 1,
		TYPE_CLIENTIPS = 2,
		TYPE_SERVERIPS = 3,
		TYPE_CLIENTPORTS = 4,
		TYPE_SERVERPORTS = 5,
	};

	sinsp_filter_check_fdlist();
	sinsp_filter_check* allocate_new();
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

private:
	string m_strval;
	char m_addrbuff[100];
};

class sinsp_filter_check_k8s : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_K8S_POD_NAME = 0,
		TYPE_K8S_POD_ID,
		TYPE_K8S_POD_LABEL,
		TYPE_K8S_POD_LABELS,
		TYPE_K8S_RC_NAME,
		TYPE_K8S_RC_ID,
		TYPE_K8S_RC_LABEL,
		TYPE_K8S_RC_LABELS,
		TYPE_K8S_SVC_NAME,
		TYPE_K8S_SVC_ID,
		TYPE_K8S_SVC_LABEL,
		TYPE_K8S_SVC_LABELS,
		TYPE_K8S_NS_NAME,
		TYPE_K8S_NS_ID,
		TYPE_K8S_NS_LABEL,
		TYPE_K8S_NS_LABELS,
	};

	sinsp_filter_check_k8s();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str, bool alloc_state);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

private:
	int32_t extract_arg(const string& fldname, const string& val);
	const k8s_pod_t* find_pod_for_thread(const sinsp_threadinfo* tinfo);
	const k8s_ns_t* find_ns_by_name(const string& ns_name);
	const k8s_rc_t* find_rc_by_pod(const k8s_pod_t* pod);
	vector<const k8s_service_t*> find_svc_by_pod(const k8s_pod_t* pod);
	void concatenate_labels(const k8s_pair_list& labels, string* s);
	bool find_label(const k8s_pair_list& labels, const string& key, string* value);

	string m_argname;
	string m_tstr;
};

class sinsp_filter_check_mesos : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_MESOS_TASK_NAME = 0,
		TYPE_MESOS_TASK_ID,
		TYPE_MESOS_TASK_LABEL,
		TYPE_MESOS_TASK_LABELS,
		TYPE_MESOS_FRAMEWORK_NAME,
		TYPE_MESOS_FRAMEWORK_ID,
		TYPE_MARATHON_APP_NAME,
		TYPE_MARATHON_APP_ID,
		TYPE_MARATHON_APP_LABEL,
		TYPE_MARATHON_APP_LABELS,
		TYPE_MARATHON_GROUP_NAME,
		TYPE_MARATHON_GROUP_ID,
	};

	sinsp_filter_check_mesos();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str, bool alloc_state);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

private:

	int32_t extract_arg(const string& fldname, const string& val);
	mesos_task::ptr_t find_task_for_thread(const sinsp_threadinfo* tinfo);
	const mesos_framework* find_framework_by_task(mesos_task::ptr_t task);
	marathon_app::ptr_t find_app_by_task(mesos_task::ptr_t task);
	marathon_group::ptr_t find_group_by_task(mesos_task::ptr_t task);
	void concatenate_labels(const mesos_pair_list& labels, string* s);
	bool find_label(const mesos_pair_list& labels, const string& key, string* value);

	string m_argname;
	string m_tstr;
};

#endif // HAS_FILTERING
