#pragma once

#ifdef HAS_FILTERING

#define VALIDATE_STR_VAL if(val.length() >= sizeof(m_val_storage)) \
{ \
	throw sinsp_exception("filter error: value too long: " + val); \
}

bool flt_compare(ppm_cmp_operator op, ppm_param_type type, void* operand1, void* operand2);
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
	virtual filter_check_info* get_filelds()
	{
		return &m_info;
	}

	//
	// Parse the name of the field.
	// Returns the lenght of the parsed field if successful, an exception in 
	// case of error.
	//
	virtual int32_t parse_field_name(const char* str);
	
	//
	// If this check is used by a filter, extract the constant to compare it to
	// Doesn't return the field lenght because the filtering engine can calculate it.
	//
	virtual void parse_filter_value(const char* str);

	//
	// Return the info about the field that this instance contains 
	//
	virtual const filtercheck_field_info* get_field_info();

	//
	// Extract the field from the event
	//
	virtual uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len) = 0;

	//
	// Compare the field with the constant value obtained from parse_filter_value()
	//
	virtual bool compare(sinsp_evt *evt);

	//
	// Extract the value from the event and convert it into a string
	//
	virtual char* tostring(sinsp_evt* evt);

	sinsp* m_inspector;
	boolop m_boolop;
	ppm_cmp_operator m_cmpop;

protected:
	char* rawval_to_string(uint8_t* rawval, const filtercheck_field_info* finfo, uint32_t len);
	void string_to_rawval(const char* str, ppm_param_type ptype);

	char m_getpropertystr_storage[1024];
	uint8_t m_val_storage[1024];
	const filtercheck_field_info* m_field;
	filter_check_info m_info;
	uint32_t m_field_id;

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
	void get_all_fields(vector<const filter_check_info*>* list);
	sinsp_filter_check* new_filter_check_from_fldname(string name, sinsp* inspector);

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
	int32_t parse_field_name(const char* str)
	{
		ASSERT(false);
		return 0;
	}

	void parse_filter_value(const char* str)
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
		TYPE_FDNAME = 2,
		TYPE_IP = 3,
		TYPE_CLIENTIP = 4,
		TYPE_SERVERIP = 5,
		TYPE_PORT = 6,
		TYPE_CLIENTPORT = 7,
		TYPE_SERVERPORT = 8,
		TYPE_L4PROTO = 9,
		TYPE_SOCKFAMILY = 10,
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
	int32_t parse_field_name(const char* str);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len);
	uint8_t* extract_fdtype(sinsp_fdinfo_t* fdinfo);
	bool compare_ip(sinsp_evt *evt);
	bool compare_port(sinsp_evt *evt);
	bool compare(sinsp_evt *evt);
	char* tostring(sinsp_evt* evt);

	sinsp_threadinfo* m_tinfo;
	sinsp_fdinfo_t* m_fdinfo;
	fd_type m_fd_type;
	string m_tstr;

private:
	bool extract_fd(sinsp_evt *evt);
};

//
// thread checks
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
		TYPE_CWD = 4,
		TYPE_NCHILDS = 5,
		TYPE_TID = 6,
		TYPE_ISMAINTHREAD = 7,
		TYPE_PARENTNAME = 8,
		IOBYTES = 9,
		TOTIOBYTES = 10,
		LATENCY = 11,
		TOTLATENCY = 12,
	};

	sinsp_filter_check_thread();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len);

	// XXX this is overkill and wasted for most of the fields.
	// It could be optimized by dynamically allocating the right amount
	// of memory, but we don't care for the moment since we expect filters 
	// to be pretty small.
	uint32_t m_tbool;
	string m_tstr;
	uint64_t m_u64val;
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
		TYPE_DATETIME = 2,
		TYPE_RAWTS = 3,
		TYPE_RAWTS_S = 4,
		TYPE_RAWTS_NS = 5,
		TYPE_RELTS = 6,
		TYPE_RELTS_S = 7,
		TYPE_RELTS_NS = 8,
		TYPE_LATENCY = 9,
		TYPE_DIR = 10,
		TYPE_NAME = 11,
		TYPE_CPU = 12,
		TYPE_ARGS = 13,
		TYPE_ARGSTR = 14,
		TYPE_ARGRAW = 15,
		TYPE_RESSTR = 16,
		TYPE_RESRAW = 17,
	};

	sinsp_filter_check_event();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str);
	void parse_filter_value(const char* str);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len);
	bool compare(sinsp_evt *evt);
	char* tostring(sinsp_evt* evt);

	uint64_t m_first_ts;
	uint64_t m_u64val;
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
	void ts_to_string(uint64_t ts, OUT string* res, bool full);
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
	int32_t parse_field_name(const char* str);
	void parse_filter_value(const char* str);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len);

	// XXX this is overkill and wasted for most of the fields.
	// It could be optimized by dynamically allocating the right amount
	// of memory, but we don't care for the moment since we expect filters 
	// to be pretty small.
	string m_text;
	uint32_t m_text_len;
};

#endif // HAS_FILTERING
