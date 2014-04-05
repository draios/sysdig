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

#ifndef VISIBILITY_PRIVATE
#define VISIBILITY_PRIVATE private:
#endif

typedef class sinsp sinsp;
typedef class sinsp_threadinfo sinsp_threadinfo;

///////////////////////////////////////////////////////////////////////////////
// Event arguments
///////////////////////////////////////////////////////////////////////////////
typedef enum filtercheck_field_flags
{
	EPF_NONE = 0,
	EPF_FILTER_ONLY, ///< this field can only be used as a filter.
	EPF_PRINT_ONLY, ///< this field can only be printed.
	EPF_REQUIRES_ARGUMENT, ///< this field includes an argument, under the form 'property.argument'.
}filtercheck_field_flags;

/*!
  \brief Information about a filter/formatting field.
*/
typedef struct filtercheck_field_info
{
	ppm_param_type m_type; ///< Field type.
	filtercheck_field_flags m_flags;  ///< Field flags.
	ppm_print_format m_print_format;  ///< If this is a numeric field, this flag specifies if it should be rendered as decimal or hex. 
	char m_name[64];  ///< Field name.
	char m_description[1024];  ///< Field description.
}filtercheck_field_info;

/** @defgroup event Event manipulation
 * Classes to manipulate events, extract their content and convert them into strings.
 *  @{
 */

/*!
  \brief Wrapper that exports the libscap event tables.
*/
class SINSP_PUBLIC sinsp_evttables
{
public:
	const struct ppm_event_info* m_event_info; ///< List of events supported by the capture and analysis subsystems. Each entry fully documents an event and its parameters.
	const struct ppm_syscall_desc* m_syscall_info_table; ///< List of system calls that the capture subsystem recognizes, including the ones that are not decoded yet.
};

/*!
  \brief Event parameter wrapper.
  This class describes a raw event coming from the driver.
*/
class SINSP_PUBLIC sinsp_evt_param
{
public:
	char* m_val;	///< Pointer to the event parameter data.
	uint16_t m_len; ///< Lenght os the parameter pointed by m_val.
private:
	void init(char* valptr, uint16_t len);

	friend class sinsp_evt;
};

/*!
  \brief Event class.
  This class is returned by \ref sinsp::next() and encapsulates the state 
  related to a captured event, and includes a bunch of members to manipulate 
  events and their parameters, including parsing, formatting and extracting 
  state like the event process or FD.
*/
class SINSP_PUBLIC sinsp_evt
{
public:
	/*!
	  \brief How to render an event parameter to string.
	*/
	enum param_fmt
	{
		PF_NORMAL,	///< Normal screen output
		PF_JSON,	///< Json formatting
		PF_SIMPLE,	///< Reduced output, e.g. not type character for FDs
		PF_HEX,		///< Hexadecimal output
		PF_HEXASCII,///< Hexadecimal + ASCII output
		PF_EOLS,	///< Normal + end of lines
	};

	/*!
	  \brief Event subcategory specialization based on the fd type.
	*/
	enum subcategory
	{
		SC_UNKNOWN = 0,
		SC_NONE = 1,
		SC_OTHER = 2,
		SC_FILE = 3,
		SC_NET = 4,
		SC_IPC = 5,
	};

	enum fd_number_type
	{
		INVALID_FD_NUM = -100000
	};

	/*!
	  \brief Information regarding an event category, enriched with fd state.
	*/
	struct category
	{
		ppm_event_category m_category;	///< Event category from the driver
		subcategory m_subcategory;		///< Domain for IO and wait events
	};

	sinsp_evt();
	sinsp_evt(sinsp* inspector);
	~sinsp_evt();

	/*!
	  \brief Get the incremental number of this event.
	*/
	uint64_t get_num();

	/*!
	  \brief Get the number of the CPU where this event was captured.
	*/
	int16_t get_cpuid();

	/*!
	  \brief Get the event type. 
	  
	  \note For a list of event types, refer to \ref etypes.
	*/
	uint16_t get_type();

	/*!
	  \brief Get the event's flags.
	*/
	ppm_event_flags get_flags();

	/*!
	  \brief Return the event direction: in or out.
	*/
	event_direction get_direction();

	/*!
	  \brief Get the event timestamp.

	  \return The event timestamp, in nanoseconds from epoch
	*/
	uint64_t get_ts();


	/*!
	  \brief Return the event name string, e.g. 'open' or 'socket'.
	*/
	const char* get_name();

	/*!
	  \brief Get the ID of the thread that generated the event.
	*/
	int64_t get_tid();

	/*!
	  \brief Return the information about the thread that generated the event.

	  \param query_os_if_not_found if this is a live a capture and this flag is
	   set to true, scan the /proc file system to find process information in
	   case the thread is not in the table.
	*/
	sinsp_threadinfo* get_thread_info(bool query_os_if_not_found = false);

	/*!
	  \brief Return the information about the FD on which this event operated.

	  \note For events that are not I/O related, get_fd_info() returns NULL. 
	*/
	sinsp_fdinfo_t* get_fd_info();

	/*!
	  \brief Return the number of the FD associated with this event.

	  \note For events that are not I/O related, get_fd_num() returns sinsp_evt::INVALID_FD_NUM. 
	*/
	uint64_t get_fd_num();

	/*!
	  \brief Return the number of parameters that this event has.
	*/
	uint32_t get_num_params();

	/*!
	  \brief Get the name of one of the event parameters, e.g. 'fd' or 'addr'.

	  \param id The parameter number.
	*/
	const char* get_param_name(uint32_t id);

	/*!
	  \brief Get the metadata that describes one of this event's parameters.

	  \param id The parameter number.

	  \note Refer to the g_event_info structure in driver/event_table.c for 
	   a list of event descriptions.
	*/
	const struct ppm_param_info* get_param_info(uint32_t id);

	/*!
	  \brief Get a parameter in raw format.

	  \param id The parameter number.
	*/
	sinsp_evt_param* get_param(uint32_t id);

	/*!
	  \brief Get a parameter in raw format.

	  \param name The parameter name.
	*/
	const sinsp_evt_param* get_param_value_raw(const char* name);

	/*!
	  \brief Get a hostname from a binary ipv4 string

	  \param binary_adress The 32 bit binary address to use
	  \param buf The hostname container, of size NI_MAXHOST
 	*/
	char* get_binary_ipv4_as_host(void* binary_address, char* buf);

	/*!
	  \brief Get a parameter as a C++ string.

	  \param name The parameter name.
	  \param resolved If true, the library will try to resolve the parameter 
	   before returning it. For example, and FD number will be converted into
	   the correspondent file, TCP tuple, etc.
	*/
	string get_param_value_str(string& name, bool resolved = true);

	/*!
	  \brief Return the event's category, based on the event type and the FD on
	   which the event operates.
	*/
	void get_category(OUT sinsp_evt::category* cat);

#ifdef HAS_FILTERING
	/*!
	  \brief Return true if the event has been rejected by the filtering system.
	*/
	bool is_filtered_out();
#endif

// Doxygen doesn't understand VISIBILITY_PRIVATE
#ifdef _DOXYGEN
private:
#endif

	void set_iosize(uint32_t size);
	uint32_t get_iosize();
	const char* get_param_as_str(uint32_t id, OUT const char** resolved_str, param_fmt fmt = PF_NORMAL);
	const char* get_param_value_str(const char* name, OUT const char** resolved_str, param_fmt fmt = PF_NORMAL);

	void init();
	void init(uint8_t* evdata, uint16_t cpuid);
	void load_params();
	string get_param_value_str(uint32_t id, bool resolved);
	string get_param_value_str(const char* name, bool resolved = true);

VISIBILITY_PRIVATE

	sinsp* m_inspector;
	scap_evt* m_pevt;
	uint16_t m_cpuid;
	uint64_t m_evtnum;
	bool m_params_loaded;
	const struct ppm_event_info* m_info;
	vector<sinsp_evt_param> m_params;

	// Note: this is a lot of storage. We assume that it's not a bit deal since
	//       currently there's no case in which more than one single event is 
	//       needed by the library users. We'll optmize this when we'll have the 
	//       need.
	vector<char> m_paramstr_storage;
	vector<char> m_resolved_paramstr_storage;

	sinsp_threadinfo* m_tinfo;
	sinsp_fdinfo_t* m_fdinfo;
	uint32_t m_iosize;
	int32_t m_errorcode;
#ifdef HAS_FILTERING
	bool m_filtered_out;
#endif

	friend class sinsp;
	friend class sinsp_parser;
	friend class sinsp_threadinfo;
	friend class sinsp_analyzer;
	friend class sinsp_filter_check_event;
	friend class sinsp_dumper;
	friend class sinsp_analyzer_fd_listener;
	friend class sinsp_analyzer_parsers;
};

/*@}*/
