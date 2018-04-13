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

class sinsp_filter_check;

/** @defgroup event Event manipulation
 *  @{
 */

/*!
  \brief Event to string converter class.
  This class can be used to format an event into a string, based on an arbitrary
  format.
*/
class SINSP_PUBLIC sinsp_evt_formatter
{
public:
	/*!
	  \brief Constructs a formatter.

	  \param inspector Pointer to the inspector instance that will generate the
	   events to be formatter.
	  \param fmt The printf-like format to use. The accepted format is the same
	   as the one of the sysdig '-p' command line flag, so refer to the sysdig
	   manual for details.
	*/
	sinsp_evt_formatter(sinsp* inspector, const string& fmt);

	~sinsp_evt_formatter();

	/*!
	  \brief Resolve all the formatted tokens and return them in a key/value
	  map.

	  \param evt Pointer to the event to be converted into string.
	  \param res Reference to the map that will be filled with the result.

	  \return true if all the tokens can be retrieved successfully, false
	  otherwise.
	*/
	bool resolve_tokens(sinsp_evt *evt, map<string,string>& values);

	/*!
	  \brief Fills res with the string rendering of the event.

	  \param evt Pointer to the event to be converted into string.
	  \param res Pointer to the string that will be filled with the result.

	  \return true if the string should be shown (based on the initial *),
	   false otherwise.
	*/
	bool tostring(sinsp_evt* evt, OUT string* res);

	/*!
	  \brief Fills res with end of capture string rendering of the event.
	  \param res Pointer to the string that will be filled with the result.

	  \return true if there is a string to show (based on the format),
	   false otherwise.
	*/
	bool on_capture_end(OUT string* res);

private:
	void set_format(const string& fmt);

	// vector of (full string of the token, filtercheck) pairs
	// e.g. ("proc.aname[2], ptr to sinsp_filter_check_thread)
	vector<pair<string, sinsp_filter_check*>> m_tokens;
	vector<uint32_t> m_tokenlens;
	sinsp* m_inspector;
	bool m_require_all_values;
	vector<sinsp_filter_check*> m_chks_to_free;

	Json::Value m_root;
	Json::FastWriter m_writer;
};

/*!
  \brief Caching version of sinsp_evt_formatter
  This class is a wrapper around sinsp_evt_formatter, maintaining a
  cache of previously seen formatters. It avoids the overhead of
  recreating sinsp_evt_formatter objects for each event.
*/
class SINSP_PUBLIC sinsp_evt_formatter_cache
{
public:
	sinsp_evt_formatter_cache(sinsp *inspector);
	virtual ~sinsp_evt_formatter_cache();

	// Resolve the tokens inside format and return them as a key/value map.
	// Creates a new sinsp_evt_formatter object if necessary.
	bool resolve_tokens(sinsp_evt *evt, std::string &format, map<string,string>& values);

	// Fills in res with the event formatted according to
	// format. Creates a new sinsp_evt_formatter object if
	// necessary.
	bool tostring(sinsp_evt *evt, std::string &format, OUT std::string *res);

private:

	// Get the formatter for this format string. Creates a new
	// sinsp_evt_formatter object if necessary.
	std::shared_ptr<sinsp_evt_formatter>& get_cached_formatter(string &format);

	std::map<std::string,std::shared_ptr<sinsp_evt_formatter>> m_formatter_cache;
	sinsp *m_inspector;
};
/*@}*/
