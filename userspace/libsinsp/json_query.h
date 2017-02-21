//
// json_parser.h
//
// jq wrapper
//

#ifdef __linux__

#pragma once
//
// Avoid some annoying "function not used" from jq headers;
// this pragma affects this header file only and has no efect
// on source file including it;
// see https://gcc.gnu.org/onlinedocs/cpp/System-Headers.html
//
#ifdef __GNUC__
#	pragma GCC system_header
#endif

#include <string.h>
#include <alloca.h>
#include <assert.h>

// jq is not C++-friendly
extern "C"
{
	#include "jv.h"
	#include "jq.h"
}

#include <string>

class json_query
{
public:
	json_query(const std::string& json = "", const std::string& filter = "", bool dbg = false);
	~json_query();

	void set_json(const std::string& json);
	const std::string& get_json() const;

	void set_filter(const std::string& filter);
	const std::string& get_filter() const;

	bool process(const std::string& json, const std::string& filter, bool dbg = false);
	const std::string& result(int flags = 0);

	const std::string& get_error() const;

private:
	void clear();
	void cleanup();
	void cleanup(jv& j, const std::string& msg = "");

	jq_state*           m_jq;
	std::string         m_json;
	std::string         m_filter;
	std::string         m_filtered_json;
	jv                  m_input;
	jv                  m_result;
	bool                m_processed;
	mutable std::string m_error;
};

inline void json_query::set_json(const std::string& json)
{
	m_json = json;
}

inline const std::string& json_query::get_json() const
{
	return m_json;
}

inline void json_query::set_filter(const std::string& filter)
{
	m_filter = filter;
}

inline const std::string& json_query::get_filter() const
{
	return m_filter;
}

inline const std::string& json_query::get_error() const
{
	return m_error;
}

#endif // __linux__
