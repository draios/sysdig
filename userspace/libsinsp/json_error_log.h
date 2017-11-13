#pragma once

#include <string>

class json_error_log
{
public:

	// Upon any json parsing error, write the error and json
	// document that had the error to this file. Not enabled by
	// default.
	void set_json_parse_errors_file(const std::string& filename);

	// Possibly log a json parsing error, depending on whether or
	// not the above filename was set.
	void log(const std::string &json, const std::string &errstr);

private:
	std::string m_json_parse_errors_file;
};

extern json_error_log g_json_error_log;

