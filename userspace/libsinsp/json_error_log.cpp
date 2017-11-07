#include <fstream>

#include "json_error_log.h"

json_error_log g_json_error_log;

void json_error_log::set_json_parse_errors_file(const std::string& filename)
{
	m_json_parse_errors_file = filename;
}

void json_error_log::log(const std::string &json, const std::string &errstr)
{
	std::ofstream errs(m_json_parse_errors_file, std::ofstream::out | std::ofstream::app);

	errs << "*******************************";
	errs << errstr;
	errs << json;
	errs << "*******************************";

	errs.close();
}

