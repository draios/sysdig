/*
Copyright (C) 2013-2014 Draios inc.
 
This file is part of sysdig.

sysdig is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

///////////////////////////////////////////////////////////////////////////////
// The logger class
///////////////////////////////////////////////////////////////////////////////
typedef void (*sinsp_logger_callback)(char* str, uint32_t sev);

class SINSP_PUBLIC sinsp_logger
{
public:
	enum severity
	{
		SEV_DEBUG = 0,
		SEV_INFO = 1,
		SEV_WARNING = 2,
		SEV_ERROR = 3,
		SEV_CRITICAL = 4,
		SEV_MAX = SEV_CRITICAL,
	};

	enum output_type
	{
		OT_NONE = 0,
		OT_STDOUT = 1,
		OT_STDERR = 2,
		OT_FILE = 4,
		OT_CALLBACK = 8,
		OT_NOTS = 256,
	};

	sinsp_logger();
	~sinsp_logger();

	void set_log_output_type(sinsp_logger::output_type log_output_type);
	void add_stdout_log();
	void add_stderr_log();
	void add_file_log(string filename);
	void add_file_log(FILE* f);
	void add_callback_log(sinsp_logger_callback callback);

	void set_severity(severity sev);

	void log(string msg, severity sev=SEV_INFO);
	// Log function that accepts printf syntax and returns the formatted buffer.
	char* format(severity sev, const char* fmt, ...);

private:
	FILE* m_file;
	sinsp_logger_callback m_callback;
	uint32_t m_flags;
	severity m_sev;
	char m_tbuf[512];
};
