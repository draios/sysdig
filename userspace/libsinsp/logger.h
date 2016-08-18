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

///////////////////////////////////////////////////////////////////////////////
// The logger class
///////////////////////////////////////////////////////////////////////////////
typedef void (*sinsp_logger_callback)(std::string&& str, uint32_t sev);

class SINSP_PUBLIC sinsp_logger
{
public:
	static const uint32_t SEVERITY_NONE = (uint32_t)-1;

	enum severity
	{
		SEV_FATAL = 1,
		SEV_CRITICAL = 2,
		SEV_ERROR = 3,
		SEV_WARNING = 4,
		SEV_NOTICE = 5,
		SEV_INFO = 6,
		SEV_DEBUG = 7,
		SEV_TRACE = 8,
		SEV_MIN = SEV_FATAL,
		SEV_MAX = SEV_TRACE
	};

	enum event_severity
	{
		SEV_EVT_EMERGENCY = 10,
		SEV_EVT_FATAL = 11,
		SEV_EVT_CRITICAL = 12,
		SEV_EVT_ERROR = 13,
		SEV_EVT_WARNING = 14,
		SEV_EVT_NOTICE = 15,
		SEV_EVT_INFORMATION = 16,
		SEV_EVT_DEBUG = 17,
		SEV_EVT_MIN = SEV_EVT_EMERGENCY,
		SEV_EVT_MAX = SEV_EVT_DEBUG
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
	void remove_callback_log();

	void set_severity(severity sev);
	severity get_severity() const;

	void log(string msg, severity sev=SEV_INFO);
	void log(string msg, event_severity sev);

	// Log functions that accept printf syntax and return the formatted buffer.
	char* format(severity sev, const char* fmt, ...);
	char* format(const char* fmt, ...);

private:
	bool is_callback() const;
	bool is_user_event(severity sev) const;

	FILE* m_file;
	sinsp_logger_callback m_callback;
	uint32_t m_flags;
	severity m_sev;
	char m_tbuf[32768];
};

inline bool sinsp_logger::is_callback() const
{
	 return (m_flags & sinsp_logger::OT_CALLBACK) != 0;
}

inline bool sinsp_logger::is_user_event(severity sev) const
{
	 return (static_cast<int>(sev) >= static_cast<int>(SEV_EVT_MIN) &&
			static_cast<int>(sev) <= static_cast<int>(SEV_EVT_MAX));
}

