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
