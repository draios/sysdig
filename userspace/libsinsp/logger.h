/*
Copyright (C) 2013-2019 Sysdig, Inc.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#pragma once

#include "sinsp_public.h"

#include <atomic>
#include <string>

using sinsp_logger_callback = void (*)(std::string&& str, uint32_t sev);

/**
 * Sysdig component logging API.  This API exposes the ability to log to a
 * variety of log sinks.  sinsp_logger will use only one enabled log* sink;
 * if multiple are enabled, then it will use the first available one it
 * finds.  The order in which log sinks is considered is: (1) a registered
 * callback function, (2) a registered file, (3) standard output, and
 * (4) standard error.
 */
class SINSP_PUBLIC sinsp_logger
{
public:
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
	};
	const static severity SEV_MIN = SEV_FATAL;
	const static severity SEV_MAX = SEV_TRACE;

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
	};
	const static event_severity SEV_EVT_MIN = SEV_EVT_EMERGENCY;
	const static event_severity SEV_EVT_MAX = SEV_EVT_DEBUG;

	enum event_memdump_severity
	{
		SEV_EVT_MDUMP = SEV_EVT_MAX + 1
	};

	const static uint32_t OT_NONE;
	const static uint32_t OT_STDOUT;
	const static uint32_t OT_STDERR;
	const static uint32_t OT_FILE;
	const static uint32_t OT_CALLBACK;
	const static uint32_t OT_NOTS;
	const static uint32_t OT_ENCODE_SEV;

	/**
	 * Initialize this sinsp_logger with no output sinks enabled.
	 */
	sinsp_logger();
	~sinsp_logger();

	/**
	 * Get the currently configured output type, which includes the
	 * configured output sinks as well as whether timestamps are enabled
	 * or not.
	 */
	uint32_t get_log_output_type() const;

	/** Enable the standard output log sink. */
	void add_stdout_log();

	/** Enable the standard error log sink. */
	void add_stderr_log();

	/**
	 * Enable the file log sink.
	 *
	 * @param[in] filename The filename to which sinsp_logger should write
	 *                     logs.
	 */
	void add_file_log(const std::string& filename);

	/** Disables tagging logs with the current timestamp. */
	void disable_timestamps();

	/** Adds encoded severity to log messages */
	void add_encoded_severity();

	/**
	 * Registered the given callback as the logging callback.
	 *
	 * Note: the given callback must be thread-safe.
	 */
	void add_callback_log(sinsp_logger_callback callback);

	/** Deregister any registered logging callbacks.  */
	void remove_callback_log();

	/**
	 * Set the minimum severity of logs that this sinsp_logger will emit.
	 */
	void set_severity(severity sev);

	/**
	 * Returns the minimum severity of logs that this sinsp_logger
	 * will emit.
	 */
	severity get_severity() const;

	/**
	 * Emit the given msg to the configured log sink if the given sev
	 * is greater than or equal to the minimum configured logging severity.
	 */
	void log(std::string msg, severity sev = SEV_INFO);

	void log(std::string msg, event_severity sev);

	/**
	 * Write the given printf-style log message of the given severity
	 * with the given format to the configured log sink.
	 *
	 * @returns a pointer to static thread-local storage containing the
	 *          formatted log message.
	 */
	const char* format(severity sev, const char* fmt, ...);

	/**
	 * Write the given printf-style log message of SEV_INFO severity
	 * with the given format to the configured log sink.
	 *
	 * @returns a pointer to static thread-local storage containing the
	 *          formatted log message.
	 */
	const char* format(const char* fmt, ...);

	/** Sets `sev` to the decoded severity or SEV_MAX+1 for errors.
	 *  Returns the length of the severity string on success
	 *  and 0 in case of errors
	 */
	static size_t decode_severity(const std::string &s, severity& sev);

private:
	/** Returns true if the callback log sync is enabled, false otherwise. */
	bool is_callback() const;

	/**
	 * Returns true if the given severity is an event.  The type here
	 * doesn't match the behavior; the implementation checks for a value
	 * of type event_severity even though the parameter is of type
	 * severity.  This component seems to treat the two distinct types
	 * as a single type.
	 */
	static bool is_event_severity(severity sev);

	/** Returns a string containing encoded severity, for OT_ENCODE_SEV. */
	static const char* encode_severity(severity sev);

	std::atomic<FILE*> m_file;
	std::atomic<sinsp_logger_callback> m_callback;
	std::atomic<uint32_t> m_flags;
	std::atomic<severity> m_sev;
};

extern sinsp_logger g_logger;
