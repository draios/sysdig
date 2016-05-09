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

#ifndef _WIN32
#include <sys/time.h>
#else
#include <time.h>
#endif
#include <stdarg.h>
#include "sinsp.h"
#include "sinsp_int.h"

///////////////////////////////////////////////////////////////////////////////
// sinsp_logger implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_logger::sinsp_logger()
{
	m_file = NULL;
	m_flags = OT_NONE;
	m_sev = SEV_INFO;
	m_callback = NULL;
}

sinsp_logger::~sinsp_logger()
{
	if(m_file)
	{
		ASSERT(m_flags & sinsp_logger::OT_FILE);
		fclose(m_file);
	}
}

void sinsp_logger::set_log_output_type(sinsp_logger::output_type log_output_type)
{
	if(log_output_type & (sinsp_logger::OT_STDOUT | sinsp_logger::OT_STDERR)) 
	{
		m_flags = log_output_type;
	}
	else if(log_output_type == sinsp_logger::OT_STDERR)
	{
		add_file_log("sinsp.log");
	}
	else if(log_output_type == sinsp_logger::OT_NONE)
	{
		return;
	}
	else
	{
		ASSERT(false);
		throw sinsp_exception("invalid log output type");
	}
}

void sinsp_logger::add_stdout_log()
{
	ASSERT((m_flags & sinsp_logger::OT_STDERR) == 0);

	m_flags |= sinsp_logger::OT_STDOUT;
}

void sinsp_logger::add_stderr_log()
{
	ASSERT((m_flags & sinsp_logger::OT_STDOUT) == 0);

	m_flags |= sinsp_logger::OT_STDERR;
}

void sinsp_logger::add_file_log(string filename)
{
	ASSERT(m_file == NULL);

	m_file = fopen(filename.c_str(), "w");
	if(!m_file)
	{
		throw sinsp_exception("unable to open file " + filename + " for writing");
	}

	m_flags |= sinsp_logger::OT_FILE;
}

void sinsp_logger::add_callback_log(sinsp_logger_callback callback)
{
	ASSERT(m_callback == NULL);
	m_callback = callback;
	m_flags |= sinsp_logger::OT_CALLBACK;
}

void sinsp_logger::remove_callback_log()
{
	m_callback = 0;
	m_flags &= ~sinsp_logger::OT_CALLBACK;
}

void sinsp_logger::set_severity(severity sev)
{
	if(m_sev < SEV_MIN || m_sev > SEV_MAX)
	{
		throw sinsp_exception("invalid log severity");
	}

	m_sev = sev;
}

sinsp_logger::severity sinsp_logger::get_severity() const
{
	return m_sev;
}

void sinsp_logger::log(string msg, event_severity sev)
{
	if(is_callback())
	{
		(*m_callback)(std::move(msg), (uint32_t)sev);
	}
}

void sinsp_logger::log(string msg, severity sev)
{
	if((sev > m_sev) || is_user_event(sev))
	{
		return;
	}

	if((m_flags & sinsp_logger::OT_NOTS) == 0)
	{
		struct timeval ts;
		gettimeofday(&ts, NULL);
		time_t rawtime = (time_t)ts.tv_sec;
		struct tm* time_info = gmtime(&rawtime);
		snprintf(m_tbuf, sizeof(m_tbuf), "%.2d-%.2d %.2d:%.2d:%.2d.%.6d ",
			time_info->tm_mon + 1,
			time_info->tm_mday,
			time_info->tm_hour,
			time_info->tm_min,
			time_info->tm_sec,
			(int)ts.tv_usec);
		msg.insert(0, m_tbuf, 22);
	}

	if(is_callback() && m_callback)
	{
		(*m_callback)(std::move(msg), (uint32_t)sev);
	}
	else if((m_flags & sinsp_logger::OT_FILE) && m_file)
	{
		fprintf(m_file, "%s\n", msg.c_str());
		fflush(m_file);
	}
	else if(m_flags & sinsp_logger::OT_STDOUT)
	{
		fprintf(stdout, "%s\n", msg.c_str());
		fflush(stdout);
	}
	else if(m_flags & sinsp_logger::OT_STDERR)
	{
		fprintf(stderr, "%s\n", msg.c_str());
		fflush(stderr);
	}
}

char* sinsp_logger::format(severity sev, const char* fmt, ...)
{
	if(!is_callback() && is_user_event(sev))
	{
		m_tbuf[0] = '\0';
		return m_tbuf;
	}

	va_list ap;

	va_start(ap, fmt);
	vsnprintf(m_tbuf, sizeof(m_tbuf), fmt, ap);
	va_end(ap);

	log(m_tbuf, sev);

	return m_tbuf;
}

char* sinsp_logger::format(const char* fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(m_tbuf, sizeof(m_tbuf), fmt, ap);
	va_end(ap);

	log(m_tbuf, SEV_INFO);

	return m_tbuf;
}
