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

#include "sinsp.h"
#include "sinsp_int.h"
#include "../libscap/scap.h"
#include "dumper.h"

sinsp_dumper::sinsp_dumper(sinsp* inspector)
{
	m_inspector = inspector;
	m_dumper = NULL;
	m_target_memory_buffer = NULL;
	m_target_memory_buffer_size = 0;
	m_nevts = 0;
}

sinsp_dumper::sinsp_dumper(sinsp* inspector, uint8_t* target_memory_buffer, uint64_t target_memory_buffer_size)
{
	m_inspector = inspector;
	m_dumper = NULL;
	m_target_memory_buffer = target_memory_buffer;
	m_target_memory_buffer_size = target_memory_buffer_size;
}

sinsp_dumper::~sinsp_dumper()
{
	if(m_dumper != NULL)
	{
		scap_dump_close(m_dumper);
	}
}

void sinsp_dumper::open(const string& filename, bool compress, bool threads_from_sinsp)
{
	if(m_inspector->m_h == NULL)
	{
		throw sinsp_exception("can't start event dump, inspector not opened yet");
	}

	if(m_target_memory_buffer)
	{
		m_dumper = scap_memory_dump_open(m_inspector->m_h, m_target_memory_buffer, m_target_memory_buffer_size);
	}
	else
	{
		if(compress)
		{
			m_dumper = scap_dump_open(m_inspector->m_h, filename.c_str(), SCAP_COMPRESSION_GZIP);
		}
		else
		{
			m_dumper = scap_dump_open(m_inspector->m_h, filename.c_str(), SCAP_COMPRESSION_NONE);
		}
	}

	if(m_dumper == NULL)
	{
		throw sinsp_exception(scap_getlasterr(m_inspector->m_h));
	}

	if(threads_from_sinsp)
	{
		m_inspector->m_thread_manager->dump_threads_to_file(m_dumper);
	}

	m_inspector->m_container_manager.dump_containers(m_dumper);

	m_nevts = 0;
}

void sinsp_dumper::fdopen(int fd, bool compress, bool threads_from_sinsp)
{
	if(m_inspector->m_h == NULL)
	{
		throw sinsp_exception("can't start event dump, inspector not opened yet");
	}

	if(compress)
	{
		m_dumper = scap_dump_open_fd(m_inspector->m_h, fd, SCAP_COMPRESSION_GZIP, true);
	}
	else
	{
		m_dumper = scap_dump_open_fd(m_inspector->m_h, fd, SCAP_COMPRESSION_NONE, true);
	}

	if(m_dumper == NULL)
	{
		throw sinsp_exception(scap_getlasterr(m_inspector->m_h));
	}

	if(threads_from_sinsp)
	{
		m_inspector->m_thread_manager->dump_threads_to_file(m_dumper);
	}

	m_inspector->m_container_manager.dump_containers(m_dumper);

	m_nevts = 0;
}

void sinsp_dumper::close()
{
	if(m_dumper != NULL)
	{
		scap_dump_close(m_dumper);
		m_dumper = NULL;
	}
}

bool sinsp_dumper::is_open()
{
	return (m_dumper != NULL);
}

bool sinsp_dumper::written_events()
{
	return m_nevts;
}

void sinsp_dumper::dump(sinsp_evt* evt)
{
	if(m_dumper == NULL)
	{
		throw sinsp_exception("dumper not opened yet");
	}

	scap_evt* pdevt = (evt->m_poriginal_evt)? evt->m_poriginal_evt : evt->m_pevt;

	int32_t res = scap_dump(m_inspector->m_h,
		m_dumper, pdevt, evt->m_cpuid, 0);

	if(res != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_inspector->m_h));
	}

	m_nevts++;
}

uint64_t sinsp_dumper::written_bytes()
{
	if(m_dumper == NULL)
	{
		return 0;
	}

	int64_t written_bytes = scap_dump_get_offset(m_dumper);
	if(written_bytes == -1)
	{
		throw sinsp_exception("error getting offset");
	}

	return written_bytes;
}

uint64_t sinsp_dumper::next_write_position()
{
	if(m_dumper == NULL)
	{
		return 0;
	}

	int64_t position = scap_dump_ftell(m_dumper);
	if(position == -1)
	{
		throw sinsp_exception("error getting offset");
	}

	return position;
}

void sinsp_dumper::flush()
{
	if(m_dumper == NULL)
	{
		throw sinsp_exception("dumper not opened yet");
	}

	scap_dump_flush(m_dumper);
}
