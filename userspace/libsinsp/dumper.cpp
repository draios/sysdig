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

#include "sinsp.h"
#include "sinsp_int.h"
#include "../libscap/scap.h"
#include "dumper.h"

sinsp_dumper::sinsp_dumper(sinsp* inspector)
{
	m_inspector = inspector;
	m_dumper = NULL;
}

sinsp_dumper::~sinsp_dumper()
{
	if(m_dumper != NULL)
	{
		scap_dump_close(m_dumper);
	}
}

void sinsp_dumper::open(const string& filename)
{
	if(m_inspector->m_h == NULL)
	{
		throw sinsp_exception("can't start event dump, inspector not opened yet");
	}

	m_dumper = scap_dump_open(m_inspector->m_h, filename.c_str());
	if(m_dumper == NULL)
	{
		throw sinsp_exception(scap_getlasterr(m_inspector->m_h));
	}
}

void sinsp_dumper::dump(sinsp_evt* evt)
{
	if(m_dumper == NULL)
	{
		throw sinsp_exception("dumper not opened yet");
	}

	int32_t res = scap_dump(m_inspector->m_h, 
		m_dumper, evt->m_pevt, evt->m_cpuid);

	if(res != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_inspector->m_h));
	}
}

uint64_t sinsp_dumper::written_bytes()
{
	if(m_dumper == NULL)
	{
		throw sinsp_exception("dumper not opened yet");
	}

	return scap_dump_ftell(m_dumper);	
}
