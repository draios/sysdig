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

#include <time.h>
#ifndef _WIN32
#include <algorithm>
#endif
#include "sinsp.h"
#include "sinsp_int.h"
#include "protodecoder.h"

extern sinsp_protodecoder_list g_decoderlist;

///////////////////////////////////////////////////////////////////////////////
// sinsp_protodecoder implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_protodecoder::sinsp_protodecoder()
{
}

void sinsp_protodecoder::set_inspector(sinsp* inspector)
{
	m_inspector = inspector;
}

void sinsp_protodecoder::on_read(sinsp_evt* evt, char *data, uint32_t len)
{
	ASSERT(false);
}

void sinsp_protodecoder::on_write(sinsp_evt* evt, char *data, uint32_t len)
{
	ASSERT(false);
}

void sinsp_protodecoder::register_event_callback(sinsp_pd_callback_type etype)
{
	ASSERT(m_inspector != NULL);

	m_inspector->m_parser->register_event_callback(etype, this);
}

void sinsp_protodecoder::register_read_callback(sinsp_fdinfo_t* fdinfo)
{
	ASSERT(m_inspector != NULL);

	fdinfo->register_event_callback(CT_READ, this);
}

void sinsp_protodecoder::register_write_callback(sinsp_fdinfo_t* fdinfo)
{
	ASSERT(m_inspector != NULL);

	fdinfo->register_event_callback(CT_WRITE, this);
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_protodecoder_list implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_protodecoder_list::sinsp_protodecoder_list()
{
	//////////////////////////////////////////////////////////////////////////////
	// ADD NEW DECODER CLASSES HERE
	//////////////////////////////////////////////////////////////////////////////
//	add_protodecoder(new sinsp_decoder_syslog());
}

sinsp_protodecoder_list::~sinsp_protodecoder_list()
{
	uint32_t j;

	for(j = 0; j < m_decoders_list.size(); j++)
	{
		delete m_decoders_list[j];
	}
}

void sinsp_protodecoder_list::add_protodecoder(sinsp_protodecoder* protodecoder)
{
	m_decoders_list.push_back(protodecoder);
}

sinsp_protodecoder* sinsp_protodecoder_list::new_protodecoder_from_name(const string& name,
																		   sinsp* inspector)
{
	uint32_t j;

	for(j = 0; j < m_decoders_list.size(); j++)
	{
		m_decoders_list[j]->m_inspector = inspector;

		if(m_decoders_list[j]->m_name == name)
		{
			sinsp_protodecoder* newchk = m_decoders_list[j]->allocate_new();
			newchk->set_inspector(inspector);
			return newchk;
		}
	}

	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_decoder_syslog implementation
///////////////////////////////////////////////////////////////////////////////
/*
sinsp_decoder_syslog::sinsp_decoder_syslog()
{
	m_name = "syslog";
}

sinsp_protodecoder* sinsp_decoder_syslog::allocate_new()
{
	return (sinsp_protodecoder*) new sinsp_decoder_syslog();
}

void sinsp_decoder_syslog::init()
{
	register_event_callback(CT_OPEN);
	register_event_callback(CT_CONNECT);
}

void sinsp_decoder_syslog::on_fd_from_proc(sinsp_fdinfo_t* fdinfo)
{
	ASSERT(fdinfo != NULL);

	if(fdinfo->m_name.find("/dev/log") != string::npos)
	{
		register_write_callback(fdinfo);
	}
}

void sinsp_decoder_syslog::on_event(sinsp_evt* evt, sinsp_pd_callback_type etype)
{
	if(etype == CT_OPEN ||
		etype == CT_CONNECT)
	{
		sinsp_fdinfo_t* fdinfo = evt->get_fd_info();

		if(fdinfo->m_name.find("/dev/log") != string::npos)
		{
			register_write_callback(fdinfo);
		}
	}
	else
	{
		ASSERT(false);
	}
}

void sinsp_decoder_syslog::on_write(sinsp_evt* evt, char *data, uint32_t len)
{
	int a = 0;
}
*/