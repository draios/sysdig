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
// The protocol decoder interface
///////////////////////////////////////////////////////////////////////////////
class sinsp_protodecoder
{
public:
	sinsp_protodecoder();
	
	virtual ~sinsp_protodecoder()
	{
	}

	//
	// Allocate a new decoder of the same type.
	// Every protodecoder plugin must implement this.
	//
	virtual sinsp_protodecoder* allocate_new() = 0;

	//
	// Allocate a new decoder of the same type.
	// Every protodecoder plugin must implement this.
	//
	virtual void init() = 0;

	//
	// Return the protocol decoder name
	//
	const string& get_name()
	{
		return m_name;
	}

	//
	// Called by the engine for each of the FDs that are added from proc 
	// (or from the file) at the beginning of a capture.
	//
	virtual void on_fd_from_proc(sinsp_fdinfo_t* fdinfo) = 0;

	//
	// Called by the engine after an event has been received and parsed.
	//
	virtual void on_event(sinsp_evt* evt, sinsp_parser::callback_type etype) = 0;
	
	//
	// These have custom implementations for performance reasons
	//
	virtual void on_read(sinsp_evt* evt, char *data, uint32_t len);
	virtual void on_write(sinsp_evt* evt, char *data, uint32_t len);

protected:
	//
	// Interface for the plugins
	//
	void register_event_callback(sinsp_parser::callback_type etype);
	void register_read_callback(sinsp_fdinfo_t* fdinfo);
	void register_write_callback(sinsp_fdinfo_t* fdinfo);

	string m_name;

private:
	void set_inspector(sinsp* inspector);

	sinsp* m_inspector;

friend class sinsp_protodecoder_list;
};

///////////////////////////////////////////////////////////////////////////////
// Global class that stores the list of protocol decoders and offers
// functions to work with it.
///////////////////////////////////////////////////////////////////////////////
class sinsp_protodecoder_list
{
public:
	sinsp_protodecoder_list();
	~sinsp_protodecoder_list();
	void add_protodecoder(sinsp_protodecoder* protodecoder);
	sinsp_protodecoder* new_protodecoder_from_name(const string& name, sinsp* inspector);

private:
	vector<sinsp_protodecoder*> m_decoders_list;
};

///////////////////////////////////////////////////////////////////////////////
// Decoder classes
// NOTE: these should be moved to a separate file but, since we have only one
//       for the moment, we keep it here
///////////////////////////////////////////////////////////////////////////////
class sinsp_decoder_syslog : public sinsp_protodecoder
{
public:
	sinsp_decoder_syslog();
	sinsp_protodecoder* allocate_new();
	void init();
	void on_fd_from_proc(sinsp_fdinfo_t* fdinfo);
	void on_event(sinsp_evt* evt, sinsp_parser::callback_type etype);
	void on_write(sinsp_evt* evt, char *data, uint32_t len);

private:
};
