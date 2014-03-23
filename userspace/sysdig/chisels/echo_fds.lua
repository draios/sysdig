--[[
Copyright (C) 2013-2014 Draios inc.
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
--]]

-- Chisel description
description = "print the data read and written for any FD. Combine this script with a filter to restrict what it shows.";
short_description = "echo FDs";
category = "IO";

args = {}

require "common"
terminal = require "ansiterminal"

-- Initialization callback
function on_init()
	-- Request the fileds that we need
	fbuf = chisel.request_field("evt.rawarg.data")
	fisread = chisel.request_field("evt.is_io_read")
	fres = chisel.request_field("evt.rawarg.res")
	fname = chisel.request_field("fd.name")

	-- increase the snaplen so we capture more of the conversation 
	sysdig.set_snaplen(2000)
	
	-- set the filter
	chisel.set_filter("evt.is_io=true and evt.dir=<")
	chisel.set_event_formatter("%evt.arg.data")
	
	return true
end

-- Event parsing callback
function on_event()
	buf = evt.field(fbuf)
	isread = evt.field(fisread)
	res = evt.field(fres)
	name = evt.field(fname)

	if name == nil then
		name = "<NA>"
	end

	if res <= 0 then
		return true
	end
	
	if isread then
		infostr = string.format("%s------ Read %s from %s", terminal.red, format_bytes(res), name)
	else
		infostr = string.format("%s------ Write %s to %s", terminal.blue, format_bytes(res), name)
	end
	
	print(infostr)

	return true
end

function on_capture_end()
	print(terminal.resetcolor)
end
