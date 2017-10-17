--[[
Copyright (C) 2014 Draios inc.
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.


This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
--]]

-- Chisel description
description = "This chisel intercepts all reads and writes to files of any of the given types: files, pipes or unix sockets. You can capture all or limit to files, pipes or unix socket."
short_description = "Echo any read/write made by any process to files, pipes or unix sockets. Optionally, you can provide the name of a file, pipe or unix socket to only intercept reads/writes to that file, pipe or unix socket.";
category = "I/O";

-- Argument list
args = 
{
	{
		name = "read_or_write",
		description = "Specify 'R' to capture only read events; 'W' to capture only write events; 'RW' to capture read and write events. By default both read and write events are captured.",
		argtype = "string",
		optional = true
	},
	{
		name = "type_of_file", 
		description = "Specify 'F' to capture only file events; 'P' to capture only pipe events; 'U' to capture only unix socket events; 'FP' to capture file and pipe events; Similar with 'PF', 'FU', 'PU', etc. By default only file events are captured.",
		argtype = "string",
		optional = true
	},
	{
		name = "spy_on_file_name", 
		description = "The name of the file which the chisel should spy on for all read and write activity.", 
		argtype = "string",
		optional = true
	}
}

-- Imports and globals
require "common"
local spy_file_name = nil
local read_or_write = nil
local type_of_file = "f"
local verbose = false

-- Argument notification callback
function on_set_arg(name, val)
	if name == "read_or_write" then
		read_or_write = val:lower()
		return true
	elseif name == "type_of_file" then
		type_of_file = val:lower()
		return true
	elseif name == "spy_on_file_name" then
		spy_file_name = val
		return true
	end

	return false
end

-- Initialization callback
function on_init()	
	local filter

	-- Request the fields that we need
	fbuf = chisel.request_field("evt.buffer")
	fdata = chisel.request_field("evt.arg.data")
	ffdname = chisel.request_field("fd.name")
	fisw = chisel.request_field("evt.is_io_write")
	fpid = chisel.request_field("proc.pid")
	fpname = chisel.request_field("proc.name")
	fres = chisel.request_field("evt.rawarg.res")
	ftid = chisel.request_field("thread.tid")
	fts = chisel.request_field("evt.time")

	-- increase the snaplen so we capture more of the conversation 
	sysdig.set_snaplen(2000)

	-- set the output format to ascii
	sysdig.set_output_format("ascii")

	-- set the filter
	if spy_file_name ~= nil and spy_file_name ~= "" then
		if type_of_file ~= nil and type_of_file:match("u") ~= nil then
			-- use contains when filtering against unix sockets names
			filter = string.format("(fd.name contains %s) and ", spy_file_name)
		else
			filter = string.format("(fd.name=%s) and ", spy_file_name)
		end
	else
		-- watching terminals risks looping in a live capture
		filter = "(not fd.name contains /dev/pt and not fd.name contains /dev/tty) and "
	end

	if read_or_write == "r" then
		filter = string.format("%s%s", filter, "evt.is_io_read=true and ")
	elseif read_or_write == "w" then
		filter = string.format("%s%s", filter, "evt.is_io_write=true and ")
	else
		filter = string.format("%s%s", filter, "evt.is_io=true and ")
	end

	if type_of_file == "f" then
		filter = string.format("%s%s", filter, "fd.type=file and ")
	elseif type_of_file == "p" then
		filter = string.format("%s%s", filter, "fd.type=pipe and ")
	elseif type_of_file == "u" then
		filter = string.format("%s%s", filter, "fd.type=unix and ")
	elseif type_of_file == "fp" or type_of_file == "pf" then
		filter = string.format("%s%s", filter, "(fd.type=file or fd.type=pipe) and ")
	elseif type_of_file == "fu" or type_of_file == "uf" then
		filter = string.format("%s%s", filter, "(fd.type=file or fd.type=unix) and ")
	elseif type_of_file == "pu" or type_of_file == "up" then
		filter = string.format("%s%s", filter, "(fd.type=pipe or fd.type=unix) and ")
	else
		filter = string.format("%s%s", filter, "(fd.type=file or fd.type=pipe or fd.type=unix) and ")
	end

	filter = string.format("%s%s", filter, "evt.dir=< and evt.failed=false")

	if verbose then
		print("filter=" .. filter)
	end

	chisel.set_filter(filter)

	return true
end

-- Event parsing callback
function on_event()	
	-- Extract the event details
	local data = evt.field(fdata)
	local fdname = evt.field(ffdname)
	local is_write = evt.field(fisw)
	local pid = evt.field(fpid)
	local pname = evt.field(fpname)
	local res = evt.field(fres)
	local ts = evt.field(fts)
	local read_write

	-- Render the message to screen
	if is_write == true then
		read_write = "W"
	else
		read_write = "R"
	end

	print(string.format("%s %s(%s) %s %s %s %s", ts, pname, pid, read_write, format_bytes(res), fdname, data))

	return true
end
