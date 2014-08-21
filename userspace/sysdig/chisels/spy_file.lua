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
description = "This chisel intercepts all reads and writes to all files. Instead of all files, you can limit inteception to one file."
short_description = "Echo any read/write made by any process to all files. Optionally, you can provide the name of one file to only intercept reads/writes to that file. The option of exporting the events around each message to a dump file is also available.";
category = "I/O";
		   
-- Argument list
args = 
{
	{
		name = "spy_on_file_name", 
		description = "the name of the file which the chisel should spy on for all read and write activity.", 
		argtype = "string",
		optional = true
	},
    {
		name = "read_or_write",
		description = "specify 'R' to capture only read events; 'W' to capture only write events; 'RW' to capture read and write events. By default both read and write events are captured.",
		argtype = "string",
		optional = true
    },
	{
		name = "dump_file_name", 
		description = "the name of the file where the chisel will write the events related to each syslog entry.", 
		argtype = "string",
		optional = true
	},
	{
		name = "dump_range_ms", 
		description = "the time interval to capture *before* and *after* each event, in milliseconds. For example, 500 means that 1 second around each displayed event (.5s before and .5s after) will be saved to <dump_file_name>. The default value for dump_range_ms is 1000.", 
		argtype = "int",
		optional = true
	},
}

-- Imports and globals
require "common"
local spy_file_name = nil
local read_or_write = nil
local do_dump = false
local dump_file_name = nil
local dump_range_ms = "1000"
local entrylist = {}
local capturing = false
local lastfd = ""
local verbose = false

-- Argument notification callback
function on_set_arg(name, val)
	if name == "read_or_write" then
		read_or_write = val
		return true
	elseif name == "spy_on_file_name" then
		spy_file_name = val
		return true
	elseif name == "dump_file_name" then
		do_dump = true
        dump_file_name = val
        return true
    elseif name == "dump_range_ms" then
        dump_range_ms = val
        return true
    end

    return false
end

-- Initialization callback
function on_init()	
	local filter

	-- Request the fields that we need
	fbuf = chisel.request_field("evt.buffer")
    fts = chisel.request_field("evt.time")
    fisw = chisel.request_field("evt.is_io_write")
	ftid = chisel.request_field("thread.tid")
	fpid = chisel.request_field("proc.pid")
	fpname = chisel.request_field("proc.name")
	ffdname = chisel.request_field("fd.name")

	-- increase the snaplen so we capture more of the conversation 
	sysdig.set_snaplen(2000)
	
	-- set the output format to ascii
	sysdig.set_output_format("ascii")
	
	-- set the filter
	if spy_file_name ~= nil and spy_file_name ~= "" then
		filter = string.format("(fd.name=%s) and ", spy_file_name)
	else
        -- watching terminals risks looping in a live capture
		filter = "(not fd.name contains /dev/pt and not fd.name contains /dev/tty) and "
	end

	if read_or_write == "R" or read_or_write == "r" then
		filter = string.format("%s%s", filter, "evt.is_io_read=true and ")
	elseif read_or_write == "W" or read_or_write == "w" then
		filter = string.format("%s%s", filter, "evt.is_io_write=true and ")
	else
		filter = string.format("%s%s", filter, "evt.is_io=true and ")
	end
	
	filter = string.format("%s%s", filter, "fd.type=file and evt.dir=< and evt.failed=false")

    if verbose then
    	print("filter=" .. filter)
    end

	chisel.set_filter(filter)
	
	-- determine if we're printing our output in a terminal
	is_tty = sysdig.is_tty()
	
	return true
end

function on_capture_start()
	if do_dump then
		if sysdig.is_live() then
			print("events export not supported on live captures")
			return false
		end
	end
	
	capturing = true

	return true
end

-- Event parsing callback
function on_event()	
	-- Extract the event details
	local buf = evt.field(fbuf)
    local ts
    local is_write
	local fdname
    local pid
	local pname

    ts = evt.field(fts)
    is_write = evt.field(fisw)
	fdname = evt.field(ffdname)
    pid = evt.field(fpid)
	pname = evt.field(fpname)
	
	msgs = split(buf, "\n")

	-- Render the message to screen
	for i, msg in ipairs(msgs) do
		if #msg ~= 0 then
			local infostr
			local read_write

			if is_write == true then
				read_write = "W"
			else
				read_write = "R"
			end

			infostr = string.format("%s %s(%s) %s %s %s", ts, pname, pid, read_write, fdname, msg)
			print(infostr)
		end
	end
	
	if do_dump then
		local hi, low = evt.get_ts()
		local tid = evt.field(ftid)
		table.insert(entrylist, {hi, low, tid})
	end
			
	return true
end

function on_capture_end()
	if do_dump then
		if capturing then
			local sn = sysdig.get_evtsource_name()

			local args = "-F -r" .. sn .. " -w" .. dump_file_name .. " "
			
			for i, v in ipairs(entrylist) do
				if i ~= 1 then
					args = args .. " or "
				end
				
				args = args .. "(evt.around[" .. ts_to_str(v[1], v[2]) .. "]=" .. dump_range_ms .. " and thread.tid=" .. v[3] .. ")"
			end		

			print("Writing events for " .. #entrylist .. " log entries")
			sysdig.run_sysdig(args)
		end
	end
end
