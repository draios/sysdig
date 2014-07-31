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

-- Edit this to change which files are watched by this chisel
FILE_FILTER = "(fd.name contains .log or fd.name contains _log or fd.name contains /var/log) and not (fd.name contains .gz or fd.name contains .tgz)"

-- Chisel description
description = "This chisel intercepts all the writes to files containing '.log' or '_log' in their name, and pretty prints them. You can combine this chisel with filters like 'proc.name=foo' (to restrict the output to a specific process), or 'evt.buffer contains foo' (to show only messages including a specific string). You can also write the events generated around each log entry to file by using the dump_file_name and dump_range_ms arguments.";
short_description = "Echo any write made by any process to a log file. Optionally, export the events around each log message to file.";
category = "Logs";
		   
-- Argument list
args = 
{
	{
		name = "dump_file_name", 
		description = "the name of the file where the chisel will write the events related to each syslog entry.", 
		argtype = "srting",
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
terminal = require "ansiterminal"
terminal.enable_color(true)
local do_dump = false
local dump_file_name = nil
local dump_range_ms = "1000"
local entrylist = {}
local capturing = false
local lastfd = ""
local verbose = true

-- Argument notification callback
function on_set_arg(name, val)
    if name == "dump_file_name" then
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
	-- Request the fields that we need
	fbuf = chisel.request_field("evt.buffer")
	ftid = chisel.request_field("thread.tid")
	fpname = chisel.request_field("proc.name")
	ffdname = chisel.request_field("fd.name")

	-- increase the snaplen so we capture more of the conversation 
	sysdig.set_snaplen(2000)
	
	-- set the output format to ascii
	sysdig.set_output_format("ascii")
	
	-- set the filter
	chisel.set_filter("(" .. FILE_FILTER .. ") and evt.is_io_write=true and evt.dir=< and evt.failed=false")
	
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
	local fdname
	local pname
	
	if verbose then
		fdname = evt.field(ffdname)
		pname = evt.field(fpname)
	end
	
	msgs = split(buf, "\n")

	-- Render the message to screen
	for i, msg in ipairs(msgs) do
		if #msg ~= 0 then
			local infostr

			if verbose then
				infostr = pname .. " " .. fdname .. " "
			else
				infostr = ""
			end

			if is_tty then
				local color = terminal.green
				local ls = string.lower(msg)

				if ls.find(ls, "warn") ~= nil then
					color = terminal.yellow
				elseif ls.find(msg, "err") then
					color = terminal.red
				end

				infostr = string.format("%s%s%s", color, infostr, msg)
			else
				infostr = string.format("%s%s", infostr, msg)
			end

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
	if is_tty then
		print(terminal.reset)
	end

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
