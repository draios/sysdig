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
description = "Print every message written to syslog by any process. You can combine this chisel with filters like 'proc.name=foo' (to restrict the output to a specific process), or 'syslog.message contains foo' (to show only messages including a specific string). You can also write the events generated around each log entry to file by using the dump_file_name and dump_range_ms arguments.";
short_description = "Print every message written to syslog.";
category = "Misc";
		   
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
local is_dumping = false
local dump_file_name = nil
local dump_range_ms = "1000"
entrylist = {}

-- Argument notification callback
function on_set_arg(name, val)
    if name == "dump_file_name" then
		is_dumping = true
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
	ffac = chisel.request_field("syslog.facility.str")
	fsev = chisel.request_field("syslog.severity.str")
	fsevcode = chisel.request_field("syslog.severity")
	fmsg = chisel.request_field("syslog.message")
	ftid = chisel.request_field("thread.tid")

	-- increase the snaplen so we capture more of the conversation 
	sysdig.set_snaplen(1000)
	
	-- set the filter
	chisel.set_filter("evt.is_io_write=true and evt.dir=< and fd.name contains /dev/log")
	
	is_tty = sysdig.is_tty()
	
	return true
end

-- Event parsing callback
function on_event()	
	-- Extract the event details
	local fac = evt.field(ffac)
	local sev = evt.field(fsev)
	local msg = evt.field(fmsg)
	local sevcode = evt.field(fsevcode)
	
	-- Render the message to screen
	if is_tty then
		local color = terminal.green
		
		if sevcode == 4 then
			color = terminal.yellow
		elseif sevcode < 4 then
			color = terminal.red
		end

		infostr = string.format("%s%s.%s %s", color, fac, sev, msg)
	else
		infostr = string.format("%s.%s %s", fac, sev, msg)
	end
	
	print(infostr)
	
	if is_dumping then
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

	if is_dumping then
		local sn = sysdig.get_evtsource_name()

		local args = "-F -r" .. sn .. " -w" .. dump_file_name .. " "
		
		for i, v in ipairs(entrylist) do
			if i ~= 1 then
				args = args .. " or "
			end
			
			args = args .. "(evt.around[" .. ts_to_str(v[1], v[2]) .. "]=" .. dump_range_ms .. " and thread.tid=" .. v[3] .. ")"
		end		

print(args)		
		sysdig.run_sysdig(args)
	end
end
