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
description = "Print every message written to syslog by any process. Combine this chisel with a filter like proc.name to restrict its output.";
short_description = "Print every message written to syslog.";
category = "Misc";

args =
{
    {
        name = "content_match",
        description = "if specified, this argument contains a string that is matched against every syslog message. Only the messages that contain the string will be printed by the chisel",
        argtype = "string",
        optional = true
    },
}

require "common"
terminal = require "ansiterminal"
terminal.enable_color(true)

-- Argument notification callback
function on_set_arg(name, val)
    if name == "content_match" then
        match = val
    end
	
    return true
end

-- Initialization callback
function on_init()
	-- Request the fields that we need
	fbuf = chisel.request_field("evt.rawarg.data")
	fpname = chisel.request_field("proc.name")
	fppid = chisel.request_field("proc.pid")
	fres = chisel.request_field("evt.rawarg.res")

	-- increase the snaplen so we capture more of the conversation 
	sysdig.set_snaplen(1000)
	
	-- set the filter
	chisel.set_filter("evt.is_io_write=true and evt.dir=< and fd.name=/var/log/messages")
	
	is_tty = sysdig.is_tty()
	return true
end

-- Event parsing callback
function on_event()
	local buf = evt.field(fbuf)
	local pname = evt.field(fpname)
	local ppid = evt.field(fppid)
	local res = evt.field(fres)

	if res <= 0 then
		return true
	end
	
	if buf == nil then
		name = "<NA>"
	end
	
	lines = split(buf, "\n")
	
	for i, l in ipairs(lines) do
		if string.len(l) ~= 0 then
			if is_tty then
				infostr = string.format("%s %s %s %s", terminal.red, pname, terminal.blue, l)
			else
				infostr = string.format("%s %s", pname, l)
			end
			
			print(infostr)
		end
	end
	
	return true
end

function on_capture_end()
	if is_tty then
		print(terminal.reset)
	end
end
