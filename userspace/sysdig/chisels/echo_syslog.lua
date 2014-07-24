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
description = "Print every message written to syslog by any process. You can combine this chisel with filters like 'proc.name=foo' (to restrict the output to a specific process), or 'syslog.message contains foo' (to show only messages containing a specific string).";
short_description = "Print every message written to syslog.";
category = "Misc";
		   
require "common"
terminal = require "ansiterminal"
terminal.enable_color(true)

args = {}

-- Initialization callback
function on_init()
	-- Request the fields that we need
	ffac = chisel.request_field("syslog.facility.str")
	fsev = chisel.request_field("syslog.severity.str")
	fsevcode = chisel.request_field("syslog.severity")
	fmsg = chisel.request_field("syslog.message")

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
	
	return true
end

function on_capture_end()
	if is_tty then
		print(terminal.reset)
	end
end
