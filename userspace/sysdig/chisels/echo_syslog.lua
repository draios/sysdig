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

-- Constant tables
severity_strings = {"emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"}

facility_strings = {"kern", 
	"user", 
	"mail", 
	"daemon", 
	"auth", 
	"syslog", 
	"lpr", 
	"news", 
	"uucp", 
	"clock", 
	"authpriv", 
	"ftp", 
	"ntp", 
	"logaudit", 
	"logalert", 
	"cron",
	"local0",
	"local1",
	"local2",
	"local3",
	"local4",
	"local5",
	"local6",
	"local7"
}

-- The table with the list of syslog consumers (e.g. systemd-journal), which we
-- don't include in the output
syslog_consumers = {}

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
	fiswrite = chisel.request_field("evt.is_io_write")
	fetime = chisel.request_field("evt.time.s")

	-- increase the snaplen so we capture more of the conversation 
	sysdig.set_snaplen(1000)
	
	-- set the filter
	chisel.set_filter("evt.is_io=true and evt.dir=< and fd.name contains /dev/log")
	
	is_tty = sysdig.is_tty()
	return true
end

-- Extract facility and severity from a syslog priority number
-- Note: we use division/subtraction instead of bitwise operations to avoid 
-- including an external dependency for something that is not performance critical
function decode_pri(pri)
	local facility = math.floor(pri / 8)
	local severity = pri - (facility * 8)
	
	local fs = "<NA>"
	if facility <= #facility_strings then
		fs = facility_strings[facility + 1]
	end
	
	local ss = "<NA>"
	if severity <= #severity_strings then
		ss = severity_strings[severity + 1]
	end
	
	return severity, fs, ss
end

-- Event parsing callback
function on_event()
	local iswrite = evt.field(fiswrite)
	local ppid = tonumber(evt.field(fppid))

	-- We filter out events written by processes that also read from /dev/log
	-- The reason is that processes like systemd-journal seem to echo the data
	-- they consume back to /dev/log
	if not iswrite then
		syslog_consumers[ppid] = 1
		return
	end

	if syslog_consumers[ppid] == 1 then
		return true
	end
	
	-- Extract the event details
	local buf = evt.field(fbuf)
	local pname = evt.field(fpname)
	local res = evt.field(fres)
	local etime = evt.field(fetime)
	
	if res <= 0 then
		return true
	end
	
	if buf == nil then
		name = "<NA>"
	end

	-- Extract the priority number from the beginning of the buffer
	local priendpos = string.find(buf, ">", nil, true)
	local pri = tonumber(string.sub(buf, 2, priendpos - 1))
	local sevcode, facility, severity = decode_pri(pri)

	local message = string.sub(buf, priendpos + 1)
	
	-- Render the message to screen
	if is_tty then
		local color = terminal.green
		
		if sevcode == 4 then
			color = terminal.yellow
		elseif sevcode < 4 then
			color = terminal.red
		end

		infostr = string.format("%s %s %s %s %s[%d] %s", etime, color, facility, severity, pname, ppid, message)
	else
		infostr = string.format("%s %s %s %s[%d] %s", etime, facility, severity, pname, ppid, message)
	end
	
	print(infostr)
		
	return true
end

function on_capture_end()
	if is_tty then
		print(terminal.reset)
	end
end
